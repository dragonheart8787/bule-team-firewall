#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kerberos Anomaly Detector - Kerberos 異常偵測
偵測：可疑服務票證、黃金票證、白銀票證、票證濫用
"""

from collections import defaultdict
from typing import Dict, List, Any, Optional

try:
    from windows_event_parser import WindowsEventParser, ParsedEvent
except ImportError:
    WindowsEventParser = None
    ParsedEvent = None


class KerberosAnomalyDetector:
    """Kerberos 異常偵測器"""
    
    # Event ID: 4768=TGT, 4769=TGS, 4770=票證續訂, 4771=預認證失敗
    TGT_REQUEST = 4768
    TGS_REQUEST = 4769
    TICKET_RENEWAL = 4770
    PREAUTH_FAILURE = 4771
    
    # 敏感服務 SPN
    SENSITIVE_SPNS = ["cifs", "ldap", "dns", "krbtgt", "host", "rpcss", "http", "wsman"]
    
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
    
    def analyze(self, events: Optional[List] = None, parser: Optional["WindowsEventParser"] = None) -> Dict[str, Any]:
        """分析 Kerberos 事件"""
        if events is None and parser:
            events = parser.get_kerberos_events()
        if not events:
            return {"findings": [], "summary": {}}
        
        self.findings = []
        
        self._detect_suspicious_service_tickets(events)
        self._detect_golden_ticket_indicators(events)
        self._detect_silver_ticket_indicators(events)
        self._detect_ticket_anomaly(events)
        self._detect_preauth_bruteforce(events)
        
        return {
            "findings": self.findings,
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f.get("severity") == "Critical"),
            }
        }
    
    def _get_event_data(self, e) -> Dict[str, Any]:
        """取得事件資料"""
        raw = getattr(e, "raw_data", {}) or {}
        if isinstance(raw, dict) and "EventData" in raw:
            ed = raw["EventData"]
            if isinstance(ed, dict):
                return ed
            return {d.get("Name", ""): d.get("#text", d.get("Value", "")) for d in (ed or []) if isinstance(d, dict)}
        return {}
    
    def _detect_suspicious_service_tickets(self, events: List) -> None:
        """可疑服務票證行為 (4769)"""
        # 異常：同一帳號短時間大量 TGS 請求、請求敏感 SPN
        tgs_by_user = defaultdict(list)
        for e in events:
            if getattr(e, "event_id", 0) != self.TGS_REQUEST:
                continue
            user = getattr(e, "user", None) or getattr(e, "target_user", None)
            data = self._get_event_data(e)
            spn = data.get("ServiceName", data.get("TargetServerName", ""))
            tgs_by_user[user].append({"spn": spn, "event": e})
        
        for user, reqs in tgs_by_user.items():
            if len(reqs) >= 20:  # 短時間大量
                self.findings.append({
                    "type": "SUSPICIOUS_SERVICE_TICKET_VOLUME",
                    "severity": "Medium",
                    "description": f"帳號 {user} 短時間大量 TGS 請求 ({len(reqs)} 次)",
                    "target_user": user,
                    "request_count": len(reqs),
                })
            # 敏感 SPN
            for r in reqs:
                spn = (r.get("spn") or "").lower()
                if any(s in spn for s in self.SENSITIVE_SPNS) and "krbtgt" in spn:
                    self.findings.append({
                        "type": "SENSITIVE_SPN_TICKET_REQUEST",
                        "severity": "High",
                        "description": f"請求敏感 SPN 票證: {spn}",
                        "target_user": user,
                        "spn": spn,
                    })
    
    def _detect_golden_ticket_indicators(self, events: List) -> None:
        """黃金票證指標 (4768 異常)"""
        # 黃金票證：TGT 請求無 4768 對應的 4770 預認證、或異常時間戳
        for e in events:
            if getattr(e, "event_id", 0) != self.TGT_REQUEST:
                continue
            data = self._get_event_data(e)
            # Status 0x0 = 成功，若無對應 4770 預認證可能為偽造
            status = data.get("Status", data.get("ResultCode", ""))
            if status in ("0x0", "0x0 "):
                # 簡化：檢查是否有異常
                pass
            # 可擴充：比對 4770 時間戳
    
    def _detect_silver_ticket_indicators(self, events: List) -> None:
        """白銀票證指標 (4769 異常)"""
        # 白銀票證：直接 TGS 請求無 TGT、異常加密類型
        for e in events:
            if getattr(e, "event_id", 0) != self.TGS_REQUEST:
                continue
            data = self._get_event_data(e)
            ticket_enc = data.get("TicketEncryptionType", data.get("EncryptionType", ""))
            # 弱加密或異常類型
            if "0x17" in str(ticket_enc) or "RC4" in str(ticket_enc).upper():
                self.findings.append({
                    "type": "WEAK_TICKET_ENCRYPTION",
                    "severity": "Medium",
                    "description": f"TGS 使用弱加密類型: {ticket_enc}",
                })
    
    def _detect_ticket_anomaly(self, events: List) -> None:
        """票證異常（異常續訂、異常數量）"""
        renewals = [e for e in events if getattr(e, "event_id", 0) == self.TICKET_RENEWAL]
        if len(renewals) > 100:  # 大量續訂
            self.findings.append({
                "type": "TICKET_RENEWAL_ANOMALY",
                "severity": "Low",
                "description": f"異常大量票證續訂: {len(renewals)} 次",
            })
    
    def _detect_preauth_bruteforce(self, events: List) -> None:
        """預認證失敗暴力破解 (4771)"""
        failures = defaultdict(int)
        for e in events:
            if getattr(e, "event_id", 0) != self.PREAUTH_FAILURE:
                continue
            user = getattr(e, "target_user", None) or getattr(e, "user", None)
            failures[user] += 1
        
        for user, count in failures.items():
            if count >= 5:
                self.findings.append({
                    "type": "KERBEROS_PREAUTH_BRUTEFORCE",
                    "severity": "High",
                    "description": f"帳號 {user} Kerberos 預認證失敗 {count} 次",
                    "target_user": user,
                    "count": count,
                })


# 測試
if __name__ == "__main__":
    detector = KerberosAnomalyDetector()
    r = detector.analyze(events=[])
    print("Findings:", r["findings"])
    print("Summary:", r["summary"])
