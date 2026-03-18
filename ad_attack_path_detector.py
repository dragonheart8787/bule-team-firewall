#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AD Attack Path Detector - AD 攻擊路徑偵測
偵測：異常登入、大量失敗登入、橫向移動、GPO 異常、PowerShell 異常
"""

from collections import defaultdict
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

# 依賴事件解析器
try:
    from windows_event_parser import WindowsEventParser, ParsedEvent
except ImportError:
    WindowsEventParser = None
    ParsedEvent = None


class ADAttackPathDetector:
    """AD 攻擊路徑偵測器"""
    
    # 異常登入時間（非工作時間）
    OFF_HOURS = list(range(0, 6)) + list(range(22, 24))  # 22:00-06:00
    
    # 可疑 Logon Type
    # 3=Network, 4=Batch, 5=Service, 7=Unlock, 8=NetworkCleartext, 9=NewCredentials, 10=RemoteInteractive
    SUSPICIOUS_LOGON_TYPES = {4, 5, 9}  # Batch, Service, NewCredentials 較可疑
    
    # 高權限帳號
    PRIVILEGED_ACCOUNTS = {"administrator", "admin", "domain admin", "enterprise admin", "krbtgt"}
    
    def __init__(self, event_parser: Optional["WindowsEventParser"] = None):
        self.parser = event_parser or (WindowsEventParser() if WindowsEventParser else None)
        self.findings: List[Dict[str, Any]] = []
    
    def analyze(self, events: Optional[List["ParsedEvent"]] = None) -> Dict[str, Any]:
        """執行 AD 攻擊路徑分析"""
        if events is None and self.parser:
            events = self.parser.parsed_events
        if not events:
            return {"findings": [], "summary": {}}
        
        self.findings = []
        
        # 1. 異常登入時間與來源
        self._detect_anomalous_logon_time(events)
        
        # 2. 大量失敗登入
        self._detect_mass_failed_logon(events)
        
        # 3. 橫向移動特徵關聯
        self._detect_lateral_movement(events)
        
        # 4. 群組成員異常變更
        self._detect_group_changes(events)
        
        # 5. 新增高權限帳號
        self._detect_privileged_account_creation(events)
        
        # 6. GPO 異常修改
        self._detect_gpo_anomaly(events)
        
        # 7. PowerShell 異常腳本
        self._detect_powershell_anomaly(events)
        
        return {
            "findings": self.findings,
            "summary": {
                "total_findings": len(self.findings),
                "critical": sum(1 for f in self.findings if f.get("severity") == "Critical"),
                "high": sum(1 for f in self.findings if f.get("severity") == "High"),
            }
        }
    
    def _detect_anomalous_logon_time(self, events: List) -> None:
        """異常登入時間與來源主機"""
        for e in events:
            if getattr(e, "event_id", 0) != 4624:
                continue
            try:
                tc = getattr(e, "time_created", "") or ""
                if "T" in tc:
                    hour = int(tc.split("T")[1][:2])
                else:
                    hour = datetime.now().hour  # fallback
                
                if hour in self.OFF_HOURS:
                    self.findings.append({
                        "type": "ANOMALOUS_LOGON_TIME",
                        "severity": "Medium",
                        "description": f"非工作時間登入: {getattr(e, 'target_user', '?')} from {getattr(e, 'source_ip', '?')}",
                        "user": getattr(e, "target_user", None),
                        "source_ip": getattr(e, "source_ip", None),
                        "event_id": getattr(e, "event_id", None),
                    })
            except (ValueError, IndexError):
                pass
    
    def _detect_mass_failed_logon(self, events: List) -> None:
        """大量失敗登入"""
        failed_by_ip = defaultdict(int)
        failed_by_user = defaultdict(int)
        
        for e in events:
            if getattr(e, "event_id", 0) != 4625:
                continue
            ip = getattr(e, "source_ip", None) or "unknown"
            user = getattr(e, "target_user", None) or "unknown"
            failed_by_ip[ip] += 1
            failed_by_user[user] += 1
        
        threshold = 5
        for ip, count in failed_by_ip.items():
            if count >= threshold:
                self.findings.append({
                    "type": "MASS_FAILED_LOGON_BY_IP",
                    "severity": "High",
                    "description": f"來源 IP {ip} 失敗登入 {count} 次（可能暴力破解）",
                    "source_ip": ip,
                    "count": count,
                })
        
        for user, count in failed_by_user.items():
            if count >= threshold:
                self.findings.append({
                    "type": "MASS_FAILED_LOGON_BY_USER",
                    "severity": "High",
                    "description": f"帳號 {user} 失敗登入 {count} 次（可能針對性攻擊）",
                    "target_user": user,
                    "count": count,
                })
    
    def _detect_lateral_movement(self, events: List) -> None:
        """橫向移動特徵關聯"""
        # Logon Type 3 (Network) 從多台主機登入同一帳號
        user_sources = defaultdict(set)
        for e in events:
            if getattr(e, "event_id", 0) != 4624:
                continue
            lt = getattr(e, "logon_type", None)
            if lt == 3:  # Network
                user = getattr(e, "target_user", None) or "?"
                ip = getattr(e, "source_ip", None) or "?"
                user_sources[user].add(ip)
        
        for user, ips in user_sources.items():
            if len(ips) >= 3:  # 從 3+ 來源登入
                self.findings.append({
                    "type": "LATERAL_MOVEMENT_INDICATOR",
                    "severity": "Medium",
                    "description": f"帳號 {user} 從 {len(ips)} 個不同來源 Network 登入",
                    "target_user": user,
                    "source_count": len(ips),
                })
    
    def _detect_group_changes(self, events: List) -> None:
        """群組成員異常變更 (4728, 4729, 4732, 4733)"""
        privileged_groups = {"domain admins", "enterprise admins", "administrators"}
        for e in events:
            eid = getattr(e, "event_id", 0)
            if eid in {4728, 4729, 4732, 4733}:
                target = (getattr(e, "target_user", None) or "").lower()
                if any(pg in target for pg in privileged_groups):
                    self.findings.append({
                        "type": "PRIVILEGED_GROUP_CHANGE",
                        "severity": "High",
                        "description": f"特權群組變更 EventID={eid}",
                        "event_id": eid,
                    })
    
    def _detect_privileged_account_creation(self, events: List) -> None:
        """新增高權限帳號 (4720)"""
        for e in events:
            if getattr(e, "event_id", 0) != 4720:
                continue
            target = (getattr(e, "target_user", None) or "").lower()
            if any(pa in target for pa in self.PRIVILEGED_ACCOUNTS):
                self.findings.append({
                    "type": "PRIVILEGED_ACCOUNT_CREATION",
                    "severity": "Critical",
                    "description": f"新增高權限帳號: {target}",
                    "target_user": target,
                })
    
    def _detect_gpo_anomaly(self, events: List) -> None:
        """GPO 異常修改 (5136, 5137, 5141)"""
        for e in events:
            if getattr(e, "event_id", 0) in {5136, 5137, 5141}:
                self.findings.append({
                    "type": "GPO_MODIFICATION",
                    "severity": "Medium",
                    "description": f"GPO 物件變更 EventID={getattr(e, 'event_id', 0)}",
                    "event_id": getattr(e, "event_id", None),
                })
    
    def _detect_powershell_anomaly(self, events: List) -> None:
        """PowerShell 異常腳本 (4688 + 命令行)"""
        # 簡化：若有 4688 且命令行含 powershell + -enc/-encodedcommand 等
        for e in events:
            raw = getattr(e, "raw_data", {}) or {}
            if isinstance(raw, dict):
                cmd = str(raw.get("CommandLine", raw.get("command_line", ""))).lower()
            else:
                cmd = str(raw).lower()
            if "powershell" in cmd and ("-enc" in cmd or "-encodedcommand" in cmd or "bypass" in cmd):
                self.findings.append({
                    "type": "POWERSHELL_SUSPICIOUS_SCRIPT",
                    "severity": "High",
                    "description": "PowerShell 可疑參數 (-enc/-bypass)",
                    "event_id": getattr(e, "event_id", None),
                })


# 測試
if __name__ == "__main__":
    detector = ADAttackPathDetector()
    # 模擬事件
    class MockEvent:
        pass
    evts = []
    for _ in range(10):
        e = MockEvent()
        e.event_id = 4625
        e.target_user = "admin"
        e.source_ip = "192.168.1.100"
        e.time_created = "2026-03-18T03:00:00"
        e.logon_type = 3
        e.raw_data = {}
        evts.append(e)
    r = detector.analyze(evts)
    print("Findings:", len(r["findings"]))
    print("Summary:", r["summary"])
