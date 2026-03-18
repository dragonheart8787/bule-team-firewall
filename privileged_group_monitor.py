#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Privileged Group Monitor - 特權群組監控
監控：Domain Admins、Enterprise Admins、Administrators 等群組成員變更
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field

try:
    from windows_event_parser import WindowsEventParser, ParsedEvent
except ImportError:
    WindowsEventParser = None
    ParsedEvent = None


@dataclass
class GroupChangeRecord:
    """群組變更記錄"""
    event_id: int
    group_name: str
    target_account: str
    action: str  # MemberAdded, MemberRemoved, GroupCreated
    timestamp: str
    source_computer: str = ""


class PrivilegedGroupMonitor:
    """特權群組監控器"""
    
    PRIVILEGED_GROUPS = {
        "domain admins", "enterprise admins", "administrators",
        "schema admins", "dns admins", "backup operators",
        "account operators", "server operators", "print operators"
    }
    
    # Event ID: 4728=成員加入, 4729=成員移除, 4732=成員加入(複製), 4733=成員移除(複製)
    # 4720=帳號建立, 4722=帳號啟用, 4724=密碼重設
    MEMBER_ADDED = {4728, 4732}
    MEMBER_REMOVED = {4729, 4733}
    
    def __init__(self):
        self.records: List[GroupChangeRecord] = []
        self.alerts: List[Dict[str, Any]] = []
    
    def analyze(self, events: Optional[List] = None, parser: Optional["WindowsEventParser"] = None) -> Dict[str, Any]:
        """分析特權群組變更"""
        if events is None and parser:
            events = parser.get_account_changes()
        if not events:
            return {"records": [], "alerts": [], "summary": {}}
        
        self.records = []
        self.alerts = []
        
        for e in events:
            eid = getattr(e, "event_id", 0)
            if eid not in {4728, 4729, 4732, 4733, 4720, 4722, 4724}:
                continue
            
            data = self._get_event_data(e)
            group = (data.get("TargetGroupName", data.get("GroupName", "")) or "").lower()
            target = data.get("TargetUserName", data.get("MemberName", getattr(e, "target_user", ""))) or ""
            
            if not any(pg in group for pg in self.PRIVILEGED_GROUPS) and eid not in {4720, 4722, 4724}:
                continue
            
            action = "MemberAdded" if eid in self.MEMBER_ADDED else "MemberRemoved" if eid in self.MEMBER_REMOVED else "AccountChange"
            
            rec = GroupChangeRecord(
                event_id=eid,
                group_name=group or "N/A",
                target_account=target,
                action=action,
                timestamp=getattr(e, "time_created", "") or datetime.utcnow().isoformat(),
                source_computer=getattr(e, "computer", "") or ""
            )
            self.records.append(rec)
            
            # 產生警報
            if eid in self.MEMBER_ADDED:
                self.alerts.append({
                    "type": "PRIVILEGED_GROUP_MEMBER_ADDED",
                    "severity": "High",
                    "description": f"特權群組 {group} 新增成員: {target}",
                    "group": group,
                    "target_account": target,
                    "event_id": eid,
                })
            elif eid == 4720:  # 帳號建立
                if any(p in target.lower() for p in ["admin", "administrator", "root"]):
                    self.alerts.append({
                        "type": "PRIVILEGED_ACCOUNT_CREATED",
                        "severity": "Critical",
                        "description": f"新增高權限帳號: {target}",
                        "target_account": target,
                        "event_id": eid,
                    })
        
        return {
            "records": [
                {
                    "event_id": r.event_id,
                    "group_name": r.group_name,
                    "target_account": r.target_account,
                    "action": r.action,
                    "timestamp": r.timestamp,
                }
                for r in self.records
            ],
            "alerts": self.alerts,
            "summary": {
                "total_changes": len(self.records),
                "alerts": len(self.alerts),
                "critical": sum(1 for a in self.alerts if a.get("severity") == "Critical"),
            }
        }
    
    def _get_event_data(self, e) -> Dict[str, Any]:
        raw = getattr(e, "raw_data", {}) or {}
        if isinstance(raw, dict) and "EventData" in raw:
            ed = raw["EventData"]
            if isinstance(ed, dict):
                return ed
            return {d.get("Name", ""): d.get("#text", d.get("Value", "")) for d in (ed or []) if isinstance(d, dict)}
        return {}
    
    def get_baseline(self) -> Dict[str, List[str]]:
        """取得目前特權群組基準（需從 AD 或日誌建立）"""
        return {
            "domain_admins": [],
            "enterprise_admins": [],
            "administrators": [],
        }
    
    def compare_with_baseline(self, baseline: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """與基準比對，偵測異常新增"""
        diff_alerts = []
        for rec in self.records:
            if rec.action != "MemberAdded":
                continue
            group_key = rec.group_name.replace(" ", "_").lower()
            if group_key in baseline and rec.target_account not in baseline[group_key]:
                diff_alerts.append({
                    "type": "UNAUTHORIZED_GROUP_ADDITION",
                    "severity": "High",
                    "description": f"未授權新增 {rec.target_account} 至 {rec.group_name}",
                })
        return diff_alerts


# 測試
if __name__ == "__main__":
    monitor = PrivilegedGroupMonitor()
    r = monitor.analyze(events=[])
    print("Records:", len(r["records"]))
    print("Alerts:", len(r["alerts"]))
    print("Summary:", r["summary"])
