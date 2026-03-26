#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows Event Parser - Windows 事件解析
解析 Security、System、Application 等事件日誌
支援 EVTX 格式與 XML 格式
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass


@dataclass
class ParsedEvent:
    """解析後的 Windows 事件"""
    event_id: int
    channel: str
    computer: str
    time_created: str
    user: Optional[str]
    source_ip: Optional[str]
    logon_type: Optional[int]
    target_user: Optional[str]
    raw_data: Dict[str, Any]


class WindowsEventParser:
    """Windows 事件解析器"""
    
    # 關鍵登入相關 Event ID
    LOGON_EVENTS = {4624, 4625, 4634, 4644, 4647, 4648, 4768, 4769, 4770, 4771}
    # 帳號/群組變更
    ACCOUNT_EVENTS = {4720, 4722, 4723, 4724, 4725, 4726, 4732, 4733, 4756}
    # GPO 變更
    GPO_EVENTS = {5136, 5137, 5141}
    # 服務/票證
    KERBEROS_EVENTS = {4768, 4769, 4770, 4771}
    
    def __init__(self):
        self.parsed_events: List[ParsedEvent] = []
    
    def parse_evtx_line(self, line: str) -> Optional[ParsedEvent]:
        """解析單行 EVTX/XML 格式事件（簡化版）"""
        # 支援 XML 格式片段
        event_id = self._extract_xml_value(line, "EventID") or self._extract_xml_value(line, "EventID", ns=True)
        if not event_id:
            return None
        
        try:
            eid = int(event_id)
        except (ValueError, TypeError):
            return None
        
        return ParsedEvent(
            event_id=eid,
            channel=self._extract_xml_value(line, "Channel") or "Security",
            computer=self._extract_xml_value(line, "Computer") or "",
            time_created=self._extract_xml_value(line, "TimeCreated", attr="SystemTime") or "",
            user=self._extract_data(line, "TargetUserName"),
            source_ip=self._extract_data(line, "IpAddress") or self._extract_data(line, "ClientAddress"),
            logon_type=self._parse_int(self._extract_data(line, "LogonType")),
            target_user=self._extract_data(line, "TargetUserName"),
            raw_data={"raw": line[:500]}
        )
    
    def _extract_xml_value(self, text: str, tag: str, attr: Optional[str] = None, ns: bool = False) -> Optional[str]:
        """從 XML 片段提取值"""
        patterns = [
            f"<{tag}[^>]*" + (f" {attr}=\"([^\"]+)\"" if attr else ">([^<]+)") + ("" if attr else "<"),
            f"<.*:{tag}[^>]*" + (f" {attr}=\"([^\"]+)\"" if attr else ">([^<]+)") + ("" if attr else "<"),
        ]
        for p in patterns:
            m = re.search(p, text, re.IGNORECASE | re.DOTALL)
            if m:
                return m.group(1).strip()
        return None
    
    def _extract_data(self, text: str, name: str) -> Optional[str]:
        """提取 Data 節點"""
        m = re.search(rf'<Data[^>]*Name="{re.escape(name)}"[^>]*>([^<]*)</Data>', text, re.I)
        if m:
            return m.group(1).strip()
        return None
    
    def _parse_int(self, v: Optional[str]) -> Optional[int]:
        if v is None:
            return None
        try:
            return int(v)
        except ValueError:
            return None
    
    def parse_json_event(self, event: Dict[str, Any]) -> ParsedEvent:
        """解析 JSON 格式事件（如從 SIEM 匯出）"""
        system = event.get("System", event)
        event_id = system.get("EventID", system.get("EventRecordID", 0))
        if isinstance(event_id, dict):
            event_id = event_id.get("#text", 0)
        
        event_data = event.get("EventData", event.get("Data", {}))
        if isinstance(event_data, dict):
            data = event_data
        else:
            data = {d.get("Name", ""): d.get("#text", d.get("Value", "")) for d in (event_data or []) if isinstance(d, dict)}
        
        return ParsedEvent(
            event_id=int(event_id),
            channel=system.get("Channel", "Security"),
            computer=system.get("Computer", ""),
            time_created=system.get("TimeCreated", {}).get("SystemTime", "") if isinstance(system.get("TimeCreated"), dict) else str(system.get("TimeCreated", "")),
            user=data.get("TargetUserName", data.get("AccountName")),
            source_ip=data.get("IpAddress", data.get("ClientAddress", data.get("IpAddress"))),
            logon_type=self._parse_int(data.get("LogonType", data.get("Logon Type"))),
            target_user=data.get("TargetUserName", data.get("TargetAccount")),
            raw_data=event
        )
    
    def load_and_parse(self, file_path: str) -> List[ParsedEvent]:
        """載入並解析事件檔案"""
        path = Path(file_path)
        if not path.exists():
            return []
        
        self.parsed_events = []
        content = path.read_text(encoding="utf-8", errors="replace")
        
        # 嘗試 JSON
        if content.strip().startswith("{"):
            try:
                data = json.loads(content)
                events = data if isinstance(data, list) else [data]
                for e in events:
                    self.parsed_events.append(self.parse_json_event(e))
            except json.JSONDecodeError:
                pass
        else:
            # 逐行/逐事件解析 XML 片段
            for line in content.split("\n"):
                if "EventID" in line or "EventRecordID" in line:
                    evt = self.parse_evtx_line(line)
                    if evt:
                        self.parsed_events.append(evt)
        
        return self.parsed_events
    
    def get_logon_events(self) -> List[ParsedEvent]:
        """取得登入相關事件"""
        return [e for e in self.parsed_events if e.event_id in self.LOGON_EVENTS]
    
    def get_failed_logons(self) -> List[ParsedEvent]:
        """取得失敗登入 (4625)"""
        return [e for e in self.parsed_events if e.event_id == 4625]
    
    def get_account_changes(self) -> List[ParsedEvent]:
        """取得帳號/群組變更"""
        return [e for e in self.parsed_events if e.event_id in self.ACCOUNT_EVENTS]
    
    def get_kerberos_events(self) -> List[ParsedEvent]:
        """取得 Kerberos 事件"""
        return [e for e in self.parsed_events if e.event_id in self.KERBEROS_EVENTS]


# 測試
if __name__ == "__main__":
    parser = WindowsEventParser()
    # 模擬 JSON 事件
    sample = [{
        "System": {"EventID": 4625, "Computer": "DC01", "Channel": "Security"},
        "EventData": {"TargetUserName": "admin", "IpAddress": "192.168.1.100", "LogonType": "3"}
    }]
    for e in sample:
        evt = parser.parse_json_event(e)
        parser.parsed_events.append(evt)
    print("解析事件數:", len(parser.parsed_events))
    print("失敗登入:", len(parser.get_failed_logons()))
