#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AD/DC 偵測模組驗證測試
非僅 CLI 能跑，實際驗證邏輯與輸出
"""

import sys
import json
from pathlib import Path

# 加入專案路徑
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_windows_event_parser():
    """測試 Windows 事件解析器"""
    from windows_event_parser import WindowsEventParser, ParsedEvent
    
    parser = WindowsEventParser()
    
    # 模擬 JSON 事件
    sample = [
        {"System": {"EventID": 4625, "Computer": "DC01", "Channel": "Security"},
         "EventData": {"TargetUserName": "admin", "IpAddress": "192.168.1.100", "LogonType": "3"}},
        {"System": {"EventID": 4625, "Computer": "DC01", "Channel": "Security"},
         "EventData": {"TargetUserName": "admin", "IpAddress": "192.168.1.100", "LogonType": "3"}},
        {"System": {"EventID": 4624, "Computer": "DC01", "Channel": "Security"},
         "EventData": {"TargetUserName": "user1", "IpAddress": "10.0.0.5", "LogonType": "3"}},
    ]
    
    events = []
    for e in sample:
        evt = parser.parse_json_event(e)
        events.append(evt)
    
    assert len(events) == 3
    assert events[0].event_id == 4625
    assert events[0].target_user == "admin"
    assert events[0].source_ip == "192.168.1.100"
    
    parser.parsed_events = events
    failed = parser.get_failed_logons()
    assert len(failed) == 2
    
    return {"passed": True, "events_parsed": len(events), "failed_logons": len(failed)}


def test_ad_attack_path_detector():
    """測試 AD 攻擊路徑偵測"""
    from ad_attack_path_detector import ADAttackPathDetector
    
    # 建立模擬事件
    class MockEvent:
        def __init__(self, eid, user, ip, logon_type=3):
            self.event_id = eid
            self.target_user = user
            self.source_ip = ip
            self.logon_type = logon_type
            self.time_created = "2026-03-18T03:00:00"  # 凌晨
            self.raw_data = {}
    
    events = []
    for i in range(10):
        events.append(MockEvent(4625, "admin", "192.168.1.100"))  # 10 次失敗登入
    
    detector = ADAttackPathDetector()
    result = detector.analyze(events)
    
    assert "findings" in result
    assert "summary" in result
    # 應偵測到 MASS_FAILED_LOGON
    findings_types = [f["type"] for f in result["findings"]]
    assert "MASS_FAILED_LOGON_BY_IP" in findings_types or "MASS_FAILED_LOGON_BY_USER" in findings_types
    
    return {"passed": True, "findings": len(result["findings"]), "summary": result["summary"]}


def test_kerberos_anomaly_detector():
    """測試 Kerberos 異常偵測"""
    from kerberos_anomaly_detector import KerberosAnomalyDetector
    
    class MockEvent:
        def __init__(self, eid, user="test"):
            self.event_id = eid
            self.target_user = user
            self.user = user
            self.raw_data = {}
    
    events = [MockEvent(4771, "admin") for _ in range(6)]  # 6 次預認證失敗
    
    detector = KerberosAnomalyDetector()
    result = detector.analyze(events)
    
    assert "findings" in result
    # 應偵測到 KERBEROS_PREAUTH_BRUTEFORCE
    findings_types = [f["type"] for f in result["findings"]]
    assert "KERBEROS_PREAUTH_BRUTEFORCE" in findings_types
    
    return {"passed": True, "findings": len(result["findings"])}


def test_privileged_group_monitor():
    """測試特權群組監控"""
    from privileged_group_monitor import PrivilegedGroupMonitor
    
    class MockEvent:
        def __init__(self, eid, group, target):
            self.event_id = eid
            self.target_user = target
            self.time_created = "2026-03-18T12:00:00"
            self.computer = "DC01"
            self.raw_data = {
                "EventData": {
                    "TargetGroupName": group,
                    "TargetUserName": target,
                    "MemberName": target,
                }
            }
    
    class MockEvent4720:
        event_id = 4720
        target_user = "hacker_admin"
        time_created = "2026-03-18T12:00:00"
        computer = "DC01"
        raw_data = {"EventData": {"TargetUserName": "hacker_admin", "TargetGroupName": ""}}
    
    events = [
        MockEvent(4728, "Domain Admins", "newadmin"),  # 成員加入
        MockEvent4720(),  # 帳號建立 4720
    ]
    
    monitor = PrivilegedGroupMonitor()
    result = monitor.analyze(events)
    
    assert "records" in result
    assert "alerts" in result
    assert len(result["records"]) >= 1
    assert len(result["alerts"]) >= 1
    
    return {"passed": True, "records": len(result["records"]), "alerts": len(result["alerts"])}


def run_all():
    """執行所有 AD 偵測測試"""
    results = {}
    
    tests = [
        ("Windows Event Parser", test_windows_event_parser),
        ("AD Attack Path Detector", test_ad_attack_path_detector),
        ("Kerberos Anomaly Detector", test_kerberos_anomaly_detector),
        ("Privileged Group Monitor", test_privileged_group_monitor),
    ]
    
    print("=" * 60)
    print("AD/DC 偵測模組驗證測試")
    print("=" * 60)
    
    for name, fn in tests:
        try:
            r = fn()
            results[name] = {"passed": True, **r}
            print(f"  [OK] {name}")
        except Exception as e:
            results[name] = {"passed": False, "error": str(e)}
            print(f"  [FAIL] {name}: {e}")
    
    passed = sum(1 for r in results.values() if r.get("passed"))
    print("=" * 60)
    print(f"通過: {passed}/{len(tests)}")
    print("=" * 60)
    
    return results


if __name__ == "__main__":
    run_all()
