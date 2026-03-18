#!/usr/bin/env python3
"""
Atomic Red Team T1021.002 攻擊模擬與 SIEM 檢測驗證
Remote Services: SMB/Windows Admin Shares (Lateral Movement)
"""

import os
import sys
from datetime import datetime
import json

try:
    script_path = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_path)
    sys.path.append(os.getcwd())
except Exception as e:
    print(f"更改工作目錄時出錯: {e}")

try:
    from siem_dashboards import SOCDashboard
except ImportError as e:
    print(f"導入失敗: {e}")
    print("請確保 siem_dashboards.py 與此腳本位於同一目錄中。")
    sys.exit(1)

def simulate_t1021_002_attack():
    """
    模擬 Atomic Red Team T1021.002 攻擊：
    一台受感染的主機嘗試存取另一台主機的管理員共用 (C$) 以進行橫向移動。
    """
    print("正在模擬 ATT&CK T1021.002 攻擊：橫向移動至管理員共用...")
    
    # 模仿伺服器或網路監控設備捕獲的 SMB 連線日誌
    attack_event = {
        'event_type': 'smb_connection',
        'timestamp': datetime.now().isoformat(),
        'source_hostname': 'COMPROMISED-WS',
        'src_ip': '192.168.1.130',
        'dest_hostname': 'FILE-SRV-01',
        'dest_ip': '192.168.1.20',
        'share_name': r'\\FILE-SRV-01\C$',
        'user': 'compromised-user',
        'status': 'success',
        'log_source': 'FileServerLogs'
    }
    
    print("模擬的攻擊日誌事件：")
    print(json.dumps(attack_event, indent=2, ensure_ascii=False))
    
    return attack_event

def verify_detection(attack_event: dict):
    """
    使用 SIEM 儀表板驗證攻擊是否被檢測到
    """
    print("\n正在使用 SIEM 儀表板驗證檢測...")
    
    dashboard = SOCDashboard()
    print("SOC 儀表板已初始化。")
    print(f"已加載 {len(dashboard.rules)} 條規則。")
    
    dashboard.process_event(attack_event)
    print("攻擊事件已提交至 SIEM 進行處理。")
    
    alerts = dashboard.get_dashboard_data().get('recent_alerts', [])
    print(f"SIEM 產生了 {len(alerts)} 條警報。")
    
    detection_successful = False
    for alert in alerts:
        if alert.get('rule_id') == 'R011':
            print("\n--- 檢測成功！ ---")
            print(f"觸發的規則 ID: {alert.get('rule_id')}")
            print(f"規則名稱: {alert.get('rule_name')}")
            print(f"嚴重性: {alert.get('severity')}")
            print("警報詳細資訊匹配 T1021.002 (橫向移動) 攻擊模擬。")
            detection_successful = True
            break
            
    if not detection_successful:
        print("\n--- 檢測失敗 ---")
        print("SIEM 未能觸發針對 T1021.002 的特定警報 (R011)。")
        
    return detection_successful

def main():
    """
    主執行函數
    """
    print("======================================================")
    print("== Atomic Red Team T1021.002 模擬與檢測驗證腳本 ==")
    print("======================================================")
    
    event = simulate_t1021_002_attack()
    success = verify_detection(event)
    
    print("\n------------------------------------------------------")
    if success:
        print("最終結果：成功 - 藍隊防禦系統按預期偵測到威脅。")
    else:
        print("最終結果：失敗 - 藍隊防禦系統未能偵測到威脅。")
    print("------------------------------------------------------")

if __name__ == "__main__":
    main()
