#!/usr/bin/env python3
"""
Atomic Red Team T1486 攻擊模擬與 SIEM 檢測驗證
Data Encrypted for Impact (Ransomware Behavior)
"""

import os
import sys
from datetime import datetime
import json
import time

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

def simulate_t1486_attack_and_process_events(dashboard: SOCDashboard):
    """
    模擬 Atomic Red Team T1486 攻擊：
    一個程序在短時間內大量重新命名檔案。
    """
    print("正在模擬 ATT&CK T1486 攻擊：勒索軟體檔案加密行為...")
    
    process_name = "ransomware.exe"
    process_id = "9988"
    hostname = "FINANCE-SERVER"
    src_ip = "192.168.1.78"
    num_files_to_rename = 150

    print(f"'{process_name}' (PID: {process_id}) 將在短時間內重新命名 {num_files_to_rename} 個檔案。")
    
    # 快速生成並處理大量 file_renamed 事件
    for i in range(num_files_to_rename):
        event = {
            'event_type': 'file_renamed',
            'timestamp': datetime.now().isoformat(),
            'hostname': hostname,
            'process_name': process_name,
            'process_id': process_id,
            'user': 'system',
            'old_path': f"C:\\Users\\Finance\\Documents\\report_{i}.txt",
            'new_path': f"C:\\Users\\Finance\\Documents\\report_{i}.txt.locked",
            'src_ip': src_ip,
            'log_source': 'EDR'
        }
        # 立即處理每個事件
        dashboard.process_event(event)
        # 稍微暫停一下以模擬真實情況，但保持在10秒的窗口內
        time.sleep(0.01)

    print(f"{num_files_to_rename} 個檔案重新命名事件已生成並提交至 SIEM。")


def verify_detection(dashboard: SOCDashboard):
    """
    使用 SIEM 儀表板驗證攻擊是否被檢測到
    """
    print("\n正在使用 SIEM 儀表板驗證檢測...")
    
    alerts = dashboard.get_dashboard_data().get('recent_alerts', [])
    print(f"SIEM 總共產生了 {len(alerts)} 條警報。")
    
    detection_successful = False
    for alert in alerts:
        if alert.get('rule_id') == 'R009':
            print("\n--- 檢測成功！ ---")
            print(f"觸發的規則 ID: {alert.get('rule_id')}")
            print(f"規則名稱: {alert.get('rule_name')}")
            print(f"嚴重性: {alert.get('severity')}")
            print("警報詳細資訊匹配 T1486 (勒索軟體) 攻擊模擬。")
            detection_successful = True
            break
            
    if not detection_successful:
        print("\n--- 檢測失敗 ---")
        print("SIEM 未能觸發針對 T1486 的特定警報 (R009)。")
        
    return detection_successful

def main():
    """
    主執行函數
    """
    print("======================================================")
    print("== Atomic Red Team T1486 模擬與檢測驗證腳本 ==")
    print("======================================================")
    
    # 初始化儀表板
    dashboard = SOCDashboard()
    print("SOC 儀表板已初始化。")
    
    # 模擬攻擊並即時處理事件
    simulate_t1486_attack_and_process_events(dashboard)
    
    # 驗證結果
    success = verify_detection(dashboard)
    
    print("\n------------------------------------------------------")
    if success:
        print("最終結果：成功 - 藍隊防禦系統按預期偵測到威脅。")
    else:
        print("最終結果：失敗 - 藍隊防禦系統未能偵測到威脅。")
    print("------------------------------------------------------")

if __name__ == "__main__":
    main()
