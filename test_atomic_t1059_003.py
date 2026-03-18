#!/usr/bin/env python3
"""
Atomic Red Team T1059.003 攻擊模擬與 SIEM 檢測驗證
"""

import os
import sys
from datetime import datetime
import json

# 確保可以從當前目錄導入模組
# 解決中文路徑問題
try:
    # 獲取腳本的絕對路徑
    script_path = os.path.dirname(os.path.abspath(__file__))
    # 將工作目錄更改為腳本所在的目錄
    os.chdir(script_path)
    # 將當前目錄添加到 sys.path
    sys.path.append(os.getcwd())
except Exception as e:
    print(f"更改工作目錄時出錯: {e}")


try:
    from siem_dashboards import SOCDashboard
except ImportError as e:
    print(f"導入失敗: {e}")
    print("請確保 siem_dashboards.py 與此腳本位於同一目錄中。")
    sys.exit(1)

def simulate_t1059_003_attack():
    """
    模擬 Atomic Red Team T1059.003 攻擊：
    執行 'whoami' 指令。
    這是一個常見的偵察技術。
    """
    print("正在模擬 ATT&CK T1059.003 攻擊：執行 'whoami'...")
    
    # 構造一個模擬的日誌事件
    # 這模仿了從端點檢測與響應（EDR）系統捕獲的進程創建事件
    attack_event = {
        'event_type': 'process_creation',
        'timestamp': datetime.now().isoformat(),
        'hostname': 'WORKSTATION-01',
        'process_name': 'cmd.exe',
        'process_id': '1234',
        'parent_process_name': 'explorer.exe',
        'parent_process_id': '5678',
        'command_line': 'C:\\Windows\\system32\\cmd.exe /c whoami',
        'user': 'testuser',
        'src_ip': '192.168.1.101',
        'log_source': 'EDR'
    }
    
    print("模擬的攻擊日誌事件：")
    # 使用 ensure_ascii=False 來正確顯示非 ASCII 字符
    print(json.dumps(attack_event, indent=2, ensure_ascii=False))
    
    return attack_event

def verify_detection(attack_event: dict):
    """
    使用 SIEM 儀表板驗證攻擊是否被檢測到
    """
    print("\n正在使用 SIEM 儀表板驗證檢測...")
    
    # 1. 初始化 SOC 儀表板
    dashboard = SOCDashboard()
    print("SOC 儀表板已初始化。")
    print(f"已加載 {len(dashboard.rules)} 條規則。")
    
    # 2. 處理模擬的攻擊事件
    dashboard.process_event(attack_event)
    print("攻擊事件已提交至 SIEM 進行處理。")
    
    # 3. 檢查是否觸發了正確的警報
    alerts = dashboard.get_dashboard_data().get('recent_alerts', [])
    
    print(f"SIEM 產生了 {len(alerts)} 條警報。")
    
    detection_successful = False
    for alert in alerts:
        # 我們的 SIEM 規則 R005 專門用於此類攻擊
        if alert.get('rule_id') == 'R005':
            print("\n--- 檢測成功！ ---")
            print(f"觸發的規則 ID: {alert.get('rule_id')}")
            print(f"規則名稱: {alert.get('rule_name')}")
            print(f"嚴重性: {alert.get('severity')}")
            print("警報詳細資訊匹配 T1059.003 攻擊模擬。")
            detection_successful = True
            break
            
    if not detection_successful:
        print("\n--- 檢測失敗 ---")
        print("SIEM 未能觸發針對 T1059.003 的特定警報 (R005)。")
        print("請檢查 SIEM 規則配置或事件格式。")
        
    return detection_successful

def main():
    """
    主執行函數
    """
    print("======================================================")
    print("== Atomic Red Team T1059.003 模擬與檢測驗證腳本 ==")
    print("======================================================")
    
    # 步驟 1: 模擬攻擊
    event = simulate_t1059_003_attack()
    
    # 步驟 2: 驗證檢測
    success = verify_detection(event)
    
    print("\n------------------------------------------------------")
    if success:
        print("最終結果：成功 - 藍隊防禦系統按預期偵測到威脅。")
    else:
        print("最終結果：失敗 - 藍隊防禦系統未能偵測到威脅。")
    print("------------------------------------------------------")

if __name__ == "__main__":
    main()
