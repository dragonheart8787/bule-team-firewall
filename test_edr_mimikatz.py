import sys
import os
import time
from datetime import datetime
import json

try:
    script_path = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_path)
    sys.path.append(os.getcwd())
except Exception as e:
    print(f"[*] 更改工作目錄時出錯: {e}")

from siem_dashboards import SOCDashboard, WAFControlInterface

def simulate_edr_mimikatz_detection_and_soar_response():
    """
    模擬 ATT&CK T1003.001 - OS Credential Dumping (Mimikatz)
    - 步驟: 模擬一台受感染主機上的 EDR Agent 偵測到 'mimikatz.exe' 執行。
      EDR Agent 立即將此事件回傳給 SIEM。
    - 預期:
      1. SIEM 應產生一個 CRITICAL 等級的 R017 警報。
      2. 該警報應觸發 SOAR Playbook 'PB001_BLOCK_IP_AT_WAF'。
      3. 攻擊者的 IP (192.168.1.105) 應被添加到 WAF 的封鎖清單中。
    """
    print("--- 執行 T1003.001 (Mimikatz) EDR 偵測與 SOAR 回應模擬 ---")
    dashboard = SOCDashboard()
    waf_api = WAFControlInterface() # 獲取 WAF API 的實例以供驗證

    # 清空之前的封鎖紀錄以便測試
    waf_api.blocked_ips.clear()

    # 事件: EDR Agent 在 'WS-COMPROMISED' 上偵測到 Mimikatz
    attack_event = {
        'event_type': 'edr_alert',
        'timestamp': datetime.now().isoformat(),
        'hostname': 'WS-COMPROMISED',
        'process_name': 'mimikatz.exe',
        'process_id': '1337',
        'command_line': 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"',
        'user': 'CORP\\victim',
        'src_ip': '192.168.1.105'
    }
    
    print(f"\n[+] 模擬 EDR 事件: {json.dumps(attack_event, indent=2)}")
    dashboard.submit_event(attack_event)
    
    # 等待事件處理
    dashboard.event_queue.join()
    time.sleep(1) # 給予 SOAR Playbook 一點執行時間

    # 驗證結果
    alerts = dashboard.alerts
    r017_alerts = [alert for alert in alerts if alert['rule_id'] == 'R017']
    blocked_ips = waf_api.get_blocked_ips()
    
    print("\n--- 驗證結果 ---")
    alert_triggered = len(r017_alerts) == 1
    ip_blocked = '192.168.1.105' in blocked_ips

    if alert_triggered:
        print(f"成功: 偵測到 Mimikatz 執行！")
        print(f"   - 觸發規則: {r017_alerts[0]['rule_name']} ({r017_alerts[0]['rule_id']})")
    else:
        print(f"失敗: 未能正確偵測到 Mimikatz 執行。")

    if ip_blocked:
        print(f"成功: SOAR Playbook 已自動封鎖攻擊者 IP！")
        print(f"   - WAF 封鎖清單: {blocked_ips}")
    else:
        print(f"失敗: SOAR Playbook 未能成功封鎖攻擊者 IP。")

    dashboard.shutdown()

    if alert_triggered and ip_blocked:
        return True
    else:
        return False

if __name__ == "__main__":
    if simulate_edr_mimikatz_detection_and_soar_response():
        print("\nT1003.001 EDR 偵測與 SOAR 回應模擬測試成功結束。")
    else:
        print("\nT1003.001 EDR 偵測與 SOAR 回應模擬測試失敗。")
        sys.exit(1)

