import sys
import os
from datetime import datetime
import json

try:
    script_path = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_path)
    sys.path.append(os.getcwd())
except Exception as e:
    print(f"[*] 更改工作目錄時出錯: {e}")

from siem_dashboards import SOCDashboard

def simulate_pass_the_hash_attack():
    """
    模擬 ATT&CK T1550.002 - 哈希傳遞攻擊
    - 步驟: 模擬一個成功的遠端登入事件，該事件使用 NTLM 進行身份驗證，
      且 Logon Type 為 9 (NewCredentials)。這通常是 PtH 工具 (如 Mimikatz) 的特徵。
    - 預期: 系統應產生一個 HIGH 等級的 R015 警報。
    """
    print("--- 執行 T1550.002 (哈希傳遞) 攻擊模擬 ---")
    dashboard = SOCDashboard()

    # 事件: 使用 PtH 成功登入一台檔案伺服器
    attack_event = {
        'event_type': 'authentication_success', # Windows Event ID 4624
        'timestamp': datetime.now().isoformat(),
        'hostname': 'FILE-SRV-01', # 攻擊目標主機
        'logon_type': 9, # 關鍵特徵: NewCredentials
        'authentication_package': 'NTLM', # 關鍵特徵
        'account_name': 'ADMINISTRATOR',
        'source_ip': '192.168.1.105', # 攻擊來源
        'workstation_name': 'ATTACKER-WS',
        'result': 'success',
        'src_ip': '192.168.1.105' # 為了告警關聯
    }
    
    print(f"\n[+] 模擬事件: {json.dumps(attack_event, indent=2)}")
    dashboard.submit_event(attack_event)
    
    # 等待事件處理
    dashboard.event_queue.join()

    # 驗證結果
    alerts = dashboard.alerts
    r015_alerts = [alert for alert in alerts if alert['rule_id'] == 'R015']

    print("\n--- 驗證結果 ---")
    if len(r015_alerts) == 1:
        alert = r015_alerts[0]
        print(f"成功: 偵測到 T1550.002 攻擊！")
        print(f"   - 觸發規則: {alert['rule_name']} ({alert['rule_id']})")
        print(f"   - 嚴重性: {alert['severity']}")
        print(f"   - 事件詳情: 偵測到來自 {alert['event']['source_ip']} 的可疑 NTLM 遠端登入 (LogonType 9)。")
        dashboard.shutdown()
        return True
    else:
        print(f"失敗: 未能正確偵測到 T1550.002 攻擊。")
        print(f"   - 預期觸發 1 次 R015 警報，但實際觸發了 {len(r015_alerts)} 次。")
        dashboard.shutdown()
        return False

if __name__ == "__main__":
    if simulate_pass_the_hash_attack():
        print("\nT1550.002 模擬測試成功結束。")
    else:
        print("\nT1550.002 模擬測試失敗。")
        sys.exit(1)

