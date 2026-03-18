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

def simulate_golden_ticket_attack():
    """
    模擬 ATT&CK T1558.001 - 黃金票據攻擊
    - 步驟: 模擬一台非網域控制站的主機，為一個特權帳戶請求了 krbtgt 的服務票據。
      在正常情況下，只有 DC 會為其他 DC 請求 krbtgt 票據。
    - 預期: 系統應產生一個 CRITICAL 等級的 R014 警報。
    """
    print("--- 執行 T1558.001 (黃金票據) 攻擊模擬 ---")
    dashboard = SOCDashboard()

    # 事件: 一台受感染的工作站 (192.168.1.105) 請求 krbtgt 票據
    attack_event = {
        'event_type': 'kerberos_ticket_request', # Windows Event ID 4769
        'timestamp': datetime.now().isoformat(),
        'hostname': 'DC-01', # 票據是由 DC 核發的
        'service_name': 'krbtgt/CORP.LOCAL', # 關鍵特徵
        'service_id': 'S-1-5-21-123456789-123456789-123456789-502',
        'client_ip': '192.168.1.105', # 請求來源 IP (非 DC)
        'account_name': 'compromised_admin@CORP.LOCAL',
        'result': 'success',
        'src_ip': '192.168.1.105' # 為了告警關聯
    }
    
    print(f"\n[+] 模擬事件: {json.dumps(attack_event, indent=2)}")
    dashboard.submit_event(attack_event)
    
    # 等待事件處理
    dashboard.event_queue.join()

    # 驗證結果
    alerts = dashboard.alerts
    r014_alerts = [alert for alert in alerts if alert['rule_id'] == 'R014']

    print("\n--- 驗證結果 ---")
    if len(r014_alerts) == 1:
        alert = r014_alerts[0]
        print(f"成功: 偵測到 T1558.001 攻擊！")
        print(f"   - 觸發規則: {alert['rule_name']} ({alert['rule_id']})")
        print(f"   - 嚴重性: {alert['severity']}")
        print(f"   - 事件詳情: 來自 {alert['event']['client_ip']} 的可疑 krbtgt 票據請求。")
        dashboard.shutdown()
        return True
    else:
        print(f"失敗: 未能正確偵測到 T1558.001 攻擊。")
        print(f"   - 預期觸發 1 次 R014 警報，但實際觸發了 {len(r014_alerts)} 次。")
        dashboard.shutdown()
        return False

if __name__ == "__main__":
    if simulate_golden_ticket_attack():
        print("\nT1558.001 模擬測試成功結束。")
    else:
        print("\nT1558.001 模擬測試失敗。")
        sys.exit(1)

