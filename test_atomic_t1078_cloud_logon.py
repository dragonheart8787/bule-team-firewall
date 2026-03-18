import sys
import os
from datetime import datetime

# 確保可以從根目錄導入 siem_dashboards
try:
    script_path = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_path)
    sys.path.append(os.getcwd())
except Exception as e:
    print(f"[*] 更改工作目錄時出錯: {e}")

from siem_dashboards import SOCDashboard

def simulate_cloud_logon_anomaly_attack():
    """
    模擬 ATT&CK T1078 - 有效帳號（雲端登入異常）
    - 步驟1: 一個正常使用者從他們的常見國家登入。
    - 步驟2: 同一個使用者短時間內從一個從未見過的國家登入。
    - 步驟3: 系統應該只針對第二次登入產生警報。
    """
    print("--- 執行 T1078 (雲端登入異常) 攻擊模擬 ---")
    dashboard = SOCDashboard()

    # 為了測試，我們手動清空狀態追蹤器
    dashboard._cloud_logon_tracker.clear()

    user = "cloud_admin@example.com"

    # 事件1: 正常登入 (基準線)
    event1 = {
        'event_type': 'cloud_console_login',
        'timestamp': datetime.now().isoformat(),
        'user': {'name': user},
        'source': {'ip': '73.15.199.34', 'geo': {'country': 'USA'}},
        'result': 'success',
        'src_ip': '73.15.199.34' # 為了告警關聯
    }
    print(f"\n[+] 模擬事件1: 使用者 '{user}' 從 'USA' 成功登入 (預期：無告警)")
    dashboard.process_event(event1)

    # 事件2: 異常登入
    event2 = {
        'event_type': 'cloud_console_login',
        'timestamp': datetime.now().isoformat(),
        'user': {'name': user},
        'source': {'ip': '91.207.175.82', 'geo': {'country': 'Russia'}},
        'result': 'success',
        'src_ip': '91.207.175.82'
    }
    print(f"[+] 模擬事件2: 使用者 '{user}' 從 'Russia' 成功登入 (預期：R012 告警)")
    dashboard.process_event(event2)

    # 事件3: 再次從正常地點登入
    event3 = {
        'event_type': 'cloud_console_login',
        'timestamp': datetime.now().isoformat(),
        'user': {'name': user},
        'source': {'ip': '73.15.199.35', 'geo': {'country': 'USA'}},
        'result': 'success',
        'src_ip': '73.15.199.35'
    }
    print(f"[+] 模擬事件3: 使用者 '{user}' 再次從 'USA' 成功登入 (預期：無告警)")
    dashboard.process_event(event3)

    # 驗證結果
    alerts = dashboard.alerts
    r012_alerts = [alert for alert in alerts if alert['rule_id'] == 'R012']

    print("\n--- 驗證結果 ---")
    if len(r012_alerts) == 1:
        alert = r012_alerts[0]
        print(f"成功: 偵測到 T1078 攻擊！")
        print(f"   - 觸發規則: {alert['rule_name']} ({alert['rule_id']})")
        print(f"   - 嚴重性: {alert['severity']}")
        print(f"   - 事件詳情: 使用者 '{alert['event']['user']}' 從新國家 '{alert['event']['new_country']}' 登入。")
        print(f"   - 已知國家: {alert['event']['known_countries']}")
        return True
    else:
        print(f"失敗: 未能正確偵測到 T1078 攻擊。")
        print(f"   - 預期觸發 1 次 R012 警報，但實際觸發了 {len(r012_alerts)} 次。")
        return False

if __name__ == "__main__":
    if simulate_cloud_logon_anomaly_attack():
        print("\nT1078 模擬測試成功結束。")
    else:
        print("\nT1078 模擬測試失敗。")
        sys.exit(1)
