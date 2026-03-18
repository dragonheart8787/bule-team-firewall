import sys
import os
import time
from datetime import datetime
import json
import random

try:
    script_path = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_path)
    sys.path.append(os.getcwd())
except Exception as e:
    print(f"[*] 更改工作目錄時出錯: {e}")

from siem_dashboards import SOCDashboard

def simulate_c2_beaconing_attack():
    """
    模擬 ATT&CK T1071.001 - C2 心跳包攻擊
    - 步驟: 模擬從一台受感染主機，以固定的時間間隔 (5秒 + 微小抖動) 向外部 C2 伺服器發送網路連線。
    - 預期: 狀態化偵測引擎 (R016) 應該能在累積足夠的樣本後 (預設10次)，
      識別出這種規律的 "心跳" 模式並產生一個 MEDIUM 等級的警報。
    """
    print("--- 執行 T1071.001 (C2 心跳包) 攻擊模擬 ---")
    dashboard = SOCDashboard()

    src_ip = "192.168.1.105"
    dest_ip = "1.2.3.4" # 模擬的外部 C2 伺服器
    interval = 5.0 # 5 秒心跳間隔
    jitter = 0.5   # 0.5 秒抖動
    beacon_count = 12 # 發送12次心跳包

    print(f"\n[+] 將在 {beacon_count * interval:.0f} 秒內，模擬 {beacon_count} 次從 {src_ip} 到 {dest_ip} 的心跳包...")

    for i in range(beacon_count):
        attack_event = {
            'event_type': 'network_connection',
            'timestamp': datetime.now().isoformat(),
            'hostname': 'ATTACKER-WS',
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'dest_port': 443,
            'protocol': 'TCP',
            'process_name': 'rundll32.exe', # 偽裝成系統程序
        }
        
        print(f"  -  發送心跳包 #{i+1} at {attack_event['timestamp']}")
        dashboard.submit_event(attack_event)
        
        # 模擬固定的時間間隔 + 抖動
        sleep_time = interval + random.uniform(-jitter, jitter)
        time.sleep(sleep_time)

    # 等待事件處理
    print("\n[+] 心跳包發送完畢，等待 SIEM 處理...")
    dashboard.event_queue.join()
    # 給予關聯規則額外的處理時間
    time.sleep(2)

    # 驗證結果
    alerts = dashboard.alerts
    r016_alerts = [alert for alert in alerts if alert['rule_id'] == 'R016']

    print("\n--- 驗證結果 ---")
    if len(r016_alerts) == 1:
        alert = r016_alerts[0]
        print(f"成功: 偵測到 T1071.001 C2 心跳包攻擊！")
        print(f"   - 觸發規則: {alert['rule_name']} ({alert['rule_id']})")
        print(f"   - 嚴重性: {alert['severity']}")
        details = alert['event']
        print(f"   - 事件詳情: 偵測到從 {details['src_ip']} 到 {details['dest_ip']} 的 {details['connection_count']} 次規律連線。")
        print(f"   - 平均間隔: {details['average_interval']}秒, 變異數: {details['interval_variance']}")
        dashboard.shutdown()
        return True
    else:
        print(f"失敗: 未能正確偵測到 T1071.001 C2 心跳包攻擊。")
        print(f"   - 預期觸發 1 次 R016 警報，但實際觸發了 {len(r016_alerts)} 次。")
        dashboard.shutdown()
        return False

if __name__ == "__main__":
    if simulate_c2_beaconing_attack():
        print("\nT1071.001 模擬測試成功結束。")
    else:
        print("\nT1071.001 模擬測試失敗。")
        sys.exit(1)

