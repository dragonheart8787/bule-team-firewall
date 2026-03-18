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

def simulate_container_escape_attack():
    """
    模擬 ATT&CK T1610 - 容器逃逸
    - 步驟: 模擬一個由容器 shim 行程產生的子程序，該子程序嘗試存取主機的敏感檔案。
    - 預期: 系統應產生一個 CRITICAL 等級的警報。
    """
    print("--- 執行 T1610 (容器逃逸) 攻擊模擬 ---")
    dashboard = SOCDashboard()

    # 事件: 容器內的程序嘗試讀取主機的 /etc/shadow
    attack_event = {
        'event_type': 'process_creation',
        'timestamp': datetime.now().isoformat(),
        'hostname': 'k8s-worker-node-01',
        'process_id': '8888',
        'process_name': 'cat',
        'command_line': 'cat /host_fs/etc/shadow',
        'parent_process_id': '7777',
        'parent_process_name': 'containerd-shim-runc-v2', # 關鍵特徵
        'user': 'root',
        'src_ip': '10.0.2.15' # 容器 Pod IP
    }
    
    print(f"\n[+] 模擬事件: 容器行程 '{attack_event['parent_process_name']}' 產生子程序 '{attack_event['command_line']}' (預期：R013 告警)")
    dashboard.process_event(attack_event)

    # 驗證結果
    alerts = dashboard.alerts
    r013_alerts = [alert for alert in alerts if alert['rule_id'] == 'R013']

    print("\n--- 驗證結果 ---")
    if len(r013_alerts) == 1:
        alert = r013_alerts[0]
        print(f"成功: 偵測到 T1610 攻擊！")
        print(f"   - 觸發規則: {alert['rule_name']} ({alert['rule_id']})")
        print(f"   - 嚴重性: {alert['severity']}")
        print(f"   - 事件詳情: 父程序 '{alert['event']['parent_process_name']}' 執行了可疑指令 '{alert['event']['command_line']}'")
        return True
    else:
        print(f"失敗: 未能正確偵測到 T1610 攻擊。")
        print(f"   - 預期觸發 1 次 R013 警報，但實際觸發了 {len(r013_alerts)} 次。")
        return False

if __name__ == "__main__":
    if simulate_container_escape_attack():
        print("\nT1610 模擬測試成功結束。")
    else:
        print("\nT1610 模擬測試失敗。")
        sys.exit(1)
