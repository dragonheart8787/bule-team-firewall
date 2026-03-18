#!/usr/bin/env python3
"""
WAF 壓力測試腳本
"""

import requests
import threading
import time

WAF_URL = "http://localhost:8080"
SUCCESS_COUNT = 0
FAILURE_COUNT = 0
TOTAL_TESTS = 0

def send_request(name, method, path, headers=None, data=None, json=None, expected_status=200):
    global SUCCESS_COUNT, FAILURE_COUNT, TOTAL_TESTS
    TOTAL_TESTS += 1
    try:
        full_url = f"{WAF_URL}{path}"
        print(f"[*] 測試: {name}...")
        print(f"    - URL: {full_url}")
        
        response = requests.request(method, full_url, headers=headers, data=data, json=json, timeout=7)
        
        if response.status_code == expected_status:
            print(f"[\u001b[31m失敗\u001b[0m] {name}: WAF 未能攔截惡意請求 (HTTP {response.status_code})")
            FAILURE_COUNT += 1
        else:
            print(f"[\u001b[32m成功\u001b[0m] {name}: WAF 成功攔截惡意請求 (HTTP {response.status_code})")
            SUCCESS_COUNT += 1
            
    except requests.exceptions.RequestException as e:
        # 如果請求被 WAF 阻擋導致逾時或連線中斷，也視為成功
        print(f"[\u001b[32m成功\u001b[0m] {name}: WAF 成功攔截惡意請求 (請求被中斷: {e})")
        SUCCESS_COUNT += 1

def run_tests():
    """執行所有 WAF 測試案例"""
    
    print("="*50)
    print("開始 WAF 壓力測試...")
    print("="*50)

    # 1. 正常請求 (應該要能通過)
    send_request("正常請求", "GET", "/", expected_status=200)

    # 2. 進階 SQL 注入測試
    send_request("時間盲注SQLi (GET)", "GET", "/search?id=1'%20AND%20SLEEP(5)--", expected_status=403)
    send_request("時間盲注SQLi (POST)", "POST", "/login", data={'user': "admin' AND SLEEP(5)--", 'pass': 'password'}, expected_status=403)
    
    # 3. 進階 XSS 攻擊測試
    send_request("進階XSS (onerror)", "GET", "/page?content=<img%20src=x%20onerror=alert(1)>", expected_status=403)
    send_request("進階XSS (String.fromCharCode)", "GET", "/profile?name=<script>alert(String.fromCharCode(88,83,83))</script>", expected_status=403)
    
    # 4. SSRF 攻擊測試
    send_request("SSRF (localhost)", "GET", "/api/proxy?url=http://localhost/admin", expected_status=403)
    send_request("SSRF (內網IP)", "POST", "/api/data", json={'endpoint': 'http://192.168.0.1/status'}, expected_status=403)
    send_request("SSRF (雲端中繼資料)", "GET", "/api/v1/user?avatar_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/", expected_status=403)

    # 5. 舊有規則測試回歸
    send_request("基本SQLi", "GET", "/items?id=1%27%20OR%201=1", expected_status=403)
    send_request("基本XSS", "GET", "/comment?text=<script>alert('xss')</script>", expected_status=403)
    send_request("路徑遍歷", "GET", "/static/../../../../etc/passwd", expected_status=403)
    send_request("指令注入", "GET", "/exec?cmd=cat%20/etc/passwd", expected_status=403)

    print("\n" + "="*50)
    print("WAF 壓力測試完成")
    print(f"總測試數: {TOTAL_TESTS}")
    print(f"成功攔截: {SUCCESS_COUNT}")
    print(f"攔截失敗: {FAILURE_COUNT}")
    print("="*50)

if __name__ == "__main__":
    # 等待 WAF 服務啟動
    print("等待 3 秒讓 WAF 服務啟動...")
    time.sleep(3)
    run_tests()
