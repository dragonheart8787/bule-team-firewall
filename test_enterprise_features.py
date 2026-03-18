#!/usr/bin/env python3
"""
企業級 WAF 系統功能測試腳本
"""

import requests
import json
import time

def test_health_checks():
    """測試健康檢查端點"""
    print("測試健康檢查端點...")
    
    # WAF 健康檢查
    try:
        response = requests.get("http://localhost:8080/healthz", timeout=5)
        print(f"WAF 健康檢查: {response.status_code} - {response.json()}")
    except Exception as e:
        print(f"WAF 健康檢查失敗: {e}")
    
    # SIEM 健康檢查
    try:
        response = requests.get("http://localhost:8001/healthz", timeout=5)
        print(f"SIEM 健康檢查: {response.status_code} - {response.json()}")
    except Exception as e:
        print(f"SIEM 健康檢查失敗: {e}")

def test_metrics():
    """測試指標端點"""
    print("\n測試指標端點...")
    
    # WAF 指標
    try:
        response = requests.get("http://localhost:8080/metrics", timeout=5)
        print(f"WAF 指標: {response.json()}")
    except Exception as e:
        print(f"WAF 指標失敗: {e}")
    
    # SIEM 指標
    try:
        response = requests.get("http://localhost:8001/metrics", timeout=5)
        print(f"SIEM 指標: {response.json()}")
    except Exception as e:
        print(f"SIEM 指標失敗: {e}")

def test_blocklist_management():
    """測試封鎖名單管理"""
    print("\n測試封鎖名單管理...")
    
    # 查看當前封鎖清單
    try:
        response = requests.get("http://localhost:8080/api/blocklist", timeout=5)
        print(f"當前封鎖清單: {response.json()}")
    except Exception as e:
        print(f"獲取封鎖清單失敗: {e}")
    
    # 封鎖測試 IP
    test_ip = "192.168.1.200"
    try:
        response = requests.post("http://localhost:8080/api/blocklist", 
                               json={"ip": test_ip, "action": "block"}, 
                               timeout=5)
        print(f"封鎖 IP {test_ip}: {response.json()}")
    except Exception as e:
        print(f"封鎖 IP 失敗: {e}")
    
    # 驗證封鎖
    try:
        response = requests.get("http://localhost:8080/api/blocklist", timeout=5)
        blocked_ips = response.json().get("blocked_ips", [])
        if test_ip in blocked_ips:
            print(f"IP {test_ip} 已成功封鎖")
        else:
            print(f"IP {test_ip} 封鎖失敗")
    except Exception as e:
        print(f"驗證封鎖失敗: {e}")

def test_attack_detection():
    """測試攻擊檢測"""
    print("\n測試攻擊檢測...")
    
    # SQL 注入攻擊
    sql_payloads = [
        "1' OR '1'='1",
        "'; DROP TABLE users; --",
        "UNION SELECT * FROM users",
        "1' UNION SELECT password FROM users--"
    ]
    
    for payload in sql_payloads:
        try:
            response = requests.get(f"http://localhost:8080/search?query={payload}", 
                                 timeout=5, allow_redirects=False)
            if response.status_code == 403:
                print(f"SQL 注入檢測成功: {payload[:30]}...")
            else:
                print(f"SQL 注入檢測異常: {payload[:30]}... (狀態碼: {response.status_code})")
        except requests.exceptions.RequestException as e:
            print(f"SQL 注入被阻擋: {payload[:30]}... (連接被拒絕)")
        except Exception as e:
            print(f"測試失敗: {e}")
    
    # XSS 攻擊
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>"
    ]
    
    for payload in xss_payloads:
        try:
            response = requests.get(f"http://localhost:8080/search?query={payload}", 
                                 timeout=5, allow_redirects=False)
            if response.status_code == 403:
                print(f"XSS 檢測成功: {payload[:30]}...")
            else:
                print(f"XSS 檢測異常: {payload[:30]}... (狀態碼: {response.status_code})")
        except requests.exceptions.RequestException as e:
            print(f"XSS 被阻擋: {payload[:30]}... (連接被拒絕)")
        except Exception as e:
            print(f"測試失敗: {e}")

def test_normal_requests():
    """測試正常請求"""
    print("\n測試正常請求...")
    
    normal_requests = [
        "http://localhost:8080/search?query=test",
        "http://localhost:8080/search?query=hello",
        "http://localhost:5000/",
    ]
    
    for url in normal_requests:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                print(f"正常請求成功: {url}")
            else:
                print(f"正常請求異常: {url} (狀態碼: {response.status_code})")
        except Exception as e:
            print(f"正常請求失敗: {url} - {e}")

def test_siem_alerts():
    """測試 SIEM 警報"""
    print("\n測試 SIEM 警報...")
    
    try:
        response = requests.get("http://localhost:8001/alerts", timeout=5)
        alerts = response.json()
        print(f"SIEM 警報數量: {len(alerts)}")
        
        if alerts:
            print("最新警報:")
            for alert in alerts[:3]:  # 顯示前3個警報
                print(f"  - {alert.get('rule_name', 'Unknown')}: {alert.get('severity', 'Unknown')}")
        
    except Exception as e:
        print(f"SIEM 警報測試失敗: {e}")

def main():
    """主測試函數"""
    print("開始企業級 WAF 系統功能測試...\n")
    
    test_health_checks()
    test_metrics()
    test_blocklist_management()
    test_attack_detection()
    test_normal_requests()
    test_siem_alerts()
    
    print("\n測試完成！")
    print("\n系統狀態:")
    print("- WAF 代理: http://localhost:8080")
    print("- SIEM 引擎: http://localhost:8001")
    print("- 目標應用: http://localhost:5000")
    print("- 管理 API: http://localhost:8080/api/blocklist")

if __name__ == "__main__":
    main()
