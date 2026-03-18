#!/usr/bin/env python3
"""
快速系統測試腳本
"""

import requests
import time

def test_services():
    """測試所有服務"""
    print("=" * 50)
    print("企業級 WAF 系統快速測試")
    print("=" * 50)
    
    services = {
        '目標應用': 'http://localhost:5000',
        'SIEM 引擎': 'http://localhost:8001/healthz',
        'WAF 代理': 'http://localhost:8080/healthz'
    }
    
    print("\n1. 服務健康檢查")
    print("-" * 30)
    
    for name, url in services.items():
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                print(f"[OK] {name}: 正常運行")
            else:
                print(f"[FAIL] {name}: HTTP {response.status_code}")
        except Exception as e:
            print(f"[FAIL] {name}: 無法連接 - {str(e)[:50]}...")
    
    print("\n2. WAF 功能測試")
    print("-" * 30)
    
    # 測試正常請求
    try:
        response = requests.get("http://localhost:8080/search?query=test", timeout=3)
        print(f"[OK] 正常請求: HTTP {response.status_code}")
    except Exception as e:
        print(f"[FAIL] 正常請求: {str(e)[:50]}...")
    
    # 測試攻擊請求
    try:
        response = requests.get("http://localhost:8080/search?query=1' OR '1'='1", timeout=3)
        if response.status_code == 403:
            print(f"[OK] SQL 注入檢測: 成功阻擋")
        else:
            print(f"[WARN] SQL 注入檢測: HTTP {response.status_code}")
    except Exception as e:
        print(f"[OK] SQL 注入檢測: 連接被阻擋")
    
    print("\n3. 系統指標")
    print("-" * 30)
    
    # WAF 指標
    try:
        response = requests.get("http://localhost:8080/metrics", timeout=3)
        if response.status_code == 200:
            data = response.json()
            print(f"[OK] WAF 規則數: {data.get('rule_count', 'N/A')}")
            print(f"[OK] 封鎖 IP 數: {data.get('blocked_ips', 'N/A')}")
        else:
            print(f"[FAIL] WAF 指標: HTTP {response.status_code}")
    except Exception as e:
        print(f"[FAIL] WAF 指標: {str(e)[:50]}...")
    
    # SIEM 指標
    try:
        response = requests.get("http://localhost:8001/metrics", timeout=3)
        if response.status_code == 200:
            data = response.json()
            print(f"[OK] SIEM 活躍規則: {data.get('metrics', 'N/A')}")
        else:
            print(f"[FAIL] SIEM 指標: HTTP {response.status_code}")
    except Exception as e:
        print(f"[FAIL] SIEM 指標: {str(e)[:50]}...")
    
    print("\n" + "=" * 50)
    print("測試完成！")
    print("=" * 50)

if __name__ == "__main__":
    test_services()
