#!/usr/bin/env python3
"""
真正穩定版測試
驗證穩定性問題是否已解決
"""

import requests
import time
import json
from datetime import datetime

def test_rock_solid():
    """測試真正穩定版系統"""
    print("測試真正穩定版系統...")
    print("=" * 50)
    
    # 測試服務狀態
    print("1. 測試服務狀態...")
    services = [
        ('目標應用', 'http://localhost:5000/'),
        ('SIEM', 'http://localhost:8001/healthz'),
        ('WAF', 'http://localhost:8080/healthz')
    ]
    
    for name, url in services:
        try:
            response = requests.get(url, timeout=5)
            print(f"  {name}: {response.status_code} - {response.elapsed.total_seconds():.3f}s")
        except Exception as e:
            print(f"  {name}: ERROR - {e}")
    
    print("\n2. 測試 WAF 保護功能...")
    
    # 測試管理員路徑
    admin_paths = ['/admin', '/administrator', '/wp-admin', '/phpmyadmin']
    blocked_count = 0
    
    for path in admin_paths:
        try:
            response = requests.get(f"http://localhost:8080{path}", timeout=3)
            blocked = response.status_code == 403
            if blocked:
                blocked_count += 1
            print(f"  {path}: {response.status_code} {'[BLOCKED]' if blocked else '[ALLOWED]'}")
        except Exception as e:
            print(f"  {path}: ERROR - {e}")
    
    # 測試 SQL 注入
    sql_payloads = ["1' OR '1'='1", "'; DROP TABLE users; --"]
    for payload in sql_payloads:
        try:
            response = requests.get(f"http://localhost:8080/?id={payload}", timeout=3)
            blocked = response.status_code == 403
            if blocked:
                blocked_count += 1
            print(f"  SQL注入 '{payload}': {response.status_code} {'[BLOCKED]' if blocked else '[ALLOWED]'}")
        except Exception as e:
            print(f"  SQL注入 '{payload}': ERROR - {e}")
    
    # 測試 XSS
    xss_payloads = ["<script>alert('XSS')</script>", "javascript:alert('XSS')"]
    for payload in xss_payloads:
        try:
            response = requests.get(f"http://localhost:8080/?search={payload}", timeout=3)
            blocked = response.status_code == 403
            if blocked:
                blocked_count += 1
            print(f"  XSS '{payload}': {response.status_code} {'[BLOCKED]' if blocked else '[ALLOWED]'}")
        except Exception as e:
            print(f"  XSS '{payload}': ERROR - {e}")
    
    total_tests = len(admin_paths) + len(sql_payloads) + len(xss_payloads)
    protection_rate = (blocked_count / total_tests * 100) if total_tests > 0 else 0
    
    print(f"\n保護率: {protection_rate:.1f}% ({blocked_count}/{total_tests})")
    
    print("\n3. 測試穩定性（連續請求）...")
    
    # 連續請求測試
    success_count = 0
    total_requests = 20
    
    for i in range(total_requests):
        try:
            response = requests.get("http://localhost:8080/", timeout=3)
            if response.status_code == 200:
                success_count += 1
            print(f"  穩定性測試 {i+1}/{total_requests}: {response.status_code}")
        except Exception as e:
            print(f"  穩定性測試 {i+1}/{total_requests}: ERROR - {e}")
    
    stability_rate = (success_count / total_requests * 100) if total_requests > 0 else 0
    print(f"\n穩定性: {stability_rate:.1f}% ({success_count}/{total_requests})")
    
    print("\n4. 測試管理員路徑阻擋...")
    
    # 專門測試管理員路徑
    admin_test_paths = [
        '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
        '/backend', '/management', '/dashboard', '/system',
        '/config', '/settings', '/logs', '/backup', '/security'
    ]
    
    admin_blocked_count = 0
    for path in admin_test_paths:
        try:
            response = requests.get(f"http://localhost:8080{path}", timeout=3)
            blocked = response.status_code == 403
            if blocked:
                admin_blocked_count += 1
            print(f"  {path}: {response.status_code} {'[BLOCKED]' if blocked else '[ALLOWED]'}")
        except Exception as e:
            print(f"  {path}: ERROR - {e}")
    
    admin_protection_rate = (admin_blocked_count / len(admin_test_paths) * 100) if admin_test_paths else 0
    print(f"\n管理員路徑保護率: {admin_protection_rate:.1f}% ({admin_blocked_count}/{len(admin_test_paths)})")
    
    print("\n5. 測試 SIEM 整合...")
    
    siem_endpoints = ['/healthz', '/status', '/alerts', '/dashboard', '/metrics', '/slo']
    successful_endpoints = 0
    
    for endpoint in siem_endpoints:
        try:
            response = requests.get(f"http://localhost:8001{endpoint}", timeout=5)
            if response.status_code == 200:
                successful_endpoints += 1
            print(f"  {endpoint}: {response.status_code}")
        except Exception as e:
            print(f"  {endpoint}: ERROR - {e}")
    
    siem_success_rate = (successful_endpoints / len(siem_endpoints) * 100) if siem_endpoints else 0
    print(f"\nSIEM 成功率: {siem_success_rate:.1f}% ({successful_endpoints}/{len(siem_endpoints)})")
    
    # 總體評估
    print("\n" + "=" * 50)
    print("總體評估:")
    print(f"WAF 保護率: {protection_rate:.1f}%")
    print(f"管理員路徑保護率: {admin_protection_rate:.1f}%")
    print(f"系統穩定性: {stability_rate:.1f}%")
    print(f"SIEM 成功率: {siem_success_rate:.1f}%")
    
    # 更嚴格的評估標準
    if (protection_rate >= 80 and 
        admin_protection_rate >= 80 and 
        stability_rate >= 90 and 
        siem_success_rate >= 80):
        print("總體狀態: [SUCCESS] 系統運行良好，穩定性問題已解決！")
        return True
    else:
        print("總體狀態: [FAILURE] 仍有問題需要解決")
        return False

if __name__ == "__main__":
    test_rock_solid()




