#!/usr/bin/env python3
"""
調試 WAF 規則檢查邏輯
找出為什麼管理員路徑沒有被阻擋
"""

import re

def debug_admin_path_detection():
    """調試管理員路徑檢測"""
    print("調試管理員路徑檢測...")
    print("=" * 50)
    
    # 模擬 WAF 中的管理員路徑列表
    admin_paths = [
        '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
        '/backend', '/management', '/dashboard', '/system',
        '/config', '/settings', '/logs', '/backup', '/security',
        '/api/admin', '/admin/api'
    ]
    
    # 測試路徑
    test_paths = [
        '/admin',
        '/administrator', 
        '/wp-admin',
        '/phpmyadmin',
        '/backend',
        '/management',
        '/dashboard',
        '/system',
        '/config',
        '/settings',
        '/logs',
        '/backup',
        '/security',
        '/api/admin',
        '/admin/api',
        '/normal/path',
        '/user/profile'
    ]
    
    print("1. 測試直接字符串匹配...")
    for path in test_paths:
        if path in admin_paths:
            print(f"  {path} -> MATCH (直接匹配)")
        else:
            print(f"  {path} -> NO MATCH")
    
    print("\n2. 測試正則表達式匹配...")
    # 模擬 WAF 中的正則表達式檢查
    for path in test_paths:
        matched = False
        for admin_path in admin_paths:
            # 模擬 WAF 中的檢查邏輯
            if admin_path == path:  # 直接匹配
                matched = True
                break
            elif admin_path.startswith('/') and path.startswith(admin_path):  # 前綴匹配
                matched = True
                break
        
        if matched:
            print(f"  {path} -> MATCH (正則匹配)")
        else:
            print(f"  {path} -> NO MATCH")
    
    print("\n3. 測試 WAF 請求處理邏輯...")
    # 模擬 WAF 中的請求處理
    for path in test_paths:
        print(f"\n處理請求: GET {path}")
        
        # 檢查管理員路徑
        is_admin = path in admin_paths
        print(f"  管理員路徑檢查: {is_admin}")
        
        if is_admin:
            print(f"  -> 應該返回 403 BLOCKED")
        else:
            print(f"  -> 應該轉發到後端")
    
    print("\n4. 測試實際的 WAF 響應...")
    import requests
    
    for path in test_paths[:5]:  # 只測試前5個
        try:
            response = requests.get(f"http://localhost:8080{path}", timeout=3)
            print(f"  {path}: {response.status_code} {'[BLOCKED]' if response.status_code == 403 else '[ALLOWED]'}")
        except Exception as e:
            print(f"  {path}: ERROR - {e}")

def debug_waf_service():
    """調試 WAF 服務狀態"""
    print("\n調試 WAF 服務狀態...")
    print("=" * 50)
    
    import requests
    
    # 測試健康檢查
    try:
        response = requests.get("http://localhost:8080/healthz", timeout=5)
        print(f"健康檢查: {response.status_code}")
        if response.status_code == 200:
            print(f"響應: {response.json()}")
    except Exception as e:
        print(f"健康檢查失敗: {e}")
        return
    
    # 測試正常請求
    try:
        response = requests.get("http://localhost:8080/", timeout=5)
        print(f"正常請求: {response.status_code}")
        print(f"響應時間: {response.elapsed.total_seconds():.3f}s")
    except Exception as e:
        print(f"正常請求失敗: {e}")
    
    # 測試管理員路徑
    admin_paths = ['/admin', '/administrator', '/wp-admin', '/phpmyadmin']
    
    for path in admin_paths:
        try:
            response = requests.get(f"http://localhost:8080{path}", timeout=5)
            print(f"{path}: {response.status_code} {'[BLOCKED]' if response.status_code == 403 else '[ALLOWED]'}")
            if response.status_code == 403:
                try:
                    error_data = response.json()
                    print(f"  錯誤信息: {error_data}")
                except:
                    print(f"  錯誤信息: {response.text}")
        except Exception as e:
            print(f"{path}: ERROR - {e}")

if __name__ == "__main__":
    debug_admin_path_detection()
    debug_waf_service()




