#!/usr/bin/env python3
"""
直接測試 WAF 功能
"""

import requests
import time
import json

def test_waf_direct():
    """直接測試 WAF"""
    print("直接測試 WAF 功能...")
    print("=" * 40)
    
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
    
    # 測試 SQL 注入
    try:
        response = requests.get("http://localhost:8080/?id=1' OR '1'='1", timeout=5)
        print(f"SQL 注入測試: {response.status_code} {'[BLOCKED]' if response.status_code == 403 else '[ALLOWED]'}")
    except Exception as e:
        print(f"SQL 注入測試失敗: {e}")

if __name__ == "__main__":
    test_waf_direct()




