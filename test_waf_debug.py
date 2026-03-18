#!/usr/bin/env python3
"""
WAF 調試測試腳本
"""

import requests
import json

def test_waf_debug():
    """測試 WAF 並顯示詳細信息"""
    print("測試 WAF 調試...")
    
    # 測試健康檢查
    try:
        response = requests.get("http://localhost:8080/healthz", timeout=5)
        print(f"健康檢查: {response.status_code} - {response.json()}")
    except Exception as e:
        print(f"健康檢查失敗: {e}")
        return
    
    # 測試正常請求
    try:
        print("\n測試正常請求...")
        response = requests.get("http://localhost:8080/search?query=test", timeout=5)
        print(f"正常請求: {response.status_code}")
        print(f"內容: {response.text[:200]}")
    except requests.exceptions.RequestException as e:
        print(f"正常請求被阻擋: {e}")
    
    # 測試攻擊請求
    try:
        print("\n測試攻擊請求...")
        response = requests.get("http://localhost:8080/search?query=1' OR '1'='1", timeout=5)
        print(f"攻擊請求: {response.status_code}")
        if response.status_code == 403:
            print("攻擊被成功阻擋!")
        else:
            print(f"攻擊未被阻擋: {response.text[:200]}")
    except requests.exceptions.RequestException as e:
        print(f"攻擊請求被阻擋: {e}")
    
    # 測試指標
    try:
        print("\n測試指標...")
        response = requests.get("http://localhost:8080/metrics", timeout=5)
        print(f"指標: {response.json()}")
    except Exception as e:
        print(f"指標失敗: {e}")

if __name__ == "__main__":
    test_waf_debug()

