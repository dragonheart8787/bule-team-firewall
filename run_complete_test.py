#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整的測試運行腳本
自動啟動服務並運行所有測試
"""

import subprocess
import time
import sys
import os
import requests

def check_service(name, url, timeout=3):
    """檢查服務是否運行"""
    try:
        resp = requests.get(url, timeout=timeout)
        return resp.status_code == 200
    except:
        return False

def start_services():
    """啟動所有服務"""
    print("=" * 60)
    print("啟動所有服務...")
    print("=" * 60)
    print()
    
    # 停止現有進程
    print("[1/4] 停止現有服務...")
    os.system("taskkill /f /im python.exe >nul 2>&1")
    time.sleep(2)
    print("      完成！")
    print()
    
    # 啟動 Target App
    print("[2/4] 啟動 Target App (Port 5000)...")
    subprocess.Popen(["python", "target_app_high_performance.py"], 
                     creationflags=subprocess.CREATE_NEW_CONSOLE)
    time.sleep(3)
    print("      完成！")
    print()
    
    # 啟動 SIEM
    print("[3/4] 啟動 SIEM Dashboard (Port 8001)...")
    subprocess.Popen(["python", "siem_dashboards.py"],
                     creationflags=subprocess.CREATE_NEW_CONSOLE)
    time.sleep(3)
    print("      完成！")
    print()
    
    # 啟動 WAF
    print("[4/4] 啟動 WAF Proxy (Port 8080)...")
    subprocess.Popen(["python", "waf_proxy_final_solution.py"],
                     creationflags=subprocess.CREATE_NEW_CONSOLE)
    time.sleep(3)
    print("      完成！")
    print()
    
    # 等待服務就緒
    print("等待服務就緒...")
    max_retries = 10
    for i in range(max_retries):
        if (check_service("Target", "http://localhost:5000/") and
            check_service("SIEM", "http://localhost:8001/healthz") and
            check_service("WAF", "http://localhost:8080/health")):
            print("[OK] 所有服務已就緒！")
            return True
        time.sleep(2)
        print(f"  等待中... ({i+1}/{max_retries})")
    
    print("[WARN] 部分服務可能未就緒，繼續測試...")
    return False

def run_quick_test():
    """運行快速測試"""
    print()
    print("=" * 60)
    print("運行快速測試...")
    print("=" * 60)
    print()
    
    result = subprocess.run(["python", "quick_test_suite.py"], 
                          capture_output=False)
    return result.returncode == 0

def run_advanced_test():
    """運行進階測試"""
    print()
    print("=" * 60)
    print("運行進階測試...")
    print("=" * 60)
    print()
    
    result = subprocess.run(["python", "advanced_test_methods.py"],
                          capture_output=False)
    return result.returncode == 0

def main():
    print("\n")
    print("=" * 60)
    print("WAF 系統完整測試")
    print("=" * 60)
    print()
    
    # 啟動服務
    if not start_services():
        print("[WARN] 服務啟動可能不完整")
    
    # 運行測試
    quick_ok = run_quick_test()
    advanced_ok = run_advanced_test()
    
    # 顯示結果
    print()
    print("=" * 60)
    print("測試完成！")
    print("=" * 60)
    print(f"快速測試: {'[PASS]' if quick_ok else '[FAIL]'}")
    print(f"進階測試: {'[PASS]' if advanced_ok else '[FAIL]'}")
    print("=" * 60)
    print()
    
    return 0 if (quick_ok and advanced_ok) else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[中斷] 測試被用戶中斷")
        sys.exit(1)


