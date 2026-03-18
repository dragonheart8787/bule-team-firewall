#!/usr/bin/env python3
"""
診斷腳本 - 找出具體問題
"""

import requests
import time
import json
from datetime import datetime

def test_admin_paths():
    """測試管理員路徑檢測"""
    print("測試管理員路徑檢測...")
    print("=" * 40)
    
    admin_paths = [
        '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
        '/backend', '/management', '/dashboard', '/system',
        '/config', '/settings', '/logs', '/backup', '/security',
        '/api/admin', '/admin/api'
    ]
    
    results = []
    for path in admin_paths:
        try:
            response = requests.get(f"http://localhost:8080{path}", timeout=3)
            blocked = response.status_code == 403
            results.append({
                'path': path,
                'status_code': response.status_code,
                'blocked': blocked,
                'response_time': response.elapsed.total_seconds()
            })
            print(f"{path:<20} -> {response.status_code} {'[BLOCKED]' if blocked else '[ALLOWED]'}")
        except Exception as e:
            results.append({'path': path, 'error': str(e)})
            print(f"{path:<20} -> ERROR: {e}")
    
    blocked_count = sum(1 for r in results if r.get('blocked', False))
    total_count = len(results)
    protection_rate = (blocked_count / total_count * 100) if total_count > 0 else 0
    
    print(f"\n保護率: {protection_rate:.1f}% ({blocked_count}/{total_count})")
    return results

def test_performance():
    """測試性能"""
    print("\n測試性能...")
    print("=" * 40)
    
    response_times = []
    errors = []
    
    for i in range(10):
        try:
            start = time.time()
            response = requests.get("http://localhost:8080/", timeout=5)
            end = time.time()
            
            response_time = end - start
            response_times.append(response_time)
            
            print(f"請求 {i+1}: {response.status_code} - {response_time:.3f}s")
            
        except Exception as e:
            errors.append(str(e))
            print(f"請求 {i+1}: ERROR - {e}")
    
    if response_times:
        avg_time = sum(response_times) / len(response_times)
        max_time = max(response_times)
        min_time = min(response_times)
        
        print(f"\n性能統計:")
        print(f"  平均響應時間: {avg_time:.3f}s")
        print(f"  最小響應時間: {min_time:.3f}s")
        print(f"  最大響應時間: {max_time:.3f}s")
        print(f"  錯誤數: {len(errors)}")
        
        if avg_time > 2.0:
            print("  [WARNING] 響應時間過高")
        if len(errors) > 0:
            print("  [WARNING] 有請求錯誤")
    else:
        print("  [ERROR] 沒有成功的請求")

def test_services():
    """測試服務狀態"""
    print("測試服務狀態...")
    print("=" * 40)
    
    services = [
        ('目標應用', 'http://localhost:5000/'),
        ('SIEM', 'http://localhost:8001/healthz'),
        ('WAF', 'http://localhost:8080/healthz')
    ]
    
    for name, url in services:
        try:
            response = requests.get(url, timeout=5)
            print(f"{name}: {response.status_code} - {response.elapsed.total_seconds():.3f}s")
        except Exception as e:
            print(f"{name}: ERROR - {e}")

def main():
    """主函數"""
    print("開始診斷...")
    print("=" * 60)
    
    # 測試服務狀態
    test_services()
    
    # 測試管理員路徑
    admin_results = test_admin_paths()
    
    # 測試性能
    test_performance()
    
    print("\n診斷完成！")

if __name__ == "__main__":
    main()




