#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
服務健康檢查腳本
快速檢查所有服務是否正常運行
"""

import requests
import time
import sys

def check_service(name, url, timeout=3):
    """檢查服務狀態"""
    try:
        start = time.time()
        resp = requests.get(url, timeout=timeout)
        elapsed = time.time() - start
        status = "[OK]" if resp.status_code == 200 else f"[WARN-{resp.status_code}]"
        print(f"  {status} {name}: {resp.status_code} ({elapsed:.3f}s)")
        return resp.status_code == 200
    except requests.exceptions.Timeout:
        print(f"  [TIMEOUT] {name}: 請求超時（>{timeout}s）")
        return False
    except requests.exceptions.ConnectionError:
        print(f"  [DOWN] {name}: 服務未運行")
        return False
    except Exception as e:
        print(f"  [ERROR] {name}: {str(e)[:50]}")
        return False

def main():
    print("=" * 60)
    print("服務健康檢查")
    print("=" * 60)
    print()
    
    services = [
        ("Target App", "http://localhost:5000/"),
        ("SIEM Health", "http://localhost:8001/healthz"),
        ("WAF Health", "http://localhost:8080/health"),
        ("WAF Status", "http://localhost:8080/status"),
    ]
    
    results = []
    for name, url in services:
        results.append(check_service(name, url))
    
    print()
    print("=" * 60)
    healthy = sum(results)
    total = len(results)
    
    if healthy == total:
        print(f"狀態: [全部正常] {healthy}/{total} 服務運行中")
        print("=" * 60)
        return 0
    else:
        print(f"狀態: [異常] {healthy}/{total} 服務運行中")
        print()
        print("請執行以下命令啟動所有服務:")
        print("  start_all_services.bat")
        print("=" * 60)
        return 1

if __name__ == "__main__":
    sys.exit(main())



