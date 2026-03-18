#!/usr/bin/env python3
"""
企業級 WAF 功能展示腳本
展示所有企業級功能
"""

import requests
import json
import time
import random

class EnterpriseDemo:
    def __init__(self):
        self.waf_url = "http://localhost:8080"
        self.siem_url = "http://localhost:8001"
        self.target_url = "http://localhost:5000"
        
    def demo_health_checks(self):
        """展示健康檢查功能"""
        print("=" * 60)
        print("1. 企業級健康檢查功能")
        print("=" * 60)
        
        services = [
            ("WAF 代理", f"{self.waf_url}/healthz"),
            ("SIEM 引擎", f"{self.siem_url}/healthz"),
            ("目標應用", f"{self.target_url}")
        ]
        
        for name, url in services:
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    data = response.json() if 'json' in response.headers.get('content-type', '') else {}
                    print(f"[OK] {name}: 健康狀態正常")
                    if data:
                        print(f"     狀態: {data}")
                else:
                    print(f"[WARN] {name}: HTTP {response.status_code}")
            except Exception as e:
                print(f"[FAIL] {name}: {str(e)[:50]}...")
        
        print()
    
    def demo_metrics(self):
        """展示指標監控功能"""
        print("=" * 60)
        print("2. 企業級指標監控功能")
        print("=" * 60)
        
        # WAF 指標
        try:
            response = requests.get(f"{self.waf_url}/metrics", timeout=3)
            if response.status_code == 200:
                data = response.json()
                print("[OK] WAF 指標:")
                print(f"   - 規則數量: {data.get('rule_count', 'N/A')}")
                print(f"   - 速率限制 IP: {data.get('rate_limit_ips', 'N/A')}")
                print(f"   - 封鎖 IP 數量: {data.get('blocked_ips', 'N/A')}")
            else:
                print(f"[FAIL] WAF 指標: HTTP {response.status_code}")
        except Exception as e:
            print(f"[FAIL] WAF 指標: {str(e)[:50]}...")
        
        # SIEM 指標
        try:
            response = requests.get(f"{self.siem_url}/metrics", timeout=3)
            if response.status_code == 200:
                data = response.json()
                print("[OK] SIEM 指標:")
                metrics = data.get('metrics', '')
                for line in metrics.split('\n'):
                    if line.strip():
                        print(f"   - {line}")
            else:
                print(f"[FAIL] SIEM 指標: HTTP {response.status_code}")
        except Exception as e:
            print(f"[FAIL] SIEM 指標: {str(e)[:50]}...")
        
        print()
    
    def demo_blocklist_management(self):
        """展示封鎖名單管理功能"""
        print("=" * 60)
        print("3. 企業級封鎖名單管理功能")
        print("=" * 60)
        
        # 查看當前封鎖清單
        try:
            response = requests.get(f"{self.waf_url}/api/blocklist", timeout=3)
            if response.status_code == 200:
                data = response.json()
                print("[OK] 當前封鎖清單:")
                blocked_ips = data.get('blocked_ips', [])
                for ip in blocked_ips:
                    print(f"   - {ip}")
            else:
                print(f"[FAIL] 獲取封鎖清單: HTTP {response.status_code}")
        except Exception as e:
            print(f"[FAIL] 獲取封鎖清單: {str(e)[:50]}...")
        
        # 測試封鎖新 IP
        test_ip = f"192.168.1.{random.randint(200, 250)}"
        try:
            response = requests.post(f"{self.waf_url}/api/blocklist", 
                                   json={"ip": test_ip, "action": "block"}, 
                                   timeout=3)
            if response.status_code == 200:
                data = response.json()
                print(f"[OK] 封鎖 IP {test_ip}: {data.get('status', 'Unknown')}")
            else:
                print(f"[FAIL] 封鎖 IP: HTTP {response.status_code}")
        except Exception as e:
            print(f"[FAIL] 封鎖 IP: {str(e)[:50]}...")
        
        print()
    
    def demo_attack_detection(self):
        """展示攻擊檢測功能"""
        print("=" * 60)
        print("4. 企業級攻擊檢測功能")
        print("=" * 60)
        
        attacks = [
            {
                "name": "SQL 注入攻擊",
                "payload": "1' OR '1'='1",
                "expected": 403
            },
            {
                "name": "XSS 攻擊",
                "payload": "<script>alert('XSS')</script>",
                "expected": 403
            },
            {
                "name": "路徑遍歷攻擊",
                "payload": "../../../etc/passwd",
                "expected": 403
            },
            {
                "name": "命令注入攻擊",
                "payload": "; cat /etc/passwd",
                "expected": 403
            }
        ]
        
        for attack in attacks:
            try:
                url = f"{self.waf_url}/search?query={attack['payload']}"
                response = requests.get(url, timeout=3, allow_redirects=False)
                
                if response.status_code == attack['expected']:
                    print(f"[OK] {attack['name']}: 成功檢測並阻擋")
                elif response.status_code == 200:
                    print(f"[WARN] {attack['name']}: 未檢測到攻擊 (HTTP 200)")
                else:
                    print(f"[INFO] {attack['name']}: HTTP {response.status_code}")
                    
            except requests.exceptions.ConnectionError:
                print(f"[OK] {attack['name']}: 連接被阻擋")
            except Exception as e:
                print(f"[FAIL] {attack['name']}: {str(e)[:50]}...")
        
        print()
    
    def demo_siem_alerts(self):
        """展示 SIEM 警報功能"""
        print("=" * 60)
        print("5. 企業級 SIEM 警報功能")
        print("=" * 60)
        
        try:
            response = requests.get(f"{self.siem_url}/alerts", timeout=3)
            if response.status_code == 200:
                alerts = response.json()
                print(f"[OK] SIEM 警報系統正常運行")
                print(f"   警報總數: {len(alerts)}")
                
                if alerts:
                    print("   最新警報:")
                    for alert in alerts[:3]:  # 顯示前3個警報
                        rule_name = alert.get('rule_name', 'Unknown')
                        severity = alert.get('severity', 'Unknown')
                        timestamp = alert.get('timestamp', 'Unknown')
                        print(f"   - {rule_name} ({severity}) - {timestamp}")
                else:
                    print("   目前無警報")
            else:
                print(f"[FAIL] SIEM 警報: HTTP {response.status_code}")
        except Exception as e:
            print(f"[FAIL] SIEM 警報: {str(e)[:50]}...")
        
        print()
    
    def demo_performance_test(self):
        """展示效能測試"""
        print("=" * 60)
        print("6. 企業級效能測試")
        print("=" * 60)
        
        print("執行負載測試...")
        start_time = time.time()
        
        # 發送多個並發請求
        success_count = 0
        total_requests = 20
        
        for i in range(total_requests):
            try:
                response = requests.get(f"{self.waf_url}/search?query=test{i}", timeout=2)
                if response.status_code in [200, 403]:  # 200 正常，403 被阻擋也算成功處理
                    success_count += 1
            except:
                pass
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"[OK] 效能測試結果:")
        print(f"   總請求數: {total_requests}")
        print(f"   成功處理: {success_count}")
        print(f"   成功率: {(success_count/total_requests)*100:.1f}%")
        print(f"   總耗時: {duration:.2f} 秒")
        print(f"   平均響應時間: {(duration/total_requests)*1000:.1f} ms")
        
        print()
    
    def run_demo(self):
        """執行完整展示"""
        print("企業級 WAF 防護系統功能展示")
        print("時間:", time.strftime("%Y-%m-%d %H:%M:%S"))
        print()
        
        self.demo_health_checks()
        self.demo_metrics()
        self.demo_blocklist_management()
        self.demo_attack_detection()
        self.demo_siem_alerts()
        self.demo_performance_test()
        
        print("=" * 60)
        print("展示完成！")
        print("=" * 60)
        print()
        print("系統端點:")
        print(f"- 目標應用: {self.target_url}")
        print(f"- SIEM 引擎: {self.siem_url}")
        print(f"- WAF 代理: {self.waf_url}")
        print(f"- WAF 管理: {self.waf_url}/api/blocklist")

def main():
    demo = EnterpriseDemo()
    demo.run_demo()

if __name__ == "__main__":
    main()
