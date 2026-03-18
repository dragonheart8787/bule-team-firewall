#!/usr/bin/env python3
"""
企業級 WAF 系統狀態檢查腳本
檢查所有服務的健康狀態和指標
"""

import requests
import json
import time
from datetime import datetime

class SystemStatusChecker:
    def __init__(self):
        self.services = {
            'target_app': 'http://localhost:5000',
            'siem_engine': 'http://localhost:8001',
            'waf_proxy': 'http://localhost:8080'
        }
        self.results = {}
    
    def check_health(self, service_name, base_url):
        """檢查服務健康狀態"""
        try:
            health_url = f"{base_url}/healthz"
            response = requests.get(health_url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'status': 'healthy',
                    'response_time': response.elapsed.total_seconds(),
                    'data': data
                }
            else:
                return {
                    'status': 'unhealthy',
                    'response_time': response.elapsed.total_seconds(),
                    'error': f"HTTP {response.status_code}"
                }
        except requests.exceptions.ConnectionError:
            return {
                'status': 'down',
                'response_time': None,
                'error': 'Connection refused'
            }
        except requests.exceptions.Timeout:
            return {
                'status': 'timeout',
                'response_time': None,
                'error': 'Request timeout'
            }
        except Exception as e:
            return {
                'status': 'error',
                'response_time': None,
                'error': str(e)
            }
    
    def check_metrics(self, service_name, base_url):
        """檢查服務指標"""
        try:
            metrics_url = f"{base_url}/metrics"
            response = requests.get(metrics_url, timeout=5)
            
            if response.status_code == 200:
                return {
                    'status': 'available',
                    'data': response.json()
                }
            else:
                return {
                    'status': 'unavailable',
                    'error': f"HTTP {response.status_code}"
                }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def check_waf_functionality(self):
        """檢查 WAF 功能"""
        test_cases = [
            {
                'name': '正常請求',
                'url': 'http://localhost:8080/search?query=test',
                'expected_status': 200
            },
            {
                'name': 'SQL 注入攻擊',
                'url': 'http://localhost:8080/search?query=1\' OR \'1\'=\'1',
                'expected_status': 403
            },
            {
                'name': 'XSS 攻擊',
                'url': 'http://localhost:8080/search?query=<script>alert("xss")</script>',
                'expected_status': 403
            }
        ]
        
        results = []
        for test_case in test_cases:
            try:
                response = requests.get(test_case['url'], timeout=5, allow_redirects=False)
                actual_status = response.status_code
                success = actual_status == test_case['expected_status']
                
                results.append({
                    'name': test_case['name'],
                    'expected': test_case['expected_status'],
                    'actual': actual_status,
                    'success': success,
                    'response_time': response.elapsed.total_seconds()
                })
            except Exception as e:
                results.append({
                    'name': test_case['name'],
                    'expected': test_case['expected_status'],
                    'actual': 'error',
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    def check_siem_alerts(self):
        """檢查 SIEM 警報"""
        try:
            alerts_url = 'http://localhost:8001/alerts'
            response = requests.get(alerts_url, timeout=5)
            
            if response.status_code == 200:
                alerts = response.json()
                return {
                    'status': 'available',
                    'alert_count': len(alerts),
                    'alerts': alerts[:5]  # 只顯示前5個警報
                }
            else:
                return {
                    'status': 'unavailable',
                    'error': f"HTTP {response.status_code}"
                }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def run_full_check(self):
        """執行完整系統檢查"""
        print("=" * 60)
        print("企業級 WAF 防護系統狀態檢查")
        print("=" * 60)
        print(f"檢查時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # 檢查服務健康狀態
        print("1. 服務健康狀態檢查")
        print("-" * 40)
        for service_name, base_url in self.services.items():
            print(f"檢查 {service_name} ({base_url})...")
            health_result = self.check_health(service_name, base_url)
            self.results[service_name] = health_result
            
            status_icon = "[OK]" if health_result['status'] == 'healthy' else "[FAIL]"
            print(f"  {status_icon} 狀態: {health_result['status']}")
            
            if health_result['response_time']:
                print(f"  響應時間: {health_result['response_time']:.3f}s")
            
            if 'error' in health_result:
                print(f"  錯誤: {health_result['error']}")
            
            print()
        
        # 檢查指標
        print("2. 服務指標檢查")
        print("-" * 40)
        for service_name, base_url in self.services.items():
            print(f"檢查 {service_name} 指標...")
            metrics_result = self.check_metrics(service_name, base_url)
            
            if metrics_result['status'] == 'available':
                print(f"  [OK] 指標可用")
                if 'data' in metrics_result:
                    print(f"  數據: {json.dumps(metrics_result['data'], indent=2, ensure_ascii=False)}")
            else:
                print(f"  [FAIL] 指標不可用: {metrics_result.get('error', 'Unknown error')}")
            print()
        
        # 檢查 WAF 功能
        print("3. WAF 功能測試")
        print("-" * 40)
        waf_tests = self.check_waf_functionality()
        for test in waf_tests:
            status_icon = "[OK]" if test['success'] else "[FAIL]"
            print(f"  {status_icon} {test['name']}: {test['actual']} (期望: {test['expected']})")
            if 'response_time' in test:
                print(f"    響應時間: {test['response_time']:.3f}s")
            if 'error' in test:
                print(f"    錯誤: {test['error']}")
        print()
        
        # 檢查 SIEM 警報
        print("4. SIEM 警報檢查")
        print("-" * 40)
        siem_result = self.check_siem_alerts()
        if siem_result['status'] == 'available':
            print(f"  [OK] SIEM 警報系統正常")
            print(f"  警報數量: {siem_result['alert_count']}")
            if siem_result['alerts']:
                print("  最新警報:")
                for alert in siem_result['alerts']:
                    print(f"    - {alert.get('rule_name', 'Unknown')}: {alert.get('severity', 'Unknown')}")
        else:
            print(f"  [FAIL] SIEM 警報系統異常: {siem_result.get('error', 'Unknown error')}")
        print()
        
        # 總結
        print("5. 系統狀態總結")
        print("-" * 40)
        healthy_services = sum(1 for result in self.results.values() if result['status'] == 'healthy')
        total_services = len(self.results)
        
        print(f"健康服務: {healthy_services}/{total_services}")
        
        if healthy_services == total_services:
            print("[OK] 所有服務運行正常")
        else:
            print("[WARN] 部分服務存在問題，請檢查上述詳細信息")
        
        print("\n系統端點:")
        print("- 目標應用: http://localhost:5000")
        print("- SIEM 引擎: http://localhost:8001")
        print("- WAF 代理: http://localhost:8080")
        print("- WAF 管理: http://localhost:8080/api/blocklist")

def main():
    """主函數"""
    checker = SystemStatusChecker()
    checker.run_full_check()

if __name__ == "__main__":
    main()
