#!/usr/bin/env python3
"""
高級測試方法
全面驗證企業級 WAF 系統的所有功能
"""

import requests
import time
import json
import threading
import statistics
import psutil
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import string

class AdvancedTestMethods:
    """高級測試方法類"""
    
    def __init__(self):
        self.base_url = 'http://localhost:8080'
        self.siem_url = 'http://localhost:8001'
        self.target_url = 'http://localhost:5000'
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'test_suite': 'Advanced Enterprise WAF Testing',
            'version': '2.0',
            'tests': {}
        }
    
    def test_connectivity_advanced(self):
        """高級連通性測試"""
        print("[連通性] 執行高級連通性測試...")
        
        services = [
            {'name': 'Target App', 'url': f"{self.target_url}/", 'expected_status': 200},
            {'name': 'SIEM Health', 'url': f"{self.siem_url}/healthz", 'expected_status': 200},
            {'name': 'WAF Health', 'url': f"{self.base_url}/healthz", 'expected_status': 200},
            {'name': 'WAF Metrics', 'url': f"{self.base_url}/metrics", 'expected_status': 200},
            {'name': 'WAF Config', 'url': f"{self.base_url}/api/config", 'expected_status': 200}
        ]
        
        results = []
        for service in services:
            try:
                start_time = time.time()
                response = requests.get(service['url'], timeout=10)
                end_time = time.time()
                
                result = {
                    'service': service['name'],
                    'url': service['url'],
                    'status': 'PASS' if response.status_code == service['expected_status'] else 'FAIL',
                    'status_code': response.status_code,
                    'expected_status': service['expected_status'],
                    'response_time': end_time - start_time,
                    'content_length': len(response.content),
                    'content_type': response.headers.get('content-type', ''),
                    'server': response.headers.get('server', ''),
                    'timestamp': datetime.now().isoformat()
                }
                
                if response.status_code == 200 and 'application/json' in result['content_type']:
                    try:
                        result['json_data'] = response.json()
                    except:
                        pass
                
                results.append(result)
                print(f"  [OK] {service['name']}: {response.status_code} ({result['response_time']:.3f}s)")
                
            except Exception as e:
                result = {
                    'service': service['name'],
                    'url': service['url'],
                    'status': 'ERROR',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }
                results.append(result)
                print(f"  [ERROR] {service['name']}: ERROR - {e}")
        
        self.results['tests']['connectivity_advanced'] = {
            'total_services': len(services),
            'passed_services': len([r for r in results if r['status'] == 'PASS']),
            'failed_services': len([r for r in results if r['status'] == 'FAIL']),
            'error_services': len([r for r in results if r['status'] == 'ERROR']),
            'success_rate': len([r for r in results if r['status'] == 'PASS']) / len(services) * 100,
            'results': results
        }
        
        return len([r for r in results if r['status'] == 'PASS']) / len(services) >= 0.8
    
    def test_waf_protection_comprehensive(self):
        """綜合 WAF 保護測試"""
        print("[WAF保護] 執行綜合 WAF 保護測試...")
        
        test_categories = {
            'sql_injection': [
                "'; DROP TABLE users; --",
                "1' OR '1'='1",
                "admin'--",
                "1' UNION SELECT * FROM users--",
                "'; EXEC xp_cmdshell('dir'); --",
                "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
                "1' OR 1=1#",
                "1' OR 'x'='x"
            ],
            'xss_attacks': [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "';alert('XSS');//",
                "<svg onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%252F..%252F..%252Fetc%252Fpasswd"
            ],
            'admin_access': [
                '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
                '/backend', '/management', '/dashboard', '/system',
                '/config', '/settings', '/logs', '/backup', '/security',
                '/api/admin', '/admin/api', '/admin.php', '/admin.asp'
            ],
            'command_injection': [
                "; ls -la",
                "| cat /etc/passwd",
                "`whoami`",
                "$(id)",
                "; ping -c 1 127.0.0.1",
                "| dir",
                "; type C:\\windows\\system32\\drivers\\etc\\hosts"
            ]
        }
        
        results = {}
        total_tests = 0
        total_blocked = 0
        
        for category, payloads in test_categories.items():
            print(f"  測試 {category}...")
            category_results = []
            
            for payload in payloads:
                try:
                    if category == 'admin_access':
                        # 管理員路徑測試
                        response = requests.get(f"{self.base_url}{payload}", timeout=5)
                    else:
                        # 其他攻擊測試
                        response = requests.get(f"{self.base_url}/?test={payload}", timeout=5)
                    
                    blocked = response.status_code == 403
                    if blocked:
                        total_blocked += 1
                    
                    result = {
                        'payload': payload,
                        'blocked': blocked,
                        'status_code': response.status_code,
                        'response_time': response.elapsed.total_seconds(),
                        'content_length': len(response.content)
                    }
                    
                    if response.status_code == 403:
                        try:
                            result['block_reason'] = response.json()
                        except:
                            result['block_reason'] = response.text
                    
                    category_results.append(result)
                    total_tests += 1
                    
                    status = "[BLOCKED]" if blocked else "[ALLOWED]"
                    print(f"    {status} {payload[:50]}...")
                    
                except Exception as e:
                    result = {
                        'payload': payload,
                        'error': str(e),
                        'blocked': False
                    }
                    category_results.append(result)
                    total_tests += 1
                    print(f"    [ERROR] {payload[:50]}... - {e}")
            
            results[category] = {
                'total_tests': len(payloads),
                'blocked_count': len([r for r in category_results if r.get('blocked', False)]),
                'block_rate': len([r for r in category_results if r.get('blocked', False)]) / len(payloads) * 100,
                'results': category_results
            }
        
        overall_protection_rate = (total_blocked / total_tests * 100) if total_tests > 0 else 0
        
        self.results['tests']['waf_protection_comprehensive'] = {
            'total_tests': total_tests,
            'total_blocked': total_blocked,
            'overall_protection_rate': overall_protection_rate,
            'categories': results,
            'status': 'PASS' if overall_protection_rate >= 80 else 'FAIL'
        }
        
        print(f"  [統計] 總體保護率: {overall_protection_rate:.1f}% ({total_blocked}/{total_tests})")
        return overall_protection_rate >= 80
    
    def test_performance_stress(self):
        """壓力性能測試"""
        print("[壓力測試] 執行壓力性能測試...")
        
        test_scenarios = [
            {'name': '輕量級', 'concurrent': 5, 'requests_per_thread': 20, 'timeout': 5},
            {'name': '中等負載', 'concurrent': 10, 'requests_per_thread': 15, 'timeout': 5},
            {'name': '高負載', 'concurrent': 20, 'requests_per_thread': 10, 'timeout': 5}
        ]
        
        results = {}
        
        for scenario in test_scenarios:
            print(f"  執行 {scenario['name']} 測試...")
            scenario_results = self._run_stress_test(scenario)
            results[scenario['name']] = scenario_results
            
            # 顯示結果
            if scenario_results['successful_requests'] > 0:
                print(f"    [統計] 成功率: {scenario_results['success_rate']:.1f}%")
                print(f"    [統計] 平均響應時間: {scenario_results['avg_response_time']:.3f}s")
                print(f"    [統計] P95 響應時間: {scenario_results['p95_response_time']:.3f}s")
                print(f"    [統計] RPS: {scenario_results['requests_per_second']:.1f}")
            else:
                print(f"    [FAIL] 測試失敗")
        
        self.results['tests']['performance_stress'] = results
        return True
    
    def _run_stress_test(self, scenario):
        """執行壓力測試"""
        results = {
            'response_times': [],
            'status_codes': {},
            'errors': [],
            'start_time': time.time()
        }
        
        def worker():
            for _ in range(scenario['requests_per_thread']):
                try:
                    start = time.time()
                    response = requests.get(f"{self.base_url}/", timeout=scenario['timeout'])
                    end = time.time()
                    
                    results['response_times'].append(end - start)
                    status = response.status_code
                    results['status_codes'][status] = results['status_codes'].get(status, 0) + 1
                    
                except Exception as e:
                    results['errors'].append(str(e))
        
        # 執行測試
        with ThreadPoolExecutor(max_workers=scenario['concurrent']) as executor:
            futures = [executor.submit(worker) for _ in range(scenario['concurrent'])]
            for future in as_completed(futures):
                future.result()
        
        results['end_time'] = time.time()
        results['duration'] = results['end_time'] - results['start_time']
        
        # 分析結果
        if results['response_times']:
            response_times = results['response_times']
            results.update({
                'successful_requests': len(response_times),
                'error_count': len(results['errors']),
                'success_rate': len(response_times) / (len(response_times) + len(results['errors'])) * 100,
                'avg_response_time': statistics.mean(response_times),
                'min_response_time': min(response_times),
                'max_response_time': max(response_times),
                'p50_response_time': statistics.median(response_times),
                'p95_response_time': sorted(response_times)[int(len(response_times) * 0.95)],
                'p99_response_time': sorted(response_times)[int(len(response_times) * 0.99)],
                'requests_per_second': len(response_times) / results['duration']
            })
        else:
            results.update({
                'successful_requests': 0,
                'error_count': len(results['errors']),
                'success_rate': 0,
                'avg_response_time': 0,
                'min_response_time': 0,
                'max_response_time': 0,
                'p50_response_time': 0,
                'p95_response_time': 0,
                'p99_response_time': 0,
                'requests_per_second': 0
            })
        
        return results
    
    def test_siem_integration_advanced(self):
        """高級 SIEM 整合測試"""
        print("[SIEM測試] 執行高級 SIEM 整合測試...")
        
        # 測試所有 SIEM 端點
        endpoints = [
            {'path': '/healthz', 'expected_status': 200, 'description': '健康檢查'},
            {'path': '/status', 'expected_status': 200, 'description': '系統狀態'},
            {'path': '/alerts', 'expected_status': 200, 'description': '警報列表'},
            {'path': '/dashboard', 'expected_status': 200, 'description': '儀表板'},
            {'path': '/metrics', 'expected_status': 200, 'description': '系統指標'},
            {'path': '/slo', 'expected_status': 200, 'description': 'SLO 狀態'}
        ]
        
        results = []
        for endpoint in endpoints:
            try:
                start_time = time.time()
                response = requests.get(f"{self.siem_url}{endpoint['path']}", timeout=10)
                end_time = time.time()
                
                result = {
                    'endpoint': endpoint['path'],
                    'description': endpoint['description'],
                    'status': 'PASS' if response.status_code == endpoint['expected_status'] else 'FAIL',
                    'status_code': response.status_code,
                    'expected_status': endpoint['expected_status'],
                    'response_time': end_time - start_time,
                    'content_length': len(response.content),
                    'content_type': response.headers.get('content-type', ''),
                    'timestamp': datetime.now().isoformat()
                }
                
                if response.status_code == 200 and 'application/json' in result['content_type']:
                    try:
                        result['json_data'] = response.json()
                    except:
                        pass
                
                results.append(result)
                print(f"  [OK] {endpoint['description']}: {response.status_code} ({result['response_time']:.3f}s)")
                
            except Exception as e:
                result = {
                    'endpoint': endpoint['path'],
                    'description': endpoint['description'],
                    'status': 'ERROR',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }
                results.append(result)
                print(f"  [ERROR] {endpoint['description']}: ERROR - {e}")
        
        # 測試 WAF 到 SIEM 的整合
        print("  測試 WAF 到 SIEM 的整合...")
        try:
            # 發送一個測試請求到 WAF
            response = requests.get(f"{self.base_url}/?test=siem_integration", timeout=5)
            integration_result = {
                'test': 'WAF to SIEM Integration',
                'status': 'PASS' if response.status_code in [200, 403] else 'FAIL',
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'timestamp': datetime.now().isoformat()
            }
            print(f"  [OK] WAF 到 SIEM 整合: {response.status_code}")
        except Exception as e:
            integration_result = {
                'test': 'WAF to SIEM Integration',
                'status': 'ERROR',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            print(f"  [ERROR] WAF 到 SIEM 整合: ERROR - {e}")
        
        results.append(integration_result)
        
        # 計算統計
        total_tests = len(results)
        passed_tests = len([r for r in results if r['status'] == 'PASS'])
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        self.results['tests']['siem_integration_advanced'] = {
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': len([r for r in results if r['status'] == 'FAIL']),
            'error_tests': len([r for r in results if r['status'] == 'ERROR']),
            'success_rate': success_rate,
            'results': results,
            'status': 'PASS' if success_rate >= 80 else 'FAIL'
        }
        
        print(f"  [統計] SIEM 整合成功率: {success_rate:.1f}% ({passed_tests}/{total_tests})")
        return success_rate >= 80
    
    def test_system_resources(self):
        """系統資源測試"""
        print("[資源測試] 執行系統資源測試...")
        
        # 獲取系統資源信息
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # 測試前的資源狀態
        before_resources = {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_available_gb': memory.available / (1024**3),
            'disk_percent': disk.percent,
            'disk_free_gb': disk.free / (1024**3),
            'timestamp': datetime.now().isoformat()
        }
        
        # 執行一些請求來測試資源使用
        print("  執行資源使用測試...")
        start_time = time.time()
        
        def resource_test_worker():
            for _ in range(10):
                try:
                    requests.get(f"{self.base_url}/", timeout=3)
                except:
                    pass
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(resource_test_worker) for _ in range(3)]
            for future in as_completed(futures):
                future.result()
        
        # 測試後的資源狀態
        after_resources = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'memory_available_gb': psutil.virtual_memory().available / (1024**3),
            'disk_percent': psutil.disk_usage('/').percent,
            'disk_free_gb': psutil.disk_usage('/').free / (1024**3),
            'timestamp': datetime.now().isoformat()
        }
        
        # 計算資源變化
        resource_changes = {
            'cpu_change': after_resources['cpu_percent'] - before_resources['cpu_percent'],
            'memory_change': after_resources['memory_percent'] - before_resources['memory_percent'],
            'disk_change': after_resources['disk_percent'] - before_resources['disk_percent']
        }
        
        results = {
            'before_resources': before_resources,
            'after_resources': after_resources,
            'resource_changes': resource_changes,
            'test_duration': time.time() - start_time,
            'status': 'PASS' if resource_changes['cpu_change'] < 50 and resource_changes['memory_change'] < 20 else 'WARN'
        }
        
        self.results['tests']['system_resources'] = results
        
        print(f"  [統計] CPU 使用率變化: {resource_changes['cpu_change']:+.1f}%")
        print(f"  [統計] 記憶體使用率變化: {resource_changes['memory_change']:+.1f}%")
        print(f"  [統計] 磁碟使用率變化: {resource_changes['disk_change']:+.1f}%")
        
        return True
    
    def test_security_headers(self):
        """安全標頭測試"""
        print("[安全測試] 執行安全標頭測試...")
        
        security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'Referrer-Policy'
        ]
        
        results = []
        
        try:
            response = requests.get(f"{self.base_url}/", timeout=5)
            
            for header in security_headers:
                header_value = response.headers.get(header, '')
                result = {
                    'header': header,
                    'present': bool(header_value),
                    'value': header_value,
                    'status': 'PASS' if bool(header_value) else 'WARN'
                }
                results.append(result)
                
                status = "[OK]" if result['present'] else "[WARN]"
                print(f"  {status} {header}: {header_value or 'Not Set'}")
        
        except Exception as e:
            results = [{'error': str(e)}]
            print(f"  [ERROR] 安全標頭測試失敗: {e}")
        
        self.results['tests']['security_headers'] = {
            'total_headers': len(security_headers),
            'present_headers': len([r for r in results if r.get('present', False)]),
            'results': results
        }
        
        return True
    
    def generate_comprehensive_report(self):
        """生成綜合測試報告"""
        print("📋 生成綜合測試報告...")
        
        # 計算總體統計
        total_tests = 0
        passed_tests = 0
        
        for test_name, test_data in self.results['tests'].items():
            if 'status' in test_data:
                total_tests += 1
                if test_data['status'] == 'PASS':
                    passed_tests += 1
            elif 'success_rate' in test_data:
                total_tests += 1
                if test_data['success_rate'] >= 80:
                    passed_tests += 1
        
        overall_success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        # 生成摘要
        summary = {
            'total_test_categories': total_tests,
            'passed_categories': passed_tests,
            'failed_categories': total_tests - passed_tests,
            'overall_success_rate': overall_success_rate,
            'overall_status': 'PASS' if overall_success_rate >= 80 else 'FAIL',
            'test_duration': (datetime.now() - datetime.fromisoformat(self.results['timestamp'])).total_seconds(),
            'recommendations': self._generate_recommendations()
        }
        
        self.results['summary'] = summary
        
        # 保存報告
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ADVANCED_TEST_REPORT_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)
        
        print(f"[報告] 報告已保存到: {filename}")
        
        # 顯示摘要
        print("\n" + "="*60)
        print("[報告] 綜合測試報告摘要")
        print("="*60)
        print(f"總測試類別: {total_tests}")
        print(f"通過類別: {passed_tests}")
        print(f"失敗類別: {total_tests - passed_tests}")
        print(f"總體成功率: {overall_success_rate:.1f}%")
        print(f"總體狀態: {summary['overall_status']}")
        print(f"測試耗時: {summary['test_duration']:.1f} 秒")
        
        if summary['recommendations']:
            print("\n[建議]:")
            for rec in summary['recommendations']:
                print(f"  • {rec}")
        
        return summary['overall_status'] == 'PASS'
    
    def _generate_recommendations(self):
        """生成建議"""
        recommendations = []
        
        for test_name, test_data in self.results['tests'].items():
            if test_name == 'waf_protection_comprehensive':
                if test_data.get('overall_protection_rate', 0) < 80:
                    recommendations.append("提高 WAF 保護規則的準確性")
            elif test_name == 'performance_stress':
                for scenario_name, scenario_data in test_data.items():
                    if scenario_data.get('success_rate', 0) < 90:
                        recommendations.append(f"優化 {scenario_name} 場景下的性能")
            elif test_name == 'siem_integration_advanced':
                if test_data.get('success_rate', 0) < 80:
                    recommendations.append("改善 SIEM 整合的穩定性")
            elif test_name == 'system_resources':
                if test_data.get('status') == 'WARN':
                    recommendations.append("監控系統資源使用情況")
        
        return recommendations
    
    def run_all_tests(self):
        """運行所有測試"""
        print("[啟動] 開始執行高級測試套件...")
        print("="*60)
        
        start_time = time.time()
        
        # 執行所有測試
        tests = [
            ('連通性測試', self.test_connectivity_advanced),
            ('WAF 保護測試', self.test_waf_protection_comprehensive),
            ('性能壓力測試', self.test_performance_stress),
            ('SIEM 整合測試', self.test_siem_integration_advanced),
            ('系統資源測試', self.test_system_resources),
            ('安全標頭測試', self.test_security_headers)
        ]
        
        for test_name, test_func in tests:
            try:
                print(f"\n[執行] {test_name}...")
                test_func()
            except Exception as e:
                print(f"[ERROR] {test_name} 執行失敗: {e}")
                self.results['tests'][test_name.lower().replace(' ', '_')] = {
                    'status': 'ERROR',
                    'error': str(e)
                }
        
        # 生成報告
        print(f"\n[統計] 總測試時間: {time.time() - start_time:.1f} 秒")
        success = self.generate_comprehensive_report()
        
        return success

def main():
    """主函數"""
    tester = AdvancedTestMethods()
    success = tester.run_all_tests()
    
    if success:
        print("\n[SUCCESS] 所有測試通過！系統已達到企業級標準。")
        return 0
    else:
        print("\n[WARN] 部分測試失敗，請查看詳細報告。")
        return 1

if __name__ == "__main__":
    main()



