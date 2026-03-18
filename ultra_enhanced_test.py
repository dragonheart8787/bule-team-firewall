#!/usr/bin/env python3
"""
超強化測試套件
深度測試所有功能並提供詳細的性能分析
"""

import requests
import time
import json
import threading
import statistics
from datetime import datetime
import subprocess
import os
import sys

class UltraEnhancedTester:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'tests': {},
            'performance': {},
            'summary': {}
        }
        self.base_url = 'http://localhost:8080'
        self.siem_url = 'http://localhost:8001'
        self.target_url = 'http://localhost:5000'
        
    def test_connectivity(self):
        """測試基本連通性"""
        print("測試基本連通性...")
        tests = {}
        
        # 測試目標應用
        try:
            response = requests.get(f"{self.target_url}/", timeout=5)
            tests['target_app'] = {
                'status': 'PASS' if response.status_code == 200 else 'FAIL',
                'response_time': response.elapsed.total_seconds(),
                'status_code': response.status_code
            }
        except Exception as e:
            tests['target_app'] = {'status': 'FAIL', 'error': str(e)}
        
        # 測試 SIEM
        try:
            response = requests.get(f"{self.siem_url}/healthz", timeout=5)
            tests['siem'] = {
                'status': 'PASS' if response.status_code == 200 else 'FAIL',
                'response_time': response.elapsed.total_seconds(),
                'status_code': response.status_code
            }
        except Exception as e:
            tests['siem'] = {'status': 'FAIL', 'error': str(e)}
        
        # 測試 WAF
        try:
            response = requests.get(f"{self.base_url}/healthz", timeout=5)
            tests['waf'] = {
                'status': 'PASS' if response.status_code == 200 else 'FAIL',
                'response_time': response.elapsed.total_seconds(),
                'status_code': response.status_code
            }
        except Exception as e:
            tests['waf'] = {'status': 'FAIL', 'error': str(e)}
        
        self.results['tests']['connectivity'] = tests
        return all(test['status'] == 'PASS' for test in tests.values())
    
    def test_waf_protection_enhanced(self):
        """增強版 WAF 保護測試"""
        print("測試 WAF 保護功能（增強版）...")
        tests = {}
        
        # SQL 注入測試
        sql_payloads = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "1' UNION SELECT * FROM users--"
        ]
        
        sql_results = []
        for payload in sql_payloads:
            try:
                response = requests.get(f"{self.base_url}/?id={payload}", timeout=3)
                sql_results.append({
                    'payload': payload,
                    'blocked': response.status_code == 403,
                    'status_code': response.status_code,
                    'response_time': response.elapsed.total_seconds()
                })
            except Exception as e:
                sql_results.append({'payload': payload, 'error': str(e)})
        
        tests['sql_injection'] = {
            'total_tests': len(sql_payloads),
            'blocked_count': sum(1 for r in sql_results if r.get('blocked', False)),
            'results': sql_results
        }
        
        # XSS 測試
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert('XSS');//"
        ]
        
        xss_results = []
        for payload in xss_payloads:
            try:
                response = requests.get(f"{self.base_url}/?search={payload}", timeout=3)
                xss_results.append({
                    'payload': payload,
                    'blocked': response.status_code == 403,
                    'status_code': response.status_code,
                    'response_time': response.elapsed.total_seconds()
                })
            except Exception as e:
                xss_results.append({'payload': payload, 'error': str(e)})
        
        tests['xss'] = {
            'total_tests': len(xss_payloads),
            'blocked_count': sum(1 for r in xss_results if r.get('blocked', False)),
            'results': xss_results
        }
        
        # 管理員路徑測試
        admin_paths = ['/admin', '/administrator', '/wp-admin', '/phpmyadmin']
        admin_results = []
        
        for path in admin_paths:
            try:
                response = requests.get(f"{self.base_url}{path}", timeout=3)
                admin_results.append({
                    'path': path,
                    'blocked': response.status_code == 403,
                    'status_code': response.status_code,
                    'response_time': response.elapsed.total_seconds()
                })
            except Exception as e:
                admin_results.append({'path': path, 'error': str(e)})
        
        tests['admin_access'] = {
            'total_tests': len(admin_paths),
            'blocked_count': sum(1 for r in admin_results if r.get('blocked', False)),
            'results': admin_results
        }
        
        # 計算總體保護率
        total_tests = tests['sql_injection']['total_tests'] + tests['xss']['total_tests'] + tests['admin_access']['total_tests']
        total_blocked = tests['sql_injection']['blocked_count'] + tests['xss']['blocked_count'] + tests['admin_access']['blocked_count']
        protection_rate = (total_blocked / total_tests * 100) if total_tests > 0 else 0
        
        tests['summary'] = {
            'total_tests': total_tests,
            'total_blocked': total_blocked,
            'protection_rate': protection_rate,
            'status': 'PASS' if protection_rate >= 80 else 'FAIL'
        }
        
        self.results['tests']['waf_protection'] = tests
        return tests['summary']['status'] == 'PASS'
    
    def test_performance_ultra(self):
        """超性能測試"""
        print("執行超性能測試...")
        
        # 測試配置
        test_configs = [
            {'name': '輕量級', 'concurrent': 10, 'requests': 100, 'timeout': 3},
            {'name': '中等負載', 'concurrent': 25, 'requests': 250, 'timeout': 5},
            {'name': '高負載', 'concurrent': 50, 'requests': 500, 'timeout': 10}
        ]
        
        performance_results = {}
        
        for config in test_configs:
            print(f"  執行 {config['name']} 測試...")
            results = self._run_load_test(
                config['concurrent'], 
                config['requests'], 
                config['timeout']
            )
            
            performance_results[config['name']] = {
                'config': config,
                'results': results,
                'summary': self._analyze_performance(results)
            }
        
        self.results['performance'] = performance_results
        return True
    
    def _run_load_test(self, concurrent, total_requests, timeout):
        """執行負載測試"""
        results = {
            'response_times': [],
            'status_codes': {},
            'errors': [],
            'start_time': time.time()
        }
        
        def worker():
            for _ in range(total_requests // concurrent):
                try:
                    start = time.time()
                    response = requests.get(f"{self.base_url}/", timeout=timeout)
                    end = time.time()
                    
                    results['response_times'].append(end - start)
                    status = response.status_code
                    results['status_codes'][status] = results['status_codes'].get(status, 0) + 1
                    
                except Exception as e:
                    results['errors'].append(str(e))
        
        # 啟動工作線程
        threads = []
        for _ in range(concurrent):
            thread = threading.Thread(target=worker)
            thread.start()
            threads.append(thread)
        
        # 等待完成
        for thread in threads:
            thread.join()
        
        results['end_time'] = time.time()
        results['duration'] = results['end_time'] - results['start_time']
        
        return results
    
    def _analyze_performance(self, results):
        """分析性能結果"""
        if not results['response_times']:
            return {'status': 'FAIL', 'error': 'No successful requests'}
        
        response_times = results['response_times']
        
        analysis = {
            'total_requests': len(response_times),
            'successful_requests': len(response_times),
            'error_count': len(results['errors']),
            'avg_response_time': statistics.mean(response_times),
            'min_response_time': min(response_times),
            'max_response_time': max(response_times),
            'p50_response_time': statistics.median(response_times),
            'p95_response_time': sorted(response_times)[int(len(response_times) * 0.95)],
            'p99_response_time': sorted(response_times)[int(len(response_times) * 0.99)],
            'requests_per_second': len(response_times) / results['duration'],
            'status_codes': results['status_codes']
        }
        
        # 性能評估
        if analysis['p95_response_time'] < 0.5:
            analysis['performance_grade'] = 'A'
        elif analysis['p95_response_time'] < 1.0:
            analysis['performance_grade'] = 'B'
        elif analysis['p95_response_time'] < 2.0:
            analysis['performance_grade'] = 'C'
        else:
            analysis['performance_grade'] = 'D'
        
        analysis['status'] = 'PASS' if analysis['performance_grade'] in ['A', 'B'] else 'FAIL'
        
        return analysis
    
    def test_siem_integration_enhanced(self):
        """增強版 SIEM 整合測試"""
        print("測試 SIEM 整合（增強版）...")
        tests = {}
        
        # 測試所有 SIEM 端點
        endpoints = [
            '/healthz',
            '/status',
            '/alerts',
            '/dashboard',
            '/metrics',
            '/slo'
        ]
        
        endpoint_results = {}
        for endpoint in endpoints:
            try:
                response = requests.get(f"{self.siem_url}{endpoint}", timeout=5)
                endpoint_results[endpoint] = {
                    'status': 'PASS' if response.status_code == 200 else 'FAIL',
                    'status_code': response.status_code,
                    'response_time': response.elapsed.total_seconds(),
                    'content_type': response.headers.get('content-type', ''),
                    'content_length': len(response.content)
                }
            except Exception as e:
                endpoint_results[endpoint] = {
                    'status': 'FAIL',
                    'error': str(e)
                }
        
        tests['endpoints'] = endpoint_results
        
        # 測試 WAF 到 SIEM 的整合
        try:
            # 發送一個測試請求到 WAF
            response = requests.get(f"{self.base_url}/?test=siem_integration", timeout=5)
            tests['waf_to_siem'] = {
                'status': 'PASS' if response.status_code in [200, 403] else 'FAIL',
                'status_code': response.status_code
            }
        except Exception as e:
            tests['waf_to_siem'] = {'status': 'FAIL', 'error': str(e)}
        
        # 計算總體狀態
        total_endpoints = len(endpoints)
        successful_endpoints = sum(1 for r in endpoint_results.values() if r['status'] == 'PASS')
        success_rate = (successful_endpoints / total_endpoints * 100) if total_endpoints > 0 else 0
        
        tests['summary'] = {
            'total_endpoints': total_endpoints,
            'successful_endpoints': successful_endpoints,
            'success_rate': success_rate,
            'status': 'PASS' if success_rate >= 80 else 'FAIL'
        }
        
        self.results['tests']['siem_integration'] = tests
        return tests['summary']['status'] == 'PASS'
    
    def test_waf_config_api(self):
        """測試 WAF 配置 API"""
        print("測試 WAF 配置 API...")
        tests = {}
        
        # 測試獲取配置
        try:
            response = requests.get(f"{self.base_url}/api/config", timeout=5)
            tests['get_config'] = {
                'status': 'PASS' if response.status_code == 200 else 'FAIL',
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds()
            }
        except Exception as e:
            tests['get_config'] = {'status': 'FAIL', 'error': str(e)}
        
        # 測試更新配置
        try:
            config_data = {
                'governance_mode': 'observation',
                'small_traffic_percent': 10,
                'rate_limits': {
                    'global_rps': 1000,
                    'per_ip_rps': 100,
                    'per_endpoint_rps': 50
                }
            }
            response = requests.post(f"{self.base_url}/api/config", json=config_data, timeout=5)
            tests['update_config'] = {
                'status': 'PASS' if response.status_code == 200 else 'FAIL',
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds()
            }
        except Exception as e:
            tests['update_config'] = {'status': 'FAIL', 'error': str(e)}
        
        self.results['tests']['waf_config_api'] = tests
        return all(test['status'] == 'PASS' for test in tests.values())
    
    def generate_summary(self):
        """生成測試摘要"""
        total_tests = 0
        passed_tests = 0
        
        for test_category, test_results in self.results['tests'].items():
            if isinstance(test_results, dict):
                if 'summary' in test_results:
                    total_tests += 1
                    if test_results['summary']['status'] == 'PASS':
                        passed_tests += 1
                else:
                    # 計算子測試
                    for test_name, test_result in test_results.items():
                        if isinstance(test_result, dict) and 'status' in test_result:
                            total_tests += 1
                            if test_result['status'] == 'PASS':
                                passed_tests += 1
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        self.results['summary'] = {
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': total_tests - passed_tests,
            'success_rate': success_rate,
            'overall_status': 'PASS' if success_rate >= 80 else 'FAIL'
        }
        
        return self.results['summary']
    
    def run_all_tests(self):
        """運行所有測試"""
        print("開始超強化測試...")
        print("=" * 60)
        
        # 運行所有測試
        connectivity_ok = self.test_connectivity()
        waf_protection_ok = self.test_waf_protection_enhanced()
        performance_ok = self.test_performance_ultra()
        siem_integration_ok = self.test_siem_integration_enhanced()
        waf_config_ok = self.test_waf_config_api()
        
        # 生成摘要
        summary = self.generate_summary()
        
        # 顯示結果
        print("\n" + "=" * 60)
        print("測試結果摘要")
        print("=" * 60)
        print(f"總測試數: {summary['total_tests']}")
        print(f"通過測試: {summary['passed_tests']}")
        print(f"失敗測試: {summary['failed_tests']}")
        print(f"成功率: {summary['success_rate']:.1f}%")
        print(f"總體狀態: {summary['overall_status']}")
        
        # 保存結果
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ULTRA_ENHANCED_TEST_REPORT_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)
        
        print(f"\n詳細報告已保存到: {filename}")
        
        return summary['overall_status'] == 'PASS'

def main():
    """主函數"""
    tester = UltraEnhancedTester()
    success = tester.run_all_tests()
    
    if success:
        print("\n[SUCCESS] 所有測試通過！系統已達到企業級標準。")
        return 0
    else:
        print("\n[FAILURE] 部分測試失敗，需要進一步優化。")
        return 1

if __name__ == "__main__":
    sys.exit(main())




