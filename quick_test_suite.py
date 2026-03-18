#!/usr/bin/env python3
"""
快速測試套件
快速驗證系統基本功能
"""

import requests
import time
import json
from datetime import datetime

class QuickTestSuite:
    """快速測試套件"""
    
    def __init__(self):
        self.base_url = 'http://localhost:8080'
        self.siem_url = 'http://localhost:8001'
        self.target_url = 'http://localhost:5000'
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'test_suite': 'Quick Test Suite',
            'version': '1.0',
            'results': {}
        }
    
    def test_quick_connectivity(self):
        """快速連通性測試"""
        print("快速連通性測試...")
        
        services = [
            ('Target App', f"{self.target_url}/"),
            ('SIEM', f"{self.siem_url}/healthz"),
            ('WAF', f"{self.base_url}/healthz")
        ]
        
        results = []
        for name, url in services:
            try:
                response = requests.get(url, timeout=3)
                status = 'PASS' if response.status_code == 200 else 'FAIL'
                results.append({
                    'service': name,
                    'status': status,
                    'status_code': response.status_code,
                    'response_time': response.elapsed.total_seconds()
                })
                print(f"  [OK] {name}: {response.status_code} ({response.elapsed.total_seconds():.3f}s)")
            except Exception as e:
                results.append({
                    'service': name,
                    'status': 'ERROR',
                    'error': str(e)
                })
                print(f"  [FAIL] {name}: ERROR - {e}")
        
        self.results['results']['connectivity'] = results
        return len([r for r in results if r['status'] == 'PASS']) >= 2
    
    def test_quick_protection(self):
        """快速保護測試"""
        print("快速保護測試...")
        
        test_cases = [
            ('SQL注入', '/?id=1\' OR \'1\'=\'1'),
            ('XSS攻擊', '/?search=<script>alert("XSS")</script>'),
            ('管理員路徑', '/admin'),
            ('路徑遍歷', '/?file=../../../etc/passwd')
        ]
        
        results = []
        blocked_count = 0
        
        for test_name, test_url in test_cases:
            try:
                response = requests.get(f"{self.base_url}{test_url}", timeout=3)
                blocked = response.status_code == 403
                if blocked:
                    blocked_count += 1
                
                results.append({
                    'test': test_name,
                    'blocked': blocked,
                    'status_code': response.status_code,
                    'response_time': response.elapsed.total_seconds()
                })
                
                status = "[BLOCKED]" if blocked else "[ALLOWED]"
                print(f"  {status} {test_name}: {response.status_code}")
                
            except Exception as e:
                results.append({
                    'test': test_name,
                    'error': str(e),
                    'blocked': False
                })
                print(f"  [FAIL] {test_name}: ERROR - {e}")
        
        protection_rate = (blocked_count / len(test_cases) * 100) if test_cases else 0
        self.results['results']['protection'] = {
            'total_tests': len(test_cases),
            'blocked_count': blocked_count,
            'protection_rate': protection_rate,
            'results': results
        }
        
        print(f"  保護率: {protection_rate:.1f}% ({blocked_count}/{len(test_cases)})")
        return protection_rate >= 50
    
    def test_quick_performance(self):
        """快速性能測試"""
        print("快速性能測試...")
        
        response_times = []
        errors = []
        
        for i in range(10):
            try:
                start = time.time()
                response = requests.get(f"{self.base_url}/", timeout=5)
                end = time.time()
                
                if response.status_code == 200:
                    response_times.append(end - start)
                    print(f"  請求 {i+1}: {response.status_code} ({end-start:.3f}s)")
                else:
                    errors.append(f"Status {response.status_code}")
                    
            except Exception as e:
                errors.append(str(e))
                print(f"  請求 {i+1}: ERROR - {e}")
        
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            min_time = min(response_times)
            success_rate = len(response_times) / 10 * 100
            
            results = {
                'total_requests': 10,
                'successful_requests': len(response_times),
                'error_count': len(errors),
                'success_rate': success_rate,
                'avg_response_time': avg_time,
                'max_response_time': max_time,
                'min_response_time': min_time,
                'response_times': response_times
            }
            
            print(f"  [統計] 成功率: {success_rate:.1f}%")
            print(f"  [統計] 平均響應時間: {avg_time:.3f}s")
            print(f"  [統計] 最大響應時間: {max_time:.3f}s")
            print(f"  [統計] 最小響應時間: {min_time:.3f}s")
            
        else:
            results = {
                'total_requests': 10,
                'successful_requests': 0,
                'error_count': len(errors),
                'success_rate': 0,
                'errors': errors
            }
            print(f"  [FAIL] 所有請求都失敗了")
        
        self.results['results']['performance'] = results
        return results.get('success_rate', 0) >= 70
    
    def test_quick_siem(self):
        """快速 SIEM 測試"""
        print("快速 SIEM 測試...")
        
        endpoints = ['/healthz', '/alerts', '/dashboard', '/metrics']
        results = []
        successful = 0
        
        for endpoint in endpoints:
            try:
                response = requests.get(f"{self.siem_url}{endpoint}", timeout=5)
                if response.status_code == 200:
                    successful += 1
                results.append({
                    'endpoint': endpoint,
                    'status': 'PASS' if response.status_code == 200 else 'FAIL',
                    'status_code': response.status_code,
                    'response_time': response.elapsed.total_seconds()
                })
                print(f"  [OK] {endpoint}: {response.status_code}")
            except Exception as e:
                results.append({
                    'endpoint': endpoint,
                    'status': 'ERROR',
                    'error': str(e)
                })
                print(f"  [FAIL] {endpoint}: ERROR - {e}")
        
        success_rate = (successful / len(endpoints) * 100) if endpoints else 0
        self.results['results']['siem'] = {
            'total_endpoints': len(endpoints),
            'successful_endpoints': successful,
            'success_rate': success_rate,
            'results': results
        }
        
        print(f"  SIEM 成功率: {success_rate:.1f}% ({successful}/{len(endpoints)})")
        return success_rate >= 50
    
    def test_quick_stability(self):
        """快速穩定性測試"""
        print("快速穩定性測試...")
        
        success_count = 0
        total_requests = 8
        
        for i in range(total_requests):
            try:
                response = requests.get(f"{self.base_url}/", timeout=3)
                if response.status_code == 200:
                    success_count += 1
                print(f"  穩定性測試 {i+1}: {response.status_code}")
            except Exception as e:
                print(f"  穩定性測試 {i+1}: ERROR - {e}")
        
        stability_rate = (success_count / total_requests * 100) if total_requests > 0 else 0
        results = {
            'total_requests': total_requests,
            'successful_requests': success_count,
            'stability_rate': stability_rate
        }
        
        self.results['results']['stability'] = results
        print(f"  穩定性: {stability_rate:.1f}% ({success_count}/{total_requests})")
        return stability_rate >= 60
    
    def generate_quick_summary(self):
        """生成快速摘要"""
        print("\n" + "="*50)
        print("快速測試摘要")
        print("="*50)
        
        # 計算總體統計
        total_tests = 0
        passed_tests = 0
        
        test_results = {
            '連通性': self.results['results'].get('connectivity', []),
            '保護功能': self.results['results'].get('protection', {}),
            '性能': self.results['results'].get('performance', {}),
            'SIEM': self.results['results'].get('siem', {}),
            '穩定性': self.results['results'].get('stability', {})
        }
        
        for test_name, test_data in test_results.items():
            if test_name == '連通性':
                passed = len([r for r in test_data if r.get('status') == 'PASS'])
                total = len(test_data)
            elif test_name == '保護功能':
                passed = 1 if test_data.get('protection_rate', 0) >= 50 else 0
                total = 1
            elif test_name == '性能':
                passed = 1 if test_data.get('success_rate', 0) >= 70 else 0
                total = 1
            elif test_name == 'SIEM':
                passed = 1 if test_data.get('success_rate', 0) >= 50 else 0
                total = 1
            elif test_name == '穩定性':
                passed = 1 if test_data.get('stability_rate', 0) >= 60 else 0
                total = 1
            else:
                passed = 0
                total = 1
            
            total_tests += total
            passed_tests += passed
            
            status = "[PASS]" if passed >= total else "[FAIL]"
            print(f"{test_name}: {status}")
        
        overall_success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        overall_status = "[PASS]" if overall_success_rate >= 60 else "[FAIL]"
        
        print(f"\n總體狀態: {overall_status}")
        print(f"總體成功率: {overall_success_rate:.1f}% ({passed_tests}/{total_tests})")
        
        # 保存結果
        self.results['summary'] = {
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'overall_success_rate': overall_success_rate,
            'overall_status': 'PASS' if overall_success_rate >= 60 else 'FAIL'
        }
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"QUICK_TEST_RESULTS_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)
        
        print(f"\n結果已保存到: {filename}")
        
        return overall_success_rate >= 60
    
    def run_quick_tests(self):
        """運行快速測試"""
        print("開始快速測試...")
        print("="*50)
        
        start_time = time.time()
        
        # 運行所有測試
        tests = [
            ('連通性測試', self.test_quick_connectivity),
            ('保護功能測試', self.test_quick_protection),
            ('性能測試', self.test_quick_performance),
            ('SIEM 測試', self.test_quick_siem),
            ('穩定性測試', self.test_quick_stability)
        ]
        
        for test_name, test_func in tests:
            try:
                print(f"\n執行 {test_name}...")
                test_func()
            except Exception as e:
                print(f"ERROR {test_name} 執行失敗: {e}")
        
        # 生成摘要
        print(f"\n總測試時間: {time.time() - start_time:.1f} 秒")
        success = self.generate_quick_summary()
        
        return success

def main():
    """主函數"""
    tester = QuickTestSuite()
    success = tester.run_quick_tests()
    
    if success:
        print("\n快速測試通過！系統基本功能正常。")
        return 0
    else:
        print("\n快速測試失敗，請檢查系統狀態。")
        return 1

if __name__ == "__main__":
    main()
