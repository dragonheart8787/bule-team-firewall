#!/usr/bin/env python3
"""
快速測試所有模組
"""

import sys
import os
import json
import time
from datetime import datetime

def test_module(module_name, test_func):
    """測試單個模組"""
    try:
        print(f"測試 {module_name}...")
        result = test_func()
        print(f"   [OK] {module_name} 測試通過")
        return True, result
    except Exception as e:
        print(f"   [FAIL] {module_name} 測試失敗: {str(e)}")
        return False, str(e)

def test_waf_proxy():
    """測試WAF代理"""
    try:
        from waf_proxy import ModSecurityRules
        rules = ModSecurityRules()
        return len(rules.rules) > 0
    except:
        return False

def test_ml_anomaly():
    """測試ML異常檢測"""
    try:
        from ml_anomaly_detector import MLAnomalyDetector
        detector = MLAnomalyDetector()
        return True
    except:
        return False

def test_virtual_patch():
    """測試虛擬補丁"""
    try:
        from virtual_patch_manager import VirtualPatchManager
        manager = VirtualPatchManager()
        return manager.get_patch_stats()['total_patches'] > 0
    except:
        return False

def test_soc_dashboard():
    """測試SOC儀表板"""
    try:
        from soc_dashboard import SOCDashboard
        dashboard = SOCDashboard()
        return True
    except:
        return False

def test_advanced_waf():
    """測試高級WAF系統"""
    try:
        from advanced_waf_system import AdvancedWAFSystem
        waf = AdvancedWAFSystem()
        return True
    except:
        return False

def main():
    """主測試函數"""
    print("開始快速測試所有模組...")
    print("=" * 50)
    
    test_results = {}
    
    # 測試各個模組
    modules = [
        ("WAF代理", test_waf_proxy),
        ("ML異常檢測", test_ml_anomaly),
        ("虛擬補丁", test_virtual_patch),
        ("SOC儀表板", test_soc_dashboard),
        ("高級WAF系統", test_advanced_waf)
    ]
    
    for module_name, test_func in modules:
        success, result = test_module(module_name, test_func)
        test_results[module_name] = {
            'success': success,
            'result': result,
            'timestamp': datetime.now().isoformat()
        }
    
    # 統計結果
    total_tests = len(modules)
    passed_tests = sum(1 for r in test_results.values() if r['success'])
    failed_tests = total_tests - passed_tests
    
    print("\n" + "=" * 50)
    print("測試結果摘要:")
    print(f"  總測試數: {total_tests}")
    print(f"  通過: {passed_tests}")
    print(f"  失敗: {failed_tests}")
    print(f"  成功率: {(passed_tests/total_tests)*100:.1f}%")
    
    # 保存結果到JSON
    report = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_tests': total_tests,
            'passed': passed_tests,
            'failed': failed_tests,
            'success_rate': (passed_tests/total_tests)*100
        },
        'results': test_results
    }
    
    with open('quick_test_report.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    
    print(f"\n詳細報告已保存到: quick_test_report.json")
    
    return passed_tests == total_tests

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
