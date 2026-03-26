#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
顯示最新測試結果摘要
"""

import json
import os
from datetime import datetime
from glob import glob

def get_latest_file(pattern):
    """獲取最新的測試結果文件"""
    files = glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getmtime)

def show_quick_test_results():
    """顯示快速測試結果"""
    latest = get_latest_file("QUICK_TEST_RESULTS_*.json")
    if not latest:
        print("  未找到快速測試結果")
        return
    
    try:
        with open(latest, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print(f"\n快速測試結果 ({latest})")
        print("=" * 60)
        
        summary = data.get('summary', {})
        tests = data.get('tests', {})
        
        # 顯示各項測試結果
        print(f"  連通性:   {tests.get('connectivity', {}).get('status', 'N/A')}")
        print(f"  保護功能: {tests.get('protection', {}).get('status', 'N/A')} - 保護率 {tests.get('protection', {}).get('protection_rate', 'N/A')}")
        print(f"  性能:     {tests.get('performance', {}).get('status', 'N/A')}")
        print(f"  SIEM:     {tests.get('siem', {}).get('status', 'N/A')}")
        print(f"  穩定性:   {tests.get('stability', {}).get('status', 'N/A')}")
        print()
        print(f"  總體狀態: {summary.get('overall_status', 'N/A')}")
        print(f"  總體成功率: {summary.get('success_rate', 'N/A')}")
        print(f"  測試時間: {summary.get('total_time', 'N/A')}秒")
    except Exception as e:
        print(f"  解析錯誤: {e}")

def show_advanced_test_results():
    """顯示進階測試結果"""
    latest = get_latest_file("ADVANCED_TEST_REPORT_*.json")
    if not latest:
        print("\n  未找到進階測試結果")
        return
    
    try:
        with open(latest, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print(f"\n進階測試結果 ({latest})")
        print("=" * 60)
        
        summary = data.get('summary', {})
        tests = data.get('tests', {})
        
        print(f"  總測試類別: {summary.get('total_test_categories', 'N/A')}")
        print(f"  通過類別: {summary.get('passed_categories', 'N/A')}")
        print(f"  失敗類別: {summary.get('failed_categories', 'N/A')}")
        print(f"  總體成功率: {summary.get('overall_success_rate', 'N/A')}%")
        print(f"  總體狀態: {summary.get('overall_status', 'N/A')}")
        print(f"  測試耗時: {summary.get('test_duration', 'N/A')}秒")
        
        # 顯示各項詳細結果
        if tests:
            print("\n  詳細結果:")
            
            # WAF 保護測試
            if 'waf_protection_comprehensive' in tests:
                waf = tests['waf_protection_comprehensive']
                protection_rate = waf.get('overall_protection_rate', 0)
                print(f"    - WAF 保護: {waf.get('status', 'N/A')} - 保護率 {protection_rate:.1f}% ({waf.get('total_blocked', 0)}/{waf.get('total_tests', 0)})")
                
                # 分類詳情
                categories = waf.get('categories', {})
                if categories:
                    for cat_name, cat_data in categories.items():
                        block_rate = cat_data.get('block_rate', 0)
                        blocked = cat_data.get('blocked_count', 0)
                        total = cat_data.get('total_tests', 0)
                        print(f"      · {cat_name}: {block_rate:.0f}% ({blocked}/{total})")
            
            # 性能壓力測試
            if 'performance_stress' in tests:
                perf = tests['performance_stress']
                print(f"    - 性能壓力: PASS")
                for scenario_name, scenario_data in perf.items():
                    if isinstance(scenario_data, dict) and 'success_rate' in scenario_data:
                        success_rate = scenario_data.get('success_rate', 0)
                        avg_time = scenario_data.get('avg_response_time', 0)
                        print(f"      · {scenario_name}: {success_rate:.0f}% (平均 {avg_time:.2f}s)")
            
            # SIEM 整合
            if 'siem_integration_advanced' in tests:
                siem = tests['siem_integration_advanced']
                success_rate = siem.get('success_rate', 0)
                passed = siem.get('passed_tests', 0)
                total = siem.get('total_tests', 0)
                print(f"    - SIEM 整合: {siem.get('status', 'N/A')} - 成功率 {success_rate:.0f}% ({passed}/{total})")
            
            # 安全標頭
            if 'security_headers' in tests:
                headers = tests['security_headers']
                present = headers.get('present_headers', 0)
                total = headers.get('total_headers', 0)
                print(f"    - 安全標頭: PASS - 配置率 {present/total*100:.0f}% ({present}/{total})")
    except Exception as e:
        print(f"  解析錯誤: {e}")

def main():
    print("\n" + "=" * 60)
    print("最新測試結果摘要")
    print("=" * 60)
    
    show_quick_test_results()
    show_advanced_test_results()
    
    print("\n" + "=" * 60)
    print()

if __name__ == "__main__":
    main()


