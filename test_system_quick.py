#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速系統測試腳本
Quick System Test Script
快速驗證系統核心功能
"""

import sys
import time
import json
import traceback
from datetime import datetime

def test_system_quick():
    """快速系統測試"""
    print("=" * 80)
    print("🛡️ 真實終極軍事防禦系統 - 快速測試")
    print("=" * 80)
    print(f"測試時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    test_results = {
        'timestamp': datetime.now().isoformat(),
        'modules': {},
        'summary': {}
    }
    
    # 1. 測試主系統載入
    print("🚀 1. 主系統載入測試")
    print("-" * 40)
    
    try:
        from real_ultimate_military_defense_system import RealUltimateMilitaryDefenseSystem
        system = RealUltimateMilitaryDefenseSystem()
        
        test_results['summary']['main_system_loaded'] = True
        test_results['summary']['total_modules'] = len(system.defense_modules)
        
        print(f"✅ 主系統載入成功")
        print(f"   - 已初始化模組: {len(system.defense_modules)}")
        print(f"   - 模組列表: {list(system.defense_modules.keys())}")
        
    except Exception as e:
        test_results['summary']['main_system_loaded'] = False
        test_results['summary']['error'] = str(e)
        print(f"❌ 主系統載入失敗: {e}")
        return test_results
    
    print()
    
    # 2. 測試核心模組狀態
    print("🔍 2. 核心模組狀態測試")
    print("-" * 40)
    
    core_modules = [
        'behavioral_analytics',
        'incident_playbooks', 
        'threat_hunting_queries',
        'cloud_native_security',
        'iot_device_management',
        'ai_adversarial_defense',
        'compliance_frameworks'
    ]
    
    successful_modules = 0
    total_modules = len(core_modules)
    
    for module_name in core_modules:
        try:
            if module_name in system.defense_modules:
                module = system.defense_modules[module_name]
                status_result = module.get_status()
                
                if status_result.get('success', False):
                    successful_modules += 1
                    print(f"   ✅ {module_name}: 正常運行")
                    test_results['modules'][module_name] = {
                        'available': True,
                        'status': 'running',
                        'success': True
                    }
                else:
                    print(f"   ⚠️ {module_name}: 狀態異常")
                    test_results['modules'][module_name] = {
                        'available': True,
                        'status': 'error',
                        'success': False
                    }
            else:
                print(f"   ❌ {module_name}: 未載入")
                test_results['modules'][module_name] = {
                    'available': False,
                    'status': 'not_loaded',
                    'success': False
                }
                
        except Exception as e:
            print(f"   ❌ {module_name}: 錯誤 - {e}")
            test_results['modules'][module_name] = {
                'available': False,
                'status': 'error',
                'success': False,
                'error': str(e)
            }
    
    success_rate = (successful_modules / total_modules * 100) if total_modules > 0 else 0
    print(f"   📈 核心模組成功率: {successful_modules}/{total_modules} ({success_rate:.1f}%)")
    
    print()
    
    # 3. 測試系統整合功能
    print("🔗 3. 系統整合功能測試")
    print("-" * 40)
    
    integration_tests = []
    
    # 測試系統狀態獲取
    try:
        system_status = system.get_system_status()
        if system_status.get('success', False):
            integration_tests.append(('系統狀態獲取', True))
            print("   ✅ 系統狀態獲取: 成功")
        else:
            integration_tests.append(('系統狀態獲取', False))
            print("   ❌ 系統狀態獲取: 失敗")
    except Exception as e:
        integration_tests.append(('系統狀態獲取', False))
        print(f"   ❌ 系統狀態獲取: 錯誤 - {e}")
    
    # 測試綜合報告生成
    try:
        comprehensive_report = system.get_comprehensive_report()
        if comprehensive_report.get('success', False):
            integration_tests.append(('綜合報告生成', True))
            print("   ✅ 綜合報告生成: 成功")
        else:
            integration_tests.append(('綜合報告生成', False))
            print("   ❌ 綜合報告生成: 失敗")
    except Exception as e:
        integration_tests.append(('綜合報告生成', False))
        print(f"   ❌ 綜合報告生成: 錯誤 - {e}")
    
    # 測試數據庫文件
    try:
        import os
        db_files = [
            'behavioral_analytics.db',
            'incident_playbooks.db', 
            'threat_hunting_queries.db',
            'cloud_native_security.db',
            'iot_device_management.db',
            'ai_adversarial_defense.db',
            'compliance_frameworks.db'
        ]
        
        existing_dbs = [f for f in db_files if os.path.exists(f)]
        if len(existing_dbs) > 0:
            integration_tests.append(('數據庫文件', True))
            print(f"   ✅ 數據庫文件: 成功 ({len(existing_dbs)}/{len(db_files)})")
        else:
            integration_tests.append(('數據庫文件', False))
            print("   ❌ 數據庫文件: 失敗")
    except Exception as e:
        integration_tests.append(('數據庫文件', False))
        print(f"   ❌ 數據庫文件: 錯誤 - {e}")
    
    integration_success = sum(1 for _, success in integration_tests if success)
    integration_total = len(integration_tests)
    integration_rate = (integration_success / integration_total * 100) if integration_total > 0 else 0
    
    print(f"   📈 整合測試成功率: {integration_success}/{integration_total} ({integration_rate:.1f}%)")
    
    print()
    
    # 4. 生成測試總結
    print("📊 4. 測試總結")
    print("-" * 40)
    
    # 總體評估
    overall_success = (
        test_results['summary'].get('main_system_loaded', False) and
        success_rate >= 70.0 and
        integration_rate >= 66.7
    )
    
    print(f"📊 系統統計:")
    print(f"   - 主系統載入: {'✅' if test_results['summary'].get('main_system_loaded', False) else '❌'}")
    print(f"   - 總模組數: {total_modules}")
    print(f"   - 成功模組數: {successful_modules}")
    print(f"   - 模組成功率: {success_rate:.1f}%")
    print(f"   - 整合測試成功率: {integration_rate:.1f}%")
    
    print(f"\n🎯 總體評估:")
    if overall_success:
        print("🎉 系統測試通過！")
        print("   - 主系統正常載入")
        print("   - 核心模組運行正常")
        print("   - 系統整合功能正常")
        print("   - 系統已準備就緒")
    elif success_rate >= 50.0:
        print("⚠️ 系統測試部分通過，建議檢查失敗項目。")
        print("   - 大部分功能可用")
        print("   - 需要修復部分模組")
        print("   - 系統基本可用")
    else:
        print("❌ 系統測試失敗，需要修復。")
        print("   - 多個模組無法運行")
        print("   - 需要檢查依賴關係")
        print("   - 系統需要修復")
    
    # 保存測試結果
    test_results['summary']['overall_success'] = overall_success
    test_results['summary']['module_success_rate'] = success_rate
    test_results['summary']['integration_success_rate'] = integration_rate
    test_results['summary']['successful_modules'] = successful_modules
    test_results['summary']['total_modules'] = total_modules
    test_results['integration_tests'] = integration_tests
    
    try:
        with open('quick_system_test_report.json', 'w', encoding='utf-8') as f:
            json.dump(test_results, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n💾 測試報告已保存至: quick_system_test_report.json")
    except Exception as e:
        print(f"\n⚠️ 保存測試報告失敗: {e}")
    
    print("\n" + "=" * 80)
    print("快速系統測試完成")
    print("=" * 80)
    
    return test_results

def main():
    """主函數"""
    try:
        results = test_system_quick()
        return results
    except Exception as e:
        print(f"❌ 測試過程發生錯誤: {e}")
        traceback.print_exc()
        return None

if __name__ == "__main__":
    main()






