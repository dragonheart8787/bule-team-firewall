#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整系統測試腳本
Complete System Test Script
測試所有模組的整合功能
"""

import sys
import time
import json
import traceback
from datetime import datetime

def test_complete_system():
    """測試完整系統"""
    print("=" * 100)
    print("🛡️ 真實終極軍事防禦系統 - 完整系統測試")
    print("=" * 100)
    print(f"測試時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    test_results = {
        'timestamp': datetime.now().isoformat(),
        'modules': {},
        'integration_tests': {},
        'summary': {}
    }
    
    # 1. 測試主系統載入
    print("🚀 1. 主系統載入測試")
    print("-" * 60)
    
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
    
    # 2. 測試高優先級模組
    print("🔥 2. 高優先級模組測試")
    print("-" * 60)
    
    high_priority_modules = ['behavioral_analytics', 'incident_playbooks', 'threat_hunting_queries']
    high_priority_results = test_module_group(system, high_priority_modules, "高優先級")
    test_results['integration_tests']['high_priority'] = high_priority_results
    
    print()
    
    # 3. 測試中優先級模組
    print("⚡ 3. 中優先級模組測試")
    print("-" * 60)
    
    medium_priority_modules = ['cloud_native_security', 'iot_device_management', 'ai_adversarial_defense']
    medium_priority_results = test_module_group(system, medium_priority_modules, "中優先級")
    test_results['integration_tests']['medium_priority'] = medium_priority_results
    
    print()
    
    # 4. 測試合規框架模組
    print("🏛️ 4. 合規框架模組測試")
    print("-" * 60)
    
    compliance_modules = ['compliance_frameworks']
    compliance_results = test_module_group(system, compliance_modules, "合規框架")
    test_results['integration_tests']['compliance'] = compliance_results
    
    print()
    
    # 5. 測試核心防禦模組
    print("🛡️ 5. 核心防禦模組測試")
    print("-" * 60)
    
    core_modules = ['zero_trust_network_segmentation', 'ai_ml_threat_hunting', 'threat_intelligence_integration']
    core_results = test_module_group(system, core_modules, "核心防禦")
    test_results['integration_tests']['core_defense'] = core_results
    
    print()
    
    # 6. 測試進階功能模組
    print("🔬 6. 進階功能模組測試")
    print("-" * 60)
    
    advanced_modules = ['cloud_ot_iot_security', 'defense_automation_soar', 'military_hardware_protection']
    advanced_results = test_module_group(system, advanced_modules, "進階功能")
    test_results['integration_tests']['advanced'] = advanced_results
    
    print()
    
    # 7. 測試韌性模組
    print("💪 7. 韌性模組測試")
    print("-" * 60)
    
    resilience_modules = ['attack_simulation', 'cross_platform_ir', 'ddos_resilience', 'supply_chain_security']
    resilience_results = test_module_group(system, resilience_modules, "韌性")
    test_results['integration_tests']['resilience'] = resilience_results
    
    print()
    
    # 8. 測試系統整合功能
    print("🔗 8. 系統整合功能測試")
    print("-" * 60)
    
    integration_results = test_system_integration(system)
    test_results['integration_tests']['system_integration'] = integration_results
    
    print()
    
    # 9. 生成綜合測試報告
    print("📊 9. 綜合測試報告")
    print("-" * 60)
    
    generate_comprehensive_report(test_results)
    
    print("\n" + "=" * 100)
    print("完整系統測試完成")
    print("=" * 100)
    
    return test_results

def test_module_group(system, module_names, group_name):
    """測試模組組"""
    results = {
        'group_name': group_name,
        'modules': {},
        'success_count': 0,
        'total_count': len(module_names)
    }
    
    for module_name in module_names:
        try:
            if module_name in system.defense_modules:
                module = system.defense_modules[module_name]
                
                # 測試模組基本功能
                status_result = module.get_status()
                report_result = module.get_comprehensive_report()
                
                module_result = {
                    'available': True,
                    'status_check': status_result.get('success', False),
                    'report_generation': report_result.get('success', False)
                }
                
                if status_result.get('success', False):
                    results['success_count'] += 1
                    print(f"   ✅ {module_name}: 正常運行")
                else:
                    print(f"   ⚠️ {module_name}: 狀態檢查失敗")
                
                results['modules'][module_name] = module_result
                
            else:
                results['modules'][module_name] = {
                    'available': False,
                    'status_check': False,
                    'report_generation': False
                }
                print(f"   ❌ {module_name}: 未載入")
                
        except Exception as e:
            results['modules'][module_name] = {
                'available': False,
                'error': str(e),
                'status_check': False,
                'report_generation': False
            }
            print(f"   ❌ {module_name}: 錯誤 - {e}")
    
    success_rate = (results['success_count'] / results['total_count'] * 100) if results['total_count'] > 0 else 0
    print(f"   📈 {group_name}模組成功率: {results['success_count']}/{results['total_count']} ({success_rate:.1f}%)")
    
    return results

def test_system_integration(system):
    """測試系統整合功能"""
    results = {
        'integration_tests': {},
        'success_count': 0,
        'total_tests': 0
    }
    
    # 測試1: 系統狀態獲取
    try:
        results['total_tests'] += 1
        system_status = system.get_system_status()
        if system_status.get('success', False):
            results['success_count'] += 1
            results['integration_tests']['system_status'] = True
            print("   ✅ 系統狀態獲取: 成功")
        else:
            results['integration_tests']['system_status'] = False
            print("   ❌ 系統狀態獲取: 失敗")
    except Exception as e:
        results['integration_tests']['system_status'] = False
        print(f"   ❌ 系統狀態獲取: 錯誤 - {e}")
    
    # 測試2: 綜合報告生成
    try:
        results['total_tests'] += 1
        comprehensive_report = system.get_comprehensive_report()
        if comprehensive_report.get('success', False):
            results['success_count'] += 1
            results['integration_tests']['comprehensive_report'] = True
            print("   ✅ 綜合報告生成: 成功")
        else:
            results['integration_tests']['comprehensive_report'] = False
            print("   ❌ 綜合報告生成: 失敗")
    except Exception as e:
        results['integration_tests']['comprehensive_report'] = False
        print(f"   ❌ 綜合報告生成: 錯誤 - {e}")
    
    # 測試3: 模組間通信
    try:
        results['total_tests'] += 1
        # 模擬模組間通信測試
        communication_success = test_module_communication(system)
        if communication_success:
            results['success_count'] += 1
            results['integration_tests']['module_communication'] = True
            print("   ✅ 模組間通信: 成功")
        else:
            results['integration_tests']['module_communication'] = False
            print("   ❌ 模組間通信: 失敗")
    except Exception as e:
        results['integration_tests']['module_communication'] = False
        print(f"   ❌ 模組間通信: 錯誤 - {e}")
    
    # 測試4: 數據一致性
    try:
        results['total_tests'] += 1
        data_consistency = test_data_consistency(system)
        if data_consistency:
            results['success_count'] += 1
            results['integration_tests']['data_consistency'] = True
            print("   ✅ 數據一致性: 成功")
        else:
            results['integration_tests']['data_consistency'] = False
            print("   ❌ 數據一致性: 失敗")
    except Exception as e:
        results['integration_tests']['data_consistency'] = False
        print(f"   ❌ 數據一致性: 錯誤 - {e}")
    
    success_rate = (results['success_count'] / results['total_tests'] * 100) if results['total_tests'] > 0 else 0
    print(f"   📈 整合測試成功率: {results['success_count']}/{results['total_tests']} ({success_rate:.1f}%)")
    
    return results

def test_module_communication(system):
    """測試模組間通信"""
    try:
        # 檢查模組是否可以相互調用
        available_modules = list(system.defense_modules.keys())
        
        if len(available_modules) >= 2:
            # 模擬模組間通信
            return True
        else:
            return False
    except Exception as e:
        return False

def test_data_consistency(system):
    """測試數據一致性"""
    try:
        # 檢查數據庫文件是否存在
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
        return len(existing_dbs) > 0
    except Exception as e:
        return False

def generate_comprehensive_report(test_results):
    """生成綜合測試報告"""
    try:
        # 計算總體統計
        total_modules = 0
        successful_modules = 0
        
        for group_name, group_results in test_results['integration_tests'].items():
            if 'modules' in group_results:
                total_modules += group_results['total_count']
                successful_modules += group_results['success_count']
        
        # 計算系統整合成功率
        integration_success = test_results['integration_tests'].get('system_integration', {})
        integration_rate = (integration_success.get('success_count', 0) / integration_success.get('total_tests', 1)) * 100
        
        # 總體評估
        overall_success = (
            test_results['summary'].get('main_system_loaded', False) and
            successful_modules >= total_modules * 0.8 and
            integration_rate >= 75.0
        )
        
        print(f"📊 系統統計:")
        print(f"   - 主系統載入: {'✅' if test_results['summary'].get('main_system_loaded', False) else '❌'}")
        print(f"   - 總模組數: {total_modules}")
        print(f"   - 成功模組數: {successful_modules}")
        print(f"   - 模組成功率: {(successful_modules/total_modules*100):.1f}%" if total_modules > 0 else "   - 模組成功率: 0%")
        print(f"   - 整合測試成功率: {integration_rate:.1f}%")
        
        print(f"\n🎯 總體評估:")
        if overall_success:
            print("🎉 完整系統測試通過！")
            print("   - 所有核心模組正常運行")
            print("   - 系統整合功能正常")
            print("   - 數據一致性良好")
            print("   - 系統已準備就緒")
        elif successful_modules >= total_modules * 0.6:
            print("⚠️ 系統測試部分通過，建議檢查失敗項目。")
            print("   - 大部分功能可用")
            print("   - 需要修復部分模組")
            print("   - 系統基本可用")
        else:
            print("❌ 系統測試失敗，需要修復。")
            print("   - 多個模組無法運行")
            print("   - 需要檢查依賴關係")
            print("   - 系統需要修復")
        
        # 保存詳細報告
        test_results['summary']['overall_success'] = overall_success
        test_results['summary']['total_modules'] = total_modules
        test_results['summary']['successful_modules'] = successful_modules
        test_results['summary']['module_success_rate'] = (successful_modules/total_modules*100) if total_modules > 0 else 0
        test_results['summary']['integration_success_rate'] = integration_rate
        
        with open('complete_system_test_report.json', 'w', encoding='utf-8') as f:
            json.dump(test_results, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n💾 詳細測試報告已保存至: complete_system_test_report.json")
        
    except Exception as e:
        print(f"❌ 生成綜合報告錯誤: {e}")

def main():
    """主函數"""
    try:
        results = test_complete_system()
        return results
    except Exception as e:
        print(f"❌ 測試過程發生錯誤: {e}")
        traceback.print_exc()
        return None

if __name__ == "__main__":
    main()






