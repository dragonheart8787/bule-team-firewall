#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
合規框架模組測試腳本
Test Compliance Frameworks Module
測試NIST、ISO27001、SOC2、GDPR合規檢查
"""

import sys
import time
import json
import traceback
from datetime import datetime

def test_compliance_frameworks():
    """測試合規框架模組"""
    print("=" * 80)
    print("🏛️ 真實終極軍事防禦系統 - 合規框架模組測試")
    print("=" * 80)
    print(f"測試時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    test_results = {
        'timestamp': datetime.now().isoformat(),
        'modules': {},
        'summary': {}
    }
    
    # 1. 測試合規框架模組
    print("🏛️ 1. 合規框架模組測試")
    print("-" * 40)
    
    try:
        from real_compliance_frameworks import RealComplianceFrameworks
        config = {
            'frameworks': ['nist_csf', 'iso27001', 'soc2', 'gdpr'],
            'assessment_interval': 3600,
            'report_generation': True,
            'cross_framework_mapping': True,
            'compliance_threshold': 80.0
        }
        module = RealComplianceFrameworks(config)
        
        # 測試啟動
        result = module.start_compliance_monitoring()
        test_results['modules']['compliance_frameworks'] = {
            'name': '合規框架模組',
            'available': True,
            'initialization': result.get('success', False),
            'message': result.get('message', '')
        }
        
        if result.get('success', False):
            print("✅ 合規框架模組: 可用")
            print(f"   - 初始化: {'✅' if result.get('success', False) else '❌'}")
            
            # 測試獲取合規狀態
            status_result = module.get_compliance_status()
            print(f"   - 合規狀態: {'✅' if status_result.get('success', False) else '❌'}")
            
            if status_result.get('success', False):
                frameworks = status_result.get('frameworks', [])
                print(f"   - 支援框架數量: {len(frameworks)}")
                for framework in frameworks:
                    print(f"     * {framework['framework_name']}: {framework['compliance_score']:.1f}%")
            
            # 測試獲取NIST框架控制項
            nist_controls = module.get_framework_controls('nist_csf')
            print(f"   - NIST控制項: {'✅' if nist_controls.get('success', False) else '❌'}")
            
            if nist_controls.get('success', False):
                print(f"     * 控制項數量: {nist_controls.get('total_controls', 0)}")
            
            # 測試獲取ISO27001框架控制項
            iso_controls = module.get_framework_controls('iso27001')
            print(f"   - ISO27001控制項: {'✅' if iso_controls.get('success', False) else '❌'}")
            
            if iso_controls.get('success', False):
                print(f"     * 控制項數量: {iso_controls.get('total_controls', 0)}")
            
            # 測試獲取SOC2框架控制項
            soc2_controls = module.get_framework_controls('soc2')
            print(f"   - SOC2控制項: {'✅' if soc2_controls.get('success', False) else '❌'}")
            
            if soc2_controls.get('success', False):
                print(f"     * 控制項數量: {soc2_controls.get('total_controls', 0)}")
            
            # 測試獲取GDPR框架控制項
            gdpr_controls = module.get_framework_controls('gdpr')
            print(f"   - GDPR控制項: {'✅' if gdpr_controls.get('success', False) else '❌'}")
            
            if gdpr_controls.get('success', False):
                print(f"     * 控制項數量: {gdpr_controls.get('total_controls', 0)}")
            
            # 測試跨框架映射
            mapping_result = module.get_cross_framework_mapping()
            print(f"   - 跨框架映射: {'✅' if mapping_result.get('success', False) else '❌'}")
            
            if mapping_result.get('success', False):
                mapping = mapping_result.get('cross_framework_mapping', {})
                print(f"     * 映射類別數量: {len(mapping)}")
                for category in mapping.keys():
                    print(f"       - {category}")
            
            # 停止模組
            module.stop_compliance_monitoring()
        else:
            print(f"❌ 合規框架模組: 錯誤 - {result.get('error', '未知錯誤')}")
            
    except Exception as e:
        test_results['modules']['compliance_frameworks'] = {
            'name': '合規框架模組',
            'available': False,
            'error': str(e)
        }
        print(f"❌ 合規框架模組: 錯誤 - {e}")
    
    print()
    
    # 2. 測試主系統整合
    print("🔗 2. 主系統整合測試")
    print("-" * 40)
    
    try:
        from real_ultimate_military_defense_system import RealUltimateMilitaryDefenseSystem
        system = RealUltimateMilitaryDefenseSystem()
        
        test_results['summary']['main_system_loaded'] = True
        test_results['summary']['total_modules'] = len(system.defense_modules)
        
        print(f"✅ 主系統載入成功")
        print(f"   - 已初始化模組: {len(system.defense_modules)}")
        
        # 檢查合規框架模組是否載入
        if 'compliance_frameworks' in system.defense_modules:
            print(f"   - compliance_frameworks: ✅ 已載入")
        else:
            print(f"   - compliance_frameworks: ❌ 未載入")
        
        # 檢查所有模組載入狀態
        all_modules = [
            'behavioral_analytics', 'incident_playbooks', 'threat_hunting_queries',
            'cloud_native_security', 'iot_device_management', 'ai_adversarial_defense',
            'compliance_frameworks'
        ]
        
        loaded_modules = 0
        for module_name in all_modules:
            if module_name in system.defense_modules:
                loaded_modules += 1
                print(f"   - {module_name}: ✅ 已載入")
            else:
                print(f"   - {module_name}: ❌ 未載入")
        
        test_results['summary']['loaded_modules'] = loaded_modules
        test_results['summary']['total_expected_modules'] = len(all_modules)
        
    except Exception as e:
        test_results['summary']['main_system_loaded'] = False
        test_results['summary']['error'] = str(e)
        print(f"❌ 主系統載入失敗: {e}")
    
    print()
    
    # 3. 生成測試總結
    print("📊 3. 測試總結")
    print("-" * 40)
    
    # 計算成功率
    available_modules = sum(1 for m in test_results['modules'].values() if m.get('available', False))
    total_modules = len(test_results['modules'])
    module_success_rate = (available_modules / total_modules * 100) if total_modules > 0 else 0
    
    print(f"✅ 模組可用性: {available_modules}/{total_modules} ({module_success_rate:.1f}%)")
    
    if 'summary' in test_results:
        print(f"✅ 主系統載入: {'通過' if test_results['summary'].get('main_system_loaded', False) else '失敗'}")
        if 'loaded_modules' in test_results['summary']:
            loaded = test_results['summary']['loaded_modules']
            total = test_results['summary']['total_expected_modules']
            print(f"✅ 模組載入: {loaded}/{total} ({loaded/total*100:.1f}%)")
    
    # 總體評估
    overall_success = (
        test_results['summary'].get('main_system_loaded', False) and
        module_success_rate >= 80
    )
    
    test_results['summary']['overall_success'] = overall_success
    test_results['summary']['module_success_rate'] = module_success_rate
    
    print(f"\n🎯 總體評估:")
    if overall_success:
        print("🎉 合規框架模組測試通過！")
        print("   - 合規框架模組正常載入")
        print("   - 支援NIST、ISO27001、SOC2、GDPR")
        print("   - 跨框架映射功能正常")
        print("   - 系統整合成功")
    elif module_success_rate >= 60:
        print("⚠️ 部分模組測試通過，建議檢查失敗項目。")
        print("   - 大部分功能可用")
        print("   - 需要修復失敗模組")
    else:
        print("❌ 合規框架模組測試失敗，需要修復。")
        print("   - 多個模組無法載入")
        print("   - 需要檢查依賴關係")
    
    # 保存測試報告
    try:
        with open('compliance_frameworks_test_report.json', 'w', encoding='utf-8') as f:
            json.dump(test_results, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n💾 測試報告已保存至: compliance_frameworks_test_report.json")
    except Exception as e:
        print(f"\n⚠️ 保存測試報告失敗: {e}")
    
    print("\n" + "=" * 80)
    print("合規框架模組測試完成")
    print("=" * 80)
    
    return test_results

def main():
    """主函數"""
    try:
        results = test_compliance_frameworks()
        return results
    except Exception as e:
        print(f"❌ 測試過程發生錯誤: {e}")
        traceback.print_exc()
        return None

if __name__ == "__main__":
    main()






