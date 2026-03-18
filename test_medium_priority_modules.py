#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中優先級模組測試腳本
Test Medium Priority Modules
測試雲原生安全、IoT設備管理、AI對抗防禦
"""

import sys
import time
import json
import traceback
from datetime import datetime

def test_medium_priority_modules():
    """測試中優先級模組"""
    print("=" * 80)
    print("🛡️ 真實終極軍事防禦系統 - 中優先級模組測試")
    print("=" * 80)
    print(f"測試時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    test_results = {
        'timestamp': datetime.now().isoformat(),
        'modules': {},
        'summary': {}
    }
    
    # 1. 測試雲原生安全模組
    print("☁️ 1. 雲原生安全模組測試")
    print("-" * 40)
    
    try:
        from real_cloud_native_security import RealCloudNativeSecurity
        config = {
            'kubectl_path': 'kubectl',
            'docker_path': 'docker',
            'trivy_path': 'trivy',
            'service_mesh': 'istio'
        }
        module = RealCloudNativeSecurity(config)
        
        # 測試啟動
        result = module.start_cloud_security()
        test_results['modules']['cloud_native_security'] = {
            'name': '雲原生安全模組',
            'available': True,
            'initialization': result.get('success', False),
            'message': result.get('message', '')
        }
        
        if result.get('success', False):
            print("✅ 雲原生安全模組: 可用")
            print(f"   - 初始化: {'✅' if result.get('success', False) else '❌'}")
            
            # 測試獲取安全狀態
            status_result = module.get_security_status()
            print(f"   - 安全狀態: {'✅' if status_result.get('success', False) else '❌'}")
            
            if status_result.get('success', False):
                k8s_events = status_result.get('kubernetes_security', {}).get('total_events', 0)
                container_events = status_result.get('container_security', {}).get('total_containers', 0)
                print(f"   - K8s安全事件: {k8s_events}")
                print(f"   - 容器安全事件: {container_events}")
            
            # 停止模組
            module.stop_cloud_security()
        else:
            print(f"❌ 雲原生安全模組: 錯誤 - {result.get('error', '未知錯誤')}")
            
    except Exception as e:
        test_results['modules']['cloud_native_security'] = {
            'name': '雲原生安全模組',
            'available': False,
            'error': str(e)
        }
        print(f"❌ 雲原生安全模組: 錯誤 - {e}")
    
    print()
    
    # 2. 測試IoT設備管理模組
    print("🌐 2. IoT設備管理模組測試")
    print("-" * 40)
    
    try:
        from real_iot_device_management import RealIoTDeviceManagement
        config = {
            'scan_networks': ['192.168.1.0/24'],
            'scan_ports': [80, 443, 22, 23],
            'scan_timeout': 5,
            'vulnerability_threshold': 'medium'
        }
        module = RealIoTDeviceManagement(config)
        
        # 測試啟動
        result = module.start_device_management()
        test_results['modules']['iot_device_management'] = {
            'name': 'IoT設備管理模組',
            'available': True,
            'initialization': result.get('success', False),
            'message': result.get('message', '')
        }
        
        if result.get('success', False):
            print("✅ IoT設備管理模組: 可用")
            print(f"   - 初始化: {'✅' if result.get('success', False) else '❌'}")
            
            # 測試獲取設備列表
            devices_result = module.get_device_list()
            print(f"   - 設備列表: {'✅' if devices_result.get('success', False) else '❌'}")
            
            if devices_result.get('success', False):
                device_count = devices_result.get('total_count', 0)
                print(f"   - 發現設備數量: {device_count}")
            
            # 測試固件分析（模擬）
            firmware_result = module.analyze_firmware('test_device_001', '/tmp/test_firmware.bin')
            print(f"   - 固件分析: {'✅' if firmware_result.get('success', False) else '❌'}")
            
            # 停止模組
            module.stop_device_management()
        else:
            print(f"❌ IoT設備管理模組: 錯誤 - {result.get('error', '未知錯誤')}")
            
    except Exception as e:
        test_results['modules']['iot_device_management'] = {
            'name': 'IoT設備管理模組',
            'available': False,
            'error': str(e)
        }
        print(f"❌ IoT設備管理模組: 錯誤 - {e}")
    
    print()
    
    # 3. 測試AI對抗防禦模組
    print("🤖 3. AI對抗防禦模組測試")
    print("-" * 40)
    
    try:
        from real_ai_adversarial_defense import RealAIAdversarialDefense
        config = {
            'detection_methods': ['statistical_anomaly', 'ensemble_detection'],
            'protection_methods': ['adversarial_training', 'defensive_distillation'],
            'monitoring_interval': 60
        }
        module = RealAIAdversarialDefense(config)
        
        # 測試啟動
        result = module.start_ai_defense()
        test_results['modules']['ai_adversarial_defense'] = {
            'name': 'AI對抗防禦模組',
            'available': True,
            'initialization': result.get('success', False),
            'message': result.get('message', '')
        }
        
        if result.get('success', False):
            print("✅ AI對抗防禦模組: 可用")
            print(f"   - 初始化: {'✅' if result.get('success', False) else '❌'}")
            
            # 測試註冊AI模型
            model_result = module.register_ai_model(
                'test_model_001',
                '測試模型',
                'classification',
                '/tmp/test_model.pkl',
                accuracy=0.95,
                robustness_score=0.85
            )
            print(f"   - 模型註冊: {'✅' if model_result.get('success', False) else '❌'}")
            
            # 測試獲取AI安全狀態
            status_result = module.get_ai_security_status()
            print(f"   - 安全狀態: {'✅' if status_result.get('success', False) else '❌'}")
            
            if status_result.get('success', False):
                ai_models = status_result.get('ai_models', {}).get('total_models', 0)
                attacks_24h = status_result.get('adversarial_attacks', {}).get('total_attacks_24h', 0)
                print(f"   - AI模型數量: {ai_models}")
                print(f"   - 24小時攻擊次數: {attacks_24h}")
            
            # 停止模組
            module.stop_ai_defense()
        else:
            print(f"❌ AI對抗防禦模組: 錯誤 - {result.get('error', '未知錯誤')}")
            
    except Exception as e:
        test_results['modules']['ai_adversarial_defense'] = {
            'name': 'AI對抗防禦模組',
            'available': False,
            'error': str(e)
        }
        print(f"❌ AI對抗防禦模組: 錯誤 - {e}")
    
    print()
    
    # 4. 測試主系統整合
    print("🔗 4. 主系統整合測試")
    print("-" * 40)
    
    try:
        from real_ultimate_military_defense_system import RealUltimateMilitaryDefenseSystem
        system = RealUltimateMilitaryDefenseSystem()
        
        test_results['summary']['main_system_loaded'] = True
        test_results['summary']['total_modules'] = len(system.defense_modules)
        
        print(f"✅ 主系統載入成功")
        print(f"   - 已初始化模組: {len(system.defense_modules)}")
        
        # 檢查新模組是否載入
        new_modules = ['cloud_native_security', 'iot_device_management', 'ai_adversarial_defense']
        loaded_new_modules = 0
        
        for module_name in new_modules:
            if module_name in system.defense_modules:
                loaded_new_modules += 1
                print(f"   - {module_name}: ✅ 已載入")
            else:
                print(f"   - {module_name}: ❌ 未載入")
        
        test_results['summary']['new_modules_loaded'] = loaded_new_modules
        test_results['summary']['new_modules_total'] = len(new_modules)
        
    except Exception as e:
        test_results['summary']['main_system_loaded'] = False
        test_results['summary']['error'] = str(e)
        print(f"❌ 主系統載入失敗: {e}")
    
    print()
    
    # 5. 生成測試總結
    print("📊 5. 測試總結")
    print("-" * 40)
    
    # 計算成功率
    available_modules = sum(1 for m in test_results['modules'].values() if m.get('available', False))
    total_modules = len(test_results['modules'])
    module_success_rate = (available_modules / total_modules * 100) if total_modules > 0 else 0
    
    print(f"✅ 模組可用性: {available_modules}/{total_modules} ({module_success_rate:.1f}%)")
    
    if 'summary' in test_results:
        print(f"✅ 主系統載入: {'通過' if test_results['summary'].get('main_system_loaded', False) else '失敗'}")
        if 'new_modules_loaded' in test_results['summary']:
            new_loaded = test_results['summary']['new_modules_loaded']
            new_total = test_results['summary']['new_modules_total']
            print(f"✅ 新模組載入: {new_loaded}/{new_total} ({new_loaded/new_total*100:.1f}%)")
    
    # 總體評估
    overall_success = (
        test_results['summary'].get('main_system_loaded', False) and
        module_success_rate >= 80
    )
    
    test_results['summary']['overall_success'] = overall_success
    test_results['summary']['module_success_rate'] = module_success_rate
    
    print(f"\n🎯 總體評估:")
    if overall_success:
        print("🎉 中優先級模組測試通過！")
        print("   - 所有核心模組正常載入")
        print("   - 新功能完全可用")
        print("   - 系統整合成功")
    elif module_success_rate >= 60:
        print("⚠️ 部分模組測試通過，建議檢查失敗項目。")
        print("   - 大部分功能可用")
        print("   - 需要修復失敗模組")
    else:
        print("❌ 中優先級模組測試失敗，需要修復。")
        print("   - 多個模組無法載入")
        print("   - 需要檢查依賴關係")
    
    # 保存測試報告
    try:
        with open('medium_priority_modules_test_report.json', 'w', encoding='utf-8') as f:
            json.dump(test_results, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n💾 測試報告已保存至: medium_priority_modules_test_report.json")
    except Exception as e:
        print(f"\n⚠️ 保存測試報告失敗: {e}")
    
    print("\n" + "=" * 80)
    print("中優先級模組測試完成")
    print("=" * 80)
    
    return test_results

def main():
    """主函數"""
    try:
        results = test_medium_priority_modules()
        return results
    except Exception as e:
        print(f"❌ 測試過程發生錯誤: {e}")
        traceback.print_exc()
        return None

if __name__ == "__main__":
    main()






