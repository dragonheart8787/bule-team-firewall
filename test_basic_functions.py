#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基本功能測試腳本
測試能正常載入的防禦模組功能
"""

import sys
import time
import json
import traceback
from datetime import datetime

def test_available_modules():
    """測試可用的模組"""
    print("=" * 60)
    print("🔧 測試可用模組")
    print("=" * 60)
    
    available_modules = {}
    
    # 測試跨平台IR模組
    try:
        from real_cross_platform_ir import RealCrossPlatformIR
        config = {'enable_osquery': True, 'osquery': {'osqueryi_path': 'osqueryi'}}
        module = RealCrossPlatformIR(config)
        result = module.start_ir()
        available_modules['cross_platform_ir'] = {
            'module': module,
            'status': result.get('success', False),
            'message': result.get('message', '')
        }
        print(f"✅ 跨平台IR模組: 可用")
    except Exception as e:
        print(f"❌ 跨平台IR模組: 錯誤 - {e}")
        available_modules['cross_platform_ir'] = {'status': False, 'error': str(e)}
    
    # 測試DDoS韌性模組
    try:
        from real_ddos_resilience import RealDDOSResilience
        config = {'threshold_pps': 100000, 'default_action': 'rate_limit'}
        module = RealDDOSResilience(config)
        result = module.start_resilience()
        available_modules['ddos_resilience'] = {
            'module': module,
            'status': result.get('success', False),
            'message': result.get('message', '')
        }
        print(f"✅ DDoS韌性模組: 可用")
    except Exception as e:
        print(f"❌ DDoS韌性模組: 錯誤 - {e}")
        available_modules['ddos_resilience'] = {'status': False, 'error': str(e)}
    
    # 測試供應鏈安全模組
    try:
        from real_supply_chain_security import RealSupplyChainSecurity
        config = {'sbom': {'syft_path': 'syft'}, 'sign': {'cosign_path': 'cosign'}}
        module = RealSupplyChainSecurity(config)
        result = module.generate_sbom('.')
        available_modules['supply_chain_security'] = {
            'module': module,
            'status': result.get('success', False),
            'message': result.get('message', '')
        }
        print(f"✅ 供應鏈安全模組: 可用")
    except Exception as e:
        print(f"❌ 供應鏈安全模組: 錯誤 - {e}")
        available_modules['supply_chain_security'] = {'status': False, 'error': str(e)}
    
    # 測試攻擊圖譜模組
    try:
        from real_attack_graph import RealAttackGraph
        config = {}
        module = RealAttackGraph(config)
        module.add_node('test', 'Test Node', 'event')
        module.add_technique('T1059')
        graph = module.get_graph()
        available_modules['attack_graph'] = {
            'module': module,
            'status': True,
            'message': '攻擊圖譜功能正常'
        }
        print(f"✅ 攻擊圖譜模組: 可用")
    except Exception as e:
        print(f"❌ 攻擊圖譜模組: 錯誤 - {e}")
        available_modules['attack_graph'] = {'status': False, 'error': str(e)}
    
    # 測試攻防演練模組
    try:
        from real_attack_simulation import RealAttackSimulation
        config = {'enable_atomic': False, 'enable_caldera': False}
        module = RealAttackSimulation(config)
        result = module.run_simulation()
        available_modules['attack_simulation'] = {
            'module': module,
            'status': result.get('success', False),
            'message': result.get('message', '')
        }
        print(f"✅ 攻防演練模組: 可用")
    except Exception as e:
        print(f"❌ 攻防演練模組: 錯誤 - {e}")
        available_modules['attack_simulation'] = {'status': False, 'error': str(e)}
    
    return available_modules

def test_module_functions(available_modules):
    """測試模組功能"""
    print("\n" + "=" * 60)
    print("🔍 測試模組功能")
    print("=" * 60)
    
    test_results = {}
    
    for name, info in available_modules.items():
        if not info.get('status', False):
            print(f"⚠️  {name}: 跳過（不可用）")
            continue
            
        module = info.get('module')
        if not module:
            print(f"⚠️  {name}: 跳過（無模組實例）")
            continue
        
        try:
            # 測試狀態獲取
            if hasattr(module, 'get_status'):
                status = module.get_status()
                print(f"📊 {name} 狀態: {'✅' if status.get('success', False) else '❌'}")
                test_results[f'{name}_status'] = status.get('success', False)
            
            # 測試綜合報告
            if hasattr(module, 'get_comprehensive_report'):
                report = module.get_comprehensive_report()
                print(f"📋 {name} 報告: {'✅' if report.get('success', False) else '❌'}")
                test_results[f'{name}_report'] = report.get('success', False)
            
            # 測試特定功能
            if name == 'cross_platform_ir' and hasattr(module, 'stop_ir'):
                result = module.stop_ir()
                print(f"🛑 {name} 停止: {'✅' if result.get('success', False) else '❌'}")
                test_results[f'{name}_stop'] = result.get('success', False)
            
            elif name == 'ddos_resilience' and hasattr(module, 'stop_resilience'):
                result = module.stop_resilience()
                print(f"🛑 {name} 停止: {'✅' if result.get('success', False) else '❌'}")
                test_results[f'{name}_stop'] = result.get('success', False)
            
            elif name == 'attack_graph':
                navigator = module.export_attack_navigator_layer()
                print(f"🗺️  {name} ATT&CK層: {'✅' if navigator else '❌'}")
                test_results[f'{name}_navigator'] = bool(navigator)
            
            print(f"✅ {name}: 功能測試完成")
            
        except Exception as e:
            print(f"❌ {name}: 功能測試錯誤 - {e}")
            test_results[f'{name}_error'] = str(e)
    
    return test_results

def test_configuration():
    """測試配置檔案"""
    print("\n" + "=" * 60)
    print("⚙️ 測試配置檔案")
    print("=" * 60)
    
    try:
        import yaml
        with open('real_ultimate_defense_config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        print("✅ 配置檔案載入成功")
        
        # 檢查新模組配置
        new_modules = ['attack_simulation', 'cross_platform_ir', 'ddos_resilience', 'supply_chain_security']
        for module in new_modules:
            if module in config.get('modules', {}):
                enabled = config['modules'][module].get('enabled', False)
                print(f"   - {module}: {'✅ 啟用' if enabled else '❌ 停用'}")
            else:
                print(f"   - {module}: ❌ 未配置")
        
        return True
        
    except Exception as e:
        print(f"❌ 配置測試失敗: {e}")
        return False

def main():
    """主測試函數"""
    print("🛡️ 真實終極軍事防禦系統 - 基本功能測試")
    print("=" * 60)
    print(f"測試時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 1. 測試配置
    config_ok = test_configuration()
    
    # 2. 測試可用模組
    available_modules = test_available_modules()
    
    # 3. 測試模組功能
    test_results = test_module_functions(available_modules)
    
    # 4. 生成測試報告
    print("\n" + "=" * 60)
    print("📋 測試結果總結")
    print("=" * 60)
    
    print(f"✅ 配置載入: {'通過' if config_ok else '失敗'}")
    
    available_count = sum(1 for info in available_modules.values() if info.get('status', False))
    total_count = len(available_modules)
    print(f"✅ 可用模組: {available_count}/{total_count} ({available_count/total_count*100:.1f}%)")
    
    # 功能測試結果
    success_count = sum(1 for result in test_results.values() if result is True)
    total_tests = len([r for r in test_results.values() if isinstance(r, bool)])
    if total_tests > 0:
        print(f"✅ 功能測試: {success_count}/{total_tests} ({success_count/total_tests*100:.1f}%)")
    
    # 詳細結果
    print("\n📊 詳細結果:")
    for name, info in available_modules.items():
        status = "✅" if info.get('status', False) else "❌"
        print(f"   - {name}: {status}")
    
    # 保存測試報告
    report = {
        'timestamp': datetime.now().isoformat(),
        'config_ok': config_ok,
        'available_modules': available_modules,
        'test_results': test_results,
        'summary': {
            'available_count': available_count,
            'total_count': total_count,
            'success_rate': (available_count/total_count*100) if total_count > 0 else 0
        }
    }
    
    try:
        with open('basic_test_results.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n💾 測試報告已保存至: basic_test_results.json")
    except Exception as e:
        print(f"\n⚠️ 保存測試報告失敗: {e}")
    
    if available_count >= 3:
        print("\n🎉 基本功能測試通過！核心模組運行正常。")
    elif available_count >= 1:
        print("\n⚠️ 部分功能正常，建議檢查失敗模組。")
    else:
        print("\n❌ 基本功能測試失敗，需要修復。")

if __name__ == "__main__":
    main()


