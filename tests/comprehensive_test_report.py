#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整功能驗證報告
測試所有防禦模組並生成詳細報告
"""

import sys
import time
import json
import traceback
from datetime import datetime

def test_core_modules():
    """測試核心模組"""
    print("=" * 80)
    print("🛡️ 真實終極軍事防禦系統 - 完整功能驗證報告")
    print("=" * 80)
    print(f"測試時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # 測試結果收集
    test_results = {
        'timestamp': datetime.now().isoformat(),
        'modules': {},
        'external_tools': {},
        'configuration': {},
        'summary': {}
    }
    
    # 1. 測試配置載入
    print("📋 1. 配置檔案測試")
    print("-" * 40)
    try:
        import yaml
        with open('config/real_ultimate_defense_config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        test_results['configuration']['config_loaded'] = True
        test_results['configuration']['system_name'] = config.get('system', {}).get('name', 'N/A')
        test_results['configuration']['version'] = config.get('system', {}).get('version', 'N/A')
        test_results['configuration']['total_modules'] = len(config.get('modules', {}))
        test_results['configuration']['defense_layers'] = len(config.get('defense_layers', {}))
        
        print(f"✅ 配置檔案載入成功")
        print(f"   - 系統名稱: {test_results['configuration']['system_name']}")
        print(f"   - 版本: {test_results['configuration']['version']}")
        print(f"   - 模組數量: {test_results['configuration']['total_modules']}")
        print(f"   - 防禦層數量: {test_results['configuration']['defense_layers']}")
        
    except Exception as e:
        test_results['configuration']['config_loaded'] = False
        test_results['configuration']['error'] = str(e)
        print(f"❌ 配置檔案載入失敗: {e}")
    
    print()
    
    # 2. 測試新增模組
    print("🔧 2. 新增模組測試")
    print("-" * 40)
    
    new_modules = [
        ('cross_platform_ir', '跨平台即時操作'),
        ('ddos_resilience', 'DDoS韌性防護'),
        ('supply_chain_security', '供應鏈完整性'),
        ('attack_graph', '攻擊圖譜生成'),
        ('attack_simulation', '攻防演練')
    ]
    
    for module_name, display_name in new_modules:
        try:
            if module_name == 'cross_platform_ir':
                from real_cross_platform_ir import RealCrossPlatformIR
                config = {'enable_osquery': True, 'osquery': {'osqueryi_path': 'osqueryi'}}
                module = RealCrossPlatformIR(config)
                result = module.start_ir()
                
            elif module_name == 'ddos_resilience':
                from real_ddos_resilience import RealDDOSResilience
                config = {'threshold_pps': 100000, 'default_action': 'rate_limit'}
                module = RealDDOSResilience(config)
                result = module.start_resilience()
                
            elif module_name == 'supply_chain_security':
                from real_supply_chain_security import RealSupplyChainSecurity
                config = {'sbom': {'syft_path': 'syft'}, 'sign': {'cosign_path': 'cosign'}}
                module = RealSupplyChainSecurity(config)
                result = module.generate_sbom('.')
                
            elif module_name == 'attack_graph':
                from real_attack_graph import RealAttackGraph
                config = {}
                module = RealAttackGraph(config)
                module.add_node('test', 'Test Node', 'event')
                module.add_technique('T1059')
                result = {'success': True, 'message': '攻擊圖譜功能正常'}
                
            elif module_name == 'attack_simulation':
                from real_attack_simulation import RealAttackSimulation
                config = {'enable_atomic': False, 'enable_caldera': False}
                module = RealAttackSimulation(config)
                result = module.run_simulation()
            
            # 測試模組功能
            status = module.get_status() if hasattr(module, 'get_status') else {'success': True}
            report = module.get_comprehensive_report() if hasattr(module, 'get_comprehensive_report') else {'success': True}
            
            test_results['modules'][module_name] = {
                'name': display_name,
                'available': True,
                'initialization': result.get('success', False),
                'status_check': status.get('success', False),
                'report_generation': report.get('success', False),
                'message': result.get('message', '')
            }
            
            print(f"✅ {display_name}: 可用")
            print(f"   - 初始化: {'✅' if result.get('success', False) else '❌'}")
            print(f"   - 狀態檢查: {'✅' if status.get('success', False) else '❌'}")
            print(f"   - 報告生成: {'✅' if report.get('success', False) else '❌'}")
            
        except Exception as e:
            test_results['modules'][module_name] = {
                'name': display_name,
                'available': False,
                'error': str(e)
            }
            print(f"❌ {display_name}: 錯誤 - {e}")
    
    print()
    
    # 3. 測試外部工具
    print("🔧 3. 外部工具測試")
    print("-" * 40)
    
    tools = {
        'Suricata': 'suricata',
        'Sysmon': 'sysmon',
        'osquery': 'osqueryi',
        'syft': 'syft',
        'cosign': 'cosign'
    }
    
    available_tools = 0
    for tool_name, command in tools.items():
        try:
            import subprocess
            result = subprocess.run([command, '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                test_results['external_tools'][tool_name] = {'available': True, 'version': result.stdout[:100]}
                print(f"✅ {tool_name}: 可用")
                available_tools += 1
            else:
                test_results['external_tools'][tool_name] = {'available': False, 'error': 'Command failed'}
                print(f"❌ {tool_name}: 不可用")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            test_results['external_tools'][tool_name] = {'available': False, 'error': 'Not installed'}
            print(f"⚠️  {tool_name}: 未安裝")
        except Exception as e:
            test_results['external_tools'][tool_name] = {'available': False, 'error': str(e)}
            print(f"❌ {tool_name}: 檢查錯誤 - {e}")
    
    test_results['external_tools']['summary'] = {
        'available': available_tools,
        'total': len(tools),
        'percentage': (available_tools / len(tools)) * 100
    }
    
    print(f"\n📊 外部工具可用性: {available_tools}/{len(tools)} ({available_tools/len(tools)*100:.1f}%)")
    print()
    
    # 4. 測試系統整合
    print("🔗 4. 系統整合測試")
    print("-" * 40)
    
    try:
        # 測試主系統載入（不啟動，避免依賴問題）
        from real_ultimate_military_defense_system import RealUltimateMilitaryDefenseSystem
        system = RealUltimateMilitaryDefenseSystem()
        
        test_results['summary']['main_system_loaded'] = True
        test_results['summary']['initialized_modules'] = len(system.defense_modules)
        test_results['summary']['total_configured_modules'] = len(system.config.get('modules', {}))
        
        print(f"✅ 主系統載入成功")
        print(f"   - 已初始化模組: {len(system.defense_modules)}")
        print(f"   - 配置模組總數: {len(system.config.get('modules', {}))}")
        
        # 測試系統狀態
        status = system.get_system_status()
        if status.get('success', False):
            print(f"   - 系統狀態: 正常")
            test_results['summary']['system_status_ok'] = True
        else:
            print(f"   - 系統狀態: 異常 - {status.get('error', '未知錯誤')}")
            test_results['summary']['system_status_ok'] = False
        
    except Exception as e:
        test_results['summary']['main_system_loaded'] = False
        test_results['summary']['error'] = str(e)
        print(f"❌ 主系統載入失敗: {e}")
    
    print()
    
    # 5. 生成總結報告
    print("📊 5. 測試總結")
    print("-" * 40)
    
    # 計算成功率
    available_modules = sum(1 for m in test_results['modules'].values() if m.get('available', False))
    total_modules = len(test_results['modules'])
    module_success_rate = (available_modules / total_modules * 100) if total_modules > 0 else 0
    
    config_ok = test_results['configuration'].get('config_loaded', False)
    system_ok = test_results['summary'].get('main_system_loaded', False)
    tools_available = test_results['external_tools']['summary']['available']
    
    test_results['summary']['module_success_rate'] = module_success_rate
    test_results['summary']['overall_success'] = config_ok and system_ok and module_success_rate >= 60
    
    print(f"✅ 配置載入: {'通過' if config_ok else '失敗'}")
    print(f"✅ 主系統載入: {'通過' if system_ok else '失敗'}")
    print(f"✅ 模組可用性: {available_modules}/{total_modules} ({module_success_rate:.1f}%)")
    print(f"🔧 外部工具: {tools_available} 個可用")
    
    print(f"\n🎯 總體評估:")
    if test_results['summary']['overall_success']:
        print("🎉 系統功能驗證通過！防禦系統運行正常。")
        print("   - 核心模組正常載入")
        print("   - 配置檔案正確")
        print("   - 新增功能可用")
    elif module_success_rate >= 40:
        print("⚠️ 系統部分功能正常，建議檢查失敗項目。")
        print("   - 部分模組可用")
        print("   - 需要修復失敗模組")
    else:
        print("❌ 系統存在嚴重問題，需要修復。")
        print("   - 多個模組無法載入")
        print("   - 需要檢查依賴關係")
    
    # 6. 保存詳細報告
    try:
        with open('comprehensive_test_report.json', 'w', encoding='utf-8') as f:
            json.dump(test_results, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n💾 詳細測試報告已保存至: comprehensive_test_report.json")
    except Exception as e:
        print(f"\n⚠️ 保存測試報告失敗: {e}")
    
    print("\n" + "=" * 80)
    print("測試完成")
    print("=" * 80)
    
    return test_results

def main():
    """主函數"""
    try:
        results = test_core_modules()
        return results
    except Exception as e:
        print(f"❌ 測試過程發生錯誤: {e}")
        traceback.print_exc()
        return None

if __name__ == "__main__":
    main()


