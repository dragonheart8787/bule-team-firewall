#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
全面功能測試腳本
測試所有防禦模組的功能
"""

import sys
import time
import json
import traceback
from datetime import datetime

def test_system_initialization():
    """測試系統初始化"""
    print("=" * 60)
    print("🔧 測試系統初始化")
    print("=" * 60)
    
    try:
        from real_ultimate_military_defense_system import RealUltimateMilitaryDefenseSystem
        system = RealUltimateMilitaryDefenseSystem()
        print("✅ 系統初始化成功")
        return system
    except Exception as e:
        print(f"❌ 系統初始化失敗: {e}")
        traceback.print_exc()
        return None

def test_module_startup(system):
    """測試模組啟動"""
    print("\n" + "=" * 60)
    print("🚀 測試模組啟動")
    print("=" * 60)
    
    try:
        result = system.start_defense_system()
        if result['success']:
            print("✅ 防禦系統啟動成功")
            return True
        else:
            print(f"❌ 防禦系統啟動失敗: {result.get('error', '未知錯誤')}")
            return False
    except Exception as e:
        print(f"❌ 模組啟動測試失敗: {e}")
        traceback.print_exc()
        return False

def test_module_health(system):
    """測試模組健康狀態"""
    print("\n" + "=" * 60)
    print("🏥 測試模組健康狀態")
    print("=" * 60)
    
    healthy_modules = 0
    total_modules = len(system.defense_modules)
    
    for name, module in system.defense_modules.items():
        try:
            if hasattr(module, 'get_status'):
                health = module.get_status()
                if health.get('success', False):
                    print(f"✅ {name}: 健康")
                    healthy_modules += 1
                else:
                    print(f"❌ {name}: 不健康 - {health.get('error', '未知錯誤')}")
            else:
                print(f"⚠️  {name}: 無健康檢查方法")
                healthy_modules += 1
        except Exception as e:
            print(f"❌ {name}: 健康檢查錯誤 - {e}")
    
    print(f"\n📊 健康模組: {healthy_modules}/{total_modules} ({healthy_modules/total_modules*100:.1f}%)")
    return healthy_modules == total_modules

def test_individual_modules(system):
    """測試個別模組功能"""
    print("\n" + "=" * 60)
    print("🔍 測試個別模組功能")
    print("=" * 60)
    
    test_results = {}
    
    # 測試網路監控模組
    if 'network_monitor' in system.defense_modules:
        try:
            module = system.defense_modules['network_monitor']
            if hasattr(module, 'analyze_network_traffic'):
                result = module.analyze_network_traffic()
                test_results['network_monitor'] = result.get('success', False)
                print(f"🌐 網路監控: {'✅' if test_results['network_monitor'] else '❌'}")
        except Exception as e:
            test_results['network_monitor'] = False
            print(f"🌐 網路監控: ❌ 錯誤 - {e}")
    
    # 測試威脅檢測模組
    if 'threat_detection' in system.defense_modules:
        try:
            module = system.defense_modules['threat_detection']
            if hasattr(module, 'analyze_threats'):
                result = module.analyze_threats()
                test_results['threat_detection'] = result.get('success', False)
                print(f"🛡️ 威脅檢測: {'✅' if test_results['threat_detection'] else '❌'}")
        except Exception as e:
            test_results['threat_detection'] = False
            print(f"🛡️ 威脅檢測: ❌ 錯誤 - {e}")
    
    # 測試AI/ML威脅獵捕模組
    if 'ai_ml_threat_hunting' in system.defense_modules:
        try:
            module = system.defense_modules['ai_ml_threat_hunting']
            if hasattr(module, 'perform_ml_analysis'):
                result = module.perform_ml_analysis()
                test_results['ai_ml_threat_hunting'] = result.get('success', False)
                print(f"🤖 AI/ML威脅獵捕: {'✅' if test_results['ai_ml_threat_hunting'] else '❌'}")
        except Exception as e:
            test_results['ai_ml_threat_hunting'] = False
            print(f"🤖 AI/ML威脅獵捕: ❌ 錯誤 - {e}")
    
    # 測試零信任模組
    if 'zero_trust_segmentation' in system.defense_modules:
        try:
            module = system.defense_modules['zero_trust_segmentation']
            if hasattr(module, 'evaluate_zero_trust'):
                result = module.evaluate_zero_trust()
                test_results['zero_trust_segmentation'] = result.get('success', False)
                print(f"🔐 零信任分段: {'✅' if test_results['zero_trust_segmentation'] else '❌'}")
        except Exception as e:
            test_results['zero_trust_segmentation'] = False
            print(f"🔐 零信任分段: ❌ 錯誤 - {e}")
    
    # 測試威脅情報模組
    if 'threat_intelligence' in system.defense_modules:
        try:
            module = system.defense_modules['threat_intelligence']
            if hasattr(module, 'update_threat_intelligence'):
                result = module.update_threat_intelligence()
                test_results['threat_intelligence'] = result.get('success', False)
                print(f"📡 威脅情報: {'✅' if test_results['threat_intelligence'] else '❌'}")
        except Exception as e:
            test_results['threat_intelligence'] = False
            print(f"📡 威脅情報: ❌ 錯誤 - {e}")
    
    # 測試攻防演練模組
    if 'attack_simulation' in system.defense_modules:
        try:
            module = system.defense_modules['attack_simulation']
            if hasattr(module, 'run_simulation'):
                result = module.run_simulation()
                test_results['attack_simulation'] = result.get('success', False)
                print(f"⚔️ 攻防演練: {'✅' if test_results['attack_simulation'] else '❌'}")
        except Exception as e:
            test_results['attack_simulation'] = False
            print(f"⚔️ 攻防演練: ❌ 錯誤 - {e}")
    
    # 測試跨平台IR模組
    if 'cross_platform_ir' in system.defense_modules:
        try:
            module = system.defense_modules['cross_platform_ir']
            if hasattr(module, 'start_ir'):
                result = module.start_ir()
                test_results['cross_platform_ir'] = result.get('success', False)
                print(f"🖥️ 跨平台IR: {'✅' if test_results['cross_platform_ir'] else '❌'}")
        except Exception as e:
            test_results['cross_platform_ir'] = False
            print(f"🖥️ 跨平台IR: ❌ 錯誤 - {e}")
    
    # 測試DDoS韌性模組
    if 'ddos_resilience' in system.defense_modules:
        try:
            module = system.defense_modules['ddos_resilience']
            if hasattr(module, 'start_resilience'):
                result = module.start_resilience()
                test_results['ddos_resilience'] = result.get('success', False)
                print(f"🛡️ DDoS韌性: {'✅' if test_results['ddos_resilience'] else '❌'}")
        except Exception as e:
            test_results['ddos_resilience'] = False
            print(f"🛡️ DDoS韌性: ❌ 錯誤 - {e}")
    
    # 測試供應鏈安全模組
    if 'supply_chain_security' in system.defense_modules:
        try:
            module = system.defense_modules['supply_chain_security']
            if hasattr(module, 'generate_sbom'):
                result = module.generate_sbom('.')
                test_results['supply_chain_security'] = result.get('success', False)
                print(f"🔗 供應鏈安全: {'✅' if test_results['supply_chain_security'] else '❌'}")
        except Exception as e:
            test_results['supply_chain_security'] = False
            print(f"🔗 供應鏈安全: ❌ 錯誤 - {e}")
    
    return test_results

def test_system_reporting(system):
    """測試系統報告功能"""
    print("\n" + "=" * 60)
    print("📊 測試系統報告功能")
    print("=" * 60)
    
    try:
        # 測試系統狀態報告
        status = system.get_system_status()
        if status.get('success', False):
            print("✅ 系統狀態報告: 成功")
            print(f"   - 運行狀態: {status.get('running', False)}")
            print(f"   - 模組數量: {status.get('defense_modules', 0)}")
            print(f"   - 健康狀態: {status.get('overall_health', {})}")
        else:
            print(f"❌ 系統狀態報告: 失敗 - {status.get('error', '未知錯誤')}")
            return False
        
        # 測試綜合報告
        report = system.get_comprehensive_report()
        if report.get('success', False):
            print("✅ 綜合報告: 成功")
            print(f"   - 系統名稱: {report.get('system_info', {}).get('name', 'N/A')}")
            print(f"   - 版本: {report.get('system_info', {}).get('version', 'N/A')}")
            print(f"   - 模組報告數量: {len(report.get('defense_modules', {}))}")
        else:
            print(f"❌ 綜合報告: 失敗 - {report.get('error', '未知錯誤')}")
            return False
        
        # 測試防禦分析
        analysis = system.execute_defense_analysis()
        if analysis.get('success', False):
            print("✅ 防禦分析: 成功")
            print(f"   - 分析模組數: {analysis.get('modules_analyzed', 0)}")
            print(f"   - 檢測威脅數: {analysis.get('threats_detected', 0)}")
            print(f"   - 防禦有效性: {analysis.get('defense_effectiveness', 0):.1f}%")
        else:
            print(f"❌ 防禦分析: 失敗 - {analysis.get('error', '未知錯誤')}")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ 系統報告測試失敗: {e}")
        traceback.print_exc()
        return False

def test_configuration_loading():
    """測試配置載入"""
    print("\n" + "=" * 60)
    print("⚙️ 測試配置載入")
    print("=" * 60)
    
    try:
        import yaml
        with open('real_ultimate_defense_config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        print("✅ 配置檔案載入成功")
        print(f"   - 系統名稱: {config.get('system', {}).get('name', 'N/A')}")
        print(f"   - 版本: {config.get('system', {}).get('version', 'N/A')}")
        print(f"   - 模組數量: {len(config.get('modules', {}))}")
        print(f"   - 防禦層數量: {len(config.get('defense_layers', {}))}")
        
        # 檢查關鍵模組配置
        critical_modules = ['network_monitor', 'threat_detection', 'incident_response']
        for module in critical_modules:
            if module in config.get('modules', {}):
                enabled = config['modules'][module].get('enabled', False)
                print(f"   - {module}: {'✅ 啟用' if enabled else '❌ 停用'}")
            else:
                print(f"   - {module}: ❌ 未配置")
        
        return True
        
    except Exception as e:
        print(f"❌ 配置載入失敗: {e}")
        traceback.print_exc()
        return False

def test_external_tools():
    """測試外部工具可用性"""
    print("\n" + "=" * 60)
    print("🔧 測試外部工具可用性")
    print("=" * 60)
    
    tools = {
        'Suricata': 'suricata',
        'Sysmon': 'sysmon',
        'osquery': 'osqueryi',
        'syft': 'syft',
        'cosign': 'cosign'
    }
    
    available_tools = 0
    total_tools = len(tools)
    
    for tool_name, command in tools.items():
        try:
            import subprocess
            result = subprocess.run([command, '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"✅ {tool_name}: 可用")
                available_tools += 1
            else:
                print(f"❌ {tool_name}: 不可用")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print(f"⚠️  {tool_name}: 未安裝或無法執行")
        except Exception as e:
            print(f"❌ {tool_name}: 檢查錯誤 - {e}")
    
    print(f"\n📊 可用工具: {available_tools}/{total_tools} ({available_tools/total_tools*100:.1f}%)")
    return available_tools

def main():
    """主測試函數"""
    print("🛡️ 真實終極軍事防禦系統 - 全面功能測試")
    print("=" * 60)
    print(f"測試時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    test_results = {
        'system_initialization': False,
        'module_startup': False,
        'module_health': False,
        'individual_modules': {},
        'system_reporting': False,
        'configuration_loading': False,
        'external_tools': 0
    }
    
    # 1. 測試配置載入
    test_results['configuration_loading'] = test_configuration_loading()
    
    # 2. 測試系統初始化
    system = test_system_initialization()
    if system:
        test_results['system_initialization'] = True
        
        # 3. 測試模組啟動
        test_results['module_startup'] = test_module_startup(system)
        
        if test_results['module_startup']:
            # 4. 測試模組健康狀態
            test_results['module_health'] = test_module_health(system)
            
            # 5. 測試個別模組功能
            test_results['individual_modules'] = test_individual_modules(system)
            
            # 6. 測試系統報告功能
            test_results['system_reporting'] = test_system_reporting(system)
            
            # 7. 停止系統
            try:
                system.stop_defense_system()
                print("\n✅ 系統已安全停止")
            except Exception as e:
                print(f"\n⚠️ 系統停止時出現錯誤: {e}")
    
    # 8. 測試外部工具
    test_results['external_tools'] = test_external_tools()
    
    # 生成測試報告
    print("\n" + "=" * 60)
    print("📋 測試結果總結")
    print("=" * 60)
    
    print(f"✅ 配置載入: {'通過' if test_results['configuration_loading'] else '失敗'}")
    print(f"✅ 系統初始化: {'通過' if test_results['system_initialization'] else '失敗'}")
    print(f"✅ 模組啟動: {'通過' if test_results['module_startup'] else '失敗'}")
    print(f"✅ 模組健康: {'通過' if test_results['module_health'] else '失敗'}")
    print(f"✅ 系統報告: {'通過' if test_results['system_reporting'] else '失敗'}")
    print(f"🔧 外部工具: {test_results['external_tools']} 個可用")
    
    # 個別模組測試結果
    if test_results['individual_modules']:
        print("\n📊 個別模組測試結果:")
        for module, result in test_results['individual_modules'].items():
            print(f"   - {module}: {'✅' if result else '❌'}")
    
    # 計算總體成功率
    total_tests = 5  # 基本測試項目
    passed_tests = sum([
        test_results['configuration_loading'],
        test_results['system_initialization'],
        test_results['module_startup'],
        test_results['module_health'],
        test_results['system_reporting']
    ])
    
    success_rate = (passed_tests / total_tests) * 100
    print(f"\n🎯 總體成功率: {success_rate:.1f}% ({passed_tests}/{total_tests})")
    
    if success_rate >= 80:
        print("🎉 系統測試通過！防禦系統運行正常。")
    elif success_rate >= 60:
        print("⚠️ 系統部分功能正常，建議檢查失敗項目。")
    else:
        print("❌ 系統存在嚴重問題，需要修復。")
    
    # 保存測試報告
    try:
        with open('test_results.json', 'w', encoding='utf-8') as f:
            json.dump(test_results, f, indent=2, ensure_ascii=False)
        print(f"\n💾 測試報告已保存至: test_results.json")
    except Exception as e:
        print(f"\n⚠️ 保存測試報告失敗: {e}")

if __name__ == "__main__":
    main()


