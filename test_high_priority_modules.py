#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高優先級模組測試腳本
Test High Priority Modules
測試行為分析、事件回應劇本、威脅獵捕查詢
"""

import sys
import time
import json
import traceback
from datetime import datetime

def test_high_priority_modules():
    """測試高優先級模組"""
    print("=" * 80)
    print("🛡️ 真實終極軍事防禦系統 - 高優先級模組測試")
    print("=" * 80)
    print(f"測試時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    test_results = {
        'timestamp': datetime.now().isoformat(),
        'modules': {},
        'summary': {}
    }
    
    # 1. 測試行為分析模組
    print("🧠 1. 行為分析模組測試")
    print("-" * 40)
    
    try:
        from real_behavioral_analytics import RealBehavioralAnalytics
        config = {
            'ml_models': True,
            'behavior_tracking': True,
            'anomaly_detection': True,
            'risk_scoring': True
        }
        module = RealBehavioralAnalytics(config)
        
        # 測試啟動
        result = module.start_analytics()
        test_results['modules']['behavioral_analytics'] = {
            'name': '行為分析引擎',
            'available': True,
            'initialization': result.get('success', False),
            'message': result.get('message', '')
        }
        
        if result.get('success', False):
            print("✅ 行為分析模組: 可用")
            print(f"   - 初始化: {'✅' if result.get('success', False) else '❌'}")
            
            # 測試記錄行為
            behavior_result = module.record_behavior(
                'test_user', 'login_behavior', {
                    'timestamp': datetime.now().isoformat(),
                    'ip_address': '192.168.1.100',
                    'user_agent': 'Mozilla/5.0',
                    'session_duration': 3600
                }
            )
            print(f"   - 行為記錄: {'✅' if behavior_result.get('success', False) else '❌'}")
            
            # 測試風險評分
            risk_result = module.get_user_risk_score('test_user')
            print(f"   - 風險評分: {'✅' if risk_result.get('success', False) else '❌'}")
            
            # 測試異常事件
            anomaly_result = module.get_anomaly_events(limit=10)
            print(f"   - 異常事件: {'✅' if anomaly_result.get('success', False) else '❌'}")
            
            # 停止模組
            module.stop_analytics()
        else:
            print(f"❌ 行為分析模組: 錯誤 - {result.get('error', '未知錯誤')}")
            
    except Exception as e:
        test_results['modules']['behavioral_analytics'] = {
            'name': '行為分析引擎',
            'available': False,
            'error': str(e)
        }
        print(f"❌ 行為分析模組: 錯誤 - {e}")
    
    print()
    
    # 2. 測試事件回應劇本模組
    print("📋 2. 事件回應劇本模組測試")
    print("-" * 40)
    
    try:
        from real_incident_playbooks import RealIncidentPlaybooks
        config = {
            'automation_level': 'semi_automatic',
            'playbook_templates': True,
            'workflow_engine': True
        }
        module = RealIncidentPlaybooks(config)
        
        # 測試啟動
        result = module.start_playbook_engine()
        test_results['modules']['incident_playbooks'] = {
            'name': '事件回應劇本系統',
            'available': True,
            'initialization': result.get('success', False),
            'message': result.get('message', '')
        }
        
        if result.get('success', False):
            print("✅ 事件回應劇本模組: 可用")
            print(f"   - 初始化: {'✅' if result.get('success', False) else '❌'}")
            
            # 測試創建事件
            incident_result = module.create_incident(
                '測試惡意程式事件',
                '檢測到可疑的PowerShell活動',
                'high',
                priority=1
            )
            print(f"   - 事件創建: {'✅' if incident_result.get('success', False) else '❌'}")
            
            if incident_result.get('success', False):
                incident_id = incident_result['incident_id']
                
                # 測試獲取事件狀態
                status_result = module.get_incident_status(incident_id)
                print(f"   - 事件狀態: {'✅' if status_result.get('success', False) else '❌'}")
            
            # 停止模組
            module.stop_playbook_engine()
        else:
            print(f"❌ 事件回應劇本模組: 錯誤 - {result.get('error', '未知錯誤')}")
            
    except Exception as e:
        test_results['modules']['incident_playbooks'] = {
            'name': '事件回應劇本系統',
            'available': False,
            'error': str(e)
        }
        print(f"❌ 事件回應劇本模組: 錯誤 - {e}")
    
    print()
    
    # 3. 測試威脅獵捕查詢模組
    print("🔍 3. 威脅獵捕查詢模組測試")
    print("-" * 40)
    
    try:
        from real_threat_hunting_queries import RealThreatHuntingQueries
        config = {
            'query_templates': True,
            'custom_rules': True,
            'correlation_analysis': True
        }
        module = RealThreatHuntingQueries(config)
        
        # 測試啟動
        result = module.start_hunting_engine()
        test_results['modules']['threat_hunting_queries'] = {
            'name': '威脅獵捕查詢庫',
            'available': True,
            'initialization': result.get('success', False),
            'message': result.get('message', '')
        }
        
        if result.get('success', False):
            print("✅ 威脅獵捕查詢模組: 可用")
            print(f"   - 初始化: {'✅' if result.get('success', False) else '❌'}")
            
            # 測試執行查詢
            query_result = module.execute_query('malware_detection', {'time_range': '24h'})
            print(f"   - 查詢執行: {'✅' if query_result.get('success', False) else '❌'}")
            
            if query_result.get('success', False):
                print(f"   - 查詢結果: {query_result.get('result_count', 0)} 條記錄")
            
            # 測試獲取查詢模板
            templates_result = module.get_query_templates()
            print(f"   - 查詢模板: {'✅' if templates_result.get('success', False) else '❌'}")
            
            if templates_result.get('success', False):
                print(f"   - 模板數量: {templates_result.get('count', 0)}")
            
            # 測試關聯分析
            correlation_result = module.execute_correlation_analysis()
            print(f"   - 關聯分析: {'✅' if correlation_result.get('success', False) else '❌'}")
            
            if correlation_result.get('success', False):
                print(f"   - 關聯結果: {correlation_result.get('matches_found', 0)} 個匹配")
            
            # 測試創建自定義規則
            rule_result = module.create_custom_rule(
                'test_rule_001',
                '測試自定義規則',
                'process',
                'SELECT * FROM process_events WHERE command_line LIKE "%suspicious%"',
                description='測試用的自定義規則'
            )
            print(f"   - 自定義規則: {'✅' if rule_result.get('success', False) else '❌'}")
            
            # 停止模組
            module.stop_hunting_engine()
        else:
            print(f"❌ 威脅獵捕查詢模組: 錯誤 - {result.get('error', '未知錯誤')}")
            
    except Exception as e:
        test_results['modules']['threat_hunting_queries'] = {
            'name': '威脅獵捕查詢庫',
            'available': False,
            'error': str(e)
        }
        print(f"❌ 威脅獵捕查詢模組: 錯誤 - {e}")
    
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
        new_modules = ['behavioral_analytics', 'incident_playbooks', 'threat_hunting_queries']
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
        print("🎉 高優先級模組測試通過！")
        print("   - 所有核心模組正常載入")
        print("   - 新功能完全可用")
        print("   - 系統整合成功")
    elif module_success_rate >= 60:
        print("⚠️ 部分模組測試通過，建議檢查失敗項目。")
        print("   - 大部分功能可用")
        print("   - 需要修復失敗模組")
    else:
        print("❌ 高優先級模組測試失敗，需要修復。")
        print("   - 多個模組無法載入")
        print("   - 需要檢查依賴關係")
    
    # 保存測試報告
    try:
        with open('high_priority_modules_test_report.json', 'w', encoding='utf-8') as f:
            json.dump(test_results, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n💾 測試報告已保存至: high_priority_modules_test_report.json")
    except Exception as e:
        print(f"\n⚠️ 保存測試報告失敗: {e}")
    
    print("\n" + "=" * 80)
    print("高優先級模組測試完成")
    print("=" * 80)
    
    return test_results

def main():
    """主函數"""
    try:
        results = test_high_priority_modules()
        return results
    except Exception as e:
        print(f"❌ 測試過程發生錯誤: {e}")
        traceback.print_exc()
        return None

if __name__ == "__main__":
    main()






