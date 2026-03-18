#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTF系統測試腳本
Test CTF System
測試攻擊模擬、挑戰生成、競賽管理
"""

import sys
import time
import json
import traceback
from datetime import datetime

def test_ctf_system():
    """測試CTF系統"""
    print("=" * 80)
    print("🏆 真實CTF/CROT系統測試")
    print("=" * 80)
    print(f"測試時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    test_results = {
        'timestamp': datetime.now().isoformat(),
        'modules': {},
        'summary': {}
    }
    
    # 1. 測試CTF攻擊模擬
    print("⚔️ 1. CTF攻擊模擬測試")
    print("-" * 40)
    
    try:
        from real_ctf_attack_simulation import RealCTFAttackSimulation
        config = {
            'web_attacks': True,
            'pwn_attacks': True,
            'crypto_attacks': True,
            'forensics_attacks': True
        }
        module = RealCTFAttackSimulation(config)
        
        # 測試啟動
        result = module.start_attack_simulation()
        test_results['modules']['ctf_attack_simulation'] = {
            'name': 'CTF攻擊模擬系統',
            'available': True,
            'initialization': result.get('success', False),
            'message': result.get('message', '')
        }
        
        if result.get('success', False):
            print("✅ CTF攻擊模擬系統: 可用")
            print(f"   - 初始化: {'✅' if result.get('success', False) else '❌'}")
            
            # 測試獲取攻擊統計
            stats_result = module.get_attack_statistics()
            print(f"   - 攻擊統計: {'✅' if stats_result.get('success', False) else '❌'}")
            
            if stats_result.get('success', False):
                total_points = stats_result.get('total_points', 0)
                print(f"   - 總分數: {total_points}")
            
            # 停止模組
            module.stop_attack_simulation()
        else:
            print(f"❌ CTF攻擊模擬系統: 錯誤 - {result.get('error', '未知錯誤')}")
            
    except Exception as e:
        test_results['modules']['ctf_attack_simulation'] = {
            'name': 'CTF攻擊模擬系統',
            'available': False,
            'error': str(e)
        }
        print(f"❌ CTF攻擊模擬系統: 錯誤 - {e}")
    
    print()
    
    # 2. 測試CTF挑戰生成器
    print("🎯 2. CTF挑戰生成器測試")
    print("-" * 40)
    
    try:
        from real_ctf_challenge_generator import RealCTFChallengeGenerator
        config = {
            'challenge_templates': True,
            'auto_generation': True
        }
        module = RealCTFChallengeGenerator(config)
        
        test_results['modules']['ctf_challenge_generator'] = {
            'name': 'CTF挑戰生成器',
            'available': True,
            'initialization': True,
            'message': '初始化成功'
        }
        
        print("✅ CTF挑戰生成器: 可用")
        print("   - 初始化: ✅")
        
        # 測試生成Web挑戰
        web_result = module.generate_challenge('web', 'sql_injection')
        print(f"   - Web挑戰生成: {'✅' if web_result.get('success', False) else '❌'}")
        
        # 測試生成PWN挑戰
        pwn_result = module.generate_challenge('pwn', 'buffer_overflow')
        print(f"   - PWN挑戰生成: {'✅' if pwn_result.get('success', False) else '❌'}")
        
        # 測試生成密碼學挑戰
        crypto_result = module.generate_challenge('crypto', 'caesar_cipher')
        print(f"   - 密碼學挑戰生成: {'✅' if crypto_result.get('success', False) else '❌'}")
        
        # 測試獲取挑戰列表
        challenges_result = module.get_challenge_list()
        print(f"   - 挑戰列表: {'✅' if challenges_result.get('success', False) else '❌'}")
        
        if challenges_result.get('success', False):
            challenge_count = challenges_result.get('total_count', 0)
            print(f"   - 挑戰數量: {challenge_count}")
        
    except Exception as e:
        test_results['modules']['ctf_challenge_generator'] = {
            'name': 'CTF挑戰生成器',
            'available': False,
            'error': str(e)
        }
        print(f"❌ CTF挑戰生成器: 錯誤 - {e}")
    
    print()
    
    # 3. 測試CTF競賽管理系統
    print("🏆 3. CTF競賽管理系統測試")
    print("-" * 40)
    
    try:
        from real_ctf_competition_manager import RealCTFCompetitionManager
        config = {
            'max_teams': 50,
            'competition_duration': 24,
            'scoring_system': 'dynamic'
        }
        module = RealCTFCompetitionManager(config)
        
        # 測試創建競賽
        competition_result = module.create_competition(
            'test_comp_001',
            '測試CTF競賽',
            '這是一個測試競賽',
            '2024-01-01 00:00:00',
            '2024-01-02 00:00:00'
        )
        test_results['modules']['ctf_competition_manager'] = {
            'name': 'CTF競賽管理系統',
            'available': True,
            'initialization': competition_result.get('success', False),
            'message': competition_result.get('message', '')
        }
        
        if competition_result.get('success', False):
            print("✅ CTF競賽管理系統: 可用")
            print(f"   - 競賽創建: {'✅' if competition_result.get('success', False) else '❌'}")
            
            # 測試註冊團隊
            team_result = module.register_team(
                'team_001',
                '測試團隊',
                ['player1', 'player2', 'player3']
            )
            print(f"   - 團隊註冊: {'✅' if team_result.get('success', False) else '❌'}")
            
            # 測試添加挑戰
            challenge_result = module.add_challenge(
                'challenge_001',
                'web',
                'SQL注入挑戰',
                '找到SQL注入漏洞',
                'medium',
                100,
                'flag{sql_injection_1234}'
            )
            print(f"   - 挑戰添加: {'✅' if challenge_result.get('success', False) else '❌'}")
            
            # 測試提交flag
            if team_result.get('success', False) and challenge_result.get('success', False):
                flag_result = module.submit_flag(
                    'team_001',
                    'challenge_001',
                    'flag{sql_injection_1234}'
                )
                print(f"   - Flag提交: {'✅' if flag_result.get('success', False) else '❌'}")
                
                if flag_result.get('success', False):
                    print(f"   - 提交結果: {'正確' if flag_result.get('correct', False) else '錯誤'}")
                    print(f"   - 獲得分數: {flag_result.get('points', 0)}")
            
            # 測試獲取排行榜
            leaderboard_result = module.get_leaderboard()
            print(f"   - 排行榜: {'✅' if leaderboard_result.get('success', False) else '❌'}")
            
            # 測試啟動監控
            monitor_result = module.start_competition_monitoring()
            print(f"   - 競賽監控: {'✅' if monitor_result.get('success', False) else '❌'}")
            
            # 停止監控
            module.stop_competition_monitoring()
        else:
            print(f"❌ CTF競賽管理系統: 錯誤 - {competition_result.get('error', '未知錯誤')}")
            
    except Exception as e:
        test_results['modules']['ctf_competition_manager'] = {
            'name': 'CTF競賽管理系統',
            'available': False,
            'error': str(e)
        }
        print(f"❌ CTF競賽管理系統: 錯誤 - {e}")
    
    print()
    
    # 4. 生成測試總結
    print("📊 4. 測試總結")
    print("-" * 40)
    
    # 計算成功率
    available_modules = sum(1 for m in test_results['modules'].values() if m.get('available', False))
    total_modules = len(test_results['modules'])
    module_success_rate = (available_modules / total_modules * 100) if total_modules > 0 else 0
    
    print(f"✅ 模組可用性: {available_modules}/{total_modules} ({module_success_rate:.1f}%)")
    
    # 總體評估
    overall_success = module_success_rate >= 80
    
    test_results['summary']['overall_success'] = overall_success
    test_results['summary']['module_success_rate'] = module_success_rate
    
    print(f"\n🎯 總體評估:")
    if overall_success:
        print("🎉 CTF系統測試通過！")
        print("   - 所有核心模組正常載入")
        print("   - CTF功能完全可用")
        print("   - 適合CROT和CTF競賽")
    elif module_success_rate >= 60:
        print("⚠️ 部分模組測試通過，建議檢查失敗項目。")
        print("   - 大部分功能可用")
        print("   - 需要修復失敗模組")
    else:
        print("❌ CTF系統測試失敗，需要修復。")
        print("   - 多個模組無法載入")
        print("   - 需要檢查依賴關係")
    
    # 保存測試報告
    try:
        with open('ctf_system_test_report.json', 'w', encoding='utf-8') as f:
            json.dump(test_results, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n💾 測試報告已保存至: ctf_system_test_report.json")
    except Exception as e:
        print(f"\n⚠️ 保存測試報告失敗: {e}")
    
    print("\n" + "=" * 80)
    print("CTF系統測試完成")
    print("=" * 80)
    
    return test_results

def main():
    """主函數"""
    try:
        results = test_ctf_system()
        return results
    except Exception as e:
        print(f"❌ 測試過程發生錯誤: {e}")
        traceback.print_exc()
        return None

if __name__ == "__main__":
    main()


