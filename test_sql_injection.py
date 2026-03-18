#!/usr/bin/env python3
"""
SQL 注入測試腳本
測試各種 SQL 注入攻擊模式
"""

import requests
import json
import time

def test_sql_injection():
    """測試 SQL 注入攻擊"""
    base_url = "http://127.0.0.1:8080"
    
    # SQL 注入測試案例
    sql_tests = [
        {
            'name': '基本 UNION SELECT',
            'payload': "1' UNION SELECT * FROM users--",
            'expected_status': 403
        },
        {
            'name': 'OR 1=1 攻擊',
            'payload': "1' OR 1=1--",
            'expected_status': 403
        },
        {
            'name': 'OR 1=1 無註解',
            'payload': "1' OR 1=1",
            'expected_status': 403
        },
        {
            'name': 'OR a=a 攻擊',
            'payload': "1' OR 'a'='a",
            'expected_status': 403
        },
        {
            'name': 'SELECT FROM 語句',
            'payload': "1'; SELECT * FROM users;--",
            'expected_status': 403
        },
        {
            'name': 'INSERT 語句',
            'payload': "1'; INSERT INTO users VALUES ('hacker', 'password');--",
            'expected_status': 403
        },
        {
            'name': 'UPDATE 語句',
            'payload': "1'; UPDATE users SET password='hacked' WHERE id=1;--",
            'expected_status': 403
        },
        {
            'name': 'DELETE 語句',
            'payload': "1'; DELETE FROM users WHERE id=1;--",
            'expected_status': 403
        },
        {
            'name': 'DROP TABLE 語句',
            'payload': "1'; DROP TABLE users;--",
            'expected_status': 403
        },
        {
            'name': 'EXEC 語句',
            'payload': "1'; EXEC xp_cmdshell('dir');--",
            'expected_status': 403
        },
        {
            'name': 'URL 編碼攻擊',
            'payload': "1%27%20OR%201%3D1%23",
            'expected_status': 403
        },
        {
            'name': '雙重編碼攻擊',
            'payload': "1%2527%2520OR%25201%25253D1%2523",
            'expected_status': 403
        },
        {
            'name': '時間盲注',
            'payload': "1'; WAITFOR DELAY '00:00:05';--",
            'expected_status': 403
        },
        {
            'name': '布爾盲注',
            'payload': "1' AND (SELECT COUNT(*) FROM users) > 0--",
            'expected_status': 403
        },
        {
            'name': '聯合查詢',
            'payload': "1' UNION SELECT username, password FROM users--",
            'expected_status': 403
        }
    ]
    
    print("🔒 開始 SQL 注入測試...")
    print("=" * 60)
    
    results = []
    
    for test in sql_tests:
        print(f"\n🧪 測試: {test['name']}")
        print(f"   負載: {test['payload']}")
        
        try:
            response = requests.get(
                f"{base_url}/?id={test['payload']}", 
                timeout=10
            )
            
            status_code = response.status_code
            print(f"   狀態碼: {status_code}")
            
            # 檢查是否為預期狀態碼
            if status_code == test['expected_status']:
                print("   ✅ 測試通過 - 攻擊被阻擋")
                result = 'PASS'
            else:
                print(f"   ❌ 測試失敗 - 期望 {test['expected_status']}, 得到 {status_code}")
                result = 'FAIL'
            
            # 如果是 403，顯示 WAF 響應
            if status_code == 403:
                try:
                    waf_response = response.json()
                    print(f"   🛡️  WAF 阻擋原因: {waf_response.get('message', 'Unknown')}")
                    if 'violations' in waf_response:
                        for violation in waf_response['violations']:
                            print(f"      - {violation['rule_id']}: {violation['severity']}")
                except:
                    print(f"   🛡️  WAF 響應: {response.text[:100]}...")
            
            results.append({
                'test': test['name'],
                'payload': test['payload'],
                'status_code': status_code,
                'result': result
            })
            
        except requests.exceptions.RequestException as e:
            print(f"   ❌ 請求失敗: {e}")
            results.append({
                'test': test['name'],
                'payload': test['payload'],
                'status_code': None,
                'result': 'ERROR'
            })
        
        time.sleep(0.5)  # 避免請求過快
    
    # 顯示測試結果摘要
    print("\n" + "=" * 60)
    print("📊 SQL 注入測試結果摘要:")
    print("=" * 60)
    
    passed = sum(1 for r in results if r['result'] == 'PASS')
    failed = sum(1 for r in results if r['result'] == 'FAIL')
    errors = sum(1 for r in results if r['result'] == 'ERROR')
    
    print(f"✅ 通過: {passed}")
    print(f"❌ 失敗: {failed}")
    print(f"⚠️  錯誤: {errors}")
    print(f"📈 總計: {len(results)}")
    print(f"🎯 防護率: {(passed/len(results)*100):.1f}%")
    
    if failed == 0 and errors == 0:
        print("\n所有 SQL 注入測試通過")
    elif passed >= len(results) * 0.8:
        print(f"\n✅ SQL 注入防護良好！{passed}/{len(results)} 個攻擊被成功阻擋。")
    else:
        print(f"\n⚠️  SQL 注入防護需要改進，有 {failed + errors} 個攻擊未被阻擋。")
    
    return results

if __name__ == "__main__":
    test_sql_injection()

