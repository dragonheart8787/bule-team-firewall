#!/usr/bin/env python3
"""
NoSQL 注入測試腳本
測試各種 NoSQL 注入攻擊模式
"""

import requests
import json
import time

def test_nosql_injection():
    """測試 NoSQL 注入攻擊"""
    base_url = "http://127.0.0.1:8080"
    
    # NoSQL 注入測試案例
    nosql_tests = [
        {
            'name': 'MongoDB $where 注入',
            'payload': '{"username": {"$where": "this.password == this.username"}}',
            'expected_status': 403
        },
        {
            'name': 'MongoDB $ne 注入',
            'payload': '{"username": {"$ne": null}, "password": {"$ne": null}}',
            'expected_status': 403
        },
        {
            'name': 'MongoDB $regex 注入',
            'payload': '{"username": {"$regex": ".*"}}',
            'expected_status': 403
        },
        {
            'name': 'MongoDB $or 注入',
            'payload': '{"$or": [{"username": "admin"}, {"username": "administrator"}]}',
            'expected_status': 403
        },
        {
            'name': 'MongoDB $and 注入',
            'payload': '{"$and": [{"username": {"$exists": true}}, {"password": {"$exists": true}}]}',
            'expected_status': 403
        },
        {
            'name': 'MongoDB $in 注入',
            'payload': '{"username": {"$in": ["admin", "root", "administrator"]}}',
            'expected_status': 403
        },
        {
            'name': 'MongoDB $gt 注入',
            'payload': '{"age": {"$gt": 0}}',
            'expected_status': 403
        },
        {
            'name': 'MongoDB $lt 注入',
            'payload': '{"age": {"$lt": 100}}',
            'expected_status': 403
        },
        {
            'name': 'MongoDB $exists 注入',
            'payload': '{"admin": {"$exists": true}}',
            'expected_status': 403
        },
        {
            'name': 'MongoDB $elemMatch 注入',
            'payload': '{"tags": {"$elemMatch": {"$eq": "admin"}}}',
            'expected_status': 403
        },
        {
            'name': 'MongoDB $size 注入',
            'payload': '{"array": {"$size": 0}}',
            'expected_status': 403
        },
        {
            'name': 'MongoDB $type 注入',
            'payload': '{"field": {"$type": "string"}}',
            'expected_status': 403
        },
        {
            'name': 'MongoDB $mod 注入',
            'payload': '{"number": {"$mod": [2, 0]}}',
            'expected_status': 403
        },
        {
            'name': 'MongoDB $text 注入',
            'payload': '{"$text": {"$search": "admin"}}',
            'expected_status': 403
        },
        {
            'name': 'MongoDB $geoWithin 注入',
            'payload': '{"location": {"$geoWithin": {"$center": [[0, 0], 100]}}}',
            'expected_status': 403
        }
    ]
    
    print("🔒 開始 NoSQL 注入測試...")
    print("=" * 60)
    
    results = []
    
    for test in nosql_tests:
        print(f"\n🧪 測試: {test['name']}")
        print(f"   負載: {test['payload'][:50]}...")
        
        try:
            response = requests.post(
                f"{base_url}/api/search",
                data=test['payload'],
                headers={'Content-Type': 'application/json'},
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
    print("📊 NoSQL 注入測試結果摘要:")
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
        print("\n所有 NoSQL 注入測試通過")
    elif passed >= len(results) * 0.8:
        print(f"\n✅ NoSQL 注入防護良好！{passed}/{len(results)} 個攻擊被成功阻擋。")
    else:
        print(f"\n⚠️  NoSQL 注入防護需要改進，有 {failed + errors} 個攻擊未被阻擋。")
    
    return results

if __name__ == "__main__":
    test_nosql_injection()

