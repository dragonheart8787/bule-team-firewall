#!/usr/bin/env python3
"""
測試 WAF 規則檢測
"""

import sys
import os
sys.path.append('.')

# 模擬 WAF 規則檢查
from waf_proxy_enterprise_fixed import ModSecurityRules

def test_waf_rules():
    """測試 WAF 規則"""
    print("=== 測試 WAF 規則檢測 ===")
    
    # 創建 WAF 實例
    waf = ModSecurityRules()
    
    # 測試案例
    test_cases = [
        {"method": "GET", "path": "/", "body": "", "name": "正常請求"},
        {"method": "GET", "path": "/admin", "body": "", "name": "管理員路徑"},
        {"method": "GET", "path": "/administrator", "body": "", "name": "管理員路徑變體"},
        {"method": "GET", "path": "/?id=1' OR '1'='1", "body": "", "name": "SQL 注入"},
        {"method": "POST", "path": "/", "body": "<script>alert('xss')</script>", "name": "XSS 攻擊"},
    ]
    
    for case in test_cases:
        print(f"\n測試: {case['name']}")
        print(f"請求: {case['method']} {case['path']} {case['body']}")
        
        # 檢查請求
        violations = waf.check_request(
            client_ip="127.0.0.1",
            method=case['method'],
            path=case['path'],
            headers={},
            body=case['body']
        )
        
        print(f"違規數量: {len(violations)}")
        for violation in violations:
            print(f"  規則: {violation['rule_id']}")
            print(f"  匹配: {violation['matched']}")
            print(f"  動作: {violation['action']}")

if __name__ == "__main__":
    test_waf_rules()



