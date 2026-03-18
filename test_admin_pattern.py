#!/usr/bin/env python3
"""
測試管理員路徑正則表達式
"""

import re

def test_admin_patterns():
    """測試管理員路徑匹配"""
    request_content = 'GET /admin'
    admin_patterns = [
        r'/admin',
        r'/administrator', 
        r'/wp-admin',
        r'/phpmyadmin',
        r'/admin\.php',
        r'/admin\.asp'
    ]
    
    print('測試管理員路徑匹配:')
    for pattern in admin_patterns:
        match = re.search(pattern, request_content, re.IGNORECASE)
        print(f'Pattern: {pattern}, Match: {match is not None}')
        if match:
            print(f'  Match object: {match}')
            print(f'  Matched text: {match.group()}')

if __name__ == "__main__":
    test_admin_patterns()




