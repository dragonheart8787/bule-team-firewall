#!/usr/bin/env python3
"""
測試正則表達式
"""

import re

def test_admin_patterns():
    """測試管理員路徑正則表達式"""
    admin_patterns = [
        r"/admin",
        r"/administrator", 
        r"/wp-admin",
        r"/phpmyadmin",
        r"/backend",
        r"/management",
        r"/dashboard",
        r"/system",
        r"/config",
        r"/settings",
        r"/logs",
        r"/backup",
        r"/security",
        r"/api/admin",
        r"/admin/api"
    ]
    
    test_paths = [
        '/admin',
        '/administrator',
        '/wp-admin',
        '/phpmyadmin',
        '/backend',
        '/management',
        '/dashboard',
        '/system',
        '/config',
        '/settings',
        '/logs',
        '/backup',
        '/security',
        '/api/admin',
        '/admin/api',
        '/normal/path',
        '/user/profile'
    ]
    
    print("測試管理員路徑正則表達式...")
    print("=" * 50)
    
    for path in test_paths:
        matched = False
        matched_patterns = []
        
        for pattern in admin_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                matched = True
                matched_patterns.append(pattern)
        
        status = "MATCH" if matched else "NO MATCH"
        print(f"{path:<20} -> {status} {matched_patterns}")
    
    print("\n測試請求內容匹配...")
    print("=" * 50)
    
    # 模擬 WAF 中的請求內容匹配
    for path in test_paths:
        request_content = f"GET {path} "
        matched = False
        matched_patterns = []
        
        for pattern in admin_patterns:
            if re.search(pattern, request_content, re.IGNORECASE):
                matched = True
                matched_patterns.append(pattern)
        
        status = "MATCH" if matched else "NO MATCH"
        print(f"GET {path:<15} -> {status} {matched_patterns}")

if __name__ == "__main__":
    test_admin_patterns()




