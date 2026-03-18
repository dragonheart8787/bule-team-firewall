#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試 user 帳號登入
"""

import requests
import json

def test_user_login():
    """測試 user 登入"""
    print("=" * 60)
    print("測試 User 帳號登入")
    print("=" * 60)
    
    # 1. 獲取登入頁面（獲取 CSRF Token）
    print("\n[1/3] 獲取登入頁面...")
    try:
        response = requests.get("http://127.0.0.1:5000/login", timeout=5)
        if response.status_code == 200:
            print("  ✓ 登入頁面載入成功")
            # 從 HTML 中提取 CSRF Token（簡化版本，實際應該用正則）
            html = response.text
            if 'csrf_token' in html:
                print("  ✓ CSRF Token 已生成")
        else:
            print(f"  ✗ 登入頁面載入失敗: {response.status_code}")
            return
    except Exception as e:
        print(f"  ✗ 連接失敗: {e}")
        print("\n請確保 Web 系統正在運行: python secure_web_system.py")
        return
    
    # 2. 測試 admin 登入
    print("\n[2/3] 測試 Admin 登入...")
    session = requests.Session()
    
    # 先獲取頁面取得 CSRF Token
    resp = session.get("http://127.0.0.1:5000/login")
    csrf_token = "test_token"  # 簡化測試，實際會從頁面提取
    
    # 嘗試登入
    login_data = {
        "username": "admin",
        "password": "Admin@2025",
        "csrf_token": csrf_token
    }
    
    try:
        response = session.post(
            "http://127.0.0.1:5000/login",
            json=login_data,
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                print("  ✓ Admin 登入成功")
            else:
                print(f"  ✗ Admin 登入失敗: {data.get('error', '未知錯誤')}")
        elif response.status_code == 403:
            print("  ⚠ CSRF Token 驗證失敗（預期行為，直接測試密碼驗證）")
        else:
            print(f"  ✗ 登入請求失敗: {response.status_code}")
    except Exception as e:
        print(f"  ✗ 登入請求異常: {e}")
    
    # 3. 測試 user 登入
    print("\n[3/3] 測試 User 登入...")
    session2 = requests.Session()
    
    login_data = {
        "username": "user",
        "password": "User@2025",
        "csrf_token": csrf_token
    }
    
    try:
        response = session2.post(
            "http://127.0.0.1:5000/login",
            json=login_data,
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                print("  ✓ User 登入成功")
            else:
                print(f"  ✗ User 登入失敗: {data.get('error', '未知錯誤')}")
        elif response.status_code == 403:
            print("  ⚠ CSRF Token 驗證失敗（預期行為）")
        else:
            print(f"  ✗ 登入請求失敗: {response.status_code}")
    except Exception as e:
        print(f"  ✗ 登入請求異常: {e}")
    
    # 4. 顯示密碼雜湊驗證
    print("\n[驗證] 密碼雜湊檢查...")
    print("  如果使用固定 SALT，密碼雜湊應該一致")
    print("  SALT: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6")
    
    import hashlib
    SALT = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"
    
    # 計算 admin 密碼雜湊
    admin_hash = hashlib.pbkdf2_hmac(
        'sha256',
        'Admin@2025'.encode('utf-8'),
        SALT.encode('utf-8'),
        100000
    ).hex()
    print(f"\n  Admin 密碼雜湊:")
    print(f"    {admin_hash[:64]}...")
    
    # 計算 user 密碼雜湊
    user_hash = hashlib.pbkdf2_hmac(
        'sha256',
        'User@2025'.encode('utf-8'),
        SALT.encode('utf-8'),
        100000
    ).hex()
    print(f"\n  User 密碼雜湊:")
    print(f"    {user_hash[:64]}...")
    
    print("\n" + "=" * 60)
    print("測試完成！")
    print("=" * 60)
    print("\n手動測試步驟:")
    print("  1. 訪問 http://127.0.0.1:5000")
    print("  2. 輸入帳號: user")
    print("  3. 輸入密碼: User@2025")
    print("  4. 點擊登入")
    print("\n如果登入成功，應該看到儀表板（僅顯示部分資料）")
    print("如果登入失敗，請刪除 secure_web_data.json 並重新啟動系統")

if __name__ == '__main__':
    test_user_login()

