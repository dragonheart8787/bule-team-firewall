#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重置密碼 - 使用固定 SALT 重新生成密碼雜湊
"""

import hashlib
import json
import os

# 固定 SALT（與 secure_web_system.py 中一致）
SALT = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"

def hash_password(password):
    """使用固定 SALT 雜湊密碼"""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        SALT.encode('utf-8'),
        100000
    ).hex()

def reset_passwords():
    """重置所有密碼"""
    print("=" * 60)
    print("重置密碼工具")
    print("=" * 60)
    
    data_file = "secure_web_data.json"
    
    # 刪除舊的資料檔案
    if os.path.exists(data_file):
        print(f"\n[1/3] 刪除舊的資料檔案: {data_file}")
        os.remove(data_file)
        print("  [OK] 已刪除")
    else:
        print(f"\n[1/3] 資料檔案不存在: {data_file}")
    
    # 生成新的密碼雜湊
    print("\n[2/3] 生成新的密碼雜湊...")
    
    admin_password = "Admin@2025"
    user_password = "User@2025"
    
    admin_hash = hash_password(admin_password)
    user_hash = hash_password(user_password)
    
    print(f"  Admin 密碼: {admin_password}")
    print(f"  Admin 雜湊: {admin_hash[:64]}...")
    print(f"  User 密碼: {user_password}")
    print(f"  User 雜湊: {user_hash[:64]}...")
    
    # 創建新的資料結構
    data = {
        "users": {
            "admin": {
                "password_hash": admin_hash,
                "role": "admin",
                "email": "admin@example.com"
            },
            "user": {
                "password_hash": user_hash,
                "role": "user",
                "email": "user@example.com"
            }
        },
        "sensitive_data": {
            "database": {
                "host": "db.example.com",
                "user": "admin",
                "pass": "DB@2025"
            },
            "api_keys": {
                "aws": "AKIA...",
                "stripe": "sk_live_..."
            },
            "documents": {
                "plan": "戰略計劃文件",
                "report": "財務報告"
            }
        }
    }
    
    # 保存新的資料檔案
    print("\n[3/3] 保存新的資料檔案...")
    with open(data_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  [OK] 已保存到: {data_file}")
    
    print("\n" + "=" * 60)
    print("密碼重置完成！")
    print("=" * 60)
    print("\n現在可以使用以下帳號登入:")
    print("  管理員: admin / Admin@2025")
    print("  用戶:   user  / User@2025")
    print("\n請重新啟動 Web 系統:")
    print("  python secure_web_system.py")

if __name__ == '__main__':
    reset_passwords()

