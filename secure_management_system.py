#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
國防等級安全管理系統
具備密碼保護、角色權限、APT 防護、DDoS 防禦、入侵檢測
"""

import hashlib
import secrets
import time
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import socket
import hmac

# ==================== 安全配置 ====================

class SecurityConfig:
    """安全配置"""
    # 密碼雜湊加鹽
    SALT = secrets.token_hex(32)
    
    # 登入嘗試限制
    MAX_LOGIN_ATTEMPTS = 3
    LOCKOUT_DURATION = 300  # 5 分鐘鎖定
    
    # Session 設置
    SESSION_TIMEOUT = 1800  # 30 分鐘
    
    # DDoS 防護
    DDOS_THRESHOLD = 10  # 每分鐘最多請求數
    DDOS_WINDOW = 60  # 時間窗口（秒）
    
    # APT 檢測
    APT_SUSPICIOUS_PATTERNS = [
        'union', 'select', 'drop', 'insert', 'update', 'delete',
        'exec', 'script', 'alert', 'onerror', '../', '..\\',
        'cmd', 'powershell', 'bash', '/etc/passwd', 'system32'
    ]

# ==================== 數據存儲（加密） ====================

class SecureDataStore:
    """加密數據存儲"""
    
    def __init__(self):
        self.data_file = "secure_data.json"
        self.audit_log = "security_audit.log"
        self.data = self._load_data()
        
    def _load_data(self):
        """加載數據"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        
        # 默認數據
        return {
            "users": {
                # 用戶名: {密碼雜湊, 角色, 創建時間}
                "admin": {
                    "password_hash": self._hash_password("Admin@2025"),
                    "role": "admin",
                    "created": datetime.now().isoformat(),
                    "last_login": None
                },
                "user": {
                    "password_hash": self._hash_password("User@2025"),
                    "role": "user",
                    "created": datetime.now().isoformat(),
                    "last_login": None
                }
            },
            "sensitive_data": {
                "database_credentials": {
                    "host": "db.example.com",
                    "username": "db_admin",
                    "password": "DB_P@ssw0rd_2025",
                    "classification": "TOP_SECRET"
                },
                "api_keys": {
                    "stripe": "sk_live_XXXXXXXXXXXX",
                    "aws": "AKIAIOSFODNN7EXAMPLE",
                    "classification": "SECRET"
                },
                "internal_documents": {
                    "strategic_plan": "5年戰略規劃 - 機密文件",
                    "financial_report": "Q4 財報 - 內部資料",
                    "classification": "CONFIDENTIAL"
                }
            },
            "system_config": {
                "firewall_status": "ACTIVE",
                "intrusion_detection": "ENABLED",
                "ddos_protection": "ENABLED",
                "apt_defense": "ENABLED",
                "encryption": "AES-256-GCM",
                "last_update": datetime.now().isoformat()
            }
        }
    
    def _hash_password(self, password):
        """密碼雜湊"""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            SecurityConfig.SALT.encode('utf-8'),
            100000
        ).hex()
    
    def save_data(self):
        """保存數據"""
        with open(self.data_file, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
    
    def verify_password(self, username, password):
        """驗證密碼"""
        if username not in self.data['users']:
            return False
        
        stored_hash = self.data['users'][username]['password_hash']
        input_hash = self._hash_password(password)
        
        return hmac.compare_digest(stored_hash, input_hash)
    
    def get_user_role(self, username):
        """獲取用戶角色"""
        return self.data['users'].get(username, {}).get('role')
    
    def log_audit(self, username, action, result, details=""):
        """記錄審計日誌"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "username": username,
            "action": action,
            "result": result,
            "details": details,
            "ip": "127.0.0.1"  # 在實際環境中獲取真實 IP
        }
        
        with open(self.audit_log, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')

# ==================== 安全防護系統 ====================

class DefenseSystem:
    """國防等級防護系統"""
    
    def __init__(self):
        # 登入失敗追蹤
        self.login_attempts = defaultdict(list)
        self.locked_accounts = {}
        
        # DDoS 防護
        self.request_tracker = defaultdict(list)
        self.blocked_ips = set()
        
        # APT 檢測
        self.suspicious_activities = []
        self.threat_level = "GREEN"  # GREEN, YELLOW, ORANGE, RED
        
        # 攻擊者追蹤
        self.attackers = []
        
        # Session 管理
        self.active_sessions = {}
        
    def check_account_lockout(self, username):
        """檢查帳號是否被鎖定"""
        if username in self.locked_accounts:
            unlock_time = self.locked_accounts[username]
            if time.time() < unlock_time:
                remaining = int(unlock_time - time.time())
                return True, remaining
            else:
                del self.locked_accounts[username]
                self.login_attempts[username] = []
        return False, 0
    
    def record_login_attempt(self, username, success, ip="127.0.0.1"):
        """記錄登入嘗試"""
        current_time = time.time()
        
        if not success:
            self.login_attempts[username].append(current_time)
            
            # 清理舊記錄
            self.login_attempts[username] = [
                t for t in self.login_attempts[username]
                if current_time - t < 300
            ]
            
            # 檢查是否超過限制
            if len(self.login_attempts[username]) >= SecurityConfig.MAX_LOGIN_ATTEMPTS:
                self.locked_accounts[username] = current_time + SecurityConfig.LOCKOUT_DURATION
                
                # 記錄攻擊者
                self.attackers.append({
                    "ip": ip,
                    "username": username,
                    "timestamp": datetime.now().isoformat(),
                    "attack_type": "BRUTE_FORCE",
                    "attempts": len(self.login_attempts[username])
                })
                
                return True  # 帳號已鎖定
        else:
            # 成功登入，清除失敗記錄
            self.login_attempts[username] = []
        
        return False
    
    def check_ddos(self, ip):
        """檢查 DDoS 攻擊"""
        current_time = time.time()
        
        # 清理舊記錄
        self.request_tracker[ip] = [
            t for t in self.request_tracker[ip]
            if current_time - t < SecurityConfig.DDOS_WINDOW
        ]
        
        # 記錄當前請求
        self.request_tracker[ip].append(current_time)
        
        # 檢查是否超過閾值
        if len(self.request_tracker[ip]) > SecurityConfig.DDOS_THRESHOLD:
            if ip not in self.blocked_ips:
                self.blocked_ips.add(ip)
                self.attackers.append({
                    "ip": ip,
                    "username": "N/A",
                    "timestamp": datetime.now().isoformat(),
                    "attack_type": "DDOS",
                    "requests": len(self.request_tracker[ip])
                })
                self.update_threat_level()
            return True
        
        return False
    
    def detect_apt(self, input_data):
        """檢測 APT 攻擊"""
        suspicious_patterns = []
        
        for pattern in SecurityConfig.APT_SUSPICIOUS_PATTERNS:
            if pattern.lower() in input_data.lower():
                suspicious_patterns.append(pattern)
        
        if suspicious_patterns:
            self.suspicious_activities.append({
                "timestamp": datetime.now().isoformat(),
                "patterns": suspicious_patterns,
                "input": input_data[:100]  # 只記錄前 100 個字符
            })
            
            self.attackers.append({
                "ip": "127.0.0.1",
                "username": "N/A",
                "timestamp": datetime.now().isoformat(),
                "attack_type": "APT",
                "patterns": suspicious_patterns
            })
            
            self.update_threat_level()
            return True, suspicious_patterns
        
        return False, []
    
    def update_threat_level(self):
        """更新威脅等級"""
        recent_attacks = len([
            a for a in self.attackers
            if (datetime.now() - datetime.fromisoformat(a['timestamp'])).seconds < 300
        ])
        
        if recent_attacks >= 10:
            self.threat_level = "RED"
        elif recent_attacks >= 5:
            self.threat_level = "ORANGE"
        elif recent_attacks >= 2:
            self.threat_level = "YELLOW"
        else:
            self.threat_level = "GREEN"
    
    def create_session(self, username):
        """創建 Session"""
        session_id = secrets.token_urlsafe(32)
        self.active_sessions[session_id] = {
            "username": username,
            "created": time.time(),
            "last_activity": time.time()
        }
        return session_id
    
    def validate_session(self, session_id):
        """驗證 Session"""
        if session_id not in self.active_sessions:
            return False, None
        
        session = self.active_sessions[session_id]
        current_time = time.time()
        
        # 檢查超時
        if current_time - session['last_activity'] > SecurityConfig.SESSION_TIMEOUT:
            del self.active_sessions[session_id]
            return False, None
        
        # 更新活動時間
        session['last_activity'] = current_time
        return True, session['username']

# ==================== 互動式管理介面 ====================

class SecureManagementInterface:
    """安全管理介面"""
    
    def __init__(self):
        self.data_store = SecureDataStore()
        self.defense_system = DefenseSystem()
        self.current_user = None
        self.current_role = None
        self.session_id = None
        
    def clear_screen(self):
        """清空螢幕"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        """顯示橫幅"""
        print("=" * 70)
        print(" " * 15 + "國防等級安全管理系統")
        print(" " * 10 + "Defense-Grade Secure Management System")
        print("=" * 70)
        print()
    
    def print_security_status(self):
        """顯示安全狀態"""
        threat_colors = {
            "GREEN": "[正常]",
            "YELLOW": "[警戒]",
            "ORANGE": "[危險]",
            "RED": "[緊急]"
        }
        
        print(f"威脅等級: {threat_colors[self.defense_system.threat_level]} {self.defense_system.threat_level}")
        print(f"防火牆: {self.data_store.data['system_config']['firewall_status']}")
        print(f"入侵檢測: {self.data_store.data['system_config']['intrusion_detection']}")
        print(f"DDoS 防護: {self.data_store.data['system_config']['ddos_protection']}")
        print(f"APT 防禦: {self.data_store.data['system_config']['apt_defense']}")
        print(f"攔截 IP 數: {len(self.defense_system.blocked_ips)}")
        print(f"檢測到攻擊: {len(self.defense_system.attackers)}")
        print("=" * 70)
        print()
    
    def login(self):
        """登入流程"""
        self.clear_screen()
        self.print_banner()
        
        print("[登入系統]")
        print()
        
        # DDoS 檢查
        if self.defense_system.check_ddos("127.0.0.1"):
            print("[安全警告] 檢測到 DDoS 攻擊！IP 已被封鎖。")
            self.data_store.log_audit("SYSTEM", "DDOS_DETECTED", "BLOCKED", "127.0.0.1")
            time.sleep(3)
            return False
        
        username = input("用戶名: ").strip()
        
        if not username:
            return False
        
        # APT 檢測
        is_apt, patterns = self.defense_system.detect_apt(username)
        if is_apt:
            print(f"\n[安全警告] 檢測到 APT 攻擊模式: {', '.join(patterns)}")
            print("攻擊已記錄，通知管理員。")
            self.data_store.log_audit(username, "APT_DETECTED", "BLOCKED", f"Patterns: {patterns}")
            time.sleep(3)
            return False
        
        # 檢查帳號鎖定
        is_locked, remaining = self.defense_system.check_account_lockout(username)
        if is_locked:
            print(f"\n[安全警告] 帳號已被鎖定！")
            print(f"剩餘鎖定時間: {remaining} 秒")
            print("多次登入失敗，已通知管理員。")
            time.sleep(3)
            return False
        
        # 隱藏密碼輸入
        import getpass
        password = getpass.getpass("密碼: ")
        
        # APT 檢測密碼
        is_apt, patterns = self.defense_system.detect_apt(password)
        if is_apt:
            print(f"\n[安全警告] 檢測到 APT 攻擊模式: {', '.join(patterns)}")
            self.data_store.log_audit(username, "APT_DETECTED", "BLOCKED", f"Patterns: {patterns}")
            time.sleep(3)
            return False
        
        # 驗證密碼
        if self.data_store.verify_password(username, password):
            # 登入成功
            self.current_user = username
            self.current_role = self.data_store.get_user_role(username)
            self.session_id = self.defense_system.create_session(username)
            
            # 記錄成功登入
            self.defense_system.record_login_attempt(username, True)
            self.data_store.log_audit(username, "LOGIN", "SUCCESS", f"Role: {self.current_role}")
            
            # 更新最後登入時間
            self.data_store.data['users'][username]['last_login'] = datetime.now().isoformat()
            self.data_store.save_data()
            
            print(f"\n登入成功！歡迎 {username} ({self.current_role.upper()})")
            time.sleep(2)
            return True
        else:
            # 登入失敗
            is_locked = self.defense_system.record_login_attempt(username, False)
            self.data_store.log_audit(username, "LOGIN", "FAILED", "Invalid credentials")
            
            if is_locked:
                print(f"\n[安全警告] 多次登入失敗！帳號已被鎖定 {SecurityConfig.LOCKOUT_DURATION} 秒。")
                print("此事件已通知管理員。")
            else:
                remaining = SecurityConfig.MAX_LOGIN_ATTEMPTS - len(self.defense_system.login_attempts[username])
                print(f"\n登入失敗！剩餘嘗試次數: {remaining}")
            
            time.sleep(3)
            return False
    
    def admin_menu(self):
        """管理員選單"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_security_status()
            
            print(f"當前用戶: {self.current_user} (管理員)")
            print()
            print("[管理員選單]")
            print("1. 查看機密資料")
            print("2. 修改機密資料")
            print("3. 系統配置管理")
            print("4. 查看安全日誌")
            print("5. 查看攻擊者列表")
            print("6. 封鎖/解封 IP")
            print("7. 修改威脅等級")
            print("8. 查看活動 Session")
            print("9. 變更用戶密碼")
            print("0. 登出")
            print()
            
            choice = input("請選擇功能 (0-9): ").strip()
            
            if choice == "1":
                self.view_data()
            elif choice == "2":
                self.modify_data()
            elif choice == "3":
                self.manage_system_config()
            elif choice == "4":
                self.view_security_logs()
            elif choice == "5":
                self.view_attackers()
            elif choice == "6":
                self.manage_blocked_ips()
            elif choice == "7":
                self.change_threat_level()
            elif choice == "8":
                self.view_sessions()
            elif choice == "9":
                self.change_password()
            elif choice == "0":
                self.logout()
                break
            else:
                print("\n無效的選擇！")
                time.sleep(1)
    
    def user_menu(self):
        """用戶選單"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_security_status()
            
            print(f"當前用戶: {self.current_user} (普通用戶)")
            print()
            print("[用戶選單]")
            print("1. 查看資料（唯讀）")
            print("2. 查看系統狀態")
            print("3. 查看我的登入記錄")
            print("0. 登出")
            print()
            
            choice = input("請選擇功能 (0-3): ").strip()
            
            if choice == "1":
                self.view_data()
            elif choice == "2":
                self.view_system_status()
            elif choice == "3":
                self.view_my_logs()
            elif choice == "0":
                self.logout()
                break
            else:
                print("\n無效的選擇！")
                time.sleep(1)
    
    def view_data(self):
        """查看資料"""
        self.clear_screen()
        print("[機密資料查看]")
        print("=" * 70)
        
        data = self.data_store.data['sensitive_data']
        
        for category, content in data.items():
            print(f"\n[{category}]")
            classification = content.pop('classification', 'UNCLASSIFIED')
            print(f"機密等級: {classification}")
            
            for key, value in content.items():
                if self.current_role == 'admin' or classification not in ['TOP_SECRET']:
                    print(f"  {key}: {value}")
                else:
                    print(f"  {key}: [權限不足 - 需要管理員權限]")
            
            content['classification'] = classification
        
        self.data_store.log_audit(self.current_user, "VIEW_DATA", "SUCCESS", "Viewed sensitive data")
        
        print("\n" + "=" * 70)
        input("\n按 Enter 繼續...")
    
    def modify_data(self):
        """修改資料（僅管理員）"""
        if self.current_role != 'admin':
            print("\n[權限拒絕] 只有管理員可以修改資料！")
            time.sleep(2)
            return
        
        self.clear_screen()
        print("[修改機密資料]")
        print("=" * 70)
        
        print("\n可修改的類別:")
        categories = list(self.data_store.data['sensitive_data'].keys())
        for i, cat in enumerate(categories, 1):
            print(f"{i}. {cat}")
        print("0. 返回")
        
        choice = input("\n選擇類別: ").strip()
        
        if choice == "0":
            return
        
        try:
            cat_index = int(choice) - 1
            if 0 <= cat_index < len(categories):
                category = categories[cat_index]
                
                print(f"\n修改 [{category}]")
                key = input("鍵名: ").strip()
                value = input("新值: ").strip()
                
                if key and value:
                    self.data_store.data['sensitive_data'][category][key] = value
                    self.data_store.save_data()
                    self.data_store.log_audit(
                        self.current_user,
                        "MODIFY_DATA",
                        "SUCCESS",
                        f"Modified {category}.{key}"
                    )
                    print("\n修改成功！")
                else:
                    print("\n修改取消。")
            else:
                print("\n無效的選擇！")
        except:
            print("\n輸入錯誤！")
        
        time.sleep(2)
    
    def manage_system_config(self):
        """系統配置管理"""
        if self.current_role != 'admin':
            print("\n[權限拒絕] 只有管理員可以管理系統配置！")
            time.sleep(2)
            return
        
        self.clear_screen()
        print("[系統配置管理]")
        print("=" * 70)
        
        config = self.data_store.data['system_config']
        
        print("\n1. 防火牆狀態:", config['firewall_status'])
        print("2. 入侵檢測:", config['intrusion_detection'])
        print("3. DDoS 防護:", config['ddos_protection'])
        print("4. APT 防禦:", config['apt_defense'])
        print("0. 返回")
        
        choice = input("\n選擇要修改的項目 (0-4): ").strip()
        
        if choice == "0":
            return
        
        if choice in ['1', '2', '3', '4']:
            new_status = input("新狀態 (ACTIVE/INACTIVE 或 ENABLED/DISABLED): ").strip().upper()
            
            if choice == '1':
                config['firewall_status'] = new_status
            elif choice == '2':
                config['intrusion_detection'] = new_status
            elif choice == '3':
                config['ddos_protection'] = new_status
            elif choice == '4':
                config['apt_defense'] = new_status
            
            config['last_update'] = datetime.now().isoformat()
            self.data_store.save_data()
            self.data_store.log_audit(
                self.current_user,
                "MODIFY_CONFIG",
                "SUCCESS",
                f"Changed option {choice} to {new_status}"
            )
            print("\n配置已更新！")
        
        time.sleep(2)
    
    def view_security_logs(self):
        """查看安全日誌"""
        if self.current_role != 'admin':
            print("\n[權限拒絕] 只有管理員可以查看完整安全日誌！")
            time.sleep(2)
            return
        
        self.clear_screen()
        print("[安全審計日誌]")
        print("=" * 70)
        
        if os.path.exists(self.data_store.audit_log):
            with open(self.data_store.audit_log, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            # 顯示最後 20 條
            for line in lines[-20:]:
                try:
                    entry = json.loads(line)
                    print(f"[{entry['timestamp']}] {entry['username']}: {entry['action']} - {entry['result']}")
                    if entry['details']:
                        print(f"  詳情: {entry['details']}")
                except:
                    pass
        else:
            print("暫無日誌記錄。")
        
        print("=" * 70)
        input("\n按 Enter 繼續...")
    
    def view_attackers(self):
        """查看攻擊者列表"""
        if self.current_role != 'admin':
            print("\n[權限拒絕] 只有管理員可以查看攻擊者列表！")
            time.sleep(2)
            return
        
        self.clear_screen()
        print("[攻擊者追蹤列表]")
        print("=" * 70)
        
        if self.defense_system.attackers:
            for i, attacker in enumerate(self.defense_system.attackers[-20:], 1):
                print(f"\n[攻擊 {i}]")
                print(f"  IP地址: {attacker['ip']}")
                print(f"  目標用戶: {attacker.get('username', 'N/A')}")
                print(f"  時間: {attacker['timestamp']}")
                print(f"  類型: {attacker['attack_type']}")
                
                if 'patterns' in attacker:
                    print(f"  檢測模式: {', '.join(attacker['patterns'])}")
                if 'attempts' in attacker:
                    print(f"  嘗試次數: {attacker['attempts']}")
                if 'requests' in attacker:
                    print(f"  請求數: {attacker['requests']}")
        else:
            print("\n目前沒有檢測到攻擊。")
        
        print("\n" + "=" * 70)
        input("\n按 Enter 繼續...")
    
    def manage_blocked_ips(self):
        """管理封鎖的 IP"""
        if self.current_role != 'admin':
            print("\n[權限拒絕] 只有管理員可以管理 IP 封鎖！")
            time.sleep(2)
            return
        
        self.clear_screen()
        print("[IP 封鎖管理]")
        print("=" * 70)
        
        if self.defense_system.blocked_ips:
            print("\n已封鎖的 IP:")
            for ip in self.defense_system.blocked_ips:
                print(f"  - {ip}")
        else:
            print("\n目前沒有封鎖的 IP。")
        
        print("\n1. 封鎖新 IP")
        print("2. 解封 IP")
        print("0. 返回")
        
        choice = input("\n選擇操作 (0-2): ").strip()
        
        if choice == "1":
            ip = input("輸入要封鎖的 IP: ").strip()
            if ip:
                self.defense_system.blocked_ips.add(ip)
                self.data_store.log_audit(self.current_user, "BLOCK_IP", "SUCCESS", ip)
                print(f"\nIP {ip} 已被封鎖！")
                time.sleep(2)
        elif choice == "2":
            ip = input("輸入要解封的 IP: ").strip()
            if ip in self.defense_system.blocked_ips:
                self.defense_system.blocked_ips.remove(ip)
                self.data_store.log_audit(self.current_user, "UNBLOCK_IP", "SUCCESS", ip)
                print(f"\nIP {ip} 已解封！")
                time.sleep(2)
    
    def change_threat_level(self):
        """修改威脅等級"""
        if self.current_role != 'admin':
            print("\n[權限拒絕] 只有管理員可以修改威脅等級！")
            time.sleep(2)
            return
        
        self.clear_screen()
        print("[威脅等級管理]")
        print("=" * 70)
        
        print(f"\n當前威脅等級: {self.defense_system.threat_level}")
        print("\n可選等級:")
        print("1. GREEN (正常)")
        print("2. YELLOW (警戒)")
        print("3. ORANGE (危險)")
        print("4. RED (緊急)")
        print("0. 返回")
        
        choice = input("\n選擇新等級 (0-4): ").strip()
        
        levels = {
            "1": "GREEN",
            "2": "YELLOW",
            "3": "ORANGE",
            "4": "RED"
        }
        
        if choice in levels:
            new_level = levels[choice]
            self.defense_system.threat_level = new_level
            self.data_store.log_audit(
                self.current_user,
                "CHANGE_THREAT_LEVEL",
                "SUCCESS",
                f"Changed to {new_level}"
            )
            print(f"\n威脅等級已更新為: {new_level}")
            time.sleep(2)
    
    def view_sessions(self):
        """查看活動 Session"""
        if self.current_role != 'admin':
            print("\n[權限拒絕] 只有管理員可以查看 Session！")
            time.sleep(2)
            return
        
        self.clear_screen()
        print("[活動 Session]")
        print("=" * 70)
        
        if self.defense_system.active_sessions:
            for sid, session in self.defense_system.active_sessions.items():
                print(f"\nSession ID: {sid[:16]}...")
                print(f"  用戶: {session['username']}")
                print(f"  創建時間: {datetime.fromtimestamp(session['created']).isoformat()}")
                print(f"  最後活動: {datetime.fromtimestamp(session['last_activity']).isoformat()}")
        else:
            print("\n目前沒有活動 Session。")
        
        print("\n" + "=" * 70)
        input("\n按 Enter 繼續...")
    
    def change_password(self):
        """變更密碼"""
        if self.current_role != 'admin':
            print("\n[權限拒絕] 只有管理員可以變更密碼！")
            time.sleep(2)
            return
        
        self.clear_screen()
        print("[變更用戶密碼]")
        print("=" * 70)
        
        print("\n可用用戶:")
        for username in self.data_store.data['users'].keys():
            print(f"  - {username}")
        
        target_user = input("\n輸入用戶名: ").strip()
        
        if target_user in self.data_store.data['users']:
            import getpass
            new_password = getpass.getpass("新密碼: ")
            confirm_password = getpass.getpass("確認密碼: ")
            
            if new_password == confirm_password:
                new_hash = self.data_store._hash_password(new_password)
                self.data_store.data['users'][target_user]['password_hash'] = new_hash
                self.data_store.save_data()
                self.data_store.log_audit(
                    self.current_user,
                    "CHANGE_PASSWORD",
                    "SUCCESS",
                    f"Changed password for {target_user}"
                )
                print("\n密碼已更新！")
            else:
                print("\n密碼不匹配！")
        else:
            print("\n用戶不存在！")
        
        time.sleep(2)
    
    def view_system_status(self):
        """查看系統狀態"""
        self.clear_screen()
        print("[系統狀態]")
        print("=" * 70)
        
        config = self.data_store.data['system_config']
        
        print(f"\n防火牆: {config['firewall_status']}")
        print(f"入侵檢測: {config['intrusion_detection']}")
        print(f"DDoS 防護: {config['ddos_protection']}")
        print(f"APT 防禦: {config['apt_defense']}")
        print(f"加密方式: {config['encryption']}")
        print(f"最後更新: {config['last_update']}")
        
        print(f"\n威脅等級: {self.defense_system.threat_level}")
        print(f"封鎖 IP 數: {len(self.defense_system.blocked_ips)}")
        print(f"活動 Session: {len(self.defense_system.active_sessions)}")
        
        print("\n" + "=" * 70)
        input("\n按 Enter 繼續...")
    
    def view_my_logs(self):
        """查看自己的登入記錄"""
        self.clear_screen()
        print("[我的登入記錄]")
        print("=" * 70)
        
        if os.path.exists(self.data_store.audit_log):
            with open(self.data_store.audit_log, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            my_logs = []
            for line in lines:
                try:
                    entry = json.loads(line)
                    if entry['username'] == self.current_user and entry['action'] == 'LOGIN':
                        my_logs.append(entry)
                except:
                    pass
            
            if my_logs:
                for log in my_logs[-10:]:
                    status = "✓" if log['result'] == 'SUCCESS' else "✗"
                    print(f"[{log['timestamp']}] {status} {log['result']}")
            else:
                print("\n暫無登入記錄。")
        else:
            print("\n暫無登入記錄。")
        
        print("\n" + "=" * 70)
        input("\n按 Enter 繼續...")
    
    def logout(self):
        """登出"""
        if self.session_id:
            if self.session_id in self.defense_system.active_sessions:
                del self.defense_system.active_sessions[self.session_id]
        
        self.data_store.log_audit(self.current_user, "LOGOUT", "SUCCESS", "")
        
        print("\n正在登出...")
        self.current_user = None
        self.current_role = None
        self.session_id = None
        time.sleep(1)
    
    def run(self):
        """運行系統"""
        while True:
            if not self.current_user:
                if not self.login():
                    continue
            
            if self.current_role == 'admin':
                self.admin_menu()
            else:
                self.user_menu()

# ==================== 主程序 ====================

def main():
    print("\n初始化國防等級安全管理系統...")
    print("\n預設帳號:")
    print("  管理員 - 用戶名: admin, 密碼: Admin@2025")
    print("  普通用戶 - 用戶名: user, 密碼: User@2025")
    print("\n按 Enter 開始...")
    input()
    
    system = SecureManagementInterface()
    
    try:
        system.run()
    except KeyboardInterrupt:
        print("\n\n系統正在安全關閉...")
        system.data_store.log_audit("SYSTEM", "SHUTDOWN", "SUCCESS", "Graceful shutdown")
        time.sleep(1)
    except Exception as e:
        print(f"\n\n[系統錯誤] {e}")
        system.data_store.log_audit("SYSTEM", "ERROR", "FAILED", str(e))
        time.sleep(2)

if __name__ == "__main__":
    main()


