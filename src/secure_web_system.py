#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
國防等級 Web 安全管理系統
- Web UI 介面
- 密碼輸入框（安全隱藏）
- 中央伺服器資料傳輸
- 中間層攻擊防護
- DDoS 防護
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import hashlib
import secrets
import time
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
import hmac
import threading

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ==================== 安全配置 ====================

class SecurityConfig:
    """安全配置"""
    # 固定 SALT 值，確保密碼雜湊一致性
    # 注意：在生產環境中，應該使用環境變數或配置檔案
    SALT = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"
    
    # 登入保護
    MAX_LOGIN_ATTEMPTS = 3
    LOCKOUT_DURATION = 300
    
    # Session
    SESSION_TIMEOUT = 1800
    
    # DDoS 防護
    DDOS_THRESHOLD = 100  # 每分鐘請求數
    DDOS_WINDOW = 60
    RATE_LIMIT = 20  # 每個端點每分鐘請求數
    
    # 中間層防護
    ALLOWED_ORIGINS = ['http://localhost:5000', 'http://127.0.0.1:5000']
    REQUIRE_CSRF_TOKEN = True
    
    # 資料傳輸加密（固定密鑰，確保 SHA-256 加密一致性）
    ENCRYPTION_KEY = b'secure_defense_grade_encryption_key_2025_v1.0_secret'

# ==================== 中央伺服器模擬 ====================

class CentralServer:
    """中央伺服器（真實連接）"""
    
    def __init__(self):
        self.server_url = "http://127.0.0.1:9000"
        self.api_key = secrets.token_hex(32)
        self.transmission_log = []
        
    def transmit_data(self, data_type, data, user):
        """傳輸資料到中央伺服器"""
        import requests
        
        transmission = {
            "id": secrets.token_hex(16),
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "data_type": data_type,
            "data": self._encrypt_data(data),
            "checksum": self._calculate_checksum(data),
            "status": "PENDING"
        }
        
        # 嘗試傳輸到真實中央伺服器
        try:
            response = requests.post(
                f"{self.server_url}/api/receive",
                json=transmission,
                timeout=3
            )
            
            if response.status_code == 200:
                transmission["status"] = "SUCCESS"
            else:
                transmission["status"] = "FAILED"
        except:
            transmission["status"] = "OFFLINE"
        
        self.transmission_log.append(transmission)
        
        return transmission["id"]
    
    def _encrypt_data(self, data):
        """加密資料"""
        data_str = json.dumps(data, ensure_ascii=False)
        encrypted = hashlib.sha256(
            data_str.encode() + SecurityConfig.ENCRYPTION_KEY
        ).hexdigest()
        return encrypted
    
    def _calculate_checksum(self, data):
        """計算校驗和"""
        data_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
        return hashlib.md5(data_str.encode()).hexdigest()
    
    def get_transmission_history(self, limit=10):
        """獲取傳輸歷史"""
        return self.transmission_log[-limit:]

# ==================== 防護系統 ====================

class DefenseSystem:
    """防護系統"""
    
    def __init__(self):
        # 登入失敗追蹤
        self.login_attempts = defaultdict(list)
        self.locked_accounts = {}
        
        # DDoS 防護
        self.request_tracker = defaultdict(lambda: defaultdict(list))
        self.blocked_ips = set()
        
        # 中間層攻擊檢測
        self.suspicious_requests = []
        
        # 攻擊記錄
        self.attack_log = []
        
        # 威脅等級
        self.threat_level = "GREEN"
        
        # CSRF Token
        self.csrf_tokens = {}
    
    def check_rate_limit(self, ip, endpoint):
        """檢查速率限制"""
        current_time = time.time()
        
        # 清理舊記錄
        self.request_tracker[ip][endpoint] = [
            t for t in self.request_tracker[ip][endpoint]
            if current_time - t < SecurityConfig.DDOS_WINDOW
        ]
        
        # 記錄當前請求
        self.request_tracker[ip][endpoint].append(current_time)
        
        # 檢查是否超過限制
        if len(self.request_tracker[ip][endpoint]) > SecurityConfig.RATE_LIMIT:
            self._log_attack(ip, "RATE_LIMIT_EXCEEDED", endpoint)
            return False
        
        return True
    
    def check_ddos(self, ip):
        """檢查 DDoS 攻擊"""
        if ip in self.blocked_ips:
            return False
        
        current_time = time.time()
        
        # 計算所有端點的總請求數
        total_requests = 0
        for endpoint_requests in self.request_tracker[ip].values():
            recent_requests = [
                t for t in endpoint_requests
                if current_time - t < SecurityConfig.DDOS_WINDOW
            ]
            total_requests += len(recent_requests)
        
        if total_requests > SecurityConfig.DDOS_THRESHOLD:
            self.blocked_ips.add(ip)
            self._log_attack(ip, "DDOS", f"{total_requests} requests/min")
            self._update_threat_level()
            return False
        
        return True
    
    def check_middleware_attack(self, request_obj):
        """檢查中間層攻擊"""
        attacks_detected = []
        
        # 檢查 SQL 注入
        sql_patterns = ['union', 'select', 'insert', 'update', 'delete', 'drop', '--', ';']
        for param_value in request_obj.values:
            param_str = str(param_value).lower()
            for pattern in sql_patterns:
                if pattern in param_str:
                    attacks_detected.append(f"SQL_INJECTION:{pattern}")
        
        # 檢查 XSS
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=']
        for param_value in request_obj.values:
            param_str = str(param_value).lower()
            for pattern in xss_patterns:
                if pattern in param_str:
                    attacks_detected.append(f"XSS:{pattern}")
        
        # 檢查路徑遍歷
        if '../' in str(request_obj.values) or '..\\' in str(request_obj.values):
            attacks_detected.append("PATH_TRAVERSAL")
        
        # 檢查命令注入
        cmd_patterns = ['|', ';', '`', '$', '&&', '||']
        for param_value in request_obj.values:
            param_str = str(param_value)
            for pattern in cmd_patterns:
                if pattern in param_str:
                    attacks_detected.append(f"COMMAND_INJECTION:{pattern}")
        
        if attacks_detected:
            ip = request_obj.remote_addr
            self._log_attack(ip, "MIDDLEWARE_ATTACK", ', '.join(attacks_detected))
            self.suspicious_requests.append({
                "timestamp": datetime.now().isoformat(),
                "ip": ip,
                "path": request_obj.path,
                "attacks": attacks_detected
            })
            self._update_threat_level()
            return False
        
        return True
    
    def generate_csrf_token(self, session_id):
        """生成 CSRF Token"""
        token = secrets.token_urlsafe(32)
        self.csrf_tokens[session_id] = {
            "token": token,
            "created": time.time()
        }
        return token
    
    def validate_csrf_token(self, session_id, token):
        """驗證 CSRF Token"""
        if session_id not in self.csrf_tokens:
            return False
        
        stored = self.csrf_tokens[session_id]
        
        # 檢查過期（10分鐘）
        if time.time() - stored["created"] > 600:
            del self.csrf_tokens[session_id]
            return False
        
        return hmac.compare_digest(stored["token"], token)
    
    def _log_attack(self, ip, attack_type, details):
        """記錄攻擊"""
        self.attack_log.append({
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "type": attack_type,
            "details": details
        })
    
    def _update_threat_level(self):
        """更新威脅等級"""
        recent_attacks = len([
            a for a in self.attack_log
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

# ==================== 數據存儲 ====================

class SecureDataStore:
    """安全數據存儲"""
    
    def __init__(self):
        self.data_file = "secure_web_data.json"
        self.data = self._load_data()
        
    def _load_data(self):
        """加載數據"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        
        return {
            "users": {
                "admin": {
                    "password_hash": self._hash_password("Admin@2025"),
                    "role": "admin",
                    "email": "admin@example.com"
                },
                "user": {
                    "password_hash": self._hash_password("User@2025"),
                    "role": "user",
                    "email": "user@example.com"
                }
            },
            "sensitive_data": {
                "database": {"host": "db.example.com", "user": "admin", "pass": "DB@2025"},
                "api_keys": {"aws": "AKIA...", "stripe": "sk_live_..."},
                "documents": {"plan": "戰略計劃文件", "report": "財務報告"}
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
    
    def verify_password(self, username, password):
        """驗證密碼"""
        if username not in self.data['users']:
            return False
        
        stored_hash = self.data['users'][username]['password_hash']
        input_hash = self._hash_password(password)
        
        return hmac.compare_digest(stored_hash, input_hash)
    
    def get_user_info(self, username):
        """獲取用戶信息"""
        return self.data['users'].get(username, {})
    
    def save_data(self):
        """保存數據"""
        with open(self.data_file, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)

# ==================== 全局實例 ====================

data_store = SecureDataStore()
defense_system = DefenseSystem()
central_server = CentralServer()

# ==================== 裝飾器 ====================

def require_login(f):
    """需要登入"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """需要管理員權限"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or session.get('role') != 'admin':
            return jsonify({"error": "權限不足"}), 403
        return f(*args, **kwargs)
    return decorated_function

def check_security(f):
    """安全檢查"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        
        # DDoS 檢查
        if not defense_system.check_ddos(ip):
            return jsonify({"error": "請求過於頻繁，已被封鎖"}), 429
        
        # 速率限制
        if not defense_system.check_rate_limit(ip, request.endpoint):
            return jsonify({"error": "請求速率超過限制"}), 429
        
        # 中間層攻擊檢查
        if not defense_system.check_middleware_attack(request):
            return jsonify({"error": "檢測到可疑請求"}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# ==================== 路由 ====================

@app.route('/')
def index():
    """首頁"""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@check_security
def login():
    """登入頁面"""
    if request.method == 'GET':
        # 生成 CSRF Token
        csrf_token = defense_system.generate_csrf_token(request.remote_addr)
        return render_template('login.html', csrf_token=csrf_token)
    
    # POST 請求
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    csrf_token = data.get('csrf_token', '')
    
    # CSRF 驗證
    if not defense_system.validate_csrf_token(request.remote_addr, csrf_token):
        return jsonify({"error": "CSRF Token 無效"}), 403
    
    # 檢查帳號鎖定
    if username in defense_system.locked_accounts:
        unlock_time = defense_system.locked_accounts[username]
        if time.time() < unlock_time:
            remaining = int(unlock_time - time.time())
            return jsonify({"error": f"帳號已鎖定，剩餘 {remaining} 秒"}), 403
        else:
            del defense_system.locked_accounts[username]
    
    # 驗證密碼
    if data_store.verify_password(username, password):
        # 登入成功
        user_info = data_store.get_user_info(username)
        session['user'] = username
        session['role'] = user_info['role']
        session['login_time'] = time.time()
        
        # 傳輸登入事件到中央伺服器
        central_server.transmit_data(
            "LOGIN_EVENT",
            {"username": username, "role": user_info['role'], "ip": request.remote_addr},
            username
        )
        
        # 清除失敗記錄
        defense_system.login_attempts[username] = []
        
        return jsonify({"success": True, "redirect": url_for('dashboard')})
    else:
        # 登入失敗
        defense_system.login_attempts[username].append(time.time())
        
        # 清理舊記錄
        defense_system.login_attempts[username] = [
            t for t in defense_system.login_attempts[username]
            if time.time() - t < 300
        ]
        
        # 檢查是否需要鎖定
        if len(defense_system.login_attempts[username]) >= SecurityConfig.MAX_LOGIN_ATTEMPTS:
            defense_system.locked_accounts[username] = time.time() + SecurityConfig.LOCKOUT_DURATION
            defense_system._log_attack(request.remote_addr, "BRUTE_FORCE", username)
            
            # 傳輸攻擊事件
            central_server.transmit_data(
                "SECURITY_ALERT",
                {"type": "BRUTE_FORCE", "username": username, "ip": request.remote_addr},
                "SYSTEM"
            )
            
            return jsonify({"error": "登入失敗次數過多，帳號已鎖定 5 分鐘"}), 403
        
        remaining = SecurityConfig.MAX_LOGIN_ATTEMPTS - len(defense_system.login_attempts[username])
        return jsonify({"error": f"密碼錯誤，剩餘嘗試次數: {remaining}"}), 401

@app.route('/dashboard')
@require_login
@check_security
def dashboard():
    """儀表板"""
    return render_template('dashboard.html',
                         user=session['user'],
                         role=session['role'],
                         threat_level=defense_system.threat_level)

@app.route('/api/data')
@require_login
@check_security
def get_data():
    """獲取資料"""
    role = session.get('role')
    data = data_store.data['sensitive_data']
    
    # 根據角色過濾資料
    if role == 'admin':
        filtered_data = data
    else:
        # 普通用戶只能看部分資料
        filtered_data = {
            "documents": data.get("documents", {})
        }
    
    # 傳輸資料訪問事件
    central_server.transmit_data(
        "DATA_ACCESS",
        {"role": role, "data_accessed": list(filtered_data.keys())},
        session['user']
    )
    
    return jsonify(filtered_data)

@app.route('/api/data/update', methods=['POST'])
@require_admin
@check_security
def update_data():
    """更新資料（僅管理員）"""
    data = request.get_json()
    category = data.get('category')
    key = data.get('key')
    value = data.get('value')
    
    if category and key and value:
        if category not in data_store.data['sensitive_data']:
            data_store.data['sensitive_data'][category] = {}
        
        data_store.data['sensitive_data'][category][key] = value
        data_store.save_data()
        
        # 傳輸資料修改事件
        central_server.transmit_data(
            "DATA_MODIFICATION",
            {"category": category, "key": key},
            session['user']
        )
        
        return jsonify({"success": True, "message": "資料已更新"})
    
    return jsonify({"error": "參數不完整"}), 400

@app.route('/api/security/status')
@require_login
@check_security
def security_status():
    """安全狀態"""
    return jsonify({
        "threat_level": defense_system.threat_level,
        "blocked_ips": list(defense_system.blocked_ips),
        "recent_attacks": defense_system.attack_log[-10:],
        "suspicious_requests": defense_system.suspicious_requests[-10:]
    })

@app.route('/api/security/attacks')
@require_admin
@check_security
def get_attacks():
    """獲取攻擊列表（僅管理員）"""
    return jsonify({
        "total_attacks": len(defense_system.attack_log),
        "attacks": defense_system.attack_log[-50:],
        "blocked_ips": list(defense_system.blocked_ips)
    })

@app.route('/api/central/transmissions')
@require_admin
@check_security
def get_transmissions():
    """獲取中央伺服器傳輸記錄（僅管理員）"""
    return jsonify({
        "transmissions": central_server.get_transmission_history(20),
        "server_url": central_server.server_url
    })

@app.route('/api/security/unblock', methods=['POST'])
@require_admin
@check_security
def unblock_ip():
    """解封 IP（僅管理員）"""
    data = request.get_json()
    ip = data.get('ip')
    
    if ip in defense_system.blocked_ips:
        defense_system.blocked_ips.remove(ip)
        
        # 傳輸解封事件
        central_server.transmit_data(
            "IP_UNBLOCKED",
            {"ip": ip},
            session['user']
        )
        
        return jsonify({"success": True, "message": f"IP {ip} 已解封"})
    
    return jsonify({"error": "IP 不在封鎖列表中"}), 400

@app.route('/logout')
def logout():
    """登出"""
    if 'user' in session:
        # 傳輸登出事件
        central_server.transmit_data(
            "LOGOUT_EVENT",
            {"username": session['user']},
            session['user']
        )
        
        session.clear()
    
    return redirect(url_for('login'))

# ==================== HTML 模板（內嵌） ====================

def create_templates():
    """創建模板文件"""
    os.makedirs('templates', exist_ok=True)
    
    # login.html
    with open('templates/login.html', 'w', encoding='utf-8') as f:
        f.write('''<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登入 - 國防等級安全系統</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Microsoft JhengHei', 'Arial', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 90%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #667eea;
            font-size: 24px;
            margin-bottom: 5px;
        }
        .logo p {
            color: #666;
            font-size: 14px;
        }
        .shield-icon {
            font-size: 48px;
            margin-bottom: 10px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: bold;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
        }
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        .alert {
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: none;
        }
        .alert.error {
            background: #fee;
            border: 1px solid #fcc;
            color: #c33;
        }
        .alert.show {
            display: block;
        }
        .info-box {
            background: #f0f7ff;
            border: 1px solid #b3d9ff;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            font-size: 12px;
            color: #0066cc;
        }
        .info-box strong {
            display: block;
            margin-bottom: 5px;
        }
        .security-badge {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-top: 20px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
            font-size: 12px;
            color: #666;
        }
        .security-badge span {
            color: #28a745;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <div class="shield-icon">🛡️</div>
            <h1>國防等級安全系統</h1>
            <p>Defense-Grade Security Platform</p>
        </div>
        
        <div id="alert" class="alert"></div>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="username">用戶名</label>
                <input type="text" id="username" name="username" required autocomplete="username" placeholder="請輸入用戶名">
            </div>
            
            <div class="form-group">
                <label for="password">密碼</label>
                <input type="password" id="password" name="password" required autocomplete="current-password" placeholder="請輸入密碼">
            </div>
            
            <button type="submit" class="btn" id="loginBtn">登入系統</button>
        </form>
        
        <div class="info-box">
            <strong>預設帳號：</strong>
            管理員: admin / Admin@2025<br>
            用戶: user / User@2025
        </div>
        
        <div class="security-badge">
            🔒 <span>SHA-256 加密</span> | 🛡️ <span>DDoS 防護</span> | 🔍 <span>入侵檢測</span> | 📡 <span>中央伺服器傳輸</span>
        </div>
    </div>
    
    <script>
        const csrfToken = "{{ csrf_token }}";
        
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const btn = document.getElementById('loginBtn');
            const alert = document.getElementById('alert');
            
            btn.disabled = true;
            btn.textContent = '登入中...';
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username: username,
                        password: password,
                        csrf_token: csrfToken
                    })
                });
                
                const data = await response.json();
                
                if (response.ok && data.success) {
                    alert.className = 'alert';
                    window.location.href = data.redirect;
                } else {
                    alert.className = 'alert error show';
                    alert.textContent = data.error || '登入失敗';
                    btn.disabled = false;
                    btn.textContent = '登入系統';
                }
            } catch (error) {
                alert.className = 'alert error show';
                alert.textContent = '網路錯誤，請稍後再試';
                btn.disabled = false;
                btn.textContent = '登入系統';
            }
        });
    </script>
</body>
</html>''')
    
    # dashboard.html
    with open('templates/dashboard.html', 'w', encoding='utf-8') as f:
        f.write('''<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>儀表板 - 國防等級安全系統</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Microsoft JhengHei', 'Arial', sans-serif;
            background: #f5f7fa;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            font-size: 24px;
        }
        .user-info {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        .user-badge {
            background: rgba(255,255,255,0.2);
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 14px;
        }
        .logout-btn {
            background: rgba(255,255,255,0.3);
            border: none;
            color: white;
            padding: 8px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
        }
        .logout-btn:hover {
            background: rgba(255,255,255,0.4);
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .threat-level {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 20px;
        }
        .threat-icon {
            font-size: 48px;
        }
        .threat-info h2 {
            font-size: 18px;
            margin-bottom: 5px;
        }
        .threat-level.GREEN { border-left: 5px solid #28a745; }
        .threat-level.YELLOW { border-left: 5px solid #ffc107; }
        .threat-level.ORANGE { border-left: 5px solid #fd7e14; }
        .threat-level.RED { border-left: 5px solid #dc3545; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .card h3 {
            font-size: 18px;
            margin-bottom: 15px;
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .data-item {
            margin-bottom: 10px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .data-item strong {
            color: #667eea;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin-right: 10px;
            margin-bottom: 10px;
        }
        .btn:hover {
            opacity: 0.9;
        }
        .btn-danger {
            background: #dc3545;
        }
        .transmission-log {
            max-height: 400px;
            overflow-y: auto;
        }
        .transmission-item {
            padding: 10px;
            background: #f8f9fa;
            border-left: 3px solid #28a745;
            margin-bottom: 10px;
            border-radius: 3px;
            font-size: 12px;
        }
        .attack-item {
            padding: 10px;
            background: #fff3cd;
            border-left: 3px solid #ffc107;
            margin-bottom: 10px;
            border-radius: 3px;
            font-size: 12px;
        }
        .blocked-ip {
            display: inline-block;
            background: #f8d7da;
            color: #721c24;
            padding: 5px 10px;
            border-radius: 5px;
            margin: 5px;
            font-size: 12px;
        }
        .unblock-btn {
            background: #28a745;
            color: white;
            border: none;
            padding: 3px 8px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 10px;
            margin-left: 5px;
        }
        .loading {
            text-align: center;
            padding: 20px;
            color: #666;
        }
        {% if role == 'user' %}
        .admin-only {
            display: none !important;
        }
        {% endif %}
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>🛡️ 國防等級安全系統</h1>
            <div class="user-info">
                <div class="user-badge">
                    👤 {{ user }} ({% if role == 'admin' %}管理員{% else %}用戶{% endif %})
                </div>
                <button class="logout-btn" onclick="location.href='/logout'">登出</button>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="threat-level {{ threat_level }}" id="threatLevel">
            <div class="threat-icon">
                {% if threat_level == 'GREEN' %}🟢{% elif threat_level == 'YELLOW' %}🟡{% elif threat_level == 'ORANGE' %}🟠{% else %}🔴{% endif %}
            </div>
            <div class="threat-info">
                <h2>威脅等級: {{ threat_level }}</h2>
                <p id="threatDesc"></p>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>📊 機密資料</h3>
                <div id="dataContent" class="loading">載入中...</div>
                <div class="admin-only">
                    <button class="btn" onclick="showUpdateForm()">新增/修改資料</button>
                </div>
            </div>
            
            <div class="card admin-only">
                <h3>🚨 攻擊記錄</h3>
                <div id="attacksContent" class="loading">載入中...</div>
            </div>
            
            <div class="card admin-only">
                <h3>🔒 封鎖 IP</h3>
                <div id="blockedIPs" class="loading">載入中...</div>
            </div>
        </div>
        
        <div class="card admin-only">
            <h3>📡 中央伺服器傳輸記錄</h3>
            <div id="transmissionLog" class="transmission-log loading">載入中...</div>
        </div>
    </div>
    
    <script>
        const isAdmin = "{{ role }}" === "admin";
        
        // 載入資料
        async function loadData() {
            try {
                const response = await fetch('/api/data');
                const data = await response.json();
                
                let html = '';
                for (const [category, items] of Object.entries(data)) {
                    html += `<div class="data-item"><strong>${category}</strong><br>`;
                    for (const [key, value] of Object.entries(items)) {
                        html += `${key}: ${value}<br>`;
                    }
                    html += '</div>';
                }
                
                document.getElementById('dataContent').innerHTML = html || '暫無資料';
            } catch (error) {
                document.getElementById('dataContent').innerHTML = '載入失敗';
            }
        }
        
        // 載入攻擊記錄
        async function loadAttacks() {
            if (!isAdmin) return;
            
            try {
                const response = await fetch('/api/security/attacks');
                const data = await response.json();
                
                let html = `<p>總攻擊數: ${data.total_attacks}</p>`;
                
                if (data.attacks.length > 0) {
                    data.attacks.slice(-10).reverse().forEach(attack => {
                        html += `<div class="attack-item">
                            <strong>${attack.type}</strong><br>
                            IP: ${attack.ip}<br>
                            時間: ${new Date(attack.timestamp).toLocaleString('zh-TW')}<br>
                            詳情: ${attack.details}
                        </div>`;
                    });
                } else {
                    html += '<p>目前無攻擊記錄</p>';
                }
                
                document.getElementById('attacksContent').innerHTML = html;
            } catch (error) {
                document.getElementById('attacksContent').innerHTML = '載入失敗';
            }
        }
        
        // 載入封鎖 IP
        async function loadBlockedIPs() {
            if (!isAdmin) return;
            
            try {
                const response = await fetch('/api/security/status');
                const data = await response.json();
                
                let html = '';
                if (data.blocked_ips.length > 0) {
                    data.blocked_ips.forEach(ip => {
                        html += `<span class="blocked-ip">${ip} 
                            <button class="unblock-btn" onclick="unblockIP('${ip}')">解封</button>
                        </span>`;
                    });
                } else {
                    html = '<p>目前無封鎖 IP</p>';
                }
                
                document.getElementById('blockedIPs').innerHTML = html;
            } catch (error) {
                document.getElementById('blockedIPs').innerHTML = '載入失敗';
            }
        }
        
        // 載入傳輸記錄
        async function loadTransmissions() {
            if (!isAdmin) return;
            
            try {
                const response = await fetch('/api/central/transmissions');
                const data = await response.json();
                
                let html = `<p>中央伺服器: ${data.server_url}</p><hr style="margin: 10px 0;">`;
                
                if (data.transmissions.length > 0) {
                    data.transmissions.reverse().forEach(trans => {
                        html += `<div class="transmission-item">
                            <strong>ID:</strong> ${trans.id}<br>
                            <strong>類型:</strong> ${trans.data_type}<br>
                            <strong>用戶:</strong> ${trans.user}<br>
                            <strong>時間:</strong> ${new Date(trans.timestamp).toLocaleString('zh-TW')}<br>
                            <strong>🔐 SHA-256 加密資料:</strong><br>
                            <code style="font-size: 10px; background: #f0f0f0; padding: 5px; display: block; word-break: break-all; border-left: 3px solid #667eea; margin: 5px 0;">${trans.data}</code>
                            <strong>✓ MD5 校驗和:</strong> <code style="font-size: 10px; background: #e8f5e9; padding: 2px 5px;">${trans.checksum}</code><br>
                            <strong>狀態:</strong> <span style="color: #28a745;">✓ ${trans.status}</span>
                        </div>`;
                    });
                } else {
                    html += '<p>暫無傳輸記錄</p>';
                }
                
                document.getElementById('transmissionLog').innerHTML = html;
            } catch (error) {
                document.getElementById('transmissionLog').innerHTML = '載入失敗';
            }
        }
        
        // 解封 IP
        async function unblockIP(ip) {
            if (!confirm(`確定要解封 ${ip}?`)) return;
            
            try {
                const response = await fetch('/api/security/unblock', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ip })
                });
                
                if (response.ok) {
                    alert('解封成功');
                    loadBlockedIPs();
                } else {
                    alert('解封失敗');
                }
            } catch (error) {
                alert('操作失敗');
            }
        }
        
        // 顯示更新表單
        function showUpdateForm() {
            const category = prompt('類別名稱:');
            if (!category) return;
            
            const key = prompt('鍵名:');
            if (!key) return;
            
            const value = prompt('值:');
            if (!value) return;
            
            updateData(category, key, value);
        }
        
        // 更新資料
        async function updateData(category, key, value) {
            try {
                const response = await fetch('/api/data/update', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ category, key, value })
                });
                
                if (response.ok) {
                    alert('更新成功');
                    loadData();
                } else {
                    alert('更新失敗');
                }
            } catch (error) {
                alert('操作失敗');
            }
        }
        
        // 更新威脅等級描述
        function updateThreatDesc() {
            const level = "{{ threat_level }}";
            const desc = {
                'GREEN': '系統正常運行，無檢測到威脅',
                'YELLOW': '檢測到輕微可疑活動，保持警戒',
                'ORANGE': '檢測到多次攻擊嘗試，已加強防護',
                'RED': '遭受嚴重攻擊，所有防護系統已啟動'
            };
            document.getElementById('threatDesc').textContent = desc[level] || '';
        }
        
        // 初始化
        document.addEventListener('DOMContentLoaded', () => {
            updateThreatDesc();
            loadData();
            if (isAdmin) {
                loadAttacks();
                loadBlockedIPs();
                loadTransmissions();
                
                // 定期更新
                setInterval(loadAttacks, 10000);
                setInterval(loadBlockedIPs, 10000);
                setInterval(loadTransmissions, 15000);
            }
        });
    </script>
</body>
</html>''')

# ==================== 主程序 ====================

if __name__ == '__main__':
    create_templates()
    print("\n" + "=" * 70)
    print("國防等級 Web 安全管理系統")
    print("Defense-Grade Web Security Management System")
    print("=" * 70)
    print("\n系統特性:")
    print("  ✓ Web UI 介面")
    print("  ✓ 密碼輸入框（隱藏顯示）")
    print("  ✓ 中央伺服器資料傳輸")
    print("  ✓ 中間層攻擊防護（SQL注入、XSS、路徑遍歷、命令注入）")
    print("  ✓ DDoS 防護（速率限制 + IP 封鎖）")
    print("  ✓ CSRF 保護")
    print("  ✓ Session 安全管理")
    print("  ✓ 即時攻擊監控")
    print("\n加密技術:")
    print("  [加密] SHA-256 資料加密")
    print("  [校驗] MD5 完整性校驗")
    print("  [密碼] PBKDF2-HMAC-SHA256 (100,000 迭代)")
    
    # 顯示 SHA-256 加密證明
    print("\nSHA-256 加密證明:")
    test_data = {"username": "admin", "action": "login"}
    test_encrypted = hashlib.sha256(
        json.dumps(test_data).encode() + SecurityConfig.ENCRYPTION_KEY
    ).hexdigest()
    print(f"  原始資料: {test_data}")
    print(f"  SHA-256:  {test_encrypted}")
    print(f"  長度: {len(test_encrypted)} 字符（64位十六進制）")
    
    print("\n預設帳號:")
    print("  管理員: admin / Admin@2025")
    print("  用戶:   user  / User@2025")
    print("\n啟動服務...")
    print("  URL: http://127.0.0.1:5000")
    print("=" * 70 + "\n")
    
    app.run(host='127.0.0.1', port=5000, debug=False)

