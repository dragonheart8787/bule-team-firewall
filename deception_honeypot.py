#!/usr/bin/env python3
"""
誘捕/欺敵模組
部署蜜罐網段與欺敵系統
"""

import json
import time
import threading
import socket
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import random
import string

class HoneypotService:
    """蜜罐服務基類"""
    
    def __init__(self, name: str, port: int, service_type: str):
        self.name = name
        self.port = port
        self.service_type = service_type
        self.running = False
        self.server_socket = None
        self.connections = []
        self.attacks_log = []
        self.logger = logging.getLogger(f"honeypot.{name}")
    
    def start(self):
        """啟動蜜罐服務"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.running = True
            
            self.logger.info(f"蜜罐服務 {self.name} 已啟動，監聽端口 {self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    self.logger.info(f"檢測到連接: {address}")
                    
                    # 在新線程中處理連接
                    thread = threading.Thread(
                        target=self.handle_connection,
                        args=(client_socket, address)
                    )
                    thread.daemon = True
                    thread.start()
                    self.connections.append(thread)
                    
                except Exception as e:
                    if self.running:
                        self.logger.error(f"接受連接時發生錯誤: {e}")
                    
        except Exception as e:
            self.logger.error(f"啟動蜜罐服務失敗: {e}")
    
    def stop(self):
        """停止蜜罐服務"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.logger.info(f"蜜罐服務 {self.name} 已停止")
    
    def handle_connection(self, client_socket: socket.socket, address: Tuple[str, int]):
        """處理客戶端連接"""
        try:
            self.log_attack(address, "CONNECTION_ATTEMPT")
            self.interact_with_attacker(client_socket, address)
        except Exception as e:
            self.logger.error(f"處理連接時發生錯誤: {e}")
        finally:
            client_socket.close()
    
    def interact_with_attacker(self, client_socket: socket.socket, address: Tuple[str, int]):
        """與攻擊者互動"""
        # 子類需要實現此方法
        pass
    
    def log_attack(self, address: Tuple[str, int], attack_type: str, details: str = ""):
        """記錄攻擊事件"""
        attack_record = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': address[0],
            'source_port': address[1],
            'attack_type': attack_type,
            'service': self.name,
            'port': self.port,
            'details': details
        }
        
        self.attacks_log.append(attack_record)
        self.logger.warning(f"攻擊檢測: {attack_type} 來自 {address[0]}:{address[1]}")
    
    def get_attack_logs(self) -> List[Dict]:
        """獲取攻擊日誌"""
        return self.attacks_log.copy()

class SSHHoneypot(HoneypotService):
    """SSH蜜罐"""
    
    def __init__(self, port: int = 2222):
        super().__init__("SSH-Honeypot", port, "ssh")
        self.login_attempts = 0
    
    def interact_with_attacker(self, client_socket: socket.socket, address: Tuple[str, int]):
        """模擬SSH服務"""
        try:
            # 發送SSH banner
            banner = "SSH-2.0-OpenSSH_7.4\n"
            client_socket.send(banner.encode())
            
            # 接收數據
            data = client_socket.recv(1024).decode('utf-8', errors='ignore')
            
            if data:
                self.log_attack(address, "SSH_LOGIN_ATTEMPT", data[:100])
                self.login_attempts += 1
                
                # 模擬認證失敗
                error_msg = "Permission denied (publickey,password).\n"
                client_socket.send(error_msg.encode())
                
                # 保持連接一段時間
                time.sleep(random.uniform(1, 3))
                
        except Exception as e:
            self.logger.error(f"SSH蜜罐互動錯誤: {e}")

class HTTPHoneypot(HoneypotService):
    """HTTP蜜罐"""
    
    def __init__(self, port: int = 8080):
        super().__init__("HTTP-Honeypot", port, "http")
        self.request_count = 0
    
    def interact_with_attacker(self, client_socket: socket.socket, address: Tuple[str, int]):
        """模擬HTTP服務"""
        try:
            # 接收HTTP請求
            request = client_socket.recv(4096).decode('utf-8', errors='ignore')
            
            if request:
                self.request_count += 1
                self.log_attack(address, "HTTP_REQUEST", request[:200])
                
                # 解析請求
                lines = request.split('\n')
                if lines:
                    first_line = lines[0]
                    method, path, version = first_line.split(' ', 2)
                    
                    # 模擬不同的響應
                    if '/admin' in path:
                        response = self.generate_admin_page()
                    elif '/wp-admin' in path:
                        response = self.generate_wp_admin_page()
                    elif '/.env' in path:
                        response = self.generate_env_file()
                    else:
                        response = self.generate_default_page()
                    
                    client_socket.send(response.encode())
                
        except Exception as e:
            self.logger.error(f"HTTP蜜罐互動錯誤: {e}")
    
    def generate_default_page(self) -> str:
        """生成默認頁面"""
        return """HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 200

<html>
<head><title>Welcome</title></head>
<body>
<h1>Welcome to our server</h1>
<p>This is a test server.</p>
</body>
</html>"""
    
    def generate_admin_page(self) -> str:
        """生成管理頁面"""
        return """HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 300

<html>
<head><title>Admin Panel</title></head>
<body>
<h1>Admin Panel</h1>
<form method="post" action="/login">
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<input type="submit" value="Login">
</form>
</body>
</html>"""
    
    def generate_wp_admin_page(self) -> str:
        """生成WordPress管理頁面"""
        return """HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 400

<html>
<head><title>WordPress Admin</title></head>
<body>
<h1>WordPress Administration</h1>
<p>Please log in to access the admin area.</p>
<form method="post" action="/wp-login.php">
<input type="text" name="log" placeholder="Username or Email">
<input type="password" name="pwd" placeholder="Password">
<input type="submit" value="Log In">
</form>
</body>
</html>"""
    
    def generate_env_file(self) -> str:
        """生成環境文件"""
        return """HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 100

DB_HOST=localhost
DB_USER=admin
DB_PASS=secret123
API_KEY=abc123def456
SECRET_TOKEN=xyz789"""

class FTPHoneypot(HoneypotService):
    """FTP蜜罐"""
    
    def __init__(self, port: int = 2121):
        super().__init__("FTP-Honeypot", port, "ftp")
        self.login_attempts = 0
    
    def interact_with_attacker(self, client_socket: socket.socket, address: Tuple[str, int]):
        """模擬FTP服務"""
        try:
            # 發送FTP歡迎消息
            welcome = "220 Welcome to FTP server\n"
            client_socket.send(welcome.encode())
            
            # 接收命令
            while True:
                data = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                if not data:
                    break
                
                self.log_attack(address, "FTP_COMMAND", data)
                
                if data.upper().startswith('USER'):
                    client_socket.send("331 Password required\n".encode())
                elif data.upper().startswith('PASS'):
                    client_socket.send("530 Login incorrect\n".encode())
                    self.login_attempts += 1
                elif data.upper().startswith('QUIT'):
                    client_socket.send("221 Goodbye\n".encode())
                    break
                else:
                    client_socket.send("502 Command not implemented\n".encode())
                
        except Exception as e:
            self.logger.error(f"FTP蜜罐互動錯誤: {e}")

class HoneypotManager:
    """蜜罐管理器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.honeypots = {}
        self.running = False
        self.threads = []
    
    def add_honeypot(self, honeypot: HoneypotService):
        """添加蜜罐服務"""
        self.honeypots[honeypot.name] = honeypot
        self.logger.info(f"添加蜜罐服務: {honeypot.name}")
    
    def start_all(self):
        """啟動所有蜜罐"""
        if self.running:
            self.logger.warning("蜜罐系統已在運行中")
            return
        
        self.running = True
        
        for name, honeypot in self.honeypots.items():
            thread = threading.Thread(target=honeypot.start)
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        self.logger.info(f"已啟動 {len(self.honeypots)} 個蜜罐服務")
    
    def stop_all(self):
        """停止所有蜜罐"""
        self.running = False
        
        for honeypot in self.honeypots.values():
            honeypot.stop()
        
        self.logger.info("所有蜜罐服務已停止")
    
    def get_attack_summary(self) -> Dict:
        """獲取攻擊摘要"""
        total_attacks = 0
        attack_types = {}
        source_ips = set()
        
        for honeypot in self.honeypots.values():
            logs = honeypot.get_attack_logs()
            total_attacks += len(logs)
            
            for log in logs:
                attack_type = log['attack_type']
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                source_ips.add(log['source_ip'])
        
        return {
            'total_attacks': total_attacks,
            'attack_types': attack_types,
            'unique_source_ips': len(source_ips),
            'honeypots_count': len(self.honeypots),
            'running': self.running
        }

def test_honeypot_system():
    """測試蜜罐系統"""
    print("測試蜜罐系統...")
    
    # 創建蜜罐管理器
    manager = HoneypotManager()
    
    # 添加各種蜜罐
    manager.add_honeypot(SSHHoneypot(2222))
    manager.add_honeypot(HTTPHoneypot(8081))
    manager.add_honeypot(FTPHoneypot(2121))
    
    # 啟動蜜罐
    print("啟動蜜罐服務...")
    manager.start_all()
    
    # 等待一段時間
    print("等待攻擊檢測...")
    time.sleep(5)
    
    # 顯示攻擊摘要
    summary = manager.get_attack_summary()
    print(f"攻擊摘要: {summary}")
    
    # 停止蜜罐
    print("停止蜜罐服務...")
    manager.stop_all()
    
    print("蜜罐系統測試完成")

if __name__ == "__main__":
    test_honeypot_system()

