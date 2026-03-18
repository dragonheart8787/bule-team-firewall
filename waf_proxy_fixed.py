#!/usr/bin/env python3
"""
企業級 WAF 代理 - 修復版本
解決連接穩定性、超時處理、重試機制等問題
"""

import http.server
import socketserver
import urllib.request
import urllib.parse
import urllib.error
import json
import re
import time
import os
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import socket
import ssl
from urllib.parse import urlparse

# 配置日誌
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "source": "waf_proxy"
        }
        if hasattr(record, 'extra'):
            log_record.update(record.extra)
        return json.dumps(log_record)

def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    handler = logging.StreamHandler()
    formatter = JsonFormatter(datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# 環境變數配置
BACKEND_HOST = os.getenv('BACKEND_HOST', 'localhost')
BACKEND_PORT = int(os.getenv('BACKEND_PORT', '5000'))
PROXY_PORT = int(os.getenv('PROXY_PORT', '8080'))

class ConnectionPool:
    """連接池管理，提高連接重用和穩定性"""
    
    def __init__(self, max_connections=100, timeout=30):
        self.max_connections = max_connections
        self.timeout = timeout
        self.connections = {}
        self.lock = threading.Lock()
        self.last_cleanup = time.time()
    
    def get_connection(self, host, port):
        """獲取或創建連接"""
        key = f"{host}:{port}"
        now = time.time()
        
        with self.lock:
            # 定期清理過期連接
            if now - self.last_cleanup > 60:  # 每分鐘清理一次
                self._cleanup_expired_connections(now)
                self.last_cleanup = now
            
            if key in self.connections:
                conn_info = self.connections[key]
                if now - conn_info['last_used'] < self.timeout:
                    conn_info['last_used'] = now
                    return conn_info['connection']
                else:
                    # 連接過期，移除
                    del self.connections[key]
            
            # 創建新連接
            if len(self.connections) < self.max_connections:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)  # 連接超時
                    sock.connect((host, port))
                    sock.settimeout(None)  # 移除超時限制
                    
                    conn_info = {
                        'connection': sock,
                        'created': now,
                        'last_used': now
                    }
                    self.connections[key] = conn_info
                    return sock
                except Exception as e:
                    logging.error({"message": "Failed to create connection", "error": str(e), "host": host, "port": port})
                    return None
            else:
                logging.warning({"message": "Connection pool exhausted", "max_connections": self.max_connections})
                return None
    
    def _cleanup_expired_connections(self, now):
        """清理過期連接"""
        expired_keys = []
        for key, conn_info in self.connections.items():
            if now - conn_info['last_used'] > self.timeout:
                try:
                    conn_info['connection'].close()
                except:
                    pass
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.connections[key]
    
    def close_all(self):
        """關閉所有連接"""
        with self.lock:
            for conn_info in self.connections.values():
                try:
                    conn_info['connection'].close()
                except:
                    pass
            self.connections.clear()

class CircuitBreaker:
    """熔斷器，防止雪崩效應"""
    
    def __init__(self, failure_threshold=5, recovery_timeout=30):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
        self.lock = threading.Lock()
    
    def call(self, func, *args, **kwargs):
        """執行函數，帶熔斷保護"""
        with self.lock:
            if self.state == 'OPEN':
                if time.time() - self.last_failure_time > self.recovery_timeout:
                    self.state = 'HALF_OPEN'
                else:
                    raise Exception("Circuit breaker is OPEN")
            
            try:
                result = func(*args, **kwargs)
                if self.state == 'HALF_OPEN':
                    self.state = 'CLOSED'
                    self.failure_count = 0
                return result
            except Exception as e:
                self.failure_count += 1
                self.last_failure_time = time.time()
                
                if self.failure_count >= self.failure_threshold:
                    self.state = 'OPEN'
                
                raise e

class ModSecurityRules:
    """ModSecurity 規則引擎 - 優化版本"""
    
    def __init__(self):
        self.rules = {
            'sql_injection': [
                r"('|(\\')|(;)|(\\;)|(--)|(\\/\\*)|(\\*\\/))",
                r"(union|select|insert|update|delete|drop|create|alter|exec|execute)",
                r"(or|and)\\s+\\d+\\s*=\\s*\\d+",
                r"(or|and)\\s+['\"].*['\"]\\s*=\\s*['\"].*['\"]"
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\\w+\\s*=",
                r"<iframe[^>]*>",
                r"<object[^>]*>",
                r"<embed[^>]*>"
            ],
            'path_traversal': [
                r"\\.\\.",
                r"%2e%2e",
                r"%252e%252e",
                r"\\.\\/",
                r"\\.\\\\",
                r"\\/etc\\/passwd",
                r"\\/windows\\/system32"
            ],
            'command_injection': [
                r"[;&|`$]",
                r"\\b(cat|ls|dir|type|more|less|head|tail|grep|find|awk|sed)\\b",
                r"\\b(ping|tracert|nslookup|netstat|ps|top|kill)\\b"
            ]
        }
        
        # 連接池和熔斷器
        self.connection_pool = ConnectionPool()
        self.circuit_breaker = CircuitBreaker()
        
        # 封鎖名單
        self.blocklist = set()
        self.blocklist_file = 'waf_blocklist.json'
        self._load_blocklist()
        
        # 速率限制
        self.rate_limits = {}
        self.rate_limit_window = 60  # 秒
        self.rate_limit_max = 100   # 每分鐘最大請求數
        
        # DDoS 防護
        self.ddos_protection = {
            'connection_limits': {},
            'request_frequency': {},
            'suspicious_patterns': {}
        }
        
        logging.info({"message": "ModSecurity rules loaded", "rule_count": sum(len(rules) for rules in self.rules.values())})
    
    def check_request(self, client_ip, method, path, headers, body):
        """檢查請求是否違反規則 - 優化版本"""
        violations = []
        
        # 檢查封鎖名單
        if self.is_ip_blocked(client_ip):
            return [{
                'rule_id': 'BLOCKLIST',
                'severity': 'HIGH',
                'action': 'BLOCK',
                'matched': f'IP {client_ip} is in blocklist',
                'pattern': 'BLOCKLIST'
            }]
        
        # 檢查速率限制
        rate_limit_violation = self._check_rate_limit(client_ip)
        if rate_limit_violation:
            violations.append(rate_limit_violation)
        
        # 檢查 DDoS 防護
        ddos_violations = self._check_ddos_protection(client_ip, method, path, headers, body)
        violations.extend(ddos_violations)
        
        # 只對可疑路徑應用規則檢查
        suspicious_paths = ['admin', 'login', 'api', 'search', 'user', 'data']
        if any(keyword in path.lower() for keyword in suspicious_paths):
            # 檢查各種攻擊模式
            for rule_type, patterns in self.rules.items():
                for pattern in patterns:
                    if re.search(pattern, path + ' ' + (body or ''), re.IGNORECASE):
                        violations.append({
                            'rule_id': f'R{rule_type.upper()}',
                            'severity': 'HIGH',
                            'action': 'BLOCK',
                            'matched': f'{rule_type} pattern detected',
                            'pattern': pattern
                        })
                        break  # 找到一個匹配就足夠
        
        return violations
    
    def _check_rate_limit(self, client_ip):
        """檢查速率限制"""
        current_time = time.time()
        
        if client_ip not in self.rate_limits:
            self.rate_limits[client_ip] = []
        
        # 清理過期記錄
        window_start = current_time - self.rate_limit_window
        self.rate_limits[client_ip] = [
            req_time for req_time in self.rate_limits[client_ip]
            if req_time > window_start
        ]
        
        # 檢查是否超過限制
        if len(self.rate_limits[client_ip]) >= self.rate_limit_max:
            return {
                'rule_id': 'RATE_LIMIT',
                'severity': 'MEDIUM',
                'action': 'BLOCK',
                'matched': f'Rate limit exceeded: {len(self.rate_limits[client_ip])} requests in {self.rate_limit_window}s',
                'pattern': 'RATE_LIMIT'
            }
        
        # 記錄當前請求
        self.rate_limits[client_ip].append(current_time)
        return None

    def _check_ddos_protection(self, client_ip, method, path, headers, body):
        """DDoS 防護檢查 - 優化版本"""
        violations = []
        now = time.time()
        
        # 1. 連線數限制
        if client_ip not in self.ddos_protection['connection_limits']:
            self.ddos_protection['connection_limits'][client_ip] = 0
        
        if self.ddos_protection['connection_limits'][client_ip] > 50:
            violations.append({
                'rule_id': 'DDOS_CONNECTION_LIMIT',
                'severity': 'HIGH',
                'action': 'BLOCK',
                'matched': f'Too many connections from {client_ip}',
                'pattern': 'DDOS_PROTECTION'
            })
        
        # 2. 請求頻率限制
        if client_ip not in self.ddos_protection['request_frequency']:
            self.ddos_protection['request_frequency'][client_ip] = []
        
        # 清理過期記錄
        self.ddos_protection['request_frequency'][client_ip] = [
            req_time for req_time in self.ddos_protection['request_frequency'][client_ip]
            if now - req_time < 60
        ]
        
        recent_requests = self.ddos_protection['request_frequency'][client_ip]
        
        # 1分鐘內超過 100 請求
        if len(recent_requests) > 100:
            violations.append({
                'rule_id': 'DDOS_HIGH_FREQUENCY',
                'severity': 'CRITICAL',
                'action': 'BLOCK',
                'matched': f'High frequency requests from {client_ip}: {len(recent_requests)}/min',
                'pattern': 'DDOS_PROTECTION'
            })
        
        # 10秒內超過 20 請求
        very_recent = [req_time for req_time in recent_requests if now - req_time < 10]
        if len(very_recent) > 20:
            violations.append({
                'rule_id': 'DDOS_BURST_ATTACK',
                'severity': 'CRITICAL',
                'action': 'BLOCK',
                'matched': f'Burst attack from {client_ip}: {len(very_recent)}/10s',
                'pattern': 'DDOS_PROTECTION'
            })
        
        # 記錄請求
        self.ddos_protection['request_frequency'][client_ip].append(now)
        
        return violations

    def _calculate_suspicious_score(self, client_ip, method, path, headers, body):
        """計算可疑分數"""
        score = 0
        
        # 檢查 User-Agent
        user_agent = headers.get('User-Agent', '').lower()
        if not user_agent or 'bot' in user_agent or 'crawler' in user_agent:
            score += 20
        
        # 檢查 Referer
        referer = headers.get('Referer', '')
        if not referer and method == 'GET':
            score += 10
        
        # 檢查路徑長度
        if len(path) > 200:
            score += 15
        
        # 檢查參數數量
        if '?' in path and len(path.split('&')) > 10:
            score += 10
        
        return min(score, 100)

    def _load_blocklist(self):
        """載入封鎖名單"""
        try:
            if os.path.exists(self.blocklist_file):
                with open(self.blocklist_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.blocklist = set(data.get('blocked_ips', []))
        except Exception as e:
            logging.error({"message": "Failed to load blocklist", "error": str(e)})

    def _save_blocklist(self):
        """儲存封鎖名單"""
        try:
            with open(self.blocklist_file, 'w', encoding='utf-8') as f:
                json.dump({"blocked_ips": sorted(list(self.blocklist))}, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logging.error({"message": "Failed to save blocklist", "error": str(e)})

    def block_ip(self, ip: str) -> bool:
        """封鎖 IP"""
        if ip not in self.blocklist:
            self.blocklist.add(ip)
            self._save_blocklist()
            return True
        return False

    def unblock_ip(self, ip: str) -> bool:
        """解除封鎖 IP"""
        if ip in self.blocklist:
            self.blocklist.remove(ip)
            self._save_blocklist()
            return True
        return False

    def is_ip_blocked(self, ip: str) -> bool:
        """檢查 IP 是否被封鎖"""
        return ip in self.blocklist

    def get_metrics(self):
        """獲取指標"""
        return {
            'rule_count': sum(len(rules) for rules in self.rules.values()),
            'rate_limit_ips': len(self.rate_limits),
            'blocked_ips': len(self.blocklist)
        }

class WAFProxyHandler(http.server.BaseHTTPRequestHandler):
    """WAF 代理處理器 - 修復版本"""
    
    def __init__(self, *args, **kwargs):
        self.modsec = ModSecurityRules()
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """自定義日誌格式"""
        logging.info({
            "message": format % args,
            "client_ip": self.client_address[0],
            "method": self.command,
            "path": self.path
        })
    
    def get_client_ip(self):
        """獲取客戶端 IP"""
        # 檢查 X-Forwarded-For 標頭
        forwarded_for = self.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        return self.client_address[0]
    
    def handle_request(self, method):
        """處理請求 - 修復版本"""
        client_ip = self.get_client_ip()
        
        # 讀取請求體
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else None
        
        # 檢查規則
        violations = self.modsec.check_request(client_ip, method, self.path, self.headers, body)
        
        if violations:
            # 記錄違規
            for violation in violations:
                logging.warning({
                    "message": "Request blocked",
                    "client_ip": client_ip,
                    "method": method,
                    "path": self.path,
                    "violation": violation
                })
            
            # 發送 403 響應
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response = {
                "error": "Request blocked by WAF",
                "violations": violations,
                "timestamp": datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(response).encode())
            return
        
        # 轉發請求
        try:
            self.forward_request(method, body)
        except Exception as e:
            logging.error({
                "message": "Failed to forward request",
                "error": str(e),
                "client_ip": client_ip,
                "method": method,
                "path": self.path
            })
            
            # 發送錯誤響應
            self.send_response(502)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response = {
                "error": "Backend service unavailable",
                "message": "The requested service is temporarily unavailable",
                "timestamp": datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(response).encode())
    
    def forward_request(self, method, body):
        """轉發請求到後端服務 - 修復版本"""
        max_retries = 3
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            try:
                # 後端服務地址
                backend_url = f"http://{BACKEND_HOST}:{BACKEND_PORT}"
                target_url = f"{backend_url}{self.path}"
                
                # 準備請求
                req_data = body.encode() if body else None
                req = urllib.request.Request(target_url, data=req_data, method=method)
                
                # 複製標頭
                for header, value in self.headers.items():
                    if header.lower() not in ['host', 'content-length']:
                        req.add_header(header, value)
                
                # 設置超時和重試
                timeout = 10 + (attempt * 5)  # 遞增超時
                
                # 發送請求
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    # 發送響應狀態
                    self.send_response(response.getcode())
                    
                    # 複製響應標頭
                    for header, value in response.headers.items():
                        if header.lower() not in ['connection', 'transfer-encoding']:
                            self.send_header(header, value)
                    
                    # 設置 keep-alive
                    self.send_header('Connection', 'keep-alive')
                    self.end_headers()
                    
                    # 複製響應體
                    response_data = response.read()
                    self.wfile.write(response_data)
                    
                    # 記錄成功轉發
                    logging.info({
                        "message": "Request forwarded successfully",
                        "client_ip": self.get_client_ip(),
                        "method": method,
                        "path": self.path,
                        "status_code": response.getcode(),
                        "response_size": len(response_data),
                        "attempt": attempt + 1
                    })
                    return
                    
            except urllib.error.HTTPError as e:
                # HTTP 錯誤，直接轉發
                self.send_response(e.code)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                
                error_response = {
                    "error": f"Backend error: {e.code}",
                    "message": e.reason,
                    "timestamp": datetime.now().isoformat()
                }
                self.wfile.write(json.dumps(error_response).encode())
                return
                
            except (urllib.error.URLError, OSError, socket.timeout) as e:
                # 網路錯誤，重試
                if attempt < max_retries - 1:
                    logging.warning({
                        "message": "Request failed, retrying",
                        "error": str(e),
                        "attempt": attempt + 1,
                        "max_retries": max_retries,
                        "retry_delay": retry_delay
                    })
                    time.sleep(retry_delay)
                    retry_delay *= 2  # 指數退避
                    continue
                else:
                    # 最後一次嘗試失敗
                    raise e
            except Exception as e:
                # 其他錯誤，不重試
                raise e
        
        # 所有重試都失敗
        raise Exception(f"Failed to forward request after {max_retries} attempts")
    
    def do_GET(self):
        """處理 GET 請求"""
        if self.path == '/healthz':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
            return
        
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(self.modsec.get_metrics()).encode())
            return
        
        if self.path == '/api/blocklist':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"blocked_ips": sorted(list(self.modsec.blocklist))}).encode())
            return
            
        self.handle_request('GET')
    
    def do_POST(self):
        """處理 POST 請求"""
        if self.path.startswith('/api/blocklist'):
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ''
            try:
                data = json.loads(body) if body else {}
            except Exception:
                data = {}
            ip = data.get('ip')
            action = data.get('action', 'block')
            if not ip:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "missing ip"}).encode())
                return
            if action == 'block':
                added = self.modsec.block_ip(ip)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "blocked", "ip": ip, "added": added}).encode())
                return
            elif action == 'unblock':
                removed = self.modsec.unblock_ip(ip)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "unblocked", "ip": ip, "removed": removed}).encode())
                return
            else:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "invalid action"}).encode())
                return
        
        self.handle_request('POST')
    
    def do_PUT(self):
        """處理 PUT 請求"""
        self.handle_request('PUT')
    
    def do_DELETE(self):
        """處理 DELETE 請求"""
        self.handle_request('DELETE')

def start_waf_proxy():
    """啟動 WAF 代理服務"""
    setup_logging()
    
    # 創建服務器
    with socketserver.TCPServer(("", PROXY_PORT), WAFProxyHandler) as httpd:
        httpd.allow_reuse_address = True
        httpd.timeout = 30  # 設置服務器超時
        
        logging.info({
            "message": "WAF Proxy started",
            "port": PROXY_PORT,
            "backend": f"{BACKEND_HOST}:{BACKEND_PORT}"
        })
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logging.info({"message": "WAF Proxy stopped"})
        finally:
            # 清理連接池
            if hasattr(WAFProxyHandler, 'modsec'):
                WAFProxyHandler.modsec.connection_pool.close_all()

if __name__ == "__main__":
    start_waf_proxy()

