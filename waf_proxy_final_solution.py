#!/usr/bin/env python3
"""
最終解決方案 WAF 代理
使用不同的架構解決穩定性問題
"""

import os
import sys
import json
import time
import logging
import urllib.request
import urllib.error
import urllib.parse
import re
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
from threading import Lock

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except Exception:
    requests = None

# 環境變數
BACKEND_HOST = os.getenv('BACKEND_HOST', 'localhost')
BACKEND_PORT = int(os.getenv('BACKEND_PORT', '5000'))
PROXY_PORT = int(os.getenv('PROXY_PORT', '8080'))

# 配置日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 全域配置（可由 /api/config 動態更新）
CONFIG_LOCK: Lock = Lock()
CONFIG = {
    'governance_mode': 'full',
    'backend_connect_timeout': float(os.getenv('BACKEND_CONNECT_TIMEOUT', '0.5')),
    'backend_read_timeout': float(os.getenv('BACKEND_READ_TIMEOUT', '2.0')),
    'admin_paths': {
        '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
        '/backend', '/management', '/dashboard', '/system',
        '/config', '/settings', '/logs', '/backup', '/security',
        '/api/admin', '/admin/api'
    }
}

# 後端連線池（requests Session）
SESSION = None
def _init_session_if_needed():
    global SESSION
    if SESSION is None and requests is not None:
        s = requests.Session()
        # 合理的連線池與重試策略（針對短暫網路抖動）
        retries = Retry(total=2, backoff_factor=0.1, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(pool_connections=50, pool_maxsize=200, max_retries=retries)
        s.mount('http://', adapter)
        s.mount('https://', adapter)
        SESSION = s

class FinalSolutionWAFHandler(BaseHTTPRequestHandler):
    """最終解決方案 WAF 處理器"""
    
    def __init__(self, *args, **kwargs):
        # 初始化連線池
        _init_session_if_needed()
        
        # SQL 注入模式
        self.sql_patterns = [
            re.compile(r"('|(\\')|(;)|(\\;)|(--)|(\\/\\*)|(\\*\\/))", re.IGNORECASE),
            re.compile(r"(union|select|insert|update|delete|drop|create|alter|exec|execute)", re.IGNORECASE),
            re.compile(r"(or|and)\\s+\\d+\\s*=\\s*\\d+", re.IGNORECASE)
        ]
        
        # XSS 模式
        self.xss_patterns = [
            re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"on\w+\s*=", re.IGNORECASE)
        ]
        
        # 路徑遍歷模式
        self.path_traversal_patterns = [
            re.compile(r"\.\./", re.IGNORECASE),
            re.compile(r"\.\./", re.IGNORECASE),
            re.compile(r"\.\.\\", re.IGNORECASE),
            re.compile(r"%2e%2e%2f", re.IGNORECASE),
            re.compile(r"%2e%2e/", re.IGNORECASE),
            re.compile(r"\.\.%2f", re.IGNORECASE),
            re.compile(r"%252e%252e%252f", re.IGNORECASE)
        ]
        
        # 命令注入模式
        self.command_injection_patterns = [
            re.compile(r";\s*(ls|cat|whoami|id|ping|dir|type|wget|curl)", re.IGNORECASE),
            re.compile(r"\|\s*(ls|cat|whoami|id|ping|dir|type|wget|curl)", re.IGNORECASE),
            re.compile(r"`.*?`", re.IGNORECASE),
            re.compile(r"\$\(.*?\)", re.IGNORECASE)
        ]
        
        # 統計數據
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'forwarded_requests': 0,
            'error_requests': 0,
            'start_time': time.time()
        }
        
        super().__init__(*args, **kwargs)
    
    def get_client_ip(self):
        """獲取客戶端 IP"""
        try:
            return self.client_address[0]
        except:
            return 'unknown'
    
    def do_GET(self):
        """處理 GET 請求"""
        self._handle_request('GET')
    
    def do_POST(self):
        """處理 POST 請求"""
        self._handle_request('POST')
    
    def _handle_request(self, method):
        """處理請求 - 最終解決方案"""
        try:
            # 快速路徑處理
            if self.path == '/healthz':
                self._handle_healthz()
                return
            elif self.path == '/metrics':
                self._handle_metrics()
                return
            elif self.path.startswith('/api/config'):
                if self.command == 'GET':
                    self._handle_config_get()
                elif self.command == 'POST':
                    self._handle_config_post()
                else:
                    self._send_error_response(405, 'Method Not Allowed')
                return
            
            # 更新統計
            self.stats['total_requests'] += 1
            
            # 檢查管理員路徑
            normalized_path = self._normalized_path(self.path)
            with CONFIG_LOCK:
                admin_paths = CONFIG['admin_paths']
            if normalized_path in admin_paths:
                self.stats['blocked_requests'] += 1
                self._send_blocked_response()
                return
            
            # 讀取請求體
            body = None
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    # 讀取請求體，忽略解碼錯誤避免崩潰
                    raw = self.rfile.read(content_length)
                    try:
                        body = raw.decode('utf-8', errors='ignore')
                    except Exception:
                        body = None
            except Exception:
                body = None
            
            # 檢查其他規則（包含 URL 查詢參數和請求體）
            if self._check_rules(method, self.path, body):
                self.stats['blocked_requests'] += 1
                self._send_blocked_response()
                return
            
            # 轉發請求
            try:
                self._forward_request(method, body)
                self.stats['forwarded_requests'] += 1
            except Exception as e:
                logger.error(f"轉發請求失敗: {e}")
                self.stats['error_requests'] += 1
                self._send_error_response(502, "Bad Gateway")
            
        except Exception as e:
            logger.error(f"請求處理錯誤: {e}")
            self.stats['error_requests'] += 1
            self._send_error_response(500, "Internal Server Error")
    
    def _handle_healthz(self):
        """處理健康檢查"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        health_data = {
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "uptime": time.time() - self.stats['start_time'],
            "total_requests": self.stats['total_requests'],
            "blocked_requests": self.stats['blocked_requests'],
            "forwarded_requests": self.stats['forwarded_requests'],
            "error_requests": self.stats['error_requests']
        }
        self.wfile.write(json.dumps(health_data).encode())
    
    def _handle_metrics(self):
        """處理指標查詢"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        metrics = {
            'total_requests': self.stats['total_requests'],
            'blocked_requests': self.stats['blocked_requests'],
            'forwarded_requests': self.stats['forwarded_requests'],
            'error_requests': self.stats['error_requests'],
            'block_rate': (self.stats['blocked_requests'] / max(1, self.stats['total_requests'])) * 100.0,
            'error_rate': (self.stats['error_requests'] / max(1, self.stats['total_requests'])) * 100.0,
            'uptime': time.time() - self.stats['start_time']
        }
        self.wfile.write(json.dumps(metrics).encode())
    
    def _handle_config_get(self):
        """讀取當前配置"""
        with CONFIG_LOCK:
            cfg = {
                'governance_mode': CONFIG['governance_mode'],
                'admin_paths': sorted(list(CONFIG['admin_paths'])),
                'backend_connect_timeout': CONFIG['backend_connect_timeout'],
                'backend_read_timeout': CONFIG['backend_read_timeout'],
                'status': 'ok'
            }
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        try:
            self.wfile.write(json.dumps(cfg).encode())
        except BrokenPipeError:
            pass

    def _handle_config_post(self):
        """更新配置（動態）"""
        try:
            length = int(self.headers.get('Content-Length', 0))
            payload = {}
            if length > 0:
                data = self.rfile.read(length)
                try:
                    payload = json.loads(data.decode('utf-8', errors='ignore'))
                except Exception:
                    payload = {}

            updated = {}
            with CONFIG_LOCK:
                if 'governance_mode' in payload:
                    CONFIG['governance_mode'] = str(payload['governance_mode'])
                    updated['governance_mode'] = CONFIG['governance_mode']
                if 'backend_connect_timeout' in payload:
                    CONFIG['backend_connect_timeout'] = float(payload['backend_connect_timeout'])
                    updated['backend_connect_timeout'] = CONFIG['backend_connect_timeout']
                if 'backend_read_timeout' in payload:
                    CONFIG['backend_read_timeout'] = float(payload['backend_read_timeout'])
                    updated['backend_read_timeout'] = CONFIG['backend_read_timeout']
                if 'admin_paths' in payload and isinstance(payload['admin_paths'], list):
                    CONFIG['admin_paths'] = set(map(str, payload['admin_paths']))
                    updated['admin_paths'] = sorted(list(CONFIG['admin_paths']))

            resp = {'status': 'ok', 'updated': updated}
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            try:
                self.wfile.write(json.dumps(resp).encode())
            except BrokenPipeError:
                pass
        except Exception as e:
            logger.error(f"更新配置錯誤: {e}")
            self._send_error_response(400, 'Bad Request')

    def _normalized_path(self, path: str) -> str:
        # 去除查詢字串，僅比對純路徑
        try:
            return path.split('?', 1)[0]
        except Exception:
            return path
    
    def _check_rules(self, method, path, body):
        """檢查規則 - 檢查完整請求（URL + Query + Body）"""
        try:
            # 解析查詢參數
            from urllib.parse import unquote
            
            # URL 解碼以檢測編碼的攻擊
            decoded_path = unquote(path)
            
            # 構建完整的請求內容（包含方法、路徑、查詢參數、請求體）
            request_content = f"{method} {decoded_path}"
            if body:
                request_content += f" {body}"
            
            # 檢查 SQL 注入
            for pattern in self.sql_patterns:
                if pattern.search(request_content):
                    logger.info(f"SQL injection detected: {request_content[:100]}")
                    return True
            
            # 檢查 XSS
            for pattern in self.xss_patterns:
                if pattern.search(request_content):
                    logger.info(f"XSS attack detected: {request_content[:100]}")
                    return True
            
            # 檢查路徑遍歷
            for pattern in self.path_traversal_patterns:
                if pattern.search(request_content):
                    logger.info(f"Path traversal detected: {request_content[:100]}")
                    return True
            
            # 檢查命令注入
            for pattern in self.command_injection_patterns:
                if pattern.search(request_content):
                    logger.info(f"Command injection detected: {request_content[:100]}")
                    return True
            
            return False
        except Exception as e:
            logger.error(f"規則檢查錯誤: {e}")
            return False
    
    def _send_blocked_response(self):
        """發送阻擋響應"""
        self.send_response(403)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response = {
            "error": "Request blocked by WAF",
            "reason": "Security rule violation",
            "path": self.path,
            "timestamp": datetime.now().isoformat()
        }
        self.wfile.write(json.dumps(response).encode())
    
    def _send_error_response(self, code, message):
        """發送錯誤響應"""
        self.send_response(code)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        try:
            self.wfile.write(f'<h1>{code} {message}</h1>'.encode())
        except BrokenPipeError:
            pass
    
    def _forward_request(self, method, body):
        """轉發請求到後端"""
        try:
            backend_url = f"http://{BACKEND_HOST}:{BACKEND_PORT}{self.path}"

            # 準備標頭（過濾 Host/Content-Length 由 requests 自行處理）
            headers = {k: v for k, v in self.headers.items() if k.lower() not in ['host', 'content-length', 'connection']}

            # 超時設定
            with CONFIG_LOCK:
                connect_to = CONFIG['backend_connect_timeout']
                read_to = CONFIG['backend_read_timeout']
            timeout = (connect_to, read_to)

            if SESSION is None or requests is None:
                # 後備路徑：維持原 urllib，超時放寬以避免誤殺
                req_data = body.encode() if body else None
                req = urllib.request.Request(backend_url, data=req_data, method=method)
                for hk, hv in headers.items():
                    req.add_header(hk, hv)
                with urllib.request.urlopen(req, timeout=read_to) as resp:
                    self.send_response(resp.getcode())
                    for hk, hv in resp.headers.items():
                        if hk.lower() not in ['connection', 'transfer-encoding']:
                            self.send_header(hk, hv)
                    self.end_headers()
                    try:
                        self.wfile.write(resp.read())
                    except BrokenPipeError:
                        pass
                return

            # 使用連線池請求
            resp = SESSION.request(method=method, url=backend_url, headers=headers, data=(body.encode() if body else None), timeout=timeout, allow_redirects=False)
            self.send_response(resp.status_code)
            for hk, hv in resp.headers.items():
                if hk.lower() not in ['connection', 'transfer-encoding']:
                    self.send_header(hk, hv)
            
            # 添加安全標頭
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('X-XSS-Protection', '1; mode=block')
            self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
            self.send_header('Content-Security-Policy', "default-src 'self'")
            
            # 明確關閉連線到客戶端，避免 Windows 下半開連線殘留
            self.send_header('Connection', 'close')
            self.end_headers()
            try:
                self.wfile.write(resp.content)
            except BrokenPipeError:
                pass
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            try:
                self.wfile.write(f'<h1>{e.code} {e.reason}</h1>'.encode())
            except BrokenPipeError:
                pass
        except Exception as e:
            logger.error(f"轉發請求錯誤: {e}")
            raise

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """多線程 HTTP 服務器"""
    daemon_threads = True
    allow_reuse_address = True

def run_final_solution_waf():
    """運行最終解決方案 WAF"""
    print("啟動最終解決方案 WAF 代理...")
    print(f"後端: {BACKEND_HOST}:{BACKEND_PORT}")
    print(f"代理端口: {PROXY_PORT}")
    
    try:
        server = ThreadedHTTPServer(('0.0.0.0', PROXY_PORT), FinalSolutionWAFHandler)
        print(f"WAF 代理運行在 http://0.0.0.0:{PROXY_PORT}")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n停止 WAF 代理...")
        server.shutdown()
    except Exception as e:
        print(f"服務器錯誤: {e}")
        logger.error(f"服務器錯誤: {e}")

if __name__ == "__main__":
    run_final_solution_waf()
