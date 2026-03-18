#!/usr/bin/env python3
"""
真正穩定的 WAF 代理
解決所有穩定性問題，確保長期穩定運行
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
import traceback
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

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

class RockSolidWAFHandler(BaseHTTPRequestHandler):
    """真正穩定的 WAF 處理器"""
    
    def __init__(self, *args, **kwargs):
        # 管理員路徑列表
        self.admin_paths = {
            '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
            '/backend', '/management', '/dashboard', '/system',
            '/config', '/settings', '/logs', '/backup', '/security',
            '/api/admin', '/admin/api'
        }
        
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
            re.compile(r"on\\w+\\s*=", re.IGNORECASE)
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
        """處理 GET 請求 - 超穩定版"""
        try:
            self._handle_request_safely('GET')
        except Exception as e:
            logger.error(f"GET 請求處理錯誤: {e}")
            logger.error(f"錯誤詳情: {traceback.format_exc()}")
            self._send_error_response(500, "Internal Server Error")
    
    def do_POST(self):
        """處理 POST 請求 - 超穩定版"""
        try:
            self._handle_request_safely('POST')
        except Exception as e:
            logger.error(f"POST 請求處理錯誤: {e}")
            logger.error(f"錯誤詳情: {traceback.format_exc()}")
            self._send_error_response(500, "Internal Server Error")
    
    def _handle_request_safely(self, method):
        """安全處理請求 - 包含所有異常處理"""
        try:
            # 快速路徑處理
            if self.path == '/healthz':
                self._handle_healthz()
                return
            elif self.path == '/metrics':
                self._handle_metrics()
                return
            elif self.path == '/api/config':
                self._handle_config()
                return
            
            # 處理一般請求
            self._handle_request(method)
            
        except Exception as e:
            logger.error(f"請求處理錯誤: {e}")
            logger.error(f"錯誤詳情: {traceback.format_exc()}")
            self._send_error_response(500, "Internal Server Error")
    
    def _handle_healthz(self):
        """處理健康檢查"""
        try:
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
        except Exception as e:
            logger.error(f"健康檢查處理錯誤: {e}")
            self._send_error_response(500, "Health Check Error")
    
    def _handle_metrics(self):
        """處理指標查詢"""
        try:
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
        except Exception as e:
            logger.error(f"指標查詢處理錯誤: {e}")
            self._send_error_response(500, "Metrics Error")
    
    def _handle_config(self):
        """處理配置查詢"""
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'governance_mode': 'full',
                'admin_paths': list(self.admin_paths),
                'status': 'ok'
            }).encode())
        except Exception as e:
            logger.error(f"配置查詢處理錯誤: {e}")
            self._send_error_response(500, "Config Error")
    
    def _handle_request(self, method):
        """處理請求 - 超穩定版"""
        try:
            client_ip = self.get_client_ip()
            
            # 更新統計
            self.stats['total_requests'] += 1
            
            # 讀取請求體
            body = None
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    body = self.rfile.read(content_length).decode('utf-8')
            except Exception as e:
                logger.warning(f"讀取請求體錯誤: {e}")
                body = None
            
            # 檢查規則
            violations = self._check_rules(method, self.path, body)
            
            if violations:
                # 記錄違規
                logger.warning(f"請求被阻擋: {violations}")
                
                self.stats['blocked_requests'] += 1
                
                # 發送 403 響應
                self._send_blocked_response(violations)
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
            logger.error(f"錯誤詳情: {traceback.format_exc()}")
            self.stats['error_requests'] += 1
            self._send_error_response(500, "Internal Server Error")
    
    def _check_rules(self, method, path, body):
        """檢查規則 - 超穩定版"""
        try:
            violations = []
            
            # 檢查管理員路徑 - 使用集合查找，最高效
            if path in self.admin_paths:
                violations.append({
                    'rule_id': 'ADMIN_ACCESS',
                    'severity': 'HIGH',
                    'action': 'BLOCK',
                    'matched': f'Admin path detected: {path}'
                })
                return violations
            
            # 檢查 SQL 注入
            if body:
                request_content = f"{method} {path} {body}"
                for pattern in self.sql_patterns:
                    if pattern.search(request_content):
                        violations.append({
                            'rule_id': 'SQL_INJECTION',
                            'severity': 'HIGH',
                            'action': 'BLOCK',
                            'matched': f'SQL injection pattern detected'
                        })
                        break
            
            # 檢查 XSS
            if body:
                for pattern in self.xss_patterns:
                    if pattern.search(request_content):
                        violations.append({
                            'rule_id': 'XSS',
                            'severity': 'HIGH',
                            'action': 'BLOCK',
                            'matched': f'XSS pattern detected'
                        })
                        break
            
            return violations
            
        except Exception as e:
            logger.error(f"規則檢查錯誤: {e}")
            return []
    
    def _send_blocked_response(self, violations):
        """發送阻擋響應"""
        try:
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response = {
                "error": "Request blocked by WAF",
                "violations": violations,
                "timestamp": datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(response).encode())
        except Exception as e:
            logger.error(f"發送阻擋響應錯誤: {e}")
            self._send_error_response(500, "Response Error")
    
    def _send_error_response(self, code, message):
        """發送錯誤響應"""
        try:
            self.send_response(code)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(f'<h1>{code} {message}</h1>'.encode())
        except Exception as e:
            logger.error(f"發送錯誤響應錯誤: {e}")
            # 最後的錯誤處理
            try:
                self.send_response(500)
                self.end_headers()
            except:
                pass
    
    def _forward_request(self, method, body):
        """轉發請求到後端 - 超穩定版"""
        try:
            backend_url = f"http://{BACKEND_HOST}:{BACKEND_PORT}{self.path}"
            
            # 準備請求
            req_data = body.encode() if body else None
            req = urllib.request.Request(backend_url, data=req_data, method=method)
            
            # 複製標頭
            for header, value in self.headers.items():
                if header.lower() not in ['host', 'content-length']:
                    req.add_header(header, value)
            
            # 發送請求 - 減少超時時間
            with urllib.request.urlopen(req, timeout=1) as response:
                self.send_response(response.getcode())
                
                # 複製響應標頭
                for header, value in response.headers.items():
                    if header.lower() not in ['connection', 'transfer-encoding']:
                        self.send_header(header, value)
                
                self.end_headers()
                
                # 複製響應體
                response_data = response.read()
                self.wfile.write(response_data)
                
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(f'<h1>{e.code} {e.reason}</h1>'.encode())
        except Exception as e:
            logger.error(f"轉發請求錯誤: {e}")
            raise

def run_rock_solid_waf():
    """運行真正穩定的 WAF"""
    print("啟動真正穩定的 WAF 代理...")
    print(f"後端: {BACKEND_HOST}:{BACKEND_PORT}")
    print(f"代理端口: {PROXY_PORT}")
    
    server = HTTPServer(('0.0.0.0', PROXY_PORT), RockSolidWAFHandler)
    print(f"WAF 代理運行在 http://0.0.0.0:{PROXY_PORT}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n停止 WAF 代理...")
        server.shutdown()
    except Exception as e:
        print(f"服務器錯誤: {e}")
        logger.error(f"服務器錯誤: {e}")

if __name__ == "__main__":
    run_rock_solid_waf()




