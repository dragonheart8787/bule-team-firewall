#!/usr/bin/env python3
"""
診斷版 WAF 代理
專注於找出問題根本原因
"""

import os
import sys
import json
import time
import logging
import urllib.request
import urllib.error
import urllib.parse
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

class DebugWAFHandler(BaseHTTPRequestHandler):
    """診斷版 WAF 處理器"""
    
    def __init__(self, *args, **kwargs):
        # 管理員路徑列表
        self.admin_paths = {'/admin', '/administrator', '/wp-admin', '/phpmyadmin'}
        
        # 統計數據
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'forwarded_requests': 0,
            'start_time': time.time()
        }
        
        super().__init__(*args, **kwargs)
    
    def get_client_ip(self):
        """獲取客戶端 IP"""
        return self.client_address[0]
    
    def do_GET(self):
        """處理 GET 請求"""
        print(f"[DEBUG] 收到 GET 請求: {self.path}")
        
        try:
            # 快速路徑處理
            if self.path == '/healthz':
                self._handle_healthz()
                return
            elif self.path == '/metrics':
                self._handle_metrics()
                return
            
            # 處理一般請求
            self._handle_request('GET')
            
        except Exception as e:
            print(f"[DEBUG] GET 請求處理錯誤: {e}")
            logger.error(f"GET 請求處理錯誤: {e}")
            self._send_error_response(500, "Internal Server Error")
    
    def _handle_healthz(self):
        """處理健康檢查"""
        print("[DEBUG] 處理健康檢查")
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        health_data = {
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "uptime": time.time() - self.stats['start_time']
        }
        self.wfile.write(json.dumps(health_data).encode())
        print("[DEBUG] 健康檢查完成")
    
    def _handle_metrics(self):
        """處理指標查詢"""
        print("[DEBUG] 處理指標查詢")
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        metrics = {
            'total_requests': self.stats['total_requests'],
            'blocked_requests': self.stats['blocked_requests'],
            'forwarded_requests': self.stats['forwarded_requests'],
            'uptime': time.time() - self.stats['start_time']
        }
        self.wfile.write(json.dumps(metrics).encode())
        print("[DEBUG] 指標查詢完成")
    
    def _handle_request(self, method):
        """處理請求 - 診斷版"""
        print(f"[DEBUG] 開始處理請求: {method} {self.path}")
        
        try:
            client_ip = self.get_client_ip()
            print(f"[DEBUG] 客戶端 IP: {client_ip}")
            
            # 更新統計
            self.stats['total_requests'] += 1
            print(f"[DEBUG] 總請求數: {self.stats['total_requests']}")
            
            # 檢查管理員路徑
            if self.path in self.admin_paths:
                print(f"[DEBUG] 檢測到管理員路徑: {self.path}")
                self.stats['blocked_requests'] += 1
                self._send_blocked_response()
                return
            
            print(f"[DEBUG] 路徑 {self.path} 不是管理員路徑，準備轉發")
            
            # 轉發請求
            try:
                self._forward_request(method)
                self.stats['forwarded_requests'] += 1
                print(f"[DEBUG] 請求轉發成功")
                
            except Exception as e:
                print(f"[DEBUG] 轉發請求失敗: {e}")
                logger.error(f"轉發請求失敗: {e}")
                self._send_error_response(502, "Bad Gateway")
            
        except Exception as e:
            print(f"[DEBUG] 請求處理錯誤: {e}")
            logger.error(f"請求處理錯誤: {e}")
            self._send_error_response(500, "Internal Server Error")
    
    def _send_blocked_response(self):
        """發送阻擋響應"""
        print("[DEBUG] 發送阻擋響應")
        self.send_response(403)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response = {
            "error": "Request blocked by WAF",
            "reason": "Admin path detected",
            "path": self.path,
            "timestamp": datetime.now().isoformat()
        }
        self.wfile.write(json.dumps(response).encode())
        print("[DEBUG] 阻擋響應發送完成")
    
    def _send_error_response(self, code, message):
        """發送錯誤響應"""
        print(f"[DEBUG] 發送錯誤響應: {code} {message}")
        self.send_response(code)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(f'<h1>{code} {message}</h1>'.encode())
        print(f"[DEBUG] 錯誤響應發送完成")
    
    def _forward_request(self, method):
        """轉發請求到後端 - 診斷版"""
        print(f"[DEBUG] 開始轉發請求到後端: {method} {self.path}")
        
        try:
            backend_url = f"http://{BACKEND_HOST}:{BACKEND_PORT}{self.path}"
            print(f"[DEBUG] 後端 URL: {backend_url}")
            
            # 準備請求
            req = urllib.request.Request(backend_url, method=method)
            
            # 複製標頭
            for header, value in self.headers.items():
                if header.lower() not in ['host', 'content-length']:
                    req.add_header(header, value)
            
            print(f"[DEBUG] 發送請求到後端...")
            
            # 發送請求
            with urllib.request.urlopen(req, timeout=2) as response:
                print(f"[DEBUG] 後端響應: {response.getcode()}")
                
                self.send_response(response.getcode())
                
                # 複製響應標頭
                for header, value in response.headers.items():
                    if header.lower() not in ['connection', 'transfer-encoding']:
                        self.send_header(header, value)
                
                self.end_headers()
                
                # 複製響應體
                response_data = response.read()
                self.wfile.write(response_data)
                
                print(f"[DEBUG] 響應轉發完成，數據大小: {len(response_data)} bytes")
                
        except urllib.error.HTTPError as e:
            print(f"[DEBUG] 後端 HTTP 錯誤: {e.code} {e.reason}")
            self.send_response(e.code)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(f'<h1>{e.code} {e.reason}</h1>'.encode())
        except Exception as e:
            print(f"[DEBUG] 轉發請求錯誤: {e}")
            logger.error(f"轉發請求錯誤: {e}")
            raise

def run_debug_waf():
    """運行診斷版 WAF"""
    print("啟動診斷版 WAF 代理...")
    print(f"後端: {BACKEND_HOST}:{BACKEND_PORT}")
    print(f"代理端口: {PROXY_PORT}")
    
    server = HTTPServer(('0.0.0.0', PROXY_PORT), DebugWAFHandler)
    print(f"WAF 代理運行在 http://0.0.0.0:{PROXY_PORT}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n停止 WAF 代理...")
        server.shutdown()

if __name__ == "__main__":
    run_debug_waf()




