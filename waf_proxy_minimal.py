#!/usr/bin/env python3
"""
最簡單的 WAF 代理
專注於找出問題根本原因
"""

import os
import sys
import json
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

# 環境變數
BACKEND_HOST = os.getenv('BACKEND_HOST', 'localhost')
BACKEND_PORT = int(os.getenv('BACKEND_PORT', '5000'))
PROXY_PORT = int(os.getenv('PROXY_PORT', '8080'))

class MinimalWAFHandler(BaseHTTPRequestHandler):
    """最簡單的 WAF 處理器"""
    
    def __init__(self, *args, **kwargs):
        # 管理員路徑列表
        self.admin_paths = {'/admin', '/administrator', '/wp-admin', '/phpmyadmin'}
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """處理 GET 請求 - 最簡單版"""
        print(f"[MINIMAL] 收到 GET 請求: {self.path}")
        
        try:
            # 健康檢查
            if self.path == '/healthz':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok"}).encode())
                print("[MINIMAL] 健康檢查完成")
                return
            
            # 檢查管理員路徑
            if self.path in self.admin_paths:
                print(f"[MINIMAL] 檢測到管理員路徑: {self.path}")
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": "Request blocked by WAF",
                    "reason": "Admin path detected"
                }).encode())
                print("[MINIMAL] 管理員路徑阻擋完成")
                return
            
            # 轉發到後端
            print(f"[MINIMAL] 轉發請求到後端: {self.path}")
            self._forward_to_backend()
            print("[MINIMAL] 轉發完成")
            
        except Exception as e:
            print(f"[MINIMAL] 錯誤: {e}")
            self.send_response(500)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(f'<h1>500 Error: {e}</h1>'.encode())
    
    def _forward_to_backend(self):
        """轉發到後端 - 最簡單版"""
        try:
            import urllib.request
            
            backend_url = f"http://{BACKEND_HOST}:{BACKEND_PORT}{self.path}"
            print(f"[MINIMAL] 後端 URL: {backend_url}")
            
            # 發送請求
            with urllib.request.urlopen(backend_url, timeout=2) as response:
                print(f"[MINIMAL] 後端響應: {response.getcode()}")
                
                # 複製響應
                self.send_response(response.getcode())
                
                # 複製標頭
                for header, value in response.headers.items():
                    if header.lower() not in ['connection', 'transfer-encoding']:
                        self.send_header(header, value)
                
                self.end_headers()
                
                # 複製數據
                data = response.read()
                self.wfile.write(data)
                print(f"[MINIMAL] 數據複製完成: {len(data)} bytes")
                
        except Exception as e:
            print(f"[MINIMAL] 轉發錯誤: {e}")
            self.send_response(502)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(f'<h1>502 Bad Gateway: {e}</h1>'.encode())

def run_minimal_waf():
    """運行最簡單的 WAF"""
    print("啟動最簡單的 WAF 代理...")
    print(f"後端: {BACKEND_HOST}:{BACKEND_PORT}")
    print(f"代理端口: {PROXY_PORT}")
    
    try:
        server = HTTPServer(('0.0.0.0', PROXY_PORT), MinimalWAFHandler)
        print(f"WAF 代理運行在 http://0.0.0.0:{PROXY_PORT}")
        server.serve_forever()
    except Exception as e:
        print(f"服務器錯誤: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    run_minimal_waf()




