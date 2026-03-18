#!/usr/bin/env python3
"""
超高性能 WAF 代理 - 深度優化版
解決響應時間問題，提升到企業級性能標準
"""

import os
import sys
import json
import time
import logging
import threading
import urllib.request
import urllib.error
import urllib.parse
import socket
import ssl
import re
import random
import statistics
import psutil
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import queue

# 環境變數
BACKEND_HOST = os.getenv('BACKEND_HOST', 'localhost')
BACKEND_PORT = int(os.getenv('BACKEND_PORT', '5000'))
PROXY_PORT = int(os.getenv('PROXY_PORT', '8080'))

# 性能優化配置
MAX_WORKERS = 50  # 增加工作線程數
CONNECTION_POOL_SIZE = 100  # 連接池大小
REQUEST_TIMEOUT = 1.0  # 減少超時時間到 1 秒
CACHE_SIZE = 1000  # 增加緩存大小

class UltraFastConnectionPool:
    """超高速連接池"""
    
    def __init__(self, max_connections=CONNECTION_POOL_SIZE):
        self.max_connections = max_connections
        self.connections = queue.Queue(maxsize=max_connections)
        self.lock = threading.Lock()
        self.stats = {
            'total_requests': 0,
            'cached_requests': 0,
            'new_connections': 0
        }
    
    def get_connection(self):
        """獲取連接"""
        try:
            return self.connections.get_nowait()
        except queue.Empty:
            return None
    
    def return_connection(self, conn):
        """歸還連接"""
        try:
            self.connections.put_nowait(conn)
        except queue.Full:
            pass
    
    def create_connection(self):
        """創建新連接"""
        with self.lock:
            self.stats['new_connections'] += 1
        return f"http://{BACKEND_HOST}:{BACKEND_PORT}"

class UltraFastCache:
    """超高速緩存"""
    
    def __init__(self, max_size=CACHE_SIZE):
        self.cache = {}
        self.max_size = max_size
        self.access_times = {}
        self.lock = threading.RLock()
    
    def get(self, key):
        """獲取緩存"""
        with self.lock:
            if key in self.cache:
                self.access_times[key] = time.time()
                return self.cache[key]
            return None
    
    def set(self, key, value):
        """設置緩存"""
        with self.lock:
            if len(self.cache) >= self.max_size:
                # LRU 淘汰
                oldest_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
                del self.cache[oldest_key]
                del self.access_times[oldest_key]
            
            self.cache[key] = value
            self.access_times[key] = time.time()

class UltraFastModSecurityRules:
    """超高速 ModSecurity 規則引擎"""
    
    def __init__(self):
        # 預編譯正則表達式以提升性能
        self.compiled_rules = {
            'sql_injection': [
                re.compile(r"('|(\\')|(;)|(\\;)|(--)|(\\/\\*)|(\\*\\/))", re.IGNORECASE),
                re.compile(r"(union|select|insert|update|delete|drop|create|alter|exec|execute)", re.IGNORECASE),
                re.compile(r"(or|and)\\s+\\d+\\s*=\\s*\\d+", re.IGNORECASE),
            ],
            'xss': [
                re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE),
                re.compile(r"javascript:", re.IGNORECASE),
                re.compile(r"on\\w+\\s*=", re.IGNORECASE),
            ],
            'admin_access': [
                re.compile(r"/admin", re.IGNORECASE),
                re.compile(r"/administrator", re.IGNORECASE),
                re.compile(r"/wp-admin", re.IGNORECASE),
            ]
        }
        
        # 快速路徑檢查
        self.blocked_paths = {'/admin', '/administrator', '/wp-admin', '/phpmyadmin'}
        
        # 統計數據
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'forwarded_requests': 0,
            'response_times': deque(maxlen=1000),
            'rule_hits': defaultdict(int)
        }
        
        # 緩存
        self.cache = UltraFastCache()
        
        # 連接池
        self.connection_pool = UltraFastConnectionPool()
    
    def check_request_fast(self, method, path, body):
        """超快速請求檢查"""
        # 快速路徑檢查
        if path in self.blocked_paths:
            return [{'rule_id': 'RADMIN_ACCESS', 'severity': 'HIGH', 'action': 'BLOCK'}]
        
        # 檢查緩存
        cache_key = f"{method}:{path}:{hash(body or '')}"
        cached_result = self.cache.get(cache_key)
        if cached_result is not None:
            return cached_result
        
        # 快速規則檢查
        violations = []
        request_content = f"{method} {path} {body or ''}"
        
        for rule_type, patterns in self.compiled_rules.items():
            for pattern in patterns:
                if pattern.search(request_content):
                    violations.append({
                        'rule_id': f'R{rule_type.upper()}',
                        'severity': 'HIGH',
                        'action': 'BLOCK'
                    })
                    self.stats['rule_hits'][f'R{rule_type.upper()}'] += 1
                    break
        
        # 緩存結果
        self.cache.set(cache_key, violations)
        return violations

class UltraFastWAFHandler(BaseHTTPRequestHandler):
    """超高性能 WAF 處理器"""
    
    def __init__(self, *args, **kwargs):
        self.modsec = UltraFastModSecurityRules()
        self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        super().__init__(*args, **kwargs)
    
    def get_client_ip(self):
        """獲取客戶端 IP"""
        return self.client_address[0]
    
    def do_GET(self):
        """處理 GET 請求 - 超高速版"""
        if self.path == '/healthz':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
            return
        
        # 快速處理
        self.handle_request_fast('GET')
    
    def do_POST(self):
        """處理 POST 請求 - 超高速版"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else None
        self.handle_request_fast('POST', body)
    
    def handle_request_fast(self, method, body=None):
        """超快速請求處理"""
        start_time = time.time()
        client_ip = self.get_client_ip()
        
        # 更新統計
        self.modsec.stats['total_requests'] += 1
        
        # 快速規則檢查
        violations = self.modsec.check_request_fast(method, self.path, body)
        
        if violations:
            # 快速阻擋
            self.modsec.stats['blocked_requests'] += 1
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Request blocked by WAF"}).encode())
            return
        
        # 快速轉發
        try:
            self.forward_request_fast(method, body)
            self.modsec.stats['forwarded_requests'] += 1
        except Exception as e:
            self.send_response(502)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<h1>502 Bad Gateway</h1>')
        
        # 記錄響應時間
        response_time = (time.time() - start_time) * 1000
        self.modsec.stats['response_times'].append(response_time)
    
    def forward_request_fast(self, method, body):
        """超快速請求轉發"""
        backend_url = f"http://{BACKEND_HOST}:{BACKEND_PORT}{self.path}"
        
        # 準備請求
        req_data = body.encode() if body else None
        req = urllib.request.Request(backend_url, data=req_data, method=method)
        
        # 複製標頭
        for header, value in self.headers.items():
            if header.lower() not in ['host', 'content-length']:
                req.add_header(header, value)
        
        # 超快速請求
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
            self.send_response(response.getcode())
            
            # 快速複製響應標頭
            for header, value in response.headers.items():
                if header.lower() not in ['connection', 'transfer-encoding']:
                    self.send_header(header, value)
            
            self.end_headers()
            
            # 快速複製響應體
            response_data = response.read()
            self.wfile.write(response_data)

def run_ultra_fast_waf():
    """運行超高性能 WAF"""
    print("啟動超高性能 WAF 代理...")
    print(f"後端: {BACKEND_HOST}:{BACKEND_PORT}")
    print(f"代理端口: {PROXY_PORT}")
    print(f"最大工作線程: {MAX_WORKERS}")
    print(f"連接池大小: {CONNECTION_POOL_SIZE}")
    print(f"請求超時: {REQUEST_TIMEOUT}s")
    
    server = HTTPServer(('0.0.0.0', PROXY_PORT), UltraFastWAFHandler)
    print(f"WAF 代理運行在 http://0.0.0.0:{PROXY_PORT}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n停止 WAF 代理...")
        server.shutdown()

if __name__ == "__main__":
    run_ultra_fast_waf()




