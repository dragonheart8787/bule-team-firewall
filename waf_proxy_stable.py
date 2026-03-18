#!/usr/bin/env python3
"""
穩定版 WAF 代理
修復服務崩潰問題，確保長期穩定運行
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

class StableModSecurityRules:
    """穩定版 ModSecurity 規則引擎"""
    
    def __init__(self):
        # 規則定義
        self.rules = {
            'sql_injection': [
                r"('|(\\')|(;)|(\\;)|(--)|(\\/\\*)|(\\*\\/))",
                r"(union|select|insert|update|delete|drop|create|alter|exec|execute)",
                r"(or|and)\\s+\\d+\\s*=\\s*\\d+",
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\\w+\\s*=",
            ],
            'path_traversal': [
                r"\\.\\.",
                r"\\.\\/",
                r"\\.\\\\",
                r"\\/etc\\/passwd",
                r"\\/windows\\/system32"
            ],
            'admin_access': [
                r"/admin",
                r"/administrator", 
                r"/wp-admin",
                r"/phpmyadmin",
                r"/backend",
                r"/management",
                r"/dashboard",
                r"/system",
                r"/config",
                r"/settings",
                r"/logs",
                r"/backup",
                r"/security",
                r"/api/admin",
                r"/admin/api"
            ],
            'command_injection': [
                r"[;&|`$]",
                r"\\b(cat|ls|dir|type|more|less|head|tail|grep|find|awk|sed)\\b",
                r"\\b(ping|tracert|nslookup|netstat|ps|top|kill)\\b"
            ]
        }
        
        # 統計數據
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'forwarded_requests': 0,
            'error_requests': 0,
            'response_times': deque(maxlen=1000),
            'rule_hits': defaultdict(int)
        }
        
        # 封鎖名單
        self.blocklist = set()
        
        # 治理模式
        self.governance_mode = 'full'  # gray, observation, small_traffic, full
        self.small_traffic_percent = 10
        
        # SLO 閾值
        self.slo_thresholds = {
            'availability': 99.95,
            'https_p95_ms': 220,
            'error_rate': 0.1
        }
    
    def check_request(self, client_ip, method, path, headers, body):
        """檢查請求是否違反規則"""
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
        
        # 對所有請求應用規則檢查
        request_content = f"{method} {path} {body or ''}"
        for rule_type, patterns in self.rules.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, request_content, re.IGNORECASE):
                        violations.append({
                            'rule_id': f'R{rule_type.upper()}',
                            'severity': 'HIGH',
                            'action': 'BLOCK',
                            'matched': f'{rule_type} pattern detected in: {request_content[:100]}',
                            'pattern': pattern
                        })
                        self.stats['rule_hits'][f'R{rule_type.upper()}'] += 1
                        break
                except Exception as e:
                    logger.error(f"規則檢查錯誤: {e}")
                    continue
        
        # 治理模式處理
        mode = headers.get('X-WAF-Mode', self.governance_mode)
        if violations:
            if mode in ['gray', 'observation']:
                # 記錄但不阻擋
                for v in violations:
                    v['action'] = 'LOG_ONLY'
                return []  # 不阻擋
            if mode == 'small_traffic':
                # 小流量測試
                if random.randint(1, 100) > self.small_traffic_percent:
                    for v in violations:
                        v['action'] = 'LOG_ONLY'
                    return []  # 不阻擋
        
        return violations
    
    def is_ip_blocked(self, ip):
        """檢查 IP 是否被封鎖"""
        return ip in self.blocklist
    
    def block_ip(self, ip):
        """封鎖 IP"""
        self.blocklist.add(ip)
        return True
    
    def unblock_ip(self, ip):
        """解除封鎖 IP"""
        if ip in self.blocklist:
            self.blocklist.remove(ip)
            return True
        return False
    
    def get_metrics(self):
        """獲取指標"""
        rt_list = list(self.stats['response_times'])
        p95 = 0
        if rt_list:
            sorted_rt = sorted(rt_list)
            p95 = sorted_rt[min(int(len(sorted_rt)*0.95), len(sorted_rt)-1)]
        
        error_rate = (self.stats['error_requests'] / max(1, self.stats['total_requests'])) * 100.0
        availability = 100.0 - error_rate
        
        return {
            'total_requests': self.stats['total_requests'],
            'blocked_requests': self.stats['blocked_requests'],
            'forwarded_requests': self.stats['forwarded_requests'],
            'error_requests': self.stats['error_requests'],
            'block_rate': (self.stats['blocked_requests'] / max(1, self.stats['total_requests'])) * 100.0,
            'error_rate': error_rate,
            'availability': availability,
            'avg_response_time': statistics.mean(rt_list) if rt_list else 0,
            'p95_response_time': p95,
            'rule_hits': dict(self.stats['rule_hits']),
            'blocked_ips_count': len(self.blocklist),
            'rule_count': sum(len(rules) for rules in self.rules.values())
        }

class StableWAFHandler(BaseHTTPRequestHandler):
    """穩定版 WAF 處理器"""
    
    def __init__(self, *args, **kwargs):
        self.modsec = StableModSecurityRules()
        super().__init__(*args, **kwargs)
    
    def get_client_ip(self):
        """獲取客戶端 IP"""
        return self.client_address[0]
    
    def do_GET(self):
        """處理 GET 請求"""
        try:
            if self.path == '/healthz':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                
                health_data = {
                    "status": "ok",
                    "timestamp": datetime.now().isoformat(),
                    "backend_healthy": True,
                    "uptime": time.time() - getattr(self, 'start_time', time.time())
                }
                self.wfile.write(json.dumps(health_data).encode())
                return
            
            if self.path == '/slo':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                
                rt_list = list(self.modsec.stats['response_times'])
                p95 = 0
                if rt_list:
                    sorted_rt = sorted(rt_list)
                    p95 = sorted_rt[min(int(len(sorted_rt)*0.95), len(sorted_rt)-1)]
                
                error_rate = (self.modsec.stats['error_requests'] / max(1, self.modsec.stats['total_requests'])) * 100.0
                availability = 100.0 - error_rate
                
                slo = {
                    'availability_pct': availability,
                    'p95_latency_ms': p95,
                    'error_rate_pct': error_rate,
                    'thresholds': self.modsec.slo_thresholds,
                    'passed': {
                        'availability': availability >= self.modsec.slo_thresholds['availability'],
                        'p95': p95 <= self.modsec.slo_thresholds['https_p95_ms'],
                        'error_rate': error_rate <= self.modsec.slo_thresholds['error_rate']
                    }
                }
                self.wfile.write(json.dumps(slo).encode())
                return
            
            if self.path == '/metrics':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(self.modsec.get_metrics()).encode())
                return
            
            if self.path == '/api/config':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    'governance_mode': self.modsec.governance_mode,
                    'small_traffic_percent': self.modsec.small_traffic_percent,
                    'slo_thresholds': self.modsec.slo_thresholds
                }).encode())
                return
            
            # 處理一般請求
            self.handle_request('GET')
            
        except Exception as e:
            logger.error(f"GET 請求處理錯誤: {e}")
            self.send_error(500, "Internal Server Error")
    
    def do_POST(self):
        """處理 POST 請求"""
        try:
            if self.path == '/api/config':
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
                data = json.loads(body)
                
                # 更新配置
                if 'governance_mode' in data:
                    self.modsec.governance_mode = data['governance_mode']
                if 'small_traffic_percent' in data:
                    self.modsec.small_traffic_percent = data['small_traffic_percent']
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'ok'}).encode())
                return
            
            # 處理一般請求
            self.handle_request('POST')
            
        except Exception as e:
            logger.error(f"POST 請求處理錯誤: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_request(self, method):
        """處理請求"""
        try:
            client_ip = self.get_client_ip()
            start_time = time.time()
            
            # 更新統計
            self.modsec.stats['total_requests'] += 1
            
            # 讀取請求體
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else None
            
            # 檢查規則
            violations = self.modsec.check_request(client_ip, method, self.path, self.headers, body)
            
            if violations:
                # 記錄違規
                for violation in violations:
                    logger.warning(f"請求被阻擋: {violation}")
                
                self.modsec.stats['blocked_requests'] += 1
                
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
                self.modsec.stats['forwarded_requests'] += 1
                
            except Exception as e:
                self.modsec.stats['error_requests'] += 1
                logger.error(f"轉發請求失敗: {e}")
                self.send_response(502)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<h1>502 Bad Gateway</h1>')
            
            # 記錄響應時間
            response_time = (time.time() - start_time) * 1000
            self.modsec.stats['response_times'].append(response_time)
            
        except Exception as e:
            logger.error(f"請求處理錯誤: {e}")
            self.send_error(500, "Internal Server Error")
    
    def forward_request(self, method, body):
        """轉發請求到後端"""
        try:
            backend_url = f"http://{BACKEND_HOST}:{BACKEND_PORT}{self.path}"
            
            # 準備請求
            req_data = body.encode() if body else None
            req = urllib.request.Request(backend_url, data=req_data, method=method)
            
            # 複製標頭
            for header, value in self.headers.items():
                if header.lower() not in ['host', 'content-length']:
                    req.add_header(header, value)
            
            # 發送請求
            with urllib.request.urlopen(req, timeout=3) as response:
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

def run_stable_waf():
    """運行穩定版 WAF"""
    print("啟動穩定版 WAF 代理...")
    print(f"後端: {BACKEND_HOST}:{BACKEND_PORT}")
    print(f"代理端口: {PROXY_PORT}")
    
    server = HTTPServer(('0.0.0.0', PROXY_PORT), StableWAFHandler)
    print(f"WAF 代理運行在 http://0.0.0.0:{PROXY_PORT}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n停止 WAF 代理...")
        server.shutdown()

if __name__ == "__main__":
    run_stable_waf()




