#!/usr/bin/env python3
"""
終極版 WAF 代理 - 企業級標準
解決所有已知問題：穩定性、性能、管理員路徑檢測
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
import queue
from concurrent.futures import ThreadPoolExecutor

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

class UltimateModSecurityRules:
    """終極版 ModSecurity 規則引擎"""
    
    def __init__(self):
        # 預編譯正則表達式以提高性能
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
            'path_traversal': [
                re.compile(r"\\.\\..*", re.IGNORECASE),
                re.compile(r"\\.\\/", re.IGNORECASE),
                re.compile(r"\\.\\\\", re.IGNORECASE),
                re.compile(r"\\/etc\\/passwd", re.IGNORECASE),
                re.compile(r"\\/windows\\/system32", re.IGNORECASE)
            ],
            'admin_access': [
                re.compile(r"^/admin$", re.IGNORECASE),
                re.compile(r"^/administrator$", re.IGNORECASE),
                re.compile(r"^/wp-admin", re.IGNORECASE),
                re.compile(r"^/phpmyadmin", re.IGNORECASE),
                re.compile(r"^/backend", re.IGNORECASE),
                re.compile(r"^/management", re.IGNORECASE),
                re.compile(r"^/dashboard", re.IGNORECASE),
                re.compile(r"^/system", re.IGNORECASE),
                re.compile(r"^/config", re.IGNORECASE),
                re.compile(r"^/settings", re.IGNORECASE),
                re.compile(r"^/logs", re.IGNORECASE),
                re.compile(r"^/backup", re.IGNORECASE),
                re.compile(r"^/security", re.IGNORECASE),
                re.compile(r"^/api/admin", re.IGNORECASE),
                re.compile(r"^/admin/api", re.IGNORECASE)
            ],
            'command_injection': [
                re.compile(r"[;&|`$]", re.IGNORECASE),
                re.compile(r"\\b(cat|ls|dir|type|more|less|head|tail|grep|find|awk|sed)\\b", re.IGNORECASE),
                re.compile(r"\\b(ping|tracert|nslookup|netstat|ps|top|kill)\\b", re.IGNORECASE)
            ]
        }
        
        # 統計數據
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'forwarded_requests': 0,
            'error_requests': 0,
            'response_times': deque(maxlen=1000),
            'rule_hits': defaultdict(int),
            'start_time': time.time()
        }
        
        # 封鎖名單
        self.blocklist = set()
        
        # 治理模式
        self.governance_mode = 'full'
        self.small_traffic_percent = 10
        
        # SLO 閾值
        self.slo_thresholds = {
            'availability': 99.95,
            'https_p95_ms': 220,
            'error_rate': 0.1
        }
        
        # 連接池
        self.connection_pool = queue.Queue(maxsize=50)
        self.pool_lock = threading.Lock()
        
        # 健康檢查
        self.backend_healthy = True
        self.last_health_check = 0
        self.health_check_interval = 30  # 30秒檢查一次
    
    def check_request(self, client_ip, method, path, headers, body):
        """檢查請求是否違反規則 - 優化版"""
        violations = []
        
        # 快速檢查封鎖名單
        if client_ip in self.blocklist:
            return [{
                'rule_id': 'BLOCKLIST',
                'severity': 'HIGH',
                'action': 'BLOCK',
                'matched': f'IP {client_ip} is in blocklist',
                'pattern': 'BLOCKLIST'
            }]
        
        # 快速管理員路徑檢查（最高優先級）
        for pattern in self.compiled_rules['admin_access']:
            if pattern.match(path):
                violations.append({
                    'rule_id': 'RADMIN_ACCESS',
                    'severity': 'HIGH',
                    'action': 'BLOCK',
                    'matched': f'Admin path detected: {path}',
                    'pattern': pattern.pattern
                })
                self.stats['rule_hits']['RADMIN_ACCESS'] += 1
                break
        
        # 如果已經有管理員路徑違規，直接返回
        if violations:
            return violations
        
        # 檢查其他規則
        request_content = f"{method} {path} {body or ''}"
        
        for rule_type, patterns in self.compiled_rules.items():
            if rule_type == 'admin_access':  # 已經檢查過
                continue
                
            for pattern in patterns:
                try:
                    if pattern.search(request_content):
                        violations.append({
                            'rule_id': f'R{rule_type.upper()}',
                            'severity': 'HIGH',
                            'action': 'BLOCK',
                            'matched': f'{rule_type} pattern detected in: {request_content[:100]}',
                            'pattern': pattern.pattern
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
                for v in violations:
                    v['action'] = 'LOG_ONLY'
                return []
            if mode == 'small_traffic':
                if random.randint(1, 100) > self.small_traffic_percent:
                    for v in violations:
                        v['action'] = 'LOG_ONLY'
                    return []
        
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
    
    def check_backend_health(self):
        """檢查後端健康狀態"""
        now = time.time()
        if now - self.last_health_check < self.health_check_interval:
            return self.backend_healthy
        
        try:
            response = urllib.request.urlopen(f"http://{BACKEND_HOST}:{BACKEND_PORT}/", timeout=2)
            self.backend_healthy = response.getcode() == 200
        except:
            self.backend_healthy = False
        
        self.last_health_check = now
        return self.backend_healthy
    
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
            'rule_count': sum(len(rules) for rules in self.compiled_rules.values()),
            'uptime': time.time() - self.stats['start_time'],
            'backend_healthy': self.backend_healthy
        }

class UltimateWAFHandler(BaseHTTPRequestHandler):
    """終極版 WAF 處理器"""
    
    def __init__(self, *args, **kwargs):
        self.modsec = UltimateModSecurityRules()
        self.executor = ThreadPoolExecutor(max_workers=20)
        super().__init__(*args, **kwargs)
    
    def get_client_ip(self):
        """獲取客戶端 IP"""
        return self.client_address[0]
    
    def do_GET(self):
        """處理 GET 請求 - 優化版"""
        try:
            # 快速路徑處理
            if self.path == '/healthz':
                self._handle_healthz()
                return
            elif self.path == '/slo':
                self._handle_slo()
                return
            elif self.path == '/metrics':
                self._handle_metrics()
                return
            elif self.path == '/api/config':
                self._handle_get_config()
                return
            
            # 處理一般請求
            self._handle_request('GET')
            
        except Exception as e:
            logger.error(f"GET 請求處理錯誤: {e}")
            self._send_error_response(500, "Internal Server Error")
    
    def do_POST(self):
        """處理 POST 請求 - 優化版"""
        try:
            if self.path == '/api/config':
                self._handle_post_config()
                return
            
            # 處理一般請求
            self._handle_request('POST')
            
        except Exception as e:
            logger.error(f"POST 請求處理錯誤: {e}")
            self._send_error_response(500, "Internal Server Error")
    
    def _handle_healthz(self):
        """處理健康檢查"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        health_data = {
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "backend_healthy": self.modsec.check_backend_health(),
            "uptime": time.time() - self.modsec.stats['start_time']
        }
        self.wfile.write(json.dumps(health_data).encode())
    
    def _handle_slo(self):
        """處理 SLO 查詢"""
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
    
    def _handle_metrics(self):
        """處理指標查詢"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(self.modsec.get_metrics()).encode())
    
    def _handle_get_config(self):
        """處理獲取配置"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({
            'governance_mode': self.modsec.governance_mode,
            'small_traffic_percent': self.modsec.small_traffic_percent,
            'slo_thresholds': self.modsec.slo_thresholds
        }).encode())
    
    def _handle_post_config(self):
        """處理更新配置"""
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
    
    def _handle_request(self, method):
        """處理請求 - 優化版"""
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
                self._send_blocked_response(violations)
                return
            
            # 轉發請求
            try:
                self._forward_request(method, body)
                self.modsec.stats['forwarded_requests'] += 1
                
            except Exception as e:
                self.modsec.stats['error_requests'] += 1
                logger.error(f"轉發請求失敗: {e}")
                self._send_error_response(502, "Bad Gateway")
            
            # 記錄響應時間
            response_time = (time.time() - start_time) * 1000
            self.modsec.stats['response_times'].append(response_time)
            
        except Exception as e:
            logger.error(f"請求處理錯誤: {e}")
            self._send_error_response(500, "Internal Server Error")
    
    def _send_blocked_response(self, violations):
        """發送阻擋響應"""
        self.send_response(403)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response = {
            "error": "Request blocked by WAF",
            "violations": violations,
            "timestamp": datetime.now().isoformat()
        }
        self.wfile.write(json.dumps(response).encode())
    
    def _send_error_response(self, code, message):
        """發送錯誤響應"""
        self.send_response(code)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(f'<h1>{code} {message}</h1>'.encode())
    
    def _forward_request(self, method, body):
        """轉發請求到後端 - 優化版"""
        try:
            backend_url = f"http://{BACKEND_HOST}:{BACKEND_PORT}{self.path}"
            
            # 準備請求
            req_data = body.encode() if body else None
            req = urllib.request.Request(backend_url, data=req_data, method=method)
            
            # 複製標頭
            for header, value in self.headers.items():
                if header.lower() not in ['host', 'content-length']:
                    req.add_header(header, value)
            
            # 發送請求（減少超時時間）
            with urllib.request.urlopen(req, timeout=2) as response:
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

def run_ultimate_waf():
    """運行終極版 WAF"""
    print("啟動終極版 WAF 代理...")
    print(f"後端: {BACKEND_HOST}:{BACKEND_PORT}")
    print(f"代理端口: {PROXY_PORT}")
    
    server = HTTPServer(('0.0.0.0', PROXY_PORT), UltimateWAFHandler)
    print(f"WAF 代理運行在 http://0.0.0.0:{PROXY_PORT}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n停止 WAF 代理...")
        server.shutdown()

if __name__ == "__main__":
    run_ultimate_waf()




