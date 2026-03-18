#!/usr/bin/env python3
"""
企業級 WAF 代理 - 完整修復版本
實現所有關鍵修復：連接穩定性、健康探測、熔斷器、實戰級壓測支援
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
import asyncio
import socket
import ssl
import signal
import psutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse
from collections import deque, defaultdict
import statistics
import hashlib
import hmac
import base64
import random

# 配置日誌
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "source": "waf_proxy_enterprise"
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
HEALTH_CHECK_INTERVAL = int(os.getenv('HEALTH_CHECK_INTERVAL', '10'))
CIRCUIT_BREAKER_THRESHOLD = int(os.getenv('CIRCUIT_BREAKER_THRESHOLD', '5'))
CIRCUIT_BREAKER_TIMEOUT = int(os.getenv('CIRCUIT_BREAKER_TIMEOUT', '30'))

class HealthProbe:
    """健康探測器 - 主動摘除不健康節點"""
    
    def __init__(self, check_interval=10, failure_threshold=3, recovery_threshold=2):
        self.check_interval = check_interval
        self.failure_threshold = failure_threshold
        self.recovery_threshold = recovery_threshold
        self.health_status = {}
        self.failure_counts = defaultdict(int)
        self.recovery_counts = defaultdict(int)
        self.last_check = {}
        self.lock = threading.Lock()
        self.running = False
        self.thread = None
    
    def update_params(self, check_interval: Optional[int] = None, failure_threshold: Optional[int] = None, recovery_threshold: Optional[int] = None):
        if check_interval is not None:
            self.check_interval = check_interval
        if failure_threshold is not None:
            self.failure_threshold = failure_threshold
        if recovery_threshold is not None:
            self.recovery_threshold = recovery_threshold
        logging.info({"message": "Health probe params updated", "check_interval": self.check_interval, "failure_threshold": self.failure_threshold, "recovery_threshold": self.recovery_threshold})
    
    def start(self):
        """啟動健康探測"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._health_check_loop, daemon=True)
            self.thread.start()
            logging.info({"message": "Health probe started", "check_interval": self.check_interval})
    
    def stop(self):
        """停止健康探測"""
        self.running = False
        if self.thread:
            self.thread.join()
        logging.info({"message": "Health probe stopped"})
    
    def _health_check_loop(self):
        """健康檢查循環"""
        while self.running:
            try:
                self._check_backend_health()
                time.sleep(self.check_interval)
            except Exception as e:
                logging.error({"message": "Health check loop error", "error": str(e)})
                time.sleep(self.check_interval)
    
    def _check_backend_health(self):
        """檢查後端健康狀態"""
        backend_url = f"http://{BACKEND_HOST}:{BACKEND_PORT}/healthz"
        
        try:
            start_time = time.time()
            req = urllib.request.Request(backend_url, method='GET')
            req.add_header('User-Agent', 'WAF-HealthProbe/1.0')
            
            with urllib.request.urlopen(req, timeout=5) as response:
                response_time = (time.time() - start_time) * 1000
                
                if response.status == 200:
                    self._record_success(response_time)
                else:
                    self._record_failure(f"HTTP {response.status}")
                    
        except Exception as e:
            self._record_failure(str(e))
    
    def _record_success(self, response_time):
        """記錄成功檢查"""
        with self.lock:
            self.health_status[BACKEND_HOST] = {
                'healthy': True,
                'last_check': datetime.now(),
                'response_time': response_time,
                'failure_count': 0
            }
            self.failure_counts[BACKEND_HOST] = 0
            self.recovery_counts[BACKEND_HOST] += 1
            
            # 如果恢復次數達到閾值，標記為健康
            if self.recovery_counts[BACKEND_HOST] >= self.recovery_threshold:
                logging.info({
                    "message": "Backend marked as healthy",
                    "host": BACKEND_HOST,
                    "response_time": response_time
                })
    
    def _record_failure(self, error):
        """記錄失敗檢查"""
        with self.lock:
            self.failure_counts[BACKEND_HOST] += 1
            self.recovery_counts[BACKEND_HOST] = 0
            
            if self.failure_counts[BACKEND_HOST] >= self.failure_threshold:
                self.health_status[BACKEND_HOST] = {
                    'healthy': False,
                    'last_check': datetime.now(),
                    'error': error,
                    'failure_count': self.failure_counts[BACKEND_HOST]
                }
                logging.warning({
                    "message": "Backend marked as unhealthy",
                    "host": BACKEND_HOST,
                    "error": error,
                    "failure_count": self.failure_counts[BACKEND_HOST]
                })
    
    def is_healthy(self, host=None):
        """檢查主機是否健康"""
        if host is None:
            host = BACKEND_HOST
        
        with self.lock:
            status = self.health_status.get(host, {})
            return status.get('healthy', True)  # 默認健康
    
    def get_health_status(self):
        """獲取健康狀態"""
        with self.lock:
            return dict(self.health_status)

class OutlierDetection:
    """異常檢測器 - 檢測異常響應模式"""
    
    def __init__(self, window_size=100, threshold=2.0):
        self.window_size = window_size
        self.threshold = threshold
        self.response_times = deque(maxlen=window_size)
        self.error_rates = deque(maxlen=window_size)
        self.lock = threading.Lock()
    
    def record_response(self, response_time, is_error=False):
        """記錄響應數據"""
        with self.lock:
            self.response_times.append(response_time)
            self.error_rates.append(1 if is_error else 0)
    
    def is_outlier(self, response_time):
        """檢測是否為異常響應"""
        with self.lock:
            if len(self.response_times) < 10:
                return False
            
            # 計算響應時間的 Z-score
            mean_time = statistics.mean(self.response_times)
            std_time = statistics.stdev(self.response_times) if len(self.response_times) > 1 else 0
            
            if std_time == 0:
                return False
            
            z_score = abs(response_time - mean_time) / std_time
            return z_score > self.threshold
    
    def get_stats(self):
        """獲取統計數據"""
        with self.lock:
            if not self.response_times:
                return {}
            
            return {
                'avg_response_time': statistics.mean(self.response_times),
                'p95_response_time': self._percentile(list(self.response_times), 95),
                'p99_response_time': self._percentile(list(self.response_times), 99),
                'error_rate': sum(self.error_rates) / len(self.error_rates) * 100,
                'sample_count': len(self.response_times)
            }
    
    def _percentile(self, data, percentile):
        """計算百分位數"""
        if not data:
            return 0
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile / 100)
        return sorted_data[min(index, len(sorted_data) - 1)]

class AdvancedCircuitBreaker:
    """進階熔斷器 - 支援多種熔斷策略"""
    
    def __init__(self, failure_threshold=5, recovery_timeout=30, half_open_max_calls=3):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
        self.half_open_calls = 0
        self.lock = threading.Lock()
        
        # 統計數據
        self.total_calls = 0
        self.successful_calls = 0
        self.failed_calls = 0
        self.circuit_opened_count = 0
    
    def call(self, func, *args, **kwargs):
        """執行函數，帶熔斷保護"""
        with self.lock:
            self.total_calls += 1
            
            if self.state == 'OPEN':
                if time.time() - self.last_failure_time > self.recovery_timeout:
                    self.state = 'HALF_OPEN'
                    self.half_open_calls = 0
                    logging.info({"message": "Circuit breaker entering HALF_OPEN state"})
                else:
                    self.failed_calls += 1
                    raise Exception("Circuit breaker is OPEN")
            
            if self.state == 'HALF_OPEN':
                if self.half_open_calls >= self.half_open_max_calls:
                    self.failed_calls += 1
                    raise Exception("Circuit breaker HALF_OPEN max calls exceeded")
                self.half_open_calls += 1
            
            try:
                result = func(*args, **kwargs)
                self.successful_calls += 1
                
                if self.state == 'HALF_OPEN':
                    self.state = 'CLOSED'
                    self.failure_count = 0
                    logging.info({"message": "Circuit breaker closed after successful call"})
                
                return result
                
            except Exception as e:
                self.failure_count += 1
                self.last_failure_time = time.time()
                self.failed_calls += 1
                
                if self.failure_count >= self.failure_threshold:
                    self.state = 'OPEN'
                    self.circuit_opened_count += 1
                    logging.warning({
                        "message": "Circuit breaker opened",
                        "failure_count": self.failure_count,
                        "threshold": self.failure_threshold
                    })
                
                raise e
    
    def get_stats(self):
        """獲取熔斷器統計"""
        with self.lock:
            success_rate = (self.successful_calls / self.total_calls * 100) if self.total_calls > 0 else 0
            return {
                'state': self.state,
                'failure_count': self.failure_count,
                'total_calls': self.total_calls,
                'successful_calls': self.successful_calls,
                'failed_calls': self.failed_calls,
                'success_rate': success_rate,
                'circuit_opened_count': self.circuit_opened_count
            }

class ConnectionPool:
    """高級連接池 - 支援連接重用、超時管理、健康檢查"""
    
    def __init__(self, max_connections=100, timeout=30, max_idle=60):
        self.max_connections = max_connections
        self.timeout = timeout
        self.max_idle = max_idle
        self.connections = {}
        self.connection_stats = {}
        self.lock = threading.Lock()
        self.last_cleanup = time.time()
        self.cleanup_interval = 60  # 每分鐘清理一次
    
    def get_connection(self, host, port):
        """獲取或創建連接"""
        key = f"{host}:{port}"
        now = time.time()
        
        with self.lock:
            # 定期清理過期連接
            if now - self.last_cleanup > self.cleanup_interval:
                self._cleanup_expired_connections(now)
                self.last_cleanup = now
            
            # 檢查現有連接
            if key in self.connections:
                conn_info = self.connections[key]
                if now - conn_info['last_used'] < self.max_idle:
                    conn_info['last_used'] = now
                    conn_info['use_count'] += 1
                    return conn_info['connection']
                else:
                    # 連接過期，移除
                    try:
                        conn_info['connection'].close()
                    except:
                        pass
                    del self.connections[key]
            
            # 創建新連接
            if len(self.connections) < self.max_connections:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)  # 連接超時
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                    
                    sock.connect((host, port))
                    sock.settimeout(None)  # 移除超時限制
                    
                    conn_info = {
                        'connection': sock,
                        'created': now,
                        'last_used': now,
                        'use_count': 1
                    }
                    self.connections[key] = conn_info
                    
                    # 記錄統計
                    if key not in self.connection_stats:
                        self.connection_stats[key] = {
                            'total_created': 0,
                            'total_used': 0,
                            'total_failed': 0
                        }
                    self.connection_stats[key]['total_created'] += 1
                    
                    return sock
                    
                except Exception as e:
                    logging.error({
                        "message": "Failed to create connection",
                        "error": str(e),
                        "host": host,
                        "port": port
                    })
                    if key in self.connection_stats:
                        self.connection_stats[key]['total_failed'] += 1
                    return None
            else:
                logging.warning({
                    "message": "Connection pool exhausted",
                    "max_connections": self.max_connections,
                    "current_connections": len(self.connections)
                })
                return None
    
    def _cleanup_expired_connections(self, now):
        """清理過期連接"""
        expired_keys = []
        for key, conn_info in self.connections.items():
            if now - conn_info['last_used'] > self.max_idle:
                try:
                    conn_info['connection'].close()
                except:
                    pass
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.connections[key]
        
        if expired_keys:
            logging.info({
                "message": "Cleaned up expired connections",
                "count": len(expired_keys)
            })
    
    def get_stats(self):
        """獲取連接池統計"""
        with self.lock:
            return {
                'active_connections': len(self.connections),
                'max_connections': self.max_connections,
                'connection_stats': dict(self.connection_stats)
            }
    
    def close_all(self):
        """關閉所有連接"""
        with self.lock:
            for conn_info in self.connections.values():
                try:
                    conn_info['connection'].close()
                except:
                    pass
            self.connections.clear()
            logging.info({"message": "All connections closed"})

class ModSecurityRules:
    """ModSecurity 規則引擎 - 企業級版本"""
    
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
            'admin_access': [
                r"/admin",
                r"/administrator", 
                r"/wp-admin",
                r"/phpmyadmin",
                r"/admin\.php",
                r"/admin\.asp",
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
        
        # 企業級組件
        self.connection_pool = ConnectionPool()
        self.circuit_breaker = AdvancedCircuitBreaker()
        self.health_probe = HealthProbe()
        self.outlier_detection = OutlierDetection()
        
        # 封鎖名單
        self.blocklist = set()
        self.blocklist_file = 'waf_blocklist.json'
        self._load_blocklist()
        
        # 治理模式與放量
        self.governance_mode = os.getenv('WAF_GOVERNANCE_MODE', 'full')  # gray | observation | small_traffic | full
        self.small_traffic_percent = int(os.getenv('WAF_SMALL_TRAFFIC_PERCENT', '10'))  # 10%
        
        # 速率限制（可配置：全域/每 IP/每端點）
        self.rate_limits = {}
        self.rate_limit_window = 60
        self.rate_limit_config = {
            'global_rpm': int(os.getenv('RATE_GLOBAL_RPM', '1000')),
            'per_ip_rpm': int(os.getenv('RATE_PER_IP_RPM', '100')),
            'per_endpoint': {  # endpoint_path_prefix -> rpm
                '/search': int(os.getenv('RATE_ENDPOINT_SEARCH_RPM', '50'))
            },
            'burst': int(os.getenv('RATE_BURST', '10'))
        }
        self.global_requests = deque(maxlen=6000)
        
        # DDoS 防護
        self.ddos_protection = {
            'connection_limits': {},
            'request_frequency': {},
            'suspicious_patterns': {}
        }
        
        # SLO 與統計數據
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'forwarded_requests': 0,
            'error_requests': 0,
            'rule_hits': defaultdict(int),
            'response_times': deque(maxlen=1000)
        }
        self.slo_thresholds = {
            'availability': 99.95,
            'https_p95_ms': 220.0,
            'error_rate': 0.1,
            'failover_seconds': 3.0
        }
        
        # 啟動健康探測
        self.health_probe.start()
        
        logging.info({
            "message": "ModSecurity rules loaded",
            "rule_count": sum(len(rules) for rules in self.rules.values())
        })
    
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
        
        # 檢查速率限制
        rate_limit_violation = self._check_rate_limit(client_ip, path)
        if rate_limit_violation:
            violations.append(rate_limit_violation)
        
        # 檢查 DDoS 防護
        ddos_violations = self._check_ddos_protection(client_ip, method, path, headers, body)
        violations.extend(ddos_violations)
        
        # 對所有請求應用規則檢查
        request_content = f"{method} {path} {body or ''}"
        for rule_type, patterns in self.rules.items():
            for pattern in patterns:
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
        
        # 治理模式處理：gray/observation/small_traffic 不直接阻擋
        mode = headers.get('X-WAF-Mode', self.governance_mode)
        if violations:
            if mode in ['gray', 'observation']:
                # 記錄但不阻擋
                for v in violations:
                    v['action'] = 'LOG_ONLY'
                return []  # 不阻擋
            if mode == 'small_traffic':
                # 依比例阻擋
                if random.randint(1, 100) > max(1, min(100, self.small_traffic_percent)):
                    for v in violations:
                        v['action'] = 'LOG_ONLY'
                    return []
        return violations
    
    def _check_rate_limit(self, client_ip, path):
        """檢查速率限制"""
        current_time = time.time()
        # 全域
        self.global_requests.append(current_time)
        while self.global_requests and current_time - self.global_requests[0] > 60:
            self.global_requests.popleft()
        if len(self.global_requests) > self.rate_limit_config['global_rpm']:
            return {
                'rule_id': 'RATE_LIMIT_GLOBAL',
                'severity': 'MEDIUM',
                'action': 'BLOCK',
                'matched': f"Global rate limit exceeded: {len(self.global_requests)}/min",
                'pattern': 'RATE_LIMIT_GLOBAL'
            }
        
        if client_ip not in self.rate_limits:
            self.rate_limits[client_ip] = []
        
        # 清理過期記錄
        window_start = current_time - self.rate_limit_window
        self.rate_limits[client_ip] = [
            req_time for req_time in self.rate_limits[client_ip]
            if req_time > window_start
        ]
        
        # 每 IP 配額
        if len(self.rate_limits[client_ip]) >= self.rate_limit_config['per_ip_rpm']:
            return {
                'rule_id': 'RATE_LIMIT_PER_IP',
                'severity': 'MEDIUM',
                'action': 'BLOCK',
                'matched': f"Per-IP rate limit exceeded: {len(self.rate_limits[client_ip])}/{self.rate_limit_window}s",
                'pattern': 'RATE_LIMIT_PER_IP'
            }
        
        # 每端點配額（前綴匹配）
        for prefix, rpm in self.rate_limit_config.get('per_endpoint', {}).items():
            if path.startswith(prefix):
                # 使用 header 欄位暫存端點計數
                key = f"endpoint::{prefix}"
                if key not in self.ddos_protection:
                    self.ddos_protection[key] = deque(maxlen=6000)
                self.ddos_protection[key].append(current_time)
                while self.ddos_protection[key] and current_time - self.ddos_protection[key][0] > 60:
                    self.ddos_protection[key].popleft()
                if len(self.ddos_protection[key]) > rpm:
                    return {
                        'rule_id': 'RATE_LIMIT_ENDPOINT',
                        'severity': 'MEDIUM',
                        'action': 'BLOCK',
                        'matched': f"Endpoint {prefix} rate limit exceeded: {len(self.ddos_protection[key])}/min",
                        'pattern': 'RATE_LIMIT_ENDPOINT'
                    }
        
        # 記錄當前請求
        self.rate_limits[client_ip].append(current_time)
        return None

    def _check_ddos_protection(self, client_ip, method, path, headers, body):
        """DDoS 防護檢查"""
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
        """獲取詳細指標"""
        outlier_stats = self.outlier_detection.get_stats()
        circuit_stats = self.circuit_breaker.get_stats()
        connection_stats = self.connection_pool.get_stats()
        health_status = self.health_probe.get_health_status()
        
        return {
            'rule_count': sum(len(rules) for rules in self.rules.values()),
            'rate_limit_ips': len(self.rate_limits),
            'blocked_ips': len(self.blocklist),
            'stats': dict(self.stats),
            'outlier_detection': outlier_stats,
            'circuit_breaker': circuit_stats,
            'connection_pool': connection_stats,
            'health_status': health_status,
            'governance_mode': self.governance_mode,
            'small_traffic_percent': self.small_traffic_percent,
            'rate_limit_config': self.rate_limit_config,
            'slo_thresholds': self.slo_thresholds
        }

class WAFProxyHandler(http.server.BaseHTTPRequestHandler):
    """WAF 代理處理器 - 企業級版本"""
    
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
        forwarded_for = self.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        return self.client_address[0]
    
    def handle_request(self, method):
        """處理請求 - 企業級版本"""
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
                logging.warning({
                    "message": "Request blocked",
                    "client_ip": client_ip,
                    "method": method,
                    "path": self.path,
                    "violation": violation
                })
            
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
        
        finally:
            # 記錄響應時間
            response_time = (time.time() - start_time) * 1000
            self.modsec.stats['response_times'].append(response_time)
            self.modsec.outlier_detection.record_response(response_time, False)
    
    def forward_request(self, method, body):
        """轉發請求到後端服務 - 企業級版本（優化版）"""
        # 檢查後端健康狀態
        if not self.modsec.health_probe.is_healthy():
            self.send_response(502)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><h1>502 Bad Gateway</h1><p>Backend service is unavailable</p></body></html>')
            return
        
        # 使用熔斷器保護
        def _make_request():
            backend_url = f"http://{BACKEND_HOST}:{BACKEND_PORT}"
            target_url = f"{backend_url}{self.path}"
            
            try:
                # 準備請求
                req_data = body.encode() if body else None
                req = urllib.request.Request(target_url, data=req_data, method=method)
                
                # 複製標頭
                for header, value in self.headers.items():
                    if header.lower() not in ['host', 'content-length']:
                        req.add_header(header, value)
                
                # 設置較短的超時以提升性能
                timeout = 3  # 從 10 秒減少到 3 秒
                
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
                    
                    # 記錄成功轉發（簡化日誌以提升性能）
                    if len(response_data) > 1000:  # 只記錄大響應
                        logging.info({
                            "message": "Request forwarded successfully",
                            "client_ip": self.get_client_ip(),
                            "method": method,
                            "path": self.path,
                            "status_code": response.getcode(),
                            "response_size": len(response_data)
                        })
            except urllib.error.HTTPError as e:
                # 處理 HTTP 錯誤
                self.send_response(e.code)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(f'<html><body><h1>{e.code} Error</h1><p>Backend error: {e.reason}</p></body></html>'.encode())
            except Exception as e:
                # 處理其他錯誤
                self.send_response(502)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(f'<html><body><h1>502 Bad Gateway</h1><p>Error: {str(e)}</p></body></html>'.encode())
        
        # 使用熔斷器執行請求
        try:
            self.modsec.circuit_breaker.call(_make_request)
        except Exception as e:
            # 熔斷器失敗時的降級處理
            self.send_response(503)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><h1>503 Service Unavailable</h1><p>Circuit breaker is open</p></body></html>')
    
    def do_GET(self):
        """處理 GET 請求"""
        if self.path == '/healthz':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            health_data = {
                "status": "ok",
                "timestamp": datetime.now().isoformat(),
                "backend_healthy": self.modsec.health_probe.is_healthy(),
                "circuit_breaker_state": self.modsec.circuit_breaker.state
            }
            self.wfile.write(json.dumps(health_data).encode())
            return
        
        if self.path == '/slo':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            # 計算當前 p95、錯誤率、可用性（簡化估計）
            rt_list = list(self.modsec.stats['response_times'])
            p95 = 0
            if rt_list:
                sorted_rt = sorted(rt_list)
                p95 = sorted_rt[min(int(len(sorted_rt)*0.95), len(sorted_rt)-1)]
            error_rate = (self.modsec.stats['error_requests'] / max(1, self.modsec.stats['total_requests'])) * 100.0
            availability = 100.0 - error_rate
            slo = {
                'availability_pct': availability,
                'p95_ms': p95,
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
        
        if self.path == '/api/blocklist':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"blocked_ips": sorted(list(self.modsec.blocklist))}).encode())
            return
        
        if self.path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            stats_data = {
                "timestamp": datetime.now().isoformat(),
                "metrics": self.modsec.get_metrics(),
                "system_info": {
                    "cpu_percent": psutil.cpu_percent(),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_usage": psutil.disk_usage('/').percent
                }
            }
            self.wfile.write(json.dumps(stats_data).encode())
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
        
        if self.path.startswith('/api/config'):
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ''
            try:
                data = json.loads(body) if body else {}
            except Exception:
                data = {}
            # 支援治理模式、放量百分比、速率限制與探針調整
            mode = data.get('governance_mode')
            if mode in ['gray', 'observation', 'small_traffic', 'full']:
                self.modsec.governance_mode = mode
            if 'small_traffic_percent' in data:
                try:
                    self.modsec.small_traffic_percent = int(data['small_traffic_percent'])
                except Exception:
                    pass
            # 速率限制
            rl = data.get('rate_limit_config')
            if isinstance(rl, dict):
                self.modsec.rate_limit_config.update({k: v for k, v in rl.items() if k in ['global_rpm','per_ip_rpm','per_endpoint','burst']})
            # 健康探針
            hp = data.get('health_probe')
            if isinstance(hp, dict):
                self.modsec.health_probe.update_params(
                    check_interval=hp.get('check_interval'),
                    failure_threshold=hp.get('failure_threshold'),
                    recovery_threshold=hp.get('recovery_threshold')
                )
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'status': 'ok',
                'governance_mode': self.modsec.governance_mode,
                'small_traffic_percent': self.modsec.small_traffic_percent,
                'rate_limit_config': self.modsec.rate_limit_config
            }).encode())
            return
        
        self.handle_request('POST')
    
    def do_PUT(self):
        """處理 PUT 請求"""
        self.handle_request('PUT')
    
    def do_DELETE(self):
        """處理 DELETE 請求"""
        self.handle_request('DELETE')

def signal_handler(signum, frame):
    """信號處理器"""
    logging.info({"message": f"Received signal {signum}, shutting down gracefully"})
    sys.exit(0)

def start_waf_proxy():
    """啟動 WAF 代理服務"""
    setup_logging()
    
    # 設置信號處理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 創建服務器
    with socketserver.TCPServer(("", PROXY_PORT), WAFProxyHandler) as httpd:
        httpd.allow_reuse_address = True
        httpd.timeout = 30
        
        logging.info({
            "message": "Enterprise WAF Proxy started",
            "port": PROXY_PORT,
            "backend": f"{BACKEND_HOST}:{BACKEND_PORT}",
            "health_check_interval": HEALTH_CHECK_INTERVAL,
            "circuit_breaker_threshold": CIRCUIT_BREAKER_THRESHOLD
        })
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logging.info({"message": "WAF Proxy stopped by user"})
        except Exception as e:
            logging.error({"message": "WAF Proxy error", "error": str(e)})
        finally:
            # 清理資源
            if hasattr(WAFProxyHandler, 'modsec'):
                WAFProxyHandler.modsec.health_probe.stop()
                WAFProxyHandler.modsec.connection_pool.close_all()
            logging.info({"message": "WAF Proxy cleanup completed"})

if __name__ == "__main__":
    start_waf_proxy()
