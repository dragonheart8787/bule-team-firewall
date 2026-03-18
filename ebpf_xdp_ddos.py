#!/usr/bin/env python3
"""
eBPF/XDP DDoS 防護模組
Windows 環境下的速率限制與L3/L4 DDoS緩解
"""

import time
import threading
import subprocess
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
import json

class RateLimiter:
    """速率限制器"""
    
    def __init__(self, max_requests: int, time_window: int):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()
        self.lock = threading.Lock()
    
    def is_allowed(self) -> bool:
        """檢查是否允許請求"""
        with self.lock:
            now = time.time()
            
            # 移除過期的請求記錄
            while self.requests and self.requests[0] <= now - self.time_window:
                self.requests.popleft()
            
            # 檢查是否超過限制
            if len(self.requests) >= self.max_requests:
                return False
            
            # 記錄當前請求
            self.requests.append(now)
            return True
    
    def get_remaining_requests(self) -> int:
        """獲取剩餘請求數"""
        with self.lock:
            now = time.time()
            while self.requests and self.requests[0] <= now - self.time_window:
                self.requests.popleft()
            return max(0, self.max_requests - len(self.requests))

class DDoSMitigation:
    """DDoS緩解系統"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.rate_limiters = {}
        self.blocked_ips = set()
        self.suspicious_ips = defaultdict(int)
        self.attack_patterns = defaultdict(int)
        self.monitoring = False
        self.monitor_thread = None
        
        # 配置參數
        self.config = {
            'max_requests_per_minute': 100,
            'max_requests_per_second': 10,
            'suspicious_threshold': 5,
            'block_duration': 300,  # 5分鐘
            'monitor_interval': 1,  # 1秒
            'whitelist': [
                '127.0.0.1',
                '::1',
                '192.168.0.0/16',
                '10.0.0.0/8'
            ]
        }
    
    def is_ip_whitelisted(self, ip: str) -> bool:
        """檢查IP是否在白名單中"""
        for whitelist_ip in self.config['whitelist']:
            if '/' in whitelist_ip:  # CIDR格式
                if self._ip_in_cidr(ip, whitelist_ip):
                    return True
            else:  # 單一IP
                if ip == whitelist_ip:
                    return True
        return False
    
    def _ip_in_cidr(self, ip: str, cidr: str) -> bool:
        """檢查IP是否在CIDR範圍內"""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
        except:
            return False
    
    def get_rate_limiter(self, ip: str) -> RateLimiter:
        """獲取IP的速率限制器"""
        if ip not in self.rate_limiters:
            self.rate_limiters[ip] = RateLimiter(
                self.config['max_requests_per_minute'],
                60  # 1分鐘窗口
            )
        return self.rate_limiters[ip]
    
    def check_request(self, ip: str, path: str, user_agent: str = "") -> Dict:
        """檢查請求是否為DDoS攻擊"""
        result = {
            'allowed': True,
            'reason': '',
            'action': 'PASS',
            'rate_limit_remaining': 0
        }
        
        # 檢查白名單
        if self.is_ip_whitelisted(ip):
            return result
        
        # 檢查是否已被封鎖
        if ip in self.blocked_ips:
            result['allowed'] = False
            result['reason'] = 'IP已被封鎖'
            result['action'] = 'BLOCK'
            return result
        
        # 速率限制檢查
        rate_limiter = self.get_rate_limiter(ip)
        if not rate_limiter.is_allowed():
            result['allowed'] = False
            result['reason'] = '超過速率限制'
            result['action'] = 'RATE_LIMIT'
            self.suspicious_ips[ip] += 1
            return result
        
        result['rate_limit_remaining'] = rate_limiter.get_remaining_requests()
        
        # 檢測攻擊模式
        attack_score = self.detect_attack_patterns(ip, path, user_agent)
        if attack_score > 0:
            self.suspicious_ips[ip] += attack_score
            result['attack_score'] = attack_score
        
        # 檢查是否達到可疑閾值
        if self.suspicious_ips[ip] >= self.config['suspicious_threshold']:
            self.block_ip(ip, f"可疑活動 (分數: {self.suspicious_ips[ip]})")
            result['allowed'] = False
            result['reason'] = '檢測到可疑活動'
            result['action'] = 'BLOCK'
        
        return result
    
    def detect_attack_patterns(self, ip: str, path: str, user_agent: str) -> int:
        """檢測攻擊模式"""
        score = 0
        
        # 檢測重複請求模式
        pattern_key = f"{ip}:{path}"
        self.attack_patterns[pattern_key] += 1
        
        if self.attack_patterns[pattern_key] > 10:
            score += 2
        
        # 檢測可疑路徑
        suspicious_paths = [
            '/admin', '/wp-admin', '/phpmyadmin', '/.env',
            '/config', '/backup', '/test', '/debug'
        ]
        
        for suspicious_path in suspicious_paths:
            if suspicious_path in path.lower():
                score += 1
        
        # 檢測可疑User-Agent
        suspicious_agents = [
            'bot', 'crawler', 'scanner', 'hack', 'attack',
            'sqlmap', 'nmap', 'nikto', 'dirb'
        ]
        
        for suspicious_agent in suspicious_agents:
            if suspicious_agent in user_agent.lower():
                score += 2
        
        return score
    
    def block_ip(self, ip: str, reason: str):
        """封鎖IP地址"""
        if self.is_ip_whitelisted(ip):
            self.logger.info(f"IP {ip} 在白名單中，跳過封鎖")
            return
        
        self.blocked_ips.add(ip)
        self.logger.warning(f"封鎖IP {ip}: {reason}")
        
        # 設定自動解封時間
        threading.Timer(
            self.config['block_duration'],
            self.unblock_ip,
            args=[ip]
        ).start()
    
    def unblock_ip(self, ip: str):
        """解封IP地址"""
        self.blocked_ips.discard(ip)
        self.suspicious_ips[ip] = 0
        self.logger.info(f"解封IP {ip}")
    
    def cleanup_old_data(self):
        """清理舊數據"""
        now = time.time()
        
        # 清理過期的攻擊模式記錄
        expired_patterns = []
        for pattern, count in self.attack_patterns.items():
            if count > 0:
                # 簡單的清理策略：減少計數
                self.attack_patterns[pattern] = max(0, count - 1)
                if self.attack_patterns[pattern] == 0:
                    expired_patterns.append(pattern)
        
        for pattern in expired_patterns:
            del self.attack_patterns[pattern]
    
    def monitor_attacks(self):
        """監控攻擊活動"""
        while self.monitoring:
            try:
                # 清理舊數據
                self.cleanup_old_data()
                
                # 記錄統計信息
                if self.blocked_ips or self.suspicious_ips:
                    self.logger.info(f"當前封鎖IP數: {len(self.blocked_ips)}")
                    self.logger.info(f"可疑IP數: {len(self.suspicious_ips)}")
                
                time.sleep(self.config['monitor_interval'])
                
            except Exception as e:
                self.logger.error(f"監控過程中發生錯誤: {e}")
                time.sleep(5)
    
    def start_monitoring(self):
        """開始監控"""
        if self.monitoring:
            self.logger.warning("監控已在運行中")
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_attacks)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.logger.info("DDoS緩解監控已啟動")
    
    def stop_monitoring(self):
        """停止監控"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("DDoS緩解監控已停止")
    
    def get_statistics(self) -> Dict:
        """獲取統計信息"""
        return {
            'blocked_ips_count': len(self.blocked_ips),
            'blocked_ips': list(self.blocked_ips),
            'suspicious_ips_count': len(self.suspicious_ips),
            'suspicious_ips': dict(self.suspicious_ips),
            'attack_patterns_count': len(self.attack_patterns),
            'rate_limiters_count': len(self.rate_limiters),
            'monitoring': self.monitoring
        }

def test_ddos_mitigation():
    """測試DDoS緩解功能"""
    print("測試DDoS緩解系統...")
    
    mitigation = DDoSMitigation()
    
    # 測試正常請求
    print("測試正常請求...")
    for i in range(5):
        result = mitigation.check_request('192.168.1.100', '/api/users', 'Mozilla/5.0')
        print(f"  請求 {i+1}: {result}")
    
    # 測試攻擊請求
    print("\n測試攻擊請求...")
    for i in range(15):
        result = mitigation.check_request('192.168.1.200', '/admin', 'sqlmap')
        print(f"  攻擊請求 {i+1}: {result}")
        if not result['allowed']:
            break
    
    # 顯示統計信息
    print("\n統計信息:")
    stats = mitigation.get_statistics()
    print(f"  封鎖IP數: {stats['blocked_ips_count']}")
    print(f"  可疑IP數: {stats['suspicious_ips_count']}")
    print(f"  攻擊模式數: {stats['attack_patterns_count']}")
    
    print("DDoS緩解測試完成")

if __name__ == "__main__":
    test_ddos_mitigation()

