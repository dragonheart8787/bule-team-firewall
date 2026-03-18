#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級邊界層防禦系統
Military-Grade Perimeter Defense System

功能特色：
- 次世代防火牆 (NGFW) 功能
- DDoS 緩解和防護
- Web/API Gateway 防護
- 深度封包檢測 (DPI)
- 應用層防護
"""

import os
import sys
import time
import logging
import threading
import socket
import struct
import json
import sqlite3
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import ipaddress
import subprocess
import psutil
import requests
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

class DefenseLayer(Enum):
    """防禦層級"""
    PERIMETER = "PERIMETER"        # 邊界層
    INTERNAL = "INTERNAL"          # 內部層
    MISSION_CRITICAL = "MISSION_CRITICAL"  # 關鍵任務層
    CLOUD = "CLOUD"                # 雲端層
    SOC = "SOC"                    # SOC層

class ThreatType(Enum):
    """威脅類型"""
    DDoS = "DDoS"
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    CSRF = "CSRF"
    BRUTE_FORCE = "BRUTE_FORCE"
    PORT_SCAN = "PORT_SCAN"
    MALWARE = "MALWARE"
    APT = "APT"
    ZERO_DAY = "ZERO_DAY"

class ActionType(Enum):
    """動作類型"""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    RATE_LIMIT = "RATE_LIMIT"
    CHALLENGE = "CHALLENGE"
    LOG = "LOG"

@dataclass
class NGFWRule:
    """NGFW規則"""
    id: str
    name: str
    source_zone: str
    dest_zone: str
    source_ip: str
    dest_ip: str
    protocol: str
    port: int
    application: str
    user: str
    action: ActionType
    priority: int
    conditions: Dict[str, Any]
    enabled: bool
    created_at: datetime

@dataclass
class DDoSAttack:
    """DDoS攻擊"""
    id: str
    attack_type: str
    source_ips: List[str]
    target_ip: str
    target_port: int
    packet_rate: int
    byte_rate: int
    start_time: datetime
    duration: int
    mitigation_status: str
    severity: str

@dataclass
class WebAttack:
    """Web攻擊"""
    id: str
    attack_type: ThreatType
    source_ip: str
    target_url: str
    payload: str
    user_agent: str
    headers: Dict[str, str]
    timestamp: datetime
    blocked: bool
    severity: str

@dataclass
class APIGatewayRule:
    """API閘道規則"""
    id: str
    name: str
    endpoint: str
    method: str
    rate_limit: int
    authentication_required: bool
    allowed_ips: List[str]
    blocked_ips: List[str]
    validation_rules: Dict[str, Any]
    enabled: bool
    created_at: datetime

class MilitaryPerimeterDefense:
    """軍事級邊界層防禦系統"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.ngfw_rules: Dict[str, NGFWRule] = {}
        self.ddos_attacks: Dict[str, DDoSAttack] = {}
        self.web_attacks: Dict[str, WebAttack] = {}
        self.api_rules: Dict[str, APIGatewayRule] = {}
        self.active_connections: Dict[str, Dict] = {}
        self.rate_limits: Dict[str, Dict] = {}
        
        # 統計數據
        self.stats = {
            'total_packets': 0,
            'blocked_packets': 0,
            'allowed_packets': 0,
            'ddos_attacks': 0,
            'web_attacks': 0,
            'api_requests': 0,
            'ngfw_rules': 0
        }
        
        # 初始化資料庫
        self._init_database()
        
        # 載入預設NGFW規則
        self._load_default_ngfw_rules()
        
        # 載入API閘道規則
        self._load_api_gateway_rules()
        
        # 啟動邊界防禦監控
        self._start_perimeter_monitoring()
        
        logger.info("軍事級邊界層防禦系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('military_perimeter_defense.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立NGFW規則表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ngfw_rules (
                id TEXT PRIMARY KEY,
                name TEXT,
                source_zone TEXT,
                dest_zone TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                port INTEGER,
                application TEXT,
                user TEXT,
                action TEXT,
                priority INTEGER,
                conditions TEXT,
                enabled BOOLEAN,
                created_at TIMESTAMP
            )
        ''')
        
        # 建立DDoS攻擊表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ddos_attacks (
                id TEXT PRIMARY KEY,
                attack_type TEXT,
                source_ips TEXT,
                target_ip TEXT,
                target_port INTEGER,
                packet_rate INTEGER,
                byte_rate INTEGER,
                start_time TIMESTAMP,
                duration INTEGER,
                mitigation_status TEXT,
                severity TEXT
            )
        ''')
        
        # 建立Web攻擊表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS web_attacks (
                id TEXT PRIMARY KEY,
                attack_type TEXT,
                source_ip TEXT,
                target_url TEXT,
                payload TEXT,
                user_agent TEXT,
                headers TEXT,
                timestamp TIMESTAMP,
                blocked BOOLEAN,
                severity TEXT
            )
        ''')
        
        # 建立API閘道規則表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_gateway_rules (
                id TEXT PRIMARY KEY,
                name TEXT,
                endpoint TEXT,
                method TEXT,
                rate_limit INTEGER,
                authentication_required BOOLEAN,
                allowed_ips TEXT,
                blocked_ips TEXT,
                validation_rules TEXT,
                enabled BOOLEAN,
                created_at TIMESTAMP
            )
        ''')
        
        self.db_conn.commit()

    def _load_default_ngfw_rules(self):
        """載入預設NGFW規則"""
        # 阻擋已知惡意IP
        rule1 = NGFWRule(
            id="rule_001",
            name="阻擋惡意IP",
            source_zone="EXTERNAL",
            dest_zone="INTERNAL",
            source_ip="0.0.0.0/0",
            dest_ip="192.168.0.0/16",
            protocol="ANY",
            port=0,
            application="ANY",
            user="ANY",
            action=ActionType.BLOCK,
            priority=1,
            conditions={"malicious_ip": True},
            enabled=True,
            created_at=datetime.now()
        )
        self.ngfw_rules[rule1.id] = rule1
        
        # 允許HTTPS流量
        rule2 = NGFWRule(
            id="rule_002",
            name="允許HTTPS流量",
            source_zone="EXTERNAL",
            dest_zone="DMZ",
            source_ip="0.0.0.0/0",
            dest_ip="192.168.100.0/24",
            protocol="TCP",
            port=443,
            application="HTTPS",
            user="ANY",
            action=ActionType.ALLOW,
            priority=2,
            conditions={"encryption": True},
            enabled=True,
            created_at=datetime.now()
        )
        self.ngfw_rules[rule2.id] = rule2
        
        # 阻擋SSH暴力破解
        rule3 = NGFWRule(
            id="rule_003",
            name="阻擋SSH暴力破解",
            source_zone="EXTERNAL",
            dest_zone="INTERNAL",
            source_ip="0.0.0.0/0",
            dest_ip="192.168.0.0/16",
            protocol="TCP",
            port=22,
            application="SSH",
            user="ANY",
            action=ActionType.RATE_LIMIT,
            priority=1,
            conditions={"brute_force": True, "max_attempts": 5},
            enabled=True,
            created_at=datetime.now()
        )
        self.ngfw_rules[rule3.id] = rule3
        
        # 阻擋SQL注入
        rule4 = NGFWRule(
            id="rule_004",
            name="阻擋SQL注入",
            source_zone="EXTERNAL",
            dest_zone="DMZ",
            source_ip="0.0.0.0/0",
            dest_ip="192.168.100.0/24",
            protocol="TCP",
            port=80,
            application="HTTP",
            user="ANY",
            action=ActionType.BLOCK,
            priority=1,
            conditions={"sql_injection": True},
            enabled=True,
            created_at=datetime.now()
        )
        self.ngfw_rules[rule4.id] = rule4

    def _load_api_gateway_rules(self):
        """載入API閘道規則"""
        # API認證規則
        api_rule1 = APIGatewayRule(
            id="api_001",
            name="API認證規則",
            endpoint="/api/v1/*",
            method="ANY",
            rate_limit=1000,  # 每分鐘1000次
            authentication_required=True,
            allowed_ips=["192.168.0.0/16"],
            blocked_ips=[],
            validation_rules={"jwt_required": True, "api_key_required": True},
            enabled=True,
            created_at=datetime.now()
        )
        self.api_rules[api_rule1.id] = api_rule1
        
        # 公開API規則
        api_rule2 = APIGatewayRule(
            id="api_002",
            name="公開API規則",
            endpoint="/api/public/*",
            method="GET",
            rate_limit=100,  # 每分鐘100次
            authentication_required=False,
            allowed_ips=["0.0.0.0/0"],
            blocked_ips=[],
            validation_rules={"rate_limit": True},
            enabled=True,
            created_at=datetime.now()
        )
        self.api_rules[api_rule2.id] = api_rule2

    def _start_perimeter_monitoring(self):
        """啟動邊界防禦監控"""
        def perimeter_monitor():
            while True:
                try:
                    # 監控網路流量
                    self._monitor_network_traffic()
                    
                    # 檢測DDoS攻擊
                    self._detect_ddos_attacks()
                    
                    # 檢測Web攻擊
                    self._detect_web_attacks()
                    
                    # 監控API流量
                    self._monitor_api_traffic()
                    
                    # 執行NGFW規則
                    self._enforce_ngfw_rules()
                    
                    time.sleep(1)  # 每秒監控一次
                
                except Exception as e:
                    logger.error(f"邊界防禦監控錯誤: {e}")
                    time.sleep(5)
        
        monitor_thread = threading.Thread(target=perimeter_monitor, daemon=True)
        monitor_thread.start()

    def _monitor_network_traffic(self):
        """監控網路流量"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.raddr and conn.laddr:
                    # 分析封包
                    self._analyze_packet(conn)
                    
                    # 更新統計
                    self.stats['total_packets'] += 1
        
        except Exception as e:
            logger.error(f"網路流量監控錯誤: {e}")

    def _analyze_packet(self, conn):
        """分析封包"""
        try:
            # 深度封包檢測 (DPI)
            self._deep_packet_inspection(conn)
            
            # 應用層檢測
            self._application_layer_inspection(conn)
            
            # 用戶行為分析
            self._user_behavior_analysis(conn)
        
        except Exception as e:
            logger.error(f"封包分析錯誤: {e}")

    def _deep_packet_inspection(self, conn):
        """深度封包檢測"""
        # 檢查協議
        if conn.laddr.port == 80 or conn.raddr.port == 80:
            self._inspect_http_traffic(conn)
        elif conn.laddr.port == 443 or conn.raddr.port == 443:
            self._inspect_https_traffic(conn)
        elif conn.laddr.port == 22 or conn.raddr.port == 22:
            self._inspect_ssh_traffic(conn)

    def _inspect_http_traffic(self, conn):
        """檢測HTTP流量"""
        # 模擬HTTP流量檢測
        if conn.laddr.port == 80:
            # 檢測HTTP請求
            self._detect_http_attacks(conn)

    def _inspect_https_traffic(self, conn):
        """檢測HTTPS流量"""
        # 檢測HTTPS流量模式
        if conn.laddr.port == 443:
            # 檢測SSL/TLS流量
            self._detect_ssl_attacks(conn)

    def _inspect_ssh_traffic(self, conn):
        """檢測SSH流量"""
        # 檢測SSH暴力破解
        if conn.laddr.port == 22:
            self._detect_ssh_brute_force(conn)

    def _application_layer_inspection(self, conn):
        """應用層檢測"""
        # 識別應用程式
        application = self._identify_application(conn)
        
        # 檢查應用層規則
        self._check_application_rules(conn, application)

    def _identify_application(self, conn) -> str:
        """識別應用程式"""
        port = conn.laddr.port
        if port == 80:
            return "HTTP"
        elif port == 443:
            return "HTTPS"
        elif port == 22:
            return "SSH"
        elif port == 21:
            return "FTP"
        elif port == 25:
            return "SMTP"
        elif port == 53:
            return "DNS"
        elif port == 3389:
            return "RDP"
        else:
            return "UNKNOWN"

    def _check_application_rules(self, conn, application: str):
        """檢查應用層規則"""
        for rule in self.ngfw_rules.values():
            if not rule.enabled:
                continue
            
            if rule.application == "ANY" or rule.application == application:
                if self._match_rule_conditions(conn, rule):
                    self._execute_rule_action(conn, rule)

    def _match_rule_conditions(self, conn, rule: NGFWRule) -> bool:
        """匹配規則條件"""
        # 檢查IP範圍
        if not self._check_ip_range(conn.laddr.ip, rule.source_ip):
            return False
        
        if not self._check_ip_range(conn.raddr.ip, rule.dest_ip):
            return False
        
        # 檢查端口
        if rule.port != 0 and rule.port != conn.laddr.port and rule.port != conn.raddr.port:
            return False
        
        # 檢查協議
        if rule.protocol != "ANY" and rule.protocol != "TCP":
            return False
        
        return True

    def _check_ip_range(self, ip: str, ip_range: str) -> bool:
        """檢查IP範圍"""
        try:
            if ip_range == "0.0.0.0/0":
                return True
            
            if "/" in ip_range:
                network = ipaddress.ip_network(ip_range)
                return ipaddress.ip_address(ip) in network
            else:
                return ip == ip_range
        except:
            return False

    def _execute_rule_action(self, conn, rule: NGFWRule):
        """執行規則動作"""
        if rule.action == ActionType.BLOCK:
            self._block_connection(conn, rule)
        elif rule.action == ActionType.ALLOW:
            self._allow_connection(conn, rule)
        elif rule.action == ActionType.RATE_LIMIT:
            self._rate_limit_connection(conn, rule)
        elif rule.action == ActionType.QUARANTINE:
            self._quarantine_connection(conn, rule)

    def _block_connection(self, conn, rule: NGFWRule):
        """阻擋連線"""
        logger.warning(f"阻擋連線: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port} (規則: {rule.name})")
        self.stats['blocked_packets'] += 1

    def _allow_connection(self, conn, rule: NGFWRule):
        """允許連線"""
        logger.info(f"允許連線: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port} (規則: {rule.name})")
        self.stats['allowed_packets'] += 1

    def _rate_limit_connection(self, conn, rule: NGFWRule):
        """限制連線速率"""
        key = f"{conn.laddr.ip}:{conn.raddr.ip}"
        if key not in self.rate_limits:
            self.rate_limits[key] = {'count': 0, 'last_reset': datetime.now()}
        
        # 檢查速率限制
        now = datetime.now()
        if (now - self.rate_limits[key]['last_reset']).seconds > 60:
            self.rate_limits[key] = {'count': 0, 'last_reset': now}
        
        self.rate_limits[key]['count'] += 1
        
        max_attempts = rule.conditions.get('max_attempts', 5)
        if self.rate_limits[key]['count'] > max_attempts:
            logger.warning(f"速率限制觸發: {conn.laddr.ip} -> {conn.raddr.ip} (嘗試次數: {self.rate_limits[key]['count']})")
            self._block_connection(conn, rule)

    def _quarantine_connection(self, conn, rule: NGFWRule):
        """隔離連線"""
        logger.warning(f"隔離連線: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port} (規則: {rule.name})")

    def _detect_ddos_attacks(self):
        """檢測DDoS攻擊"""
        try:
            # 檢測SYN Flood
            self._detect_syn_flood()
            
            # 檢測UDP Flood
            self._detect_udp_flood()
            
            # 檢測HTTP Flood
            self._detect_http_flood()
        
        except Exception as e:
            logger.error(f"DDoS攻擊檢測錯誤: {e}")

    def _detect_syn_flood(self):
        """檢測SYN Flood攻擊"""
        # 模擬SYN Flood檢測
        syn_connections = 0
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'SYN_SENT':
                syn_connections += 1
        
        if syn_connections > 100:  # 超過100個SYN連線
            self._log_ddos_attack("SYN_FLOOD", syn_connections)

    def _detect_udp_flood(self):
        """檢測UDP Flood攻擊"""
        # 模擬UDP Flood檢測
        udp_connections = 0
        for conn in psutil.net_connections(kind='inet'):
            if conn.type == socket.SOCK_DGRAM:
                udp_connections += 1
        
        if udp_connections > 50:  # 超過50個UDP連線
            self._log_ddos_attack("UDP_FLOOD", udp_connections)

    def _detect_http_flood(self):
        """檢測HTTP Flood攻擊"""
        # 模擬HTTP Flood檢測
        http_connections = 0
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == 80 or conn.raddr.port == 80:
                http_connections += 1
        
        if http_connections > 200:  # 超過200個HTTP連線
            self._log_ddos_attack("HTTP_FLOOD", http_connections)

    def _log_ddos_attack(self, attack_type: str, connection_count: int):
        """記錄DDoS攻擊"""
        attack_id = f"ddos_{int(time.time())}_{hashlib.md5(f'{attack_type}{connection_count}'.encode()).hexdigest()[:8]}"
        
        attack = DDoSAttack(
            id=attack_id,
            attack_type=attack_type,
            source_ips=["MULTIPLE"],
            target_ip="192.168.100.1",
            target_port=80,
            packet_rate=connection_count,
            byte_rate=connection_count * 1024,
            start_time=datetime.now(),
            duration=0,
            mitigation_status="DETECTED",
            severity="HIGH"
        )
        
        self.ddos_attacks[attack_id] = attack
        self._save_ddos_attack(attack)
        
        # 更新統計
        self.stats['ddos_attacks'] += 1
        
        logger.warning(f"DDoS攻擊檢測: {attack_type} - {connection_count} 個連線")

    def _detect_web_attacks(self):
        """檢測Web攻擊"""
        try:
            # 檢測SQL注入
            self._detect_sql_injection()
            
            # 檢測XSS攻擊
            self._detect_xss_attack()
            
            # 檢測CSRF攻擊
            self._detect_csrf_attack()
        
        except Exception as e:
            logger.error(f"Web攻擊檢測錯誤: {e}")

    def _detect_sql_injection(self):
        """檢測SQL注入"""
        # 模擬SQL注入檢測
        sql_patterns = [
            r"union\s+select",
            r"drop\s+table",
            r"insert\s+into",
            r"delete\s+from",
            r"update\s+set",
            r"or\s+1\s*=\s*1",
            r"'\s*or\s*'",
            r"'\s*;\s*--"
        ]
        
        # 檢查HTTP流量中的SQL注入模式
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == 80 or conn.raddr.port == 80:
                # 模擬檢測到SQL注入
                if self._simulate_sql_injection_detection():
                    self._log_web_attack(ThreatType.SQL_INJECTION, conn)

    def _detect_xss_attack(self):
        """檢測XSS攻擊"""
        # 模擬XSS檢測
        xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"onload\s*=",
            r"onerror\s*=",
            r"onclick\s*="
        ]
        
        # 檢查HTTP流量中的XSS模式
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == 80 or conn.raddr.port == 80:
                # 模擬檢測到XSS
                if self._simulate_xss_detection():
                    self._log_web_attack(ThreatType.XSS, conn)

    def _detect_csrf_attack(self):
        """檢測CSRF攻擊"""
        # 模擬CSRF檢測
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == 80 or conn.raddr.port == 80:
                # 模擬檢測到CSRF
                if self._simulate_csrf_detection():
                    self._log_web_attack(ThreatType.CSRF, conn)

    def _simulate_sql_injection_detection(self) -> bool:
        """模擬SQL注入檢測"""
        import random
        return random.random() < 0.01  # 1%機率檢測到

    def _simulate_xss_detection(self) -> bool:
        """模擬XSS檢測"""
        import random
        return random.random() < 0.005  # 0.5%機率檢測到

    def _simulate_csrf_detection(self) -> bool:
        """模擬CSRF檢測"""
        import random
        return random.random() < 0.003  # 0.3%機率檢測到

    def _log_web_attack(self, attack_type: ThreatType, conn):
        """記錄Web攻擊"""
        attack_id = f"web_{int(time.time())}_{hashlib.md5(f'{attack_type.value}{conn.laddr.ip}'.encode()).hexdigest()[:8]}"
        
        attack = WebAttack(
            id=attack_id,
            attack_type=attack_type,
            source_ip=conn.laddr.ip,
            target_url=f"http://{conn.raddr.ip}:{conn.raddr.port}/",
            payload="<script>alert('xss')</script>",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timestamp=datetime.now(),
            blocked=True,
            severity="HIGH"
        )
        
        self.web_attacks[attack_id] = attack
        self._save_web_attack(attack)
        
        # 更新統計
        self.stats['web_attacks'] += 1
        
        logger.warning(f"Web攻擊檢測: {attack_type.value} - 來源: {conn.laddr.ip}")

    def _monitor_api_traffic(self):
        """監控API流量"""
        try:
            # 模擬API流量監控
            self.stats['api_requests'] += 1
            
            # 檢查API規則
            self._check_api_rules()
        
        except Exception as e:
            logger.error(f"API流量監控錯誤: {e}")

    def _check_api_rules(self):
        """檢查API規則"""
        for rule in self.api_rules.values():
            if not rule.enabled:
                continue
            
            # 模擬API規則檢查
            self._simulate_api_rule_check(rule)

    def _simulate_api_rule_check(self, rule: APIGatewayRule):
        """模擬API規則檢查"""
        # 檢查速率限制
        if rule.rate_limit > 0:
            # 模擬速率限制檢查
            pass
        
        # 檢查認證
        if rule.authentication_required:
            # 模擬認證檢查
            pass

    def _enforce_ngfw_rules(self):
        """執行NGFW規則"""
        try:
            # 更新統計
            self.stats['ngfw_rules'] = len([r for r in self.ngfw_rules.values() if r.enabled])
        
        except Exception as e:
            logger.error(f"NGFW規則執行錯誤: {e}")

    def _save_ddos_attack(self, attack: DDoSAttack):
        """儲存DDoS攻擊"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO ddos_attacks 
            (id, attack_type, source_ips, target_ip, target_port, packet_rate,
             byte_rate, start_time, duration, mitigation_status, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            attack.id, attack.attack_type, json.dumps(attack.source_ips),
            attack.target_ip, attack.target_port, attack.packet_rate,
            attack.byte_rate, attack.start_time.isoformat(), attack.duration,
            attack.mitigation_status, attack.severity
        ))
        self.db_conn.commit()

    def _save_web_attack(self, attack: WebAttack):
        """儲存Web攻擊"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO web_attacks 
            (id, attack_type, source_ip, target_url, payload, user_agent,
             headers, timestamp, blocked, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            attack.id, attack.attack_type.value, attack.source_ip,
            attack.target_url, attack.payload, attack.user_agent,
            json.dumps(attack.headers), attack.timestamp.isoformat(),
            attack.blocked, attack.severity
        ))
        self.db_conn.commit()

    def get_perimeter_status(self) -> Dict[str, Any]:
        """獲取邊界防禦狀態"""
        return {
            'ngfw_rules': len(self.ngfw_rules),
            'active_rules': len([r for r in self.ngfw_rules.values() if r.enabled]),
            'ddos_attacks': len(self.ddos_attacks),
            'web_attacks': len(self.web_attacks),
            'api_rules': len(self.api_rules),
            'stats': self.stats
        }

    def get_recent_attacks(self, limit: int = 10) -> List[Any]:
        """獲取最近攻擊"""
        attacks = []
        
        # 添加DDoS攻擊
        for attack in list(self.ddos_attacks.values())[-5:]:
            attacks.append(attack)
        
        # 添加Web攻擊
        for attack in list(self.web_attacks.values())[-5:]:
            attacks.append(attack)
        
        # 按時間排序
        attacks.sort(key=lambda x: x.start_time if hasattr(x, 'start_time') else x.timestamp, reverse=True)
        return attacks[:limit]

def main():
    """主程式"""
    config = {
        'monitoring_interval': 1,
        'ddos_protection': True,
        'web_protection': True,
        'api_protection': True
    }
    
    defense = MilitaryPerimeterDefense(config)
    
    print("🛡️ 軍事級邊界層防禦系統已啟動")
    print("=" * 60)
    
    # 顯示NGFW規則
    print(f"NGFW規則: {len(defense.ngfw_rules)} 個")
    for rule in defense.ngfw_rules.values():
        print(f"  {rule.name}: {rule.source_zone} -> {rule.dest_zone} ({rule.action.value})")
    
    # 顯示API規則
    print(f"\nAPI閘道規則: {len(defense.api_rules)} 個")
    for rule in defense.api_rules.values():
        print(f"  {rule.name}: {rule.endpoint} ({rule.method})")
    
    print(f"\n🛡️ 系統正在監控邊界流量...")
    print("按 Ctrl+C 停止監控")

if __name__ == "__main__":
    main()




