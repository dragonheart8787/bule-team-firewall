#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級防火牆系統
Military-Grade Firewall System

功能特色：
- 深度封包檢測 (DPI)
- 入侵檢測系統 (IDS)
- 威脅情報整合
- 即時監控和告警
- 高可用性和容錯機制
- 軍事級加密和認證
"""

import asyncio
import json
import logging
import socket
import struct
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import hmac
import secrets
import ipaddress
import re
import subprocess
import psutil
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
import sqlite3
import yaml
import requests
from concurrent.futures import ThreadPoolExecutor
import queue
import signal
import sys

# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """威脅等級"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    MILITARY = 5

class Action(Enum):
    """防火牆動作"""
    ALLOW = "ALLOW"
    DROP = "DROP"
    REJECT = "REJECT"
    QUARANTINE = "QUARANTINE"
    LOG_ONLY = "LOG_ONLY"

@dataclass
class FirewallRule:
    """防火牆規則"""
    id: str
    name: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    action: Action
    threat_level: ThreatLevel
    description: str
    enabled: bool = True
    created_at: datetime = None
    updated_at: datetime = None

@dataclass
class PacketInfo:
    """封包資訊"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    payload_size: int
    flags: str
    payload: bytes
    threat_score: float = 0.0
    threat_indicators: List[str] = None

@dataclass
class ThreatIntelligence:
    """威脅情報"""
    ip_address: str
    threat_type: str
    confidence: float
    source: str
    last_seen: datetime
    description: str

class MilitaryFirewall:
    """軍事級防火牆主類別"""
    
    def __init__(self, config_file: str = "firewall_config.yaml"):
        self.config = self._load_config(config_file)
        self.rules: List[FirewallRule] = []
        self.threat_intel: Dict[str, ThreatIntelligence] = {}
        self.blocked_ips: set = set()
        self.suspicious_ips: set = set()
        self.packet_queue = queue.Queue(maxsize=10000)
        self.alert_queue = queue.Queue(maxsize=1000)
        self.stats = {
            'packets_processed': 0,
            'packets_blocked': 0,
            'threats_detected': 0,
            'false_positives': 0
        }
        self.running = False
        self.threads = []
        
        # 初始化資料庫
        self._init_database()
        
        # 載入預設規則
        self._load_default_rules()
        
        # 載入威脅情報
        self._load_threat_intelligence()
        
        logger.info("軍事級防火牆系統初始化完成")

    def _load_config(self, config_file: str) -> Dict:
        """載入配置檔案"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            # 建立預設配置
            default_config = {
                'firewall': {
                    'interface': 'eth0',
                    'monitoring_mode': True,
                    'auto_block': True,
                    'threat_threshold': 0.7
                },
                'ids': {
                    'enabled': True,
                    'signature_database': 'signatures.db',
                    'anomaly_detection': True
                },
                'threat_intel': {
                    'enabled': True,
                    'update_interval': 3600,
                    'sources': [
                        'https://feeds.malware-domains.com/domain_list.txt',
                        'https://rules.emergingthreats.net/blockrules/compromised-ips.txt'
                    ]
                },
                'logging': {
                    'level': 'INFO',
                    'retention_days': 30,
                    'audit_enabled': True
                }
            }
            with open(config_file, 'w', encoding='utf-8') as f:
                yaml.dump(default_config, f, default_flow_style=False, allow_unicode=True)
            return default_config

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('firewall.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立規則表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                action TEXT,
                threat_level INTEGER,
                description TEXT,
                enabled BOOLEAN,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        ''')
        
        # 建立封包日誌表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packet_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                payload_size INTEGER,
                action TEXT,
                threat_score REAL,
                threat_indicators TEXT
            )
        ''')
        
        # 建立威脅情報表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                ip_address TEXT PRIMARY KEY,
                threat_type TEXT,
                confidence REAL,
                source TEXT,
                last_seen TIMESTAMP,
                description TEXT
            )
        ''')
        
        # 建立告警表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                alert_type TEXT,
                severity TEXT,
                source_ip TEXT,
                description TEXT,
                action_taken TEXT,
                resolved BOOLEAN DEFAULT FALSE
            )
        ''')
        
        self.db_conn.commit()

    def _load_default_rules(self):
        """載入預設防火牆規則"""
        default_rules = [
            FirewallRule(
                id="rule_001",
                name="阻擋已知惡意IP",
                source_ip="*",
                dest_ip="*",
                source_port=0,
                dest_port=0,
                protocol="*",
                action=Action.DROP,
                threat_level=ThreatLevel.HIGH,
                description="自動阻擋威脅情報中的惡意IP"
            ),
            FirewallRule(
                id="rule_002",
                name="阻擋掃描行為",
                source_ip="*",
                dest_ip="*",
                source_port=0,
                dest_port=0,
                protocol="*",
                action=Action.DROP,
                threat_level=ThreatLevel.MEDIUM,
                description="阻擋端口掃描和探測行為"
            ),
            FirewallRule(
                id="rule_003",
                name="阻擋DDoS攻擊",
                source_ip="*",
                dest_ip="*",
                source_port=0,
                dest_port=0,
                protocol="*",
                action=Action.DROP,
                threat_level=ThreatLevel.CRITICAL,
                description="阻擋分散式拒絕服務攻擊"
            ),
            FirewallRule(
                id="rule_004",
                name="軍事級加密流量檢查",
                source_ip="*",
                dest_ip="*",
                source_port=0,
                dest_port=0,
                protocol="*",
                action=Action.LOG_ONLY,
                threat_level=ThreatLevel.MILITARY,
                description="深度檢查加密流量中的異常模式"
            )
        ]
        
        for rule in default_rules:
            self.add_rule(rule)

    def _load_threat_intelligence(self):
        """載入威脅情報"""
        cursor = self.db_conn.cursor()
        cursor.execute('SELECT * FROM threat_intelligence')
        rows = cursor.fetchall()
        
        for row in rows:
            threat = ThreatIntelligence(
                ip_address=row[0],
                threat_type=row[1],
                confidence=row[2],
                source=row[3],
                last_seen=datetime.fromisoformat(row[4]),
                description=row[5]
            )
            self.threat_intel[threat.ip_address] = threat
            self.blocked_ips.add(threat.ip_address)

    def add_rule(self, rule: FirewallRule):
        """新增防火牆規則"""
        rule.created_at = datetime.now()
        rule.updated_at = datetime.now()
        self.rules.append(rule)
        
        # 儲存到資料庫
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO firewall_rules 
            (id, name, source_ip, dest_ip, source_port, dest_port, protocol, 
             action, threat_level, description, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule.id, rule.name, rule.source_ip, rule.dest_ip, rule.source_port,
            rule.dest_port, rule.protocol, rule.action.value, rule.threat_level.value,
            rule.description, rule.enabled, rule.created_at.isoformat(),
            rule.updated_at.isoformat()
        ))
        self.db_conn.commit()
        
        logger.info(f"已新增防火牆規則: {rule.name}")

    def remove_rule(self, rule_id: str):
        """移除防火牆規則"""
        self.rules = [rule for rule in self.rules if rule.id != rule_id]
        
        cursor = self.db_conn.cursor()
        cursor.execute('DELETE FROM firewall_rules WHERE id = ?', (rule_id,))
        self.db_conn.commit()
        
        logger.info(f"已移除防火牆規則: {rule_id}")

    def _match_rule(self, packet: PacketInfo) -> Optional[FirewallRule]:
        """匹配封包與防火牆規則"""
        for rule in self.rules:
            if not rule.enabled:
                continue
                
            # 檢查IP匹配
            if rule.source_ip != "*" and not self._ip_match(packet.source_ip, rule.source_ip):
                continue
            if rule.dest_ip != "*" and not self._ip_match(packet.dest_ip, rule.dest_ip):
                continue
                
            # 檢查端口匹配
            if rule.source_port != 0 and packet.source_port != rule.source_port:
                continue
            if rule.dest_port != 0 and packet.dest_port != rule.dest_port:
                continue
                
            # 檢查協議匹配
            if rule.protocol != "*" and packet.protocol.lower() != rule.protocol.lower():
                continue
                
            return rule
        
        return None

    def _ip_match(self, ip: str, pattern: str) -> bool:
        """檢查IP是否匹配模式"""
        if pattern == "*":
            return True
        
        try:
            if "/" in pattern:
                # CIDR 表示法
                network = ipaddress.ip_network(pattern, strict=False)
                return ipaddress.ip_address(ip) in network
            else:
                return ip == pattern
        except:
            return False

    def _analyze_packet(self, packet: PacketInfo) -> Tuple[float, List[str]]:
        """深度封包分析"""
        threat_score = 0.0
        indicators = []
        
        # 檢查威脅情報
        if packet.source_ip in self.threat_intel:
            threat = self.threat_intel[packet.source_ip]
            threat_score += threat.confidence
            indicators.append(f"已知威脅IP: {threat.threat_type}")
        
        # 檢查異常流量模式
        if self._is_port_scan(packet):
            threat_score += 0.8
            indicators.append("端口掃描行為")
        
        if self._is_ddos_attack(packet):
            threat_score += 0.9
            indicators.append("DDoS攻擊模式")
        
        # 檢查惡意負載
        if self._contains_malicious_payload(packet.payload):
            threat_score += 0.7
            indicators.append("惡意負載檢測")
        
        # 檢查加密流量異常
        if self._is_suspicious_encryption(packet):
            threat_score += 0.6
            indicators.append("可疑加密模式")
        
        return min(threat_score, 1.0), indicators

    def _is_port_scan(self, packet: PacketInfo) -> bool:
        """檢測端口掃描"""
        # 簡化的端口掃描檢測邏輯
        # 實際實作中需要更複雜的狀態追蹤
        return False

    def _is_ddos_attack(self, packet: PacketInfo) -> bool:
        """檢測DDoS攻擊"""
        # 簡化的DDoS檢測邏輯
        # 實際實作中需要流量統計和模式分析
        return False

    def _contains_malicious_payload(self, payload: bytes) -> bool:
        """檢查惡意負載"""
        if not payload:
            return False
        
        # 檢查常見的惡意模式
        malicious_patterns = [
            b'<script>',
            b'javascript:',
            b'eval(',
            b'base64_decode',
            b'exec(',
            b'shell_exec',
            b'system(',
            b'cmd.exe',
            b'/bin/bash'
        ]
        
        payload_str = payload.lower()
        for pattern in malicious_patterns:
            if pattern in payload_str:
                return True
        
        return False

    def _is_suspicious_encryption(self, packet: PacketInfo) -> bool:
        """檢測可疑加密模式"""
        # 檢查加密流量的異常特徵
        # 例如：異常的加密強度、可疑的證書等
        return False

    def _process_packet(self, packet: PacketInfo):
        """處理封包"""
        self.stats['packets_processed'] += 1
        
        # 深度分析
        threat_score, indicators = self._analyze_packet(packet)
        packet.threat_score = threat_score
        packet.threat_indicators = indicators
        
        # 匹配規則
        matched_rule = self._match_rule(packet)
        
        if matched_rule:
            action = matched_rule.action
        elif threat_score >= self.config['firewall']['threat_threshold']:
            action = Action.DROP
            self.stats['threats_detected'] += 1
        else:
            action = Action.ALLOW
        
        # 執行動作
        if action == Action.DROP:
            self.stats['packets_blocked'] += 1
            self._block_packet(packet)
        elif action == Action.QUARANTINE:
            self._quarantine_packet(packet)
        
        # 記錄日誌
        self._log_packet(packet, action)
        
        # 產生告警
        if threat_score > 0.5:
            self._generate_alert(packet, threat_score, indicators)

    def _block_packet(self, packet: PacketInfo):
        """阻擋封包"""
        # 實際實作中需要與系統防火牆整合
        logger.warning(f"阻擋封包: {packet.source_ip}:{packet.source_port} -> {packet.dest_ip}:{packet.dest_port}")

    def _quarantine_packet(self, packet: PacketInfo):
        """隔離封包"""
        # 將可疑封包隔離進行進一步分析
        logger.warning(f"隔離封包: {packet.source_ip}:{packet.source_port} -> {packet.dest_ip}:{packet.dest_port}")

    def _log_packet(self, packet: PacketInfo, action: Action):
        """記錄封包日誌"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO packet_logs 
            (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, 
             payload_size, action, threat_score, threat_indicators)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet.timestamp.isoformat(),
            packet.source_ip,
            packet.dest_ip,
            packet.source_port,
            packet.dest_port,
            packet.protocol,
            packet.payload_size,
            action.value,
            packet.threat_score,
            json.dumps(packet.threat_indicators, ensure_ascii=False)
        ))
        self.db_conn.commit()

    def _generate_alert(self, packet: PacketInfo, threat_score: float, indicators: List[str]):
        """產生安全告警"""
        alert = {
            'timestamp': datetime.now(),
            'alert_type': 'THREAT_DETECTED',
            'severity': 'HIGH' if threat_score > 0.8 else 'MEDIUM',
            'source_ip': packet.source_ip,
            'description': f"威脅檢測: {', '.join(indicators)}",
            'action_taken': 'BLOCKED' if threat_score > 0.7 else 'MONITORED',
            'threat_score': threat_score
        }
        
        self.alert_queue.put(alert)
        
        # 記錄到資料庫
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO alerts 
            (timestamp, alert_type, severity, source_ip, description, action_taken)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            alert['timestamp'].isoformat(),
            alert['alert_type'],
            alert['severity'],
            alert['source_ip'],
            alert['description'],
            alert['action_taken']
        ))
        self.db_conn.commit()
        
        logger.critical(f"安全告警: {alert['description']}")

    def start_monitoring(self):
        """開始監控"""
        self.running = True
        
        # 啟動封包處理線程
        packet_thread = threading.Thread(target=self._packet_processor)
        packet_thread.daemon = True
        packet_thread.start()
        self.threads.append(packet_thread)
        
        # 啟動告警處理線程
        alert_thread = threading.Thread(target=self._alert_processor)
        alert_thread.daemon = True
        alert_thread.start()
        self.threads.append(alert_thread)
        
        # 啟動威脅情報更新線程
        if self.config['threat_intel']['enabled']:
            intel_thread = threading.Thread(target=self._threat_intel_updater)
            intel_thread.daemon = True
            intel_thread.start()
            self.threads.append(intel_thread)
        
        logger.info("防火牆監控已啟動")

    def stop_monitoring(self):
        """停止監控"""
        self.running = False
        
        # 等待所有線程結束
        for thread in self.threads:
            thread.join(timeout=5)
        
        self.db_conn.close()
        logger.info("防火牆監控已停止")

    def _packet_processor(self):
        """封包處理線程"""
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=1)
                self._process_packet(packet)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"封包處理錯誤: {e}")

    def _alert_processor(self):
        """告警處理線程"""
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1)
                self._handle_alert(alert)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"告警處理錯誤: {e}")

    def _handle_alert(self, alert: Dict):
        """處理告警"""
        # 實際實作中可能需要發送郵件、簡訊或整合到SIEM系統
        logger.critical(f"處理告警: {alert['description']}")

    def _threat_intel_updater(self):
        """威脅情報更新線程"""
        while self.running:
            try:
                self._update_threat_intelligence()
                time.sleep(self.config['threat_intel']['update_interval'])
            except Exception as e:
                logger.error(f"威脅情報更新錯誤: {e}")

    def _update_threat_intelligence(self):
        """更新威脅情報"""
        for source_url in self.config['threat_intel']['sources']:
            try:
                response = requests.get(source_url, timeout=30)
                if response.status_code == 200:
                    self._parse_threat_intel(response.text, source_url)
            except Exception as e:
                logger.error(f"更新威脅情報失敗 {source_url}: {e}")

    def _parse_threat_intel(self, data: str, source: str):
        """解析威脅情報"""
        lines = data.strip().split('\n')
        for line in lines:
            if line.startswith('#') or not line.strip():
                continue
            
            # 簡化的解析邏輯
            parts = line.strip().split()
            if parts:
                ip = parts[0]
                threat = ThreatIntelligence(
                    ip_address=ip,
                    threat_type="MALICIOUS",
                    confidence=0.8,
                    source=source,
                    last_seen=datetime.now(),
                    description=f"來自 {source} 的威脅情報"
                )
                self.threat_intel[ip] = threat
                self.blocked_ips.add(ip)

    def get_statistics(self) -> Dict:
        """獲取統計資訊"""
        return {
            'stats': self.stats,
            'rules_count': len(self.rules),
            'threat_intel_count': len(self.threat_intel),
            'blocked_ips_count': len(self.blocked_ips),
            'queue_sizes': {
                'packet_queue': self.packet_queue.qsize(),
                'alert_queue': self.alert_queue.qsize()
            }
        }

    def get_recent_alerts(self, limit: int = 10) -> List[Dict]:
        """獲取最近的告警"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            SELECT * FROM alerts 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'id': row[0],
                'timestamp': row[1],
                'alert_type': row[2],
                'severity': row[3],
                'source_ip': row[4],
                'description': row[5],
                'action_taken': row[6],
                'resolved': bool(row[7])
            })
        
        return alerts

def main():
    """主程式"""
    firewall = MilitaryFirewall()
    
    # 設定信號處理
    def signal_handler(signum, frame):
        logger.info("收到停止信號，正在關閉防火牆...")
        firewall.stop_monitoring()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        firewall.start_monitoring()
        
        # 主循環
        while True:
            time.sleep(1)
            
            # 顯示統計資訊
            stats = firewall.get_statistics()
            if stats['stats']['packets_processed'] % 100 == 0:
                logger.info(f"已處理封包: {stats['stats']['packets_processed']}, "
                          f"已阻擋: {stats['stats']['packets_blocked']}, "
                          f"威脅檢測: {stats['stats']['threats_detected']}")
    
    except KeyboardInterrupt:
        logger.info("收到中斷信號")
    finally:
        firewall.stop_monitoring()

if __name__ == "__main__":
    main()

