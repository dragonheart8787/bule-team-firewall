#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級網路深度防禦系統
Military-Grade Network Defense-in-Depth System

功能特色：
- 全網段流量檢測和分析
- 分區隔離和微分段防護
- 東西向流量深度分析
- 軍事級網路安全架構
- 多層次防禦策略
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
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import ipaddress
import subprocess
import psutil
import hashlib
import re

logger = logging.getLogger(__name__)

class NetworkZone(Enum):
    """網路區域"""
    DMZ = "DMZ"                    # 非軍事區
    CORE = "CORE"                  # 核心區
    MISSION = "MISSION"            # 任務系統區
    MANAGEMENT = "MANAGEMENT"      # 管理區
    EXTERNAL = "EXTERNAL"          # 外部區
    INTERNAL = "INTERNAL"          # 內部區

class TrafficDirection(Enum):
    """流量方向"""
    INBOUND = "INBOUND"            # 入站
    OUTBOUND = "OUTBOUND"          # 出站
    LATERAL = "LATERAL"            # 橫向移動
    CROSS_ZONE = "CROSS_ZONE"      # 跨區域

class ThreatLevel(Enum):
    """威脅等級"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    MILITARY_CRITICAL = "MILITARY_CRITICAL"

@dataclass
class NetworkSegment:
    """網路段"""
    id: str
    name: str
    zone: NetworkZone
    network: str                    # CIDR格式
    gateway: str
    dns_servers: List[str]
    allowed_protocols: List[str]
    allowed_ports: List[int]
    blocked_ips: List[str]
    trusted_devices: List[str]
    security_policy: str
    created_at: datetime

@dataclass
class TrafficFlow:
    """流量流"""
    id: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    direction: TrafficDirection
    source_zone: NetworkZone
    dest_zone: NetworkZone
    packet_count: int
    byte_count: int
    start_time: datetime
    last_seen: datetime
    is_encrypted: bool
    application: str
    user: str
    risk_score: float

@dataclass
class SecurityPolicy:
    """安全策略"""
    id: str
    name: str
    source_zone: NetworkZone
    dest_zone: NetworkZone
    protocol: str
    port: int
    action: str                     # ALLOW, DENY, QUARANTINE
    priority: int
    conditions: Dict[str, Any]
    enabled: bool
    created_at: datetime

@dataclass
class ThreatDetection:
    """威脅檢測"""
    id: str
    threat_type: str
    source_ip: str
    dest_ip: str
    protocol: str
    port: int
    description: str
    threat_level: ThreatLevel
    indicators: List[str]
    mitigation: str
    detected_at: datetime
    zone: NetworkZone

class MilitaryNetworkDefense:
    """軍事級網路深度防禦系統"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.network_segments: Dict[str, NetworkSegment] = {}
        self.traffic_flows: Dict[str, TrafficFlow] = {}
        self.security_policies: Dict[str, SecurityPolicy] = {}
        self.threat_detections: Dict[str, ThreatDetection] = {}
        self.active_connections: Dict[str, Dict] = {}
        
        # 統計數據
        self.stats = {
            'total_packets': 0,
            'blocked_packets': 0,
            'allowed_packets': 0,
            'threats_detected': 0,
            'zones_monitored': 0,
            'policies_active': 0
        }
        
        # 初始化資料庫
        self._init_database()
        
        # 載入預設網路架構
        self._load_default_network_architecture()
        
        # 載入軍事級安全策略
        self._load_military_security_policies()
        
        # 啟動網路監控
        self._start_network_monitoring()
        
        logger.info("軍事級網路深度防禦系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('military_network_defense.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立網路段表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_segments (
                id TEXT PRIMARY KEY,
                name TEXT,
                zone TEXT,
                network TEXT,
                gateway TEXT,
                dns_servers TEXT,
                allowed_protocols TEXT,
                allowed_ports TEXT,
                blocked_ips TEXT,
                trusted_devices TEXT,
                security_policy TEXT,
                created_at TIMESTAMP
            )
        ''')
        
        # 建立流量流表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_flows (
                id TEXT PRIMARY KEY,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                direction TEXT,
                source_zone TEXT,
                dest_zone TEXT,
                packet_count INTEGER,
                byte_count INTEGER,
                start_time TIMESTAMP,
                last_seen TIMESTAMP,
                is_encrypted BOOLEAN,
                application TEXT,
                user TEXT,
                risk_score REAL
            )
        ''')
        
        # 建立安全策略表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_policies (
                id TEXT PRIMARY KEY,
                name TEXT,
                source_zone TEXT,
                dest_zone TEXT,
                protocol TEXT,
                port INTEGER,
                action TEXT,
                priority INTEGER,
                conditions TEXT,
                enabled BOOLEAN,
                created_at TIMESTAMP
            )
        ''')
        
        # 建立威脅檢測表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_detections (
                id TEXT PRIMARY KEY,
                threat_type TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                port INTEGER,
                description TEXT,
                threat_level TEXT,
                indicators TEXT,
                mitigation TEXT,
                detected_at TIMESTAMP,
                zone TEXT
            )
        ''')
        
        self.db_conn.commit()

    def _load_default_network_architecture(self):
        """載入預設網路架構"""
        # DMZ區域
        dmz_segment = NetworkSegment(
            id="dmz_zone",
            name="非軍事區",
            zone=NetworkZone.DMZ,
            network="192.168.100.0/24",
            gateway="192.168.100.1",
            dns_servers=["8.8.8.8", "8.8.4.4"],
            allowed_protocols=["TCP", "UDP", "ICMP"],
            allowed_ports=[80, 443, 22, 25, 53],
            blocked_ips=[],
            trusted_devices=[],
            security_policy="RESTRICTED",
            created_at=datetime.now()
        )
        self.network_segments[dmz_segment.id] = dmz_segment
        
        # 核心區
        core_segment = NetworkSegment(
            id="core_zone",
            name="核心區",
            zone=NetworkZone.CORE,
            network="192.168.10.0/24",
            gateway="192.168.10.1",
            dns_servers=["192.168.10.1"],
            allowed_protocols=["TCP", "UDP"],
            allowed_ports=[443, 22, 3389, 5985, 5986],
            blocked_ips=[],
            trusted_devices=[],
            security_policy="HIGHLY_RESTRICTED",
            created_at=datetime.now()
        )
        self.network_segments[core_segment.id] = core_segment
        
        # 任務系統區
        mission_segment = NetworkSegment(
            id="mission_zone",
            name="任務系統區",
            zone=NetworkZone.MISSION,
            network="192.168.20.0/24",
            gateway="192.168.20.1",
            dns_servers=["192.168.20.1"],
            allowed_protocols=["TCP"],
            allowed_ports=[443, 22],
            blocked_ips=[],
            trusted_devices=[],
            security_policy="MILITARY_CRITICAL",
            created_at=datetime.now()
        )
        self.network_segments[mission_segment.id] = mission_segment
        
        # 管理區
        mgmt_segment = NetworkSegment(
            id="mgmt_zone",
            name="管理區",
            zone=NetworkZone.MANAGEMENT,
            network="192.168.30.0/24",
            gateway="192.168.30.1",
            dns_servers=["192.168.30.1"],
            allowed_protocols=["TCP", "UDP", "ICMP"],
            allowed_ports=[80, 443, 22, 3389, 161, 162],
            blocked_ips=[],
            trusted_devices=[],
            security_policy="MANAGEMENT",
            created_at=datetime.now()
        )
        self.network_segments[mgmt_segment.id] = mgmt_segment

    def _load_military_security_policies(self):
        """載入軍事級安全策略"""
        # 禁止外部到核心區的直接連線
        policy1 = SecurityPolicy(
            id="policy_001",
            name="禁止外部到核心區連線",
            source_zone=NetworkZone.EXTERNAL,
            dest_zone=NetworkZone.CORE,
            protocol="ANY",
            port=0,
            action="DENY",
            priority=1,
            conditions={"enforce": True},
            enabled=True,
            created_at=datetime.now()
        )
        self.security_policies[policy1.id] = policy1
        
        # 禁止DMZ到任務系統區的連線
        policy2 = SecurityPolicy(
            id="policy_002",
            name="禁止DMZ到任務系統區連線",
            source_zone=NetworkZone.DMZ,
            dest_zone=NetworkZone.MISSION,
            protocol="ANY",
            port=0,
            action="DENY",
            priority=1,
            conditions={"enforce": True},
            enabled=True,
            created_at=datetime.now()
        )
        self.security_policies[policy2.id] = policy2
        
        # 只允許管理區到核心區的SSH連線
        policy3 = SecurityPolicy(
            id="policy_003",
            name="管理區到核心區SSH連線",
            source_zone=NetworkZone.MANAGEMENT,
            dest_zone=NetworkZone.CORE,
            protocol="TCP",
            port=22,
            action="ALLOW",
            priority=2,
            conditions={"encryption_required": True, "mfa_required": True},
            enabled=True,
            created_at=datetime.now()
        )
        self.security_policies[policy3.id] = policy3
        
        # 禁止橫向移動
        policy4 = SecurityPolicy(
            id="policy_004",
            name="禁止核心區橫向移動",
            source_zone=NetworkZone.CORE,
            dest_zone=NetworkZone.CORE,
            protocol="ANY",
            port=0,
            action="QUARANTINE",
            priority=1,
            conditions={"lateral_movement": True},
            enabled=True,
            created_at=datetime.now()
        )
        self.security_policies[policy4.id] = policy4

    def _start_network_monitoring(self):
        """啟動網路監控"""
        def network_monitor():
            while True:
                try:
                    # 監控網路連線
                    self._monitor_network_connections()
                    
                    # 分析流量模式
                    self._analyze_traffic_patterns()
                    
                    # 檢測威脅
                    self._detect_threats()
                    
                    # 執行安全策略
                    self._enforce_security_policies()
                    
                    time.sleep(5)  # 每5秒監控一次
                
                except Exception as e:
                    logger.error(f"網路監控錯誤: {e}")
                    time.sleep(10)
        
        monitor_thread = threading.Thread(target=network_monitor, daemon=True)
        monitor_thread.start()

    def _monitor_network_connections(self):
        """監控網路連線"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.raddr and conn.laddr:
                    # 創建流量流ID
                    flow_id = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                    
                    # 確定源和目標區域
                    source_zone = self._get_ip_zone(conn.laddr.ip)
                    dest_zone = self._get_ip_zone(conn.raddr.ip)
                    
                    # 確定流量方向
                    direction = self._determine_traffic_direction(source_zone, dest_zone)
                    
                    # 創建或更新流量流
                    if flow_id not in self.traffic_flows:
                        flow = TrafficFlow(
                            id=flow_id,
                            source_ip=conn.laddr.ip,
                            dest_ip=conn.raddr.ip,
                            source_port=conn.laddr.port,
                            dest_port=conn.raddr.port,
                            protocol="TCP",  # 簡化處理
                            direction=direction,
                            source_zone=source_zone,
                            dest_zone=dest_zone,
                            packet_count=1,
                            byte_count=0,
                            start_time=datetime.now(),
                            last_seen=datetime.now(),
                            is_encrypted=self._is_encrypted_connection(conn),
                            application=self._identify_application(conn),
                            user="unknown",
                            risk_score=0.0
                        )
                        self.traffic_flows[flow_id] = flow
                    else:
                        flow = self.traffic_flows[flow_id]
                        flow.packet_count += 1
                        flow.last_seen = datetime.now()
                    
                    # 更新統計
                    self.stats['total_packets'] += 1
                    
                    # 檢查安全策略
                    self._check_security_policy(flow)
        
        except Exception as e:
            logger.error(f"網路連線監控錯誤: {e}")

    def _get_ip_zone(self, ip: str) -> NetworkZone:
        """根據IP確定網路區域"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            for segment in self.network_segments.values():
                network = ipaddress.ip_network(segment.network)
                if ip_obj in network:
                    return segment.zone
            
            # 檢查是否為外部IP
            if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                return NetworkZone.INTERNAL
            else:
                return NetworkZone.EXTERNAL
        
        except Exception:
            return NetworkZone.EXTERNAL

    def _determine_traffic_direction(self, source_zone: NetworkZone, dest_zone: NetworkZone) -> TrafficDirection:
        """確定流量方向"""
        if source_zone == NetworkZone.EXTERNAL and dest_zone != NetworkZone.EXTERNAL:
            return TrafficDirection.INBOUND
        elif source_zone != NetworkZone.EXTERNAL and dest_zone == NetworkZone.EXTERNAL:
            return TrafficDirection.OUTBOUND
        elif source_zone == dest_zone:
            return TrafficDirection.LATERAL
        else:
            return TrafficDirection.CROSS_ZONE

    def _is_encrypted_connection(self, conn) -> bool:
        """檢查連線是否加密"""
        # 檢查常見加密端口
        encrypted_ports = [443, 993, 995, 465, 587, 636, 989, 990]
        return conn.laddr.port in encrypted_ports or conn.raddr.port in encrypted_ports

    def _identify_application(self, conn) -> str:
        """識別應用程式"""
        port = conn.laddr.port
        if port == 80:
            return "HTTP"
        elif port == 443:
            return "HTTPS"
        elif port == 22:
            return "SSH"
        elif port == 3389:
            return "RDP"
        elif port == 21:
            return "FTP"
        elif port == 25:
            return "SMTP"
        elif port == 53:
            return "DNS"
        else:
            return "UNKNOWN"

    def _check_security_policy(self, flow: TrafficFlow):
        """檢查安全策略"""
        for policy in self.security_policies.values():
            if not policy.enabled:
                continue
            
            # 檢查源和目標區域
            if (policy.source_zone == flow.source_zone and 
                policy.dest_zone == flow.dest_zone):
                
                # 檢查協議和端口
                if (policy.protocol == "ANY" or policy.protocol == flow.protocol):
                    if policy.port == 0 or policy.port == flow.dest_port:
                        
                        # 執行策略動作
                        if policy.action == "DENY":
                            self._block_connection(flow, policy)
                        elif policy.action == "QUARANTINE":
                            self._quarantine_connection(flow, policy)
                        elif policy.action == "ALLOW":
                            self._allow_connection(flow, policy)

    def _block_connection(self, flow: TrafficFlow, policy: SecurityPolicy):
        """阻擋連線"""
        logger.warning(f"阻擋連線: {flow.source_ip}:{flow.source_port} -> {flow.dest_ip}:{flow.dest_port} (策略: {policy.name})")
        self.stats['blocked_packets'] += 1
        
        # 記錄威脅檢測
        self._log_threat_detection(
            threat_type="BLOCKED_CONNECTION",
            source_ip=flow.source_ip,
            dest_ip=flow.dest_ip,
            protocol=flow.protocol,
            port=flow.dest_port,
            description=f"連線被策略阻擋: {policy.name}",
            threat_level=ThreatLevel.MEDIUM,
            indicators=[f"Policy: {policy.name}", f"Action: {policy.action}"],
            mitigation="連線已阻擋",
            zone=flow.source_zone
        )

    def _quarantine_connection(self, flow: TrafficFlow, policy: SecurityPolicy):
        """隔離連線"""
        logger.warning(f"隔離連線: {flow.source_ip}:{flow.source_port} -> {flow.dest_ip}:{flow.dest_port} (策略: {policy.name})")
        
        # 記錄威脅檢測
        self._log_threat_detection(
            threat_type="QUARANTINED_CONNECTION",
            source_ip=flow.source_ip,
            dest_ip=flow.dest_ip,
            protocol=flow.protocol,
            port=flow.dest_port,
            description=f"連線被隔離: {policy.name}",
            threat_level=ThreatLevel.HIGH,
            indicators=[f"Policy: {policy.name}", f"Action: {policy.action}"],
            mitigation="連線已隔離",
            zone=flow.source_zone
        )

    def _allow_connection(self, flow: TrafficFlow, policy: SecurityPolicy):
        """允許連線"""
        logger.info(f"允許連線: {flow.source_ip}:{flow.source_port} -> {flow.dest_ip}:{flow.dest_port} (策略: {policy.name})")
        self.stats['allowed_packets'] += 1

    def _analyze_traffic_patterns(self):
        """分析流量模式"""
        try:
            # 檢測異常流量模式
            for flow in self.traffic_flows.values():
                # 檢測高頻連線
                if flow.packet_count > 1000:  # 5秒內超過1000個封包
                    self._detect_high_frequency_traffic(flow)
                
                # 檢測橫向移動
                if flow.direction == TrafficDirection.LATERAL:
                    self._detect_lateral_movement(flow)
                
                # 檢測加密連線
                if flow.is_encrypted:
                    self._analyze_encrypted_traffic(flow)
        
        except Exception as e:
            logger.error(f"流量模式分析錯誤: {e}")

    def _detect_high_frequency_traffic(self, flow: TrafficFlow):
        """檢測高頻流量"""
        self._log_threat_detection(
            threat_type="HIGH_FREQUENCY_TRAFFIC",
            source_ip=flow.source_ip,
            dest_ip=flow.dest_ip,
            protocol=flow.protocol,
            port=flow.dest_port,
            description=f"檢測到高頻流量: {flow.packet_count} 封包/5秒",
            threat_level=ThreatLevel.MEDIUM,
            indicators=[f"Packet count: {flow.packet_count}", f"Direction: {flow.direction.value}"],
            mitigation="建議檢查流量來源",
            zone=flow.source_zone
        )

    def _detect_lateral_movement(self, flow: TrafficFlow):
        """檢測橫向移動"""
        self._log_threat_detection(
            threat_type="LATERAL_MOVEMENT",
            source_ip=flow.source_ip,
            dest_ip=flow.dest_ip,
            protocol=flow.protocol,
            port=flow.dest_port,
            description="檢測到可能的橫向移動",
            threat_level=ThreatLevel.HIGH,
            indicators=[f"Source zone: {flow.source_zone.value}", f"Dest zone: {flow.dest_zone.value}"],
            mitigation="建議檢查內部網路安全",
            zone=flow.source_zone
        )

    def _analyze_encrypted_traffic(self, flow: TrafficFlow):
        """分析加密流量"""
        # 檢查加密流量的異常模式
        if flow.packet_count > 100 and not flow.is_encrypted:
            self._log_threat_detection(
                threat_type="SUSPICIOUS_UNENCRYPTED_TRAFFIC",
                source_ip=flow.source_ip,
                dest_ip=flow.dest_ip,
                protocol=flow.protocol,
                port=flow.dest_port,
                description="檢測到大量未加密流量",
                threat_level=ThreatLevel.MEDIUM,
                indicators=[f"Packet count: {flow.packet_count}", "Encryption: False"],
                mitigation="建議啟用加密",
                zone=flow.source_zone
            )

    def _detect_threats(self):
        """檢測威脅"""
        try:
            # 檢測已知惡意IP
            self._detect_malicious_ips()
            
            # 檢測端口掃描
            self._detect_port_scanning()
            
            # 檢測DDoS攻擊
            self._detect_ddos_attack()
            
            # 檢測異常DNS查詢
            self._detect_anomalous_dns()
        
        except Exception as e:
            logger.error(f"威脅檢測錯誤: {e}")

    def _detect_malicious_ips(self):
        """檢測惡意IP"""
        malicious_ips = [
            "192.168.1.100",  # 模擬惡意IP
            "10.0.0.100",     # 模擬惡意IP
        ]
        
        for flow in self.traffic_flows.values():
            if flow.source_ip in malicious_ips or flow.dest_ip in malicious_ips:
                self._log_threat_detection(
                    threat_type="MALICIOUS_IP",
                    source_ip=flow.source_ip,
                    dest_ip=flow.dest_ip,
                    protocol=flow.protocol,
                    port=flow.dest_port,
                    description=f"檢測到與惡意IP的連線: {flow.source_ip if flow.source_ip in malicious_ips else flow.dest_ip}",
                    threat_level=ThreatLevel.CRITICAL,
                    indicators=[f"Malicious IP: {flow.source_ip if flow.source_ip in malicious_ips else flow.dest_ip}"],
                    mitigation="立即阻擋連線",
                    zone=flow.source_zone
                )

    def _detect_port_scanning(self):
        """檢測端口掃描"""
        # 檢測同一源IP對多個端口的連線
        source_ports = {}
        for flow in self.traffic_flows.values():
            if flow.source_ip not in source_ports:
                source_ports[flow.source_ip] = set()
            source_ports[flow.source_ip].add(flow.dest_port)
        
        for source_ip, ports in source_ports.items():
            if len(ports) > 10:  # 掃描超過10個端口
                self._log_threat_detection(
                    threat_type="PORT_SCANNING",
                    source_ip=source_ip,
                    dest_ip="MULTIPLE",
                    protocol="TCP",
                    port=0,
                    description=f"檢測到端口掃描: {source_ip} 掃描了 {len(ports)} 個端口",
                    threat_level=ThreatLevel.HIGH,
                    indicators=[f"Scanned ports: {len(ports)}", f"Source: {source_ip}"],
                    mitigation="阻擋來源IP",
                    zone=self._get_ip_zone(source_ip)
                )

    def _detect_ddos_attack(self):
        """檢測DDoS攻擊"""
        # 檢測大量連線到同一目標
        dest_connections = {}
        for flow in self.traffic_flows.values():
            if flow.dest_ip not in dest_connections:
                dest_connections[flow.dest_ip] = 0
            dest_connections[flow.dest_ip] += flow.packet_count
        
        for dest_ip, packet_count in dest_connections.items():
            if packet_count > 5000:  # 5秒內超過5000個封包
                self._log_threat_detection(
                    threat_type="DDOS_ATTACK",
                    source_ip="MULTIPLE",
                    dest_ip=dest_ip,
                    protocol="TCP",
                    port=0,
                    description=f"檢測到DDoS攻擊: 目標 {dest_ip} 收到 {packet_count} 個封包",
                    threat_level=ThreatLevel.CRITICAL,
                    indicators=[f"Target: {dest_ip}", f"Packets: {packet_count}"],
                    mitigation="啟用DDoS防護",
                    zone=self._get_ip_zone(dest_ip)
                )

    def _detect_anomalous_dns(self):
        """檢測異常DNS查詢"""
        # 檢測DNS查詢模式
        dns_queries = {}
        for flow in self.traffic_flows.values():
            if flow.dest_port == 53:  # DNS端口
                if flow.source_ip not in dns_queries:
                    dns_queries[flow.source_ip] = 0
                dns_queries[flow.source_ip] += 1
        
        for source_ip, query_count in dns_queries.items():
            if query_count > 100:  # 5秒內超過100次DNS查詢
                self._log_threat_detection(
                    threat_type="ANOMALOUS_DNS",
                    source_ip=source_ip,
                    dest_ip="DNS_SERVER",
                    protocol="UDP",
                    port=53,
                    description=f"檢測到異常DNS查詢: {source_ip} 在5秒內查詢了 {query_count} 次",
                    threat_level=ThreatLevel.MEDIUM,
                    indicators=[f"Source: {source_ip}", f"Queries: {query_count}"],
                    mitigation="檢查DNS查詢內容",
                    zone=self._get_ip_zone(source_ip)
                )

    def _enforce_security_policies(self):
        """執行安全策略"""
        try:
            # 更新統計
            self.stats['zones_monitored'] = len(self.network_segments)
            self.stats['policies_active'] = len([p for p in self.security_policies.values() if p.enabled])
            
            # 清理舊流量流
            self._cleanup_old_flows()
        
        except Exception as e:
            logger.error(f"安全策略執行錯誤: {e}")

    def _cleanup_old_flows(self):
        """清理舊流量流"""
        cutoff_time = datetime.now() - timedelta(minutes=5)
        old_flows = [f for f in self.traffic_flows.values() if f.last_seen < cutoff_time]
        
        for flow in old_flows:
            del self.traffic_flows[flow.id]
        
        if old_flows:
            logger.info(f"清理了 {len(old_flows)} 個舊流量流")

    def _log_threat_detection(self, threat_type: str, source_ip: str, dest_ip: str, 
                            protocol: str, port: int, description: str, 
                            threat_level: ThreatLevel, indicators: List[str], 
                            mitigation: str, zone: NetworkZone):
        """記錄威脅檢測"""
        threat_id = f"threat_{int(time.time())}_{hashlib.md5(f'{threat_type}{source_ip}{dest_ip}'.encode()).hexdigest()[:8]}"
        
        detection = ThreatDetection(
            id=threat_id,
            threat_type=threat_type,
            source_ip=source_ip,
            dest_ip=dest_ip,
            protocol=protocol,
            port=port,
            description=description,
            threat_level=threat_level,
            indicators=indicators,
            mitigation=mitigation,
            detected_at=datetime.now(),
            zone=zone
        )
        
        self.threat_detections[threat_id] = detection
        self._save_threat_detection(detection)
        
        # 更新統計
        self.stats['threats_detected'] += 1
        
        # 記錄日誌
        logger.warning(f"威脅檢測: {threat_type} - {description} (等級: {threat_level.value})")

    def _save_threat_detection(self, detection: ThreatDetection):
        """儲存威脅檢測"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO threat_detections 
            (id, threat_type, source_ip, dest_ip, protocol, port, description,
             threat_level, indicators, mitigation, detected_at, zone)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            detection.id, detection.threat_type, detection.source_ip,
            detection.dest_ip, detection.protocol, detection.port,
            detection.description, detection.threat_level.value,
            json.dumps(detection.indicators), detection.mitigation,
            detection.detected_at.isoformat(), detection.zone.value
        ))
        self.db_conn.commit()

    def get_network_status(self) -> Dict[str, Any]:
        """獲取網路狀態"""
        return {
            'network_segments': len(self.network_segments),
            'active_flows': len(self.traffic_flows),
            'security_policies': len(self.security_policies),
            'threats_detected': len(self.threat_detections),
            'stats': self.stats,
            'zones': {
                zone.value: len([s for s in self.network_segments.values() if s.zone == zone])
                for zone in NetworkZone
            }
        }

    def get_recent_threats(self, limit: int = 10) -> List[ThreatDetection]:
        """獲取最近威脅"""
        threats = list(self.threat_detections.values())
        threats.sort(key=lambda x: x.detected_at, reverse=True)
        return threats[:limit]

def main():
    """主程式"""
    config = {
        'monitoring_interval': 5,
        'threat_detection': True,
        'policy_enforcement': True
    }
    
    defense = MilitaryNetworkDefense(config)
    
    print("🛡️ 軍事級網路深度防禦系統已啟動")
    print("=" * 60)
    
    # 顯示網路架構
    print("網路架構:")
    for segment in defense.network_segments.values():
        print(f"  {segment.zone.value}: {segment.network} ({segment.name})")
    
    # 顯示安全策略
    print(f"\n安全策略: {len(defense.security_policies)} 個")
    for policy in defense.security_policies.values():
        print(f"  {policy.name}: {policy.source_zone.value} -> {policy.dest_zone.value} ({policy.action})")
    
    print(f"\n🛡️ 系統正在監控網路流量...")
    print("按 Ctrl+C 停止監控")

if __name__ == "__main__":
    main()




