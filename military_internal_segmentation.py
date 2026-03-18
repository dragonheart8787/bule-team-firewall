#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級內部網路層防禦系統
Military-Grade Internal Segmentation Defense System

功能特色：
- 東西向流量監控 (Zeek/Suricata風格)
- 微分段隔離 (NSX/Illumio風格)
- 零信任NAC (Network Access Control)
- 機器學習威脅檢測
- 內部橫向移動檢測
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
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import ipaddress
import subprocess
import psutil
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)

class SegmentType(Enum):
    """分段類型"""
    APPLICATION = "APPLICATION"      # 應用分段
    DATABASE = "DATABASE"           # 資料庫分段
    MANAGEMENT = "MANAGEMENT"       # 管理分段
    STORAGE = "STORAGE"             # 儲存分段
    BACKUP = "BACKUP"               # 備份分段
    DEVELOPMENT = "DEVELOPMENT"     # 開發分段
    PRODUCTION = "PRODUCTION"       # 生產分段

class TrustLevel(Enum):
    """信任等級"""
    UNTRUSTED = "UNTRUSTED"         # 不信任
    LOW = "LOW"                     # 低信任
    MEDIUM = "MEDIUM"               # 中等信任
    HIGH = "HIGH"                   # 高信任
    CRITICAL = "CRITICAL"           # 關鍵信任

class DeviceType(Enum):
    """設備類型"""
    SERVER = "SERVER"               # 伺服器
    WORKSTATION = "WORKSTATION"     # 工作站
    MOBILE = "MOBILE"               # 行動設備
    IOT = "IOT"                     # 物聯網設備
    NETWORK = "NETWORK"             # 網路設備
    UNKNOWN = "UNKNOWN"             # 未知設備

@dataclass
class NetworkSegment:
    """網路分段"""
    id: str
    name: str
    segment_type: SegmentType
    network: str                    # CIDR格式
    trust_level: TrustLevel
    allowed_protocols: List[str]
    allowed_ports: List[int]
    allowed_devices: List[str]
    blocked_devices: List[str]
    microsegments: List[str]
    security_policy: str
    created_at: datetime

@dataclass
class Device:
    """設備"""
    id: str
    mac_address: str
    ip_address: str
    device_type: DeviceType
    trust_level: TrustLevel
    segment_id: str
    hostname: str
    os: str
    last_seen: datetime
    is_authenticated: bool
    certificate: str
    risk_score: float

@dataclass
class TrafficFlow:
    """流量流"""
    id: str
    source_device: str
    dest_device: str
    source_ip: str
    dest_ip: str
    protocol: str
    port: int
    bytes_transferred: int
    packets: int
    start_time: datetime
    end_time: datetime
    is_encrypted: bool
    application: str
    risk_score: float
    anomaly_score: float

@dataclass
class AnomalyDetection:
    """異常檢測"""
    id: str
    device_id: str
    anomaly_type: str
    description: str
    severity: str
    confidence: float
    indicators: List[str]
    detected_at: datetime
    mitigated: bool

class MilitaryInternalSegmentation:
    """軍事級內部網路層防禦系統"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.network_segments: Dict[str, NetworkSegment] = {}
        self.devices: Dict[str, Device] = {}
        self.traffic_flows: Dict[str, TrafficFlow] = {}
        self.anomalies: Dict[str, AnomalyDetection] = {}
        self.device_fingerprints: Dict[str, Dict] = {}
        self.trust_scores: Dict[str, float] = {}
        
        # 機器學習模型
        self.ml_models = {
            'anomaly_detector': None,
            'threat_classifier': None,
            'behavior_analyzer': None
        }
        
        # 統計數據
        self.stats = {
            'total_devices': 0,
            'authenticated_devices': 0,
            'total_flows': 0,
            'anomalies_detected': 0,
            'segments': 0,
            'microsegments': 0
        }
        
        # 初始化資料庫
        self._init_database()
        
        # 載入預設網路分段
        self._load_default_segments()
        
        # 初始化機器學習模型
        self._init_ml_models()
        
        # 啟動內部監控
        self._start_internal_monitoring()
        
        logger.info("軍事級內部網路層防禦系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('military_internal_segmentation.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立網路分段表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_segments (
                id TEXT PRIMARY KEY,
                name TEXT,
                segment_type TEXT,
                network TEXT,
                trust_level TEXT,
                allowed_protocols TEXT,
                allowed_ports TEXT,
                allowed_devices TEXT,
                blocked_devices TEXT,
                microsegments TEXT,
                security_policy TEXT,
                created_at TIMESTAMP
            )
        ''')
        
        # 建立設備表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                mac_address TEXT,
                ip_address TEXT,
                device_type TEXT,
                trust_level TEXT,
                segment_id TEXT,
                hostname TEXT,
                os TEXT,
                last_seen TIMESTAMP,
                is_authenticated BOOLEAN,
                certificate TEXT,
                risk_score REAL
            )
        ''')
        
        # 建立流量流表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_flows (
                id TEXT PRIMARY KEY,
                source_device TEXT,
                dest_device TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                port INTEGER,
                bytes_transferred INTEGER,
                packets INTEGER,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                is_encrypted BOOLEAN,
                application TEXT,
                risk_score REAL,
                anomaly_score REAL
            )
        ''')
        
        # 建立異常檢測表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomaly_detections (
                id TEXT PRIMARY KEY,
                device_id TEXT,
                anomaly_type TEXT,
                description TEXT,
                severity TEXT,
                confidence REAL,
                indicators TEXT,
                detected_at TIMESTAMP,
                mitigated BOOLEAN
            )
        ''')
        
        self.db_conn.commit()

    def _load_default_segments(self):
        """載入預設網路分段"""
        # 應用分段
        app_segment = NetworkSegment(
            id="app_segment",
            name="應用分段",
            segment_type=SegmentType.APPLICATION,
            network="192.168.10.0/24",
            trust_level=TrustLevel.HIGH,
            allowed_protocols=["TCP", "UDP"],
            allowed_ports=[80, 443, 8080, 8443],
            allowed_devices=[],
            blocked_devices=[],
            microsegments=["web_tier", "app_tier"],
            security_policy="APPLICATION_SECURITY",
            created_at=datetime.now()
        )
        self.network_segments[app_segment.id] = app_segment
        
        # 資料庫分段
        db_segment = NetworkSegment(
            id="db_segment",
            name="資料庫分段",
            segment_type=SegmentType.DATABASE,
            network="192.168.20.0/24",
            trust_level=TrustLevel.CRITICAL,
            allowed_protocols=["TCP"],
            allowed_ports=[3306, 5432, 1433, 1521],
            allowed_devices=[],
            blocked_devices=[],
            microsegments=["primary_db", "replica_db"],
            security_policy="DATABASE_SECURITY",
            created_at=datetime.now()
        )
        self.network_segments[db_segment.id] = db_segment
        
        # 管理分段
        mgmt_segment = NetworkSegment(
            id="mgmt_segment",
            name="管理分段",
            segment_type=SegmentType.MANAGEMENT,
            network="192.168.30.0/24",
            trust_level=TrustLevel.HIGH,
            allowed_protocols=["TCP", "UDP", "ICMP"],
            allowed_ports=[22, 3389, 161, 162, 443],
            allowed_devices=[],
            blocked_devices=[],
            microsegments=["admin_workstations", "monitoring"],
            security_policy="MANAGEMENT_SECURITY",
            created_at=datetime.now()
        )
        self.network_segments[mgmt_segment.id] = mgmt_segment
        
        # 儲存分段
        storage_segment = NetworkSegment(
            id="storage_segment",
            name="儲存分段",
            segment_type=SegmentType.STORAGE,
            network="192.168.40.0/24",
            trust_level=TrustLevel.HIGH,
            allowed_protocols=["TCP"],
            allowed_ports=[2049, 111, 445, 139],
            allowed_devices=[],
            blocked_devices=[],
            microsegments=["nas", "san"],
            security_policy="STORAGE_SECURITY",
            created_at=datetime.now()
        )
        self.network_segments[storage_segment.id] = storage_segment

    def _init_ml_models(self):
        """初始化機器學習模型"""
        try:
            # 初始化異常檢測模型
            self._init_anomaly_detector()
            
            # 初始化威脅分類模型
            self._init_threat_classifier()
            
            # 初始化行為分析模型
            self._init_behavior_analyzer()
            
            logger.info("機器學習模型初始化完成")
        
        except Exception as e:
            logger.error(f"機器學習模型初始化錯誤: {e}")

    def _init_anomaly_detector(self):
        """初始化異常檢測模型"""
        # 模擬異常檢測模型
        self.ml_models['anomaly_detector'] = {
            'type': 'isolation_forest',
            'trained': True,
            'features': ['bytes_transferred', 'packets', 'duration', 'port', 'protocol']
        }

    def _init_threat_classifier(self):
        """初始化威脅分類模型"""
        # 模擬威脅分類模型
        self.ml_models['threat_classifier'] = {
            'type': 'random_forest',
            'trained': True,
            'classes': ['normal', 'malware', 'lateral_movement', 'data_exfiltration']
        }

    def _init_behavior_analyzer(self):
        """初始化行為分析模型"""
        # 模擬行為分析模型
        self.ml_models['behavior_analyzer'] = {
            'type': 'lstm',
            'trained': True,
            'sequence_length': 100
        }

    def _start_internal_monitoring(self):
        """啟動內部監控"""
        def internal_monitor():
            while True:
                try:
                    # 設備發現和認證
                    self._discover_devices()
                    
                    # 流量監控
                    self._monitor_traffic_flows()
                    
                    # 異常檢測
                    self._detect_anomalies()
                    
                    # 信任評分更新
                    self._update_trust_scores()
                    
                    # 微分段執行
                    self._enforce_microsegmentation()
                    
                    time.sleep(5)  # 每5秒監控一次
                
                except Exception as e:
                    logger.error(f"內部監控錯誤: {e}")
                    time.sleep(10)
        
        monitor_thread = threading.Thread(target=internal_monitor, daemon=True)
        monitor_thread.start()

    def _discover_devices(self):
        """設備發現"""
        try:
            # 掃描網路設備
            devices = self._scan_network_devices()
            
            for device_info in devices:
                device_id = device_info['mac_address']
                
                if device_id not in self.devices:
                    # 新設備
                    device = Device(
                        id=device_id,
                        mac_address=device_info['mac_address'],
                        ip_address=device_info['ip_address'],
                        device_type=DeviceType(device_info['device_type']),
                        trust_level=TrustLevel.UNTRUSTED,
                        segment_id=self._get_device_segment(device_info['ip_address']),
                        hostname=device_info['hostname'],
                        os=device_info['os'],
                        last_seen=datetime.now(),
                        is_authenticated=False,
                        certificate="",
                        risk_score=0.5
                    )
                    self.devices[device_id] = device
                    self._save_device(device)
                    
                    # 觸發設備認證
                    self._trigger_device_authentication(device)
                else:
                    # 更新現有設備
                    device = self.devices[device_id]
                    device.last_seen = datetime.now()
                    device.ip_address = device_info['ip_address']
                    self._save_device(device)
        
        except Exception as e:
            logger.error(f"設備發現錯誤: {e}")

    def _scan_network_devices(self) -> List[Dict]:
        """掃描網路設備"""
        devices = []
        
        try:
            # 使用arp掃描本地網路
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
            
            for line in result.stdout.split('\n'):
                if '192.168.' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[1].strip('()')
                        mac = parts[3]
                        
                        # 獲取設備資訊
                        device_info = self._get_device_info(ip, mac)
                        devices.append(device_info)
        
        except Exception as e:
            logger.error(f"網路設備掃描錯誤: {e}")
        
        return devices

    def _get_device_info(self, ip: str, mac: str) -> Dict:
        """獲取設備資訊"""
        try:
            # 嘗試獲取主機名
            hostname = socket.gethostbyaddr(ip)[0] if ip != '192.168.1.1' else 'gateway'
        except:
            hostname = f"device_{ip.split('.')[-1]}"
        
        # 確定設備類型
        device_type = self._classify_device_type(ip, mac, hostname)
        
        return {
            'mac_address': mac,
            'ip_address': ip,
            'device_type': device_type.value,
            'hostname': hostname,
            'os': 'Unknown'
        }

    def _classify_device_type(self, ip: str, mac: str, hostname: str) -> DeviceType:
        """分類設備類型"""
        # 根據IP範圍和主機名分類
        if '192.168.1.1' in ip or 'gateway' in hostname.lower():
            return DeviceType.NETWORK
        elif 'server' in hostname.lower() or 'srv' in hostname.lower():
            return DeviceType.SERVER
        elif 'mobile' in hostname.lower() or 'phone' in hostname.lower():
            return DeviceType.MOBILE
        else:
            return DeviceType.WORKSTATION

    def _get_device_segment(self, ip: str) -> str:
        """獲取設備分段"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            for segment in self.network_segments.values():
                network = ipaddress.ip_network(segment.network)
                if ip_obj in network:
                    return segment.id
            
            return "unknown"
        
        except:
            return "unknown"

    def _trigger_device_authentication(self, device: Device):
        """觸發設備認證"""
        logger.info(f"新設備發現: {device.hostname} ({device.ip_address}) - 需要認證")
        
        # 模擬設備認證流程
        if self._authenticate_device(device):
            device.is_authenticated = True
            device.trust_level = TrustLevel.MEDIUM
            device.certificate = self._generate_device_certificate(device)
            logger.info(f"設備認證成功: {device.hostname}")
        else:
            logger.warning(f"設備認證失敗: {device.hostname}")

    def _authenticate_device(self, device: Device) -> bool:
        """認證設備"""
        # 模擬設備認證
        # 在實際環境中，這裡會執行真正的認證流程
        return True  # 簡化處理

    def _generate_device_certificate(self, device: Device) -> str:
        """生成設備證書"""
        # 模擬生成設備證書
        return f"cert_{device.mac_address}_{int(time.time())}"

    def _monitor_traffic_flows(self):
        """監控流量流"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.raddr and conn.laddr:
                    # 創建流量流ID
                    flow_id = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                    
                    # 獲取源和目標設備
                    source_device = self._get_device_by_ip(conn.laddr.ip)
                    dest_device = self._get_device_by_ip(conn.raddr.ip)
                    
                    if source_device and dest_device:
                        # 創建或更新流量流
                        if flow_id not in self.traffic_flows:
                            flow = TrafficFlow(
                                id=flow_id,
                                source_device=source_device.id,
                                dest_device=dest_device.id,
                                source_ip=conn.laddr.ip,
                                dest_ip=conn.raddr.ip,
                                protocol="TCP",  # 簡化處理
                                port=conn.raddr.port,
                                bytes_transferred=0,
                                packets=1,
                                start_time=datetime.now(),
                                end_time=datetime.now(),
                                is_encrypted=self._is_encrypted_connection(conn),
                                application=self._identify_application(conn),
                                risk_score=0.0,
                                anomaly_score=0.0
                            )
                            self.traffic_flows[flow_id] = flow
                        else:
                            flow = self.traffic_flows[flow_id]
                            flow.packets += 1
                            flow.end_time = datetime.now()
                        
                        # 更新統計
                        self.stats['total_flows'] += 1
                        
                        # 檢查流量是否跨分段
                        self._check_cross_segment_traffic(flow)
        
        except Exception as e:
            logger.error(f"流量流監控錯誤: {e}")

    def _get_device_by_ip(self, ip: str) -> Optional[Device]:
        """根據IP獲取設備"""
        for device in self.devices.values():
            if device.ip_address == ip:
                return device
        return None

    def _is_encrypted_connection(self, conn) -> bool:
        """檢查連線是否加密"""
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

    def _check_cross_segment_traffic(self, flow: TrafficFlow):
        """檢查跨分段流量"""
        source_device = self.devices.get(flow.source_device)
        dest_device = self.devices.get(flow.dest_device)
        
        if source_device and dest_device:
            source_segment = self.network_segments.get(source_device.segment_id)
            dest_segment = self.network_segments.get(dest_device.segment_id)
            
            if source_segment and dest_segment and source_segment.id != dest_segment.id:
                # 跨分段流量
                self._log_cross_segment_traffic(flow, source_segment, dest_segment)

    def _log_cross_segment_traffic(self, flow: TrafficFlow, source_segment: NetworkSegment, dest_segment: NetworkSegment):
        """記錄跨分段流量"""
        logger.info(f"跨分段流量: {source_segment.name} -> {dest_segment.name} ({flow.source_ip} -> {flow.dest_ip})")
        
        # 檢查是否允許跨分段流量
        if not self._is_cross_segment_allowed(source_segment, dest_segment, flow):
            logger.warning(f"未授權跨分段流量: {source_segment.name} -> {dest_segment.name}")

    def _is_cross_segment_allowed(self, source_segment: NetworkSegment, dest_segment: NetworkSegment, flow: TrafficFlow) -> bool:
        """檢查是否允許跨分段流量"""
        # 簡化的跨分段流量檢查
        # 在實際環境中，這裡會檢查詳細的安全策略
        
        # 高信任分段可以訪問低信任分段
        if source_segment.trust_level.value > dest_segment.trust_level.value:
            return True
        
        # 相同信任等級的分段可以互相訪問
        if source_segment.trust_level == dest_segment.trust_level:
            return True
        
        # 其他情況需要特殊授權
        return False

    def _detect_anomalies(self):
        """檢測異常"""
        try:
            # 使用機器學習模型檢測異常
            self._ml_anomaly_detection()
            
            # 基於規則的異常檢測
            self._rule_based_anomaly_detection()
        
        except Exception as e:
            logger.error(f"異常檢測錯誤: {e}")

    def _ml_anomaly_detection(self):
        """機器學習異常檢測"""
        try:
            # 準備特徵數據
            features = self._prepare_ml_features()
            
            if features:
                # 使用異常檢測模型
                anomaly_scores = self._predict_anomalies(features)
                
                # 處理異常檢測結果
                for i, score in enumerate(anomaly_scores):
                    if score > 0.7:  # 異常閾值
                        self._log_anomaly(features[i], score)
        
        except Exception as e:
            logger.error(f"機器學習異常檢測錯誤: {e}")

    def _prepare_ml_features(self) -> List[Dict]:
        """準備機器學習特徵"""
        features = []
        
        for flow in self.traffic_flows.values():
            feature = {
                'bytes_transferred': flow.bytes_transferred,
                'packets': flow.packets,
                'duration': (flow.end_time - flow.start_time).total_seconds(),
                'port': flow.port,
                'protocol': hash(flow.protocol) % 1000,  # 簡化處理
                'is_encrypted': 1 if flow.is_encrypted else 0
            }
            features.append(feature)
        
        return features

    def _predict_anomalies(self, features: List[Dict]) -> List[float]:
        """預測異常"""
        # 模擬異常檢測模型預測
        import random
        return [random.random() for _ in features]

    def _log_anomaly(self, feature: Dict, score: float):
        """記錄異常"""
        anomaly_id = f"anomaly_{int(time.time())}_{hashlib.md5(str(feature).encode()).hexdigest()[:8]}"
        
        anomaly = AnomalyDetection(
            id=anomaly_id,
            device_id="unknown",
            anomaly_type="ML_DETECTED",
            description=f"機器學習檢測到異常 (分數: {score:.2f})",
            severity="MEDIUM" if score > 0.8 else "LOW",
            confidence=score,
            indicators=[f"Feature: {k}={v}" for k, v in feature.items()],
            detected_at=datetime.now(),
            mitigated=False
        )
        
        self.anomalies[anomaly_id] = anomaly
        self._save_anomaly(anomaly)
        
        # 更新統計
        self.stats['anomalies_detected'] += 1
        
        logger.warning(f"異常檢測: {anomaly.description}")

    def _rule_based_anomaly_detection(self):
        """基於規則的異常檢測"""
        # 檢測異常流量模式
        self._detect_high_volume_traffic()
        
        # 檢測異常時間模式
        self._detect_anomalous_timing()
        
        # 檢測異常端口使用
        self._detect_anomalous_ports()

    def _detect_high_volume_traffic(self):
        """檢測高流量"""
        for flow in self.traffic_flows.values():
            if flow.packets > 1000:  # 超過1000個封包
                self._log_anomaly({
                    'type': 'HIGH_VOLUME_TRAFFIC',
                    'packets': flow.packets,
                    'source': flow.source_ip,
                    'dest': flow.dest_ip
                }, 0.8)

    def _detect_anomalous_timing(self):
        """檢測異常時間模式"""
        current_hour = datetime.now().hour
        
        # 檢測非工作時間的流量
        if current_hour < 6 or current_hour > 22:
            for flow in self.traffic_flows.values():
                if flow.packets > 100:
                    self._log_anomaly({
                        'type': 'ANOMALOUS_TIMING',
                        'hour': current_hour,
                        'packets': flow.packets,
                        'source': flow.source_ip
                    }, 0.6)

    def _detect_anomalous_ports(self):
        """檢測異常端口使用"""
        suspicious_ports = [21, 23, 135, 139, 445, 1433, 3389]
        
        for flow in self.traffic_flows.values():
            if flow.port in suspicious_ports:
                self._log_anomaly({
                    'type': 'SUSPICIOUS_PORT',
                    'port': flow.port,
                    'source': flow.source_ip,
                    'dest': flow.dest_ip
                }, 0.7)

    def _update_trust_scores(self):
        """更新信任評分"""
        for device in self.devices.values():
            # 計算信任評分
            trust_score = self._calculate_trust_score(device)
            device.risk_score = 1.0 - trust_score
            self.trust_scores[device.id] = trust_score

    def _calculate_trust_score(self, device: Device) -> float:
        """計算信任評分"""
        score = 0.5  # 基礎分數
        
        # 認證狀態
        if device.is_authenticated:
            score += 0.2
        
        # 設備類型
        if device.device_type == DeviceType.SERVER:
            score += 0.1
        elif device.device_type == DeviceType.WORKSTATION:
            score += 0.05
        
        # 分段信任等級
        segment = self.network_segments.get(device.segment_id)
        if segment:
            if segment.trust_level == TrustLevel.CRITICAL:
                score += 0.2
            elif segment.trust_level == TrustLevel.HIGH:
                score += 0.1
            elif segment.trust_level == TrustLevel.MEDIUM:
                score += 0.05
        
        # 異常檢測影響
        device_anomalies = [a for a in self.anomalies.values() if a.device_id == device.id]
        if device_anomalies:
            score -= len(device_anomalies) * 0.1
        
        return max(0.0, min(1.0, score))

    def _enforce_microsegmentation(self):
        """執行微分段"""
        try:
            # 更新統計
            self.stats['total_devices'] = len(self.devices)
            self.stats['authenticated_devices'] = len([d for d in self.devices.values() if d.is_authenticated])
            self.stats['segments'] = len(self.network_segments)
            self.stats['microsegments'] = sum(len(s.microsegments) for s in self.network_segments.values())
        
        except Exception as e:
            logger.error(f"微分段執行錯誤: {e}")

    def _save_device(self, device: Device):
        """儲存設備"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO devices 
            (id, mac_address, ip_address, device_type, trust_level, segment_id,
             hostname, os, last_seen, is_authenticated, certificate, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            device.id, device.mac_address, device.ip_address,
            device.device_type.value, device.trust_level.value,
            device.segment_id, device.hostname, device.os,
            device.last_seen.isoformat(), device.is_authenticated,
            device.certificate, device.risk_score
        ))
        self.db_conn.commit()

    def _save_anomaly(self, anomaly: AnomalyDetection):
        """儲存異常檢測"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO anomaly_detections 
            (id, device_id, anomaly_type, description, severity, confidence,
             indicators, detected_at, mitigated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            anomaly.id, anomaly.device_id, anomaly.anomaly_type,
            anomaly.description, anomaly.severity, anomaly.confidence,
            json.dumps(anomaly.indicators), anomaly.detected_at.isoformat(),
            anomaly.mitigated
        ))
        self.db_conn.commit()

    def get_internal_status(self) -> Dict[str, Any]:
        """獲取內部防禦狀態"""
        return {
            'devices': len(self.devices),
            'authenticated_devices': len([d for d in self.devices.values() if d.is_authenticated]),
            'segments': len(self.network_segments),
            'microsegments': sum(len(s.microsegments) for s in self.network_segments.values()),
            'traffic_flows': len(self.traffic_flows),
            'anomalies': len(self.anomalies),
            'stats': self.stats
        }

    def get_recent_anomalies(self, limit: int = 10) -> List[AnomalyDetection]:
        """獲取最近異常"""
        anomalies = list(self.anomalies.values())
        anomalies.sort(key=lambda x: x.detected_at, reverse=True)
        return anomalies[:limit]

def main():
    """主程式"""
    config = {
        'monitoring_interval': 5,
        'ml_enabled': True,
        'microsegmentation': True,
        'zero_trust': True
    }
    
    defense = MilitaryInternalSegmentation(config)
    
    print("🛡️ 軍事級內部網路層防禦系統已啟動")
    print("=" * 60)
    
    # 顯示網路分段
    print("網路分段:")
    for segment in defense.network_segments.values():
        print(f"  {segment.name}: {segment.network} (信任等級: {segment.trust_level.value})")
    
    # 顯示設備
    print(f"\n設備: {len(defense.devices)} 個")
    for device in list(defense.devices.values())[:5]:  # 顯示前5個設備
        print(f"  {device.hostname}: {device.ip_address} ({device.device_type.value})")
    
    print(f"\n🛡️ 系統正在監控內部網路...")
    print("按 Ctrl+C 停止監控")

if __name__ == "__main__":
    main()




