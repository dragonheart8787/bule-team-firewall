#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
入侵檢測系統 (IDS)
Intrusion Detection System

功能特色：
- 簽名檢測
- 異常檢測
- 機器學習檢測
- 行為分析
- 威脅獵殺
- 即時告警
"""

import re
import json
import time
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import sqlite3
import threading
from collections import defaultdict, deque
import ipaddress

logger = logging.getLogger(__name__)

class AttackType(Enum):
    """攻擊類型"""
    PORT_SCAN = "PORT_SCAN"
    DDOS = "DDOS"
    BRUTE_FORCE = "BRUTE_FORCE"
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    MALWARE = "MALWARE"
    BOTNET = "BOTNET"
    APT = "APT"
    ZERO_DAY = "ZERO_DAY"
    INSIDER_THREAT = "INSIDER_THREAT"

class Severity(Enum):
    """嚴重程度"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5

@dataclass
class IDSSignature:
    """IDS簽名"""
    id: str
    name: str
    attack_type: AttackType
    pattern: str
    severity: Severity
    description: str
    enabled: bool = True
    false_positive_rate: float = 0.0

@dataclass
class AttackEvent:
    """攻擊事件"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    attack_type: AttackType
    severity: Severity
    signature_id: str
    description: str
    payload: bytes
    confidence: float
    blocked: bool = False

@dataclass
class BehavioralProfile:
    """行為檔案"""
    ip_address: str
    normal_ports: set
    normal_protocols: set
    normal_times: List[int]
    normal_payload_sizes: List[int]
    connection_frequency: float
    last_seen: datetime
    anomaly_score: float = 0.0

class IntrusionDetectionSystem:
    """入侵檢測系統"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.signatures: List[IDSSignature] = []
        self.behavioral_profiles: Dict[str, BehavioralProfile] = {}
        self.attack_events: List[AttackEvent] = []
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.connection_tracker = defaultdict(list)
        self.port_scan_detector = PortScanDetector()
        self.ddos_detector = DDoSDetector()
        self.ml_detector = MachineLearningDetector()
        
        # 初始化資料庫
        self._init_database()
        
        # 載入簽名
        self._load_signatures()
        
        # 初始化機器學習模型
        if self.config.get('ml_detection', True):
            self._init_ml_models()
        
        logger.info("入侵檢測系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('ids.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立簽名表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ids_signatures (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                attack_type TEXT,
                pattern TEXT,
                severity INTEGER,
                description TEXT,
                enabled BOOLEAN,
                false_positive_rate REAL
            )
        ''')
        
        # 建立攻擊事件表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                source_ip TEXT,
                dest_ip TEXT,
                attack_type TEXT,
                severity INTEGER,
                signature_id TEXT,
                description TEXT,
                payload BLOB,
                confidence REAL,
                blocked BOOLEAN
            )
        ''')
        
        # 建立行為檔案表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS behavioral_profiles (
                ip_address TEXT PRIMARY KEY,
                normal_ports TEXT,
                normal_protocols TEXT,
                normal_times TEXT,
                normal_payload_sizes TEXT,
                connection_frequency REAL,
                last_seen TIMESTAMP,
                anomaly_score REAL
            )
        ''')
        
        self.db_conn.commit()

    def _load_signatures(self):
        """載入IDS簽名"""
        default_signatures = [
            IDSSignature(
                id="sig_001",
                name="SQL注入檢測",
                attack_type=AttackType.SQL_INJECTION,
                pattern=r"(union\s+select|drop\s+table|insert\s+into|delete\s+from|update\s+set|or\s+1=1|'or'1'='1)",
                severity=Severity.HIGH,
                description="檢測SQL注入攻擊模式"
            ),
            IDSSignature(
                id="sig_002",
                name="XSS攻擊檢測",
                attack_type=AttackType.XSS,
                pattern=r"(<script[^>]*>|javascript:|on\w+\s*=|\<iframe[^>]*>|document\.cookie)",
                severity=Severity.MEDIUM,
                description="檢測跨站腳本攻擊"
            ),
            IDSSignature(
                id="sig_003",
                name="惡意檔案檢測",
                attack_type=AttackType.MALWARE,
                pattern=r"(\.exe|\.bat|\.cmd|\.scr|\.pif|\.com|\.vbs|\.js)",
                severity=Severity.HIGH,
                description="檢測惡意檔案類型"
            ),
            IDSSignature(
                id="sig_004",
                name="暴力破解檢測",
                attack_type=AttackType.BRUTE_FORCE,
                pattern=r"(login|password|admin|root|user)",
                severity=Severity.MEDIUM,
                description="檢測暴力破解嘗試"
            ),
            IDSSignature(
                id="sig_005",
                name="殭屍網路檢測",
                attack_type=AttackType.BOTNET,
                pattern=r"(botnet|command.*control|cnc|irc|backdoor)",
                severity=Severity.CRITICAL,
                description="檢測殭屍網路通訊"
            )
        ]
        
        for signature in default_signatures:
            self.add_signature(signature)

    def _init_ml_models(self):
        """初始化機器學習模型"""
        try:
            # 使用隔離森林進行異常檢測
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            logger.info("機器學習模型初始化完成")
        except Exception as e:
            logger.error(f"機器學習模型初始化失敗: {e}")

    def add_signature(self, signature: IDSSignature):
        """新增IDS簽名"""
        self.signatures.append(signature)
        
        # 儲存到資料庫
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO ids_signatures 
            (id, name, attack_type, pattern, severity, description, enabled, false_positive_rate)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            signature.id, signature.name, signature.attack_type.value,
            signature.pattern, signature.severity.value, signature.description,
            signature.enabled, signature.false_positive_rate
        ))
        self.db_conn.commit()
        
        logger.info(f"已新增IDS簽名: {signature.name}")

    def analyze_packet(self, packet_info) -> List[AttackEvent]:
        """分析封包並檢測攻擊"""
        detected_attacks = []
        
        # 簽名檢測
        signature_attacks = self._signature_detection(packet_info)
        detected_attacks.extend(signature_attacks)
        
        # 異常檢測
        anomaly_attacks = self._anomaly_detection(packet_info)
        detected_attacks.extend(anomaly_attacks)
        
        # 行為分析
        behavioral_attacks = self._behavioral_analysis(packet_info)
        detected_attacks.extend(behavioral_attacks)
        
        # 機器學習檢測
        if self.config.get('ml_detection', True):
            ml_attacks = self._ml_detection(packet_info)
            detected_attacks.extend(ml_attacks)
        
        # 特殊攻擊檢測
        special_attacks = self._special_attack_detection(packet_info)
        detected_attacks.extend(special_attacks)
        
        # 記錄攻擊事件
        for attack in detected_attacks:
            self._log_attack_event(attack)
        
        return detected_attacks

    def _signature_detection(self, packet_info) -> List[AttackEvent]:
        """簽名檢測"""
        attacks = []
        
        if not packet_info.payload:
            return attacks
        
        payload_str = packet_info.payload.decode('utf-8', errors='ignore').lower()
        
        for signature in self.signatures:
            if not signature.enabled:
                continue
            
            try:
                if re.search(signature.pattern, payload_str, re.IGNORECASE):
                    attack = AttackEvent(
                        timestamp=datetime.now(),
                        source_ip=packet_info.source_ip,
                        dest_ip=packet_info.dest_ip,
                        attack_type=signature.attack_type,
                        severity=signature.severity,
                        signature_id=signature.id,
                        description=f"{signature.name}: {signature.description}",
                        payload=packet_info.payload,
                        confidence=0.8
                    )
                    attacks.append(attack)
                    logger.warning(f"簽名檢測到攻擊: {signature.name} 來自 {packet_info.source_ip}")
            except Exception as e:
                logger.error(f"簽名檢測錯誤: {e}")
        
        return attacks

    def _anomaly_detection(self, packet_info) -> List[AttackEvent]:
        """異常檢測"""
        attacks = []
        
        # 檢查異常的封包大小
        if packet_info.payload_size > 65535:  # 超過最大封包大小
            attack = AttackEvent(
                timestamp=datetime.now(),
                source_ip=packet_info.source_ip,
                dest_ip=packet_info.dest_ip,
                attack_type=AttackType.DDOS,
                severity=Severity.MEDIUM,
                signature_id="anomaly_001",
                description="異常大的封包大小",
                payload=packet_info.payload,
                confidence=0.6
            )
            attacks.append(attack)
        
        # 檢查異常的端口
        if packet_info.dest_port > 65535 or packet_info.dest_port < 0:
            attack = AttackEvent(
                timestamp=datetime.now(),
                source_ip=packet_info.source_ip,
                dest_ip=packet_info.dest_ip,
                attack_type=AttackType.PORT_SCAN,
                severity=Severity.MEDIUM,
                signature_id="anomaly_002",
                description="異常的端口號",
                payload=packet_info.payload,
                confidence=0.7
            )
            attacks.append(attack)
        
        return attacks

    def _behavioral_analysis(self, packet_info) -> List[AttackEvent]:
        """行為分析"""
        attacks = []
        source_ip = packet_info.source_ip
        
        # 更新行為檔案
        self._update_behavioral_profile(packet_info)
        
        # 檢查行為異常
        if source_ip in self.behavioral_profiles:
            profile = self.behavioral_profiles[source_ip]
            
            # 檢查異常端口使用
            if packet_info.dest_port not in profile.normal_ports:
                if len(profile.normal_ports) > 5:  # 只有當有足夠的歷史資料時
                    attack = AttackEvent(
                        timestamp=datetime.now(),
                        source_ip=source_ip,
                        dest_ip=packet_info.dest_ip,
                        attack_type=AttackType.PORT_SCAN,
                        severity=Severity.MEDIUM,
                        signature_id="behavioral_001",
                        description="異常端口訪問行為",
                        payload=packet_info.payload,
                        confidence=0.6
                    )
                    attacks.append(attack)
            
            # 檢查異常時間模式
            current_hour = datetime.now().hour
            if current_hour not in profile.normal_times:
                if len(profile.normal_times) > 10:
                    attack = AttackEvent(
                        timestamp=datetime.now(),
                        source_ip=source_ip,
                        dest_ip=packet_info.dest_ip,
                        attack_type=AttackType.INSIDER_THREAT,
                        severity=Severity.LOW,
                        signature_id="behavioral_002",
                        description="異常時間訪問模式",
                        payload=packet_info.payload,
                        confidence=0.4
                    )
                    attacks.append(attack)
        
        return attacks

    def _ml_detection(self, packet_info) -> List[AttackEvent]:
        """機器學習檢測"""
        attacks = []
        
        if not self.anomaly_detector:
            return attacks
        
        try:
            # 準備特徵向量
            features = self._extract_features(packet_info)
            features_array = np.array(features).reshape(1, -1)
            
            # 標準化特徵
            features_scaled = self.scaler.fit_transform(features_array)
            
            # 異常檢測
            anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
            
            if anomaly_score < -0.5:  # 異常閾值
                attack = AttackEvent(
                    timestamp=datetime.now(),
                    source_ip=packet_info.source_ip,
                    dest_ip=packet_info.dest_ip,
                    attack_type=AttackType.ZERO_DAY,
                    severity=Severity.HIGH,
                    signature_id="ml_001",
                    description=f"機器學習檢測到異常行為 (分數: {anomaly_score:.3f})",
                    payload=packet_info.payload,
                    confidence=abs(anomaly_score)
                )
                attacks.append(attack)
                logger.warning(f"ML檢測到異常: {packet_info.source_ip}, 分數: {anomaly_score:.3f}")
        
        except Exception as e:
            logger.error(f"機器學習檢測錯誤: {e}")
        
        return attacks

    def _extract_features(self, packet_info) -> List[float]:
        """提取特徵向量"""
        features = [
            float(packet_info.source_port),
            float(packet_info.dest_port),
            float(packet_info.payload_size),
            float(len(packet_info.payload) if packet_info.payload else 0),
            float(hash(packet_info.protocol) % 1000),  # 協議雜湊
            float(hash(packet_info.source_ip) % 1000),  # IP雜湊
            float(datetime.now().hour),  # 時間特徵
            float(datetime.now().weekday()),  # 星期特徵
        ]
        
        return features

    def _special_attack_detection(self, packet_info) -> List[AttackEvent]:
        """特殊攻擊檢測"""
        attacks = []
        
        # 端口掃描檢測
        port_scan_attacks = self.port_scan_detector.detect(packet_info)
        attacks.extend(port_scan_attacks)
        
        # DDoS檢測
        ddos_attacks = self.ddos_detector.detect(packet_info)
        attacks.extend(ddos_attacks)
        
        return attacks

    def _update_behavioral_profile(self, packet_info):
        """更新行為檔案"""
        source_ip = packet_info.source_ip
        
        if source_ip not in self.behavioral_profiles:
            self.behavioral_profiles[source_ip] = BehavioralProfile(
                ip_address=source_ip,
                normal_ports=set(),
                normal_protocols=set(),
                normal_times=[],
                normal_payload_sizes=[],
                connection_frequency=0.0,
                last_seen=datetime.now()
            )
        
        profile = self.behavioral_profiles[source_ip]
        
        # 更新正常端口
        profile.normal_ports.add(packet_info.dest_port)
        
        # 更新正常協議
        profile.normal_protocols.add(packet_info.protocol)
        
        # 更新正常時間
        current_hour = datetime.now().hour
        profile.normal_times.append(current_hour)
        if len(profile.normal_times) > 100:  # 保持最近100個記錄
            profile.normal_times = profile.normal_times[-100:]
        
        # 更新正常負載大小
        profile.normal_payload_sizes.append(packet_info.payload_size)
        if len(profile.normal_payload_sizes) > 100:
            profile.normal_payload_sizes = profile.normal_payload_sizes[-100:]
        
        # 更新連線頻率
        now = datetime.now()
        time_diff = (now - profile.last_seen).total_seconds()
        if time_diff > 0:
            profile.connection_frequency = 1.0 / time_diff
        
        profile.last_seen = now

    def _log_attack_event(self, attack: AttackEvent):
        """記錄攻擊事件"""
        self.attack_events.append(attack)
        
        # 儲存到資料庫
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO attack_events 
            (timestamp, source_ip, dest_ip, attack_type, severity, signature_id, 
             description, payload, confidence, blocked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            attack.timestamp.isoformat(),
            attack.source_ip,
            attack.dest_ip,
            attack.attack_type.value,
            attack.severity.value,
            attack.signature_id,
            attack.description,
            attack.payload,
            attack.confidence,
            attack.blocked
        ))
        self.db_conn.commit()

    def get_attack_statistics(self) -> Dict:
        """獲取攻擊統計"""
        stats = {
            'total_attacks': len(self.attack_events),
            'attacks_by_type': defaultdict(int),
            'attacks_by_severity': defaultdict(int),
            'attacks_by_source': defaultdict(int),
            'recent_attacks': []
        }
        
        # 統計攻擊類型
        for attack in self.attack_events:
            stats['attacks_by_type'][attack.attack_type.value] += 1
            stats['attacks_by_severity'][attack.severity.value] += 1
            stats['attacks_by_source'][attack.source_ip] += 1
        
        # 最近攻擊
        recent_attacks = sorted(self.attack_events, key=lambda x: x.timestamp, reverse=True)[:10]
        stats['recent_attacks'] = [
            {
                'timestamp': attack.timestamp.isoformat(),
                'source_ip': attack.source_ip,
                'attack_type': attack.attack_type.value,
                'severity': attack.severity.value,
                'description': attack.description
            }
            for attack in recent_attacks
        ]
        
        return stats

    def get_behavioral_profiles(self) -> Dict:
        """獲取行為檔案"""
        return {
            ip: {
                'normal_ports': list(profile.normal_ports),
                'normal_protocols': list(profile.normal_protocols),
                'connection_frequency': profile.connection_frequency,
                'last_seen': profile.last_seen.isoformat(),
                'anomaly_score': profile.anomaly_score
            }
            for ip, profile in self.behavioral_profiles.items()
        }

class PortScanDetector:
    """端口掃描檢測器"""
    
    def __init__(self):
        self.scan_attempts = defaultdict(list)
        self.scan_threshold = 10  # 10次嘗試視為掃描
        self.time_window = 60  # 60秒時間窗口
    
    def detect(self, packet_info) -> List[AttackEvent]:
        """檢測端口掃描"""
        attacks = []
        source_ip = packet_info.source_ip
        current_time = time.time()
        
        # 記錄掃描嘗試
        self.scan_attempts[source_ip].append({
            'timestamp': current_time,
            'port': packet_info.dest_port,
            'protocol': packet_info.protocol
        })
        
        # 清理舊記錄
        self.scan_attempts[source_ip] = [
            attempt for attempt in self.scan_attempts[source_ip]
            if current_time - attempt['timestamp'] < self.time_window
        ]
        
        # 檢查是否超過閾值
        if len(self.scan_attempts[source_ip]) >= self.scan_threshold:
            unique_ports = set(attempt['port'] for attempt in self.scan_attempts[source_ip])
            
            if len(unique_ports) >= 5:  # 至少5個不同端口
                attack = AttackEvent(
                    timestamp=datetime.now(),
                    source_ip=source_ip,
                    dest_ip=packet_info.dest_ip,
                    attack_type=AttackType.PORT_SCAN,
                    severity=Severity.HIGH,
                    signature_id="port_scan_001",
                    description=f"檢測到端口掃描: {len(unique_ports)}個端口",
                    payload=packet_info.payload,
                    confidence=0.9
                )
                attacks.append(attack)
                logger.warning(f"檢測到端口掃描: {source_ip} 掃描了 {len(unique_ports)} 個端口")
        
        return attacks

class DDoSDetector:
    """DDoS攻擊檢測器"""
    
    def __init__(self):
        self.connection_counts = defaultdict(int)
        self.last_reset = time.time()
        self.reset_interval = 60  # 60秒重置一次
        self.ddos_threshold = 100  # 100個連線視為DDoS
    
    def detect(self, packet_info) -> List[AttackEvent]:
        """檢測DDoS攻擊"""
        attacks = []
        current_time = time.time()
        
        # 重置計數器
        if current_time - self.last_reset > self.reset_interval:
            self.connection_counts.clear()
            self.last_reset = current_time
        
        # 增加連線計數
        self.connection_counts[packet_info.source_ip] += 1
        
        # 檢查是否超過閾值
        if self.connection_counts[packet_info.source_ip] >= self.ddos_threshold:
            attack = AttackEvent(
                timestamp=datetime.now(),
                source_ip=packet_info.source_ip,
                dest_ip=packet_info.dest_ip,
                attack_type=AttackType.DDOS,
                severity=Severity.CRITICAL,
                signature_id="ddos_001",
                description=f"DDoS攻擊檢測: {self.connection_counts[packet_info.source_ip]}個連線",
                payload=packet_info.payload,
                confidence=0.95
            )
            attacks.append(attack)
            logger.critical(f"檢測到DDoS攻擊: {packet_info.source_ip}")
        
        return attacks

class MachineLearningDetector:
    """機器學習檢測器"""
    
    def __init__(self):
        self.model = None
        self.feature_scaler = StandardScaler()
        self.training_data = []
        self.is_trained = False
    
    def train_model(self, training_data: List[Dict]):
        """訓練模型"""
        try:
            # 準備訓練資料
            X = []
            y = []
            
            for data in training_data:
                features = self._extract_features(data)
                X.append(features)
                y.append(data.get('label', 0))  # 0: 正常, 1: 攻擊
            
            if len(X) < 100:  # 需要足夠的訓練資料
                logger.warning("訓練資料不足，跳過模型訓練")
                return False
            
            # 標準化特徵
            X_scaled = self.feature_scaler.fit_transform(X)
            
            # 訓練模型
            from sklearn.ensemble import RandomForestClassifier
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.model.fit(X_scaled, y)
            
            self.is_trained = True
            logger.info("機器學習模型訓練完成")
            return True
        
        except Exception as e:
            logger.error(f"模型訓練失敗: {e}")
            return False
    
    def predict(self, packet_info) -> Tuple[bool, float]:
        """預測是否為攻擊"""
        if not self.is_trained or not self.model:
            return False, 0.0
        
        try:
            features = self._extract_features(packet_info)
            features_scaled = self.feature_scaler.transform([features])
            
            prediction = self.model.predict(features_scaled)[0]
            probability = self.model.predict_proba(features_scaled)[0][1]
            
            return bool(prediction), probability
        
        except Exception as e:
            logger.error(f"預測錯誤: {e}")
            return False, 0.0
    
    def _extract_features(self, data) -> List[float]:
        """提取特徵"""
        features = [
            float(data.get('source_port', 0)),
            float(data.get('dest_port', 0)),
            float(data.get('payload_size', 0)),
            float(data.get('protocol_hash', 0)),
            float(data.get('hour', 0)),
            float(data.get('weekday', 0)),
        ]
        return features

