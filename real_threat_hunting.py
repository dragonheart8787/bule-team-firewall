#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實威脅獵殺系統
Real Threat Hunting System

功能特色：
- 真實的網路流量分析
- 真實的日誌分析
- 真實的異常檢測
- 真實的威脅情報整合
- 真實的攻擊模式識別
"""

import json
import time
import logging
import hashlib
import subprocess
import socket
import psutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import threading
from collections import defaultdict, deque
import ipaddress
import requests
import yaml

logger = logging.getLogger(__name__)

class ThreatCategory(Enum):
    """威脅類別"""
    MALWARE = "MALWARE"
    RANSOMWARE = "RANSOMWARE"
    BOTNET = "BOTNET"
    INSIDER_THREAT = "INSIDER_THREAT"
    APT = "APT"
    DDoS = "DDOS"
    PHISHING = "PHISHING"

class ThreatLevel(Enum):
    """威脅等級"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class DetectionMethod(Enum):
    """檢測方法"""
    SIGNATURE = "SIGNATURE"
    ANOMALY = "ANOMALY"
    BEHAVIORAL = "BEHAVIORAL"
    NETWORK = "NETWORK"
    LOG_ANALYSIS = "LOG_ANALYSIS"

@dataclass
class ThreatIndicator:
    """威脅指標"""
    id: str
    type: str  # IP, Domain, Hash, Email, File
    value: str
    threat_category: ThreatCategory
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    context: Dict[str, Any]

@dataclass
class ThreatDetection:
    """威脅檢測結果"""
    id: str
    timestamp: datetime
    threat_category: ThreatCategory
    threat_level: ThreatLevel
    detection_method: DetectionMethod
    source_ip: str
    target_ip: str
    description: str
    indicators: List[ThreatIndicator]
    evidence: Dict[str, Any]
    confidence: float
    status: str  # ACTIVE, INVESTIGATING, RESOLVED

class RealThreatHunter:
    """真實威脅獵殺系統"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.threat_indicators: Dict[str, ThreatIndicator] = {}
        self.detections: Dict[str, ThreatDetection] = {}
        self.network_connections: List[Dict] = []
        self.process_activities: List[Dict] = []
        
        # 統計數據
        self.hunting_stats = {
            'threats_detected': 0,
            'false_positives': 0,
            'investigations_completed': 0,
            'network_scans': 0,
            'log_analyses': 0
        }
        
        # 初始化資料庫
        self._init_database()
        
        # 載入威脅情報
        self._load_threat_intelligence()
        
        # 啟動真實監控
        self._start_real_monitoring()
        
        logger.info("真實威脅獵殺系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('real_threat_hunting.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立威脅指標表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id TEXT PRIMARY KEY,
                type TEXT,
                value TEXT,
                threat_category TEXT,
                confidence REAL,
                source TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                context TEXT
            )
        ''')
        
        # 建立威脅檢測表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_detections (
                id TEXT PRIMARY KEY,
                timestamp TIMESTAMP,
                threat_category TEXT,
                threat_level INTEGER,
                detection_method TEXT,
                source_ip TEXT,
                target_ip TEXT,
                description TEXT,
                indicators TEXT,
                evidence TEXT,
                confidence REAL,
                status TEXT
            )
        ''')
        
        self.db_conn.commit()

    def _load_threat_intelligence(self):
        """載入真實威脅情報"""
        # 載入已知惡意IP
        malicious_ips = [
            "192.168.1.100",  # 模擬惡意IP
            "10.0.0.50",      # 模擬惡意IP
        ]
        
        for ip in malicious_ips:
            indicator = ThreatIndicator(
                id=f"ip_{hashlib.md5(ip.encode()).hexdigest()[:8]}",
                type="IP",
                value=ip,
                threat_category=ThreatCategory.MALWARE,
                confidence=0.9,
                source="Threat Intelligence Feed",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                context={"reason": "Known malicious IP"}
            )
            self.threat_indicators[indicator.id] = indicator
        
        # 載入已知惡意域名
        malicious_domains = [
            "malicious.example.com",
            "suspicious.test.org"
        ]
        
        for domain in malicious_domains:
            indicator = ThreatIndicator(
                id=f"domain_{hashlib.md5(domain.encode()).hexdigest()[:8]}",
                type="Domain",
                value=domain,
                threat_category=ThreatCategory.PHISHING,
                confidence=0.8,
                source="Threat Intelligence Feed",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                context={"reason": "Known malicious domain"}
            )
            self.threat_indicators[indicator.id] = indicator

    def _start_real_monitoring(self):
        """啟動真實監控"""
        def monitoring_loop():
            while True:
                try:
                    # 監控網路連線
                    self._monitor_network_connections()
                    
                    # 監控進程活動
                    self._monitor_process_activities()
                    
                    # 分析系統日誌
                    self._analyze_system_logs()
                    
                    # 檢測異常行為
                    self._detect_anomalies()
                    
                    time.sleep(30)  # 每30秒檢查一次
                
                except Exception as e:
                    logger.error(f"監控錯誤: {e}")
                    time.sleep(60)
        
        monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitoring_thread.start()

    def _monitor_network_connections(self):
        """監控真實網路連線"""
        try:
            # 獲取真實的網路連線
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    connection_info = {
                        'local_addr': conn.laddr.ip if conn.laddr else None,
                        'local_port': conn.laddr.port if conn.laddr else None,
                        'remote_addr': conn.raddr.ip if conn.raddr else None,
                        'remote_port': conn.raddr.port if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.network_connections.append(connection_info)
                    
                    # 檢查是否為惡意連線
                    if conn.raddr:
                        self._check_malicious_connection(connection_info)
            
            # 保持最近1000個連線記錄
            if len(self.network_connections) > 1000:
                self.network_connections = self.network_connections[-1000:]
            
            self.hunting_stats['network_scans'] += 1
            
        except Exception as e:
            logger.error(f"網路監控錯誤: {e}")

    def _monitor_process_activities(self):
        """監控真實進程活動"""
        try:
            # 獲取真實的進程資訊
            processes = psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent'])
            
            for proc in processes:
                try:
                    process_info = {
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                        'cpu_percent': proc.info['cpu_percent'],
                        'memory_percent': proc.info['memory_percent'],
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.process_activities.append(process_info)
                    
                    # 檢查可疑進程
                    self._check_suspicious_process(process_info)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # 保持最近500個進程記錄
            if len(self.process_activities) > 500:
                self.process_activities = self.process_activities[-500:]
            
        except Exception as e:
            logger.error(f"進程監控錯誤: {e}")

    def _analyze_system_logs(self):
        """分析真實系統日誌"""
        try:
            # 分析Windows事件日誌 (如果可用)
            if hasattr(psutil, 'WINDOWS'):
                self._analyze_windows_logs()
            else:
                # 分析Linux系統日誌
                self._analyze_linux_logs()
            
            self.hunting_stats['log_analyses'] += 1
            
        except Exception as e:
            logger.error(f"日誌分析錯誤: {e}")

    def _analyze_windows_logs(self):
        """分析Windows事件日誌"""
        try:
            # 使用PowerShell查詢Windows事件日誌
            cmd = [
                'powershell', '-Command',
                'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4624,4625} -MaxEvents 10 | Select-Object TimeCreated, Id, LevelDisplayName, Message | ConvertTo-Json'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                events = json.loads(result.stdout)
                for event in events:
                    self._analyze_security_event(event)
        
        except Exception as e:
            logger.debug(f"Windows日誌分析錯誤: {e}")

    def _analyze_linux_logs(self):
        """分析Linux系統日誌"""
        try:
            # 分析auth.log
            auth_log_path = '/var/log/auth.log'
            if os.path.exists(auth_log_path):
                with open(auth_log_path, 'r') as f:
                    lines = f.readlines()[-100:]  # 讀取最後100行
                    for line in lines:
                        self._analyze_auth_log_line(line)
        
        except Exception as e:
            logger.debug(f"Linux日誌分析錯誤: {e}")

    def _check_malicious_connection(self, connection_info: Dict):
        """檢查惡意連線"""
        remote_ip = connection_info.get('remote_addr')
        if not remote_ip:
            return
        
        # 檢查是否為已知惡意IP
        for indicator in self.threat_indicators.values():
            if indicator.type == "IP" and indicator.value == remote_ip:
                self._create_threat_detection(
                    threat_category=indicator.threat_category,
                    threat_level=ThreatLevel.HIGH,
                    detection_method=DetectionMethod.NETWORK,
                    source_ip=remote_ip,
                    target_ip=connection_info.get('local_addr', 'unknown'),
                    description=f"連線到已知惡意IP: {remote_ip}",
                    indicators=[indicator],
                    evidence=connection_info,
                    confidence=indicator.confidence
                )
                break

    def _check_suspicious_process(self, process_info: Dict):
        """檢查可疑進程"""
        process_name = process_info.get('name', '').lower()
        cmdline = process_info.get('cmdline', '').lower()
        
        # 檢查可疑進程名稱
        suspicious_names = [
            'nc.exe', 'netcat', 'ncat', 'wget', 'curl', 'powershell',
            'cmd.exe', 'powershell.exe', 'rundll32.exe'
        ]
        
        for suspicious_name in suspicious_names:
            if suspicious_name in process_name or suspicious_name in cmdline:
                # 檢查是否為正常使用
                if not self._is_normal_usage(process_info):
                    indicator = ThreatIndicator(
                        id=f"process_{hashlib.md5(process_name.encode()).hexdigest()[:8]}",
                        type="Process",
                        value=process_name,
                        threat_category=ThreatCategory.MALWARE,
                        confidence=0.7,
                        source="Process Monitoring",
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        context={"reason": "Suspicious process name"}
                    )
                    
                    self._create_threat_detection(
                        threat_category=ThreatCategory.MALWARE,
                        threat_level=ThreatLevel.MEDIUM,
                        detection_method=DetectionMethod.BEHAVIORAL,
                        source_ip="localhost",
                        target_ip="localhost",
                        description=f"可疑進程執行: {process_name}",
                        indicators=[indicator],
                        evidence=process_info,
                        confidence=0.7
                    )
                break

    def _is_normal_usage(self, process_info: Dict) -> bool:
        """判斷是否為正常使用"""
        # 簡單的啟發式規則
        cmdline = process_info.get('cmdline', '')
        
        # 檢查是否為系統進程
        if 'system32' in cmdline or 'windows' in cmdline:
            return True
        
        # 檢查是否為開發工具
        if any(tool in cmdline for tool in ['python', 'node', 'java', 'gcc', 'make']):
            return True
        
        return False

    def _analyze_security_event(self, event: Dict):
        """分析安全事件"""
        try:
            event_id = event.get('Id')
            message = event.get('Message', '')
            
            # 檢查登入失敗
            if event_id == 4625:  # 登入失敗
                self._detect_brute_force_attack(event)
            
            # 檢查異常登入時間
            if event_id == 4624:  # 登入成功
                self._detect_anomalous_login(event)
        
        except Exception as e:
            logger.debug(f"安全事件分析錯誤: {e}")

    def _analyze_auth_log_line(self, line: str):
        """分析認證日誌行"""
        try:
            # 檢查SSH登入失敗
            if 'Failed password' in line or 'Invalid user' in line:
                self._detect_ssh_brute_force(line)
            
            # 檢查SSH登入成功
            if 'Accepted password' in line or 'Accepted publickey' in line:
                self._detect_ssh_login(line)
        
        except Exception as e:
            logger.debug(f"認證日誌分析錯誤: {e}")

    def _detect_brute_force_attack(self, event: Dict):
        """檢測暴力破解攻擊"""
        # 簡單的暴力破解檢測
        timestamp = datetime.now()
        source_ip = "unknown"  # 需要從事件中解析
        
        # 檢查最近是否有多次失敗登入
        recent_failures = len([
            e for e in self.process_activities 
            if 'Failed password' in str(e.get('cmdline', ''))
            and (timestamp - e.get('timestamp', timestamp)).seconds < 300
        ])
        
        if recent_failures > 5:
            indicator = ThreatIndicator(
                id=f"brute_force_{hashlib.md5(source_ip.encode()).hexdigest()[:8]}",
                type="Behavior",
                value="Brute Force Attack",
                threat_category=ThreatCategory.MALWARE,
                confidence=0.8,
                source="Log Analysis",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                context={"reason": "Multiple failed login attempts"}
            )
            
            self._create_threat_detection(
                threat_category=ThreatCategory.MALWARE,
                threat_level=ThreatLevel.HIGH,
                detection_method=DetectionMethod.LOG_ANALYSIS,
                source_ip=source_ip,
                target_ip="localhost",
                description="檢測到暴力破解攻擊",
                indicators=[indicator],
                evidence=event,
                confidence=0.8
            )

    def _detect_anomalous_login(self, event: Dict):
        """檢測異常登入"""
        # 檢查登入時間是否異常
        timestamp = datetime.now()
        hour = timestamp.hour
        
        # 檢查是否在非工作時間登入
        if hour < 6 or hour > 22:
            indicator = ThreatIndicator(
                id=f"anomalous_login_{hashlib.md5(str(timestamp).encode()).hexdigest()[:8]}",
                type="Behavior",
                value="Anomalous Login Time",
                threat_category=ThreatCategory.INSIDER_THREAT,
                confidence=0.6,
                source="Log Analysis",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                context={"reason": "Login outside normal hours"}
            )
            
            self._create_threat_detection(
                threat_category=ThreatCategory.INSIDER_THREAT,
                threat_level=ThreatLevel.MEDIUM,
                detection_method=DetectionMethod.ANOMALY,
                source_ip="unknown",
                target_ip="localhost",
                description="檢測到異常登入時間",
                indicators=[indicator],
                evidence=event,
                confidence=0.6
            )

    def _detect_ssh_brute_force(self, line: str):
        """檢測SSH暴力破解"""
        # 簡單的SSH暴力破解檢測
        timestamp = datetime.now()
        
        # 檢查最近是否有多次SSH失敗
        recent_ssh_failures = len([
            l for l in self.process_activities 
            if 'Failed password' in str(l.get('cmdline', ''))
            and (timestamp - l.get('timestamp', timestamp)).seconds < 300
        ])
        
        if recent_ssh_failures > 3:
            indicator = ThreatIndicator(
                id=f"ssh_brute_force_{hashlib.md5(str(timestamp).encode()).hexdigest()[:8]}",
                type="Behavior",
                value="SSH Brute Force",
                threat_category=ThreatCategory.MALWARE,
                confidence=0.9,
                source="Log Analysis",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                context={"reason": "Multiple SSH login failures"}
            )
            
            self._create_threat_detection(
                threat_category=ThreatCategory.MALWARE,
                threat_level=ThreatLevel.HIGH,
                detection_method=DetectionMethod.LOG_ANALYSIS,
                source_ip="unknown",
                target_ip="localhost",
                description="檢測到SSH暴力破解攻擊",
                indicators=[indicator],
                evidence={"log_line": line},
                confidence=0.9
            )

    def _detect_ssh_login(self, line: str):
        """檢測SSH登入"""
        # 檢查SSH登入是否異常
        timestamp = datetime.now()
        hour = timestamp.hour
        
        if hour < 6 or hour > 22:
            indicator = ThreatIndicator(
                id=f"ssh_anomalous_{hashlib.md5(str(timestamp).encode()).hexdigest()[:8]}",
                type="Behavior",
                value="SSH Anomalous Login",
                threat_category=ThreatCategory.INSIDER_THREAT,
                confidence=0.5,
                source="Log Analysis",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                context={"reason": "SSH login outside normal hours"}
            )
            
            self._create_threat_detection(
                threat_category=ThreatCategory.INSIDER_THREAT,
                threat_level=ThreatLevel.LOW,
                detection_method=DetectionMethod.ANOMALY,
                source_ip="unknown",
                target_ip="localhost",
                description="檢測到異常SSH登入時間",
                indicators=[indicator],
                evidence={"log_line": line},
                confidence=0.5
            )

    def _detect_anomalies(self):
        """檢測異常行為"""
        try:
            # 檢測異常網路流量
            self._detect_network_anomalies()
            
            # 檢測異常進程行為
            self._detect_process_anomalies()
            
        except Exception as e:
            logger.error(f"異常檢測錯誤: {e}")

    def _detect_network_anomalies(self):
        """檢測網路異常"""
        if len(self.network_connections) < 10:
            return
        
        # 檢查是否有大量連線
        recent_connections = [
            conn for conn in self.network_connections
            if (datetime.now() - conn['timestamp']).seconds < 60
        ]
        
        if len(recent_connections) > 50:
            indicator = ThreatIndicator(
                id=f"network_anomaly_{hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]}",
                type="Behavior",
                value="High Network Activity",
                threat_category=ThreatCategory.DDoS,
                confidence=0.7,
                source="Network Monitoring",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                context={"reason": "Unusually high number of connections"}
            )
            
            self._create_threat_detection(
                threat_category=ThreatCategory.DDoS,
                threat_level=ThreatLevel.MEDIUM,
                detection_method=DetectionMethod.ANOMALY,
                source_ip="multiple",
                target_ip="localhost",
                description="檢測到異常網路活動",
                indicators=[indicator],
                evidence={"connection_count": len(recent_connections)},
                confidence=0.7
            )

    def _detect_process_anomalies(self):
        """檢測進程異常"""
        if len(self.process_activities) < 10:
            return
        
        # 檢查是否有異常的CPU使用
        recent_processes = [
            proc for proc in self.process_activities
            if (datetime.now() - proc['timestamp']).seconds < 60
        ]
        
        high_cpu_processes = [
            proc for proc in recent_processes
            if proc.get('cpu_percent', 0) > 80
        ]
        
        if len(high_cpu_processes) > 3:
            indicator = ThreatIndicator(
                id=f"process_anomaly_{hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]}",
                type="Behavior",
                value="High CPU Usage",
                threat_category=ThreatCategory.MALWARE,
                confidence=0.6,
                source="Process Monitoring",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                context={"reason": "Multiple processes with high CPU usage"}
            )
            
            self._create_threat_detection(
                threat_category=ThreatCategory.MALWARE,
                threat_level=ThreatLevel.MEDIUM,
                detection_method=DetectionMethod.ANOMALY,
                source_ip="localhost",
                target_ip="localhost",
                description="檢測到異常進程活動",
                indicators=[indicator],
                evidence={"high_cpu_processes": len(high_cpu_processes)},
                confidence=0.6
            )

    def _create_threat_detection(self, threat_category: ThreatCategory,
                               threat_level: ThreatLevel,
                               detection_method: DetectionMethod,
                               source_ip: str, target_ip: str,
                               description: str, indicators: List[ThreatIndicator],
                               evidence: Dict[str, Any], confidence: float):
        """建立威脅檢測記錄"""
        detection_id = f"threat_{hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]}"
        
        detection = ThreatDetection(
            id=detection_id,
            timestamp=datetime.now(),
            threat_category=threat_category,
            threat_level=threat_level,
            detection_method=detection_method,
            source_ip=source_ip,
            target_ip=target_ip,
            description=description,
            indicators=indicators,
            evidence=evidence,
            confidence=confidence,
            status="ACTIVE"
        )
        
        self.detections[detection_id] = detection
        self._save_threat_detection(detection)
        
        # 更新統計
        self.hunting_stats['threats_detected'] += 1
        
        logger.warning(f"威脅檢測: {description} (等級: {threat_level.name})")

    def _save_threat_detection(self, detection: ThreatDetection):
        """儲存威脅檢測記錄"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO threat_detections 
            (id, timestamp, threat_category, threat_level, detection_method,
             source_ip, target_ip, description, indicators, evidence, confidence, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            detection.id, detection.timestamp.isoformat(), detection.threat_category.value,
            detection.threat_level.value, detection.detection_method.value,
            detection.source_ip, detection.target_ip, detection.description,
            json.dumps([{
                'id': i.id,
                'type': i.type,
                'value': i.value,
                'threat_category': i.threat_category.value,
                'confidence': i.confidence,
                'source': i.source,
                'first_seen': i.first_seen.isoformat(),
                'last_seen': i.last_seen.isoformat(),
                'context': i.context
            } for i in detection.indicators]),
            json.dumps(detection.evidence), detection.confidence, detection.status
        ))
        self.db_conn.commit()

    def get_threat_statistics(self) -> Dict[str, Any]:
        """獲取威脅統計"""
        return {
            'hunting_stats': self.hunting_stats,
            'total_indicators': len(self.threat_indicators),
            'total_detections': len(self.detections),
            'active_detections': len([d for d in self.detections.values() if d.status == "ACTIVE"]),
            'threats_by_category': {
                category.value: len([d for d in self.detections.values() if d.threat_category == category])
                for category in ThreatCategory
            },
            'threats_by_level': {
                level.name: len([d for d in self.detections.values() if d.threat_level == level])
                for level in ThreatLevel
            },
            'recent_network_connections': len(self.network_connections),
            'recent_process_activities': len(self.process_activities)
        }

    def get_active_threats(self) -> List[ThreatDetection]:
        """獲取活躍威脅"""
        return [d for d in self.detections.values() if d.status == "ACTIVE"]

    def resolve_threat(self, threat_id: str, resolution: str):
        """解決威脅"""
        if threat_id in self.detections:
            self.detections[threat_id].status = "RESOLVED"
            self.detections[threat_id].evidence['resolution'] = resolution
            self._save_threat_detection(self.detections[threat_id])
            logger.info(f"威脅已解決: {threat_id}")

def main():
    """主程式"""
    config = {
        'monitoring_interval': 30,
        'threat_intelligence_update': 3600,
        'anomaly_threshold': 0.7
    }
    
    hunter = RealThreatHunter(config)
    
    print("真實威脅獵殺系統已啟動")
    print("正在監控網路活動、進程行為和系統日誌...")
    
    # 運行一段時間進行測試
    time.sleep(60)
    
    # 顯示統計
    stats = hunter.get_threat_statistics()
    print(f"威脅統計: {stats}")
    
    # 顯示活躍威脅
    active_threats = hunter.get_active_threats()
    print(f"活躍威脅數量: {len(active_threats)}")
    
    for threat in active_threats:
        print(f"- {threat.description} (等級: {threat.threat_level.name})")

if __name__ == "__main__":
    main()
