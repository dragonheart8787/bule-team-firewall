#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級SOC/指揮中心系統
Military-Grade SOC/Command Center System

功能特色：
- SIEM (Security Information and Event Management)
- SOAR (Security Orchestration, Automation, Response)
- MITRE ATT&CK 映射和防禦
- 紅藍紫隊演練
- 威脅情報整合
- 自動化回應
"""

import os
import sys
import time
import logging
import threading
import json
import sqlite3
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import subprocess
import psutil
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """威脅等級"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    MILITARY_CRITICAL = "MILITARY_CRITICAL"

class AttackTactic(Enum):
    """攻擊戰術 (MITRE ATT&CK)"""
    INITIAL_ACCESS = "T1078"        # 初始訪問
    EXECUTION = "T1059"             # 執行
    PERSISTENCE = "T1543"           # 持久化
    PRIVILEGE_ESCALATION = "T1548"  # 權限提升
    DEFENSE_EVASION = "T1562"       # 防禦規避
    CREDENTIAL_ACCESS = "T1555"     # 憑證訪問
    DISCOVERY = "T1083"             # 發現
    LATERAL_MOVEMENT = "T1021"      # 橫向移動
    COLLECTION = "T1005"            # 收集
    COMMAND_AND_CONTROL = "T1071"   # 命令與控制
    EXFILTRATION = "T1041"          # 滲透
    IMPACT = "T1489"                # 影響

class TeamType(Enum):
    """團隊類型"""
    RED_TEAM = "RED_TEAM"           # 紅隊 (攻擊)
    BLUE_TEAM = "BLUE_TEAM"         # 藍隊 (防禦)
    PURPLE_TEAM = "PURPLE_TEAM"     # 紫隊 (協作)

class IncidentStatus(Enum):
    """事件狀態"""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

@dataclass
class SecurityEvent:
    """安全事件"""
    id: str
    event_type: str
    source: str
    destination: str
    timestamp: datetime
    severity: ThreatLevel
    description: str
    raw_data: Dict[str, Any]
    indicators: List[str]
    tactics: List[AttackTactic]
    techniques: List[str]
    mitre_id: str
    confidence: float

@dataclass
class SecurityIncident:
    """安全事件"""
    id: str
    title: str
    description: str
    status: IncidentStatus
    severity: ThreatLevel
    tactics: List[AttackTactic]
    techniques: List[str]
    affected_assets: List[str]
    timeline: List[Dict[str, Any]]
    assigned_team: TeamType
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]

@dataclass
class ThreatIntelligence:
    """威脅情報"""
    id: str
    ioc_type: str  # IP, Domain, Hash, Email
    ioc_value: str
    threat_type: str
    source: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    description: str

@dataclass
class SOARPlaybook:
    """SOAR劇本"""
    id: str
    name: str
    description: str
    trigger_conditions: List[str]
    actions: List[Dict[str, Any]]
    enabled: bool
    created_at: datetime

@dataclass
class RedTeamExercise:
    """紅隊演練"""
    id: str
    name: str
    objective: str
    tactics: List[AttackTactic]
    techniques: List[str]
    target_assets: List[str]
    start_time: datetime
    end_time: Optional[datetime]
    status: str
    results: Dict[str, Any]

class MilitarySOCCommandCenter:
    """軍事級SOC/指揮中心系統"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.security_events: Dict[str, SecurityEvent] = {}
        self.security_incidents: Dict[str, SecurityIncident] = {}
        self.threat_intelligence: Dict[str, ThreatIntelligence] = {}
        self.soar_playbooks: Dict[str, SOARPlaybook] = {}
        self.red_team_exercises: Dict[str, RedTeamExercise] = {}
        self.mitre_mapping: Dict[str, Dict] = {}
        
        # 統計數據
        self.stats = {
            'total_events': 0,
            'open_incidents': 0,
            'resolved_incidents': 0,
            'threat_intel_iocs': 0,
            'active_playbooks': 0,
            'red_team_exercises': 0
        }
        
        # 初始化資料庫
        self._init_database()
        
        # 載入MITRE ATT&CK映射
        self._load_mitre_attack_mapping()
        
        # 載入威脅情報
        self._load_threat_intelligence()
        
        # 載入SOAR劇本
        self._load_soar_playbooks()
        
        # 啟動SOC監控
        self._start_soc_monitoring()
        
        logger.info("軍事級SOC/指揮中心系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('military_soc_command_center.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立安全事件表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id TEXT PRIMARY KEY,
                event_type TEXT,
                source TEXT,
                destination TEXT,
                timestamp TIMESTAMP,
                severity TEXT,
                description TEXT,
                raw_data TEXT,
                indicators TEXT,
                tactics TEXT,
                techniques TEXT,
                mitre_id TEXT,
                confidence REAL
            )
        ''')
        
        # 建立安全事件表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_incidents (
                id TEXT PRIMARY KEY,
                title TEXT,
                description TEXT,
                status TEXT,
                severity TEXT,
                tactics TEXT,
                techniques TEXT,
                affected_assets TEXT,
                timeline TEXT,
                assigned_team TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                resolved_at TIMESTAMP
            )
        ''')
        
        # 建立威脅情報表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id TEXT PRIMARY KEY,
                ioc_type TEXT,
                ioc_value TEXT,
                threat_type TEXT,
                source TEXT,
                confidence REAL,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                tags TEXT,
                description TEXT
            )
        ''')
        
        # 建立SOAR劇本表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS soar_playbooks (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                trigger_conditions TEXT,
                actions TEXT,
                enabled BOOLEAN,
                created_at TIMESTAMP
            )
        ''')
        
        # 建立紅隊演練表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS red_team_exercises (
                id TEXT PRIMARY KEY,
                name TEXT,
                objective TEXT,
                tactics TEXT,
                techniques TEXT,
                target_assets TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT,
                results TEXT
            )
        ''')
        
        self.db_conn.commit()

    def _load_mitre_attack_mapping(self):
        """載入MITRE ATT&CK映射"""
        self.mitre_mapping = {
            "T1078": {
                "name": "Valid Accounts",
                "tactic": "Initial Access",
                "description": "攻擊者使用有效帳戶來獲得對系統的初始訪問"
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": "攻擊者使用命令和腳本解釋器來執行命令"
            },
            "T1543": {
                "name": "Create or Modify System Process",
                "tactic": "Persistence",
                "description": "攻擊者創建或修改系統進程以保持持久性"
            },
            "T1548": {
                "name": "Abuse Elevation Control Mechanism",
                "tactic": "Privilege Escalation",
                "description": "攻擊者濫用權限提升控制機制"
            },
            "T1562": {
                "name": "Impair Defenses",
                "tactic": "Defense Evasion",
                "description": "攻擊者損害防禦機制"
            },
            "T1555": {
                "name": "Credentials from Password Stores",
                "tactic": "Credential Access",
                "description": "攻擊者從密碼存儲中獲取憑證"
            },
            "T1083": {
                "name": "File and Directory Discovery",
                "tactic": "Discovery",
                "description": "攻擊者發現文件和目錄"
            },
            "T1021": {
                "name": "Remote Services",
                "tactic": "Lateral Movement",
                "description": "攻擊者使用遠程服務進行橫向移動"
            },
            "T1005": {
                "name": "Data from Local System",
                "tactic": "Collection",
                "description": "攻擊者從本地系統收集數據"
            },
            "T1071": {
                "name": "Application Layer Protocol",
                "tactic": "Command and Control",
                "description": "攻擊者使用應用層協議進行命令與控制"
            },
            "T1041": {
                "name": "Exfiltration Over C2 Channel",
                "tactic": "Exfiltration",
                "description": "攻擊者通過C2通道進行數據滲透"
            },
            "T1489": {
                "name": "Service Stop",
                "tactic": "Impact",
                "description": "攻擊者停止服務以造成影響"
            }
        }

    def _load_threat_intelligence(self):
        """載入威脅情報"""
        # 載入已知惡意IP
        malicious_ips = [
            "192.168.1.100",
            "10.0.0.100",
            "172.16.0.100"
        ]
        
        for ip in malicious_ips:
            ti = ThreatIntelligence(
                id=f"ti_{hashlib.md5(ip.encode()).hexdigest()[:8]}",
                ioc_type="IP",
                ioc_value=ip,
                threat_type="Malware",
                source="Internal",
                confidence=0.9,
                first_seen=datetime.now() - timedelta(days=30),
                last_seen=datetime.now(),
                tags=["malware", "botnet", "c2"],
                description=f"已知惡意IP: {ip}"
            )
            self.threat_intelligence[ti.id] = ti
        
        # 載入已知惡意域名
        malicious_domains = [
            "malicious.example.com",
            "c2.evil.org",
            "phishing.bad.net"
        ]
        
        for domain in malicious_domains:
            ti = ThreatIntelligence(
                id=f"ti_{hashlib.md5(domain.encode()).hexdigest()[:8]}",
                ioc_type="Domain",
                ioc_value=domain,
                threat_type="C2",
                source="External",
                confidence=0.8,
                first_seen=datetime.now() - timedelta(days=15),
                last_seen=datetime.now(),
                tags=["c2", "malware", "phishing"],
                description=f"已知惡意域名: {domain}"
            )
            self.threat_intelligence[ti.id] = ti

    def _load_soar_playbooks(self):
        """載入SOAR劇本"""
        # 惡意IP阻擋劇本
        playbook1 = SOARPlaybook(
            id="playbook_001",
            name="惡意IP自動阻擋",
            description="檢測到惡意IP時自動阻擋",
            trigger_conditions=["malicious_ip_detected"],
            actions=[
                {"action": "block_ip", "target": "firewall"},
                {"action": "quarantine_device", "target": "network"},
                {"action": "send_alert", "target": "soc_team"}
            ],
            enabled=True,
            created_at=datetime.now()
        )
        self.soar_playbooks[playbook1.id] = playbook1
        
        # 橫向移動檢測劇本
        playbook2 = SOARPlaybook(
            id="playbook_002",
            name="橫向移動自動檢測",
            description="檢測到橫向移動時自動回應",
            trigger_conditions=["lateral_movement_detected"],
            actions=[
                {"action": "isolate_network", "target": "network"},
                {"action": "collect_forensics", "target": "affected_systems"},
                {"action": "escalate_incident", "target": "soc_team"}
            ],
            enabled=True,
            created_at=datetime.now()
        )
        self.soar_playbooks[playbook2.id] = playbook2
        
        # 數據滲透檢測劇本
        playbook3 = SOARPlaybook(
            id="playbook_003",
            name="數據滲透自動檢測",
            description="檢測到數據滲透時自動回應",
            trigger_conditions=["data_exfiltration_detected"],
            actions=[
                {"action": "block_external_connections", "target": "firewall"},
                {"action": "preserve_evidence", "target": "forensics"},
                {"action": "notify_legal_team", "target": "compliance"}
            ],
            enabled=True,
            created_at=datetime.now()
        )
        self.soar_playbooks[playbook3.id] = playbook3

    def _start_soc_monitoring(self):
        """啟動SOC監控"""
        def soc_monitor():
            while True:
                try:
                    # 監控安全事件
                    self._monitor_security_events()
                    
                    # 處理安全事件
                    self._process_security_incidents()
                    
                    # 執行SOAR劇本
                    self._execute_soar_playbooks()
                    
                    # 更新威脅情報
                    self._update_threat_intelligence()
                    
                    # 執行紅隊演練
                    self._execute_red_team_exercises()
                    
                    time.sleep(10)  # 每10秒監控一次
                
                except Exception as e:
                    logger.error(f"SOC監控錯誤: {e}")
                    time.sleep(30)
        
        monitor_thread = threading.Thread(target=soc_monitor, daemon=True)
        monitor_thread.start()

    def _monitor_security_events(self):
        """監控安全事件"""
        try:
            # 模擬安全事件生成
            self._generate_simulated_events()
            
            # 處理事件
            for event in list(self.security_events.values()):
                self._process_security_event(event)
        
        except Exception as e:
            logger.error(f"安全事件監控錯誤: {e}")

    def _generate_simulated_events(self):
        """生成模擬安全事件"""
        import random
        
        # 模擬事件類型
        event_types = [
            "malicious_ip_connection",
            "suspicious_file_download",
            "privilege_escalation_attempt",
            "lateral_movement_detected",
            "data_exfiltration_attempt",
            "command_and_control_communication"
        ]
        
        # 隨機生成事件
        if random.random() < 0.1:  # 10%機率生成事件
            event_type = random.choice(event_types)
            self._create_security_event(event_type)

    def _create_security_event(self, event_type: str):
        """創建安全事件"""
        event_id = f"event_{int(time.time())}_{hashlib.md5(event_type.encode()).hexdigest()[:8]}"
        
        # 根據事件類型創建事件
        if event_type == "malicious_ip_connection":
            event = SecurityEvent(
                id=event_id,
                event_type=event_type,
                source="192.168.1.50",
                destination="192.168.1.100",
                timestamp=datetime.now(),
                severity=ThreatLevel.HIGH,
                description="檢測到與已知惡意IP的連線",
                raw_data={"ip": "192.168.1.100", "port": 443},
                indicators=["malicious_ip"],
                tactics=[AttackTactic.INITIAL_ACCESS],
                techniques=["T1078"],
                mitre_id="T1078",
                confidence=0.9
            )
        elif event_type == "lateral_movement_detected":
            event = SecurityEvent(
                id=event_id,
                event_type=event_type,
                source="192.168.1.10",
                destination="192.168.1.20",
                timestamp=datetime.now(),
                severity=ThreatLevel.CRITICAL,
                description="檢測到橫向移動活動",
                raw_data={"protocol": "RDP", "port": 3389},
                indicators=["lateral_movement", "rdp_connection"],
                tactics=[AttackTactic.LATERAL_MOVEMENT],
                techniques=["T1021"],
                mitre_id="T1021",
                confidence=0.8
            )
        else:
            # 默認事件
            event = SecurityEvent(
                id=event_id,
                event_type=event_type,
                source="unknown",
                destination="unknown",
                timestamp=datetime.now(),
                severity=ThreatLevel.MEDIUM,
                description=f"檢測到{event_type}",
                raw_data={},
                indicators=[event_type],
                tactics=[],
                techniques=[],
                mitre_id="",
                confidence=0.5
            )
        
        self.security_events[event_id] = event
        self._save_security_event(event)
        
        # 更新統計
        self.stats['total_events'] += 1
        
        logger.warning(f"安全事件: {event.description} (嚴重程度: {event.severity.value})")

    def _process_security_event(self, event: SecurityEvent):
        """處理安全事件"""
        # 檢查是否與現有事件相關
        related_incident = self._find_related_incident(event)
        
        if related_incident:
            # 添加到現有事件
            self._add_event_to_incident(related_incident, event)
        else:
            # 創建新事件
            self._create_security_incident(event)

    def _find_related_incident(self, event: SecurityEvent) -> Optional[SecurityIncident]:
        """查找相關事件"""
        # 簡化的相關性檢查
        for incident in self.security_incidents.values():
            if incident.status in [IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]:
                # 檢查是否相關
                if self._are_events_related(event, incident):
                    return incident
        return None

    def _are_events_related(self, event: SecurityEvent, incident: SecurityIncident) -> bool:
        """檢查事件是否相關"""
        # 簡化的相關性檢查
        # 在實際環境中，這裡會使用更複雜的算法
        
        # 檢查相同的戰術
        if event.tactics and incident.tactics:
            if any(tactic in incident.tactics for tactic in event.tactics):
                return True
        
        # 檢查相同的源IP
        if event.source in incident.affected_assets:
            return True
        
        return False

    def _add_event_to_incident(self, incident: SecurityIncident, event: SecurityEvent):
        """添加事件到事件"""
        # 更新事件時間線
        timeline_entry = {
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "description": event.description,
            "severity": event.severity.value
        }
        incident.timeline.append(timeline_entry)
        incident.updated_at = datetime.now()
        
        # 更新受影響資產
        if event.source not in incident.affected_assets:
            incident.affected_assets.append(event.source)
        if event.destination not in incident.affected_assets:
            incident.affected_assets.append(event.destination)
        
        # 保存更新
        self._save_security_incident(incident)
        
        logger.info(f"事件 {event.id} 已添加到事件 {incident.id}")

    def _create_security_incident(self, event: SecurityEvent):
        """創建安全事件"""
        incident_id = f"incident_{int(time.time())}_{hashlib.md5(event.id.encode()).hexdigest()[:8]}"
        
        incident = SecurityIncident(
            id=incident_id,
            title=f"安全事件: {event.event_type}",
            description=event.description,
            status=IncidentStatus.OPEN,
            severity=event.severity,
            tactics=event.tactics,
            techniques=event.techniques,
            affected_assets=[event.source, event.destination],
            timeline=[{
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "description": event.description,
                "severity": event.severity.value
            }],
            assigned_team=TeamType.BLUE_TEAM,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            resolved_at=None
        )
        
        self.security_incidents[incident_id] = incident
        self._save_security_incident(incident)
        
        # 更新統計
        self.stats['open_incidents'] += 1
        
        logger.warning(f"新安全事件: {incident.title} (嚴重程度: {incident.severity.value})")

    def _process_security_incidents(self):
        """處理安全事件"""
        for incident in self.security_incidents.values():
            if incident.status == IncidentStatus.OPEN:
                # 自動化事件處理
                self._automate_incident_response(incident)

    def _automate_incident_response(self, incident: SecurityIncident):
        """自動化事件回應"""
        # 根據事件嚴重程度自動分配
        if incident.severity in [ThreatLevel.CRITICAL, ThreatLevel.MILITARY_CRITICAL]:
            incident.assigned_team = TeamType.PURPLE_TEAM
            incident.status = IncidentStatus.INVESTIGATING
        elif incident.severity == ThreatLevel.HIGH:
            incident.assigned_team = TeamType.BLUE_TEAM
            incident.status = IncidentStatus.INVESTIGATING
        
        # 更新事件
        incident.updated_at = datetime.now()
        self._save_security_incident(incident)

    def _execute_soar_playbooks(self):
        """執行SOAR劇本"""
        for playbook in self.soar_playbooks.values():
            if not playbook.enabled:
                continue
            
            # 檢查觸發條件
            if self._check_playbook_triggers(playbook):
                # 執行劇本動作
                self._execute_playbook_actions(playbook)

    def _check_playbook_triggers(self, playbook: SOARPlaybook) -> bool:
        """檢查劇本觸發條件"""
        for condition in playbook.trigger_conditions:
            if condition == "malicious_ip_detected":
                # 檢查是否有惡意IP事件
                for event in self.security_events.values():
                    if event.event_type == "malicious_ip_connection":
                        return True
            elif condition == "lateral_movement_detected":
                # 檢查是否有橫向移動事件
                for event in self.security_events.values():
                    if event.event_type == "lateral_movement_detected":
                        return True
            elif condition == "data_exfiltration_detected":
                # 檢查是否有數據滲透事件
                for event in self.security_events.values():
                    if event.event_type == "data_exfiltration_attempt":
                        return True
        
        return False

    def _execute_playbook_actions(self, playbook: SOARPlaybook):
        """執行劇本動作"""
        logger.info(f"執行SOAR劇本: {playbook.name}")
        
        for action in playbook.actions:
            action_type = action.get("action")
            target = action.get("target")
            
            if action_type == "block_ip":
                logger.info(f"阻擋IP: {target}")
            elif action_type == "quarantine_device":
                logger.info(f"隔離設備: {target}")
            elif action_type == "send_alert":
                logger.info(f"發送警報: {target}")
            elif action_type == "isolate_network":
                logger.info(f"隔離網路: {target}")
            elif action_type == "collect_forensics":
                logger.info(f"收集取證: {target}")
            elif action_type == "escalate_incident":
                logger.info(f"升級事件: {target}")

    def _update_threat_intelligence(self):
        """更新威脅情報"""
        # 模擬威脅情報更新
        import random
        
        if random.random() < 0.05:  # 5%機率更新威脅情報
            # 模擬新的威脅情報
            new_ti = ThreatIntelligence(
                id=f"ti_{int(time.time())}",
                ioc_type="IP",
                ioc_value=f"192.168.1.{random.randint(100, 200)}",
                threat_type="Malware",
                source="External",
                confidence=random.uniform(0.7, 0.9),
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                tags=["malware", "new"],
                description="新發現的惡意IP"
            )
            self.threat_intelligence[new_ti.id] = new_ti
            self._save_threat_intelligence(new_ti)
            
            logger.info(f"新威脅情報: {new_ti.ioc_value}")

    def _execute_red_team_exercises(self):
        """執行紅隊演練"""
        # 模擬紅隊演練
        import random
        
        if random.random() < 0.02:  # 2%機率執行演練
            exercise_id = f"exercise_{int(time.time())}"
            
            exercise = RedTeamExercise(
                id=exercise_id,
                name="模擬攻擊演練",
                objective="測試防禦系統有效性",
                tactics=[AttackTactic.INITIAL_ACCESS, AttackTactic.LATERAL_MOVEMENT],
                techniques=["T1078", "T1021"],
                target_assets=["192.168.1.0/24"],
                start_time=datetime.now(),
                end_time=None,
                status="RUNNING",
                results={}
            )
            
            self.red_team_exercises[exercise_id] = exercise
            self._save_red_team_exercise(exercise)
            
            # 更新統計
            self.stats['red_team_exercises'] += 1
            
            logger.info(f"開始紅隊演練: {exercise.name}")

    def _save_security_event(self, event: SecurityEvent):
        """儲存安全事件"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO security_events 
            (id, event_type, source, destination, timestamp, severity, description,
             raw_data, indicators, tactics, techniques, mitre_id, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.id, event.event_type, event.source, event.destination,
            event.timestamp.isoformat(), event.severity.value, event.description,
            json.dumps(event.raw_data), json.dumps(event.indicators),
            json.dumps([t.value for t in event.tactics]),
            json.dumps(event.techniques), event.mitre_id, event.confidence
        ))
        self.db_conn.commit()

    def _save_security_incident(self, incident: SecurityIncident):
        """儲存安全事件"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO security_incidents 
            (id, title, description, status, severity, tactics, techniques,
             affected_assets, timeline, assigned_team, created_at, updated_at, resolved_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident.id, incident.title, incident.description, incident.status.value,
            incident.severity.value, json.dumps([t.value for t in incident.tactics]),
            json.dumps(incident.techniques), json.dumps(incident.affected_assets),
            json.dumps(incident.timeline), incident.assigned_team.value,
            incident.created_at.isoformat(), incident.updated_at.isoformat(),
            incident.resolved_at.isoformat() if incident.resolved_at else None
        ))
        self.db_conn.commit()

    def _save_threat_intelligence(self, ti: ThreatIntelligence):
        """儲存威脅情報"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO threat_intelligence 
            (id, ioc_type, ioc_value, threat_type, source, confidence,
             first_seen, last_seen, tags, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ti.id, ti.ioc_type, ti.ioc_value, ti.threat_type, ti.source,
            ti.confidence, ti.first_seen.isoformat(), ti.last_seen.isoformat(),
            json.dumps(ti.tags), ti.description
        ))
        self.db_conn.commit()

    def _save_red_team_exercise(self, exercise: RedTeamExercise):
        """儲存紅隊演練"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO red_team_exercises 
            (id, name, objective, tactics, techniques, target_assets,
             start_time, end_time, status, results)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            exercise.id, exercise.name, exercise.objective,
            json.dumps([t.value for t in exercise.tactics]),
            json.dumps(exercise.techniques), json.dumps(exercise.target_assets),
            exercise.start_time.isoformat(),
            exercise.end_time.isoformat() if exercise.end_time else None,
            exercise.status, json.dumps(exercise.results)
        ))
        self.db_conn.commit()

    def get_soc_status(self) -> Dict[str, Any]:
        """獲取SOC狀態"""
        return {
            'total_events': len(self.security_events),
            'open_incidents': len([i for i in self.security_incidents.values() if i.status == IncidentStatus.OPEN]),
            'investigating_incidents': len([i for i in self.security_incidents.values() if i.status == IncidentStatus.INVESTIGATING]),
            'resolved_incidents': len([i for i in self.security_incidents.values() if i.status == IncidentStatus.RESOLVED]),
            'threat_intel_iocs': len(self.threat_intelligence),
            'active_playbooks': len([p for p in self.soar_playbooks.values() if p.enabled]),
            'red_team_exercises': len(self.red_team_exercises),
            'stats': self.stats
        }

    def get_recent_events(self, limit: int = 10) -> List[SecurityEvent]:
        """獲取最近事件"""
        events = list(self.security_events.values())
        events.sort(key=lambda x: x.timestamp, reverse=True)
        return events[:limit]

    def get_recent_incidents(self, limit: int = 10) -> List[SecurityIncident]:
        """獲取最近事件"""
        incidents = list(self.security_incidents.values())
        incidents.sort(key=lambda x: x.created_at, reverse=True)
        return incidents[:limit]

def main():
    """主程式"""
    config = {
        'monitoring_interval': 10,
        'siem_enabled': True,
        'soar_enabled': True,
        'red_team_enabled': True
    }
    
    soc = MilitarySOCCommandCenter(config)
    
    print("🛡️ 軍事級SOC/指揮中心系統已啟動")
    print("=" * 60)
    
    # 顯示MITRE ATT&CK映射
    print("MITRE ATT&CK 戰術:")
    for tactic_id, tactic_info in list(soc.mitre_mapping.items())[:5]:
        print(f"  {tactic_id}: {tactic_info['name']} - {tactic_info['tactic']}")
    
    # 顯示威脅情報
    print(f"\n威脅情報: {len(soc.threat_intelligence)} 個IOC")
    for ti in list(soc.threat_intelligence.values())[:3]:
        print(f"  {ti.ioc_type}: {ti.ioc_value} ({ti.threat_type})")
    
    # 顯示SOAR劇本
    print(f"\nSOAR劇本: {len(soc.soar_playbooks)} 個")
    for playbook in soc.soar_playbooks.values():
        print(f"  {playbook.name}: {playbook.description}")
    
    print(f"\n🛡️ 系統正在監控安全事件...")
    print("按 Ctrl+C 停止監控")

if __name__ == "__main__":
    main()




