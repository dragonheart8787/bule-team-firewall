#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級進階威脅獵捕工具系統
實作 MITRE ATT&CK mapping, 紅藍紫隊演練 等功能
"""

import os
import sys
import json
import time
import hashlib
import base64
import struct
import socket
import threading
import subprocess
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

# 設定日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """威脅等級枚舉"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class TeamType(Enum):
    """隊伍類型枚舉"""
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    PURPLE_TEAM = "purple_team"

@dataclass
class MITRETechnique:
    """MITRE ATT&CK 技術資料結構"""
    technique_id: str
    name: str
    description: str
    tactics: List[str]
    platforms: List[str]
    data_sources: List[str]
    detection_rules: List[str]
    mitigation_rules: List[str]

@dataclass
class ThreatIndicator:
    """威脅指標資料結構"""
    id: str
    type: str  # IP, Domain, Hash, File, Registry, etc.
    value: str
    description: str
    threat_level: ThreatLevel
    first_seen: str
    last_seen: str
    source: str
    confidence: float

@dataclass
class HuntingQuery:
    """獵捕查詢資料結構"""
    id: str
    name: str
    description: str
    query: str
    technique_id: str
    data_source: str
    created_by: str
    created_at: str
    last_run: str = None
    results_count: int = 0

@dataclass
class ExerciseScenario:
    """演練情境資料結構"""
    id: str
    name: str
    description: str
    team_type: TeamType
    objectives: List[str]
    techniques: List[str]
    duration: int  # 分鐘
    difficulty: str
    created_at: str

class MITREATTACKMapper:
    """MITRE ATT&CK 映射工具"""
    
    def __init__(self):
        self.techniques = self._load_mitre_techniques()
        self.tactics = self._load_mitre_tactics()
    
    def _load_mitre_techniques(self) -> Dict[str, MITRETechnique]:
        """載入 MITRE ATT&CK 技術"""
        techniques = {}
        
        # 模擬 MITRE ATT&CK 技術資料
        technique_data = [
            {
                'technique_id': 'T1055',
                'name': 'Process Injection',
                'description': 'Adversaries may inject code into processes in order to evade process-based defenses',
                'tactics': ['Defense Evasion', 'Privilege Escalation'],
                'platforms': ['Windows', 'Linux', 'macOS'],
                'data_sources': ['Process monitoring', 'API monitoring', 'DLL monitoring'],
                'detection_rules': [
                    'Monitor for processes that perform process injection',
                    'Look for unusual process behavior patterns',
                    'Check for suspicious API calls'
                ],
                'mitigation_rules': [
                    'Use application whitelisting',
                    'Implement process isolation',
                    'Monitor process behavior'
                ]
            },
            {
                'technique_id': 'T1071',
                'name': 'Application Layer Protocol',
                'description': 'Adversaries may communicate using application layer protocols to avoid detection',
                'tactics': ['Command and Control'],
                'platforms': ['Windows', 'Linux', 'macOS'],
                'data_sources': ['Network traffic', 'Process monitoring', 'Packet capture'],
                'detection_rules': [
                    'Monitor for unusual network traffic patterns',
                    'Look for encrypted communications',
                    'Check for suspicious protocols'
                ],
                'mitigation_rules': [
                    'Use network segmentation',
                    'Implement traffic filtering',
                    'Monitor network communications'
                ]
            },
            {
                'technique_id': 'T1083',
                'name': 'File and Directory Discovery',
                'description': 'Adversaries may enumerate files and directories to gather information',
                'tactics': ['Discovery'],
                'platforms': ['Windows', 'Linux', 'macOS'],
                'data_sources': ['File monitoring', 'Process monitoring', 'Command line monitoring'],
                'detection_rules': [
                    'Monitor for file enumeration commands',
                    'Look for unusual file access patterns',
                    'Check for directory listing commands'
                ],
                'mitigation_rules': [
                    'Limit file system access',
                    'Implement access controls',
                    'Monitor file system activity'
                ]
            }
        ]
        
        for data in technique_data:
            technique = MITRETechnique(
                technique_id=data['technique_id'],
                name=data['name'],
                description=data['description'],
                tactics=data['tactics'],
                platforms=data['platforms'],
                data_sources=data['data_sources'],
                detection_rules=data['detection_rules'],
                mitigation_rules=data['mitigation_rules']
            )
            techniques[technique.technique_id] = technique
        
        return techniques
    
    def _load_mitre_tactics(self) -> Dict[str, Dict[str, Any]]:
        """載入 MITRE ATT&CK 戰術"""
        return {
            'TA0001': {'name': 'Initial Access', 'description': 'The adversary is trying to get into your network'},
            'TA0002': {'name': 'Execution', 'description': 'The adversary is trying to run malicious code'},
            'TA0003': {'name': 'Persistence', 'description': 'The adversary is trying to maintain their foothold'},
            'TA0004': {'name': 'Privilege Escalation', 'description': 'The adversary is trying to gain higher-level permissions'},
            'TA0005': {'name': 'Defense Evasion', 'description': 'The adversary is trying to avoid being detected'},
            'TA0006': {'name': 'Credential Access', 'description': 'The adversary is trying to steal account names and passwords'},
            'TA0007': {'name': 'Discovery', 'description': 'The adversary is trying to figure out your environment'},
            'TA0008': {'name': 'Lateral Movement', 'description': 'The adversary is trying to move through your environment'},
            'TA0009': {'name': 'Collection', 'description': 'The adversary is trying to gather data of interest'},
            'TA0010': {'name': 'Exfiltration', 'description': 'The adversary is trying to steal data'},
            'TA0011': {'name': 'Command and Control', 'description': 'The adversary is trying to communicate with compromised systems'},
            'TA0040': {'name': 'Impact', 'description': 'The adversary is trying to manipulate, interrupt, or destroy your systems and data'}
        }
    
    def map_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """映射技術"""
        return self.techniques.get(technique_id)
    
    def search_techniques(self, query: str) -> List[MITRETechnique]:
        """搜尋技術"""
        results = []
        query_lower = query.lower()
        
        for technique in self.techniques.values():
            if (query_lower in technique.name.lower() or 
                query_lower in technique.description.lower() or
                any(query_lower in tactic.lower() for tactic in technique.tactics)):
                results.append(technique)
        
        return results
    
    def get_techniques_by_tactic(self, tactic: str) -> List[MITRETechnique]:
        """根據戰術獲取技術"""
        results = []
        for technique in self.techniques.values():
            if tactic in technique.tactics:
                results.append(technique)
        return results
    
    def generate_detection_rule(self, technique_id: str, data_source: str) -> Dict[str, Any]:
        """生成檢測規則"""
        technique = self.map_technique(technique_id)
        if not technique:
            return {'success': False, 'error': '技術不存在'}
        
        # 根據資料來源生成檢測規則
        if data_source == 'Process monitoring':
            rule = f"""
# Detection rule for {technique.name} ({technique_id})
# Data source: {data_source}

rule {technique_id.replace('.', '_')}_process_monitoring {{
    meta:
        description = "Detects {technique.name}"
        technique_id = "{technique_id}"
        tactic = "{', '.join(technique.tactics)}"
    
    condition:
        process_name in ({self._get_process_names_for_technique(technique_id)})
        and
        (process_command_line contains suspicious_patterns)
}}
"""
        elif data_source == 'Network traffic':
            rule = f"""
# Detection rule for {technique.name} ({technique_id})
# Data source: {data_source}

rule {technique_id.replace('.', '_')}_network_monitoring {{
    meta:
        description = "Detects {technique.name}"
        technique_id = "{technique_id}"
        tactic = "{', '.join(technique.tactics)}"
    
    condition:
        network_connection
        and
        (destination_port in suspicious_ports
         or destination_domain in suspicious_domains)
}}
"""
        else:
            rule = f"# Generic detection rule for {technique.name} ({technique_id})"
        
        return {
            'success': True,
            'rule': rule,
            'technique': technique.name,
            'data_source': data_source
        }
    
    def _get_process_names_for_technique(self, technique_id: str) -> str:
        """獲取技術相關的進程名稱"""
        process_mapping = {
            'T1055': 'powershell.exe, cmd.exe, rundll32.exe',
            'T1071': 'svchost.exe, explorer.exe, chrome.exe',
            'T1083': 'cmd.exe, powershell.exe, dir.exe'
        }
        return process_mapping.get(technique_id, 'unknown.exe')

class ThreatHuntingEngine:
    """威脅獵捕引擎"""
    
    def __init__(self):
        self.db_path = "threat_hunting.db"
        self._init_database()
        self.mitre_mapper = MITREATTACKMapper()
        self.hunting_queries = []
        self.threat_indicators = []
    
    def _init_database(self):
        """初始化資料庫"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 創建威脅指標表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    description TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence REAL NOT NULL
                )
            ''')
            
            # 創建獵捕查詢表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hunting_queries (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    query TEXT NOT NULL,
                    technique_id TEXT NOT NULL,
                    data_source TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_run TEXT,
                    results_count INTEGER DEFAULT 0
                )
            ''')
            
            # 創建獵捕結果表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hunting_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    results TEXT NOT NULL,
                    FOREIGN KEY (query_id) REFERENCES hunting_queries (id)
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"資料庫初始化錯誤: {e}")
    
    def create_hunting_query(self, name: str, description: str, technique_id: str, 
                           data_source: str, query: str, created_by: str) -> Dict[str, Any]:
        """創建獵捕查詢"""
        try:
            query_id = f"query_{int(time.time())}"
            
            hunting_query = HuntingQuery(
                id=query_id,
                name=name,
                description=description,
                query=query,
                technique_id=technique_id,
                data_source=data_source,
                created_by=created_by,
                created_at=datetime.now().isoformat()
            )
            
            # 儲存到資料庫
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO hunting_queries 
                (id, name, description, query, technique_id, data_source, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                hunting_query.id, hunting_query.name, hunting_query.description,
                hunting_query.query, hunting_query.technique_id, hunting_query.data_source,
                hunting_query.created_by, hunting_query.created_at
            ))
            
            conn.commit()
            conn.close()
            
            self.hunting_queries.append(hunting_query)
            
            return {
                'success': True,
                'query_id': query_id,
                'message': f'獵捕查詢已創建: {name}'
            }
        except Exception as e:
            logger.error(f"創建獵捕查詢錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def execute_hunting_query(self, query_id: str) -> Dict[str, Any]:
        """執行獵捕查詢"""
        try:
            # 查找查詢
            hunting_query = None
            for q in self.hunting_queries:
                if q.id == query_id:
                    hunting_query = q
                    break
            
            if not hunting_query:
                return {'success': False, 'error': '查詢不存在'}
            
            logger.info(f"執行獵捕查詢: {hunting_query.name}")
            
            # 模擬查詢執行
            results = self._simulate_query_execution(hunting_query)
            
            # 更新查詢結果
            hunting_query.last_run = datetime.now().isoformat()
            hunting_query.results_count = len(results)
            
            # 儲存結果到資料庫
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO hunting_results (query_id, timestamp, results)
                VALUES (?, ?, ?)
            ''', (query_id, hunting_query.last_run, json.dumps(results)))
            
            cursor.execute('''
                UPDATE hunting_queries 
                SET last_run = ?, results_count = ?
                WHERE id = ?
            ''', (hunting_query.last_run, hunting_query.results_count, query_id))
            
            conn.commit()
            conn.close()
            
            return {
                'success': True,
                'results': results,
                'results_count': len(results),
                'execution_time': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"執行獵捕查詢錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _simulate_query_execution(self, hunting_query: HuntingQuery) -> List[Dict[str, Any]]:
        """模擬查詢執行"""
        # 根據技術 ID 模擬不同的結果
        if hunting_query.technique_id == 'T1055':  # Process Injection
            return [
                {
                    'timestamp': datetime.now().isoformat(),
                    'process_name': 'powershell.exe',
                    'process_id': 1234,
                    'command_line': 'powershell -enc <encoded_payload>',
                    'technique': 'Process Injection',
                    'confidence': 0.85
                },
                {
                    'timestamp': datetime.now().isoformat(),
                    'process_name': 'rundll32.exe',
                    'process_id': 5678,
                    'command_line': 'rundll32.exe shell32.dll,ShellExec_RunDLL malware.dll',
                    'technique': 'Process Injection',
                    'confidence': 0.92
                }
            ]
        elif hunting_query.technique_id == 'T1071':  # Application Layer Protocol
            return [
                {
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': '192.168.1.100',
                    'destination_ip': '10.0.0.1',
                    'destination_port': 8080,
                    'protocol': 'TCP',
                    'technique': 'Application Layer Protocol',
                    'confidence': 0.78
                }
            ]
        elif hunting_query.technique_id == 'T1083':  # File and Directory Discovery
            return [
                {
                    'timestamp': datetime.now().isoformat(),
                    'process_name': 'cmd.exe',
                    'process_id': 9999,
                    'command_line': 'dir C:\\ /s /b',
                    'technique': 'File and Directory Discovery',
                    'confidence': 0.65
                }
            ]
        else:
            return []
    
    def add_threat_indicator(self, indicator_type: str, value: str, description: str, 
                           threat_level: ThreatLevel, source: str, confidence: float) -> Dict[str, Any]:
        """添加威脅指標"""
        try:
            indicator_id = f"indicator_{int(time.time())}"
            
            indicator = ThreatIndicator(
                id=indicator_id,
                type=indicator_type,
                value=value,
                description=description,
                threat_level=threat_level,
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                source=source,
                confidence=confidence
            )
            
            # 儲存到資料庫
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO threat_indicators 
                (id, type, value, description, threat_level, first_seen, last_seen, source, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                indicator.id, indicator.type, indicator.value, indicator.description,
                indicator.threat_level.value, indicator.first_seen, indicator.last_seen,
                indicator.source, indicator.confidence
            ))
            
            conn.commit()
            conn.close()
            
            self.threat_indicators.append(indicator)
            
            return {
                'success': True,
                'indicator_id': indicator_id,
                'message': f'威脅指標已添加: {value}'
            }
        except Exception as e:
            logger.error(f"添加威脅指標錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def search_threat_indicators(self, query: str = None, threat_level: ThreatLevel = None) -> List[ThreatIndicator]:
        """搜尋威脅指標"""
        results = []
        
        for indicator in self.threat_indicators:
            if query and query.lower() not in indicator.value.lower() and query.lower() not in indicator.description.lower():
                continue
            if threat_level and indicator.threat_level != threat_level:
                continue
            results.append(indicator)
        
        return results

class RedBluePurpleTeamExercises:
    """紅藍紫隊演練工具"""
    
    def __init__(self):
        self.exercises = []
        self._init_default_exercises()
    
    def _init_default_exercises(self):
        """初始化預設演練"""
        exercises = [
            ExerciseScenario(
                id="red_001",
                name="Windows 環境滲透測試",
                description="模擬攻擊者在 Windows 環境中的滲透測試活動",
                team_type=TeamType.RED_TEAM,
                objectives=[
                    "獲取初始存取權限",
                    "建立持久性",
                    "橫向移動",
                    "數據竊取"
                ],
                techniques=["T1055", "T1071", "T1083", "T1059"],
                duration=240,  # 4小時
                difficulty="Medium",
                created_at=datetime.now().isoformat()
            ),
            ExerciseScenario(
                id="blue_001",
                name="威脅檢測與回應",
                description="藍隊進行威脅檢測和事件回應演練",
                team_type=TeamType.BLUE_TEAM,
                objectives=[
                    "檢測惡意活動",
                    "分析攻擊技術",
                    "實施防護措施",
                    "事件回應"
                ],
                techniques=["T1055", "T1071", "T1083"],
                duration=180,  # 3小時
                difficulty="Medium",
                created_at=datetime.now().isoformat()
            ),
            ExerciseScenario(
                id="purple_001",
                name="協同防禦演練",
                description="紅藍隊協同進行防禦演練",
                team_type=TeamType.PURPLE_TEAM,
                objectives=[
                    "測試防護措施",
                    "改進檢測規則",
                    "優化回應流程",
                    "提升整體安全性"
                ],
                techniques=["T1055", "T1071", "T1083", "T1059"],
                duration=360,  # 6小時
                difficulty="High",
                created_at=datetime.now().isoformat()
            )
        ]
        
        self.exercises = exercises
    
    def create_exercise(self, name: str, description: str, team_type: TeamType, 
                       objectives: List[str], techniques: List[str], 
                       duration: int, difficulty: str) -> Dict[str, Any]:
        """創建演練"""
        try:
            exercise_id = f"{team_type.value}_{len(self.exercises) + 1:03d}"
            
            exercise = ExerciseScenario(
                id=exercise_id,
                name=name,
                description=description,
                team_type=team_type,
                objectives=objectives,
                techniques=techniques,
                duration=duration,
                difficulty=difficulty,
                created_at=datetime.now().isoformat()
            )
            
            self.exercises.append(exercise)
            
            return {
                'success': True,
                'exercise_id': exercise_id,
                'message': f'演練已創建: {name}'
            }
        except Exception as e:
            logger.error(f"創建演練錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def execute_exercise(self, exercise_id: str) -> Dict[str, Any]:
        """執行演練"""
        try:
            exercise = None
            for ex in self.exercises:
                if ex.id == exercise_id:
                    exercise = ex
                    break
            
            if not exercise:
                return {'success': False, 'error': '演練不存在'}
            
            logger.info(f"開始執行演練: {exercise.name}")
            
            # 模擬演練執行
            results = self._simulate_exercise_execution(exercise)
            
            return {
                'success': True,
                'exercise': self._exercise_to_dict(exercise),
                'results': results,
                'execution_time': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"執行演練錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _simulate_exercise_execution(self, exercise: ExerciseScenario) -> Dict[str, Any]:
        """模擬演練執行"""
        if exercise.team_type == TeamType.RED_TEAM:
            return {
                'attacks_attempted': 15,
                'successful_attacks': 8,
                'techniques_used': exercise.techniques,
                'objectives_achieved': len(exercise.objectives) - 1,
                'time_to_compromise': '45 minutes',
                'lateral_movement_successful': True,
                'data_exfiltration_successful': True
            }
        elif exercise.team_type == TeamType.BLUE_TEAM:
            return {
                'threats_detected': 12,
                'false_positives': 3,
                'response_time': '15 minutes',
                'incidents_contained': 8,
                'techniques_detected': exercise.techniques,
                'objectives_achieved': len(exercise.objectives)
            }
        else:  # PURPLE_TEAM
            return {
                'collaboration_score': 8.5,
                'defense_improvements': 5,
                'detection_rules_created': 12,
                'response_procedures_updated': 3,
                'overall_security_improvement': '15%'
            }
    
    def _exercise_to_dict(self, exercise: ExerciseScenario) -> Dict[str, Any]:
        """將演練轉換為字典"""
        return {
            'id': exercise.id,
            'name': exercise.name,
            'description': exercise.description,
            'team_type': exercise.team_type.value,
            'objectives': exercise.objectives,
            'techniques': exercise.techniques,
            'duration': exercise.duration,
            'difficulty': exercise.difficulty,
            'created_at': exercise.created_at
        }
    
    def get_exercises_by_team(self, team_type: TeamType) -> List[ExerciseScenario]:
        """根據隊伍類型獲取演練"""
        return [ex for ex in self.exercises if ex.team_type == team_type]

class MilitaryThreatHuntingAdvanced:
    """軍事級進階威脅獵捕主類別"""
    
    def __init__(self):
        self.hunting_engine = ThreatHuntingEngine()
        self.exercise_tools = RedBluePurpleTeamExercises()
        self.hunting_log = []
    
    def comprehensive_threat_hunting(self, hunting_scope: Dict[str, Any]) -> Dict[str, Any]:
        """執行綜合威脅獵捕"""
        try:
            results = {}
            
            # 1. MITRE ATT&CK 映射
            logger.info("執行 MITRE ATT&CK 映射...")
            results['mitre_mapping'] = self._perform_mitre_mapping(hunting_scope)
            
            # 2. 威脅指標分析
            logger.info("執行威脅指標分析...")
            results['indicator_analysis'] = self._analyze_threat_indicators(hunting_scope)
            
            # 3. 獵捕查詢執行
            logger.info("執行獵捕查詢...")
            results['hunting_queries'] = self._execute_hunting_queries(hunting_scope)
            
            # 4. 紅藍紫隊演練
            logger.info("執行紅藍紫隊演練...")
            results['team_exercises'] = self._execute_team_exercises(hunting_scope)
            
            # 5. 威脅評估
            logger.info("執行威脅評估...")
            results['threat_assessment'] = self._assess_threats(results)
            
            return {
                'success': True,
                'results': results,
                'summary': self._generate_hunting_summary(results)
            }
        except Exception as e:
            logger.error(f"綜合威脅獵捕錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _perform_mitre_mapping(self, hunting_scope: Dict[str, Any]) -> Dict[str, Any]:
        """執行 MITRE ATT&CK 映射"""
        try:
            # 搜尋相關技術
            techniques = []
            if 'query' in hunting_scope:
                techniques = self.hunting_engine.mitre_mapper.search_techniques(hunting_scope['query'])
            
            # 生成檢測規則
            detection_rules = []
            for technique in techniques[:5]:  # 限制前5個技術
                rule = self.hunting_engine.mitre_mapper.generate_detection_rule(
                    technique.technique_id, 'Process monitoring'
                )
                if rule.get('success', False):
                    detection_rules.append(rule)
            
            return {
                'techniques_found': len(techniques),
                'techniques': [self._technique_to_dict(t) for t in techniques[:5]],
                'detection_rules_generated': len(detection_rules),
                'detection_rules': detection_rules
            }
        except Exception as e:
            logger.error(f"MITRE 映射錯誤: {e}")
            return {'techniques_found': 0, 'techniques': [], 'detection_rules_generated': 0, 'detection_rules': []}
    
    def _analyze_threat_indicators(self, hunting_scope: Dict[str, Any]) -> Dict[str, Any]:
        """分析威脅指標"""
        try:
            # 搜尋威脅指標
            indicators = self.hunting_engine.search_threat_indicators()
            
            # 按威脅等級分組
            critical_indicators = [i for i in indicators if i.threat_level == ThreatLevel.CRITICAL]
            high_indicators = [i for i in indicators if i.threat_level == ThreatLevel.HIGH]
            medium_indicators = [i for i in indicators if i.threat_level == ThreatLevel.MEDIUM]
            
            return {
                'total_indicators': len(indicators),
                'critical_indicators': len(critical_indicators),
                'high_indicators': len(high_indicators),
                'medium_indicators': len(medium_indicators),
                'indicators_by_type': self._group_indicators_by_type(indicators)
            }
        except Exception as e:
            logger.error(f"威脅指標分析錯誤: {e}")
            return {'total_indicators': 0, 'critical_indicators': 0, 'high_indicators': 0, 'medium_indicators': 0, 'indicators_by_type': {}}
    
    def _execute_hunting_queries(self, hunting_scope: Dict[str, Any]) -> Dict[str, Any]:
        """執行獵捕查詢"""
        try:
            query_results = []
            
            # 執行所有獵捕查詢
            for query in self.hunting_engine.hunting_queries:
                result = self.hunting_engine.execute_hunting_query(query.id)
                if result.get('success', False):
                    query_results.append({
                        'query_id': query.id,
                        'query_name': query.name,
                        'results_count': result.get('results_count', 0),
                        'execution_time': result.get('execution_time', '')
                    })
            
            return {
                'queries_executed': len(query_results),
                'total_results': sum(q['results_count'] for q in query_results),
                'query_results': query_results
            }
        except Exception as e:
            logger.error(f"獵捕查詢執行錯誤: {e}")
            return {'queries_executed': 0, 'total_results': 0, 'query_results': []}
    
    def _execute_team_exercises(self, hunting_scope: Dict[str, Any]) -> Dict[str, Any]:
        """執行隊伍演練"""
        try:
            exercise_results = []
            
            # 執行所有演練
            for exercise in self.exercise_tools.exercises:
                result = self.exercise_tools.execute_exercise(exercise.id)
                if result.get('success', False):
                    exercise_results.append({
                        'exercise_id': exercise.id,
                        'exercise_name': exercise.name,
                        'team_type': exercise.team_type.value,
                        'results': result.get('results', {})
                    })
            
            return {
                'exercises_executed': len(exercise_results),
                'exercise_results': exercise_results
            }
        except Exception as e:
            logger.error(f"隊伍演練執行錯誤: {e}")
            return {'exercises_executed': 0, 'exercise_results': []}
    
    def _assess_threats(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """評估威脅"""
        try:
            threat_score = 0.0
            threat_factors = []
            
            # 基於威脅指標評估
            if 'indicator_analysis' in results:
                indicator_data = results['indicator_analysis']
                if indicator_data.get('critical_indicators', 0) > 0:
                    threat_score += 5.0
                    threat_factors.append("存在關鍵威脅指標")
                if indicator_data.get('high_indicators', 0) > 2:
                    threat_score += 3.0
                    threat_factors.append("存在多個高風險威脅指標")
            
            # 基於獵捕查詢結果評估
            if 'hunting_queries' in results:
                query_data = results['hunting_queries']
                if query_data.get('total_results', 0) > 10:
                    threat_score += 2.0
                    threat_factors.append("獵捕查詢發現大量可疑活動")
            
            # 基於隊伍演練結果評估
            if 'team_exercises' in results:
                exercise_data = results['team_exercises']
                for exercise_result in exercise_data.get('exercise_results', []):
                    results_data = exercise_result.get('results', {})
                    if results_data.get('successful_attacks', 0) > 5:
                        threat_score += 2.0
                        threat_factors.append("演練中發現多個成功攻擊")
            
            # 確定威脅等級
            if threat_score >= 8.0:
                threat_level = "CRITICAL"
            elif threat_score >= 6.0:
                threat_level = "HIGH"
            elif threat_score >= 4.0:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"
            
            return {
                'threat_score': min(threat_score, 10.0),
                'threat_level': threat_level,
                'threat_factors': threat_factors,
                'recommendations': self._generate_threat_recommendations(threat_level, threat_factors)
            }
        except Exception as e:
            logger.error(f"威脅評估錯誤: {e}")
            return {'threat_score': 0.0, 'threat_level': 'UNKNOWN', 'threat_factors': [], 'recommendations': []}
    
    def _generate_threat_recommendations(self, threat_level: str, threat_factors: List[str]) -> List[str]:
        """生成威脅建議"""
        recommendations = []
        
        if threat_level == "CRITICAL":
            recommendations.extend([
                "立即啟動緊急回應程序",
                "隔離所有受影響的系統",
                "通知高階管理層",
                "進行全面安全評估",
                "實施額外的監控措施"
            ])
        elif threat_level == "HIGH":
            recommendations.extend([
                "加強監控和檢測",
                "檢查系統完整性",
                "更新安全補丁",
                "審查存取控制"
            ])
        elif threat_level == "MEDIUM":
            recommendations.extend([
                "持續監控可疑活動",
                "定期安全掃描",
                "更新檢測規則"
            ])
        else:
            recommendations.extend([
                "維持現有安全措施",
                "定期威脅獵捕"
            ])
        
        return recommendations
    
    def _group_indicators_by_type(self, indicators: List[ThreatIndicator]) -> Dict[str, int]:
        """按類型分組威脅指標"""
        groups = {}
        for indicator in indicators:
            if indicator.type not in groups:
                groups[indicator.type] = 0
            groups[indicator.type] += 1
        return groups
    
    def _technique_to_dict(self, technique: MITRETechnique) -> Dict[str, Any]:
        """將技術轉換為字典"""
        return {
            'technique_id': technique.technique_id,
            'name': technique.name,
            'description': technique.description,
            'tactics': technique.tactics,
            'platforms': technique.platforms,
            'data_sources': technique.data_sources
        }
    
    def _generate_hunting_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成獵捕摘要"""
        summary = {
            'total_analyses': len(results),
            'successful_analyses': sum(1 for r in results.values() if isinstance(r, dict) and r.get('success', True)),
            'threat_level': 'UNKNOWN',
            'techniques_identified': 0,
            'indicators_found': 0,
            'queries_executed': 0
        }
        
        if 'mitre_mapping' in results:
            summary['techniques_identified'] = results['mitre_mapping'].get('techniques_found', 0)
        
        if 'indicator_analysis' in results:
            summary['indicators_found'] = results['indicator_analysis'].get('total_indicators', 0)
        
        if 'hunting_queries' in results:
            summary['queries_executed'] = results['hunting_queries'].get('queries_executed', 0)
        
        if 'threat_assessment' in results:
            summary['threat_level'] = results['threat_assessment'].get('threat_level', 'UNKNOWN')
        
        return summary
    
    def get_hunting_log(self) -> List[Dict[str, Any]]:
        """獲取獵捕日誌"""
        return self.hunting_log
    
    def export_results(self, filename: str) -> bool:
        """匯出結果"""
        try:
            data = {
                'hunting_log': self.hunting_log,
                'timestamp': datetime.now().isoformat(),
                'system_info': {
                    'platform': sys.platform,
                    'python_version': sys.version
                }
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"結果已匯出到: {filename}")
            return True
        except Exception as e:
            logger.error(f"匯出結果錯誤: {e}")
            return False

def main():
    """主程式"""
    print("🎯 軍事級進階威脅獵捕工具系統")
    print("=" * 50)
    
    # 初始化系統
    threat_hunting = MilitaryThreatHuntingAdvanced()
    
    # 測試獵捕範圍
    test_hunting_scope = {
        'query': 'process injection',
        'time_range': '24h',
        'data_sources': ['Process monitoring', 'Network traffic']
    }
    
    # 執行綜合威脅獵捕測試
    print("開始執行綜合威脅獵捕測試...")
    results = threat_hunting.comprehensive_threat_hunting(test_hunting_scope)
    
    print(f"獵捕完成，成功: {results['success']}")
    print(f"獵捕摘要: {json.dumps(results['summary'], indent=2, ensure_ascii=False)}")
    
    # 匯出結果
    threat_hunting.export_results("threat_hunting_advanced_results.json")
    
    print("進階威脅獵捕工具系統測試完成！")

if __name__ == "__main__":
    main()

