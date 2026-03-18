#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級紅藍對抗可視化系統
實作 MITRE ATT&CK Navigator、Kill Chain、ATT&CK Matrix 自動標記覆蓋率
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
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

# 設定日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AttackPhase(Enum):
    """攻擊階段枚舉"""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"

class TechniqueCategory(Enum):
    """技術類別枚舉"""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

class CoverageStatus(Enum):
    """覆蓋狀態枚舉"""
    DETECTED = "detected"
    PREVENTED = "prevented"
    MONITORED = "monitored"
    NOT_COVERED = "not_covered"

@dataclass
class ATTACKTechnique:
    """ATT&CK 技術資料結構"""
    id: str
    name: str
    description: str
    category: TechniqueCategory
    subcategory: str
    tactics: List[str]
    platforms: List[str]
    permissions_required: List[str]
    data_sources: List[str]
    detection_rules: List[str]
    mitigation_rules: List[str]
    coverage_status: CoverageStatus
    detection_score: float
    prevention_score: float

@dataclass
class KillChainStep:
    """Kill Chain 步驟資料結構"""
    phase: AttackPhase
    techniques: List[ATTACKTechnique]
    detection_coverage: float
    prevention_coverage: float
    monitoring_coverage: float

@dataclass
class RedTeamExercise:
    """紅隊演練資料結構"""
    id: str
    name: str
    description: str
    start_date: str
    end_date: str
    techniques_used: List[str]
    success_rate: float
    detection_rate: float
    prevention_rate: float
    findings: List[str]

@dataclass
class BlueTeamDefense:
    """藍隊防禦資料結構"""
    id: str
    name: str
    description: str
    techniques_covered: List[str]
    detection_capabilities: List[str]
    prevention_capabilities: List[str]
    monitoring_capabilities: List[str]
    coverage_score: float

class MITREATTACKNavigator:
    """MITRE ATT&CK Navigator"""
    
    def __init__(self):
        self.techniques = {}
        self.tactics = {}
        self.mitigations = {}
        self._load_attack_data()
    
    def _load_attack_data(self):
        """載入 ATT&CK 數據"""
        try:
            # 載入技術數據
            self._load_techniques()
            
            # 載入戰術數據
            self._load_tactics()
            
            # 載入緩解措施數據
            self._load_mitigations()
            
            logger.info("ATT&CK 數據載入完成")
        except Exception as e:
            logger.error(f"載入 ATT&CK 數據錯誤: {e}")
    
    def _load_techniques(self):
        """載入技術數據"""
        try:
            # 模擬 ATT&CK 技術數據
            techniques_data = {
                'T1055': {
                    'name': 'Process Injection',
                    'description': 'Adversaries may inject code into processes in order to evade process-based defenses',
                    'category': TechniqueCategory.DEFENSE_EVASION,
                    'subcategory': 'Process Injection',
                    'tactics': ['defense_evasion', 'privilege_escalation'],
                    'platforms': ['Windows', 'Linux', 'macOS'],
                    'permissions_required': ['User', 'Administrator'],
                    'data_sources': ['Process monitoring', 'API monitoring'],
                    'detection_rules': ['Process injection detection', 'API hooking detection'],
                    'mitigation_rules': ['Process isolation', 'Code signing']
                },
                'T1059': {
                    'name': 'Command and Scripting Interpreter',
                    'description': 'Adversaries may abuse command and script interpreters to execute commands',
                    'category': TechniqueCategory.EXECUTION,
                    'subcategory': 'Command and Scripting Interpreter',
                    'tactics': ['execution'],
                    'platforms': ['Windows', 'Linux', 'macOS'],
                    'permissions_required': ['User'],
                    'data_sources': ['Process monitoring', 'Command line monitoring'],
                    'detection_rules': ['Suspicious command execution', 'Script execution monitoring'],
                    'mitigation_rules': ['Application whitelisting', 'Script blocking']
                },
                'T1071': {
                    'name': 'Application Layer Protocol',
                    'description': 'Adversaries may communicate using application layer protocols',
                    'category': TechniqueCategory.COMMAND_AND_CONTROL,
                    'subcategory': 'Application Layer Protocol',
                    'tactics': ['command_and_control'],
                    'platforms': ['Windows', 'Linux', 'macOS'],
                    'permissions_required': ['User'],
                    'data_sources': ['Network monitoring', 'Process monitoring'],
                    'detection_rules': ['Network traffic analysis', 'Protocol analysis'],
                    'mitigation_rules': ['Network segmentation', 'Protocol filtering']
                },
                'T1083': {
                    'name': 'File and Directory Discovery',
                    'description': 'Adversaries may enumerate files and directories',
                    'category': TechniqueCategory.DISCOVERY,
                    'subcategory': 'File and Directory Discovery',
                    'tactics': ['discovery'],
                    'platforms': ['Windows', 'Linux', 'macOS'],
                    'permissions_required': ['User'],
                    'data_sources': ['File monitoring', 'Process monitoring'],
                    'detection_rules': ['File enumeration detection', 'Directory traversal detection'],
                    'mitigation_rules': ['Access controls', 'File system monitoring']
                },
                'T1105': {
                    'name': 'Ingress Tool Transfer',
                    'description': 'Adversaries may transfer tools or other files from an external system',
                    'category': TechniqueCategory.COMMAND_AND_CONTROL,
                    'subcategory': 'Ingress Tool Transfer',
                    'tactics': ['command_and_control'],
                    'platforms': ['Windows', 'Linux', 'macOS'],
                    'permissions_required': ['User'],
                    'data_sources': ['Network monitoring', 'File monitoring'],
                    'detection_rules': ['File download detection', 'Network transfer monitoring'],
                    'mitigation_rules': ['Network filtering', 'File integrity monitoring']
                }
            }
            
            for technique_id, data in techniques_data.items():
                technique = ATTACKTechnique(
                    id=technique_id,
                    name=data['name'],
                    description=data['description'],
                    category=data['category'],
                    subcategory=data['subcategory'],
                    tactics=data['tactics'],
                    platforms=data['platforms'],
                    permissions_required=data['permissions_required'],
                    data_sources=data['data_sources'],
                    detection_rules=data['detection_rules'],
                    mitigation_rules=data['mitigation_rules'],
                    coverage_status=CoverageStatus.NOT_COVERED,
                    detection_score=0.0,
                    prevention_score=0.0
                )
                self.techniques[technique_id] = technique
            
        except Exception as e:
            logger.error(f"載入技術數據錯誤: {e}")
    
    def _load_tactics(self):
        """載入戰術數據"""
        try:
            self.tactics = {
                'initial_access': {
                    'name': 'Initial Access',
                    'description': 'The adversary is trying to get into your network',
                    'techniques': ['T1078', 'T1190', 'T1133', 'T1200', 'T1071']
                },
                'execution': {
                    'name': 'Execution',
                    'description': 'The adversary is trying to run malicious code',
                    'techniques': ['T1059', 'T1106', 'T1129', 'T1053', 'T1047']
                },
                'persistence': {
                    'name': 'Persistence',
                    'description': 'The adversary is trying to maintain their foothold',
                    'techniques': ['T1543', 'T1546', 'T1053', 'T1547', 'T1037']
                },
                'privilege_escalation': {
                    'name': 'Privilege Escalation',
                    'description': 'The adversary is trying to gain higher-level permissions',
                    'techniques': ['T1548', 'T1055', 'T1547', 'T1037', 'T1543']
                },
                'defense_evasion': {
                    'name': 'Defense Evasion',
                    'description': 'The adversary is trying to avoid being detected',
                    'techniques': ['T1055', 'T1070', 'T1036', 'T1027', 'T1055']
                },
                'credential_access': {
                    'name': 'Credential Access',
                    'description': 'The adversary is trying to steal account names and passwords',
                    'techniques': ['T1003', 'T1110', 'T1555', 'T1552', 'T1056']
                },
                'discovery': {
                    'name': 'Discovery',
                    'description': 'The adversary is trying to figure out your environment',
                    'techniques': ['T1083', 'T1016', 'T1049', 'T1033', 'T1082']
                },
                'lateral_movement': {
                    'name': 'Lateral Movement',
                    'description': 'The adversary is trying to move through your environment',
                    'techniques': ['T1021', 'T1078', 'T1550', 'T1021', 'T1077']
                },
                'collection': {
                    'name': 'Collection',
                    'description': 'The adversary is trying to gather data of interest',
                    'techniques': ['T1005', 'T1039', 'T1025', 'T1114', 'T1115']
                },
                'command_and_control': {
                    'name': 'Command and Control',
                    'description': 'The adversary is trying to communicate with compromised systems',
                    'techniques': ['T1071', 'T1105', 'T1090', 'T1102', 'T1104']
                },
                'exfiltration': {
                    'name': 'Exfiltration',
                    'description': 'The adversary is trying to steal data',
                    'techniques': ['T1041', 'T1020', 'T1048', 'T1011', 'T1052']
                },
                'impact': {
                    'name': 'Impact',
                    'description': 'The adversary is trying to manipulate, interrupt, or destroy your systems',
                    'techniques': ['T1486', 'T1489', 'T1490', 'T1491', 'T1499']
                }
            }
        except Exception as e:
            logger.error(f"載入戰術數據錯誤: {e}")
    
    def _load_mitigations(self):
        """載入緩解措施數據"""
        try:
            self.mitigations = {
                'M1038': {
                    'name': 'Execution Prevention',
                    'description': 'Block execution of code on a system',
                    'techniques': ['T1059', 'T1106', 'T1129']
                },
                'M1040': {
                    'name': 'Behavior Prevention on Endpoint',
                    'description': 'Use capabilities to prevent behaviors',
                    'techniques': ['T1055', 'T1070', 'T1036']
                },
                'M1042': {
                    'name': 'Disable or Remove Feature or Program',
                    'description': 'Remove or disable features or programs',
                    'techniques': ['T1059', 'T1106', 'T1129']
                },
                'M1043': {
                    'name': 'Credential Access Protection',
                    'description': 'Use capabilities to prevent credential access',
                    'techniques': ['T1003', 'T1110', 'T1555']
                },
                'M1044': {
                    'name': 'Restrict Library Loading',
                    'description': 'Prevent loading of libraries',
                    'techniques': ['T1055', 'T1070', 'T1036']
                }
            }
        except Exception as e:
            logger.error(f"載入緩解措施數據錯誤: {e}")
    
    def generate_attack_matrix(self, coverage_data: Dict[str, Any]) -> Dict[str, Any]:
        """生成 ATT&CK 矩陣"""
        try:
            matrix = {}
            
            for tactic_name, tactic_data in self.tactics.items():
                tactic_matrix = {
                    'name': tactic_data['name'],
                    'description': tactic_data['description'],
                    'techniques': []
                }
                
                for technique_id in tactic_data['techniques']:
                    if technique_id in self.techniques:
                        technique = self.techniques[technique_id]
                        
                        # 更新覆蓋狀態
                        if technique_id in coverage_data:
                            technique.coverage_status = CoverageStatus(coverage_data[technique_id]['status'])
                            technique.detection_score = coverage_data[technique_id].get('detection_score', 0.0)
                            technique.prevention_score = coverage_data[technique_id].get('prevention_score', 0.0)
                        
                        tactic_matrix['techniques'].append({
                            'id': technique.id,
                            'name': technique.name,
                            'description': technique.description,
                            'coverage_status': technique.coverage_status.value,
                            'detection_score': technique.detection_score,
                            'prevention_score': technique.prevention_score,
                            'platforms': technique.platforms,
                            'data_sources': technique.data_sources
                        })
                
                matrix[tactic_name] = tactic_matrix
            
            return {
                'success': True,
                'matrix': matrix,
                'total_techniques': sum(len(tactic['techniques']) for tactic in matrix.values()),
                'covered_techniques': sum(
                    len([t for t in tactic['techniques'] if t['coverage_status'] != 'not_covered'])
                    for tactic in matrix.values()
                )
            }
        except Exception as e:
            logger.error(f"生成 ATT&CK 矩陣錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def calculate_coverage_percentage(self, matrix: Dict[str, Any]) -> Dict[str, Any]:
        """計算覆蓋百分比"""
        try:
            total_techniques = 0
            covered_techniques = 0
            detection_coverage = 0.0
            prevention_coverage = 0.0
            
            for tactic_name, tactic_data in matrix.items():
                for technique in tactic_data['techniques']:
                    total_techniques += 1
                    
                    if technique['coverage_status'] != 'not_covered':
                        covered_techniques += 1
                    
                    detection_coverage += technique['detection_score']
                    prevention_coverage += technique['prevention_score']
            
            if total_techniques > 0:
                coverage_percentage = (covered_techniques / total_techniques) * 100
                avg_detection_score = detection_coverage / total_techniques
                avg_prevention_score = prevention_coverage / total_techniques
            else:
                coverage_percentage = 0.0
                avg_detection_score = 0.0
                avg_prevention_score = 0.0
            
            return {
                'success': True,
                'coverage_percentage': coverage_percentage,
                'covered_techniques': covered_techniques,
                'total_techniques': total_techniques,
                'average_detection_score': avg_detection_score,
                'average_prevention_score': avg_prevention_score
            }
        except Exception as e:
            logger.error(f"計算覆蓋百分比錯誤: {e}")
            return {'success': False, 'error': str(e)}

class KillChainAnalyzer:
    """Kill Chain 分析器"""
    
    def __init__(self):
        self.kill_chain_phases = [
            AttackPhase.RECONNAISSANCE,
            AttackPhase.WEAPONIZATION,
            AttackPhase.DELIVERY,
            AttackPhase.EXPLOITATION,
            AttackPhase.INSTALLATION,
            AttackPhase.COMMAND_AND_CONTROL,
            AttackPhase.ACTIONS_ON_OBJECTIVES
        ]
        self.phase_techniques = {
            AttackPhase.RECONNAISSANCE: ['T1046', 'T1018', 'T1016', 'T1049'],
            AttackPhase.WEAPONIZATION: ['T1190', 'T1200', 'T1105'],
            AttackPhase.DELIVERY: ['T1071', 'T1105', 'T1190'],
            AttackPhase.EXPLOITATION: ['T1059', 'T1106', 'T1129'],
            AttackPhase.INSTALLATION: ['T1055', 'T1543', 'T1546'],
            AttackPhase.COMMAND_AND_CONTROL: ['T1071', 'T1105', 'T1090'],
            AttackPhase.ACTIONS_ON_OBJECTIVES: ['T1005', 'T1041', 'T1486']
        }
    
    def analyze_kill_chain(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析 Kill Chain"""
        try:
            kill_chain_steps = []
            
            for phase in self.kill_chain_phases:
                techniques = self.phase_techniques.get(phase, [])
                phase_techniques = []
                
                for technique_id in techniques:
                    if technique_id in attack_data.get('techniques', {}):
                        technique_data = attack_data['techniques'][technique_id]
                        phase_techniques.append({
                            'id': technique_id,
                            'name': technique_data.get('name', 'Unknown'),
                            'detected': technique_data.get('detected', False),
                            'prevented': technique_data.get('prevented', False),
                            'monitored': technique_data.get('monitored', False)
                        })
                
                # 計算覆蓋率
                if phase_techniques:
                    detection_coverage = sum(1 for t in phase_techniques if t['detected']) / len(phase_techniques)
                    prevention_coverage = sum(1 for t in phase_techniques if t['prevented']) / len(phase_techniques)
                    monitoring_coverage = sum(1 for t in phase_techniques if t['monitored']) / len(phase_techniques)
                else:
                    detection_coverage = 0.0
                    prevention_coverage = 0.0
                    monitoring_coverage = 0.0
                
                kill_chain_step = KillChainStep(
                    phase=phase,
                    techniques=phase_techniques,
                    detection_coverage=detection_coverage,
                    prevention_coverage=prevention_coverage,
                    monitoring_coverage=monitoring_coverage
                )
                kill_chain_steps.append(kill_chain_step)
            
            return {
                'success': True,
                'kill_chain_steps': [self._kill_chain_step_to_dict(step) for step in kill_chain_steps],
                'overall_detection_coverage': sum(step.detection_coverage for step in kill_chain_steps) / len(kill_chain_steps),
                'overall_prevention_coverage': sum(step.prevention_coverage for step in kill_chain_steps) / len(kill_chain_steps),
                'overall_monitoring_coverage': sum(step.monitoring_coverage for step in kill_chain_steps) / len(kill_chain_steps)
            }
        except Exception as e:
            logger.error(f"分析 Kill Chain 錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _kill_chain_step_to_dict(self, step: KillChainStep) -> Dict[str, Any]:
        """將 Kill Chain 步驟轉換為字典"""
        return {
            'phase': step.phase.value,
            'techniques': step.techniques,
            'detection_coverage': step.detection_coverage,
            'prevention_coverage': step.prevention_coverage,
            'monitoring_coverage': step.monitoring_coverage
        }

class RedBlueTeamAnalyzer:
    """紅藍隊分析器"""
    
    def __init__(self):
        self.red_team_exercises = {}
        self.blue_team_defenses = {}
    
    def analyze_red_team_exercise(self, exercise_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析紅隊演練"""
        try:
            exercise = RedTeamExercise(
                id=exercise_data.get('id', f"exercise_{int(time.time())}"),
                name=exercise_data.get('name', 'Unknown Exercise'),
                description=exercise_data.get('description', 'No description'),
                start_date=exercise_data.get('start_date', datetime.now().isoformat()),
                end_date=exercise_data.get('end_date', datetime.now().isoformat()),
                techniques_used=exercise_data.get('techniques_used', []),
                success_rate=exercise_data.get('success_rate', 0.0),
                detection_rate=exercise_data.get('detection_rate', 0.0),
                prevention_rate=exercise_data.get('prevention_rate', 0.0),
                findings=exercise_data.get('findings', [])
            )
            
            self.red_team_exercises[exercise.id] = exercise
            
            # 分析演練結果
            analysis = {
                'exercise_id': exercise.id,
                'techniques_used_count': len(exercise.techniques_used),
                'success_rate': exercise.success_rate,
                'detection_rate': exercise.detection_rate,
                'prevention_rate': exercise.prevention_rate,
                'findings_count': len(exercise.findings),
                'effectiveness_score': (exercise.success_rate + exercise.detection_rate + exercise.prevention_rate) / 3.0
            }
            
            return {
                'success': True,
                'exercise': self._exercise_to_dict(exercise),
                'analysis': analysis
            }
        except Exception as e:
            logger.error(f"分析紅隊演練錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def analyze_blue_team_defense(self, defense_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析藍隊防禦"""
        try:
            defense = BlueTeamDefense(
                id=defense_data.get('id', f"defense_{int(time.time())}"),
                name=defense_data.get('name', 'Unknown Defense'),
                description=defense_data.get('description', 'No description'),
                techniques_covered=defense_data.get('techniques_covered', []),
                detection_capabilities=defense_data.get('detection_capabilities', []),
                prevention_capabilities=defense_data.get('prevention_capabilities', []),
                monitoring_capabilities=defense_data.get('monitoring_capabilities', []),
                coverage_score=defense_data.get('coverage_score', 0.0)
            )
            
            self.blue_team_defenses[defense.id] = defense
            
            # 分析防禦能力
            analysis = {
                'defense_id': defense.id,
                'techniques_covered_count': len(defense.techniques_covered),
                'detection_capabilities_count': len(defense.detection_capabilities),
                'prevention_capabilities_count': len(defense.prevention_capabilities),
                'monitoring_capabilities_count': len(defense.monitoring_capabilities),
                'coverage_score': defense.coverage_score,
                'capability_score': (len(defense.detection_capabilities) + len(defense.prevention_capabilities) + len(defense.monitoring_capabilities)) / 3.0
            }
            
            return {
                'success': True,
                'defense': self._defense_to_dict(defense),
                'analysis': analysis
            }
        except Exception as e:
            logger.error(f"分析藍隊防禦錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def compare_red_blue_teams(self, red_team_data: Dict[str, Any], blue_team_data: Dict[str, Any]) -> Dict[str, Any]:
        """比較紅藍隊"""
        try:
            comparison = {
                'red_team_effectiveness': red_team_data.get('analysis', {}).get('effectiveness_score', 0.0),
                'blue_team_coverage': blue_team_data.get('analysis', {}).get('coverage_score', 0.0),
                'red_team_techniques': red_team_data.get('analysis', {}).get('techniques_used_count', 0),
                'blue_team_techniques': blue_team_data.get('analysis', {}).get('techniques_covered_count', 0),
                'detection_gap': red_team_data.get('analysis', {}).get('detection_rate', 0.0) - blue_team_data.get('analysis', {}).get('detection_capabilities_count', 0) / 10.0,
                'prevention_gap': red_team_data.get('analysis', {}).get('prevention_rate', 0.0) - blue_team_data.get('analysis', {}).get('prevention_capabilities_count', 0) / 10.0
            }
            
            # 計算整體平衡
            if comparison['red_team_effectiveness'] > comparison['blue_team_coverage']:
                balance_status = "Red Team Advantage"
            elif comparison['blue_team_coverage'] > comparison['red_team_effectiveness']:
                balance_status = "Blue Team Advantage"
            else:
                balance_status = "Balanced"
            
            comparison['balance_status'] = balance_status
            
            return {
                'success': True,
                'comparison': comparison
            }
        except Exception as e:
            logger.error(f"比較紅藍隊錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _exercise_to_dict(self, exercise: RedTeamExercise) -> Dict[str, Any]:
        """將演練轉換為字典"""
        return {
            'id': exercise.id,
            'name': exercise.name,
            'description': exercise.description,
            'start_date': exercise.start_date,
            'end_date': exercise.end_date,
            'techniques_used': exercise.techniques_used,
            'success_rate': exercise.success_rate,
            'detection_rate': exercise.detection_rate,
            'prevention_rate': exercise.prevention_rate,
            'findings': exercise.findings
        }
    
    def _defense_to_dict(self, defense: BlueTeamDefense) -> Dict[str, Any]:
        """將防禦轉換為字典"""
        return {
            'id': defense.id,
            'name': defense.name,
            'description': defense.description,
            'techniques_covered': defense.techniques_covered,
            'detection_capabilities': defense.detection_capabilities,
            'prevention_capabilities': defense.prevention_capabilities,
            'monitoring_capabilities': defense.monitoring_capabilities,
            'coverage_score': defense.coverage_score
        }

class MilitaryRedBlueVisualization:
    """軍事級紅藍對抗可視化主類別"""
    
    def __init__(self):
        self.attack_navigator = MITREATTACKNavigator()
        self.kill_chain_analyzer = KillChainAnalyzer()
        self.red_blue_analyzer = RedBlueTeamAnalyzer()
        self.visualization_log = []
    
    def comprehensive_red_blue_analysis(self, analysis_scope: Dict[str, Any]) -> Dict[str, Any]:
        """執行綜合紅藍對抗分析"""
        try:
            results = {}
            
            # 1. 生成 ATT&CK 矩陣
            logger.info("生成 ATT&CK 矩陣...")
            matrix_results = self._generate_attack_matrix(analysis_scope)
            results['attack_matrix'] = matrix_results
            
            # 2. 分析 Kill Chain
            logger.info("分析 Kill Chain...")
            kill_chain_results = self._analyze_kill_chain(analysis_scope)
            results['kill_chain_analysis'] = kill_chain_results
            
            # 3. 紅隊演練分析
            logger.info("分析紅隊演練...")
            red_team_results = self._analyze_red_team_exercises(analysis_scope)
            results['red_team_analysis'] = red_team_results
            
            # 4. 藍隊防禦分析
            logger.info("分析藍隊防禦...")
            blue_team_results = self._analyze_blue_team_defenses(analysis_scope)
            results['blue_team_analysis'] = blue_team_results
            
            # 5. 紅藍隊比較
            logger.info("比較紅藍隊...")
            comparison_results = self._compare_red_blue_teams(red_team_results, blue_team_results)
            results['red_blue_comparison'] = comparison_results
            
            # 6. 生成可視化報告
            logger.info("生成可視化報告...")
            visualization_results = self._generate_visualization_report(results)
            results['visualization_report'] = visualization_results
            
            return {
                'success': True,
                'results': results,
                'summary': self._generate_red_blue_summary(results)
            }
        except Exception as e:
            logger.error(f"綜合紅藍對抗分析錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _generate_attack_matrix(self, analysis_scope: Dict[str, Any]) -> Dict[str, Any]:
        """生成 ATT&CK 矩陣"""
        try:
            # 模擬覆蓋數據
            coverage_data = {
                'T1055': {'status': 'detected', 'detection_score': 0.8, 'prevention_score': 0.6},
                'T1059': {'status': 'prevented', 'detection_score': 0.9, 'prevention_score': 0.9},
                'T1071': {'status': 'monitored', 'detection_score': 0.7, 'prevention_score': 0.5},
                'T1083': {'status': 'detected', 'detection_score': 0.6, 'prevention_score': 0.4},
                'T1105': {'status': 'not_covered', 'detection_score': 0.0, 'prevention_score': 0.0}
            }
            
            matrix_result = self.attack_navigator.generate_attack_matrix(coverage_data)
            
            if matrix_result['success']:
                coverage_percentage = self.attack_navigator.calculate_coverage_percentage(matrix_result['matrix'])
                matrix_result['coverage_percentage'] = coverage_percentage
            
            return matrix_result
        except Exception as e:
            logger.error(f"生成 ATT&CK 矩陣錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _analyze_kill_chain(self, analysis_scope: Dict[str, Any]) -> Dict[str, Any]:
        """分析 Kill Chain"""
        try:
            # 模擬攻擊數據
            attack_data = {
                'techniques': {
                    'T1046': {'name': 'Network Service Scanning', 'detected': True, 'prevented': False, 'monitored': True},
                    'T1190': {'name': 'Exploit Public-Facing Application', 'detected': True, 'prevented': True, 'monitored': True},
                    'T1071': {'name': 'Application Layer Protocol', 'detected': False, 'prevented': False, 'monitored': True},
                    'T1059': {'name': 'Command and Scripting Interpreter', 'detected': True, 'prevented': True, 'monitored': True},
                    'T1055': {'name': 'Process Injection', 'detected': True, 'prevented': False, 'monitored': True},
                    'T1105': {'name': 'Ingress Tool Transfer', 'detected': False, 'prevented': False, 'monitored': False},
                    'T1005': {'name': 'Data from Local System', 'detected': True, 'prevented': False, 'monitored': True}
                }
            }
            
            kill_chain_result = self.kill_chain_analyzer.analyze_kill_chain(attack_data)
            return kill_chain_result
        except Exception as e:
            logger.error(f"分析 Kill Chain 錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _analyze_red_team_exercises(self, analysis_scope: Dict[str, Any]) -> Dict[str, Any]:
        """分析紅隊演練"""
        try:
            # 模擬紅隊演練數據
            exercise_data = {
                'id': 'red_team_001',
                'name': 'APT Simulation Exercise',
                'description': '模擬 APT 攻擊演練',
                'start_date': '2024-01-01T00:00:00',
                'end_date': '2024-01-07T23:59:59',
                'techniques_used': ['T1055', 'T1059', 'T1071', 'T1083', 'T1105'],
                'success_rate': 0.8,
                'detection_rate': 0.6,
                'prevention_rate': 0.4,
                'findings': [
                    '成功繞過防毒軟體',
                    '建立持久化後門',
                    '橫向移動到關鍵系統',
                    '數據外洩成功'
                ]
            }
            
            red_team_result = self.red_blue_analyzer.analyze_red_team_exercise(exercise_data)
            return red_team_result
        except Exception as e:
            logger.error(f"分析紅隊演練錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _analyze_blue_team_defenses(self, analysis_scope: Dict[str, Any]) -> Dict[str, Any]:
        """分析藍隊防禦"""
        try:
            # 模擬藍隊防禦數據
            defense_data = {
                'id': 'blue_team_001',
                'name': 'Enterprise Security Defense',
                'description': '企業安全防禦系統',
                'techniques_covered': ['T1055', 'T1059', 'T1071', 'T1083'],
                'detection_capabilities': [
                    'EDR 監控',
                    '網路流量分析',
                    '日誌分析',
                    '行為分析'
                ],
                'prevention_capabilities': [
                    '防火牆規則',
                    '應用程式白名單',
                    '網路分段',
                    '存取控制'
                ],
                'monitoring_capabilities': [
                    'SIEM 監控',
                    '威脅情報整合',
                    '異常檢測',
                    '事件回應'
                ],
                'coverage_score': 0.75
            }
            
            blue_team_result = self.red_blue_analyzer.analyze_blue_team_defense(defense_data)
            return blue_team_result
        except Exception as e:
            logger.error(f"分析藍隊防禦錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _compare_red_blue_teams(self, red_team_results: Dict[str, Any], blue_team_results: Dict[str, Any]) -> Dict[str, Any]:
        """比較紅藍隊"""
        try:
            comparison_result = self.red_blue_analyzer.compare_red_blue_teams(red_team_results, blue_team_results)
            return comparison_result
        except Exception as e:
            logger.error(f"比較紅藍隊錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _generate_visualization_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成可視化報告"""
        try:
            report = {
                'report_id': f"report_{int(time.time())}",
                'generated_at': datetime.now().isoformat(),
                'sections': []
            }
            
            # ATT&CK 矩陣報告
            if 'attack_matrix' in results and results['attack_matrix'].get('success', False):
                matrix_data = results['attack_matrix']
                report['sections'].append({
                    'section': 'ATT&CK Matrix',
                    'content': {
                        'total_techniques': matrix_data.get('total_techniques', 0),
                        'covered_techniques': matrix_data.get('covered_techniques', 0),
                        'coverage_percentage': matrix_data.get('coverage_percentage', {}).get('coverage_percentage', 0.0)
                    }
                })
            
            # Kill Chain 報告
            if 'kill_chain_analysis' in results and results['kill_chain_analysis'].get('success', False):
                kill_chain_data = results['kill_chain_analysis']
                report['sections'].append({
                    'section': 'Kill Chain Analysis',
                    'content': {
                        'overall_detection_coverage': kill_chain_data.get('overall_detection_coverage', 0.0),
                        'overall_prevention_coverage': kill_chain_data.get('overall_prevention_coverage', 0.0),
                        'overall_monitoring_coverage': kill_chain_data.get('overall_monitoring_coverage', 0.0)
                    }
                })
            
            # 紅藍隊比較報告
            if 'red_blue_comparison' in results and results['red_blue_comparison'].get('success', False):
                comparison_data = results['red_blue_comparison']
                report['sections'].append({
                    'section': 'Red vs Blue Team Comparison',
                    'content': comparison_data.get('comparison', {})
                })
            
            return {
                'success': True,
                'report': report
            }
        except Exception as e:
            logger.error(f"生成可視化報告錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _generate_red_blue_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成紅藍對抗摘要"""
        summary = {
            'total_analyses': len(results),
            'successful_analyses': sum(1 for r in results.values() if isinstance(r, dict) and r.get('success', True)),
            'attack_matrix_generated': False,
            'kill_chain_analyzed': False,
            'red_team_analyzed': False,
            'blue_team_analyzed': False,
            'comparison_completed': False
        }
        
        if 'attack_matrix' in results and results['attack_matrix'].get('success', False):
            summary['attack_matrix_generated'] = True
        
        if 'kill_chain_analysis' in results and results['kill_chain_analysis'].get('success', False):
            summary['kill_chain_analyzed'] = True
        
        if 'red_team_analysis' in results and results['red_team_analysis'].get('success', False):
            summary['red_team_analyzed'] = True
        
        if 'blue_team_analysis' in results and results['blue_team_analysis'].get('success', False):
            summary['blue_team_analyzed'] = True
        
        if 'red_blue_comparison' in results and results['red_blue_comparison'].get('success', False):
            summary['comparison_completed'] = True
        
        return summary
    
    def get_visualization_log(self) -> List[Dict[str, Any]]:
        """獲取可視化日誌"""
        return self.visualization_log
    
    def export_results(self, filename: str) -> bool:
        """匯出結果"""
        try:
            data = {
                'visualization_log': self.visualization_log,
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
    print("🎯 軍事級紅藍對抗可視化系統")
    print("=" * 50)
    
    # 初始化系統
    red_blue_visualization = MilitaryRedBlueVisualization()
    
    # 測試分析範圍
    test_analysis_scope = {
        'analysis_types': ['attack_matrix', 'kill_chain', 'red_blue_comparison'],
        'time_range': '30d',
        'include_visualizations': True
    }
    
    # 執行綜合紅藍對抗分析測試
    print("開始執行綜合紅藍對抗分析測試...")
    results = red_blue_visualization.comprehensive_red_blue_analysis(test_analysis_scope)
    
    print(f"分析完成，成功: {results['success']}")
    print(f"分析摘要: {json.dumps(results['summary'], indent=2, ensure_ascii=False)}")
    
    # 匯出結果
    red_blue_visualization.export_results("red_blue_visualization_results.json")
    
    print("軍事級紅藍對抗可視化系統測試完成！")

if __name__ == "__main__":
    main()

