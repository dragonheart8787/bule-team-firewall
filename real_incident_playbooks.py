#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實事件回應劇本系統
Real Incident Response Playbooks System
自動化劇本、工作流程、協調機制
"""

import os
import json
import time
import logging
import threading
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import sqlite3
import yaml
import requests

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealIncidentPlaybooks:
    """真實事件回應劇本系統"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.playbook_threads = []
        self.active_incidents = {}
        self.playbook_templates = {}
        self.workflow_engine = None
        
        # 初始化組件
        self._init_database()
        self._init_playbook_templates()
        self._init_workflow_engine()
        
        logger.info("真實事件回應劇本系統初始化完成")
    
    def _init_database(self):
        """初始化數據庫"""
        try:
            self.db_path = 'incident_playbooks.db'
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 創建事件表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    status TEXT DEFAULT 'open',
                    playbook_id TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    assigned_to TEXT,
                    priority INTEGER DEFAULT 3
                )
            ''')
            
            # 創建劇本表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS playbooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    playbook_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    category TEXT NOT NULL,
                    severity_levels TEXT NOT NULL,
                    steps TEXT NOT NULL,
                    automation_level TEXT DEFAULT 'manual',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 創建劇本執行表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS playbook_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    execution_id TEXT UNIQUE NOT NULL,
                    incident_id TEXT NOT NULL,
                    playbook_id TEXT NOT NULL,
                    status TEXT DEFAULT 'running',
                    current_step INTEGER DEFAULT 0,
                    total_steps INTEGER NOT NULL,
                    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    completed_at DATETIME,
                    error_message TEXT,
                    execution_log TEXT
                )
            ''')
            
            # 創建工作流程表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS workflows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workflow_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    triggers TEXT NOT NULL,
                    steps TEXT NOT NULL,
                    conditions TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("事件回應劇本數據庫初始化完成")
            
        except Exception as e:
            logger.error(f"數據庫初始化錯誤: {e}")
    
    def _init_playbook_templates(self):
        """初始化劇本模板"""
        try:
            # 惡意程式檢測劇本
            self.playbook_templates['malware_detection'] = {
                'name': '惡意程式檢測與回應',
                'description': '檢測到惡意程式時的自動回應流程',
                'category': 'malware',
                'severity_levels': ['high', 'critical'],
                'automation_level': 'semi_automatic',
                'steps': [
                    {
                        'step_id': 1,
                        'name': '隔離受感染主機',
                        'action': 'isolate_host',
                        'parameters': {'host_ip': '{{incident.host_ip}}'},
                        'timeout': 300,
                        'retry_count': 3
                    },
                    {
                        'step_id': 2,
                        'name': '收集惡意程式樣本',
                        'action': 'collect_malware_sample',
                        'parameters': {'file_path': '{{incident.file_path}}'},
                        'timeout': 600,
                        'retry_count': 2
                    },
                    {
                        'step_id': 3,
                        'name': '分析惡意程式',
                        'action': 'analyze_malware',
                        'parameters': {'sample_id': '{{step2.sample_id}}'},
                        'timeout': 1800,
                        'retry_count': 1
                    },
                    {
                        'step_id': 4,
                        'name': '更新防護規則',
                        'action': 'update_protection_rules',
                        'parameters': {'ioc_data': '{{step3.ioc_data}}'},
                        'timeout': 300,
                        'retry_count': 2
                    },
                    {
                        'step_id': 5,
                        'name': '通知相關人員',
                        'action': 'notify_stakeholders',
                        'parameters': {'incident_id': '{{incident.id}}', 'severity': '{{incident.severity}}'},
                        'timeout': 60,
                        'retry_count': 3
                    }
                ]
            }
            
            # 網路入侵檢測劇本
            self.playbook_templates['network_intrusion'] = {
                'name': '網路入侵檢測與回應',
                'description': '檢測到網路入侵時的自動回應流程',
                'category': 'network',
                'severity_levels': ['medium', 'high', 'critical'],
                'automation_level': 'semi_automatic',
                'steps': [
                    {
                        'step_id': 1,
                        'name': '封鎖可疑IP',
                        'action': 'block_ip',
                        'parameters': {'ip_address': '{{incident.src_ip}}'},
                        'timeout': 60,
                        'retry_count': 3
                    },
                    {
                        'step_id': 2,
                        'name': '收集網路流量',
                        'action': 'collect_network_traffic',
                        'parameters': {'src_ip': '{{incident.src_ip}}', 'time_range': '1h'},
                        'timeout': 900,
                        'retry_count': 2
                    },
                    {
                        'step_id': 3,
                        'name': '分析攻擊模式',
                        'action': 'analyze_attack_pattern',
                        'parameters': {'traffic_data': '{{step2.traffic_data}}'},
                        'timeout': 1200,
                        'retry_count': 1
                    },
                    {
                        'step_id': 4,
                        'name': '更新防火牆規則',
                        'action': 'update_firewall_rules',
                        'parameters': {'attack_signature': '{{step3.signature}}'},
                        'timeout': 300,
                        'retry_count': 2
                    },
                    {
                        'step_id': 5,
                        'name': '生成事件報告',
                        'action': 'generate_incident_report',
                        'parameters': {'incident_id': '{{incident.id}}', 'analysis_data': '{{step3.analysis}}'},
                        'timeout': 300,
                        'retry_count': 1
                    }
                ]
            }
            
            # 數據洩露檢測劇本
            self.playbook_templates['data_breach'] = {
                'name': '數據洩露檢測與回應',
                'description': '檢測到數據洩露時的自動回應流程',
                'category': 'data_breach',
                'severity_levels': ['high', 'critical'],
                'automation_level': 'manual',
                'steps': [
                    {
                        'step_id': 1,
                        'name': '立即隔離受影響系統',
                        'action': 'isolate_affected_systems',
                        'parameters': {'system_list': '{{incident.affected_systems}}'},
                        'timeout': 300,
                        'retry_count': 3
                    },
                    {
                        'step_id': 2,
                        'name': '評估洩露範圍',
                        'action': 'assess_breach_scope',
                        'parameters': {'breach_data': '{{incident.breach_data}}'},
                        'timeout': 1800,
                        'retry_count': 1
                    },
                    {
                        'step_id': 3,
                        'name': '通知法務團隊',
                        'action': 'notify_legal_team',
                        'parameters': {'incident_id': '{{incident.id}}', 'severity': 'critical'},
                        'timeout': 60,
                        'retry_count': 3
                    },
                    {
                        'step_id': 4,
                        'name': '準備合規報告',
                        'action': 'prepare_compliance_report',
                        'parameters': {'breach_scope': '{{step2.scope}}'},
                        'timeout': 3600,
                        'retry_count': 1
                    },
                    {
                        'step_id': 5,
                        'name': '執行損害控制',
                        'action': 'execute_damage_control',
                        'parameters': {'affected_data': '{{step2.affected_data}}'},
                        'timeout': 7200,
                        'retry_count': 1
                    }
                ]
            }
            
            # 內部威脅檢測劇本
            self.playbook_templates['insider_threat'] = {
                'name': '內部威脅檢測與回應',
                'description': '檢測到內部威脅時的自動回應流程',
                'category': 'insider_threat',
                'severity_levels': ['medium', 'high', 'critical'],
                'automation_level': 'manual',
                'steps': [
                    {
                        'step_id': 1,
                        'name': '暫停用戶權限',
                        'action': 'suspend_user_access',
                        'parameters': {'user_id': '{{incident.user_id}}'},
                        'timeout': 60,
                        'retry_count': 3
                    },
                    {
                        'step_id': 2,
                        'name': '收集用戶活動證據',
                        'action': 'collect_user_activity',
                        'parameters': {'user_id': '{{incident.user_id}}', 'time_range': '30d'},
                        'timeout': 1800,
                        'retry_count': 2
                    },
                    {
                        'step_id': 3,
                        'name': '分析行為模式',
                        'action': 'analyze_behavior_pattern',
                        'parameters': {'activity_data': '{{step2.activity_data}}'},
                        'timeout': 3600,
                        'retry_count': 1
                    },
                    {
                        'step_id': 4,
                        'name': '通知人力資源',
                        'action': 'notify_hr_department',
                        'parameters': {'user_id': '{{incident.user_id}}', 'evidence': '{{step3.evidence}}'},
                        'timeout': 60,
                        'retry_count': 3
                    },
                    {
                        'step_id': 5,
                        'name': '啟動內部調查',
                        'action': 'initiate_internal_investigation',
                        'parameters': {'incident_id': '{{incident.id}}', 'user_id': '{{incident.user_id}}'},
                        'timeout': 300,
                        'retry_count': 1
                    }
                ]
            }
            
            # 將劇本保存到數據庫
            self._save_playbook_templates()
            
            logger.info("劇本模板初始化完成")
            
        except Exception as e:
            logger.error(f"劇本模板初始化錯誤: {e}")
    
    def _save_playbook_templates(self):
        """保存劇本模板到數據庫"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for playbook_id, template in self.playbook_templates.items():
                cursor.execute('''
                    INSERT OR REPLACE INTO playbooks
                    (playbook_id, name, description, category, severity_levels, steps, automation_level)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    playbook_id,
                    template['name'],
                    template['description'],
                    template['category'],
                    json.dumps(template['severity_levels']),
                    json.dumps(template['steps']),
                    template['automation_level']
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"保存劇本模板錯誤: {e}")
    
    def _init_workflow_engine(self):
        """初始化工作流程引擎"""
        try:
            self.workflow_engine = {
                'action_handlers': {
                    'isolate_host': self._action_isolate_host,
                    'collect_malware_sample': self._action_collect_malware_sample,
                    'analyze_malware': self._action_analyze_malware,
                    'update_protection_rules': self._action_update_protection_rules,
                    'notify_stakeholders': self._action_notify_stakeholders,
                    'block_ip': self._action_block_ip,
                    'collect_network_traffic': self._action_collect_network_traffic,
                    'analyze_attack_pattern': self._action_analyze_attack_pattern,
                    'update_firewall_rules': self._action_update_firewall_rules,
                    'generate_incident_report': self._action_generate_incident_report,
                    'isolate_affected_systems': self._action_isolate_affected_systems,
                    'assess_breach_scope': self._action_assess_breach_scope,
                    'notify_legal_team': self._action_notify_legal_team,
                    'prepare_compliance_report': self._action_prepare_compliance_report,
                    'execute_damage_control': self._action_execute_damage_control,
                    'suspend_user_access': self._action_suspend_user_access,
                    'collect_user_activity': self._action_collect_user_activity,
                    'analyze_behavior_pattern': self._action_analyze_behavior_pattern,
                    'notify_hr_department': self._action_notify_hr_department,
                    'initiate_internal_investigation': self._action_initiate_internal_investigation
                },
                'condition_evaluators': {
                    'severity_check': self._evaluate_severity_condition,
                    'time_check': self._evaluate_time_condition,
                    'resource_check': self._evaluate_resource_condition
                }
            }
            
            logger.info("工作流程引擎初始化完成")
            
        except Exception as e:
            logger.error(f"工作流程引擎初始化錯誤: {e}")
    
    def start_playbook_engine(self) -> Dict[str, Any]:
        """啟動劇本引擎"""
        try:
            if self.running:
                return {'success': False, 'error': '劇本引擎已在運行中'}
            
            self.running = True
            
            # 啟動劇本監控線程
            thread = threading.Thread(target=self._monitor_incidents, daemon=True)
            thread.start()
            self.playbook_threads.append(thread)
            
            # 啟動工作流程處理線程
            thread = threading.Thread(target=self._process_workflows, daemon=True)
            thread.start()
            self.playbook_threads.append(thread)
            
            logger.info("劇本引擎已啟動")
            return {'success': True, 'message': '劇本引擎已啟動'}
            
        except Exception as e:
            logger.error(f"啟動劇本引擎錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _monitor_incidents(self):
        """監控事件"""
        try:
            while self.running:
                try:
                    # 檢查新的事件
                    self._check_new_incidents()
                    
                    # 檢查進行中的劇本執行
                    self._check_running_executions()
                    
                    time.sleep(30)  # 每30秒檢查一次
                    
                except Exception as e:
                    logger.error(f"監控事件錯誤: {e}")
                    time.sleep(10)
                    
        except Exception as e:
            logger.error(f"運行事件監控錯誤: {e}")
    
    def _check_new_incidents(self):
        """檢查新的事件"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 獲取狀態為open且沒有分配劇本的事件
            cursor.execute('''
                SELECT id, incident_id, title, description, severity, created_at
                FROM incidents
                WHERE status = 'open' AND playbook_id IS NULL
                ORDER BY created_at ASC
            ''')
            
            incidents = cursor.fetchall()
            conn.close()
            
            # 為每個事件選擇合適的劇本
            for incident in incidents:
                self._select_playbook_for_incident(incident)
                
        except Exception as e:
            logger.error(f"檢查新事件錯誤: {e}")
    
    def _select_playbook_for_incident(self, incident: Tuple):
        """為事件選擇合適的劇本"""
        try:
            incident_id, title, description, severity, created_at = incident
            
            # 根據事件標題和描述選擇劇本
            playbook_id = None
            
            if 'malware' in title.lower() or 'malware' in description.lower():
                playbook_id = 'malware_detection'
            elif 'network' in title.lower() or 'intrusion' in title.lower():
                playbook_id = 'network_intrusion'
            elif 'breach' in title.lower() or 'leak' in title.lower():
                playbook_id = 'data_breach'
            elif 'insider' in title.lower() or 'internal' in title.lower():
                playbook_id = 'insider_threat'
            else:
                # 預設使用網路入侵劇本
                playbook_id = 'network_intrusion'
            
            # 更新事件記錄
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE incidents
                SET playbook_id = ?, updated_at = CURRENT_TIMESTAMP
                WHERE incident_id = ?
            ''', (playbook_id, incident_id))
            
            conn.commit()
            conn.close()
            
            # 啟動劇本執行
            self._execute_playbook(incident_id, playbook_id)
            
            logger.info(f"為事件 {incident_id} 選擇劇本 {playbook_id}")
            
        except Exception as e:
            logger.error(f"選擇劇本錯誤: {e}")
    
    def _execute_playbook(self, incident_id: str, playbook_id: str) -> Dict[str, Any]:
        """執行劇本"""
        try:
            # 獲取劇本模板
            if playbook_id not in self.playbook_templates:
                logger.error(f"劇本 {playbook_id} 不存在")
                return {'success': False, 'error': f'劇本 {playbook_id} 不存在'}
            
            template = self.playbook_templates[playbook_id]
            steps = template['steps']
            
            # 創建執行記錄
            execution_id = f"exec_{incident_id}_{int(time.time())}"
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO playbook_executions
                (execution_id, incident_id, playbook_id, total_steps, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (execution_id, incident_id, playbook_id, len(steps), 'running'))
            
            conn.commit()
            conn.close()
            
            # 在後台執行劇本
            thread = threading.Thread(
                target=self._run_playbook_steps,
                args=(execution_id, incident_id, playbook_id, steps),
                daemon=True
            )
            thread.start()
            self.playbook_threads.append(thread)
            
            return {'success': True, 'execution_id': execution_id}
            
        except Exception as e:
            logger.error(f"執行劇本錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _run_playbook_steps(self, execution_id: str, incident_id: str, playbook_id: str, steps: List[Dict[str, Any]]):
        """運行劇本步驟"""
        try:
            execution_log = []
            current_step = 0
            
            for step in steps:
                try:
                    current_step = step['step_id']
                    
                    # 更新執行狀態
                    self._update_execution_status(execution_id, current_step, 'running')
                    
                    # 執行步驟
                    result = self._execute_playbook_step(execution_id, incident_id, step)
                    
                    if result['success']:
                        execution_log.append({
                            'step_id': current_step,
                            'step_name': step['name'],
                            'status': 'completed',
                            'result': result.get('result', {}),
                            'timestamp': datetime.now().isoformat()
                        })
                        logger.info(f"劇本步驟 {current_step} 執行成功: {step['name']}")
                    else:
                        execution_log.append({
                            'step_id': current_step,
                            'step_name': step['name'],
                            'status': 'failed',
                            'error': result.get('error', '未知錯誤'),
                            'timestamp': datetime.now().isoformat()
                        })
                        logger.error(f"劇本步驟 {current_step} 執行失敗: {step['name']} - {result.get('error', '未知錯誤')}")
                        
                        # 根據重試策略決定是否繼續
                        if step.get('retry_count', 0) > 0:
                            # 這裡可以實現重試邏輯
                            pass
                        else:
                            break
                    
                except Exception as e:
                    execution_log.append({
                        'step_id': current_step,
                        'step_name': step.get('name', '未知步驟'),
                        'status': 'error',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
                    logger.error(f"劇本步驟 {current_step} 執行錯誤: {e}")
                    break
            
            # 更新最終執行狀態
            status = 'completed' if current_step == len(steps) else 'failed'
            self._update_execution_status(execution_id, current_step, status, execution_log)
            
        except Exception as e:
            logger.error(f"運行劇本步驟錯誤: {e}")
            self._update_execution_status(execution_id, current_step, 'error', [{'error': str(e)}])
    
    def _execute_playbook_step(self, execution_id: str, incident_id: str, step: Dict[str, Any]) -> Dict[str, Any]:
        """執行劇本步驟"""
        try:
            action = step['action']
            parameters = step.get('parameters', {})
            timeout = step.get('timeout', 300)
            
            # 替換參數中的變數
            parameters = self._resolve_parameters(parameters, incident_id)
            
            # 獲取動作處理器
            if action in self.workflow_engine['action_handlers']:
                handler = self.workflow_engine['action_handlers'][action]
                result = handler(parameters)
                return result
            else:
                return {'success': False, 'error': f'未知動作: {action}'}
                
        except Exception as e:
            logger.error(f"執行劇本步驟錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _resolve_parameters(self, parameters: Dict[str, Any], incident_id: str) -> Dict[str, Any]:
        """解析參數中的變數"""
        try:
            resolved = {}
            
            for key, value in parameters.items():
                if isinstance(value, str) and value.startswith('{{') and value.endswith('}}'):
                    # 簡單的變數替換，實際實現中需要更複雜的模板引擎
                    variable = value[2:-2]
                    if variable == 'incident.id':
                        resolved[key] = incident_id
                    elif variable == 'incident.severity':
                        resolved[key] = 'high'  # 預設值
                    else:
                        resolved[key] = value  # 保持原值
                else:
                    resolved[key] = value
            
            return resolved
            
        except Exception as e:
            logger.error(f"解析參數錯誤: {e}")
            return parameters
    
    def _update_execution_status(self, execution_id: str, current_step: int, status: str, execution_log: List[Dict[str, Any]] = None):
        """更新執行狀態"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if status in ['completed', 'failed', 'error']:
                cursor.execute('''
                    UPDATE playbook_executions
                    SET status = ?, current_step = ?, completed_at = CURRENT_TIMESTAMP, execution_log = ?
                    WHERE execution_id = ?
                ''', (status, current_step, json.dumps(execution_log or []), execution_id))
            else:
                cursor.execute('''
                    UPDATE playbook_executions
                    SET current_step = ?, execution_log = ?
                    WHERE execution_id = ?
                ''', (current_step, json.dumps(execution_log or []), execution_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"更新執行狀態錯誤: {e}")
    
    def _check_running_executions(self):
        """檢查進行中的執行"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 獲取運行中的執行
            cursor.execute('''
                SELECT execution_id, incident_id, playbook_id, started_at
                FROM playbook_executions
                WHERE status = 'running'
                ORDER BY started_at ASC
            ''')
            
            executions = cursor.fetchall()
            conn.close()
            
            # 檢查超時的執行
            for execution in executions:
                execution_id, incident_id, playbook_id, started_at = execution
                start_time = datetime.fromisoformat(started_at)
                
                # 如果執行超過2小時，標記為超時
                if datetime.now() - start_time > timedelta(hours=2):
                    self._update_execution_status(execution_id, 0, 'timeout')
                    logger.warning(f"劇本執行超時: {execution_id}")
                    
        except Exception as e:
            logger.error(f"檢查運行中執行錯誤: {e}")
    
    def _process_workflows(self):
        """處理工作流程"""
        try:
            while self.running:
                try:
                    # 這裡可以實現工作流程處理邏輯
                    # 例如：定期檢查工作流程觸發條件
                    time.sleep(60)  # 每分鐘檢查一次
                    
                except Exception as e:
                    logger.error(f"處理工作流程錯誤: {e}")
                    time.sleep(10)
                    
        except Exception as e:
            logger.error(f"運行工作流程處理錯誤: {e}")
    
    # 動作處理器實現
    def _action_isolate_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """隔離主機動作"""
        try:
            host_ip = parameters.get('host_ip', '')
            logger.info(f"執行主機隔離: {host_ip}")
            
            # 模擬主機隔離操作
            time.sleep(2)
            
            return {
                'success': True,
                'result': {
                    'host_ip': host_ip,
                    'isolation_status': 'isolated',
                    'timestamp': datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"隔離主機動作錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _action_collect_malware_sample(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """收集惡意程式樣本動作"""
        try:
            file_path = parameters.get('file_path', '')
            logger.info(f"收集惡意程式樣本: {file_path}")
            
            # 模擬樣本收集
            sample_id = f"sample_{int(time.time())}"
            time.sleep(3)
            
            return {
                'success': True,
                'result': {
                    'sample_id': sample_id,
                    'file_path': file_path,
                    'collection_status': 'completed',
                    'timestamp': datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"收集惡意程式樣本動作錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _action_analyze_malware(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """分析惡意程式動作"""
        try:
            sample_id = parameters.get('sample_id', '')
            logger.info(f"分析惡意程式: {sample_id}")
            
            # 模擬惡意程式分析
            time.sleep(5)
            
            return {
                'success': True,
                'result': {
                    'sample_id': sample_id,
                    'analysis_status': 'completed',
                    'ioc_data': {
                        'file_hash': 'abc123def456',
                        'file_type': 'PE32',
                        'threat_level': 'high',
                        'family': 'trojan'
                    },
                    'timestamp': datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"分析惡意程式動作錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _action_update_protection_rules(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """更新防護規則動作"""
        try:
            ioc_data = parameters.get('ioc_data', {})
            logger.info(f"更新防護規則: {ioc_data}")
            
            # 模擬規則更新
            time.sleep(2)
            
            return {
                'success': True,
                'result': {
                    'rules_updated': True,
                    'rule_count': 3,
                    'timestamp': datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"更新防護規則動作錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _action_notify_stakeholders(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """通知相關人員動作"""
        try:
            incident_id = parameters.get('incident_id', '')
            severity = parameters.get('severity', 'medium')
            logger.info(f"通知相關人員: 事件 {incident_id}, 嚴重程度 {severity}")
            
            # 模擬通知發送
            time.sleep(1)
            
            return {
                'success': True,
                'result': {
                    'notification_sent': True,
                    'recipients': ['security_team@company.com', 'incident_manager@company.com'],
                    'timestamp': datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"通知相關人員動作錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _action_block_ip(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """封鎖IP動作"""
        try:
            ip_address = parameters.get('ip_address', '')
            logger.info(f"封鎖IP: {ip_address}")
            
            # 模擬IP封鎖
            time.sleep(1)
            
            return {
                'success': True,
                'result': {
                    'ip_address': ip_address,
                    'block_status': 'blocked',
                    'timestamp': datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"封鎖IP動作錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _action_collect_network_traffic(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """收集網路流量動作"""
        try:
            src_ip = parameters.get('src_ip', '')
            time_range = parameters.get('time_range', '1h')
            logger.info(f"收集網路流量: {src_ip}, 時間範圍 {time_range}")
            
            # 模擬流量收集
            time.sleep(3)
            
            return {
                'success': True,
                'result': {
                    'src_ip': src_ip,
                    'time_range': time_range,
                    'traffic_data': {
                        'packet_count': 1500,
                        'bytes_transferred': 2048000,
                        'connections': 25
                    },
                    'timestamp': datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"收集網路流量動作錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _action_analyze_attack_pattern(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """分析攻擊模式動作"""
        try:
            traffic_data = parameters.get('traffic_data', {})
            logger.info(f"分析攻擊模式: {traffic_data}")
            
            # 模擬攻擊模式分析
            time.sleep(4)
            
            return {
                'success': True,
                'result': {
                    'analysis_status': 'completed',
                    'signature': 'port_scan_attack',
                    'threat_level': 'medium',
                    'analysis': {
                        'attack_type': 'port_scan',
                        'target_ports': [22, 80, 443, 3389],
                        'scan_duration': '5 minutes'
                    },
                    'timestamp': datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"分析攻擊模式動作錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _action_update_firewall_rules(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """更新防火牆規則動作"""
        try:
            attack_signature = parameters.get('attack_signature', '')
            logger.info(f"更新防火牆規則: {attack_signature}")
            
            # 模擬防火牆規則更新
            time.sleep(2)
            
            return {
                'success': True,
                'result': {
                    'rules_updated': True,
                    'rule_type': 'block_port_scan',
                    'timestamp': datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"更新防火牆規則動作錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _action_generate_incident_report(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """生成事件報告動作"""
        try:
            incident_id = parameters.get('incident_id', '')
            analysis_data = parameters.get('analysis_data', {})
            logger.info(f"生成事件報告: {incident_id}")
            
            # 模擬報告生成
            time.sleep(3)
            
            return {
                'success': True,
                'result': {
                    'report_id': f"report_{incident_id}",
                    'report_status': 'generated',
                    'report_path': f"/reports/{incident_id}_report.pdf",
                    'timestamp': datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"生成事件報告動作錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    # 其他動作處理器的簡化實現
    def _action_isolate_affected_systems(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {'success': True, 'result': {'status': 'isolated'}}
    
    def _action_assess_breach_scope(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {'success': True, 'result': {'scope': 'assessed'}}
    
    def _action_notify_legal_team(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {'success': True, 'result': {'notification_sent': True}}
    
    def _action_prepare_compliance_report(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {'success': True, 'result': {'report_prepared': True}}
    
    def _action_execute_damage_control(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {'success': True, 'result': {'damage_control_executed': True}}
    
    def _action_suspend_user_access(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {'success': True, 'result': {'access_suspended': True}}
    
    def _action_collect_user_activity(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {'success': True, 'result': {'activity_collected': True}}
    
    def _action_analyze_behavior_pattern(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {'success': True, 'result': {'pattern_analyzed': True}}
    
    def _action_notify_hr_department(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {'success': True, 'result': {'hr_notified': True}}
    
    def _action_initiate_internal_investigation(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {'success': True, 'result': {'investigation_initiated': True}}
    
    # 條件評估器
    def _evaluate_severity_condition(self, condition: Dict[str, Any]) -> bool:
        return True  # 簡化實現
    
    def _evaluate_time_condition(self, condition: Dict[str, Any]) -> bool:
        return True  # 簡化實現
    
    def _evaluate_resource_condition(self, condition: Dict[str, Any]) -> bool:
        return True  # 簡化實現
    
    def create_incident(self, title: str, description: str, severity: str, **kwargs) -> Dict[str, Any]:
        """創建事件"""
        try:
            incident_id = f"inc_{int(time.time())}"
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO incidents
                (incident_id, title, description, severity, status, priority)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (incident_id, title, description, severity, 'open', kwargs.get('priority', 3)))
            
            conn.commit()
            conn.close()
            
            logger.info(f"創建事件: {incident_id} - {title}")
            
            return {
                'success': True,
                'incident_id': incident_id,
                'message': '事件創建成功'
            }
            
        except Exception as e:
            logger.error(f"創建事件錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_incident_status(self, incident_id: str) -> Dict[str, Any]:
        """獲取事件狀態"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT incident_id, title, description, severity, status, playbook_id, created_at, updated_at
                FROM incidents
                WHERE incident_id = ?
            ''', (incident_id,))
            
            incident = cursor.fetchone()
            
            if incident:
                # 獲取劇本執行狀態
                cursor.execute('''
                    SELECT execution_id, status, current_step, total_steps, started_at, completed_at
                    FROM playbook_executions
                    WHERE incident_id = ?
                    ORDER BY started_at DESC
                    LIMIT 1
                ''', (incident_id,))
                
                execution = cursor.fetchone()
                
                conn.close()
                
                return {
                    'success': True,
                    'incident': {
                        'incident_id': incident[0],
                        'title': incident[1],
                        'description': incident[2],
                        'severity': incident[3],
                        'status': incident[4],
                        'playbook_id': incident[5],
                        'created_at': incident[6],
                        'updated_at': incident[7],
                        'execution': {
                            'execution_id': execution[0] if execution else None,
                            'status': execution[1] if execution else None,
                            'current_step': execution[2] if execution else None,
                            'total_steps': execution[3] if execution else None,
                            'started_at': execution[4] if execution else None,
                            'completed_at': execution[5] if execution else None
                        } if execution else None
                    }
                }
            else:
                conn.close()
                return {'success': False, 'error': '事件不存在'}
                
        except Exception as e:
            logger.error(f"獲取事件狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def stop_playbook_engine(self) -> Dict[str, Any]:
        """停止劇本引擎"""
        try:
            self.running = False
            
            # 等待所有線程結束
            for thread in self.playbook_threads:
                thread.join(timeout=5)
            
            self.playbook_threads.clear()
            
            logger.info("劇本引擎已停止")
            return {'success': True, 'message': '劇本引擎已停止'}
            
        except Exception as e:
            logger.error(f"停止劇本引擎錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """獲取系統狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'playbook_templates': len(self.playbook_templates),
                'active_incidents': len(self.active_incidents),
                'playbook_threads': len(self.playbook_threads)
            }
        except Exception as e:
            logger.error(f"獲取系統狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """獲取綜合報告"""
        try:
            return {
                'success': True,
                'incident_playbooks': {
                    'playbook_templates': list(self.playbook_templates.keys()),
                    'active_incidents': self.active_incidents,
                    'workflow_engine': {
                        'action_handlers': len(self.workflow_engine['action_handlers']),
                        'condition_evaluators': len(self.workflow_engine['condition_evaluators'])
                    }
                }
            }
        except Exception as e:
            logger.error(f"獲取綜合報告錯誤: {e}")
            return {'success': False, 'error': str(e)}



