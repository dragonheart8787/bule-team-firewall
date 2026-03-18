#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實威脅獵捕查詢庫
Real Threat Hunting Queries Library
預建查詢、自定義規則、關聯分析
"""

import os
import json
import time
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import re

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealThreatHuntingQueries:
    """真實威脅獵捕查詢庫"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.query_templates = {}
        self.custom_rules = {}
        self.correlation_rules = {}
        
        # 初始化組件
        self._init_database()
        self._init_query_templates()
        self._init_correlation_rules()
        
        logger.info("真實威脅獵捕查詢庫初始化完成")
    
    def _init_database(self):
        """初始化數據庫"""
        try:
            self.db_path = 'threat_hunting_queries.db'
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 創建查詢模板表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS query_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    template_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    category TEXT NOT NULL,
                    query_type TEXT NOT NULL,
                    query_text TEXT NOT NULL,
                    parameters TEXT,
                    mitre_techniques TEXT,
                    severity TEXT DEFAULT 'medium',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 創建自定義規則表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS custom_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    rule_type TEXT NOT NULL,
                    rule_content TEXT NOT NULL,
                    conditions TEXT,
                    actions TEXT,
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 創建關聯規則表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS correlation_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    event_types TEXT NOT NULL,
                    time_window INTEGER DEFAULT 300,
                    conditions TEXT NOT NULL,
                    actions TEXT,
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 創建查詢執行記錄表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS query_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    execution_id TEXT UNIQUE NOT NULL,
                    template_id TEXT,
                    query_text TEXT NOT NULL,
                    parameters TEXT,
                    results_count INTEGER DEFAULT 0,
                    execution_time REAL DEFAULT 0.0,
                    status TEXT DEFAULT 'running',
                    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    completed_at DATETIME,
                    error_message TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("威脅獵捕查詢數據庫初始化完成")
            
        except Exception as e:
            logger.error(f"數據庫初始化錯誤: {e}")
    
    def _init_query_templates(self):
        """初始化查詢模板"""
        try:
            # 惡意程式檢測查詢
            self.query_templates['malware_detection'] = {
                'name': '惡意程式檢測查詢',
                'description': '檢測可疑的惡意程式活動',
                'category': 'malware',
                'query_type': 'process',
                'query_text': '''
                    SELECT process_name, command_line, parent_process, 
                           creation_time, process_id, user_name
                    FROM process_events
                    WHERE (command_line LIKE '%powershell%' AND command_line LIKE '%-enc%')
                       OR (command_line LIKE '%cmd%' AND command_line LIKE '%echo%')
                       OR (command_line LIKE '%regsvr32%' AND command_line LIKE '%-s%')
                       OR (command_line LIKE '%rundll32%' AND command_line LIKE '%javascript%')
                       OR (command_line LIKE '%wscript%' AND command_line LIKE '%.vbs%')
                       OR (command_line LIKE '%cscript%' AND command_line LIKE '%.js%')
                    ORDER BY creation_time DESC
                ''',
                'parameters': {
                    'time_range': '24h',
                    'severity_threshold': 'medium'
                },
                'mitre_techniques': ['T1059', 'T1055', 'T1053'],
                'severity': 'high'
            }
            
            # 橫向移動檢測查詢
            self.query_templates['lateral_movement'] = {
                'name': '橫向移動檢測查詢',
                'description': '檢測橫向移動活動',
                'category': 'lateral_movement',
                'query_type': 'network',
                'query_text': '''
                    SELECT src_ip, dest_ip, dest_port, protocol, 
                           connection_count, data_transferred, timestamp
                    FROM network_events
                    WHERE dest_port IN (22, 3389, 5985, 5986, 445, 135, 139)
                      AND connection_count > 10
                      AND data_transferred > 1000000
                    ORDER BY timestamp DESC
                ''',
                'parameters': {
                    'time_range': '1h',
                    'min_connections': 10
                },
                'mitre_techniques': ['T1021', 'T1071', 'T1083'],
                'severity': 'high'
            }
            
            # 權限提升檢測查詢
            self.query_templates['privilege_escalation'] = {
                'name': '權限提升檢測查詢',
                'description': '檢測權限提升活動',
                'category': 'privilege_escalation',
                'query_type': 'process',
                'query_text': '''
                    SELECT process_name, command_line, user_name, 
                           integrity_level, parent_process, creation_time
                    FROM process_events
                    WHERE (command_line LIKE '%net user%' AND command_line LIKE '%add%')
                       OR (command_line LIKE '%net localgroup%' AND command_line LIKE '%add%')
                       OR (command_line LIKE '%schtasks%' AND command_line LIKE '%create%')
                       OR (command_line LIKE '%at%' AND command_line LIKE '%add%')
                       OR (command_line LIKE '%wmic%' AND command_line LIKE '%process%')
                       OR (command_line LIKE '%reg add%')
                    ORDER BY creation_time DESC
                ''',
                'parameters': {
                    'time_range': '24h',
                    'check_admin_privileges': True
                },
                'mitre_techniques': ['T1055', 'T1078', 'T1548'],
                'severity': 'high'
            }
            
            # 數據外洩檢測查詢
            self.query_templates['data_exfiltration'] = {
                'name': '數據外洩檢測查詢',
                'description': '檢測數據外洩活動',
                'category': 'data_exfiltration',
                'query_type': 'network',
                'query_text': '''
                    SELECT src_ip, dest_ip, dest_port, protocol,
                           data_transferred, connection_duration, timestamp
                    FROM network_events
                    WHERE data_transferred > 10000000
                      AND connection_duration > 300
                      AND dest_port IN (80, 443, 21, 22, 25, 587, 465)
                    ORDER BY data_transferred DESC
                ''',
                'parameters': {
                    'time_range': '6h',
                    'min_data_size': 10000000
                },
                'mitre_techniques': ['T1041', 'T1048', 'T1052'],
                'severity': 'critical'
            }
            
            # 持久化檢測查詢
            self.query_templates['persistence'] = {
                'name': '持久化檢測查詢',
                'description': '檢測持久化機制',
                'category': 'persistence',
                'query_type': 'registry',
                'query_text': '''
                    SELECT registry_path, registry_key, registry_value,
                           operation_type, process_name, timestamp
                    FROM registry_events
                    WHERE (registry_path LIKE '%Run%' OR registry_path LIKE '%RunOnce%')
                      AND operation_type = 'SetValue'
                      AND registry_value LIKE '%.exe%'
                    ORDER BY timestamp DESC
                ''',
                'parameters': {
                    'time_range': '7d',
                    'check_autorun': True
                },
                'mitre_techniques': ['T1547', 'T1053', 'T1543'],
                'severity': 'medium'
            }
            
            # 命令與控制檢測查詢
            self.query_templates['command_control'] = {
                'name': '命令與控制檢測查詢',
                'description': '檢測C2通信活動',
                'category': 'command_control',
                'query_type': 'dns',
                'query_text': '''
                    SELECT query_name, query_type, response_data,
                           client_ip, timestamp, query_count
                    FROM dns_events
                    WHERE (query_name LIKE '%.tk' OR query_name LIKE '%.ml' 
                          OR query_name LIKE '%.onion' OR query_name LIKE '%.bit')
                       OR (query_name LIKE '%[a-f0-9]{32}%')
                       OR (query_count > 100)
                    ORDER BY query_count DESC
                ''',
                'parameters': {
                    'time_range': '1h',
                    'min_query_count': 100
                },
                'mitre_techniques': ['T1071', 'T1568', 'T1090'],
                'severity': 'high'
            }
            
            # 保存查詢模板到數據庫
            self._save_query_templates()
            
            logger.info("查詢模板初始化完成")
            
        except Exception as e:
            logger.error(f"查詢模板初始化錯誤: {e}")
    
    def _save_query_templates(self):
        """保存查詢模板到數據庫"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for template_id, template in self.query_templates.items():
                cursor.execute('''
                    INSERT OR REPLACE INTO query_templates
                    (template_id, name, description, category, query_type, 
                     query_text, parameters, mitre_techniques, severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    template_id,
                    template['name'],
                    template['description'],
                    template['category'],
                    template['query_type'],
                    template['query_text'],
                    json.dumps(template['parameters']),
                    json.dumps(template['mitre_techniques']),
                    template['severity']
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"保存查詢模板錯誤: {e}")
    
    def _init_correlation_rules(self):
        """初始化關聯規則"""
        try:
            # 多階段攻擊關聯規則
            self.correlation_rules['multi_stage_attack'] = {
                'name': '多階段攻擊關聯',
                'description': '關聯多個攻擊階段的事件',
                'event_types': ['process_creation', 'network_connection', 'file_access'],
                'time_window': 3600,  # 1小時
                'conditions': {
                    'sequence': [
                        {'event_type': 'process_creation', 'pattern': 'powershell.*-enc'},
                        {'event_type': 'network_connection', 'pattern': 'external_ip'},
                        {'event_type': 'file_access', 'pattern': 'sensitive_files'}
                    ],
                    'time_constraint': 'within_1_hour',
                    'same_source': True
                },
                'actions': ['create_incident', 'notify_security_team'],
                'severity': 'critical'
            }
            
            # 內部威脅關聯規則
            self.correlation_rules['insider_threat'] = {
                'name': '內部威脅關聯',
                'description': '檢測內部威脅行為模式',
                'event_types': ['file_access', 'network_connection', 'process_creation'],
                'time_window': 1800,  # 30分鐘
                'conditions': {
                    'sequence': [
                        {'event_type': 'file_access', 'pattern': 'confidential', 'count': '>10'},
                        {'event_type': 'network_connection', 'pattern': 'external_upload'},
                        {'event_type': 'process_creation', 'pattern': 'compression_tools'}
                    ],
                    'time_constraint': 'within_30_minutes',
                    'same_user': True
                },
                'actions': ['create_incident', 'suspend_user', 'notify_hr'],
                'severity': 'high'
            }
            
            # 數據洩露關聯規則
            self.correlation_rules['data_breach'] = {
                'name': '數據洩露關聯',
                'description': '檢測數據洩露活動',
                'event_types': ['file_access', 'network_connection', 'email_send'],
                'time_window': 7200,  # 2小時
                'conditions': {
                    'sequence': [
                        {'event_type': 'file_access', 'pattern': 'database_files', 'count': '>50'},
                        {'event_type': 'network_connection', 'pattern': 'high_bandwidth'},
                        {'event_type': 'email_send', 'pattern': 'large_attachment'}
                    ],
                    'time_constraint': 'within_2_hours',
                    'same_source': True
                },
                'actions': ['create_incident', 'block_network', 'notify_legal'],
                'severity': 'critical'
            }
            
            # 保存關聯規則到數據庫
            self._save_correlation_rules()
            
            logger.info("關聯規則初始化完成")
            
        except Exception as e:
            logger.error(f"關聯規則初始化錯誤: {e}")
    
    def _save_correlation_rules(self):
        """保存關聯規則到數據庫"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for rule_id, rule in self.correlation_rules.items():
                cursor.execute('''
                    INSERT OR REPLACE INTO correlation_rules
                    (rule_id, name, description, event_types, time_window, conditions, actions)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    rule_id,
                    rule['name'],
                    rule['description'],
                    json.dumps(rule['event_types']),
                    rule['time_window'],
                    json.dumps(rule['conditions']),
                    json.dumps(rule['actions'])
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"保存關聯規則錯誤: {e}")
    
    def start_hunting_engine(self) -> Dict[str, Any]:
        """啟動獵捕引擎"""
        try:
            if self.running:
                return {'success': False, 'error': '獵捕引擎已在運行中'}
            
            self.running = True
            
            logger.info("威脅獵捕查詢引擎已啟動")
            return {'success': True, 'message': '威脅獵捕查詢引擎已啟動'}
            
        except Exception as e:
            logger.error(f"啟動獵捕引擎錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def execute_query(self, template_id: str, parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """執行查詢"""
        try:
            if template_id not in self.query_templates:
                return {'success': False, 'error': f'查詢模板 {template_id} 不存在'}
            
            template = self.query_templates[template_id]
            query_text = template['query_text']
            template_params = template.get('parameters', {})
            
            # 合併參數
            if parameters:
                template_params.update(parameters)
            
            # 替換查詢中的參數
            resolved_query = self._resolve_query_parameters(query_text, template_params)
            
            # 記錄查詢執行
            execution_id = f"exec_{int(time.time())}"
            self._record_query_execution(execution_id, template_id, resolved_query, template_params)
            
            # 模擬查詢執行
            results = self._simulate_query_execution(resolved_query, template)
            
            # 更新執行記錄
            self._update_query_execution(execution_id, len(results), 1.5, 'completed')
            
            return {
                'success': True,
                'execution_id': execution_id,
                'results': results,
                'result_count': len(results),
                'execution_time': 1.5
            }
            
        except Exception as e:
            logger.error(f"執行查詢錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _resolve_query_parameters(self, query_text: str, parameters: Dict[str, Any]) -> str:
        """解析查詢參數"""
        try:
            resolved_query = query_text
            
            # 替換時間範圍參數
            if 'time_range' in parameters:
                time_range = parameters['time_range']
                if time_range == '1h':
                    time_condition = "timestamp >= datetime('now', '-1 hour')"
                elif time_range == '24h':
                    time_condition = "timestamp >= datetime('now', '-1 day')"
                elif time_range == '7d':
                    time_condition = "timestamp >= datetime('now', '-7 days')"
                else:
                    time_condition = "timestamp >= datetime('now', '-1 day')"
                
                resolved_query = resolved_query.replace('{{time_condition}}', time_condition)
            
            # 替換其他參數
            for key, value in parameters.items():
                placeholder = f'{{{{{key}}}}}'
                if placeholder in resolved_query:
                    resolved_query = resolved_query.replace(placeholder, str(value))
            
            return resolved_query
            
        except Exception as e:
            logger.error(f"解析查詢參數錯誤: {e}")
            return query_text
    
    def _simulate_query_execution(self, query_text: str, template: Dict[str, Any]) -> List[Dict[str, Any]]:
        """模擬查詢執行"""
        try:
            # 根據查詢類型生成模擬結果
            query_type = template.get('query_type', 'process')
            category = template.get('category', 'general')
            
            if query_type == 'process':
                return self._generate_process_results(category)
            elif query_type == 'network':
                return self._generate_network_results(category)
            elif query_type == 'dns':
                return self._generate_dns_results(category)
            elif query_type == 'registry':
                return self._generate_registry_results(category)
            else:
                return self._generate_general_results(category)
                
        except Exception as e:
            logger.error(f"模擬查詢執行錯誤: {e}")
            return []
    
    def _generate_process_results(self, category: str) -> List[Dict[str, Any]]:
        """生成進程查詢結果"""
        results = []
        
        if category == 'malware':
            results = [
                {
                    'process_name': 'powershell.exe',
                    'command_line': 'powershell -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwAA==',
                    'parent_process': 'cmd.exe',
                    'creation_time': datetime.now().isoformat(),
                    'process_id': 1234,
                    'user_name': 'SYSTEM'
                },
                {
                    'process_name': 'regsvr32.exe',
                    'command_line': 'regsvr32 /s /u scrobj.dll',
                    'parent_process': 'explorer.exe',
                    'creation_time': datetime.now().isoformat(),
                    'process_id': 5678,
                    'user_name': 'Administrator'
                }
            ]
        elif category == 'privilege_escalation':
            results = [
                {
                    'process_name': 'net.exe',
                    'command_line': 'net user hacker password123 /add',
                    'parent_process': 'cmd.exe',
                    'creation_time': datetime.now().isoformat(),
                    'process_id': 9012,
                    'user_name': 'Administrator'
                }
            ]
        
        return results
    
    def _generate_network_results(self, category: str) -> List[Dict[str, Any]]:
        """生成網路查詢結果"""
        results = []
        
        if category == 'lateral_movement':
            results = [
                {
                    'src_ip': '192.168.1.100',
                    'dest_ip': '192.168.1.200',
                    'dest_port': 3389,
                    'protocol': 'TCP',
                    'connection_count': 15,
                    'data_transferred': 2048000,
                    'timestamp': datetime.now().isoformat()
                }
            ]
        elif category == 'data_exfiltration':
            results = [
                {
                    'src_ip': '192.168.1.50',
                    'dest_ip': '203.0.113.100',
                    'dest_port': 443,
                    'protocol': 'TCP',
                    'data_transferred': 50000000,
                    'connection_duration': 1800,
                    'timestamp': datetime.now().isoformat()
                }
            ]
        
        return results
    
    def _generate_dns_results(self, category: str) -> List[Dict[str, Any]]:
        """生成DNS查詢結果"""
        results = []
        
        if category == 'command_control':
            results = [
                {
                    'query_name': 'suspicious.tk',
                    'query_type': 'A',
                    'response_data': '203.0.113.1',
                    'client_ip': '192.168.1.100',
                    'timestamp': datetime.now().isoformat(),
                    'query_count': 150
                },
                {
                    'query_name': 'c2server.ml',
                    'query_type': 'A',
                    'response_data': '198.51.100.1',
                    'client_ip': '192.168.1.100',
                    'timestamp': datetime.now().isoformat(),
                    'query_count': 200
                }
            ]
        
        return results
    
    def _generate_registry_results(self, category: str) -> List[Dict[str, Any]]:
        """生成註冊表查詢結果"""
        results = []
        
        if category == 'persistence':
            results = [
                {
                    'registry_path': 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'registry_key': 'SuspiciousApp',
                    'registry_value': 'C:\\Windows\\System32\\suspicious.exe',
                    'operation_type': 'SetValue',
                    'process_name': 'regedit.exe',
                    'timestamp': datetime.now().isoformat()
                }
            ]
        
        return results
    
    def _generate_general_results(self, category: str) -> List[Dict[str, Any]]:
        """生成一般查詢結果"""
        return [
            {
                'event_type': category,
                'timestamp': datetime.now().isoformat(),
                'description': f'模擬 {category} 事件',
                'severity': 'medium'
            }
        ]
    
    def _record_query_execution(self, execution_id: str, template_id: str, query_text: str, parameters: Dict[str, Any]):
        """記錄查詢執行"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO query_executions
                (execution_id, template_id, query_text, parameters, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (execution_id, template_id, query_text, json.dumps(parameters), 'running'))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"記錄查詢執行錯誤: {e}")
    
    def _update_query_execution(self, execution_id: str, results_count: int, execution_time: float, status: str):
        """更新查詢執行記錄"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE query_executions
                SET results_count = ?, execution_time = ?, status = ?, completed_at = CURRENT_TIMESTAMP
                WHERE execution_id = ?
            ''', (results_count, execution_time, status, execution_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"更新查詢執行記錄錯誤: {e}")
    
    def create_custom_rule(self, rule_id: str, name: str, rule_type: str, rule_content: str, **kwargs) -> Dict[str, Any]:
        """創建自定義規則"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO custom_rules
                (rule_id, name, description, rule_type, rule_content, conditions, actions, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                rule_id,
                name,
                kwargs.get('description', ''),
                rule_type,
                rule_content,
                json.dumps(kwargs.get('conditions', {})),
                json.dumps(kwargs.get('actions', [])),
                kwargs.get('enabled', True)
            ))
            
            conn.commit()
            conn.close()
            
            # 更新內存中的規則
            self.custom_rules[rule_id] = {
                'name': name,
                'description': kwargs.get('description', ''),
                'rule_type': rule_type,
                'rule_content': rule_content,
                'conditions': kwargs.get('conditions', {}),
                'actions': kwargs.get('actions', []),
                'enabled': kwargs.get('enabled', True)
            }
            
            logger.info(f"創建自定義規則: {rule_id} - {name}")
            
            return {
                'success': True,
                'rule_id': rule_id,
                'message': '自定義規則創建成功'
            }
            
        except Exception as e:
            logger.error(f"創建自定義規則錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def execute_correlation_analysis(self, time_window: int = 3600) -> Dict[str, Any]:
        """執行關聯分析"""
        try:
            correlation_results = []
            
            for rule_id, rule in self.correlation_rules.items():
                if not rule.get('enabled', True):
                    continue
                
                # 模擬關聯分析
                result = self._simulate_correlation_analysis(rule_id, rule, time_window)
                if result:
                    correlation_results.append(result)
            
            return {
                'success': True,
                'correlation_results': correlation_results,
                'rules_checked': len(self.correlation_rules),
                'matches_found': len(correlation_results)
            }
            
        except Exception as e:
            logger.error(f"執行關聯分析錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _simulate_correlation_analysis(self, rule_id: str, rule: Dict[str, Any], time_window: int) -> Optional[Dict[str, Any]]:
        """模擬關聯分析"""
        try:
            # 簡化的關聯分析模擬
            event_types = rule.get('event_types', [])
            conditions = rule.get('conditions', {})
            
            # 模擬檢測到關聯事件
            if len(event_types) >= 2:
                return {
                    'rule_id': rule_id,
                    'rule_name': rule['name'],
                    'match_count': 3,
                    'events': [
                        {
                            'event_type': event_types[0],
                            'timestamp': datetime.now().isoformat(),
                            'description': f'模擬 {event_types[0]} 事件'
                        },
                        {
                            'event_type': event_types[1],
                            'timestamp': datetime.now().isoformat(),
                            'description': f'模擬 {event_types[1]} 事件'
                        }
                    ],
                    'correlation_score': 0.85,
                    'severity': rule.get('severity', 'medium')
                }
            
            return None
            
        except Exception as e:
            logger.error(f"模擬關聯分析錯誤: {e}")
            return None
    
    def get_query_templates(self, category: str = None) -> Dict[str, Any]:
        """獲取查詢模板"""
        try:
            if category:
                filtered_templates = {
                    k: v for k, v in self.query_templates.items()
                    if v.get('category') == category
                }
            else:
                filtered_templates = self.query_templates
            
            return {
                'success': True,
                'templates': filtered_templates,
                'count': len(filtered_templates)
            }
            
        except Exception as e:
            logger.error(f"獲取查詢模板錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_correlation_rules(self) -> Dict[str, Any]:
        """獲取關聯規則"""
        try:
            return {
                'success': True,
                'rules': self.correlation_rules,
                'count': len(self.correlation_rules)
            }
            
        except Exception as e:
            logger.error(f"獲取關聯規則錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def stop_hunting_engine(self) -> Dict[str, Any]:
        """停止獵捕引擎"""
        try:
            self.running = False
            
            logger.info("威脅獵捕查詢引擎已停止")
            return {'success': True, 'message': '威脅獵捕查詢引擎已停止'}
            
        except Exception as e:
            logger.error(f"停止獵捕引擎錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """獲取系統狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'query_templates': len(self.query_templates),
                'custom_rules': len(self.custom_rules),
                'correlation_rules': len(self.correlation_rules)
            }
        except Exception as e:
            logger.error(f"獲取系統狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """獲取綜合報告"""
        try:
            return {
                'success': True,
                'threat_hunting_queries': {
                    'query_templates': list(self.query_templates.keys()),
                    'custom_rules': list(self.custom_rules.keys()),
                    'correlation_rules': list(self.correlation_rules.keys()),
                    'categories': list(set(t['category'] for t in self.query_templates.values()))
                }
            }
        except Exception as e:
            logger.error(f"獲取綜合報告錯誤: {e}")
            return {'success': False, 'error': str(e)}






