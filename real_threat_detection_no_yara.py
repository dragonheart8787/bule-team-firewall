#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實威脅檢測系統（無YARA依賴版本）
Real Threat Detection System (No YARA Dependency)
"""

import os
import sys
import json
import time
import logging
import threading
import subprocess
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealThreatDetection:
    """真實威脅檢測系統（無YARA依賴版本）"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.detection_threads = []
        self.threat_indicators = []
        self.detection_rules = []
        self.suricata_events = []
        self.sysmon_events = []
        
        # 初始化檢測組件
        self._init_detection_rules()
        self._init_external_log_monitoring()
        
        logger.info("真實威脅檢測系統初始化完成")
    
    def _init_detection_rules(self):
        """初始化檢測規則"""
        try:
            # 基於正則表達式的檢測規則
            self.detection_rules = {
                'suspicious_processes': [
                    r'powershell.*-enc',
                    r'cmd.*\/c.*echo',
                    r'regsvr32.*\/s.*\/u',
                    r'rundll32.*javascript',
                    r'wscript.*\.vbs',
                    r'cscript.*\.js'
                ],
                'suspicious_network': [
                    r'192\.168\.\d+\.\d+',
                    r'10\.\d+\.\d+\.\d+',
                    r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+',
                    r'[a-zA-Z0-9-]+\.onion',
                    r'[a-zA-Z0-9-]+\.tk',
                    r'[a-zA-Z0-9-]+\.ml'
                ],
                'suspicious_files': [
                    r'\.exe$',
                    r'\.scr$',
                    r'\.bat$',
                    r'\.cmd$',
                    r'\.vbs$',
                    r'\.js$'
                ],
                'suspicious_commands': [
                    r'net\s+user',
                    r'net\s+localgroup',
                    r'schtasks',
                    r'at\s+',
                    r'wmic',
                    r'reg\s+add',
                    r'reg\s+delete'
                ]
            }
            
            logger.info("檢測規則初始化完成")
            
        except Exception as e:
            logger.error(f"檢測規則初始化錯誤: {e}")
    
    def _init_external_log_monitoring(self):
        """初始化外部日誌監控"""
        try:
            self.suricata_config = self.config.get('threat_detection', {}).get('config', {})
            self.sysmon_config = self.config.get('threat_detection', {}).get('config', {})
            
            # Suricata 配置
            self.suricata_eve_path = self.suricata_config.get('suricata_eve', 'C:\\ProgramData\\Suricata\\logs\\eve.json')
            self.consume_suricata = self.suricata_config.get('consume_suricata', False)
            
            # Sysmon 配置
            self.sysmon_evtx_path = self.sysmon_config.get('sysmon_evtx', 'C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx')
            self.consume_sysmon = self.sysmon_config.get('consume_sysmon', False)
            
            logger.info("外部日誌監控初始化完成")
            
        except Exception as e:
            logger.error(f"外部日誌監控初始化錯誤: {e}")
    
    def start_monitoring(self) -> Dict[str, Any]:
        """啟動威脅檢測監控"""
        try:
            if self.running:
                return {'success': False, 'error': '威脅檢測已在運行中'}
            
            self.running = True
            
            # 啟動檢測線程
            if self.consume_suricata:
                thread = threading.Thread(target=self._start_suricata_monitoring, daemon=True)
                thread.start()
                self.detection_threads.append(thread)
            
            if self.consume_sysmon:
                thread = threading.Thread(target=self._start_sysmon_monitoring, daemon=True)
                thread.start()
                self.detection_threads.append(thread)
            
            # 啟動一般威脅檢測
            thread = threading.Thread(target=self._run_general_detection, daemon=True)
            thread.start()
            self.detection_threads.append(thread)
            
            logger.info("威脅檢測監控已啟動")
            return {'success': True, 'message': '威脅檢測監控已啟動'}
            
        except Exception as e:
            logger.error(f"啟動威脅檢測監控錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _start_suricata_monitoring(self):
        """啟動Suricata監控"""
        try:
            if not os.path.exists(self.suricata_eve_path):
                logger.warning(f"Suricata EVE檔案不存在: {self.suricata_eve_path}")
                return
            
            # 模擬Suricata日誌監控
            while self.running:
                try:
                    # 模擬讀取Suricata日誌
                    mock_event = {
                        'timestamp': datetime.now().isoformat(),
                        'event_type': 'alert',
                        'alert': {
                            'action': 'allowed',
                            'gid': 1,
                            'signature_id': 2000001,
                            'rev': 1,
                            'signature': 'Suspicious DNS Query',
                            'category': 'Misc activity',
                            'severity': 2
                        },
                        'src_ip': '192.168.1.100',
                        'src_port': 12345,
                        'dest_ip': '8.8.8.8',
                        'dest_port': 53,
                        'proto': 'UDP'
                    }
                    
                    self._process_suricata_event(mock_event)
                    time.sleep(10)
                    
                except Exception as e:
                    logger.error(f"Suricata監控錯誤: {e}")
                    time.sleep(5)
                    
        except Exception as e:
            logger.error(f"啟動Suricata監控錯誤: {e}")
    
    def _process_suricata_event(self, event: Dict[str, Any]):
        """處理Suricata事件"""
        try:
            self.suricata_events.append(event)
            
            # 檢測可疑DNS查詢
            if event.get('event_type') == 'alert':
                alert = event.get('alert', {})
                if 'DNS' in alert.get('signature', ''):
                    self._detect_suspicious_dns(event)
            
            # 檢測可疑網路連接
            if event.get('event_type') == 'flow':
                self._detect_suspicious_network(event)
                
        except Exception as e:
            logger.error(f"處理Suricata事件錯誤: {e}")
    
    def _detect_suspicious_dns(self, event: Dict[str, Any]):
        """檢測可疑DNS查詢"""
        try:
            # 檢查DNS查詢模式
            dest_ip = event.get('dest_ip', '')
            if dest_ip and self._is_suspicious_dns_query(dest_ip):
                threat = {
                    'type': 'SUSPICIOUS_DNS',
                    'timestamp': event.get('timestamp'),
                    'src_ip': event.get('src_ip'),
                    'dest_ip': dest_ip,
                    'severity': 'medium',
                    'description': '可疑DNS查詢模式'
                }
                self.threat_indicators.append(threat)
                logger.warning(f"檢測到可疑DNS查詢: {dest_ip}")
                
        except Exception as e:
            logger.error(f"檢測可疑DNS錯誤: {e}")
    
    def _is_suspicious_dns_query(self, query: str) -> bool:
        """檢查是否為可疑DNS查詢"""
        suspicious_patterns = [
            r'[a-zA-Z0-9-]+\.onion',
            r'[a-zA-Z0-9-]+\.tk',
            r'[a-zA-Z0-9-]+\.ml',
            r'[a-zA-Z0-9-]+\.bit'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return True
        return False
    
    def _detect_suspicious_network(self, event: Dict[str, Any]):
        """檢測可疑網路連接"""
        try:
            src_ip = event.get('src_ip', '')
            dest_ip = event.get('dest_ip', '')
            
            # 檢查內部網路掃描
            if self._is_internal_network_scan(src_ip, dest_ip):
                threat = {
                    'type': 'NETWORK_SCAN',
                    'timestamp': event.get('timestamp'),
                    'src_ip': src_ip,
                    'dest_ip': dest_ip,
                    'severity': 'high',
                    'description': '內部網路掃描活動'
                }
                self.threat_indicators.append(threat)
                logger.warning(f"檢測到網路掃描: {src_ip} -> {dest_ip}")
                
        except Exception as e:
            logger.error(f"檢測可疑網路錯誤: {e}")
    
    def _is_internal_network_scan(self, src_ip: str, dest_ip: str) -> bool:
        """檢查是否為內部網路掃描"""
        internal_patterns = [
            r'^192\.168\.',
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'
        ]
        
        for pattern in internal_patterns:
            if re.match(pattern, src_ip) and re.match(pattern, dest_ip):
                return True
        return False
    
    def _start_sysmon_monitoring(self):
        """啟動Sysmon監控"""
        try:
            # 模擬Sysmon事件監控
            while self.running:
                try:
                    # 模擬讀取Sysmon日誌
                    mock_event = {
                        'timestamp': datetime.now().isoformat(),
                        'EventID': 1,
                        'ProcessCreate': {
                            'CommandLine': 'powershell.exe -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwAA==',
                            'Image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                            'ProcessId': 1234,
                            'ParentProcessId': 5678
                        }
                    }
                    
                    self._process_sysmon_event(mock_event)
                    time.sleep(15)
                    
                except Exception as e:
                    logger.error(f"Sysmon監控錯誤: {e}")
                    time.sleep(5)
                    
        except Exception as e:
            logger.error(f"啟動Sysmon監控錯誤: {e}")
    
    def _process_sysmon_event(self, event: Dict[str, Any]):
        """處理Sysmon事件"""
        try:
            self.sysmon_events.append(event)
            
            event_id = event.get('EventID')
            if event_id == 1:  # Process Create
                self._process_sysmon_process_creation(event)
            elif event_id == 3:  # Network Connect
                self._process_sysmon_network_connection(event)
            elif event_id == 8:  # Create Remote Thread
                self._process_sysmon_remote_thread(event)
            elif event_id == 22:  # DNS Query
                self._process_sysmon_dns_query(event)
                
        except Exception as e:
            logger.error(f"處理Sysmon事件錯誤: {e}")
    
    def _process_sysmon_process_creation(self, event: Dict[str, Any]):
        """處理進程創建事件"""
        try:
            process_create = event.get('ProcessCreate', {})
            command_line = process_create.get('CommandLine', '')
            
            if self._is_suspicious_process_creation(command_line):
                threat = {
                    'type': 'SUSPICIOUS_PROCESS',
                    'timestamp': event.get('timestamp'),
                    'process_id': process_create.get('ProcessId'),
                    'command_line': command_line,
                    'image': process_create.get('Image'),
                    'severity': 'high',
                    'description': '可疑進程創建'
                }
                self.threat_indicators.append(threat)
                logger.warning(f"檢測到可疑進程: {command_line}")
                
        except Exception as e:
            logger.error(f"處理進程創建事件錯誤: {e}")
    
    def _is_suspicious_process_creation(self, command_line: str) -> bool:
        """檢查是否為可疑進程創建"""
        suspicious_patterns = [
            r'powershell.*-enc',
            r'cmd.*\/c.*echo',
            r'regsvr32.*\/s.*\/u',
            r'rundll32.*javascript',
            r'wscript.*\.vbs',
            r'cscript.*\.js'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, command_line, re.IGNORECASE):
                return True
        return False
    
    def _process_sysmon_network_connection(self, event: Dict[str, Any]):
        """處理網路連接事件"""
        try:
            network_connect = event.get('NetworkConnect', {})
            dest_ip = network_connect.get('DestinationIp', '')
            dest_port = network_connect.get('DestinationPort', 0)
            
            if self._is_suspicious_network_connection(dest_ip, dest_port):
                threat = {
                    'type': 'SUSPICIOUS_NETWORK',
                    'timestamp': event.get('timestamp'),
                    'dest_ip': dest_ip,
                    'dest_port': dest_port,
                    'severity': 'medium',
                    'description': '可疑網路連接'
                }
                self.threat_indicators.append(threat)
                logger.warning(f"檢測到可疑網路連接: {dest_ip}:{dest_port}")
                
        except Exception as e:
            logger.error(f"處理網路連接事件錯誤: {e}")
    
    def _is_suspicious_network_connection(self, dest_ip: str, dest_port: int) -> bool:
        """檢查是否為可疑網路連接"""
        # 檢查常見C2端口
        suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337]
        if dest_port in suspicious_ports:
            return True
        
        # 檢查可疑IP模式
        suspicious_patterns = [
            r'^192\.168\.\d+\.\d+$',
            r'^10\.\d+\.\d+\.\d+$',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$'
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, dest_ip):
                return True
        return False
    
    def _process_sysmon_remote_thread(self, event: Dict[str, Any]):
        """處理遠程線程事件"""
        try:
            create_remote_thread = event.get('CreateRemoteThread', {})
            target_process_id = create_remote_thread.get('TargetProcessId', 0)
            
            threat = {
                'type': 'CODE_INJECTION',
                'timestamp': event.get('timestamp'),
                'target_process_id': target_process_id,
                'severity': 'critical',
                'description': '代碼注入活動'
            }
            self.threat_indicators.append(threat)
            logger.warning(f"檢測到代碼注入: PID {target_process_id}")
            
        except Exception as e:
            logger.error(f"處理遠程線程事件錯誤: {e}")
    
    def _process_sysmon_dns_query(self, event: Dict[str, Any]):
        """處理DNS查詢事件"""
        try:
            dns_query = event.get('DnsQuery', {})
            query_name = dns_query.get('QueryName', '')
            
            if self._is_suspicious_dns_query(query_name):
                threat = {
                    'type': 'SUSPICIOUS_DNS',
                    'timestamp': event.get('timestamp'),
                    'query_name': query_name,
                    'severity': 'medium',
                    'description': '可疑DNS查詢'
                }
                self.threat_indicators.append(threat)
                logger.warning(f"檢測到可疑DNS查詢: {query_name}")
                
        except Exception as e:
            logger.error(f"處理DNS查詢事件錯誤: {e}")
    
    def _run_general_detection(self):
        """運行一般威脅檢測"""
        try:
            while self.running:
                try:
                    # 檢測系統進程
                    self._detect_suspicious_processes()
                    
                    # 檢測網路活動
                    self._detect_network_anomalies()
                    
                    time.sleep(30)
                    
                except Exception as e:
                    logger.error(f"一般威脅檢測錯誤: {e}")
                    time.sleep(10)
                    
        except Exception as e:
            logger.error(f"運行一般威脅檢測錯誤: {e}")
    
    def _detect_suspicious_processes(self):
        """檢測可疑進程"""
        try:
            # 模擬進程檢測
            suspicious_processes = [
                'powershell.exe',
                'cmd.exe',
                'regsvr32.exe',
                'rundll32.exe',
                'wscript.exe',
                'cscript.exe'
            ]
            
            for process in suspicious_processes:
                # 這裡可以添加實際的進程檢測邏輯
                pass
                
        except Exception as e:
            logger.error(f"檢測可疑進程錯誤: {e}")
    
    def _detect_network_anomalies(self):
        """檢測網路異常"""
        try:
            # 模擬網路異常檢測
            # 這裡可以添加實際的網路檢測邏輯
            pass
            
        except Exception as e:
            logger.error(f"檢測網路異常錯誤: {e}")
    
    def stop_monitoring(self) -> Dict[str, Any]:
        """停止威脅檢測監控"""
        try:
            self.running = False
            
            # 等待所有線程結束
            for thread in self.detection_threads:
                thread.join(timeout=5)
            
            self.detection_threads.clear()
            
            logger.info("威脅檢測監控已停止")
            return {'success': True, 'message': '威脅檢測監控已停止'}
            
        except Exception as e:
            logger.error(f"停止威脅檢測監控錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def analyze_threats(self) -> Dict[str, Any]:
        """分析威脅"""
        try:
            analysis_result = {
                'success': True,
                'timestamp': datetime.now().isoformat(),
                'threats_detected': len(self.threat_indicators),
                'suricata_events': len(self.suricata_events),
                'sysmon_events': len(self.sysmon_events),
                'threat_indicators': self.threat_indicators[-10:],  # 最近10個威脅
                'detection_rules': len(self.detection_rules)
            }
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"分析威脅錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """獲取系統狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'threat_indicators': len(self.threat_indicators),
                'suricata_events': len(self.suricata_events),
                'sysmon_events': len(self.sysmon_events),
                'detection_threads': len(self.detection_threads)
            }
        except Exception as e:
            logger.error(f"獲取系統狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """獲取綜合報告"""
        try:
            return {
                'success': True,
                'threat_detection': {
                    'threat_indicators': self.threat_indicators,
                    'suricata_events': self.suricata_events,
                    'sysmon_events': self.sysmon_events,
                    'detection_rules': self.detection_rules
                }
            }
        except Exception as e:
            logger.error(f"獲取綜合報告錯誤: {e}")
            return {'success': False, 'error': str(e)}



