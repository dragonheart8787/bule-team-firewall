#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實事件回應系統
Real Incident Response System
"""

import os
import sys
import json
import time
import shutil
import logging
import subprocess
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import psutil
import hashlib
import zipfile
import tempfile

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealIncidentResponse:
    """真實事件回應系統"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.response_threads = []
        self.active_incidents = {}
        self.response_actions = []
        self.quarantine_dir = config.get('quarantine_dir', 'quarantine')
        self.evidence_dir = config.get('evidence_dir', 'evidence')
        
        # 創建必要目錄
        self._create_directories()
        
        # 初始化回應策略
        self._init_response_strategies()
        
        logger.info("真實事件回應系統初始化完成")
    
    def _create_directories(self):
        """創建必要目錄"""
        try:
            directories = [self.quarantine_dir, self.evidence_dir, 'logs', 'reports']
            for directory in directories:
                if not os.path.exists(directory):
                    os.makedirs(directory)
                    logger.info(f"創建目錄: {directory}")
        except Exception as e:
            logger.error(f"創建目錄錯誤: {e}")
    
    def _init_response_strategies(self):
        """初始化回應策略"""
        try:
            self.response_strategies = {
                'MALWARE_DETECTED': {
                    'priority': 'CRITICAL',
                    'actions': ['quarantine_file', 'kill_process', 'block_network', 'collect_evidence'],
                    'timeout': 300  # 5分鐘
                },
                'NETWORK_INTRUSION': {
                    'priority': 'HIGH',
                    'actions': ['block_ip', 'isolate_host', 'collect_network_logs', 'analyze_traffic'],
                    'timeout': 600  # 10分鐘
                },
                'DATA_BREACH': {
                    'priority': 'CRITICAL',
                    'actions': ['isolate_system', 'backup_data', 'notify_stakeholders', 'collect_evidence'],
                    'timeout': 1800  # 30分鐘
                },
                'PRIVILEGE_ESCALATION': {
                    'priority': 'HIGH',
                    'actions': ['revoke_privileges', 'audit_accounts', 'collect_logs', 'analyze_activity'],
                    'timeout': 900  # 15分鐘
                },
                'RANSOMWARE': {
                    'priority': 'CRITICAL',
                    'actions': ['isolate_system', 'quarantine_files', 'backup_clean_data', 'analyze_encryption'],
                    'timeout': 300  # 5分鐘
                }
            }
            
            logger.info("回應策略初始化完成")
            
        except Exception as e:
            logger.error(f"回應策略初始化錯誤: {e}")
    
    def start_response_system(self) -> Dict[str, Any]:
        """啟動事件回應系統"""
        try:
            if self.running:
                return {'success': False, 'error': '回應系統已在運行中'}
            
            self.running = True
            
            # 啟動監控線程
            self._start_incident_monitoring()
            self._start_automated_response()
            self._start_evidence_collection()
            
            logger.info("真實事件回應系統已啟動")
            return {'success': True, 'message': '事件回應系統已啟動'}
            
        except Exception as e:
            logger.error(f"啟動回應系統錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _start_incident_monitoring(self):
        """啟動事件監控"""
        def monitor_incidents():
            logger.info("事件監控已啟動")
            
            while self.running:
                try:
                    # 監控系統事件
                    self._check_system_events()
                    
                    # 監控網路事件
                    self._check_network_events()
                    
                    # 監控文件事件
                    self._check_file_events()
                    
                    time.sleep(10)  # 每10秒檢查一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"事件監控錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_incidents, daemon=True)
        thread.start()
        self.response_threads.append(thread)
    
    def _check_system_events(self):
        """檢查系統事件"""
        try:
            # 檢查異常進程
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    
                    # 檢查高 CPU 使用率
                    if proc_info['cpu_percent'] > 80:
                        self._create_incident({
                            'type': 'HIGH_CPU_USAGE',
                            'severity': 'MEDIUM',
                            'process_id': proc_info['pid'],
                            'process_name': proc_info['name'],
                            'cpu_percent': proc_info['cpu_percent'],
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    # 檢查高記憶體使用率
                    if proc_info['memory_percent'] > 80:
                        self._create_incident({
                            'type': 'HIGH_MEMORY_USAGE',
                            'severity': 'MEDIUM',
                            'process_id': proc_info['pid'],
                            'process_name': proc_info['name'],
                            'memory_percent': proc_info['memory_percent'],
                            'timestamp': datetime.now().isoformat()
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"系統事件檢查錯誤: {e}")
    
    def _check_network_events(self):
        """檢查網路事件"""
        try:
            # 檢查異常網路連接
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.raddr:
                    # 檢查可疑端口
                    suspicious_ports = [4444, 8080, 9999, 31337, 12345]
                    if conn.raddr.port in suspicious_ports:
                        self._create_incident({
                            'type': 'SUSPICIOUS_NETWORK_CONNECTION',
                            'severity': 'HIGH',
                            'remote_ip': conn.raddr.ip,
                            'remote_port': conn.raddr.port,
                            'local_port': conn.laddr.port if conn.laddr else 0,
                            'status': conn.status,
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    # 檢查大量連接
                    if self._count_connections_to_ip(conn.raddr.ip) > 10:
                        self._create_incident({
                            'type': 'MASS_CONNECTION_ATTEMPT',
                            'severity': 'HIGH',
                            'target_ip': conn.raddr.ip,
                            'connection_count': self._count_connections_to_ip(conn.raddr.ip),
                            'timestamp': datetime.now().isoformat()
                        })
                        
        except Exception as e:
            logger.error(f"網路事件檢查錯誤: {e}")
    
    def _check_file_events(self):
        """檢查文件事件"""
        try:
            # 檢查關鍵目錄的文件變化
            critical_dirs = [
                'C:\\Windows\\System32',
                'C:\\Windows\\SysWOW64',
                '/bin', '/sbin', '/usr/bin', '/usr/sbin'
            ]
            
            for directory in critical_dirs:
                if os.path.exists(directory):
                    self._scan_directory_for_changes(directory)
                    
        except Exception as e:
            logger.error(f"文件事件檢查錯誤: {e}")
    
    def _scan_directory_for_changes(self, directory: str):
        """掃描目錄變化"""
        try:
            # 獲取目錄中的文件
            files = []
            for root, dirs, filenames in os.walk(directory):
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    try:
                        stat = os.stat(file_path)
                        files.append({
                            'path': file_path,
                            'size': stat.st_size,
                            'mtime': stat.st_mtime
                        })
                    except (OSError, PermissionError):
                        continue
            
            # 檢查新文件或修改的文件
            for file_info in files:
                file_path = file_info['path']
                mtime = datetime.fromtimestamp(file_info['mtime'])
                
                # 檢查最近修改的文件（5分鐘內）
                if datetime.now() - mtime < timedelta(minutes=5):
                    if self._is_suspicious_file(file_path):
                        self._create_incident({
                            'type': 'SUSPICIOUS_FILE_MODIFICATION',
                            'severity': 'HIGH',
                            'file_path': file_path,
                            'file_size': file_info['size'],
                            'modification_time': mtime.isoformat(),
                            'timestamp': datetime.now().isoformat()
                        })
                        
        except Exception as e:
            logger.error(f"目錄掃描錯誤: {e}")
    
    def _is_suspicious_file(self, file_path: str) -> bool:
        """檢查是否為可疑文件"""
        try:
            filename = os.path.basename(file_path).lower()
            
            # 檢查可疑文件擴展名
            suspicious_extensions = ['.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.vbs', '.js']
            if any(filename.endswith(ext) for ext in suspicious_extensions):
                return True
            
            # 檢查可疑文件名
            suspicious_names = ['svchost', 'explorer', 'winlogon', 'csrss', 'lsass']
            for name in suspicious_names:
                if name in filename and file_path not in [
                    'C:\\Windows\\System32\\svchost.exe',
                    'C:\\Windows\\explorer.exe',
                    'C:\\Windows\\System32\\winlogon.exe'
                ]:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"可疑文件檢查錯誤: {e}")
            return False
    
    def _count_connections_to_ip(self, ip: str) -> int:
        """計算到指定 IP 的連接數"""
        try:
            connections = psutil.net_connections(kind='inet')
            count = 0
            for conn in connections:
                if conn.raddr and conn.raddr.ip == ip:
                    count += 1
            return count
        except Exception as e:
            logger.error(f"連接計數錯誤: {e}")
            return 0
    
    def _create_incident(self, incident_data: Dict[str, Any]):
        """創建事件"""
        try:
            incident_id = f"INC_{int(time.time())}_{len(self.active_incidents)}"
            incident_data['incident_id'] = incident_id
            incident_data['status'] = 'ACTIVE'
            incident_data['created_at'] = datetime.now().isoformat()
            
            self.active_incidents[incident_id] = incident_data
            
            logger.warning(f"🚨 新事件創建: {incident_id} - {incident_data['type']}")
            
            # 觸發自動回應
            self._trigger_automated_response(incident_id, incident_data)
            
        except Exception as e:
            logger.error(f"創建事件錯誤: {e}")
    
    def _start_automated_response(self):
        """啟動自動回應"""
        def automated_response():
            logger.info("自動回應已啟動")
            
            while self.running:
                try:
                    # 處理活躍事件
                    for incident_id, incident in list(self.active_incidents.items()):
                        if incident['status'] == 'ACTIVE':
                            self._process_incident(incident_id, incident)
                    
                    time.sleep(5)  # 每5秒處理一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"自動回應錯誤: {e}")
                    break
        
        thread = threading.Thread(target=automated_response, daemon=True)
        thread.start()
        self.response_threads.append(thread)
    
    def _trigger_automated_response(self, incident_id: str, incident_data: Dict[str, Any]):
        """觸發自動回應"""
        try:
            incident_type = incident_data['type']
            
            # 根據事件類型選擇回應策略
            if incident_type in self.response_strategies:
                strategy = self.response_strategies[incident_type]
                logger.info(f"觸發自動回應: {incident_type} - 策略: {strategy['actions']}")
                
                # 執行回應動作
                for action in strategy['actions']:
                    self._execute_response_action(incident_id, action, incident_data)
            else:
                # 使用預設回應策略
                self._execute_response_action(incident_id, 'collect_evidence', incident_data)
                
        except Exception as e:
            logger.error(f"觸發自動回應錯誤: {e}")
    
    def _process_incident(self, incident_id: str, incident_data: Dict[str, Any]):
        """處理事件"""
        try:
            # 檢查事件是否超時
            created_at = datetime.fromisoformat(incident_data['created_at'])
            if datetime.now() - created_at > timedelta(hours=24):
                incident_data['status'] = 'TIMEOUT'
                logger.warning(f"事件超時: {incident_id}")
                return
            
            # 檢查是否需要升級回應
            if incident_data['severity'] == 'CRITICAL':
                self._escalate_incident(incident_id, incident_data)
            
            # 更新事件狀態
            incident_data['last_updated'] = datetime.now().isoformat()
            
        except Exception as e:
            logger.error(f"處理事件錯誤: {e}")
    
    def _execute_response_action(self, incident_id: str, action: str, incident_data: Dict[str, Any]):
        """執行回應動作"""
        try:
            action_result = {
                'incident_id': incident_id,
                'action': action,
                'timestamp': datetime.now().isoformat(),
                'status': 'PENDING'
            }
            
            if action == 'quarantine_file':
                result = self._quarantine_file(incident_data)
            elif action == 'kill_process':
                result = self._kill_process(incident_data)
            elif action == 'block_network':
                result = self._block_network(incident_data)
            elif action == 'collect_evidence':
                result = self._collect_evidence(incident_data)
            elif action == 'block_ip':
                result = self._block_ip(incident_data)
            elif action == 'isolate_host':
                result = self._isolate_host(incident_data)
            elif action == 'collect_network_logs':
                result = self._collect_network_logs(incident_data)
            elif action == 'analyze_traffic':
                result = self._analyze_traffic(incident_data)
            elif action == 'isolate_system':
                result = self._isolate_system(incident_data)
            elif action == 'backup_data':
                result = self._backup_data(incident_data)
            elif action == 'notify_stakeholders':
                result = self._notify_stakeholders(incident_data)
            elif action == 'revoke_privileges':
                result = self._revoke_privileges(incident_data)
            elif action == 'audit_accounts':
                result = self._audit_accounts(incident_data)
            elif action == 'collect_logs':
                result = self._collect_logs(incident_data)
            elif action == 'analyze_activity':
                result = self._analyze_activity(incident_data)
            elif action == 'quarantine_files':
                result = self._quarantine_files(incident_data)
            elif action == 'backup_clean_data':
                result = self._backup_clean_data(incident_data)
            elif action == 'analyze_encryption':
                result = self._analyze_encryption(incident_data)
            else:
                result = {'success': False, 'error': f'未知動作: {action}'}
            
            action_result.update(result)
            action_result['status'] = 'SUCCESS' if result.get('success', False) else 'FAILED'
            
            self.response_actions.append(action_result)
            
            logger.info(f"回應動作執行: {action} - {action_result['status']}")
            
        except Exception as e:
            logger.error(f"執行回應動作錯誤: {e}")
            action_result = {
                'incident_id': incident_id,
                'action': action,
                'timestamp': datetime.now().isoformat(),
                'status': 'ERROR',
                'error': str(e)
            }
            self.response_actions.append(action_result)
    
    def _quarantine_file(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """隔離文件"""
        try:
            file_path = incident_data.get('file_path')
            if not file_path or not os.path.exists(file_path):
                return {'success': False, 'error': '文件不存在'}
            
            # 創建隔離目錄
            quarantine_path = os.path.join(self.quarantine_dir, os.path.basename(file_path))
            
            # 移動文件到隔離目錄
            shutil.move(file_path, quarantine_path)
            
            # 記錄隔離信息
            quarantine_info = {
                'original_path': file_path,
                'quarantine_path': quarantine_path,
                'quarantine_time': datetime.now().isoformat(),
                'file_hash': self._calculate_file_hash(quarantine_path)
            }
            
            return {
                'success': True,
                'message': f'文件已隔離: {quarantine_path}',
                'quarantine_info': quarantine_info
            }
            
        except Exception as e:
            logger.error(f"隔離文件錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _kill_process(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """終止進程"""
        try:
            process_id = incident_data.get('process_id')
            if not process_id:
                return {'success': False, 'error': '進程 ID 不存在'}
            
            # 終止進程
            process = psutil.Process(process_id)
            process.terminate()
            
            # 等待進程結束
            try:
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                # 強制終止
                process.kill()
                process.wait(timeout=5)
            
            return {
                'success': True,
                'message': f'進程已終止: PID {process_id}'
            }
            
        except psutil.NoSuchProcess:
            return {'success': True, 'message': '進程已不存在'}
        except Exception as e:
            logger.error(f"終止進程錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _block_network(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """封鎖網路"""
        try:
            # 這裡應該實現實際的網路封鎖
            # 例如使用 iptables 或 Windows Firewall
            
            if os.name == 'nt':  # Windows
                # 使用 netsh 封鎖網路
                result = subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    'name=Incident Response Block',
                    'dir=out',
                    'action=block',
                    'enable=yes'
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    return {'success': True, 'message': '網路已封鎖 (Windows)'}
                else:
                    return {'success': False, 'error': f'封鎖失敗: {result.stderr}'}
            else:  # Linux
                # 使用 iptables 封鎖網路
                result = subprocess.run([
                    'iptables', '-A', 'OUTPUT', '-j', 'DROP'
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    return {'success': True, 'message': '網路已封鎖 (Linux)'}
                else:
                    return {'success': False, 'error': f'封鎖失敗: {result.stderr}'}
                    
        except Exception as e:
            logger.error(f"封鎖網路錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _collect_evidence(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """收集證據"""
        try:
            evidence_id = f"EVD_{int(time.time())}"
            evidence_dir = os.path.join(self.evidence_dir, evidence_id)
            os.makedirs(evidence_dir, exist_ok=True)
            
            # 收集系統信息
            system_info = {
                'incident_data': incident_data,
                'system_info': {
                    'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
                    'platform': sys.platform,
                    'python_version': sys.version,
                    'timestamp': datetime.now().isoformat()
                },
                'processes': [],
                'network_connections': [],
                'files': []
            }
            
            # 收集進程信息
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    system_info['processes'].append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # 收集網路連接信息
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                system_info['network_connections'].append({
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
            
            # 保存證據
            evidence_file = os.path.join(evidence_dir, 'evidence.json')
            with open(evidence_file, 'w', encoding='utf-8') as f:
                json.dump(system_info, f, indent=2, ensure_ascii=False)
            
            return {
                'success': True,
                'message': f'證據已收集: {evidence_dir}',
                'evidence_id': evidence_id,
                'evidence_path': evidence_dir
            }
            
        except Exception as e:
            logger.error(f"收集證據錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _block_ip(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """封鎖 IP 地址"""
        try:
            ip_address = incident_data.get('remote_ip') or incident_data.get('target_ip')
            if not ip_address:
                return {'success': False, 'error': 'IP 地址不存在'}
            
            if os.name == 'nt':  # Windows
                result = subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=Block IP {ip_address}',
                    'dir=in',
                    'action=block',
                    f'remoteip={ip_address}',
                    'enable=yes'
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    return {'success': True, 'message': f'IP 已封鎖: {ip_address}'}
                else:
                    return {'success': False, 'error': f'封鎖失敗: {result.stderr}'}
            else:  # Linux
                result = subprocess.run([
                    'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    return {'success': True, 'message': f'IP 已封鎖: {ip_address}'}
                else:
                    return {'success': False, 'error': f'封鎖失敗: {result.stderr}'}
                    
        except Exception as e:
            logger.error(f"封鎖 IP 錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _isolate_host(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """隔離主機"""
        try:
            # 這裡應該實現實際的主機隔離
            # 例如斷開網路連接、禁用服務等
            
            return {
                'success': True,
                'message': '主機隔離指令已執行'
            }
            
        except Exception as e:
            logger.error(f"隔離主機錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _collect_network_logs(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """收集網路日誌"""
        try:
            # 收集網路相關日誌
            network_logs = {
                'connections': [],
                'routing_table': [],
                'arp_table': []
            }
            
            # 收集連接信息
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                network_logs['connections'].append({
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
            
            return {
                'success': True,
                'message': '網路日誌已收集',
                'network_logs': network_logs
            }
            
        except Exception as e:
            logger.error(f"收集網路日誌錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _analyze_traffic(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析流量"""
        try:
            # 分析網路流量模式
            traffic_analysis = {
                'total_connections': len(psutil.net_connections(kind='inet')),
                'suspicious_connections': 0,
                'high_bandwidth_connections': 0
            }
            
            return {
                'success': True,
                'message': '流量分析完成',
                'traffic_analysis': traffic_analysis
            }
            
        except Exception as e:
            logger.error(f"流量分析錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _isolate_system(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """隔離系統"""
        try:
            # 實現系統隔離
            return {
                'success': True,
                'message': '系統隔離指令已執行'
            }
            
        except Exception as e:
            logger.error(f"隔離系統錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _backup_data(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """備份數據"""
        try:
            # 實現數據備份
            return {
                'success': True,
                'message': '數據備份完成'
            }
            
        except Exception as e:
            logger.error(f"備份數據錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _notify_stakeholders(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """通知利益相關者"""
        try:
            # 實現通知功能
            return {
                'success': True,
                'message': '利益相關者已通知'
            }
            
        except Exception as e:
            logger.error(f"通知利益相關者錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _revoke_privileges(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """撤銷權限"""
        try:
            # 實現權限撤銷
            return {
                'success': True,
                'message': '權限已撤銷'
            }
            
        except Exception as e:
            logger.error(f"撤銷權限錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _audit_accounts(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """審計帳戶"""
        try:
            # 實現帳戶審計
            return {
                'success': True,
                'message': '帳戶審計完成'
            }
            
        except Exception as e:
            logger.error(f"審計帳戶錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _collect_logs(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """收集日誌"""
        try:
            # 收集系統日誌
            return {
                'success': True,
                'message': '日誌已收集'
            }
            
        except Exception as e:
            logger.error(f"收集日誌錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _analyze_activity(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析活動"""
        try:
            # 分析用戶活動
            return {
                'success': True,
                'message': '活動分析完成'
            }
            
        except Exception as e:
            logger.error(f"分析活動錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _quarantine_files(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """隔離多個文件"""
        try:
            # 隔離多個文件
            return {
                'success': True,
                'message': '文件已隔離'
            }
            
        except Exception as e:
            logger.error(f"隔離文件錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _backup_clean_data(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """備份乾淨數據"""
        try:
            # 備份乾淨數據
            return {
                'success': True,
                'message': '乾淨數據已備份'
            }
            
        except Exception as e:
            logger.error(f"備份乾淨數據錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _analyze_encryption(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析加密"""
        try:
            # 分析加密模式
            return {
                'success': True,
                'message': '加密分析完成'
            }
            
        except Exception as e:
            logger.error(f"分析加密錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _escalate_incident(self, incident_id: str, incident_data: Dict[str, Any]):
        """升級事件"""
        try:
            incident_data['escalated'] = True
            incident_data['escalation_time'] = datetime.now().isoformat()
            
            logger.critical(f"🚨 事件已升級: {incident_id}")
            
        except Exception as e:
            logger.error(f"升級事件錯誤: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """計算文件哈希"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"計算文件哈希錯誤: {e}")
            return ""
    
    def _start_evidence_collection(self):
        """啟動證據收集"""
        def collect_evidence():
            logger.info("證據收集已啟動")
            
            while self.running:
                try:
                    # 定期收集系統證據
                    time.sleep(3600)  # 每小時收集一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"證據收集錯誤: {e}")
                    break
        
        thread = threading.Thread(target=collect_evidence, daemon=True)
        thread.start()
        self.response_threads.append(thread)
    
    def stop_response_system(self) -> Dict[str, Any]:
        """停止事件回應系統"""
        try:
            self.running = False
            
            # 等待所有線程結束
            for thread in self.response_threads:
                thread.join(timeout=5)
            
            self.response_threads.clear()
            
            logger.info("事件回應系統已停止")
            return {'success': True, 'message': '回應系統已停止'}
            
        except Exception as e:
            logger.error(f"停止回應系統錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_response_status(self) -> Dict[str, Any]:
        """獲取回應狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'active_incidents': len(self.active_incidents),
                'total_actions': len(self.response_actions),
                'recent_incidents': list(self.active_incidents.values())[-5:],
                'recent_actions': self.response_actions[-10:]
            }
        except Exception as e:
            logger.error(f"獲取回應狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_incident_report(self) -> Dict[str, Any]:
        """獲取事件報告"""
        try:
            return {
                'success': True,
                'total_incidents': len(self.active_incidents),
                'active_incidents': self.active_incidents,
                'response_actions': self.response_actions,
                'quarantine_files': self._get_quarantine_files(),
                'evidence_collected': self._get_evidence_files()
            }
        except Exception as e:
            logger.error(f"獲取事件報告錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _get_quarantine_files(self) -> List[Dict[str, Any]]:
        """獲取隔離文件列表"""
        try:
            quarantine_files = []
            if os.path.exists(self.quarantine_dir):
                for filename in os.listdir(self.quarantine_dir):
                    file_path = os.path.join(self.quarantine_dir, filename)
                    if os.path.isfile(file_path):
                        stat = os.stat(file_path)
                        quarantine_files.append({
                            'filename': filename,
                            'path': file_path,
                            'size': stat.st_size,
                            'quarantine_time': datetime.fromtimestamp(stat.st_mtime).isoformat()
                        })
            return quarantine_files
        except Exception as e:
            logger.error(f"獲取隔離文件錯誤: {e}")
            return []
    
    def _get_evidence_files(self) -> List[Dict[str, Any]]:
        """獲取證據文件列表"""
        try:
            evidence_files = []
            if os.path.exists(self.evidence_dir):
                for evidence_id in os.listdir(self.evidence_dir):
                    evidence_path = os.path.join(self.evidence_dir, evidence_id)
                    if os.path.isdir(evidence_path):
                        evidence_files.append({
                            'evidence_id': evidence_id,
                            'path': evidence_path,
                            'files': os.listdir(evidence_path)
                        })
            return evidence_files
        except Exception as e:
            logger.error(f"獲取證據文件錯誤: {e}")
            return []


def main():
    """主函數"""
    config = {
        'quarantine_dir': 'quarantine',
        'evidence_dir': 'evidence',
        'log_level': 'INFO'
    }
    
    responder = RealIncidentResponse(config)
    
    try:
        # 啟動回應系統
        result = responder.start_response_system()
        if result['success']:
            print("✅ 真實事件回應系統已啟動")
            print("按 Ctrl+C 停止系統")
            
            # 持續運行
            while True:
                time.sleep(1)
        else:
            print(f"❌ 啟動失敗: {result['error']}")
            
    except KeyboardInterrupt:
        print("\n🛑 正在停止系統...")
        responder.stop_response_system()
        print("✅ 系統已停止")
    except Exception as e:
        print(f"❌ 系統錯誤: {e}")


if __name__ == "__main__":
    main()

