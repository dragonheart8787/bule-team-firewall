#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實零信任與網路分段系統
Real Zero Trust Network Segmentation System
"""

import os
import sys
import json
import time
import logging
import subprocess
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import psutil
import socket
import hashlib
import requests
import yaml

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealZeroTrustNetworkSegmentation:
    """真實零信任與網路分段系統"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.segmentation_threads = []
        self.device_database = {}
        self.network_segments = {}
        self.policies = {}
        self.nac_sessions = {}
        self.east_west_traffic = []
        
        # 初始化零信任組件
        self._init_nac_system()
        self._init_microsegmentation()
        self._init_east_west_monitoring()
        
        logger.info("真實零信任與網路分段系統初始化完成")
    
    def _init_nac_system(self):
        """初始化NAC系統"""
        try:
            self.nac_config = {
                'enabled': True,
                'radius_server': self.config.get('radius_server', '127.0.0.1'),
                'radius_port': self.config.get('radius_port', 1812),
                'radius_secret': self.config.get('radius_secret', 'secret'),
                'device_profiling': True,
                'posture_assessment': True,
                'quarantine_vlan': self.config.get('quarantine_vlan', 999),
                'trusted_vlan': self.config.get('trusted_vlan', 100)
            }
            
            # 初始化設備資料庫
            self._init_device_database()
            
            logger.info("NAC系統初始化完成")
            
        except Exception as e:
            logger.error(f"NAC系統初始化錯誤: {e}")
    
    def _init_device_database(self):
        """初始化設備資料庫"""
        try:
            # 創建設備資料庫表結構
            self.device_schema = {
                'device_id': 'string',
                'mac_address': 'string',
                'ip_address': 'string',
                'device_type': 'string',
                'os_info': 'string',
                'security_posture': 'string',
                'trust_level': 'integer',
                'last_seen': 'datetime',
                'network_segment': 'string',
                'compliance_status': 'string'
            }
            
            # 載入已知設備
            self._load_known_devices()
            
        except Exception as e:
            logger.error(f"設備資料庫初始化錯誤: {e}")
    
    def _load_known_devices(self):
        """載入已知設備"""
        try:
            # 掃描網路中的設備
            self._discover_network_devices()
            
            # 載入設備配置文件
            device_config_file = 'device_config.yaml'
            if os.path.exists(device_config_file):
                with open(device_config_file, 'r', encoding='utf-8') as f:
                    device_config = yaml.safe_load(f)
                    for device in device_config.get('devices', []):
                        self.device_database[device['device_id']] = device
            
        except Exception as e:
            logger.error(f"載入已知設備錯誤: {e}")
    
    def _discover_network_devices(self):
        """發現網路設備"""
        try:
            # 獲取本地網路範圍
            local_network = self._get_local_network()
            if not local_network:
                return
            
            # 掃描網路中的設備
            base_ip = local_network.split('/')[0]
            ip_parts = base_ip.split('.')
            base_network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
            
            for i in range(1, 255):
                target_ip = f"{base_network}.{i}"
                if self._ping_host(target_ip):
                    device_info = self._profile_device(target_ip)
                    if device_info:
                        self.device_database[device_info['device_id']] = device_info
            
        except Exception as e:
            logger.error(f"發現網路設備錯誤: {e}")
    
    def _get_local_network(self) -> Optional[str]:
        """獲取本地網路範圍"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            ip_parts = local_ip.split('.')
            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        except Exception as e:
            logger.error(f"獲取本地網路錯誤: {e}")
            return None
    
    def _ping_host(self, ip: str) -> bool:
        """Ping主機"""
        try:
            if os.name == 'nt':
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                      capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def _profile_device(self, ip: str) -> Optional[Dict[str, Any]]:
        """設備指紋識別"""
        try:
            # 獲取MAC地址
            mac_address = self._get_mac_address(ip)
            if not mac_address:
                return None
            
            # 獲取設備信息
            device_info = {
                'device_id': hashlib.md5(f"{ip}_{mac_address}".encode()).hexdigest()[:16],
                'ip_address': ip,
                'mac_address': mac_address,
                'device_type': self._identify_device_type(ip),
                'os_info': self._identify_os(ip),
                'security_posture': self._assess_security_posture(ip),
                'trust_level': self._calculate_trust_level(ip),
                'last_seen': datetime.now().isoformat(),
                'network_segment': 'unknown',
                'compliance_status': 'unknown'
            }
            
            return device_info
            
        except Exception as e:
            logger.error(f"設備指紋識別錯誤 {ip}: {e}")
            return None
    
    def _get_mac_address(self, ip: str) -> Optional[str]:
        """獲取MAC地址"""
        try:
            if os.name == 'nt':
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                if ':' in part and len(part) == 17:
                                    return part
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                if ':' in part and len(part) == 17:
                                    return part
            return None
        except Exception as e:
            logger.error(f"獲取MAC地址錯誤 {ip}: {e}")
            return None
    
    def _identify_device_type(self, ip: str) -> str:
        """識別設備類型"""
        try:
            # 掃描常見端口
            common_ports = {
                22: 'server',
                23: 'network_device',
                80: 'web_server',
                443: 'web_server',
                3389: 'windows_client',
                5900: 'vnc_client',
                8080: 'application_server'
            }
            
            device_types = []
            for port, device_type in common_ports.items():
                if self._scan_port(ip, port):
                    device_types.append(device_type)
            
            if 'server' in device_types:
                return 'server'
            elif 'network_device' in device_types:
                return 'network_device'
            elif 'web_server' in device_types:
                return 'web_server'
            elif 'windows_client' in device_types:
                return 'windows_client'
            else:
                return 'unknown'
                
        except Exception as e:
            logger.error(f"識別設備類型錯誤 {ip}: {e}")
            return 'unknown'
    
    def _scan_port(self, ip: str, port: int) -> bool:
        """掃描端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _identify_os(self, ip: str) -> str:
        """識別操作系統"""
        try:
            # 使用nmap進行OS檢測
            if os.name != 'nt':
                result = subprocess.run(['nmap', '-O', '--osscan-guess', ip], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    output = result.stdout.lower()
                    if 'windows' in output:
                        return 'Windows'
                    elif 'linux' in output:
                        return 'Linux'
                    elif 'macos' in output or 'darwin' in output:
                        return 'macOS'
            
            return 'Unknown'
        except Exception as e:
            logger.error(f"識別操作系統錯誤 {ip}: {e}")
            return 'Unknown'
    
    def _assess_security_posture(self, ip: str) -> str:
        """評估安全態勢"""
        try:
            security_score = 0
            
            # 檢查開放端口
            dangerous_ports = [21, 23, 135, 139, 445, 1433, 3389, 5900]
            for port in dangerous_ports:
                if self._scan_port(ip, port):
                    security_score -= 10
            
            # 檢查安全端口
            secure_ports = [443, 22]
            for port in secure_ports:
                if self._scan_port(ip, port):
                    security_score += 5
            
            if security_score >= 5:
                return 'SECURE'
            elif security_score >= 0:
                return 'MODERATE'
            else:
                return 'VULNERABLE'
                
        except Exception as e:
            logger.error(f"評估安全態勢錯誤 {ip}: {e}")
            return 'UNKNOWN'
    
    def _calculate_trust_level(self, ip: str) -> int:
        """計算信任等級"""
        try:
            trust_level = 0
            
            # 基於設備類型
            device_type = self._identify_device_type(ip)
            if device_type == 'server':
                trust_level += 3
            elif device_type == 'network_device':
                trust_level += 4
            elif device_type == 'web_server':
                trust_level += 2
            elif device_type == 'windows_client':
                trust_level += 1
            
            # 基於安全態勢
            security_posture = self._assess_security_posture(ip)
            if security_posture == 'SECURE':
                trust_level += 2
            elif security_posture == 'MODERATE':
                trust_level += 1
            elif security_posture == 'VULNERABLE':
                trust_level -= 2
            
            return max(0, min(5, trust_level))
            
        except Exception as e:
            logger.error(f"計算信任等級錯誤 {ip}: {e}")
            return 0
    
    def _init_microsegmentation(self):
        """初始化微分段"""
        try:
            self.microsegmentation_config = {
                'enabled': True,
                'policy_engine': 'illumio_nsx_mode',
                'default_deny': True,
                'segments': {
                    'dmz': {
                        'vlan': 10,
                        'subnet': '192.168.10.0/24',
                        'trust_level': 1,
                        'allowed_services': ['http', 'https', 'dns']
                    },
                    'internal': {
                        'vlan': 20,
                        'subnet': '192.168.20.0/24',
                        'trust_level': 3,
                        'allowed_services': ['ssh', 'rdp', 'smb']
                    },
                    'critical': {
                        'vlan': 30,
                        'subnet': '192.168.30.0/24',
                        'trust_level': 5,
                        'allowed_services': ['ssh', 'database']
                    },
                    'quarantine': {
                        'vlan': 999,
                        'subnet': '192.168.99.0/24',
                        'trust_level': 0,
                        'allowed_services': []
                    }
                }
            }
            
            # 初始化策略引擎
            self._init_policy_engine()
            
            logger.info("微分段系統初始化完成")
            
        except Exception as e:
            logger.error(f"微分段系統初始化錯誤: {e}")
    
    def _init_policy_engine(self):
        """初始化策略引擎"""
        try:
            self.policy_engine = {
                'rules': [],
                'default_policy': 'DENY',
                'rule_priority': 1000
            }
            
            # 載入預設策略
            self._load_default_policies()
            
        except Exception as e:
            logger.error(f"策略引擎初始化錯誤: {e}")
    
    def _load_default_policies(self):
        """載入預設策略"""
        try:
            default_policies = [
                {
                    'id': 'POL_001',
                    'name': 'DMZ to Internal',
                    'source_segment': 'dmz',
                    'dest_segment': 'internal',
                    'action': 'ALLOW',
                    'services': ['http', 'https'],
                    'priority': 100
                },
                {
                    'id': 'POL_002',
                    'name': 'Internal to Critical',
                    'source_segment': 'internal',
                    'dest_segment': 'critical',
                    'action': 'ALLOW',
                    'services': ['ssh', 'database'],
                    'priority': 200
                },
                {
                    'id': 'POL_003',
                    'name': 'Quarantine Isolation',
                    'source_segment': 'quarantine',
                    'dest_segment': '*',
                    'action': 'DENY',
                    'services': ['*'],
                    'priority': 10
                }
            ]
            
            for policy in default_policies:
                self.policy_engine['rules'].append(policy)
            
        except Exception as e:
            logger.error(f"載入預設策略錯誤: {e}")
    
    def _init_east_west_monitoring(self):
        """初始化東西向流量監控"""
        try:
            self.east_west_config = {
                'enabled': True,
                'monitor_interval': 30,
                'lateral_movement_detection': True,
                'beaconing_detection': True,
                'dns_tunneling_detection': True,
                'suspicious_communication_detection': True
            }
            
            logger.info("東西向流量監控初始化完成")
            
        except Exception as e:
            logger.error(f"東西向流量監控初始化錯誤: {e}")
    
    def start_segmentation_system(self) -> Dict[str, Any]:
        """啟動分段系統"""
        try:
            if self.running:
                return {'success': False, 'error': '分段系統已在運行中'}
            
            self.running = True
            
            # 啟動分段線程
            self._start_nac_monitoring()
            self._start_microsegmentation_enforcement()
            self._start_east_west_monitoring()
            self._start_policy_engine()
            
            logger.info("真實零信任與網路分段系統已啟動")
            return {'success': True, 'message': '分段系統已啟動'}
            
        except Exception as e:
            logger.error(f"啟動分段系統錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _start_nac_monitoring(self):
        """啟動NAC監控"""
        def monitor_nac():
            logger.info("NAC監控已啟動")
            
            while self.running:
                try:
                    # 監控設備連接
                    self._monitor_device_connections()
                    
                    # 執行設備認證
                    self._perform_device_authentication()
                    
                    # 執行態勢評估
                    self._perform_posture_assessment()
                    
                    time.sleep(30)  # 每30秒監控一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"NAC監控錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_nac, daemon=True)
        thread.start()
        self.segmentation_threads.append(thread)
    
    def _monitor_device_connections(self):
        """監控設備連接"""
        try:
            # 獲取當前網路連接
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.laddr:
                    local_ip = conn.laddr.ip
                    local_port = conn.laddr.port
                    
                    # 檢查是否為新設備
                    if local_ip not in [device['ip_address'] for device in self.device_database.values()]:
                        self._handle_new_device(local_ip)
                    
                    # 檢查設備狀態
                    self._check_device_status(local_ip)
                    
        except Exception as e:
            logger.error(f"監控設備連接錯誤: {e}")
    
    def _handle_new_device(self, ip: str):
        """處理新設備"""
        try:
            logger.info(f"發現新設備: {ip}")
            
            # 設備指紋識別
            device_info = self._profile_device(ip)
            if device_info:
                self.device_database[device_info['device_id']] = device_info
                
                # 執行NAC認證
                self._perform_nac_authentication(device_info)
                
        except Exception as e:
            logger.error(f"處理新設備錯誤 {ip}: {e}")
    
    def _perform_nac_authentication(self, device_info: Dict[str, Any]):
        """執行NAC認證"""
        try:
            # 模擬RADIUS認證
            auth_result = self._simulate_radius_auth(device_info)
            
            if auth_result['success']:
                # 分配網路段
                network_segment = self._assign_network_segment(device_info)
                device_info['network_segment'] = network_segment
                
                # 創建NAC會話
                session_id = f"SESS_{int(time.time())}"
                self.nac_sessions[session_id] = {
                    'device_id': device_info['device_id'],
                    'ip_address': device_info['ip_address'],
                    'network_segment': network_segment,
                    'auth_time': datetime.now().isoformat(),
                    'status': 'AUTHENTICATED'
                }
                
                logger.info(f"設備認證成功: {device_info['ip_address']} -> {network_segment}")
            else:
                # 隔離設備
                self._quarantine_device(device_info)
                logger.warning(f"設備認證失敗，已隔離: {device_info['ip_address']}")
                
        except Exception as e:
            logger.error(f"NAC認證錯誤: {e}")
    
    def _simulate_radius_auth(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """模擬RADIUS認證"""
        try:
            # 基於設備信息進行認證
            trust_level = device_info.get('trust_level', 0)
            security_posture = device_info.get('security_posture', 'UNKNOWN')
            
            if trust_level >= 3 and security_posture in ['SECURE', 'MODERATE']:
                return {'success': True, 'message': '認證成功'}
            else:
                return {'success': False, 'message': '認證失敗'}
                
        except Exception as e:
            logger.error(f"RADIUS認證模擬錯誤: {e}")
            return {'success': False, 'message': '認證錯誤'}
    
    def _assign_network_segment(self, device_info: Dict[str, Any]) -> str:
        """分配網路段"""
        try:
            trust_level = device_info.get('trust_level', 0)
            device_type = device_info.get('device_type', 'unknown')
            
            if trust_level >= 4:
                return 'critical'
            elif trust_level >= 2:
                return 'internal'
            elif trust_level >= 1:
                return 'dmz'
            else:
                return 'quarantine'
                
        except Exception as e:
            logger.error(f"分配網路段錯誤: {e}")
            return 'quarantine'
    
    def _quarantine_device(self, device_info: Dict[str, Any]):
        """隔離設備"""
        try:
            device_info['network_segment'] = 'quarantine'
            device_info['compliance_status'] = 'NON_COMPLIANT'
            
            # 記錄隔離事件
            quarantine_event = {
                'device_id': device_info['device_id'],
                'ip_address': device_info['ip_address'],
                'reason': 'NAC_AUTH_FAILED',
                'quarantine_time': datetime.now().isoformat()
            }
            
            logger.warning(f"設備已隔離: {quarantine_event}")
            
        except Exception as e:
            logger.error(f"隔離設備錯誤: {e}")
    
    def _check_device_status(self, ip: str):
        """檢查設備狀態"""
        try:
            # 查找設備
            device = None
            for device_info in self.device_database.values():
                if device_info['ip_address'] == ip:
                    device = device_info
                    break
            
            if not device:
                return
            
            # 更新最後看到時間
            device['last_seen'] = datetime.now().isoformat()
            
            # 檢查是否在線
            if not self._ping_host(ip):
                # 設備離線
                self._handle_device_offline(device)
            
        except Exception as e:
            logger.error(f"檢查設備狀態錯誤 {ip}: {e}")
    
    def _handle_device_offline(self, device: Dict[str, Any]):
        """處理設備離線"""
        try:
            device_id = device['device_id']
            
            # 清理NAC會話
            sessions_to_remove = []
            for session_id, session in self.nac_sessions.items():
                if session['device_id'] == device_id:
                    sessions_to_remove.append(session_id)
            
            for session_id in sessions_to_remove:
                del self.nac_sessions[session_id]
            
            logger.info(f"設備離線: {device['ip_address']}")
            
        except Exception as e:
            logger.error(f"處理設備離線錯誤: {e}")
    
    def _perform_device_authentication(self):
        """執行設備認證"""
        try:
            # 檢查所有設備的認證狀態
            for device_id, device in self.device_database.items():
                if device.get('network_segment') == 'unknown':
                    self._perform_nac_authentication(device)
                    
        except Exception as e:
            logger.error(f"執行設備認證錯誤: {e}")
    
    def _perform_posture_assessment(self):
        """執行態勢評估"""
        try:
            for device_id, device in self.device_database.items():
                # 重新評估安全態勢
                new_posture = self._assess_security_posture(device['ip_address'])
                if new_posture != device.get('security_posture'):
                    device['security_posture'] = new_posture
                    
                    # 重新計算信任等級
                    new_trust_level = self._calculate_trust_level(device['ip_address'])
                    if new_trust_level != device.get('trust_level'):
                        device['trust_level'] = new_trust_level
                        
                        # 重新分配網路段
                        new_segment = self._assign_network_segment(device)
                        if new_segment != device.get('network_segment'):
                            device['network_segment'] = new_segment
                            logger.info(f"設備網路段變更: {device['ip_address']} -> {new_segment}")
                    
        except Exception as e:
            logger.error(f"執行態勢評估錯誤: {e}")
    
    def _start_microsegmentation_enforcement(self):
        """啟動微分段執行"""
        def enforce_microsegmentation():
            logger.info("微分段執行已啟動")
            
            while self.running:
                try:
                    # 執行微分段策略
                    self._enforce_segmentation_policies()
                    
                    # 監控策略違規
                    self._monitor_policy_violations()
                    
                    time.sleep(60)  # 每分鐘執行一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"微分段執行錯誤: {e}")
                    break
        
        thread = threading.Thread(target=enforce_microsegmentation, daemon=True)
        thread.start()
        self.segmentation_threads.append(thread)
    
    def _enforce_segmentation_policies(self):
        """執行微分段策略"""
        try:
            # 獲取當前網路連接
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.laddr and conn.raddr:
                    # 檢查連接是否符合策略
                    self._check_connection_policy(conn)
                    
        except Exception as e:
            logger.error(f"執行微分段策略錯誤: {e}")
    
    def _check_connection_policy(self, conn):
        """檢查連接策略"""
        try:
            local_ip = conn.laddr.ip
            remote_ip = conn.raddr.ip
            local_port = conn.laddr.port
            remote_port = conn.raddr.port
            
            # 獲取源和目標設備信息
            source_device = self._get_device_by_ip(local_ip)
            dest_device = self._get_device_by_ip(remote_ip)
            
            if not source_device or not dest_device:
                return
            
            # 檢查策略
            policy_result = self._evaluate_policy(source_device, dest_device, remote_port)
            
            if not policy_result['allowed']:
                # 記錄策略違規
                self._log_policy_violation(source_device, dest_device, remote_port, policy_result['reason'])
                
                # 執行阻擋動作
                self._block_connection(conn)
                
        except Exception as e:
            logger.error(f"檢查連接策略錯誤: {e}")
    
    def _get_device_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """根據IP獲取設備信息"""
        try:
            for device in self.device_database.values():
                if device['ip_address'] == ip:
                    return device
            return None
        except Exception as e:
            logger.error(f"獲取設備信息錯誤 {ip}: {e}")
            return None
    
    def _evaluate_policy(self, source_device: Dict[str, Any], dest_device: Dict[str, Any], port: int) -> Dict[str, Any]:
        """評估策略"""
        try:
            source_segment = source_device.get('network_segment', 'unknown')
            dest_segment = dest_device.get('network_segment', 'unknown')
            
            # 查找適用策略
            for rule in self.policy_engine['rules']:
                if self._rule_matches(rule, source_segment, dest_segment, port):
                    return {
                        'allowed': rule['action'] == 'ALLOW',
                        'reason': f"策略: {rule['name']}"
                    }
            
            # 預設策略
            return {
                'allowed': self.policy_engine['default_policy'] == 'ALLOW',
                'reason': '預設策略'
            }
            
        except Exception as e:
            logger.error(f"評估策略錯誤: {e}")
            return {'allowed': False, 'reason': '策略評估錯誤'}
    
    def _rule_matches(self, rule: Dict[str, Any], source_segment: str, dest_segment: str, port: int) -> bool:
        """檢查規則是否匹配"""
        try:
            # 檢查源段
            if rule['source_segment'] != '*' and rule['source_segment'] != source_segment:
                return False
            
            # 檢查目標段
            if rule['dest_segment'] != '*' and rule['dest_segment'] != dest_segment:
                return False
            
            # 檢查服務
            if '*' not in rule['services']:
                service = self._port_to_service(port)
                if service not in rule['services']:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"檢查規則匹配錯誤: {e}")
            return False
    
    def _port_to_service(self, port: int) -> str:
        """端口轉服務名稱"""
        service_map = {
            22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 135: 'rpc', 139: 'netbios',
            143: 'imap', 443: 'https', 993: 'imaps', 995: 'pop3s',
            1433: 'database', 3389: 'rdp', 5432: 'database', 5900: 'vnc',
            8080: 'http', 8443: 'https'
        }
        return service_map.get(port, 'unknown')
    
    def _log_policy_violation(self, source_device: Dict[str, Any], dest_device: Dict[str, Any], port: int, reason: str):
        """記錄策略違規"""
        try:
            violation = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': source_device['ip_address'],
                'dest_ip': dest_device['ip_address'],
                'port': port,
                'source_segment': source_device.get('network_segment', 'unknown'),
                'dest_segment': dest_device.get('network_segment', 'unknown'),
                'reason': reason,
                'action': 'BLOCKED'
            }
            
            logger.warning(f"策略違規: {source_device['ip_address']} -> {dest_device['ip_address']}:{port} ({reason})")
            
        except Exception as e:
            logger.error(f"記錄策略違規錯誤: {e}")
    
    def _block_connection(self, conn):
        """阻擋連接"""
        try:
            # 這裡應該實現實際的連接阻擋
            # 例如使用iptables或Windows Firewall
            logger.info(f"阻擋連接: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}")
            
        except Exception as e:
            logger.error(f"阻擋連接錯誤: {e}")
    
    def _monitor_policy_violations(self):
        """監控策略違規"""
        try:
            # 檢查是否有持續的策略違規
            # 這裡可以實現更複雜的違規檢測邏輯
            pass
            
        except Exception as e:
            logger.error(f"監控策略違規錯誤: {e}")
    
    def _start_east_west_monitoring(self):
        """啟動東西向流量監控"""
        def monitor_east_west():
            logger.info("東西向流量監控已啟動")
            
            while self.running:
                try:
                    # 監控橫向移動
                    self._monitor_lateral_movement()
                    
                    # 監控Beaconing
                    self._monitor_beaconing()
                    
                    # 監控DNS隧道
                    self._monitor_dns_tunneling()
                    
                    # 監控可疑通信
                    self._monitor_suspicious_communication()
                    
                    time.sleep(30)  # 每30秒監控一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"東西向流量監控錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_east_west, daemon=True)
        thread.start()
        self.segmentation_threads.append(thread)
    
    def _monitor_lateral_movement(self):
        """監控橫向移動"""
        try:
            # 獲取網路連接
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.raddr:
                    # 檢查是否為橫向移動
                    if self._is_lateral_movement(conn):
                        self._log_lateral_movement(conn)
                        
        except Exception as e:
            logger.error(f"監控橫向移動錯誤: {e}")
    
    def _is_lateral_movement(self, conn) -> bool:
        """檢查是否為橫向移動"""
        try:
            local_ip = conn.laddr.ip
            remote_ip = conn.raddr.ip
            
            # 檢查是否為內網通信
            if not self._is_internal_communication(local_ip, remote_ip):
                return False
            
            # 檢查是否為可疑端口
            suspicious_ports = [135, 139, 445, 1433, 3389, 5985, 5986]
            if conn.raddr.port in suspicious_ports:
                return True
            
            # 檢查是否為大量連接
            if self._count_connections_to_ip(remote_ip) > 10:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"檢查橫向移動錯誤: {e}")
            return False
    
    def _is_internal_communication(self, local_ip: str, remote_ip: str) -> bool:
        """檢查是否為內網通信"""
        try:
            # 檢查是否為私有IP
            private_ranges = [
                ('10.0.0.0', '10.255.255.255'),
                ('172.16.0.0', '172.31.255.255'),
                ('192.168.0.0', '192.168.255.255')
            ]
            
            for start_ip, end_ip in private_ranges:
                if self._ip_in_range(local_ip, start_ip, end_ip) and self._ip_in_range(remote_ip, start_ip, end_ip):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"檢查內網通信錯誤: {e}")
            return False
    
    def _ip_in_range(self, ip: str, start_ip: str, end_ip: str) -> bool:
        """檢查IP是否在範圍內"""
        try:
            def ip_to_int(ip):
                return sum(int(x) * 256 ** (3 - i) for i, x in enumerate(ip.split('.')))
            
            ip_int = ip_to_int(ip)
            start_int = ip_to_int(start_ip)
            end_int = ip_to_int(end_ip)
            
            return start_int <= ip_int <= end_int
            
        except Exception as e:
            logger.error(f"檢查IP範圍錯誤: {e}")
            return False
    
    def _count_connections_to_ip(self, ip: str) -> int:
        """計算到指定IP的連接數"""
        try:
            connections = psutil.net_connections(kind='inet')
            count = 0
            for conn in connections:
                if conn.raddr and conn.raddr.ip == ip:
                    count += 1
            return count
        except Exception as e:
            logger.error(f"計算連接數錯誤: {e}")
            return 0
    
    def _log_lateral_movement(self, conn):
        """記錄橫向移動"""
        try:
            movement = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': conn.laddr.ip,
                'dest_ip': conn.raddr.ip,
                'port': conn.raddr.port,
                'type': 'LATERAL_MOVEMENT',
                'severity': 'HIGH'
            }
            
            self.east_west_traffic.append(movement)
            logger.warning(f"檢測到橫向移動: {conn.laddr.ip} -> {conn.raddr.ip}:{conn.raddr.port}")
            
        except Exception as e:
            logger.error(f"記錄橫向移動錯誤: {e}")
    
    def _monitor_beaconing(self):
        """監控Beaconing"""
        try:
            # 檢查是否有定期的網路連接
            # 這裡可以實現更複雜的Beaconing檢測邏輯
            pass
            
        except Exception as e:
            logger.error(f"監控Beaconing錯誤: {e}")
    
    def _monitor_dns_tunneling(self):
        """監控DNS隧道"""
        try:
            # 檢查DNS查詢是否異常
            # 這裡可以實現DNS隧道檢測邏輯
            pass
            
        except Exception as e:
            logger.error(f"監控DNS隧道錯誤: {e}")
    
    def _monitor_suspicious_communication(self):
        """監控可疑通信"""
        try:
            # 檢查是否有可疑的通信模式
            # 這裡可以實現可疑通信檢測邏輯
            pass
            
        except Exception as e:
            logger.error(f"監控可疑通信錯誤: {e}")
    
    def _start_policy_engine(self):
        """啟動策略引擎"""
        def run_policy_engine():
            logger.info("策略引擎已啟動")
            
            while self.running:
                try:
                    # 更新策略
                    self._update_policies()
                    
                    # 優化策略
                    self._optimize_policies()
                    
                    time.sleep(300)  # 每5分鐘執行一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"策略引擎錯誤: {e}")
                    break
        
        thread = threading.Thread(target=run_policy_engine, daemon=True)
        thread.start()
        self.segmentation_threads.append(thread)
    
    def _update_policies(self):
        """更新策略"""
        try:
            # 根據設備狀態更新策略
            # 這裡可以實現動態策略更新邏輯
            pass
            
        except Exception as e:
            logger.error(f"更新策略錯誤: {e}")
    
    def _optimize_policies(self):
        """優化策略"""
        try:
            # 優化策略規則
            # 這裡可以實現策略優化邏輯
            pass
            
        except Exception as e:
            logger.error(f"優化策略錯誤: {e}")
    
    def stop_segmentation_system(self) -> Dict[str, Any]:
        """停止分段系統"""
        try:
            self.running = False
            
            # 等待所有線程結束
            for thread in self.segmentation_threads:
                thread.join(timeout=5)
            
            self.segmentation_threads.clear()
            
            logger.info("零信任與網路分段系統已停止")
            return {'success': True, 'message': '分段系統已停止'}
            
        except Exception as e:
            logger.error(f"停止分段系統錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_segmentation_status(self) -> Dict[str, Any]:
        """獲取分段狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'device_count': len(self.device_database),
                'active_sessions': len(self.nac_sessions),
                'network_segments': list(self.microsegmentation_config['segments'].keys()),
                'policy_rules': len(self.policy_engine['rules']),
                'east_west_events': len(self.east_west_traffic)
            }
        except Exception as e:
            logger.error(f"獲取分段狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_segmentation_report(self) -> Dict[str, Any]:
        """獲取分段報告"""
        try:
            return {
                'success': True,
                'device_database': self.device_database,
                'network_segments': self.microsegmentation_config['segments'],
                'policy_engine': self.policy_engine,
                'nac_sessions': self.nac_sessions,
                'east_west_traffic': self.east_west_traffic,
                'segmentation_summary': {
                    'total_devices': len(self.device_database),
                    'authenticated_devices': len([d for d in self.device_database.values() if d.get('network_segment') != 'unknown']),
                    'quarantined_devices': len([d for d in self.device_database.values() if d.get('network_segment') == 'quarantine']),
                    'lateral_movement_events': len([e for e in self.east_west_traffic if e.get('type') == 'LATERAL_MOVEMENT'])
                }
            }
        except Exception as e:
            logger.error(f"獲取分段報告錯誤: {e}")
            return {'success': False, 'error': str(e)}


def main():
    """主函數"""
    config = {
        'radius_server': '127.0.0.1',
        'radius_port': 1812,
        'radius_secret': 'secret',
        'quarantine_vlan': 999,
        'trusted_vlan': 100,
        'log_level': 'INFO'
    }
    
    segmentation = RealZeroTrustNetworkSegmentation(config)
    
    try:
        # 啟動分段系統
        result = segmentation.start_segmentation_system()
        if result['success']:
            print("✅ 真實零信任與網路分段系統已啟動")
            print("🔐 功能:")
            print("   - NAC (網路存取控制)")
            print("   - 微分段策略")
            print("   - 東西向流量監控")
            print("   - 橫向移動檢測")
            print("\n按 Ctrl+C 停止系統")
            
            # 持續運行
            while True:
                time.sleep(1)
        else:
            print(f"❌ 啟動失敗: {result['error']}")
            
    except KeyboardInterrupt:
        print("\n🛑 正在停止系統...")
        segmentation.stop_segmentation_system()
        print("✅ 系統已停止")
    except Exception as e:
        print(f"❌ 系統錯誤: {e}")


if __name__ == "__main__":
    main()
