#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實威脅檢測系統
Real Threat Detection System
"""

import os
import sys
import json
import time
import hashlib
import logging
import subprocess
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import psutil
import requests
import yara
import re

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealThreatDetector:
    """真實威脅檢測系統"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.detection_threads = []
        self.threat_signatures = {}
        self.detected_threats = []
        self.file_hashes = {}
        self.process_monitor = {}
        self.suricata_events = []
        self.sysmon_events = []
        
        # 初始化檢測引擎
        self._init_yara_rules()
        self._init_threat_intelligence()
        self._init_behavioral_analysis()
        self._init_external_log_monitoring()
        
        logger.info("真實威脅檢測系統初始化完成")
    
    def _init_yara_rules(self):
        """初始化 YARA 規則"""
        try:
            # 創建 YARA 規則目錄
            rules_dir = "yara_rules"
            if not os.path.exists(rules_dir):
                os.makedirs(rules_dir)
            
            # 創建基本惡意程式規則
            self._create_malware_rules(rules_dir)
            
            # 編譯 YARA 規則
            self.yara_rules = yara.compile(filepath=os.path.join(rules_dir, "malware.yar"))
            
            logger.info("YARA 規則初始化完成")
            
        except Exception as e:
            logger.error(f"YARA 規則初始化錯誤: {e}")
            self.yara_rules = None
    
    def _create_malware_rules(self, rules_dir: str):
        """創建惡意程式檢測規則"""
        try:
            malware_rules = '''
rule Malware_Generic {
    meta:
        description = "Generic malware detection"
        author = "Military Defense System"
        date = "2024-01-01"
    
    strings:
        $s1 = "CreateRemoteThread" ascii
        $s2 = "VirtualAllocEx" ascii
        $s3 = "WriteProcessMemory" ascii
        $s4 = "LoadLibrary" ascii
        $s5 = "GetProcAddress" ascii
        $s6 = "CreateProcess" ascii
        $s7 = "ShellExecute" ascii
        $s8 = "WinExec" ascii
        $s9 = "system" ascii
        $s10 = "cmd.exe" ascii
        $s11 = "powershell" ascii
        $s12 = "regsvr32" ascii
        $s13 = "rundll32" ascii
        $s14 = "wscript" ascii
        $s15 = "cscript" ascii
    
    condition:
        3 of them
}

rule Backdoor_Generic {
    meta:
        description = "Generic backdoor detection"
        author = "Military Defense System"
        date = "2024-01-01"
    
    strings:
        $s1 = "bind" ascii
        $s2 = "listen" ascii
        $s3 = "accept" ascii
        $s4 = "connect" ascii
        $s5 = "send" ascii
        $s6 = "recv" ascii
        $s7 = "socket" ascii
        $s8 = "WSAStartup" ascii
        $s9 = "gethostbyname" ascii
        $s10 = "inet_addr" ascii
    
    condition:
        5 of them
}

rule Ransomware_Generic {
    meta:
        description = "Generic ransomware detection"
        author = "Military Defense System"
        date = "2024-01-01"
    
    strings:
        $s1 = "encrypt" ascii
        $s2 = "decrypt" ascii
        $s3 = "AES" ascii
        $s4 = "RSA" ascii
        $s5 = "crypt" ascii
        $s6 = ".encrypted" ascii
        $s7 = ".locked" ascii
        $s8 = ".crypted" ascii
        $s9 = "ransom" ascii
        $s10 = "bitcoin" ascii
    
    condition:
        3 of them
}

rule Keylogger_Generic {
    meta:
        description = "Generic keylogger detection"
        author = "Military Defense System"
        date = "2024-01-01"
    
    strings:
        $s1 = "GetAsyncKeyState" ascii
        $s2 = "GetKeyState" ascii
        $s3 = "SetWindowsHookEx" ascii
        $s4 = "WH_KEYBOARD" ascii
        $s5 = "WH_KEYBOARD_LL" ascii
        $s6 = "keylog" ascii
        $s7 = "keystroke" ascii
        $s8 = "keyboard" ascii
    
    condition:
        3 of them
}

rule Rootkit_Generic {
    meta:
        description = "Generic rootkit detection"
        author = "Military Defense System"
        date = "2024-01-01"
    
    strings:
        $s1 = "NtQuerySystemInformation" ascii
        $s2 = "ZwQuerySystemInformation" ascii
        $s3 = "NtQueryDirectoryFile" ascii
        $s4 = "ZwQueryDirectoryFile" ascii
        $s5 = "NtOpenProcess" ascii
        $s6 = "ZwOpenProcess" ascii
        $s7 = "NtOpenThread" ascii
        $s8 = "ZwOpenThread" ascii
        $s9 = "SSDT" ascii
        $s10 = "IDT" ascii
    
    condition:
        4 of them
}
'''
            
            with open(os.path.join(rules_dir, "malware.yar"), 'w', encoding='utf-8') as f:
                f.write(malware_rules)
                
        except Exception as e:
            logger.error(f"創建惡意程式規則錯誤: {e}")
    
    def _init_threat_intelligence(self):
        """初始化威脅情報"""
        try:
            # 已知惡意 IP 列表
            self.malicious_ips = [
                '192.168.1.100',
                '10.0.0.100',
                '172.16.0.100'
            ]
            
            # 已知惡意域名
            self.malicious_domains = [
                'malicious.example.com',
                'evil.example.com',
                'bad.example.com'
            ]
            
            # 已知惡意文件哈希
            self.malicious_hashes = [
                'd41d8cd98f00b204e9800998ecf8427e',  # 示例哈希
                '5d41402abc4b2a76b9719d911017c592'   # 示例哈希
            ]
            
            # 已知惡意進程
            self.malicious_processes = [
                'nc.exe', 'netcat.exe', 'ncat.exe',
                'socat.exe', 'wget.exe', 'curl.exe',
                'powershell.exe', 'cmd.exe'
            ]
            
            logger.info("威脅情報初始化完成")
            
        except Exception as e:
            logger.error(f"威脅情報初始化錯誤: {e}")
    
    def _init_behavioral_analysis(self):
        """初始化行為分析"""
        try:
            self.behavioral_patterns = {
                'suspicious_file_operations': [
                    '大量文件加密',
                    '系統文件修改',
                    '註冊表修改',
                    '服務創建'
                ],
                'suspicious_network_behavior': [
                    '異常網路連接',
                    '大量數據傳輸',
                    '可疑端口掃描',
                    'DNS 隧道'
                ],
                'suspicious_process_behavior': [
                    '進程注入',
                    'DLL 劫持',
                    '服務安裝',
                    '計劃任務創建'
                ]
            }
            
            logger.info("行為分析初始化完成")
            
        except Exception as e:
            logger.error(f"行為分析初始化錯誤: {e}")
    
    def _init_external_log_monitoring(self):
        """初始化外部日誌監控"""
        try:
            self.external_log_config = {
                'suricata_eve': self.config.get('suricata_eve', ''),
                'sysmon_evtx': self.config.get('sysmon_evtx', ''),
                'consume_suricata': self.config.get('consume_suricata', False),
                'consume_sysmon': self.config.get('consume_sysmon', False)
            }
            
            logger.info("外部日誌監控初始化完成")
            
        except Exception as e:
            logger.error(f"外部日誌監控初始化錯誤: {e}")
    
    def start_detection(self) -> Dict[str, Any]:
        """開始威脅檢測"""
        try:
            if self.running:
                return {'success': False, 'error': '檢測已在運行中'}
            
            self.running = True
            
            # 啟動多個檢測線程
            self._start_file_monitoring()
            self._start_process_monitoring()
            self._start_network_monitoring()
            self._start_registry_monitoring()
            self._start_memory_monitoring()
            
            # 啟動外部日誌監控
            if self.external_log_config['consume_suricata']:
                self._start_suricata_monitoring()
            if self.external_log_config['consume_sysmon']:
                self._start_sysmon_monitoring()
            
            logger.info("真實威脅檢測已啟動")
            return {'success': True, 'message': '威脅檢測已啟動'}
            
        except Exception as e:
            logger.error(f"啟動檢測錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _start_file_monitoring(self):
        """啟動文件監控"""
        def monitor_files():
            logger.info("文件監控已啟動")
            
            while self.running:
                try:
                    # 監控系統關鍵目錄
                    critical_dirs = [
                        'C:\\Windows\\System32',
                        'C:\\Windows\\SysWOW64',
                        'C:\\Program Files',
                        'C:\\Program Files (x86)',
                        '/bin', '/sbin', '/usr/bin', '/usr/sbin'
                    ]
                    
                    for directory in critical_dirs:
                        if os.path.exists(directory):
                            self._scan_directory(directory)
                    
                    time.sleep(30)  # 每30秒掃描一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"文件監控錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_files, daemon=True)
        thread.start()
        self.detection_threads.append(thread)
    
    def _scan_directory(self, directory: str):
        """掃描目錄中的文件"""
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # 檢查文件是否為可執行文件
                        if self._is_executable(file_path):
                            self._analyze_file(file_path)
                    except (PermissionError, OSError):
                        continue  # 跳過無法訪問的文件
                        
        except Exception as e:
            logger.error(f"目錄掃描錯誤: {e}")
    
    def _is_executable(self, file_path: str) -> bool:
        """檢查文件是否為可執行文件"""
        try:
            if os.name == 'nt':  # Windows
                return file_path.lower().endswith(('.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1'))
            else:  # Linux/Unix
                return os.access(file_path, os.X_OK)
        except Exception:
            return False
    
    def _analyze_file(self, file_path: str):
        """分析文件"""
        try:
            # 計算文件哈希
            file_hash = self._calculate_file_hash(file_path)
            
            # 檢查是否為已知惡意文件
            if file_hash in self.malicious_hashes:
                self._log_threat({
                    'type': 'MALICIOUS_FILE',
                    'file_path': file_path,
                    'file_hash': file_hash,
                    'threat_level': 'CRITICAL',
                    'timestamp': datetime.now().isoformat()
                })
                return
            
            # 使用 YARA 規則掃描
            if self.yara_rules:
                try:
                    matches = self.yara_rules.match(file_path)
                    if matches:
                        for match in matches:
                            self._log_threat({
                                'type': 'YARA_MATCH',
                                'file_path': file_path,
                                'file_hash': file_hash,
                                'rule_name': match.rule,
                                'threat_level': 'HIGH',
                                'timestamp': datetime.now().isoformat()
                            })
                except Exception as e:
                    logger.debug(f"YARA 掃描錯誤 {file_path}: {e}")
            
            # 檢查文件行為
            self._analyze_file_behavior(file_path, file_hash)
            
        except Exception as e:
            logger.error(f"文件分析錯誤 {file_path}: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """計算文件哈希"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"計算文件哈希錯誤 {file_path}: {e}")
            return ""
    
    def _analyze_file_behavior(self, file_path: str, file_hash: str):
        """分析文件行為"""
        try:
            # 檢查文件名是否可疑
            filename = os.path.basename(file_path).lower()
            suspicious_names = [
                'svchost', 'explorer', 'winlogon', 'csrss', 'lsass',
                'services', 'smss', 'wininit', 'dwm', 'conhost'
            ]
            
            # 檢查是否偽裝成系統進程
            for suspicious in suspicious_names:
                if suspicious in filename and file_path not in [
                    'C:\\Windows\\System32\\svchost.exe',
                    'C:\\Windows\\explorer.exe',
                    'C:\\Windows\\System32\\winlogon.exe'
                ]:
                    self._log_threat({
                        'type': 'PROCESS_IMPERSONATION',
                        'file_path': file_path,
                        'file_hash': file_hash,
                        'impersonated_process': suspicious,
                        'threat_level': 'HIGH',
                        'timestamp': datetime.now().isoformat()
                    })
                    break
            
            # 檢查文件大小（異常小的可執行文件）
            try:
                file_size = os.path.getsize(file_path)
                if file_size < 1024 and self._is_executable(file_path):  # 小於1KB的可執行文件
                    self._log_threat({
                        'type': 'SUSPICIOUS_FILE_SIZE',
                        'file_path': file_path,
                        'file_hash': file_hash,
                        'file_size': file_size,
                        'threat_level': 'MEDIUM',
                        'timestamp': datetime.now().isoformat()
                    })
            except Exception:
                pass
                
        except Exception as e:
            logger.error(f"文件行為分析錯誤 {file_path}: {e}")
    
    def _start_process_monitoring(self):
        """啟動進程監控"""
        def monitor_processes():
            logger.info("進程監控已啟動")
            
            while self.running:
                try:
                    # 獲取所有進程
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'memory_info']):
                        try:
                            proc_info = proc.info
                            self._analyze_process(proc_info)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    time.sleep(10)  # 每10秒檢查一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"進程監控錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_processes, daemon=True)
        thread.start()
        self.detection_threads.append(thread)
    
    def _analyze_process(self, proc_info: Dict[str, Any]):
        """分析進程"""
        try:
            pid = proc_info['pid']
            name = proc_info['name'].lower()
            cmdline = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
            
            # 檢查是否為已知惡意進程
            if name in self.malicious_processes:
                self._log_threat({
                    'type': 'MALICIOUS_PROCESS',
                    'pid': pid,
                    'process_name': name,
                    'cmdline': cmdline,
                    'threat_level': 'HIGH',
                    'timestamp': datetime.now().isoformat()
                })
            
            # 檢查進程行為
            self._analyze_process_behavior(proc_info)
            
            # 檢查進程記憶體使用
            if 'memory_info' in proc_info and proc_info['memory_info']:
                memory_usage = proc_info['memory_info'].rss / 1024 / 1024  # MB
                if memory_usage > 1000:  # 超過1GB記憶體使用
                    self._log_threat({
                        'type': 'HIGH_MEMORY_USAGE',
                        'pid': pid,
                        'process_name': name,
                        'memory_usage_mb': memory_usage,
                        'threat_level': 'MEDIUM',
                        'timestamp': datetime.now().isoformat()
                    })
            
        except Exception as e:
            logger.error(f"進程分析錯誤: {e}")
    
    def _analyze_process_behavior(self, proc_info: Dict[str, Any]):
        """分析進程行為"""
        try:
            pid = proc_info['pid']
            name = proc_info['name']
            cmdline = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
            
            # 檢查可疑的命令行參數
            suspicious_patterns = [
                r'-e\s+\w+',  # 執行命令
                r'-c\s+\w+',  # 執行命令
                r'powershell.*-enc',  # PowerShell 編碼命令
                r'cmd.*\/c',  # CMD 執行命令
                r'regsvr32.*\/s',  # 靜默註冊
                r'rundll32.*\/s'   # 靜默執行
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    self._log_threat({
                        'type': 'SUSPICIOUS_CMDLINE',
                        'pid': pid,
                        'process_name': name,
                        'cmdline': cmdline,
                        'suspicious_pattern': pattern,
                        'threat_level': 'HIGH',
                        'timestamp': datetime.now().isoformat()
                    })
                    break
            
            # 檢查進程創建時間（異常新的進程）
            if 'create_time' in proc_info:
                create_time = datetime.fromtimestamp(proc_info['create_time'])
                if datetime.now() - create_time < timedelta(minutes=5):
                    # 檢查是否為系統進程
                    system_processes = ['svchost.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe']
                    if name.lower() not in system_processes:
                        self._log_threat({
                            'type': 'NEW_PROCESS',
                            'pid': pid,
                            'process_name': name,
                            'create_time': create_time.isoformat(),
                            'threat_level': 'LOW',
                            'timestamp': datetime.now().isoformat()
                        })
                        
        except Exception as e:
            logger.error(f"進程行為分析錯誤: {e}")
    
    def _start_network_monitoring(self):
        """啟動網路監控"""
        def monitor_network():
            logger.info("網路監控已啟動")
            
            while self.running:
                try:
                    # 獲取網路連接
                    connections = psutil.net_connections(kind='inet')
                    
                    for conn in connections:
                        if conn.raddr:
                            self._analyze_network_connection(conn)
                    
                    time.sleep(5)  # 每5秒檢查一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"網路監控錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_network, daemon=True)
        thread.start()
        self.detection_threads.append(thread)
    
    def _analyze_network_connection(self, conn):
        """分析網路連接"""
        try:
            if not conn.raddr:
                return
            
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            local_port = conn.laddr.port if conn.laddr else 0
            
            # 檢查是否連接到惡意 IP
            if remote_ip in self.malicious_ips:
                self._log_threat({
                    'type': 'MALICIOUS_IP_CONNECTION',
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'local_port': local_port,
                    'status': conn.status,
                    'threat_level': 'CRITICAL',
                    'timestamp': datetime.now().isoformat()
                })
            
            # 檢查可疑端口
            suspicious_ports = [4444, 8080, 9999, 31337, 12345, 54321]
            if remote_port in suspicious_ports:
                self._log_threat({
                    'type': 'SUSPICIOUS_PORT_CONNECTION',
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'local_port': local_port,
                    'status': conn.status,
                    'threat_level': 'HIGH',
                    'timestamp': datetime.now().isoformat()
                })
            
            # 檢查異常連接狀態
            if conn.status == 'SYN_SENT':
                self._log_threat({
                    'type': 'SYN_SENT_CONNECTION',
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'local_port': local_port,
                    'threat_level': 'MEDIUM',
                    'timestamp': datetime.now().isoformat()
                })
                
        except Exception as e:
            logger.error(f"網路連接分析錯誤: {e}")
    
    def _start_registry_monitoring(self):
        """啟動註冊表監控（Windows）"""
        def monitor_registry():
            if os.name != 'nt':
                return  # 只在 Windows 上運行
            
            logger.info("註冊表監控已啟動")
            
            while self.running:
                try:
                    # 監控關鍵註冊表項
                    critical_keys = [
                        r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                        r'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                        r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                        r'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
                    ]
                    
                    for key in critical_keys:
                        self._check_registry_key(key)
                    
                    time.sleep(60)  # 每分鐘檢查一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"註冊表監控錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_registry, daemon=True)
        thread.start()
        self.detection_threads.append(thread)
    
    def _check_registry_key(self, key_path: str):
        """檢查註冊表項"""
        try:
            # 使用 reg 命令查詢註冊表
            result = subprocess.run(['reg', 'query', key_path], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'REG_SZ' in line or 'REG_EXPAND_SZ' in line:
                        # 解析註冊表值
                        parts = line.split()
                        if len(parts) >= 3:
                            value_name = parts[0]
                            value_data = ' '.join(parts[2:])
                            
                            # 檢查可疑的註冊表值
                            if self._is_suspicious_registry_value(value_name, value_data):
                                self._log_threat({
                                    'type': 'SUSPICIOUS_REGISTRY',
                                    'key_path': key_path,
                                    'value_name': value_name,
                                    'value_data': value_data,
                                    'threat_level': 'HIGH',
                                    'timestamp': datetime.now().isoformat()
                                })
                                
        except Exception as e:
            logger.debug(f"註冊表檢查錯誤 {key_path}: {e}")
    
    def _is_suspicious_registry_value(self, name: str, data: str) -> bool:
        """檢查是否為可疑的註冊表值"""
        try:
            # 檢查可疑的文件路徑
            suspicious_paths = [
                'temp', 'appdata', 'users', 'downloads',
                'desktop', 'documents', 'pictures'
            ]
            
            data_lower = data.lower()
            for path in suspicious_paths:
                if path in data_lower and any(ext in data_lower for ext in ['.exe', '.bat', '.cmd', '.ps1']):
                    return True
            
            # 檢查可疑的命令
            suspicious_commands = [
                'powershell', 'cmd', 'rundll32', 'regsvr32',
                'wscript', 'cscript', 'mshta'
            ]
            
            for cmd in suspicious_commands:
                if cmd in data_lower:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"註冊表值檢查錯誤: {e}")
            return False
    
    def _start_memory_monitoring(self):
        """啟動記憶體監控"""
        def monitor_memory():
            logger.info("記憶體監控已啟動")
            
            while self.running:
                try:
                    # 檢查系統記憶體使用
                    memory = psutil.virtual_memory()
                    
                    if memory.percent > 90:  # 記憶體使用率超過90%
                        self._log_threat({
                            'type': 'HIGH_MEMORY_USAGE',
                            'memory_percent': memory.percent,
                            'available_mb': memory.available / 1024 / 1024,
                            'threat_level': 'MEDIUM',
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    # 檢查交換空間使用
                    swap = psutil.swap_memory()
                    if swap.percent > 80:  # 交換空間使用率超過80%
                        self._log_threat({
                            'type': 'HIGH_SWAP_USAGE',
                            'swap_percent': swap.percent,
                            'swap_used_mb': swap.used / 1024 / 1024,
                            'threat_level': 'LOW',
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    time.sleep(30)  # 每30秒檢查一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"記憶體監控錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_memory, daemon=True)
        thread.start()
        self.detection_threads.append(thread)
    
    def _log_threat(self, threat: Dict[str, Any]):
        """記錄威脅"""
        try:
            self.detected_threats.append(threat)
            
            # 根據威脅等級記錄日誌
            threat_level = threat.get('threat_level', 'UNKNOWN')
            if threat_level == 'CRITICAL':
                logger.critical(f"🚨 嚴重威脅: {threat['type']} - {threat}")
            elif threat_level == 'HIGH':
                logger.error(f"⚠️ 高級威脅: {threat['type']} - {threat}")
            elif threat_level == 'MEDIUM':
                logger.warning(f"⚠️ 中級威脅: {threat['type']} - {threat}")
            else:
                logger.info(f"ℹ️ 低級威脅: {threat['type']} - {threat}")
            
        except Exception as e:
            logger.error(f"記錄威脅錯誤: {e}")
    
    def _start_suricata_monitoring(self):
        """啟動Suricata EVE JSON監控"""
        def monitor_suricata():
            logger.info("Suricata EVE JSON監控已啟動")
            
            eve_file = self.external_log_config['suricata_eve']
            if not os.path.exists(eve_file):
                logger.warning(f"Suricata EVE文件不存在: {eve_file}")
                return
            
            try:
                with open(eve_file, 'r', encoding='utf-8') as f:
                    # 移動到文件末尾
                    f.seek(0, 2)
                    
                    while self.running:
                        line = f.readline()
                        if line:
                            try:
                                event = json.loads(line.strip())
                                self._process_suricata_event(event)
                            except json.JSONDecodeError:
                                continue
                        else:
                            time.sleep(1)
                            
            except Exception as e:
                if self.running:
                    logger.error(f"Suricata監控錯誤: {e}")
        
        thread = threading.Thread(target=monitor_suricata, daemon=True)
        thread.start()
        self.detection_threads.append(thread)
    
    def _process_suricata_event(self, event: Dict[str, Any]):
        """處理Suricata事件"""
        try:
            event_type = event.get('event_type', '')
            timestamp = event.get('timestamp', datetime.now().isoformat())
            
            if event_type == 'alert':
                alert = event.get('alert', {})
                signature = alert.get('signature', '')
                severity = alert.get('severity', 3)
                
                # 創建威脅記錄
                threat = {
                    'type': 'SURICATA_ALERT',
                    'source': 'Suricata IDS',
                    'severity': 'HIGH' if severity <= 2 else 'MEDIUM' if severity <= 3 else 'LOW',
                    'signature': signature,
                    'src_ip': event.get('src_ip', ''),
                    'dest_ip': event.get('dest_ip', ''),
                    'src_port': event.get('src_port', 0),
                    'dest_port': event.get('dest_port', 0),
                    'proto': event.get('proto', ''),
                    'timestamp': timestamp,
                    'raw_event': event
                }
                
                self.detected_threats.append(threat)
                self._log_threat(threat)
                
            elif event_type == 'dns':
                dns = event.get('dns', {})
                query = dns.get('query', '')
                
                # 檢查可疑DNS查詢
                if self._is_suspicious_dns_query(query):
                    threat = {
                        'type': 'SUSPICIOUS_DNS',
                        'source': 'Suricata DNS',
                        'severity': 'MEDIUM',
                        'query': query,
                        'src_ip': event.get('src_ip', ''),
                        'timestamp': timestamp,
                        'raw_event': event
                    }
                    
                    self.detected_threats.append(threat)
                    self._log_threat(threat)
                    
        except Exception as e:
            logger.error(f"處理Suricata事件錯誤: {e}")
    
    def _is_suspicious_dns_query(self, query: str) -> bool:
        """檢查是否為可疑DNS查詢"""
        suspicious_patterns = [
            r'.*\.bit$',  # BitCoin域名
            r'.*\.onion$',  # Tor域名
            r'.*\.(tk|ml|ga|cf)$',  # 免費域名
            r'^[a-f0-9]{32,}\..*',  # 長隨機字符串
            r'.*dga.*',  # DGA關鍵字
            r'.*malware.*',  # 惡意程式關鍵字
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, query, re.IGNORECASE):
                return True
        
        return False
    
    def _start_sysmon_monitoring(self):
        """啟動Sysmon EVTX監控"""
        def monitor_sysmon():
            logger.info("Sysmon EVTX監控已啟動")
            
            # 檢查是否為Windows系統
            if os.name != 'nt':
                logger.warning("Sysmon監控僅支援Windows系統")
                return
            
            try:
                import win32evtlog
                import win32con
                import win32evtlogutil
                
                log_type = "Microsoft-Windows-Sysmon/Operational"
                hand = win32evtlog.OpenEventLog(None, log_type)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                
                while self.running:
                    try:
                        events = win32evtlog.ReadEventLog(hand, flags, 0)
                        if events:
                            for event in events:
                                self._process_sysmon_event(event)
                        else:
                            time.sleep(5)
                    except Exception as e:
                        if self.running:
                            logger.debug(f"Sysmon事件讀取: {e}")
                        time.sleep(10)
                        
                win32evtlog.CloseEventLog(hand)
                
            except ImportError:
                logger.error("需要安裝pywin32套件才能監控Sysmon: pip install pywin32")
            except Exception as e:
                if self.running:
                    logger.error(f"Sysmon監控錯誤: {e}")
        
        thread = threading.Thread(target=monitor_sysmon, daemon=True)
        thread.start()
        self.detection_threads.append(thread)
    
    def _process_sysmon_event(self, event):
        """處理Sysmon事件"""
        try:
            event_id = event.EventID
            timestamp = event.TimeGenerated.Format()
            
            # 處理不同類型的Sysmon事件
            if event_id == 1:  # Process creation
                self._process_sysmon_process_creation(event, timestamp)
            elif event_id == 3:  # Network connection
                self._process_sysmon_network_connection(event, timestamp)
            elif event_id == 7:  # Image loaded
                self._process_sysmon_image_loaded(event, timestamp)
            elif event_id == 8:  # CreateRemoteThread
                self._process_sysmon_remote_thread(event, timestamp)
            elif event_id == 11:  # FileCreate
                self._process_sysmon_file_create(event, timestamp)
            elif event_id in [12, 13, 14]:  # Registry events
                self._process_sysmon_registry_event(event, timestamp)
            elif event_id == 22:  # DNS query
                self._process_sysmon_dns_query(event, timestamp)
                
        except Exception as e:
            logger.error(f"處理Sysmon事件錯誤: {e}")
    
    def _process_sysmon_process_creation(self, event, timestamp: str):
        """處理Sysmon進程創建事件"""
        try:
            # 解析事件數據
            event_data = win32evtlogutil.SafeFormatMessage(event, None)
            
            # 檢查可疑進程
            if self._is_suspicious_process_creation(event_data):
                threat = {
                    'type': 'SUSPICIOUS_PROCESS',
                    'source': 'Sysmon',
                    'severity': 'HIGH',
                    'event_id': 1,
                    'timestamp': timestamp,
                    'event_data': event_data
                }
                
                self.detected_threats.append(threat)
                self._log_threat(threat)
                
        except Exception as e:
            logger.error(f"處理Sysmon進程創建錯誤: {e}")
    
    def _is_suspicious_process_creation(self, event_data: str) -> bool:
        """檢查是否為可疑進程創建"""
        suspicious_patterns = [
            r'powershell.*-enc.*',  # 編碼的PowerShell
            r'cmd.*\/c.*echo.*',  # 可疑命令執行
            r'.*regsvr32.*scrobj\.dll.*',  # 無文件攻擊
            r'.*rundll32.*javascript.*',  # JavaScript執行
            r'.*wscript.*\.vbs.*',  # VBScript執行
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, event_data, re.IGNORECASE):
                return True
        
        return False
    
    def _process_sysmon_network_connection(self, event, timestamp: str):
        """處理Sysmon網路連接事件"""
        try:
            event_data = win32evtlogutil.SafeFormatMessage(event, None)
            
            # 檢查可疑網路連接
            if self._is_suspicious_network_connection(event_data):
                threat = {
                    'type': 'SUSPICIOUS_NETWORK',
                    'source': 'Sysmon',
                    'severity': 'MEDIUM',
                    'event_id': 3,
                    'timestamp': timestamp,
                    'event_data': event_data
                }
                
                self.detected_threats.append(threat)
                self._log_threat(threat)
                
        except Exception as e:
            logger.error(f"處理Sysmon網路連接錯誤: {e}")
    
    def _is_suspicious_network_connection(self, event_data: str) -> bool:
        """檢查是否為可疑網路連接"""
        suspicious_patterns = [
            r'.*:443.*',  # HTTPS連接（可能的C2）
            r'.*:8080.*',  # 代理端口
            r'.*:4444.*',  # 常見後門端口
            r'.*\.onion.*',  # Tor連接
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, event_data, re.IGNORECASE):
                return True
        
        return False
    
    def _process_sysmon_image_loaded(self, event, timestamp: str):
        """處理Sysmon映像載入事件"""
        # 實現映像載入檢測邏輯
        pass
    
    def _process_sysmon_remote_thread(self, event, timestamp: str):
        """處理Sysmon遠程線程事件"""
        try:
            event_data = win32evtlogutil.SafeFormatMessage(event, None)
            
            # 遠程線程創建通常表示代碼注入
            threat = {
                'type': 'CODE_INJECTION',
                'source': 'Sysmon',
                'severity': 'HIGH',
                'event_id': 8,
                'timestamp': timestamp,
                'event_data': event_data
            }
            
            self.detected_threats.append(threat)
            self._log_threat(threat)
            
        except Exception as e:
            logger.error(f"處理Sysmon遠程線程錯誤: {e}")
    
    def _process_sysmon_file_create(self, event, timestamp: str):
        """處理Sysmon文件創建事件"""
        # 實現文件創建檢測邏輯
        pass
    
    def _process_sysmon_registry_event(self, event, timestamp: str):
        """處理Sysmon註冊表事件"""
        # 實現註冊表檢測邏輯
        pass
    
    def _process_sysmon_dns_query(self, event, timestamp: str):
        """處理Sysmon DNS查詢事件"""
        try:
            event_data = win32evtlogutil.SafeFormatMessage(event, None)
            
            # 從事件數據提取DNS查詢
            query_match = re.search(r'QueryName:\s*([^\s]+)', event_data)
            if query_match:
                query = query_match.group(1)
                
                if self._is_suspicious_dns_query(query):
                    threat = {
                        'type': 'SUSPICIOUS_DNS',
                        'source': 'Sysmon',
                        'severity': 'MEDIUM',
                        'event_id': 22,
                        'query': query,
                        'timestamp': timestamp,
                        'event_data': event_data
                    }
                    
                    self.detected_threats.append(threat)
                    self._log_threat(threat)
                    
        except Exception as e:
            logger.error(f"處理Sysmon DNS查詢錯誤: {e}")
    
    def stop_detection(self) -> Dict[str, Any]:
        """停止威脅檢測"""
        try:
            self.running = False
            
            # 等待所有線程結束
            for thread in self.detection_threads:
                thread.join(timeout=5)
            
            self.detection_threads.clear()
            
            logger.info("威脅檢測已停止")
            return {'success': True, 'message': '檢測已停止'}
            
        except Exception as e:
            logger.error(f"停止檢測錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_detection_status(self) -> Dict[str, Any]:
        """獲取檢測狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'total_threats_detected': len(self.detected_threats),
                'threat_levels': {
                    'CRITICAL': len([t for t in self.detected_threats if t.get('threat_level') == 'CRITICAL']),
                    'HIGH': len([t for t in self.detected_threats if t.get('threat_level') == 'HIGH']),
                    'MEDIUM': len([t for t in self.detected_threats if t.get('threat_level') == 'MEDIUM']),
                    'LOW': len([t for t in self.detected_threats if t.get('threat_level') == 'LOW'])
                },
                'recent_threats': self.detected_threats[-10:] if self.detected_threats else []
            }
        except Exception as e:
            logger.error(f"獲取檢測狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_threat_report(self) -> Dict[str, Any]:
        """獲取威脅報告"""
        try:
            # 統計威脅類型
            threat_types = {}
            for threat in self.detected_threats:
                threat_type = threat.get('type', 'UNKNOWN')
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
            
            # 統計威脅等級
            threat_levels = {}
            for threat in self.detected_threats:
                level = threat.get('threat_level', 'UNKNOWN')
                threat_levels[level] = threat_levels.get(level, 0) + 1
            
            return {
                'success': True,
                'total_threats': len(self.detected_threats),
                'threat_types': threat_types,
                'threat_levels': threat_levels,
                'all_threats': self.detected_threats,
                'detection_summary': {
                    'files_scanned': len(self.file_hashes),
                    'processes_monitored': len(self.process_monitor),
                    'yara_rules_loaded': 1 if self.yara_rules else 0
                }
            }
        except Exception as e:
            logger.error(f"獲取威脅報告錯誤: {e}")
            return {'success': False, 'error': str(e)}


def main():
    """主函數"""
    config = {
        'log_level': 'INFO',
        'scan_interval': 30
    }
    
    detector = RealThreatDetector(config)
    
    try:
        # 啟動檢測
        result = detector.start_detection()
        if result['success']:
            print("✅ 真實威脅檢測系統已啟動")
            print("按 Ctrl+C 停止檢測")
            
            # 持續運行
            while True:
                time.sleep(1)
        else:
            print(f"❌ 啟動失敗: {result['error']}")
            
    except KeyboardInterrupt:
        print("\n🛑 正在停止檢測...")
        detector.stop_detection()
        print("✅ 檢測已停止")
    except Exception as e:
        print(f"❌ 系統錯誤: {e}")


if __name__ == "__main__":
    main()

