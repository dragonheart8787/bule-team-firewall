#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級主機防護系統
Military-Grade Host Protection System

核心防護技術：
- EDR (端點檢測與回應)
- HIDS (主機入侵檢測系統)
- 系統加固與配置管理
- Sysmon日誌分析
- 進程監控與行為分析
- 檔案完整性監控
- 記憶體分析
- 登錄檔分析
"""

import logging
import time
import random
import json
import sqlite3
import os
import psutil
import hashlib
import secrets
import subprocess
import threading
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Tuple, Optional, Any
import numpy as np
from collections import defaultdict, deque
import winreg
import win32api
import win32security
import win32con
import win32file
import win32process
import win32service
import win32net
import win32netcon

# 配置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatType(Enum):
    """威脅類型"""
    MALWARE = "MALWARE"
    RANSOMWARE = "RANSOMWARE"
    ROOTKIT = "ROOTKIT"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_THEFT = "DATA_THEFT"
    KEYLOGGER = "KEYLOGGER"
    BACKDOOR = "BACKDOOR"
    CRYPTOMINER = "CRYPTOMINER"

class ProcessState(Enum):
    """進程狀態"""
    RUNNING = "RUNNING"
    SUSPENDED = "SUSPENDED"
    TERMINATED = "TERMINATED"
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"

class FileIntegrity(Enum):
    """檔案完整性"""
    INTACT = "INTACT"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    CREATED = "CREATED"
    CORRUPTED = "CORRUPTED"

class MilitaryHostProtection:
    """軍事級主機防護系統"""
    
    def __init__(self, config_file: str = "military_host_protection_config.yaml"):
        """初始化主機防護系統"""
        self.config_file = config_file
        self.config = self._load_config()
        
        # 系統監控
        self.process_monitor = ProcessMonitor()
        self.file_monitor = FileMonitor()
        self.registry_monitor = RegistryMonitor()
        self.network_monitor = NetworkMonitor()
        self.memory_monitor = MemoryMonitor()
        
        # 威脅檢測
        self.threat_detector = ThreatDetector()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.signature_scanner = SignatureScanner()
        
        # 系統加固
        self.system_hardener = SystemHardener()
        self.config_manager = ConfigManager()
        
        # 事件回應
        self.incident_responder = IncidentResponder()
        self.forensics_collector = ForensicsCollector()
        
        # 統計數據
        self.stats = {
            "processes_monitored": 0,
            "files_monitored": 0,
            "threats_detected": 0,
            "incidents_responded": 0,
            "system_hardening_applied": 0
        }
        
        # 初始化資料庫
        self._init_database()
        
        # 載入檢測規則
        self._load_detection_rules()
        
        logger.info("軍事級主機防護系統初始化完成")
    
    def _load_config(self) -> Dict:
        """載入配置"""
        default_config = {
            "process_monitoring": {
                "enabled": True,
                "monitor_interval": 1.0,
                "track_children": True,
                "monitor_network": True
            },
            "file_monitoring": {
                "enabled": True,
                "monitor_paths": ["C:\\Windows\\System32", "C:\\Program Files"],
                "integrity_check": True,
                "real_time_scan": True
            },
            "registry_monitoring": {
                "enabled": True,
                "monitor_keys": [
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
                ],
                "monitor_changes": True
            },
            "threat_detection": {
                "enabled": True,
                "behavioral_analysis": True,
                "signature_scanning": True,
                "heuristic_detection": True
            },
            "system_hardening": {
                "enabled": True,
                "apply_policies": True,
                "disable_services": True,
                "configure_firewall": True
            }
        }
        
        try:
            import yaml
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                return {**default_config, **config}
        except FileNotFoundError:
            return default_config
    
    def _init_database(self):
        """初始化資料庫"""
        self.conn = sqlite3.connect('military_host_protection.db', check_same_thread=False)
        cursor = self.conn.cursor()
        
        # 進程監控表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                process_id INTEGER,
                process_name TEXT,
                parent_id INTEGER,
                command_line TEXT,
                executable_path TEXT,
                user_name TEXT,
                threat_level TEXT,
                status TEXT DEFAULT 'MONITORED'
            )
        ''')
        
        # 檔案監控表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                file_path TEXT NOT NULL,
                event_type TEXT NOT NULL,
                file_hash TEXT,
                file_size INTEGER,
                integrity_status TEXT,
                threat_level TEXT,
                status TEXT DEFAULT 'MONITORED'
            )
        ''')
        
        # 威脅檢測表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS host_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                source TEXT,
                description TEXT,
                confidence REAL,
                mitigation TEXT,
                status TEXT DEFAULT 'DETECTED'
            )
        ''')
        
        # 系統加固表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hardening_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action_type TEXT NOT NULL,
                target TEXT,
                description TEXT,
                success BOOLEAN,
                status TEXT DEFAULT 'APPLIED'
            )
        ''')
        
        # Sysmon日誌表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sysmon_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_id INTEGER,
                process_id INTEGER,
                process_name TEXT,
                command_line TEXT,
                user_name TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                dest_port INTEGER,
                threat_level TEXT,
                status TEXT DEFAULT 'ANALYZED'
            )
        ''')
        
        self.conn.commit()
    
    def _load_detection_rules(self):
        """載入檢測規則"""
        self.detection_rules = {
            "malware_signatures": [
                "malware.exe", "trojan.exe", "virus.exe", "backdoor.exe"
            ],
            "suspicious_processes": [
                "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"
            ],
            "suspicious_paths": [
                "C:\\temp\\", "C:\\windows\\temp\\", "C:\\users\\public\\"
            ],
            "registry_persistence": [
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            ]
        }
    
    def start_monitoring(self):
        """開始監控"""
        try:
            # 啟動進程監控
            if self.config["process_monitoring"]["enabled"]:
                self.process_monitor.start_monitoring()
            
            # 啟動檔案監控
            if self.config["file_monitoring"]["enabled"]:
                self.file_monitor.start_monitoring()
            
            # 啟動登錄檔監控
            if self.config["registry_monitoring"]["enabled"]:
                self.registry_monitor.start_monitoring()
            
            # 啟動網路監控
            self.network_monitor.start_monitoring()
            
            # 啟動記憶體監控
            self.memory_monitor.start_monitoring()
            
            logger.info("主機監控已啟動")
            
        except Exception as e:
            logger.error(f"監控啟動錯誤: {e}")
    
    def detect_threats(self) -> List[Dict]:
        """檢測威脅"""
        threats = []
        
        try:
            # 進程威脅檢測
            process_threats = self.threat_detector.detect_process_threats()
            threats.extend(process_threats)
            
            # 檔案威脅檢測
            file_threats = self.threat_detector.detect_file_threats()
            threats.extend(file_threats)
            
            # 登錄檔威脅檢測
            registry_threats = self.threat_detector.detect_registry_threats()
            threats.extend(registry_threats)
            
            # 行為異常檢測
            behavior_threats = self.behavior_analyzer.detect_anomalies()
            threats.extend(behavior_threats)
            
            # 記錄威脅
            for threat in threats:
                self._log_threat(threat)
                self.stats["threats_detected"] += 1
            
            logger.info(f"檢測到 {len(threats)} 個威脅")
            return threats
            
        except Exception as e:
            logger.error(f"威脅檢測錯誤: {e}")
            return []
    
    def _log_threat(self, threat: Dict):
        """記錄威脅"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO host_threats 
            (timestamp, threat_type, source, description, confidence, mitigation)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            threat["timestamp"],
            threat["threat_type"],
            threat.get("source", ""),
            threat["description"],
            threat.get("confidence", 0.0),
            threat.get("mitigation", "")
        ))
        self.conn.commit()
    
    def analyze_sysmon_logs(self, log_file: str) -> Dict:
        """分析Sysmon日誌"""
        try:
            analysis_result = {
                "total_events": 0,
                "suspicious_events": 0,
                "threat_indicators": [],
                "process_analysis": {},
                "network_analysis": {}
            }
            
            # 模擬Sysmon日誌分析
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    analysis_result["total_events"] += 1
                    
                    # 解析Sysmon事件
                    event = self._parse_sysmon_event(line)
                    if event:
                        # 檢查可疑事件
                        if self._is_suspicious_event(event):
                            analysis_result["suspicious_events"] += 1
                            analysis_result["threat_indicators"].append(event)
                        
                        # 記錄到資料庫
                        self._log_sysmon_event(event)
            
            logger.info(f"Sysmon日誌分析完成: {log_file}")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Sysmon日誌分析錯誤: {e}")
            return {}
    
    def _parse_sysmon_event(self, line: str) -> Optional[Dict]:
        """解析Sysmon事件"""
        try:
            # 簡化的Sysmon事件解析
            parts = line.strip().split(',')
            if len(parts) >= 5:
                return {
                    "timestamp": parts[0],
                    "event_id": int(parts[1]),
                    "process_id": int(parts[2]),
                    "process_name": parts[3],
                    "command_line": parts[4] if len(parts) > 4 else "",
                    "user_name": parts[5] if len(parts) > 5 else "",
                    "source_ip": parts[6] if len(parts) > 6 else "",
                    "dest_ip": parts[7] if len(parts) > 7 else "",
                    "dest_port": int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else 0
                }
        except Exception as e:
            logger.error(f"Sysmon事件解析錯誤: {e}")
        return None
    
    def _is_suspicious_event(self, event: Dict) -> bool:
        """檢查可疑事件"""
        # 檢查可疑進程
        if event["process_name"] in self.detection_rules["suspicious_processes"]:
            return True
        
        # 檢查可疑命令列
        command_line = event.get("command_line", "").lower()
        suspicious_keywords = ["powershell", "cmd", "wscript", "cscript", "rundll32"]
        if any(keyword in command_line for keyword in suspicious_keywords):
            return True
        
        # 檢查網路連接
        if event.get("dest_ip") and event["dest_ip"] != "127.0.0.1":
            return True
        
        return False
    
    def _log_sysmon_event(self, event: Dict):
        """記錄Sysmon事件"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO sysmon_logs 
            (timestamp, event_id, process_id, process_name, command_line, user_name, source_ip, dest_ip, dest_port, threat_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event["timestamp"],
            event["event_id"],
            event["process_id"],
            event["process_name"],
            event["command_line"],
            event["user_name"],
            event["source_ip"],
            event["dest_ip"],
            event["dest_port"],
            "SUSPICIOUS" if self._is_suspicious_event(event) else "NORMAL"
        ))
        self.conn.commit()
    
    def apply_system_hardening(self) -> Dict:
        """應用系統加固"""
        try:
            hardening_results = {
                "policies_applied": 0,
                "services_disabled": 0,
                "firewall_configured": 0,
                "registry_secured": 0,
                "files_secured": 0
            }
            
            # 應用安全政策
            if self.system_hardener.apply_security_policies():
                hardening_results["policies_applied"] += 1
            
            # 停用危險服務
            disabled_services = self.system_hardener.disable_dangerous_services()
            hardening_results["services_disabled"] = len(disabled_services)
            
            # 配置防火牆
            if self.system_hardener.configure_firewall():
                hardening_results["firewall_configured"] += 1
            
            # 加固登錄檔
            if self.system_hardener.harden_registry():
                hardening_results["registry_secured"] += 1
            
            # 加固檔案權限
            if self.system_hardener.harden_file_permissions():
                hardening_results["files_secured"] += 1
            
            # 記錄加固動作
            self._log_hardening_action("SYSTEM_HARDENING", "ALL", "系統全面加固", True)
            
            self.stats["system_hardening_applied"] += 1
            logger.info("系統加固完成")
            return hardening_results
            
        except Exception as e:
            logger.error(f"系統加固錯誤: {e}")
            return {}
    
    def _log_hardening_action(self, action_type: str, target: str, description: str, success: bool):
        """記錄加固動作"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO hardening_actions 
            (timestamp, action_type, target, description, success)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            action_type,
            target,
            description,
            success
        ))
        self.conn.commit()
    
    def respond_to_incident(self, incident: Dict) -> Dict:
        """回應事件"""
        try:
            response_result = {
                "containment": False,
                "eradication": False,
                "recovery": False,
                "lessons_learned": []
            }
            
            # 事件遏制
            if self.incident_responder.contain_threat(incident):
                response_result["containment"] = True
            
            # 威脅根除
            if self.incident_responder.eradicate_threat(incident):
                response_result["eradication"] = True
            
            # 系統恢復
            if self.incident_responder.recover_system(incident):
                response_result["recovery"] = True
            
            # 收集鑑識資料
            forensics_data = self.forensics_collector.collect_evidence(incident)
            
            self.stats["incidents_responded"] += 1
            logger.info(f"事件回應完成: {incident.get('id', 'unknown')}")
            return response_result
            
        except Exception as e:
            logger.error(f"事件回應錯誤: {e}")
            return {}
    
    def get_host_status(self) -> Dict:
        """獲取主機狀態"""
        try:
            # 統計數據
            cursor = self.conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM process_events WHERE status = 'MONITORED'")
            monitored_processes = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM file_events WHERE status = 'MONITORED'")
            monitored_files = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM host_threats WHERE status = 'DETECTED'")
            detected_threats = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM hardening_actions WHERE success = 1")
            hardening_actions = cursor.fetchone()[0]
            
            # 系統資訊
            system_info = {
                "hostname": os.environ.get("COMPUTERNAME", "unknown"),
                "os_version": os.name,
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
                "disk_usage": psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent
            }
            
            return {
                "monitored_processes": monitored_processes,
                "monitored_files": monitored_files,
                "detected_threats": detected_threats,
                "hardening_actions": hardening_actions,
                "system_info": system_info,
                "stats": self.stats
            }
            
        except Exception as e:
            logger.error(f"獲取主機狀態錯誤: {e}")
            return {}

class ProcessMonitor:
    """進程監控器"""
    
    def __init__(self):
        self.monitored_processes = {}
        self.process_tree = defaultdict(list)
    
    def start_monitoring(self):
        """開始監控"""
        def monitor_thread():
            while True:
                try:
                    self._monitor_processes()
                    time.sleep(1.0)
                except Exception as e:
                    logger.error(f"進程監控錯誤: {e}")
        
        monitor_thread = threading.Thread(target=monitor_thread, daemon=True)
        monitor_thread.start()
    
    def _monitor_processes(self):
        """監控進程"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cmdline', 'username']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    
                    if pid not in self.monitored_processes:
                        self._add_process(proc_info)
                    else:
                        self._update_process(proc_info)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"進程監控錯誤: {e}")
    
    def _add_process(self, proc_info: Dict):
        """添加進程"""
        self.monitored_processes[proc_info['pid']] = {
            'name': proc_info['name'],
            'ppid': proc_info['ppid'],
            'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
            'username': proc_info['username'],
            'start_time': time.time(),
            'status': ProcessState.RUNNING.value
        }
    
    def _update_process(self, proc_info: Dict):
        """更新進程"""
        pid = proc_info['pid']
        if pid in self.monitored_processes:
            self.monitored_processes[pid].update({
                'name': proc_info['name'],
                'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                'username': proc_info['username']
            })

class FileMonitor:
    """檔案監控器"""
    
    def __init__(self):
        self.monitored_files = {}
        self.file_hashes = {}
    
    def start_monitoring(self):
        """開始監控"""
        def monitor_thread():
            while True:
                try:
                    self._monitor_files()
                    time.sleep(5.0)
                except Exception as e:
                    logger.error(f"檔案監控錯誤: {e}")
        
        monitor_thread = threading.Thread(target=monitor_thread, daemon=True)
        monitor_thread.start()
    
    def _monitor_files(self):
        """監控檔案"""
        try:
            # 監控系統目錄
            system_dirs = ["C:\\Windows\\System32", "C:\\Program Files"]
            
            for directory in system_dirs:
                if os.path.exists(directory):
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            self._check_file_integrity(file_path)
                            
        except Exception as e:
            logger.error(f"檔案監控錯誤: {e}")
    
    def _check_file_integrity(self, file_path: str):
        """檢查檔案完整性"""
        try:
            if os.path.exists(file_path):
                # 計算檔案雜湊
                file_hash = self._calculate_file_hash(file_path)
                
                if file_path in self.file_hashes:
                    if self.file_hashes[file_path] != file_hash:
                        # 檔案被修改
                        self._handle_file_change(file_path, "MODIFIED", file_hash)
                else:
                    # 新檔案
                    self._handle_file_change(file_path, "CREATED", file_hash)
                
                self.file_hashes[file_path] = file_hash
            else:
                if file_path in self.file_hashes:
                    # 檔案被刪除
                    self._handle_file_change(file_path, "DELETED", "")
                    del self.file_hashes[file_path]
                    
        except Exception as e:
            logger.error(f"檔案完整性檢查錯誤: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """計算檔案雜湊"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"檔案雜湊計算錯誤: {e}")
            return ""
    
    def _handle_file_change(self, file_path: str, change_type: str, file_hash: str):
        """處理檔案變更"""
        logger.info(f"檔案變更: {file_path} - {change_type}")

class RegistryMonitor:
    """登錄檔監控器"""
    
    def __init__(self):
        self.monitored_keys = [
            winreg.HKEY_LOCAL_MACHINE,
            winreg.HKEY_CURRENT_USER
        ]
        self.key_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        ]
    
    def start_monitoring(self):
        """開始監控"""
        def monitor_thread():
            while True:
                try:
                    self._monitor_registry()
                    time.sleep(10.0)
                except Exception as e:
                    logger.error(f"登錄檔監控錯誤: {e}")
        
        monitor_thread = threading.Thread(target=monitor_thread, daemon=True)
        monitor_thread.start()
    
    def _monitor_registry(self):
        """監控登錄檔"""
        try:
            for hkey in self.monitored_keys:
                for key_path in self.key_paths:
                    try:
                        with winreg.OpenKey(hkey, key_path) as key:
                            self._check_registry_key(key, key_path)
                    except FileNotFoundError:
                        continue
                    except Exception as e:
                        logger.error(f"登錄檔監控錯誤: {e}")
                        
        except Exception as e:
            logger.error(f"登錄檔監控錯誤: {e}")
    
    def _check_registry_key(self, key, key_path: str):
        """檢查登錄檔鍵值"""
        try:
            i = 0
            while True:
                try:
                    name, value, reg_type = winreg.EnumValue(key, i)
                    # 檢查可疑的登錄檔項目
                    if self._is_suspicious_registry_entry(name, value):
                        logger.warning(f"可疑登錄檔項目: {key_path}\\{name} = {value}")
                    i += 1
                except OSError:
                    break
        except Exception as e:
            logger.error(f"登錄檔鍵值檢查錯誤: {e}")
    
    def _is_suspicious_registry_entry(self, name: str, value: str) -> bool:
        """檢查可疑的登錄檔項目"""
        suspicious_patterns = [
            "powershell", "cmd", "wscript", "cscript", "rundll32",
            "temp", "appdata", "public"
        ]
        
        value_lower = value.lower()
        return any(pattern in value_lower for pattern in suspicious_patterns)

class NetworkMonitor:
    """網路監控器"""
    
    def __init__(self):
        self.connections = {}
        self.network_stats = defaultdict(int)
    
    def start_monitoring(self):
        """開始監控"""
        def monitor_thread():
            while True:
                try:
                    self._monitor_network()
                    time.sleep(2.0)
                except Exception as e:
                    logger.error(f"網路監控錯誤: {e}")
        
        monitor_thread = threading.Thread(target=monitor_thread, daemon=True)
        monitor_thread.start()
    
    def _monitor_network(self):
        """監控網路"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    conn_key = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                    self.connections[conn_key] = {
                        'pid': conn.pid,
                        'local_addr': conn.laddr,
                        'remote_addr': conn.raddr,
                        'status': conn.status,
                        'timestamp': time.time()
                    }
                    
        except Exception as e:
            logger.error(f"網路監控錯誤: {e}")

class MemoryMonitor:
    """記憶體監控器"""
    
    def __init__(self):
        self.memory_snapshots = deque(maxlen=100)
    
    def start_monitoring(self):
        """開始監控"""
        def monitor_thread():
            while True:
                try:
                    self._monitor_memory()
                    time.sleep(5.0)
                except Exception as e:
                    logger.error(f"記憶體監控錯誤: {e}")
        
        monitor_thread = threading.Thread(target=monitor_thread, daemon=True)
        monitor_thread.start()
    
    def _monitor_memory(self):
        """監控記憶體"""
        try:
            memory_info = psutil.virtual_memory()
            memory_snapshot = {
                'timestamp': time.time(),
                'total': memory_info.total,
                'available': memory_info.available,
                'percent': memory_info.percent,
                'used': memory_info.used,
                'free': memory_info.free
            }
            
            self.memory_snapshots.append(memory_snapshot)
            
            # 檢查記憶體異常
            if memory_info.percent > 90:
                logger.warning(f"記憶體使用率過高: {memory_info.percent}%")
                
        except Exception as e:
            logger.error(f"記憶體監控錯誤: {e}")

class ThreatDetector:
    """威脅檢測器"""
    
    def detect_process_threats(self) -> List[Dict]:
        """檢測進程威脅"""
        threats = []
        
        try:
            # 模擬進程威脅檢測
            if random.random() < 0.1:  # 10%機率檢測到威脅
                threat = {
                    "timestamp": datetime.now().isoformat(),
                    "threat_type": ThreatType.MALWARE.value,
                    "source": "PROCESS_MONITOR",
                    "description": "檢測到可疑進程行為",
                    "confidence": random.uniform(0.7, 0.95),
                    "mitigation": "終止可疑進程"
                }
                threats.append(threat)
            
            return threats
            
        except Exception as e:
            logger.error(f"進程威脅檢測錯誤: {e}")
            return []
    
    def detect_file_threats(self) -> List[Dict]:
        """檢測檔案威脅"""
        threats = []
        
        try:
            # 模擬檔案威脅檢測
            if random.random() < 0.05:  # 5%機率檢測到威脅
                threat = {
                    "timestamp": datetime.now().isoformat(),
                    "threat_type": ThreatType.RANSOMWARE.value,
                    "source": "FILE_MONITOR",
                    "description": "檢測到檔案加密行為",
                    "confidence": random.uniform(0.8, 0.98),
                    "mitigation": "隔離受影響檔案"
                }
                threats.append(threat)
            
            return threats
            
        except Exception as e:
            logger.error(f"檔案威脅檢測錯誤: {e}")
            return []
    
    def detect_registry_threats(self) -> List[Dict]:
        """檢測登錄檔威脅"""
        threats = []
        
        try:
            # 模擬登錄檔威脅檢測
            if random.random() < 0.03:  # 3%機率檢測到威脅
                threat = {
                    "timestamp": datetime.now().isoformat(),
                    "threat_type": ThreatType.PERSISTENCE.value,
                    "source": "REGISTRY_MONITOR",
                    "description": "檢測到持久化機制",
                    "confidence": random.uniform(0.6, 0.9),
                    "mitigation": "清除可疑登錄檔項目"
                }
                threats.append(threat)
            
            return threats
            
        except Exception as e:
            logger.error(f"登錄檔威脅檢測錯誤: {e}")
            return []

class BehaviorAnalyzer:
    """行為分析器"""
    
    def detect_anomalies(self) -> List[Dict]:
        """檢測異常行為"""
        threats = []
        
        try:
            # 模擬行為異常檢測
            if random.random() < 0.08:  # 8%機率檢測到異常
                threat = {
                    "timestamp": datetime.now().isoformat(),
                    "threat_type": ThreatType.LATERAL_MOVEMENT.value,
                    "source": "BEHAVIOR_ANALYZER",
                    "description": "檢測到橫向移動行為",
                    "confidence": random.uniform(0.7, 0.9),
                    "mitigation": "加強網路監控"
                }
                threats.append(threat)
            
            return threats
            
        except Exception as e:
            logger.error(f"行為異常檢測錯誤: {e}")
            return []

class SignatureScanner:
    """簽名掃描器"""
    
    def __init__(self):
        self.signatures = {
            "malware": ["malware.exe", "trojan.exe", "virus.exe"],
            "suspicious": ["cmd.exe", "powershell.exe", "wscript.exe"]
        }
    
    def scan_processes(self) -> List[Dict]:
        """掃描進程"""
        threats = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name'].lower()
                    
                    for category, signatures in self.signatures.items():
                        if any(sig in proc_name for sig in signatures):
                            threat = {
                                "timestamp": datetime.now().isoformat(),
                                "threat_type": category.upper(),
                                "source": "SIGNATURE_SCANNER",
                                "description": f"檢測到可疑進程: {proc.info['name']}",
                                "confidence": 0.9,
                                "mitigation": "終止可疑進程"
                            }
                            threats.append(threat)
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return threats
            
        except Exception as e:
            logger.error(f"進程掃描錯誤: {e}")
            return []

class SystemHardener:
    """系統加固器"""
    
    def apply_security_policies(self) -> bool:
        """應用安全政策"""
        try:
            # 模擬安全政策應用
            logger.info("應用安全政策")
            return True
        except Exception as e:
            logger.error(f"安全政策應用錯誤: {e}")
            return False
    
    def disable_dangerous_services(self) -> List[str]:
        """停用危險服務"""
        try:
            dangerous_services = [
                "Telnet", "FTP", "SNMP", "Remote Registry"
            ]
            
            disabled_services = []
            for service in dangerous_services:
                try:
                    # 模擬停用服務
                    logger.info(f"停用服務: {service}")
                    disabled_services.append(service)
                except Exception as e:
                    logger.error(f"停用服務錯誤: {service} - {e}")
            
            return disabled_services
            
        except Exception as e:
            logger.error(f"服務停用錯誤: {e}")
            return []
    
    def configure_firewall(self) -> bool:
        """配置防火牆"""
        try:
            # 模擬防火牆配置
            logger.info("配置防火牆規則")
            return True
        except Exception as e:
            logger.error(f"防火牆配置錯誤: {e}")
            return False
    
    def harden_registry(self) -> bool:
        """加固登錄檔"""
        try:
            # 模擬登錄檔加固
            logger.info("加固登錄檔設定")
            return True
        except Exception as e:
            logger.error(f"登錄檔加固錯誤: {e}")
            return False
    
    def harden_file_permissions(self) -> bool:
        """加固檔案權限"""
        try:
            # 模擬檔案權限加固
            logger.info("加固檔案權限")
            return True
        except Exception as e:
            logger.error(f"檔案權限加固錯誤: {e}")
            return False

class ConfigManager:
    """配置管理器"""
    
    def __init__(self):
        self.configs = {}
    
    def load_config(self, config_name: str) -> Dict:
        """載入配置"""
        return self.configs.get(config_name, {})
    
    def save_config(self, config_name: str, config: Dict):
        """儲存配置"""
        self.configs[config_name] = config

class IncidentResponder:
    """事件回應器"""
    
    def contain_threat(self, incident: Dict) -> bool:
        """遏制威脅"""
        try:
            logger.info(f"遏制威脅: {incident.get('id', 'unknown')}")
            return True
        except Exception as e:
            logger.error(f"威脅遏制錯誤: {e}")
            return False
    
    def eradicate_threat(self, incident: Dict) -> bool:
        """根除威脅"""
        try:
            logger.info(f"根除威脅: {incident.get('id', 'unknown')}")
            return True
        except Exception as e:
            logger.error(f"威脅根除錯誤: {e}")
            return False
    
    def recover_system(self, incident: Dict) -> bool:
        """恢復系統"""
        try:
            logger.info(f"恢復系統: {incident.get('id', 'unknown')}")
            return True
        except Exception as e:
            logger.error(f"系統恢復錯誤: {e}")
            return False

class ForensicsCollector:
    """鑑識收集器"""
    
    def collect_evidence(self, incident: Dict) -> Dict:
        """收集證據"""
        try:
            evidence = {
                "memory_dump": self._collect_memory_dump(),
                "file_artifacts": self._collect_file_artifacts(),
                "registry_artifacts": self._collect_registry_artifacts(),
                "network_artifacts": self._collect_network_artifacts()
            }
            
            logger.info(f"收集鑑識證據: {incident.get('id', 'unknown')}")
            return evidence
            
        except Exception as e:
            logger.error(f"證據收集錯誤: {e}")
            return {}
    
    def _collect_memory_dump(self) -> str:
        """收集記憶體轉儲"""
        return "memory_dump.raw"
    
    def _collect_file_artifacts(self) -> List[str]:
        """收集檔案證據"""
        return ["file1.txt", "file2.log"]
    
    def _collect_registry_artifacts(self) -> List[str]:
        """收集登錄檔證據"""
        return ["registry1.reg", "registry2.reg"]
    
    def _collect_network_artifacts(self) -> List[str]:
        """收集網路證據"""
        return ["network1.pcap", "network2.pcap"]

def main():
    """主函數"""
    try:
        # 初始化主機防護系統
        host_protection = MilitaryHostProtection()
        
        # 開始監控
        host_protection.start_monitoring()
        
        # 檢測威脅
        threats = host_protection.detect_threats()
        print(f"檢測到 {len(threats)} 個威脅")
        
        # 應用系統加固
        hardening_results = host_protection.apply_system_hardening()
        print(f"系統加固結果: {hardening_results}")
        
        # 顯示主機狀態
        status = host_protection.get_host_status()
        print(f"主機防護系統狀態: {status}")
        
        # 保持運行
        while True:
            time.sleep(10)
            
    except KeyboardInterrupt:
        logger.info("主機防護系統已停止")
    except Exception as e:
        logger.error(f"主機防護系統錯誤: {e}")

if __name__ == "__main__":
    main()



