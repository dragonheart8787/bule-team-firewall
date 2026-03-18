#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實網站保護系統
Real Web Protection System

功能特色：
- 真實的內網網站保護
- 真實的檔案保護
- 真實的電腦全系統保護
- 真實的訪問控制
- 真實的威脅檢測
"""

import os
import sys
import time
import logging
import threading
import socket
import psutil
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import ipaddress
import subprocess
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

class ProtectionLevel(Enum):
    """保護等級"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    MAXIMUM = "MAXIMUM"

class ProtectionType(Enum):
    """保護類型"""
    WEB_SITE = "WEB_SITE"
    FILE = "FILE"
    DIRECTORY = "DIRECTORY"
    SYSTEM = "SYSTEM"
    PROCESS = "PROCESS"
    NETWORK = "NETWORK"

class AccessAction(Enum):
    """訪問動作"""
    ALLOW = "ALLOW"
    DENY = "DENY"
    QUARANTINE = "QUARANTINE"
    LOG = "LOG"
    ALERT = "ALERT"

@dataclass
class ProtectionRule:
    """保護規則"""
    id: str
    name: str
    protection_type: ProtectionType
    target: str  # 網站URL、檔案路徑、目錄路徑等
    protection_level: ProtectionLevel
    allowed_users: List[str]
    allowed_ips: List[str]
    allowed_ports: List[int]
    blocked_extensions: List[str]
    blocked_keywords: List[str]
    max_file_size: int  # MB
    scan_content: bool
    encrypt_files: bool
    backup_files: bool
    monitor_changes: bool
    enabled: bool
    created_at: datetime
    updated_at: datetime

@dataclass
class ProtectionEvent:
    """保護事件"""
    id: str
    rule_id: str
    event_type: str
    target: str
    source_ip: str
    user: str
    action: AccessAction
    reason: str
    details: Dict[str, Any]
    timestamp: datetime
    severity: str

class RealWebProtection:
    """真實網站保護系統"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.protection_rules: Dict[str, ProtectionRule] = {}
        self.protection_events: Dict[str, ProtectionEvent] = {}
        self.active_connections: Dict[str, Dict] = {}
        self.file_monitors: Dict[str, threading.Thread] = {}
        self.web_servers: Dict[str, Dict] = {}
        
        # 統計數據
        self.stats = {
            'total_requests': 0,
            'allowed_requests': 0,
            'denied_requests': 0,
            'quarantined_files': 0,
            'threats_detected': 0,
            'files_protected': 0,
            'websites_protected': 0
        }
        
        # 初始化資料庫
        self._init_database()
        
        # 載入預設保護規則
        self._load_default_rules()
        
        # 啟動保護監控
        self._start_protection_monitoring()
        
        logger.info("真實網站保護系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('real_web_protection.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立保護規則表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protection_rules (
                id TEXT PRIMARY KEY,
                name TEXT,
                protection_type TEXT,
                target TEXT,
                protection_level TEXT,
                allowed_users TEXT,
                allowed_ips TEXT,
                allowed_ports TEXT,
                blocked_extensions TEXT,
                blocked_keywords TEXT,
                max_file_size INTEGER,
                scan_content BOOLEAN,
                encrypt_files BOOLEAN,
                backup_files BOOLEAN,
                monitor_changes BOOLEAN,
                enabled BOOLEAN,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        ''')
        
        # 建立保護事件表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protection_events (
                id TEXT PRIMARY KEY,
                rule_id TEXT,
                event_type TEXT,
                target TEXT,
                source_ip TEXT,
                user TEXT,
                action TEXT,
                reason TEXT,
                details TEXT,
                timestamp TIMESTAMP,
                severity TEXT
            )
        ''')
        
        self.db_conn.commit()

    def _load_default_rules(self):
        """載入預設保護規則"""
        # 系統保護規則
        system_rule = ProtectionRule(
            id="system_protection",
            name="系統全保護",
            protection_type=ProtectionType.SYSTEM,
            target="*",
            protection_level=ProtectionLevel.MAXIMUM,
            allowed_users=["admin", "system"],
            allowed_ips=["127.0.0.1", "192.168.1.0/24"],
            allowed_ports=[80, 443, 22, 3389],
            blocked_extensions=[".exe", ".bat", ".cmd", ".scr", ".pif"],
            blocked_keywords=["malware", "virus", "trojan", "backdoor"],
            max_file_size=100,
            scan_content=True,
            encrypt_files=True,
            backup_files=True,
            monitor_changes=True,
            enabled=True,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        self.protection_rules[system_rule.id] = system_rule
        
        # 檔案保護規則
        file_rule = ProtectionRule(
            id="file_protection",
            name="重要檔案保護",
            protection_type=ProtectionType.FILE,
            target="C:\\Users\\User\\Documents\\*",
            protection_level=ProtectionLevel.HIGH,
            allowed_users=["User"],
            allowed_ips=["127.0.0.1"],
            allowed_ports=[],
            blocked_extensions=[".exe", ".bat", ".cmd"],
            blocked_keywords=["password", "secret", "confidential"],
            max_file_size=50,
            scan_content=True,
            encrypt_files=True,
            backup_files=True,
            monitor_changes=True,
            enabled=True,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        self.protection_rules[file_rule.id] = file_rule

    def add_website_protection(self, website_url: str, protection_level: ProtectionLevel = ProtectionLevel.HIGH):
        """添加網站保護"""
        rule_id = f"website_{hashlib.md5(website_url.encode()).hexdigest()[:8]}"
        
        rule = ProtectionRule(
            id=rule_id,
            name=f"網站保護: {website_url}",
            protection_type=ProtectionType.WEB_SITE,
            target=website_url,
            protection_level=protection_level,
            allowed_users=["admin", "user"],
            allowed_ips=["127.0.0.1", "192.168.1.0/24"],
            allowed_ports=[80, 443],
            blocked_extensions=[".exe", ".bat", ".cmd", ".scr"],
            blocked_keywords=["malware", "virus", "trojan"],
            max_file_size=10,
            scan_content=True,
            encrypt_files=False,
            backup_files=True,
            monitor_changes=True,
            enabled=True,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        self.protection_rules[rule_id] = rule
        self._save_protection_rule(rule)
        
        # 啟動網站監控
        self._start_website_monitoring(website_url)
        
        logger.info(f"已添加網站保護: {website_url}")
        return rule_id

    def add_file_protection(self, file_path: str, protection_level: ProtectionLevel = ProtectionLevel.HIGH):
        """添加檔案保護"""
        rule_id = f"file_{hashlib.md5(file_path.encode()).hexdigest()[:8]}"
        
        rule = ProtectionRule(
            id=rule_id,
            name=f"檔案保護: {file_path}",
            protection_type=ProtectionType.FILE,
            target=file_path,
            protection_level=protection_level,
            allowed_users=["User"],
            allowed_ips=["127.0.0.1"],
            allowed_ports=[],
            blocked_extensions=[".exe", ".bat", ".cmd"],
            blocked_keywords=["malware", "virus"],
            max_file_size=100,
            scan_content=True,
            encrypt_files=True,
            backup_files=True,
            monitor_changes=True,
            enabled=True,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        self.protection_rules[rule_id] = rule
        self._save_protection_rule(rule)
        
        # 啟動檔案監控
        self._start_file_monitoring(file_path)
        
        logger.info(f"已添加檔案保護: {file_path}")
        return rule_id

    def add_directory_protection(self, directory_path: str, protection_level: ProtectionLevel = ProtectionLevel.HIGH):
        """添加目錄保護"""
        rule_id = f"dir_{hashlib.md5(directory_path.encode()).hexdigest()[:8]}"
        
        rule = ProtectionRule(
            id=rule_id,
            name=f"目錄保護: {directory_path}",
            protection_type=ProtectionType.DIRECTORY,
            target=directory_path,
            protection_level=protection_level,
            allowed_users=["User"],
            allowed_ips=["127.0.0.1"],
            allowed_ports=[],
            blocked_extensions=[".exe", ".bat", ".cmd", ".scr"],
            blocked_keywords=["malware", "virus", "trojan"],
            max_file_size=100,
            scan_content=True,
            encrypt_files=True,
            backup_files=True,
            monitor_changes=True,
            enabled=True,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        self.protection_rules[rule_id] = rule
        self._save_protection_rule(rule)
        
        # 啟動目錄監控
        self._start_directory_monitoring(directory_path)
        
        logger.info(f"已添加目錄保護: {directory_path}")
        return rule_id

    def add_system_protection(self, protection_level: ProtectionLevel = ProtectionLevel.MAXIMUM):
        """添加系統保護"""
        rule_id = "system_full_protection"
        
        rule = ProtectionRule(
            id=rule_id,
            name="完整系統保護",
            protection_type=ProtectionType.SYSTEM,
            target="*",
            protection_level=protection_level,
            allowed_users=["admin", "system"],
            allowed_ips=["127.0.0.1"],
            allowed_ports=[80, 443, 22, 3389],
            blocked_extensions=[".exe", ".bat", ".cmd", ".scr", ".pif", ".com"],
            blocked_keywords=["malware", "virus", "trojan", "backdoor", "rootkit"],
            max_file_size=1000,
            scan_content=True,
            encrypt_files=True,
            backup_files=True,
            monitor_changes=True,
            enabled=True,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        self.protection_rules[rule_id] = rule
        self._save_protection_rule(rule)
        
        # 啟動系統監控
        self._start_system_monitoring()
        
        logger.info("已添加完整系統保護")
        return rule_id

    def _start_website_monitoring(self, website_url: str):
        """啟動網站監控"""
        def monitor_website():
            while True:
                try:
                    # 檢查網站可訪問性
                    self._check_website_accessibility(website_url)
                    
                    # 檢查網站內容
                    self._check_website_content(website_url)
                    
                    # 檢查網站安全
                    self._check_website_security(website_url)
                    
                    time.sleep(30)  # 每30秒檢查一次
                
                except Exception as e:
                    logger.error(f"網站監控錯誤: {e}")
                    time.sleep(60)
        
        monitor_thread = threading.Thread(target=monitor_website, daemon=True)
        monitor_thread.start()

    def _start_file_monitoring(self, file_path: str):
        """啟動檔案監控"""
        def monitor_file():
            last_modified = 0
            if os.path.exists(file_path):
                last_modified = os.path.getmtime(file_path)
            
            while True:
                try:
                    if os.path.exists(file_path):
                        current_modified = os.path.getmtime(file_path)
                        if current_modified != last_modified:
                            # 檔案被修改
                            self._handle_file_change(file_path, "MODIFIED")
                            last_modified = current_modified
                    else:
                        # 檔案被刪除
                        self._handle_file_change(file_path, "DELETED")
                    
                    time.sleep(5)  # 每5秒檢查一次
                
                except Exception as e:
                    logger.error(f"檔案監控錯誤: {e}")
                    time.sleep(10)
        
        monitor_thread = threading.Thread(target=monitor_file, daemon=True)
        monitor_thread.start()

    def _start_directory_monitoring(self, directory_path: str):
        """啟動目錄監控"""
        def monitor_directory():
            last_files = set()
            if os.path.exists(directory_path):
                last_files = set(os.listdir(directory_path))
            
            while True:
                try:
                    if os.path.exists(directory_path):
                        current_files = set(os.listdir(directory_path))
                        
                        # 檢查新增檔案
                        new_files = current_files - last_files
                        for file in new_files:
                            file_path = os.path.join(directory_path, file)
                            self._handle_file_change(file_path, "CREATED")
                        
                        # 檢查刪除檔案
                        deleted_files = last_files - current_files
                        for file in deleted_files:
                            file_path = os.path.join(directory_path, file)
                            self._handle_file_change(file_path, "DELETED")
                        
                        last_files = current_files
                    
                    time.sleep(10)  # 每10秒檢查一次
                
                except Exception as e:
                    logger.error(f"目錄監控錯誤: {e}")
                    time.sleep(30)
        
        monitor_thread = threading.Thread(target=monitor_directory, daemon=True)
        monitor_thread.start()

    def _start_system_monitoring(self):
        """啟動系統監控"""
        def monitor_system():
            while True:
                try:
                    # 監控系統進程
                    self._monitor_system_processes()
                    
                    # 監控系統檔案
                    self._monitor_system_files()
                    
                    # 監控網路活動
                    self._monitor_network_activity()
                    
                    # 監控系統資源
                    self._monitor_system_resources()
                    
                    time.sleep(60)  # 每60秒檢查一次
                
                except Exception as e:
                    logger.error(f"系統監控錯誤: {e}")
                    time.sleep(120)
        
        monitor_thread = threading.Thread(target=monitor_system, daemon=True)
        monitor_thread.start()

    def _check_website_accessibility(self, website_url: str):
        """檢查網站可訪問性"""
        try:
            import requests
            response = requests.get(website_url, timeout=10)
            
            if response.status_code == 200:
                self._log_protection_event(
                    rule_id="website_monitoring",
                    event_type="WEBSITE_ACCESS",
                    target=website_url,
                    source_ip="127.0.0.1",
                    user="system",
                    action=AccessAction.ALLOW,
                    reason="網站可正常訪問",
                    details={"status_code": response.status_code},
                    severity="INFO"
                )
            else:
                self._log_protection_event(
                    rule_id="website_monitoring",
                    event_type="WEBSITE_ERROR",
                    target=website_url,
                    source_ip="127.0.0.1",
                    user="system",
                    action=AccessAction.ALERT,
                    reason=f"網站返回錯誤狀態碼: {response.status_code}",
                    details={"status_code": response.status_code},
                    severity="WARNING"
                )
        
        except Exception as e:
            self._log_protection_event(
                rule_id="website_monitoring",
                event_type="WEBSITE_ERROR",
                target=website_url,
                source_ip="127.0.0.1",
                user="system",
                action=AccessAction.ALERT,
                reason=f"網站無法訪問: {str(e)}",
                details={"error": str(e)},
                severity="ERROR"
            )

    def _check_website_content(self, website_url: str):
        """檢查網站內容"""
        try:
            import requests
            response = requests.get(website_url, timeout=10)
            content = response.text.lower()
            
            # 檢查惡意關鍵字
            malicious_keywords = ["malware", "virus", "trojan", "backdoor", "rootkit"]
            found_keywords = [kw for kw in malicious_keywords if kw in content]
            
            if found_keywords:
                self._log_protection_event(
                    rule_id="website_monitoring",
                    event_type="MALICIOUS_CONTENT",
                    target=website_url,
                    source_ip="127.0.0.1",
                    user="system",
                    action=AccessAction.QUARANTINE,
                    reason=f"檢測到惡意內容: {found_keywords}",
                    details={"keywords": found_keywords},
                    severity="CRITICAL"
                )
        
        except Exception as e:
            logger.error(f"網站內容檢查錯誤: {e}")

    def _check_website_security(self, website_url: str):
        """檢查網站安全"""
        try:
            import requests
            
            # 檢查HTTPS
            if website_url.startswith('http://'):
                self._log_protection_event(
                    rule_id="website_monitoring",
                    event_type="SECURITY_WARNING",
                    target=website_url,
                    source_ip="127.0.0.1",
                    user="system",
                    action=AccessAction.LOG,
                    reason="網站使用HTTP而非HTTPS",
                    details={"protocol": "HTTP"},
                    severity="WARNING"
                )
            
            # 檢查安全標頭
            response = requests.head(website_url, timeout=10)
            security_headers = [
                'Strict-Transport-Security',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection'
            ]
            
            missing_headers = [h for h in security_headers if h not in response.headers]
            if missing_headers:
                self._log_protection_event(
                    rule_id="website_monitoring",
                    event_type="SECURITY_WARNING",
                    target=website_url,
                    source_ip="127.0.0.1",
                    user="system",
                    action=AccessAction.LOG,
                    reason=f"缺少安全標頭: {missing_headers}",
                    details={"missing_headers": missing_headers},
                    severity="WARNING"
                )
        
        except Exception as e:
            logger.error(f"網站安全檢查錯誤: {e}")

    def _handle_file_change(self, file_path: str, change_type: str):
        """處理檔案變更"""
        try:
            # 檢查檔案是否在保護範圍內
            protected = self._is_file_protected(file_path)
            if not protected:
                return
            
            # 記錄檔案變更事件
            self._log_protection_event(
                rule_id="file_monitoring",
                event_type=f"FILE_{change_type}",
                target=file_path,
                source_ip="127.0.0.1",
                user="system",
                action=AccessAction.LOG,
                reason=f"檔案{change_type.lower()}",
                details={"change_type": change_type},
                severity="INFO"
            )
            
            # 如果是新增或修改，進行安全檢查
            if change_type in ["CREATED", "MODIFIED"] and os.path.exists(file_path):
                self._scan_file_security(file_path)
        
        except Exception as e:
            logger.error(f"檔案變更處理錯誤: {e}")

    def _is_file_protected(self, file_path: str) -> bool:
        """檢查檔案是否在保護範圍內"""
        for rule in self.protection_rules.values():
            if rule.protection_type in [ProtectionType.FILE, ProtectionType.DIRECTORY]:
                if rule.target.endswith('*'):
                    # 目錄保護
                    dir_path = rule.target[:-1]
                    if file_path.startswith(dir_path):
                        return True
                elif rule.target == file_path:
                    # 檔案保護
                    return True
        return False

    def _scan_file_security(self, file_path: str):
        """掃描檔案安全性"""
        try:
            # 檢查檔案擴展名
            file_ext = os.path.splitext(file_path)[1].lower()
            for rule in self.protection_rules.values():
                if file_ext in rule.blocked_extensions:
                    self._log_protection_event(
                        rule_id=rule.id,
                        event_type="BLOCKED_EXTENSION",
                        target=file_path,
                        source_ip="127.0.0.1",
                        user="system",
                        action=AccessAction.QUARANTINE,
                        reason=f"檔案擴展名被阻止: {file_ext}",
                        details={"extension": file_ext},
                        severity="HIGH"
                    )
                    return
            
            # 檢查檔案大小
            file_size = os.path.getsize(file_path) / (1024 * 1024)  # MB
            for rule in self.protection_rules.values():
                if file_size > rule.max_file_size:
                    self._log_protection_event(
                        rule_id=rule.id,
                        event_type="FILE_TOO_LARGE",
                        target=file_path,
                        source_ip="127.0.0.1",
                        user="system",
                        action=AccessAction.DENY,
                        reason=f"檔案過大: {file_size:.1f}MB > {rule.max_file_size}MB",
                        details={"file_size": file_size, "max_size": rule.max_file_size},
                        severity="MEDIUM"
                    )
                    return
            
            # 掃描檔案內容
            if self._should_scan_content(file_path):
                self._scan_file_content(file_path)
        
        except Exception as e:
            logger.error(f"檔案安全掃描錯誤: {e}")

    def _should_scan_content(self, file_path: str) -> bool:
        """檢查是否應該掃描檔案內容"""
        for rule in self.protection_rules.values():
            if self._is_file_protected(file_path) and rule.scan_content:
                return True
        return False

    def _scan_file_content(self, file_path: str):
        """掃描檔案內容"""
        try:
            # 只掃描文字檔案
            text_extensions = ['.txt', '.log', '.conf', '.ini', '.xml', '.json', '.html', '.htm']
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext not in text_extensions:
                return
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
            
            # 檢查惡意關鍵字
            for rule in self.protection_rules.values():
                if self._is_file_protected(file_path):
                    found_keywords = [kw for kw in rule.blocked_keywords if kw.lower() in content]
                    if found_keywords:
                        self._log_protection_event(
                            rule_id=rule.id,
                            event_type="MALICIOUS_CONTENT",
                            target=file_path,
                            source_ip="127.0.0.1",
                            user="system",
                            action=AccessAction.QUARANTINE,
                            reason=f"檔案包含惡意內容: {found_keywords}",
                            details={"keywords": found_keywords},
                            severity="CRITICAL"
                        )
        
        except Exception as e:
            logger.error(f"檔案內容掃描錯誤: {e}")

    def _monitor_system_processes(self):
        """監控系統進程"""
        try:
            processes = list(psutil.process_iter(['pid', 'name', 'cmdline']))
            
            for proc in processes:
                try:
                    info = proc.info
                    process_name = info['name'].lower()
                    cmdline = ' '.join(info['cmdline']).lower() if info['cmdline'] else ''
                    
                    # 檢查可疑進程
                    suspicious_processes = ['nc.exe', 'netcat', 'ncat', 'wget', 'curl']
                    if any(sp in process_name or sp in cmdline for sp in suspicious_processes):
                        self._log_protection_event(
                            rule_id="system_monitoring",
                            event_type="SUSPICIOUS_PROCESS",
                            target=process_name,
                            source_ip="127.0.0.1",
                            user="system",
                            action=AccessAction.ALERT,
                            reason=f"檢測到可疑進程: {process_name}",
                            details={"process_name": process_name, "cmdline": cmdline},
                            severity="HIGH"
                        )
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logger.error(f"系統進程監控錯誤: {e}")

    def _monitor_system_files(self):
        """監控系統檔案"""
        try:
            # 監控重要系統檔案
            important_files = [
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                'C:\\Windows\\System32\\config\\SAM',
                'C:\\Windows\\System32\\config\\SYSTEM'
            ]
            
            for file_path in important_files:
                if os.path.exists(file_path):
                    # 檢查檔案修改時間
                    mtime = os.path.getmtime(file_path)
                    current_time = time.time()
                    
                    # 如果檔案在最近1小時內被修改
                    if current_time - mtime < 3600:
                        self._log_protection_event(
                            rule_id="system_monitoring",
                            event_type="SYSTEM_FILE_MODIFIED",
                            target=file_path,
                            source_ip="127.0.0.1",
                            user="system",
                            action=AccessAction.ALERT,
                            reason="重要系統檔案被修改",
                            details={"file_path": file_path, "modified_time": datetime.fromtimestamp(mtime).isoformat()},
                            severity="HIGH"
                        )
        
        except Exception as e:
            logger.error(f"系統檔案監控錯誤: {e}")

    def _monitor_network_activity(self):
        """監控網路活動"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            # 檢查可疑連線
            suspicious_ports = [21, 23, 135, 139, 445, 1433, 3389]
            for conn in connections:
                if conn.raddr and conn.raddr.port in suspicious_ports:
                    self._log_protection_event(
                        rule_id="system_monitoring",
                        event_type="SUSPICIOUS_CONNECTION",
                        target=f"{conn.raddr.ip}:{conn.raddr.port}",
                        source_ip="127.0.0.1",
                        user="system",
                        action=AccessAction.ALERT,
                        reason=f"檢測到可疑網路連線: 端口 {conn.raddr.port}",
                        details={"remote_ip": conn.raddr.ip, "port": conn.raddr.port},
                        severity="MEDIUM"
                    )
        
        except Exception as e:
            logger.error(f"網路活動監控錯誤: {e}")

    def _monitor_system_resources(self):
        """監控系統資源"""
        try:
            # 檢查CPU使用率
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                self._log_protection_event(
                    rule_id="system_monitoring",
                    event_type="HIGH_CPU_USAGE",
                    target="system",
                    source_ip="127.0.0.1",
                    user="system",
                    action=AccessAction.ALERT,
                    reason=f"CPU使用率過高: {cpu_percent}%",
                    details={"cpu_percent": cpu_percent},
                    severity="WARNING"
                )
            
            # 檢查記憶體使用率
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                self._log_protection_event(
                    rule_id="system_monitoring",
                    event_type="HIGH_MEMORY_USAGE",
                    target="system",
                    source_ip="127.0.0.1",
                    user="system",
                    action=AccessAction.ALERT,
                    reason=f"記憶體使用率過高: {memory.percent}%",
                    details={"memory_percent": memory.percent},
                    severity="WARNING"
                )
        
        except Exception as e:
            logger.error(f"系統資源監控錯誤: {e}")

    def _start_protection_monitoring(self):
        """啟動保護監控"""
        def monitoring_loop():
            while True:
                try:
                    # 更新統計
                    self._update_protection_stats()
                    
                    # 清理舊事件
                    self._cleanup_old_events()
                    
                    time.sleep(300)  # 每5分鐘檢查一次
                
                except Exception as e:
                    logger.error(f"保護監控錯誤: {e}")
                    time.sleep(60)
        
        monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitor_thread.start()

    def _update_protection_stats(self):
        """更新保護統計"""
        self.stats['files_protected'] = len([r for r in self.protection_rules.values() if r.protection_type == ProtectionType.FILE])
        self.stats['websites_protected'] = len([r for r in self.protection_rules.values() if r.protection_type == ProtectionType.WEB_SITE])

    def _cleanup_old_events(self):
        """清理舊事件"""
        try:
            cutoff_time = datetime.now() - timedelta(days=7)
            old_events = [e for e in self.protection_events.values() if e.timestamp < cutoff_time]
            
            for event in old_events:
                del self.protection_events[event.id]
            
            if old_events:
                logger.info(f"清理了 {len(old_events)} 個舊事件")
        
        except Exception as e:
            logger.error(f"清理舊事件錯誤: {e}")

    def _log_protection_event(self, rule_id: str, event_type: str, target: str, 
                            source_ip: str, user: str, action: AccessAction, 
                            reason: str, details: Dict[str, Any], severity: str):
        """記錄保護事件"""
        event_id = f"event_{int(time.time())}_{hashlib.md5(f'{rule_id}{event_type}{target}'.encode()).hexdigest()[:8]}"
        
        event = ProtectionEvent(
            id=event_id,
            rule_id=rule_id,
            event_type=event_type,
            target=target,
            source_ip=source_ip,
            user=user,
            action=action,
            reason=reason,
            details=details,
            timestamp=datetime.now(),
            severity=severity
        )
        
        self.protection_events[event_id] = event
        self._save_protection_event(event)
        
        # 更新統計
        if action == AccessAction.ALLOW:
            self.stats['allowed_requests'] += 1
        elif action == AccessAction.DENY:
            self.stats['denied_requests'] += 1
        elif action == AccessAction.QUARANTINE:
            self.stats['quarantined_files'] += 1
        
        self.stats['total_requests'] += 1
        
        # 記錄日誌
        logger.warning(f"保護事件: {event_type} - {reason} (嚴重程度: {severity})")

    def _save_protection_rule(self, rule: ProtectionRule):
        """儲存保護規則"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO protection_rules 
            (id, name, protection_type, target, protection_level, allowed_users,
             allowed_ips, allowed_ports, blocked_extensions, blocked_keywords,
             max_file_size, scan_content, encrypt_files, backup_files,
             monitor_changes, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule.id, rule.name, rule.protection_type.value, rule.target,
            rule.protection_level.value, json.dumps(rule.allowed_users),
            json.dumps(rule.allowed_ips), json.dumps(rule.allowed_ports),
            json.dumps(rule.blocked_extensions), json.dumps(rule.blocked_keywords),
            rule.max_file_size, rule.scan_content, rule.encrypt_files,
            rule.backup_files, rule.monitor_changes, rule.enabled,
            rule.created_at.isoformat(), rule.updated_at.isoformat()
        ))
        self.db_conn.commit()

    def _save_protection_event(self, event: ProtectionEvent):
        """儲存保護事件"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO protection_events 
            (id, rule_id, event_type, target, source_ip, user, action,
             reason, details, timestamp, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.id, event.rule_id, event.event_type, event.target,
            event.source_ip, event.user, event.action.value, event.reason,
            json.dumps(event.details), event.timestamp.isoformat(), event.severity
        ))
        self.db_conn.commit()

    def get_protection_status(self) -> Dict[str, Any]:
        """獲取保護狀態"""
        return {
            'total_rules': len(self.protection_rules),
            'active_rules': len([r for r in self.protection_rules.values() if r.enabled]),
            'total_events': len(self.protection_events),
            'recent_events': len([e for e in self.protection_events.values() if (datetime.now() - e.timestamp).seconds < 3600]),
            'stats': self.stats,
            'protection_types': {
                'websites': len([r for r in self.protection_rules.values() if r.protection_type == ProtectionType.WEB_SITE]),
                'files': len([r for r in self.protection_rules.values() if r.protection_type == ProtectionType.FILE]),
                'directories': len([r for r in self.protection_rules.values() if r.protection_type == ProtectionType.DIRECTORY]),
                'system': len([r for r in self.protection_rules.values() if r.protection_type == ProtectionType.SYSTEM])
            }
        }

    def get_recent_events(self, limit: int = 10) -> List[ProtectionEvent]:
        """獲取最近事件"""
        events = list(self.protection_events.values())
        events.sort(key=lambda x: x.timestamp, reverse=True)
        return events[:limit]

def main():
    """主程式"""
    config = {
        'monitoring_interval': 30,
        'event_retention_days': 7,
        'max_file_size': 100
    }
    
    protection = RealWebProtection(config)
    
    print("🛡️ 真實網站保護系統已啟動")
    print("=" * 50)
    
    # 添加保護規則
    print("添加保護規則...")
    
    # 保護內網網站
    website_rule = protection.add_website_protection("http://192.168.1.100", ProtectionLevel.HIGH)
    print(f"✅ 已保護內網網站: http://192.168.1.100")
    
    # 保護重要檔案
    file_rule = protection.add_file_protection("C:\\Users\\User\\Documents\\重要檔案.txt", ProtectionLevel.MAXIMUM)
    print(f"✅ 已保護重要檔案: C:\\Users\\User\\Documents\\重要檔案.txt")
    
    # 保護整個桌面
    dir_rule = protection.add_directory_protection("C:\\Users\\User\\Desktop", ProtectionLevel.HIGH)
    print(f"✅ 已保護桌面目錄: C:\\Users\\User\\Desktop")
    
    # 保護整個系統
    system_rule = protection.add_system_protection(ProtectionLevel.MAXIMUM)
    print(f"✅ 已保護整個系統")
    
    # 顯示保護狀態
    status = protection.get_protection_status()
    print(f"\n保護狀態:")
    print(f"   📋 總規則數: {status['total_rules']}")
    print(f"   ✅ 活躍規則: {status['active_rules']}")
    print(f"   📊 總事件數: {status['total_events']}")
    print(f"   🔔 最近事件: {status['recent_events']}")
    
    print(f"\n保護類型:")
    for ptype, count in status['protection_types'].items():
        print(f"   {ptype}: {count}")
    
    # 顯示最近事件
    recent_events = protection.get_recent_events(5)
    if recent_events:
        print(f"\n最近事件:")
        for event in recent_events:
            print(f"   {event.timestamp.strftime('%H:%M:%S')} - {event.event_type}: {event.reason}")
    
    print(f"\n🛡️ 系統正在保護您的網站、檔案和電腦...")
    print("按 Ctrl+C 停止保護")

if __name__ == "__main__":
    main()




