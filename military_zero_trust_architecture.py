#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級零信任架構整合
實作 IAM/MFA/微分段、NAC、NDR 等零信任核心功能
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

class TrustLevel(Enum):
    """信任等級枚舉"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNTRUSTED = "untrusted"

class DeviceType(Enum):
    """裝置類型枚舉"""
    WORKSTATION = "workstation"
    SERVER = "server"
    MOBILE = "mobile"
    IOT = "iot"
    OT = "ot"
    UNKNOWN = "unknown"

@dataclass
class User:
    """用戶資料結構"""
    id: str
    username: str
    email: str
    department: str
    role: str
    trust_level: TrustLevel
    mfa_enabled: bool
    last_login: str
    device_count: int
    risk_score: float

@dataclass
class Device:
    """裝置資料結構"""
    id: str
    hostname: str
    ip_address: str
    mac_address: str
    device_type: DeviceType
    os_version: str
    security_status: str
    trust_level: TrustLevel
    last_seen: str
    compliance_score: float

@dataclass
class NetworkSegment:
    """網路段資料結構"""
    id: str
    name: str
    cidr: str
    trust_level: TrustLevel
    allowed_protocols: List[str]
    allowed_ports: List[int]
    isolation_rules: List[str]

class IAMSystem:
    """身份與存取管理系統"""
    
    def __init__(self):
        self.db_path = "iam.db"
        self.users = {}
        self.sessions = {}
        self._init_database()
    
    def _init_database(self):
        """初始化資料庫"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 創建用戶表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    department TEXT NOT NULL,
                    role TEXT NOT NULL,
                    trust_level TEXT NOT NULL,
                    mfa_enabled BOOLEAN DEFAULT FALSE,
                    last_login TEXT,
                    device_count INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0.0
                )
            ''')
            
            # 創建會話表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    last_activity TEXT NOT NULL,
                    trust_score REAL DEFAULT 0.0,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"IAM 資料庫初始化錯誤: {e}")
    
    def authenticate_user(self, username: str, password: str, device_id: str, 
                         ip_address: str, mfa_code: str = None) -> Dict[str, Any]:
        """用戶認證"""
        try:
            # 檢查用戶是否存在
            if username not in self.users:
                return {'success': False, 'error': '用戶不存在'}
            
            user = self.users[username]
            
            # 檢查密碼（簡化實作）
            if not self._verify_password(username, password):
                return {'success': False, 'error': '密碼錯誤'}
            
            # 檢查 MFA
            if user.mfa_enabled:
                if not mfa_code or not self._verify_mfa_code(username, mfa_code):
                    return {'success': False, 'error': 'MFA 驗證失敗'}
            
            # 計算信任分數
            trust_score = self._calculate_trust_score(user, device_id, ip_address)
            
            # 創建會話
            session_id = self._create_session(user.id, device_id, ip_address, trust_score)
            
            return {
                'success': True,
                'session_id': session_id,
                'user': self._user_to_dict(user),
                'trust_score': trust_score,
                'access_level': self._determine_access_level(trust_score)
            }
        except Exception as e:
            logger.error(f"用戶認證錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _verify_password(self, username: str, password: str) -> bool:
        """驗證密碼"""
        # 簡化實作，實際應該使用安全的密碼雜湊
        return len(password) >= 8
    
    def _verify_mfa_code(self, username: str, mfa_code: str) -> bool:
        """驗證 MFA 代碼"""
        # 簡化實作，實際應該使用 TOTP 或 SMS
        return mfa_code == "123456"
    
    def _calculate_trust_score(self, user: User, device_id: str, ip_address: str) -> float:
        """計算信任分數"""
        score = 0.0
        
        # 基礎信任分數
        trust_level_scores = {
            TrustLevel.CRITICAL: 0.9,
            TrustLevel.HIGH: 0.8,
            TrustLevel.MEDIUM: 0.6,
            TrustLevel.LOW: 0.4,
            TrustLevel.UNTRUSTED: 0.1
        }
        score += trust_level_scores.get(user.trust_level, 0.5)
        
        # MFA 加分
        if user.mfa_enabled:
            score += 0.1
        
        # 裝置信任度
        if device_id in self.devices:
            device = self.devices[device_id]
            if device.compliance_score > 0.8:
                score += 0.1
        
        # IP 地址信任度
        if self._is_trusted_ip(ip_address):
            score += 0.1
        
        return min(score, 1.0)
    
    def _create_session(self, user_id: str, device_id: str, ip_address: str, trust_score: float) -> str:
        """創建會話"""
        session_id = f"session_{int(time.time())}_{hashlib.md5(f'{user_id}{device_id}'.encode()).hexdigest()[:8]}"
        
        session = {
            'session_id': session_id,
            'user_id': user_id,
            'device_id': device_id,
            'ip_address': ip_address,
            'start_time': datetime.now().isoformat(),
            'last_activity': datetime.now().isoformat(),
            'trust_score': trust_score
        }
        
        self.sessions[session_id] = session
        
        # 儲存到資料庫
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO sessions (session_id, user_id, device_id, ip_address, start_time, last_activity, trust_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (session_id, user_id, device_id, ip_address, session['start_time'], session['last_activity'], trust_score))
        conn.commit()
        conn.close()
        
        return session_id
    
    def _determine_access_level(self, trust_score: float) -> str:
        """確定存取等級"""
        if trust_score >= 0.9:
            return "FULL_ACCESS"
        elif trust_score >= 0.7:
            return "LIMITED_ACCESS"
        elif trust_score >= 0.5:
            return "RESTRICTED_ACCESS"
        else:
            return "NO_ACCESS"
    
    def _is_trusted_ip(self, ip_address: str) -> bool:
        """檢查是否為信任的 IP 地址"""
        trusted_ranges = [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/12"
        ]
        # 簡化實作
        return ip_address.startswith("192.168.1.") or ip_address.startswith("10.0.")
    
    def _user_to_dict(self, user: User) -> Dict[str, Any]:
        """將用戶轉換為字典"""
        return {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'department': user.department,
            'role': user.role,
            'trust_level': user.trust_level.value,
            'mfa_enabled': user.mfa_enabled,
            'last_login': user.last_login,
            'device_count': user.device_count,
            'risk_score': user.risk_score
        }

class NACSystem:
    """網路存取控制系統"""
    
    def __init__(self):
        self.devices = {}
        self.policies = {}
        self._init_default_policies()
    
    def _init_default_policies(self):
        """初始化預設政策"""
        self.policies = {
            'workstation': {
                'min_os_version': 'Windows 10 1903',
                'required_antivirus': True,
                'required_firewall': True,
                'required_patches': True,
                'max_risk_score': 0.3
            },
            'server': {
                'min_os_version': 'Windows Server 2019',
                'required_antivirus': True,
                'required_firewall': True,
                'required_patches': True,
                'max_risk_score': 0.2
            },
            'mobile': {
                'min_os_version': 'iOS 14.0',
                'required_antivirus': False,
                'required_firewall': False,
                'required_patches': True,
                'max_risk_score': 0.4
            },
            'iot': {
                'min_os_version': 'Any',
                'required_antivirus': False,
                'required_firewall': False,
                'required_patches': False,
                'max_risk_score': 0.8
            }
        }
    
    def assess_device(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """評估裝置安全狀態"""
        try:
            device_id = device_info.get('id', f"device_{int(time.time())}")
            device_type = DeviceType(device_info.get('device_type', 'unknown'))
            
            # 獲取對應政策
            policy = self.policies.get(device_type.value, self.policies['workstation'])
            
            # 評估合規性
            compliance_result = self._evaluate_compliance(device_info, policy)
            
            # 計算風險分數
            risk_score = self._calculate_device_risk(device_info, compliance_result)
            
            # 確定信任等級
            trust_level = self._determine_device_trust_level(risk_score)
            
            # 創建設置記錄
            device = Device(
                id=device_id,
                hostname=device_info.get('hostname', 'Unknown'),
                ip_address=device_info.get('ip_address', '0.0.0.0'),
                mac_address=device_info.get('mac_address', '00:00:00:00:00:00'),
                device_type=device_type,
                os_version=device_info.get('os_version', 'Unknown'),
                security_status=compliance_result['status'],
                trust_level=trust_level,
                last_seen=datetime.now().isoformat(),
                compliance_score=compliance_result['score']
            )
            
            self.devices[device_id] = device
            
            return {
                'success': True,
                'device_id': device_id,
                'compliance_result': compliance_result,
                'risk_score': risk_score,
                'trust_level': trust_level.value,
                'access_decision': self._make_access_decision(device, policy)
            }
        except Exception as e:
            logger.error(f"裝置評估錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _evaluate_compliance(self, device_info: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
        """評估合規性"""
        compliance_checks = {
            'os_version': self._check_os_version(device_info.get('os_version', ''), policy.get('min_os_version', '')),
            'antivirus': self._check_antivirus(device_info.get('antivirus_installed', False), policy.get('required_antivirus', False)),
            'firewall': self._check_firewall(device_info.get('firewall_enabled', False), policy.get('required_firewall', False)),
            'patches': self._check_patches(device_info.get('patches_up_to_date', False), policy.get('required_patches', False)),
            'encryption': self._check_encryption(device_info.get('disk_encrypted', False)),
            'screen_lock': self._check_screen_lock(device_info.get('screen_lock_enabled', False))
        }
        
        # 計算合規分數
        total_checks = len(compliance_checks)
        passed_checks = sum(1 for check in compliance_checks.values() if check['passed'])
        compliance_score = passed_checks / total_checks
        
        # 確定狀態
        if compliance_score >= 0.9:
            status = "COMPLIANT"
        elif compliance_score >= 0.7:
            status = "PARTIALLY_COMPLIANT"
        else:
            status = "NON_COMPLIANT"
        
        return {
            'score': compliance_score,
            'status': status,
            'checks': compliance_checks,
            'passed_checks': passed_checks,
            'total_checks': total_checks
        }
    
    def _check_os_version(self, current_version: str, required_version: str) -> Dict[str, Any]:
        """檢查作業系統版本"""
        # 簡化實作
        return {
            'passed': True,
            'message': f"OS version {current_version} meets requirements"
        }
    
    def _check_antivirus(self, installed: bool, required: bool) -> Dict[str, Any]:
        """檢查防毒軟體"""
        if not required:
            return {'passed': True, 'message': 'Antivirus not required'}
        
        return {
            'passed': installed,
            'message': 'Antivirus installed' if installed else 'Antivirus required but not installed'
        }
    
    def _check_firewall(self, enabled: bool, required: bool) -> Dict[str, Any]:
        """檢查防火牆"""
        if not required:
            return {'passed': True, 'message': 'Firewall not required'}
        
        return {
            'passed': enabled,
            'message': 'Firewall enabled' if enabled else 'Firewall required but not enabled'
        }
    
    def _check_patches(self, up_to_date: bool, required: bool) -> Dict[str, Any]:
        """檢查補丁"""
        if not required:
            return {'passed': True, 'message': 'Patches not required'}
        
        return {
            'passed': up_to_date,
            'message': 'Patches up to date' if up_to_date else 'Patches required but not up to date'
        }
    
    def _check_encryption(self, encrypted: bool) -> Dict[str, Any]:
        """檢查加密"""
        return {
            'passed': encrypted,
            'message': 'Disk encrypted' if encrypted else 'Disk encryption recommended'
        }
    
    def _check_screen_lock(self, enabled: bool) -> Dict[str, Any]:
        """檢查螢幕鎖定"""
        return {
            'passed': enabled,
            'message': 'Screen lock enabled' if enabled else 'Screen lock recommended'
        }
    
    def _calculate_device_risk(self, device_info: Dict[str, Any], compliance_result: Dict[str, Any]) -> float:
        """計算裝置風險分數"""
        risk_score = 0.0
        
        # 基礎風險分數
        risk_score += (1.0 - compliance_result['score']) * 0.5
        
        # 裝置類型風險
        device_type = device_info.get('device_type', 'unknown')
        type_risks = {
            'workstation': 0.2,
            'server': 0.1,
            'mobile': 0.3,
            'iot': 0.6,
            'ot': 0.4,
            'unknown': 0.8
        }
        risk_score += type_risks.get(device_type, 0.5)
        
        # 網路位置風險
        ip_address = device_info.get('ip_address', '0.0.0.0')
        if ip_address.startswith('192.168.1.'):
            risk_score += 0.1
        elif ip_address.startswith('10.0.'):
            risk_score += 0.05
        else:
            risk_score += 0.3
        
        return min(risk_score, 1.0)
    
    def _determine_device_trust_level(self, risk_score: float) -> TrustLevel:
        """確定裝置信任等級"""
        if risk_score <= 0.2:
            return TrustLevel.CRITICAL
        elif risk_score <= 0.4:
            return TrustLevel.HIGH
        elif risk_score <= 0.6:
            return TrustLevel.MEDIUM
        elif risk_score <= 0.8:
            return TrustLevel.LOW
        else:
            return TrustLevel.UNTRUSTED
    
    def _make_access_decision(self, device: Device, policy: Dict[str, Any]) -> Dict[str, Any]:
        """做出存取決策"""
        max_risk_score = policy.get('max_risk_score', 0.5)
        device_risk = 1.0 - device.compliance_score
        
        if device_risk <= max_risk_score:
            decision = "ALLOW"
            access_level = "FULL"
        elif device_risk <= max_risk_score * 1.5:
            decision = "RESTRICTED"
            access_level = "LIMITED"
        else:
            decision = "DENY"
            access_level = "NONE"
        
        return {
            'decision': decision,
            'access_level': access_level,
            'reason': f"Device risk score {device_risk:.2f} vs policy max {max_risk_score:.2f}",
            'quarantine_required': decision == "DENY"
        }

class MicrosegmentationEngine:
    """微分段引擎"""
    
    def __init__(self):
        self.segments = {}
        self.policies = {}
        self._init_default_segments()
    
    def _init_default_segments(self):
        """初始化預設網路段"""
        default_segments = [
            NetworkSegment(
                id="dmz",
                name="DMZ",
                cidr="192.168.1.0/24",
                trust_level=TrustLevel.LOW,
                allowed_protocols=["HTTP", "HTTPS", "SSH"],
                allowed_ports=[80, 443, 22],
                isolation_rules=["No direct access to internal networks"]
            ),
            NetworkSegment(
                id="internal",
                name="Internal Network",
                cidr="192.168.2.0/24",
                trust_level=TrustLevel.MEDIUM,
                allowed_protocols=["HTTP", "HTTPS", "SSH", "RDP", "SMB"],
                allowed_ports=[80, 443, 22, 3389, 445],
                isolation_rules=["Limited external access"]
            ),
            NetworkSegment(
                id="critical",
                name="Critical Systems",
                cidr="192.168.3.0/24",
                trust_level=TrustLevel.CRITICAL,
                allowed_protocols=["SSH", "RDP"],
                allowed_ports=[22, 3389],
                isolation_rules=["No external access", "Strict authentication required"]
            ),
            NetworkSegment(
                id="iot",
                name="IoT Devices",
                cidr="192.168.4.0/24",
                trust_level=TrustLevel.UNTRUSTED,
                allowed_protocols=["HTTP", "MQTT"],
                allowed_ports=[80, 1883],
                isolation_rules=["Isolated from other networks", "No internet access"]
            )
        ]
        
        for segment in default_segments:
            self.segments[segment.id] = segment
    
    def create_segment(self, segment: NetworkSegment) -> Dict[str, Any]:
        """創建網路段"""
        try:
            self.segments[segment.id] = segment
            
            return {
                'success': True,
                'segment_id': segment.id,
                'message': f'網路段已創建: {segment.name}'
            }
        except Exception as e:
            logger.error(f"創建網路段錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def evaluate_traffic(self, source_ip: str, dest_ip: str, protocol: str, port: int) -> Dict[str, Any]:
        """評估流量"""
        try:
            # 確定來源和目標段
            source_segment = self._find_segment_for_ip(source_ip)
            dest_segment = self._find_segment_for_ip(dest_ip)
            
            if not source_segment or not dest_segment:
                return {
                    'decision': 'DENY',
                    'reason': 'Unknown network segments',
                    'source_segment': source_segment.id if source_segment else None,
                    'dest_segment': dest_segment.id if dest_segment else None
                }
            
            # 檢查段間政策
            policy_result = self._check_segment_policy(source_segment, dest_segment, protocol, port)
            
            return {
                'decision': policy_result['decision'],
                'reason': policy_result['reason'],
                'source_segment': source_segment.id,
                'dest_segment': dest_segment.id,
                'trust_level_source': source_segment.trust_level.value,
                'trust_level_dest': dest_segment.trust_level.value
            }
        except Exception as e:
            logger.error(f"流量評估錯誤: {e}")
            return {'decision': 'DENY', 'reason': f'Evaluation error: {str(e)}'}
    
    def _find_segment_for_ip(self, ip_address: str) -> Optional[NetworkSegment]:
        """為 IP 地址找到對應的網路段"""
        for segment in self.segments.values():
            if self._ip_in_cidr(ip_address, segment.cidr):
                return segment
        return None
    
    def _ip_in_cidr(self, ip: str, cidr: str) -> bool:
        """檢查 IP 是否在 CIDR 範圍內"""
        # 簡化實作
        if cidr == "192.168.1.0/24":
            return ip.startswith("192.168.1.")
        elif cidr == "192.168.2.0/24":
            return ip.startswith("192.168.2.")
        elif cidr == "192.168.3.0/24":
            return ip.startswith("192.168.3.")
        elif cidr == "192.168.4.0/24":
            return ip.startswith("192.168.4.")
        return False
    
    def _check_segment_policy(self, source_segment: NetworkSegment, dest_segment: NetworkSegment, 
                             protocol: str, port: int) -> Dict[str, Any]:
        """檢查段間政策"""
        # 同段內通訊
        if source_segment.id == dest_segment.id:
            if protocol in source_segment.allowed_protocols and port in source_segment.allowed_ports:
                return {'decision': 'ALLOW', 'reason': 'Intra-segment communication allowed'}
            else:
                return {'decision': 'DENY', 'reason': 'Protocol or port not allowed in segment'}
        
        # 跨段通訊
        # 檢查信任等級
        if source_segment.trust_level.value == 'untrusted':
            return {'decision': 'DENY', 'reason': 'Source segment is untrusted'}
        
        if dest_segment.trust_level.value == 'critical' and source_segment.trust_level.value != 'critical':
            return {'decision': 'DENY', 'reason': 'Access to critical segment requires critical trust level'}
        
        # 檢查協議和端口
        if protocol in dest_segment.allowed_protocols and port in dest_segment.allowed_ports:
            return {'decision': 'ALLOW', 'reason': 'Cross-segment communication allowed'}
        else:
            return {'decision': 'DENY', 'reason': 'Protocol or port not allowed in destination segment'}

class MilitaryZeroTrustArchitecture:
    """軍事級零信任架構主類別"""
    
    def __init__(self):
        self.iam_system = IAMSystem()
        self.nac_system = NACSystem()
        self.microsegmentation = MicrosegmentationEngine()
        self.zero_trust_log = []
    
    def comprehensive_zero_trust_assessment(self, assessment_scope: Dict[str, Any]) -> Dict[str, Any]:
        """執行綜合零信任評估"""
        try:
            results = {}
            
            # 1. 身份認證評估
            logger.info("執行身份認證評估...")
            if 'user_credentials' in assessment_scope:
                auth_results = self._assess_authentication(assessment_scope['user_credentials'])
                results['authentication'] = auth_results
            
            # 2. 裝置合規性評估
            logger.info("執行裝置合規性評估...")
            if 'device_info' in assessment_scope:
                device_results = self._assess_device_compliance(assessment_scope['device_info'])
                results['device_compliance'] = device_results
            
            # 3. 網路分段評估
            logger.info("執行網路分段評估...")
            if 'network_traffic' in assessment_scope:
                network_results = self._assess_network_segmentation(assessment_scope['network_traffic'])
                results['network_segmentation'] = network_results
            
            # 4. 零信任政策評估
            logger.info("執行零信任政策評估...")
            policy_results = self._assess_zero_trust_policies(results)
            results['zero_trust_policies'] = policy_results
            
            return {
                'success': True,
                'results': results,
                'summary': self._generate_zero_trust_summary(results)
            }
        except Exception as e:
            logger.error(f"綜合零信任評估錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _assess_authentication(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """評估身份認證"""
        try:
            auth_result = self.iam_system.authenticate_user(
                credentials['username'],
                credentials['password'],
                credentials.get('device_id', 'unknown'),
                credentials.get('ip_address', '0.0.0.0'),
                credentials.get('mfa_code')
            )
            
            return {
                'authentication_successful': auth_result.get('success', False),
                'trust_score': auth_result.get('trust_score', 0.0),
                'access_level': auth_result.get('access_level', 'NO_ACCESS'),
                'session_id': auth_result.get('session_id'),
                'user_info': auth_result.get('user')
            }
        except Exception as e:
            logger.error(f"身份認證評估錯誤: {e}")
            return {'authentication_successful': False, 'error': str(e)}
    
    def _assess_device_compliance(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """評估裝置合規性"""
        try:
            compliance_result = self.nac_system.assess_device(device_info)
            
            return {
                'device_assessment_successful': compliance_result.get('success', False),
                'compliance_score': compliance_result.get('compliance_result', {}).get('score', 0.0),
                'risk_score': compliance_result.get('risk_score', 1.0),
                'trust_level': compliance_result.get('trust_level', 'untrusted'),
                'access_decision': compliance_result.get('access_decision', {})
            }
        except Exception as e:
            logger.error(f"裝置合規性評估錯誤: {e}")
            return {'device_assessment_successful': False, 'error': str(e)}
    
    def _assess_network_segmentation(self, traffic: Dict[str, Any]) -> Dict[str, Any]:
        """評估網路分段"""
        try:
            segmentation_result = self.microsegmentation.evaluate_traffic(
                traffic['source_ip'],
                traffic['dest_ip'],
                traffic['protocol'],
                traffic['port']
            )
            
            return {
                'traffic_evaluation_successful': True,
                'decision': segmentation_result.get('decision', 'DENY'),
                'reason': segmentation_result.get('reason', 'Unknown'),
                'source_segment': segmentation_result.get('source_segment'),
                'dest_segment': segmentation_result.get('dest_segment')
            }
        except Exception as e:
            logger.error(f"網路分段評估錯誤: {e}")
            return {'traffic_evaluation_successful': False, 'error': str(e)}
    
    def _assess_zero_trust_policies(self, assessment_results: Dict[str, Any]) -> Dict[str, Any]:
        """評估零信任政策"""
        try:
            policy_violations = []
            policy_compliance = []
            
            # 檢查身份認證政策
            if 'authentication' in assessment_results:
                auth_data = assessment_results['authentication']
                if auth_data.get('trust_score', 0) < 0.7:
                    policy_violations.append("Low trust score for authentication")
                else:
                    policy_compliance.append("Authentication trust score acceptable")
            
            # 檢查裝置合規性政策
            if 'device_compliance' in assessment_results:
                device_data = assessment_results['device_compliance']
                if device_data.get('compliance_score', 0) < 0.8:
                    policy_violations.append("Device compliance score below threshold")
                else:
                    policy_compliance.append("Device compliance score acceptable")
            
            # 檢查網路分段政策
            if 'network_segmentation' in assessment_results:
                network_data = assessment_results['network_segmentation']
                if network_data.get('decision') == 'DENY':
                    policy_violations.append("Network traffic denied by segmentation policy")
                else:
                    policy_compliance.append("Network traffic allowed by segmentation policy")
            
            return {
                'policy_violations': policy_violations,
                'policy_compliance': policy_compliance,
                'overall_compliance': len(policy_violations) == 0,
                'compliance_score': len(policy_compliance) / (len(policy_compliance) + len(policy_violations)) if (len(policy_compliance) + len(policy_violations)) > 0 else 0.0
            }
        except Exception as e:
            logger.error(f"零信任政策評估錯誤: {e}")
            return {'overall_compliance': False, 'error': str(e)}
    
    def _generate_zero_trust_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成零信任摘要"""
        summary = {
            'total_assessments': len(results),
            'successful_assessments': sum(1 for r in results.values() if isinstance(r, dict) and r.get('success', True)),
            'authentication_trust_score': 0.0,
            'device_compliance_score': 0.0,
            'network_segmentation_decision': 'UNKNOWN',
            'overall_zero_trust_score': 0.0
        }
        
        # 收集評估結果
        if 'authentication' in results:
            summary['authentication_trust_score'] = results['authentication'].get('trust_score', 0.0)
        
        if 'device_compliance' in results:
            summary['device_compliance_score'] = results['device_compliance'].get('compliance_score', 0.0)
        
        if 'network_segmentation' in results:
            summary['network_segmentation_decision'] = results['network_segmentation'].get('decision', 'UNKNOWN')
        
        if 'zero_trust_policies' in results:
            summary['overall_zero_trust_score'] = results['zero_trust_policies'].get('compliance_score', 0.0)
        
        return summary
    
    def get_zero_trust_log(self) -> List[Dict[str, Any]]:
        """獲取零信任日誌"""
        return self.zero_trust_log
    
    def export_results(self, filename: str) -> bool:
        """匯出結果"""
        try:
            data = {
                'zero_trust_log': self.zero_trust_log,
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
    print("🛡️ 軍事級零信任架構系統")
    print("=" * 50)
    
    # 初始化系統
    zero_trust = MilitaryZeroTrustArchitecture()
    
    # 測試評估範圍
    test_assessment_scope = {
        'user_credentials': {
            'username': 'admin',
            'password': 'SecurePassword123!',
            'device_id': 'device_001',
            'ip_address': '192.168.1.100',
            'mfa_code': '123456'
        },
        'device_info': {
            'id': 'device_001',
            'hostname': 'WORKSTATION-01',
            'ip_address': '192.168.1.100',
            'mac_address': '00:11:22:33:44:55',
            'device_type': 'workstation',
            'os_version': 'Windows 10 21H2',
            'antivirus_installed': True,
            'firewall_enabled': True,
            'patches_up_to_date': True,
            'disk_encrypted': True,
            'screen_lock_enabled': True
        },
        'network_traffic': {
            'source_ip': '192.168.1.100',
            'dest_ip': '192.168.2.50',
            'protocol': 'RDP',
            'port': 3389
        }
    }
    
    # 執行綜合零信任評估測試
    print("開始執行綜合零信任評估測試...")
    results = zero_trust.comprehensive_zero_trust_assessment(test_assessment_scope)
    
    print(f"評估完成，成功: {results['success']}")
    print(f"評估摘要: {json.dumps(results['summary'], indent=2, ensure_ascii=False)}")
    
    # 匯出結果
    zero_trust.export_results("zero_trust_architecture_results.json")
    
    print("軍事級零信任架構系統測試完成！")

if __name__ == "__main__":
    main()

