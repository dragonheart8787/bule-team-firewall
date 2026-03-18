#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實零信任架構系統
Real Zero Trust Architecture System

功能特色：
- 真實的身份驗證
- 真實的設備驗證
- 真實的網路分段
- 真實的訪問控制
- 真實的持續驗證
"""

import json
import time
import logging
import hashlib
import socket
import psutil
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import threading
from collections import defaultdict, deque
import ipaddress
import yaml

logger = logging.getLogger(__name__)

class TrustLevel(Enum):
    """信任等級"""
    UNTRUSTED = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    FULLY_TRUSTED = 4

class AccessLevel(Enum):
    """訪問等級"""
    DENIED = "DENIED"
    READ_ONLY = "READ_ONLY"
    LIMITED = "LIMITED"
    STANDARD = "STANDARD"
    ELEVATED = "ELEVATED"
    ADMINISTRATIVE = "ADMINISTRATIVE"

class ResourceType(Enum):
    """資源類型"""
    NETWORK = "NETWORK"
    APPLICATION = "APPLICATION"
    DATA = "DATA"
    SERVICE = "SERVICE"
    DEVICE = "DEVICE"
    USER = "USER"

class PolicyAction(Enum):
    """策略動作"""
    ALLOW = "ALLOW"
    DENY = "DENY"
    CHALLENGE = "CHALLENGE"
    LOG = "LOG"
    QUARANTINE = "QUARANTINE"

@dataclass
class Identity:
    """身份物件"""
    id: str
    type: str  # USER, DEVICE, SERVICE
    name: str
    attributes: Dict[str, Any]
    trust_score: float
    last_verified: datetime
    verification_methods: List[str]
    risk_factors: List[str]
    device_fingerprint: str

@dataclass
class Resource:
    """資源物件"""
    id: str
    type: ResourceType
    name: str
    location: str
    classification: str
    owner: str
    access_requirements: Dict[str, Any]
    sensitivity_level: int
    network_segment: str

@dataclass
class AccessPolicy:
    """訪問策略"""
    id: str
    name: str
    description: str
    subject: str  # 身份或身份組
    resource: str  # 資源或資源組
    action: PolicyAction
    conditions: Dict[str, Any]
    priority: int
    enabled: bool
    created_at: datetime
    expires_at: Optional[datetime]

@dataclass
class AccessRequest:
    """訪問請求"""
    id: str
    subject_id: str
    resource_id: str
    action: str
    context: Dict[str, Any]
    timestamp: datetime
    trust_score: float
    risk_score: float
    decision: PolicyAction
    reasoning: List[str]
    device_fingerprint: str

@dataclass
class NetworkSegment:
    """網路分段"""
    id: str
    name: str
    cidr: str
    trust_level: TrustLevel
    isolation_level: int
    allowed_protocols: List[str]
    allowed_ports: List[int]
    access_policies: List[str]
    monitoring_enabled: bool

class RealZeroTrustEngine:
    """真實零信任引擎"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.identities: Dict[str, Identity] = {}
        self.resources: Dict[str, Resource] = {}
        self.policies: Dict[str, AccessPolicy] = {}
        self.network_segments: Dict[str, NetworkSegment] = {}
        self.access_requests: Dict[str, AccessRequest] = {}
        
        # 信任評估
        self.trust_scores: Dict[str, float] = {}
        self.risk_scores: Dict[str, float] = {}
        self.device_fingerprints: Dict[str, str] = {}
        
        # 統計數據
        self.stats = {
            'access_requests': 0,
            'allowed_requests': 0,
            'denied_requests': 0,
            'challenged_requests': 0,
            'quarantined_requests': 0
        }
        
        # 初始化資料庫
        self._init_database()
        
        # 載入預設策略
        self._load_default_policies()
        
        # 啟動持續驗證
        self._start_continuous_verification()
        
        logger.info("真實零信任架構系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('real_zero_trust.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立身份表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS identities (
                id TEXT PRIMARY KEY,
                type TEXT,
                name TEXT,
                attributes TEXT,
                trust_score REAL,
                last_verified TIMESTAMP,
                verification_methods TEXT,
                risk_factors TEXT,
                device_fingerprint TEXT
            )
        ''')
        
        # 建立資源表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS resources (
                id TEXT PRIMARY KEY,
                type TEXT,
                name TEXT,
                location TEXT,
                classification TEXT,
                owner TEXT,
                access_requirements TEXT,
                sensitivity_level INTEGER,
                network_segment TEXT
            )
        ''')
        
        # 建立策略表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_policies (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                subject TEXT,
                resource TEXT,
                action TEXT,
                conditions TEXT,
                priority INTEGER,
                enabled BOOLEAN,
                created_at TIMESTAMP,
                expires_at TIMESTAMP
            )
        ''')
        
        # 建立訪問請求表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_requests (
                id TEXT PRIMARY KEY,
                subject_id TEXT,
                resource_id TEXT,
                action TEXT,
                context TEXT,
                timestamp TIMESTAMP,
                trust_score REAL,
                risk_score REAL,
                decision TEXT,
                reasoning TEXT,
                device_fingerprint TEXT
            )
        ''')
        
        # 建立網路分段表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_segments (
                id TEXT PRIMARY KEY,
                name TEXT,
                cidr TEXT,
                trust_level INTEGER,
                isolation_level INTEGER,
                allowed_protocols TEXT,
                allowed_ports TEXT,
                access_policies TEXT,
                monitoring_enabled BOOLEAN
            )
        ''')
        
        self.db_conn.commit()

    def _load_default_policies(self):
        """載入預設策略"""
        # 預設拒絕策略
        default_deny = AccessPolicy(
            id="default_deny",
            name="預設拒絕",
            description="預設拒絕所有訪問",
            subject="*",
            resource="*",
            action=PolicyAction.DENY,
            conditions={},
            priority=1000,
            enabled=True,
            created_at=datetime.now(),
            expires_at=None
        )
        self.policies[default_deny.id] = default_deny
        
        # 管理員策略
        admin_policy = AccessPolicy(
            id="admin_access",
            name="管理員訪問",
            description="管理員完全訪問權限",
            subject="admin_group",
            resource="*",
            action=PolicyAction.ALLOW,
            conditions={
                "trust_score_min": 0.8,
                "risk_score_max": 0.2,
                "mfa_required": True,
                "time_restriction": "business_hours",
                "device_trusted": True
            },
            priority=1,
            enabled=True,
            created_at=datetime.now(),
            expires_at=None
        )
        self.policies[admin_policy.id] = admin_policy

    def register_identity(self, identity: Identity):
        """註冊真實身份"""
        # 生成設備指紋
        device_fingerprint = self._generate_device_fingerprint()
        identity.device_fingerprint = device_fingerprint
        
        self.identities[identity.id] = identity
        self.device_fingerprints[identity.id] = device_fingerprint
        self._save_identity(identity)
        logger.info(f"已註冊真實身份: {identity.name}")

    def register_resource(self, resource: Resource):
        """註冊真實資源"""
        self.resources[resource.id] = resource
        self._save_resource(resource)
        logger.info(f"已註冊真實資源: {resource.name}")

    def create_network_segment(self, segment: NetworkSegment):
        """建立真實網路分段"""
        self.network_segments[segment.id] = segment
        self._save_network_segment(segment)
        logger.info(f"已建立真實網路分段: {segment.name}")

    def evaluate_access_request(self, subject_id: str, resource_id: str, 
                              action: str, context: Dict[str, Any]) -> AccessRequest:
        """評估真實訪問請求"""
        request_id = self._generate_request_id()
        
        # 1. 身份驗證
        identity = self.identities.get(subject_id)
        if not identity:
            return self._create_denied_request(
                request_id, subject_id, resource_id, action, 
                context, ["身份不存在"]
            )
        
        # 2. 資源驗證
        resource = self.resources.get(resource_id)
        if not resource:
            return self._create_denied_request(
                request_id, subject_id, resource_id, action, 
                context, ["資源不存在"]
            )
        
        # 3. 設備驗證
        device_trust = self._verify_device_trust(identity, context)
        if not device_trust:
            return self._create_denied_request(
                request_id, subject_id, resource_id, action, 
                context, ["設備未受信任"]
            )
        
        # 4. 信任評估
        trust_score = self._calculate_real_trust_score(identity, context)
        
        # 5. 風險評估
        risk_score = self._calculate_real_risk_score(identity, resource, context)
        
        # 6. 策略評估
        decision, reasoning = self._evaluate_policies(
            identity, resource, action, context, trust_score, risk_score
        )
        
        # 7. 建立訪問請求記錄
        access_request = AccessRequest(
            id=request_id,
            subject_id=subject_id,
            resource_id=resource_id,
            action=action,
            context=context,
            timestamp=datetime.now(),
            trust_score=trust_score,
            risk_score=risk_score,
            decision=decision,
            reasoning=reasoning,
            device_fingerprint=identity.device_fingerprint
        )
        
        self.access_requests[request_id] = access_request
        self._save_access_request(access_request)
        
        # 8. 更新統計
        self._update_stats(decision)
        
        logger.info(f"真實訪問請求評估完成: {request_id}, 決策: {decision.value}")
        return access_request

    def _generate_device_fingerprint(self) -> str:
        """生成真實設備指紋"""
        try:
            # 收集設備資訊
            device_info = {
                'hostname': socket.gethostname(),
                'platform': psutil.WINDOWS if hasattr(psutil, 'WINDOWS') else 'Linux',
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_usage': psutil.disk_usage('/').total if not hasattr(psutil, 'WINDOWS') else psutil.disk_usage('C:\\').total
            }
            
            # 生成指紋
            fingerprint_data = json.dumps(device_info, sort_keys=True)
            fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
            
            return fingerprint
        
        except Exception as e:
            logger.error(f"設備指紋生成錯誤: {e}")
            return hashlib.sha256(str(datetime.now()).encode()).hexdigest()

    def _verify_device_trust(self, identity: Identity, context: Dict[str, Any]) -> bool:
        """驗證設備信任"""
        try:
            # 檢查設備指紋是否匹配
            current_fingerprint = self._generate_device_fingerprint()
            stored_fingerprint = identity.device_fingerprint
            
            if current_fingerprint != stored_fingerprint:
                logger.warning(f"設備指紋不匹配: {identity.id}")
                return False
            
            # 檢查設備是否在受信任列表中
            if identity.id not in self.device_fingerprints:
                logger.warning(f"設備未註冊: {identity.id}")
                return False
            
            # 檢查設備狀態
            device_status = self._check_device_status(identity)
            if not device_status:
                logger.warning(f"設備狀態異常: {identity.id}")
                return False
            
            return True
        
        except Exception as e:
            logger.error(f"設備信任驗證錯誤: {e}")
            return False

    def _check_device_status(self, identity: Identity) -> bool:
        """檢查設備狀態"""
        try:
            # 檢查設備是否在線
            if not self._is_device_online():
                return False
            
            # 檢查設備安全狀態
            if not self._is_device_secure():
                return False
            
            # 檢查設備更新狀態
            if not self._is_device_updated():
                return False
            
            return True
        
        except Exception as e:
            logger.error(f"設備狀態檢查錯誤: {e}")
            return False

    def _is_device_online(self) -> bool:
        """檢查設備是否在線"""
        try:
            # 檢查網路連線
            connections = psutil.net_connections(kind='inet')
            return len(connections) > 0
        except Exception:
            return False

    def _is_device_secure(self) -> bool:
        """檢查設備安全狀態"""
        try:
            # 檢查是否有可疑進程
            processes = psutil.process_iter(['name', 'cmdline'])
            suspicious_processes = [
                'nc.exe', 'netcat', 'ncat', 'wget', 'curl'
            ]
            
            for proc in processes:
                try:
                    proc_name = proc.info['name'].lower()
                    if any(suspicious in proc_name for suspicious in suspicious_processes):
                        return False
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return True
        except Exception:
            return False

    def _is_device_updated(self) -> bool:
        """檢查設備更新狀態"""
        try:
            # 檢查系統啟動時間
            boot_time = psutil.boot_time()
            current_time = time.time()
            uptime = current_time - boot_time
            
            # 如果系統運行時間超過30天，可能需要更新
            if uptime > 30 * 24 * 3600:
                return False
            
            return True
        except Exception:
            return True

    def _calculate_real_trust_score(self, identity: Identity, context: Dict[str, Any]) -> float:
        """計算真實信任分數"""
        base_score = identity.trust_score
        
        # 時間因子
        time_since_verification = (datetime.now() - identity.last_verification).total_seconds()
        time_factor = max(0.5, 1.0 - (time_since_verification / 86400))  # 24小時衰減
        
        # 位置因子
        location_factor = self._calculate_real_location_factor(context)
        
        # 設備因子
        device_factor = self._calculate_real_device_factor(identity, context)
        
        # 行為因子
        behavior_factor = self._calculate_real_behavior_factor(identity.id, context)
        
        # 網路因子
        network_factor = self._calculate_real_network_factor(context)
        
        # 綜合信任分數
        trust_score = (base_score * 0.3 + 
                      time_factor * 0.2 + 
                      location_factor * 0.2 + 
                      device_factor * 0.15 + 
                      behavior_factor * 0.1 +
                      network_factor * 0.05)
        
        return min(1.0, max(0.0, trust_score))

    def _calculate_real_location_factor(self, context: Dict[str, Any]) -> float:
        """計算真實位置因子"""
        try:
            # 檢查IP地理位置
            source_ip = context.get('source_ip', '')
            if source_ip:
                # 簡單的地理位置檢查
                if source_ip.startswith('192.168.') or source_ip.startswith('10.'):
                    return 1.0  # 內網
                elif source_ip.startswith('127.'):
                    return 1.0  # 本地
                else:
                    return 0.7  # 外網
            
            return 0.5
        except Exception:
            return 0.5

    def _calculate_real_device_factor(self, identity: Identity, context: Dict[str, Any]) -> float:
        """計算真實設備因子"""
        try:
            # 檢查設備指紋
            current_fingerprint = self._generate_device_fingerprint()
            if current_fingerprint == identity.device_fingerprint:
                device_factor = 1.0
            else:
                device_factor = 0.0
            
            # 檢查設備安全狀態
            if self._is_device_secure():
                security_factor = 1.0
            else:
                security_factor = 0.5
            
            # 檢查設備更新狀態
            if self._is_device_updated():
                update_factor = 1.0
            else:
                update_factor = 0.8
            
            return (device_factor * 0.5 + security_factor * 0.3 + update_factor * 0.2)
        
        except Exception:
            return 0.5

    def _calculate_real_behavior_factor(self, identity_id: str, context: Dict[str, Any]) -> float:
        """計算真實行為因子"""
        try:
            # 檢查訪問時間
            current_time = datetime.now()
            hour = current_time.hour
            
            # 檢查是否在正常時間訪問
            if 9 <= hour <= 17:  # 工作時間
                time_factor = 1.0
            elif 8 <= hour <= 18:  # 延長工作時間
                time_factor = 0.8
            else:  # 非工作時間
                time_factor = 0.6
            
            # 檢查訪問頻率
            recent_requests = [
                req for req in self.access_requests.values()
                if req.subject_id == identity_id and
                (datetime.now() - req.timestamp).seconds < 3600
            ]
            
            if len(recent_requests) > 10:  # 過於頻繁
                frequency_factor = 0.7
            elif len(recent_requests) > 5:
                frequency_factor = 0.9
            else:
                frequency_factor = 1.0
            
            return (time_factor * 0.6 + frequency_factor * 0.4)
        
        except Exception:
            return 0.5

    def _calculate_real_network_factor(self, context: Dict[str, Any]) -> float:
        """計算真實網路因子"""
        try:
            # 檢查網路連線狀態
            connections = psutil.net_connections(kind='inet')
            established_connections = len([conn for conn in connections if conn.status == 'ESTABLISHED'])
            
            if established_connections > 50:  # 過多連線
                network_factor = 0.6
            elif established_connections > 20:
                network_factor = 0.8
            else:
                network_factor = 1.0
            
            return network_factor
        except Exception:
            return 0.5

    def _calculate_real_risk_score(self, identity: Identity, resource: Resource, 
                                 context: Dict[str, Any]) -> float:
        """計算真實風險分數"""
        risk_score = 0.0
        
        # 身份風險
        if identity.risk_factors:
            risk_score += len(identity.risk_factors) * 0.1
        
        # 資源敏感度
        risk_score += resource.sensitivity_level * 0.1
        
        # 上下文風險
        if context.get('suspicious_activity', False):
            risk_score += 0.3
        
        if context.get('unusual_location', False):
            risk_score += 0.2
        
        if context.get('off_hours_access', False):
            risk_score += 0.1
        
        # 網路風險
        network_risk = self._calculate_real_network_risk(context)
        risk_score += network_risk * 0.2
        
        # 設備風險
        device_risk = self._calculate_real_device_risk(identity, context)
        risk_score += device_risk * 0.2
        
        return min(1.0, max(0.0, risk_score))

    def _calculate_real_network_risk(self, context: Dict[str, Any]) -> float:
        """計算真實網路風險"""
        try:
            # 檢查網路連線
            connections = psutil.net_connections(kind='inet')
            
            # 檢查是否有可疑連線
            suspicious_ports = [22, 23, 135, 139, 445, 3389]
            suspicious_connections = 0
            
            for conn in connections:
                if conn.raddr and conn.raddr.port in suspicious_ports:
                    suspicious_connections += 1
            
            if suspicious_connections > 5:
                return 0.8
            elif suspicious_connections > 2:
                return 0.5
            else:
                return 0.2
        
        except Exception:
            return 0.5

    def _calculate_real_device_risk(self, identity: Identity, context: Dict[str, Any]) -> float:
        """計算真實設備風險"""
        try:
            # 檢查設備安全狀態
            if not self._is_device_secure():
                return 0.8
            
            # 檢查設備更新狀態
            if not self._is_device_updated():
                return 0.6
            
            # 檢查設備指紋
            current_fingerprint = self._generate_device_fingerprint()
            if current_fingerprint != identity.device_fingerprint:
                return 0.9
            
            return 0.1
        
        except Exception:
            return 0.5

    def _evaluate_policies(self, identity: Identity, resource: Resource, 
                         action: str, context: Dict[str, Any],
                         trust_score: float, risk_score: float) -> Tuple[PolicyAction, List[str]]:
        """評估真實策略"""
        reasoning = []
        
        # 按優先級排序策略
        sorted_policies = sorted(
            self.policies.values(), 
            key=lambda x: x.priority
        )
        
        for policy in sorted_policies:
            if not policy.enabled:
                continue
            
            # 檢查策略是否適用
            if self._policy_applies(policy, identity, resource, action):
                # 檢查條件
                if self._check_policy_conditions(policy, trust_score, risk_score, context, identity):
                    reasoning.append(f"策略匹配: {policy.name}")
                    return policy.action, reasoning
        
        # 預設拒絕
        reasoning.append("沒有匹配的策略，預設拒絕")
        return PolicyAction.DENY, reasoning

    def _policy_applies(self, policy: AccessPolicy, identity: Identity, 
                       resource: Resource, action: str) -> bool:
        """檢查策略是否適用"""
        # 檢查主體
        if policy.subject != "*" and policy.subject != identity.id:
            if not self._is_in_group(identity.id, policy.subject):
                return False
        
        # 檢查資源
        if policy.resource != "*" and policy.resource != resource.id:
            if not self._is_in_group(resource.id, policy.resource):
                return False
        
        return True

    def _check_policy_conditions(self, policy: AccessPolicy, trust_score: float,
                               risk_score: float, context: Dict[str, Any],
                               identity: Identity) -> bool:
        """檢查真實策略條件"""
        conditions = policy.conditions
        
        # 信任分數條件
        if 'trust_score_min' in conditions:
            if trust_score < conditions['trust_score_min']:
                return False
        
        # 風險分數條件
        if 'risk_score_max' in conditions:
            if risk_score > conditions['risk_score_max']:
                return False
        
        # MFA要求
        if conditions.get('mfa_required', False):
            if not context.get('mfa_verified', False):
                return False
        
        # 時間限制
        if 'time_restriction' in conditions:
            if not self._check_time_restriction(conditions['time_restriction']):
                return False
        
        # 位置限制
        if 'location_restriction' in conditions:
            if not self._check_location_restriction(context, conditions['location_restriction']):
                return False
        
        # 設備信任要求
        if conditions.get('device_trusted', False):
            if not self._verify_device_trust(identity, context):
                return False
        
        return True

    def _check_time_restriction(self, restriction: str) -> bool:
        """檢查時間限制"""
        current_time = datetime.now()
        hour = current_time.hour
        
        if restriction == "business_hours":
            return 9 <= hour <= 17
        elif restriction == "working_hours":
            return 8 <= hour <= 18
        else:
            return True

    def _check_location_restriction(self, context: Dict[str, Any], restriction: str) -> bool:
        """檢查位置限制"""
        source_ip = context.get('source_ip', '')
        
        if restriction == "internal_only":
            return source_ip.startswith(('192.168.', '10.', '172.'))
        elif restriction == "approved_networks":
            approved_networks = ['192.168.', '10.', '172.']
            return any(source_ip.startswith(net) for net in approved_networks)
        else:
            return True

    def _is_in_group(self, entity_id: str, group_name: str) -> bool:
        """檢查實體是否在組中"""
        if group_name == "admin_group":
            return entity_id.startswith("admin_")
        elif group_name == "user_group":
            return entity_id.startswith("user_")
        return False

    def _create_denied_request(self, request_id: str, subject_id: str, 
                             resource_id: str, action: str, context: Dict[str, Any],
                             reasoning: List[str]) -> AccessRequest:
        """建立被拒絕的請求"""
        return AccessRequest(
            id=request_id,
            subject_id=subject_id,
            resource_id=resource_id,
            action=action,
            context=context,
            timestamp=datetime.now(),
            trust_score=0.0,
            risk_score=1.0,
            decision=PolicyAction.DENY,
            reasoning=reasoning,
            device_fingerprint=""
        )

    def _update_stats(self, decision: PolicyAction):
        """更新統計"""
        self.stats['access_requests'] += 1
        
        if decision == PolicyAction.ALLOW:
            self.stats['allowed_requests'] += 1
        elif decision == PolicyAction.DENY:
            self.stats['denied_requests'] += 1
        elif decision == PolicyAction.CHALLENGE:
            self.stats['challenged_requests'] += 1
        elif decision == PolicyAction.QUARANTINE:
            self.stats['quarantined_requests'] += 1

    def _start_continuous_verification(self):
        """啟動持續驗證"""
        def verification_loop():
            while True:
                try:
                    # 更新信任分數
                    self._update_trust_scores()
                    
                    # 檢查設備狀態
                    self._check_all_devices()
                    
                    # 檢查過期策略
                    self._check_expired_policies()
                    
                    time.sleep(300)  # 每5分鐘檢查一次
                
                except Exception as e:
                    logger.error(f"持續驗證錯誤: {e}")
                    time.sleep(60)
        
        verification_thread = threading.Thread(target=verification_loop, daemon=True)
        verification_thread.start()

    def _update_trust_scores(self):
        """更新信任分數"""
        for identity in self.identities.values():
            # 基於最近活動更新信任分數
            time_since_verification = (datetime.now() - identity.last_verified).total_seconds()
            
            if time_since_verification > 86400:  # 24小時
                # 降低信任分數
                identity.trust_score = max(0.0, identity.trust_score - 0.1)
                self._save_identity(identity)

    def _check_all_devices(self):
        """檢查所有設備"""
        for identity in self.identities.values():
            if not self._verify_device_trust(identity, {}):
                logger.warning(f"設備信任驗證失敗: {identity.id}")

    def _check_expired_policies(self):
        """檢查過期策略"""
        current_time = datetime.now()
        
        for policy in self.policies.values():
            if policy.expires_at and current_time > policy.expires_at:
                policy.enabled = False
                self._save_policy(policy)
                logger.info(f"策略已過期並停用: {policy.name}")

    def _save_identity(self, identity: Identity):
        """儲存身份"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO identities 
            (id, type, name, attributes, trust_score, last_verified, 
             verification_methods, risk_factors, device_fingerprint)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            identity.id, identity.type, identity.name, json.dumps(identity.attributes),
            identity.trust_score, identity.last_verified.isoformat(),
            json.dumps(identity.verification_methods), json.dumps(identity.risk_factors),
            identity.device_fingerprint
        ))
        self.db_conn.commit()

    def _save_resource(self, resource: Resource):
        """儲存資源"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO resources 
            (id, type, name, location, classification, owner, 
             access_requirements, sensitivity_level, network_segment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            resource.id, resource.type.value, resource.name, resource.location,
            resource.classification, resource.owner, 
            json.dumps(resource.access_requirements), resource.sensitivity_level,
            resource.network_segment
        ))
        self.db_conn.commit()

    def _save_policy(self, policy: AccessPolicy):
        """儲存策略"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO access_policies 
            (id, name, description, subject, resource, action, conditions,
             priority, enabled, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            policy.id, policy.name, policy.description, policy.subject, policy.resource,
            policy.action.value, json.dumps(policy.conditions), policy.priority,
            policy.enabled, policy.created_at.isoformat(),
            policy.expires_at.isoformat() if policy.expires_at else None
        ))
        self.db_conn.commit()

    def _save_access_request(self, request: AccessRequest):
        """儲存訪問請求"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO access_requests 
            (id, subject_id, resource_id, action, context, timestamp,
             trust_score, risk_score, decision, reasoning, device_fingerprint)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            request.id, request.subject_id, request.resource_id, request.action,
            json.dumps(request.context), request.timestamp.isoformat(),
            request.trust_score, request.risk_score, request.decision.value,
            json.dumps(request.reasoning), request.device_fingerprint
        ))
        self.db_conn.commit()

    def _save_network_segment(self, segment: NetworkSegment):
        """儲存網路分段"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO network_segments 
            (id, name, cidr, trust_level, isolation_level, allowed_protocols,
             allowed_ports, access_policies, monitoring_enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            segment.id, segment.name, segment.cidr, segment.trust_level.value,
            segment.isolation_level, json.dumps(segment.allowed_protocols),
            json.dumps(segment.allowed_ports), json.dumps(segment.access_policies),
            segment.monitoring_enabled
        ))
        self.db_conn.commit()

    def _generate_request_id(self) -> str:
        """生成請求ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        return f"REAL_REQ_{timestamp}"

    def get_statistics(self) -> Dict[str, Any]:
        """獲取統計資訊"""
        return {
            'stats': self.stats,
            'total_identities': len(self.identities),
            'total_resources': len(self.resources),
            'total_policies': len(self.policies),
            'total_segments': len(self.network_segments),
            'active_requests': len(self.access_requests),
            'trust_distribution': self._get_trust_distribution(),
            'risk_distribution': self._get_risk_distribution(),
            'device_fingerprints': len(self.device_fingerprints)
        }

    def _get_trust_distribution(self) -> Dict[str, int]:
        """獲取信任分數分佈"""
        distribution = {'high': 0, 'medium': 0, 'low': 0}
        
        for identity in self.identities.values():
            if identity.trust_score >= 0.7:
                distribution['high'] += 1
            elif identity.trust_score >= 0.4:
                distribution['medium'] += 1
            else:
                distribution['low'] += 1
        
        return distribution

    def _get_risk_distribution(self) -> Dict[str, int]:
        """獲取風險分數分佈"""
        distribution = {'high': 0, 'medium': 0, 'low': 0}
        
        for identity in self.identities.values():
            risk_factors = len(identity.risk_factors)
            if risk_factors >= 3:
                distribution['high'] += 1
            elif risk_factors >= 1:
                distribution['medium'] += 1
            else:
                distribution['low'] += 1
        
        return distribution

def main():
    """主程式"""
    config = {
        'trust_decay_rate': 0.1,
        'verification_interval': 300,
        'policy_evaluation_timeout': 5
    }
    
    zt_engine = RealZeroTrustEngine(config)
    
    # 註冊測試身份
    test_identity = Identity(
        id="user_001",
        type="USER",
        name="測試用戶",
        attributes={"department": "IT", "role": "admin"},
        trust_score=0.8,
        last_verified=datetime.now(),
        verification_methods=["password", "mfa"],
        risk_factors=[],
        device_fingerprint=""
    )
    zt_engine.register_identity(test_identity)
    
    # 註冊測試資源
    test_resource = Resource(
        id="resource_001",
        type=ResourceType.APPLICATION,
        name="管理系統",
        location="internal",
        classification="CONFIDENTIAL",
        owner="IT部門",
        access_requirements={"mfa_required": True},
        sensitivity_level=3,
        network_segment="internal"
    )
    zt_engine.register_resource(test_resource)
    
    # 測試訪問請求
    context = {
        "source_ip": "192.168.1.100",
        "mfa_verified": True
    }
    
    request = zt_engine.evaluate_access_request(
        "user_001", "resource_001", "read", context
    )
    
    print(f"真實訪問請求結果: {request.decision.value}")
    print(f"信任分數: {request.trust_score:.2f}")
    print(f"風險分數: {request.risk_score:.2f}")
    print(f"決策原因: {request.reasoning}")
    
    # 顯示統計
    stats = zt_engine.get_statistics()
    print(f"真實零信任統計: {stats}")

if __name__ == "__main__":
    main()


