#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高級威脅獵殺和APT檢測系統
Advanced Threat Hunting and APT Detection System

功能特色：
- 高級持續性威脅 (APT) 檢測
- 威脅獵殺和調查
- 行為分析和異常檢測
- 攻擊鏈重建
- 威脅情報關聯分析
- 軍事級威脅評估
- 自動化響應
- 紅隊模擬
"""

import json
import time
import logging
import hashlib
import networkx as nx
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from collections import defaultdict, deque
import threading
import yaml

logger = logging.getLogger(__name__)

class ThreatCategory(Enum):
    """威脅類別"""
    APT = "APT"
    MALWARE = "MALWARE"
    RANSOMWARE = "RANSOMWARE"
    BOTNET = "BOTNET"
    INSIDER_THREAT = "INSIDER_THREAT"
    ZERO_DAY = "ZERO_DAY"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    NATION_STATE = "NATION_STATE"

class AttackStage(Enum):
    """攻擊階段"""
    RECONNAISSANCE = "RECONNAISSANCE"
    WEAPONIZATION = "WEAPONIZATION"
    DELIVERY = "DELIVERY"
    EXPLOITATION = "EXPLOITATION"
    INSTALLATION = "INSTALLATION"
    COMMAND_CONTROL = "COMMAND_CONTROL"
    ACTIONS_OBJECTIVES = "ACTIONS_OBJECTIVES"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    EXFILTRATION = "EXFILTRATION"

class ThreatLevel(Enum):
    """威脅等級"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    MILITARY = 5

@dataclass
class ThreatIndicator:
    """威脅指標"""
    id: str
    type: str  # IP, Domain, Hash, Email, File
    value: str
    threat_category: ThreatCategory
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    context: Dict[str, Any]
    tags: List[str]

@dataclass
class AttackPattern:
    """攻擊模式"""
    id: str
    name: str
    description: str
    attack_stages: List[AttackStage]
    indicators: List[ThreatIndicator]
    techniques: List[str]
    threat_category: ThreatCategory
    confidence: float
    severity: ThreatLevel

@dataclass
class ThreatCampaign:
    """威脅活動"""
    id: str
    name: str
    description: str
    threat_category: ThreatCategory
    start_time: datetime
    end_time: Optional[datetime]
    attack_patterns: List[AttackPattern]
    affected_assets: List[str]
    threat_actors: List[str]
    severity: ThreatLevel
    status: str  # ACTIVE, INACTIVE, MITIGATED

@dataclass
class BehavioralProfile:
    """行為檔案"""
    entity_id: str
    entity_type: str  # USER, HOST, NETWORK
    normal_behavior: Dict[str, Any]
    anomaly_scores: Dict[str, float]
    risk_score: float
    last_updated: datetime
    historical_data: List[Dict[str, Any]]

class AdvancedThreatHunter:
    """高級威脅獵殺系統"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.threat_indicators: Dict[str, ThreatIndicator] = {}
        self.attack_patterns: Dict[str, AttackPattern] = {}
        self.threat_campaigns: Dict[str, ThreatCampaign] = {}
        self.behavioral_profiles: Dict[str, BehavioralProfile] = {}
        self.attack_graph = nx.DiGraph()
        
        # 機器學習模型
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.threat_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        
        # 統計數據
        self.hunting_stats = {
            'threats_detected': 0,
            'campaigns_identified': 0,
            'false_positives': 0,
            'investigations_completed': 0
        }
        
        # 初始化資料庫
        self._init_database()
        
        # 載入已知攻擊模式
        self._load_attack_patterns()
        
        # 啟動背景分析
        self._start_background_analysis()
        
        logger.info("高級威脅獵殺系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('threat_hunting.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立威脅指標表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id TEXT PRIMARY KEY,
                type TEXT,
                value TEXT,
                threat_category TEXT,
                confidence REAL,
                source TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                context TEXT,
                tags TEXT
            )
        ''')
        
        # 建立攻擊模式表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_patterns (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                attack_stages TEXT,
                indicators TEXT,
                techniques TEXT,
                threat_category TEXT,
                confidence REAL,
                severity INTEGER
            )
        ''')
        
        # 建立威脅活動表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_campaigns (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                threat_category TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                attack_patterns TEXT,
                affected_assets TEXT,
                threat_actors TEXT,
                severity INTEGER,
                status TEXT
            )
        ''')
        
        # 建立行為檔案表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS behavioral_profiles (
                id TEXT PRIMARY KEY,
                entity_id TEXT,
                entity_type TEXT,
                normal_behavior TEXT,
                anomaly_scores TEXT,
                risk_score REAL,
                last_updated TIMESTAMP,
                historical_data TEXT
            )
        ''')
        
        self.db_conn.commit()

    def _load_attack_patterns(self):
        """載入已知攻擊模式"""
        # APT攻擊模式
        apt_patterns = [
            {
                'id': 'apt_001',
                'name': 'APT29 (Cozy Bear)',
                'description': '俄羅斯國家級APT組織攻擊模式',
                'attack_stages': [
                    AttackStage.RECONNAISSANCE,
                    AttackStage.DELIVERY,
                    AttackStage.EXPLOITATION,
                    AttackStage.PERSISTENCE,
                    AttackStage.LATERAL_MOVEMENT,
                    AttackStage.EXFILTRATION
                ],
                'techniques': [
                    'T1566.001',  # Phishing: Spearphishing Attachment
                    'T1059.001',  # Command and Scripting Interpreter: PowerShell
                    'T1071.001',  # Application Layer Protocol: Web Protocols
                    'T1021.001',  # Remote Services: Remote Desktop Protocol
                    'T1041',      # Exfiltration Over C2 Channel
                ],
                'threat_category': ThreatCategory.NATION_STATE,
                'confidence': 0.9,
                'severity': ThreatLevel.MILITARY
            },
            {
                'id': 'apt_002',
                'name': 'APT1 (Comment Crew)',
                'description': '中國國家級APT組織攻擊模式',
                'attack_stages': [
                    AttackStage.RECONNAISSANCE,
                    AttackStage.WEAPONIZATION,
                    AttackStage.DELIVERY,
                    AttackStage.EXPLOITATION,
                    AttackStage.INSTALLATION,
                    AttackStage.COMMAND_CONTROL,
                    AttackStage.ACTIONS_OBJECTIVES
                ],
                'techniques': [
                    'T1566.002',  # Phishing: Spearphishing Link
                    'T1055',      # Process Injection
                    'T1071.002',  # Application Layer Protocol: File Transfer Protocols
                    'T1021.002',  # Remote Services: SMB/Windows Admin Shares
                    'T1003.001',  # OS Credential Dumping: LSASS Memory
                ],
                'threat_category': ThreatCategory.NATION_STATE,
                'confidence': 0.85,
                'severity': ThreatLevel.MILITARY
            }
        ]
        
        for pattern_data in apt_patterns:
            pattern = AttackPattern(
                id=pattern_data['id'],
                name=pattern_data['name'],
                description=pattern_data['description'],
                attack_stages=pattern_data['attack_stages'],
                indicators=[],
                techniques=pattern_data['techniques'],
                threat_category=pattern_data['threat_category'],
                confidence=pattern_data['confidence'],
                severity=pattern_data['severity']
            )
            self.attack_patterns[pattern.id] = pattern

    def hunt_threats(self, data: Dict[str, Any]) -> List[ThreatCampaign]:
        """威脅獵殺"""
        detected_campaigns = []
        
        # 1. 行為分析
        behavioral_anomalies = self._analyze_behavioral_anomalies(data)
        
        # 2. 攻擊模式匹配
        pattern_matches = self._match_attack_patterns(data)
        
        # 3. 威脅情報關聯
        intel_correlations = self._correlate_threat_intelligence(data)
        
        # 4. 攻擊鏈重建
        attack_chains = self._reconstruct_attack_chains(data)
        
        # 5. 綜合分析
        campaigns = self._synthesize_campaigns(
            behavioral_anomalies, pattern_matches, 
            intel_correlations, attack_chains
        )
        
        for campaign in campaigns:
            if campaign not in self.threat_campaigns:
                self.threat_campaigns[campaign.id] = campaign
                self._save_campaign(campaign)
                detected_campaigns.append(campaign)
                self.hunting_stats['campaigns_identified'] += 1
        
        return detected_campaigns

    def _analyze_behavioral_anomalies(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """行為異常分析"""
        anomalies = []
        
        # 提取行為特徵
        features = self._extract_behavioral_features(data)
        
        if len(features) > 0:
            # 標準化特徵
            features_scaled = self.scaler.fit_transform(features)
            
            # 異常檢測
            anomaly_scores = self.anomaly_detector.decision_function(features_scaled)
            predictions = self.anomaly_detector.predict(features_scaled)
            
            for i, (score, prediction) in enumerate(zip(anomaly_scores, predictions)):
                if prediction == -1:  # 異常
                    anomalies.append({
                        'entity_id': data.get('entity_id', f'entity_{i}'),
                        'anomaly_score': abs(score),
                        'features': features[i].tolist(),
                        'timestamp': datetime.now()
                    })
        
        return anomalies

    def _match_attack_patterns(self, data: Dict[str, Any]) -> List[AttackPattern]:
        """攻擊模式匹配"""
        matches = []
        
        for pattern in self.attack_patterns.values():
            match_score = self._calculate_pattern_match_score(data, pattern)
            
            if match_score > 0.7:  # 匹配閾值
                matches.append(pattern)
        
        return matches

    def _correlate_threat_intelligence(self, data: Dict[str, Any]) -> List[ThreatIndicator]:
        """威脅情報關聯分析"""
        correlations = []
        
        # 檢查IP地址
        if 'source_ip' in data:
            ip_indicators = self._check_ip_indicators(data['source_ip'])
            correlations.extend(ip_indicators)
        
        # 檢查域名
        if 'domain' in data:
            domain_indicators = self._check_domain_indicators(data['domain'])
            correlations.extend(domain_indicators)
        
        # 檢查檔案雜湊
        if 'file_hash' in data:
            hash_indicators = self._check_hash_indicators(data['file_hash'])
            correlations.extend(hash_indicators)
        
        return correlations

    def _reconstruct_attack_chains(self, data: Dict[str, Any]) -> List[List[AttackStage]]:
        """攻擊鏈重建"""
        attack_chains = []
        
        # 基於時間序列重建攻擊鏈
        events = data.get('events', [])
        if len(events) > 1:
            # 按時間排序事件
            sorted_events = sorted(events, key=lambda x: x.get('timestamp', 0))
            
            # 識別攻擊階段
            stages = []
            for event in sorted_events:
                stage = self._classify_attack_stage(event)
                if stage:
                    stages.append(stage)
            
            if len(stages) > 2:  # 至少需要3個階段才構成攻擊鏈
                attack_chains.append(stages)
        
        return attack_chains

    def _synthesize_campaigns(self, behavioral_anomalies: List[Dict],
                            pattern_matches: List[AttackPattern],
                            intel_correlations: List[ThreatIndicator],
                            attack_chains: List[List[AttackStage]]) -> List[ThreatCampaign]:
        """綜合分析生成威脅活動"""
        campaigns = []
        
        # 如果有足夠的證據，建立威脅活動
        if (len(behavioral_anomalies) > 0 or 
            len(pattern_matches) > 0 or 
            len(intel_correlations) > 0 or 
            len(attack_chains) > 0):
            
            campaign_id = self._generate_campaign_id()
            
            # 確定威脅類別
            threat_category = self._determine_threat_category(
                pattern_matches, intel_correlations
            )
            
            # 計算嚴重程度
            severity = self._calculate_severity(
                behavioral_anomalies, pattern_matches, 
                intel_correlations, attack_chains
            )
            
            campaign = ThreatCampaign(
                id=campaign_id,
                name=f"Threat Campaign {campaign_id}",
                description=f"檢測到的威脅活動: {threat_category.value}",
                threat_category=threat_category,
                start_time=datetime.now(),
                end_time=None,
                attack_patterns=pattern_matches,
                affected_assets=self._extract_affected_assets(behavioral_anomalies),
                threat_actors=self._identify_threat_actors(intel_correlations),
                severity=severity,
                status="ACTIVE"
            )
            
            campaigns.append(campaign)
        
        return campaigns

    def _extract_behavioral_features(self, data: Dict[str, Any]) -> np.ndarray:
        """提取行為特徵"""
        features = []
        
        # 網路行為特徵
        if 'network_activity' in data:
            network_data = data['network_activity']
            features.extend([
                network_data.get('packet_count', 0),
                network_data.get('bytes_transferred', 0),
                network_data.get('unique_connections', 0),
                network_data.get('failed_connections', 0),
                network_data.get('port_scan_attempts', 0)
            ])
        
        # 系統行為特徵
        if 'system_activity' in data:
            system_data = data['system_activity']
            features.extend([
                system_data.get('process_count', 0),
                system_data.get('file_operations', 0),
                system_data.get('registry_changes', 0),
                system_data.get('service_starts', 0),
                system_data.get('user_logins', 0)
            ])
        
        # 時間特徵
        current_time = datetime.now()
        features.extend([
            current_time.hour,
            current_time.weekday(),
            current_time.day,
            current_time.month
        ])
        
        return np.array(features).reshape(1, -1) if features else np.array([])

    def _calculate_pattern_match_score(self, data: Dict[str, Any], 
                                     pattern: AttackPattern) -> float:
        """計算攻擊模式匹配分數"""
        score = 0.0
        total_indicators = len(pattern.techniques)
        
        if total_indicators == 0:
            return 0.0
        
        # 檢查技術指標
        for technique in pattern.techniques:
            if self._check_technique_presence(data, technique):
                score += 1.0
        
        # 檢查攻擊階段
        detected_stages = self._detect_attack_stages(data)
        stage_matches = len(set(detected_stages) & set(pattern.attack_stages))
        score += (stage_matches / len(pattern.attack_stages)) * 0.5
        
        return score / (total_indicators + 0.5)

    def _check_technique_presence(self, data: Dict[str, Any], technique: str) -> bool:
        """檢查技術指標是否存在"""
        # 簡化的技術檢測邏輯
        technique_indicators = {
            'T1566.001': ['email_attachment', 'malicious_file'],
            'T1059.001': ['powershell_command', 'script_execution'],
            'T1071.001': ['http_communication', 'https_communication'],
            'T1021.001': ['rdp_connection', 'remote_desktop'],
            'T1041': ['data_exfiltration', 'c2_communication'],
            'T1055': ['process_injection', 'dll_injection'],
            'T1003.001': ['lsass_access', 'credential_dumping']
        }
        
        if technique in technique_indicators:
            indicators = technique_indicators[technique]
            for indicator in indicators:
                if indicator in str(data).lower():
                    return True
        
        return False

    def _detect_attack_stages(self, data: Dict[str, Any]) -> List[AttackStage]:
        """檢測攻擊階段"""
        stages = []
        
        # 基於數據特徵檢測攻擊階段
        if 'reconnaissance' in str(data).lower():
            stages.append(AttackStage.RECONNAISSANCE)
        
        if 'exploit' in str(data).lower() or 'vulnerability' in str(data).lower():
            stages.append(AttackStage.EXPLOITATION)
        
        if 'persistence' in str(data).lower() or 'backdoor' in str(data).lower():
            stages.append(AttackStage.PERSISTENCE)
        
        if 'lateral' in str(data).lower() or 'movement' in str(data).lower():
            stages.append(AttackStage.LATERAL_MOVEMENT)
        
        if 'exfiltration' in str(data).lower() or 'data_theft' in str(data).lower():
            stages.append(AttackStage.EXFILTRATION)
        
        return stages

    def _check_ip_indicators(self, ip: str) -> List[ThreatIndicator]:
        """檢查IP威脅指標"""
        indicators = []
        
        # 檢查已知惡意IP
        if ip in self.threat_indicators:
            indicators.append(self.threat_indicators[ip])
        
        return indicators

    def _check_domain_indicators(self, domain: str) -> List[ThreatIndicator]:
        """檢查域名威脅指標"""
        indicators = []
        
        # 檢查已知惡意域名
        for indicator in self.threat_indicators.values():
            if indicator.type == 'Domain' and domain in indicator.value:
                indicators.append(indicator)
        
        return indicators

    def _check_hash_indicators(self, file_hash: str) -> List[ThreatIndicator]:
        """檢查檔案雜湊威脅指標"""
        indicators = []
        
        # 檢查已知惡意檔案雜湊
        for indicator in self.threat_indicators.values():
            if indicator.type == 'Hash' and file_hash == indicator.value:
                indicators.append(indicator)
        
        return indicators

    def _classify_attack_stage(self, event: Dict[str, Any]) -> Optional[AttackStage]:
        """分類攻擊階段"""
        event_type = event.get('type', '').lower()
        event_data = str(event).lower()
        
        if 'scan' in event_type or 'recon' in event_data:
            return AttackStage.RECONNAISSANCE
        elif 'exploit' in event_type or 'vulnerability' in event_data:
            return AttackStage.EXPLOITATION
        elif 'install' in event_type or 'backdoor' in event_data:
            return AttackStage.INSTALLATION
        elif 'persist' in event_type or 'startup' in event_data:
            return AttackStage.PERSISTENCE
        elif 'lateral' in event_data or 'movement' in event_data:
            return AttackStage.LATERAL_MOVEMENT
        elif 'exfil' in event_data or 'theft' in event_data:
            return AttackStage.EXFILTRATION
        
        return None

    def _determine_threat_category(self, pattern_matches: List[AttackPattern],
                                 intel_correlations: List[ThreatIndicator]) -> ThreatCategory:
        """確定威脅類別"""
        if not pattern_matches and not intel_correlations:
            return ThreatCategory.MALWARE
        
        # 基於攻擊模式確定類別
        if pattern_matches:
            categories = [p.threat_category for p in pattern_matches]
            return max(set(categories), key=categories.count)
        
        # 基於威脅情報確定類別
        if intel_correlations:
            categories = [i.threat_category for i in intel_correlations]
            return max(set(categories), key=categories.count)
        
        return ThreatCategory.MALWARE

    def _calculate_severity(self, behavioral_anomalies: List[Dict],
                          pattern_matches: List[AttackPattern],
                          intel_correlations: List[ThreatIndicator],
                          attack_chains: List[List[AttackStage]]) -> ThreatLevel:
        """計算嚴重程度"""
        severity_score = 0
        
        # 行為異常嚴重程度
        if behavioral_anomalies:
            max_anomaly_score = max(a['anomaly_score'] for a in behavioral_anomalies)
            severity_score += max_anomaly_score * 2
        
        # 攻擊模式嚴重程度
        if pattern_matches:
            max_pattern_severity = max(p.severity.value for p in pattern_matches)
            severity_score += max_pattern_severity
        
        # 威脅情報嚴重程度
        if intel_correlations:
            severity_score += len(intel_correlations) * 0.5
        
        # 攻擊鏈複雜度
        if attack_chains:
            max_chain_length = max(len(chain) for chain in attack_chains)
            severity_score += max_chain_length * 0.3
        
        # 映射到威脅等級
        if severity_score >= 4:
            return ThreatLevel.MILITARY
        elif severity_score >= 3:
            return ThreatLevel.CRITICAL
        elif severity_score >= 2:
            return ThreatLevel.HIGH
        elif severity_score >= 1:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _extract_affected_assets(self, behavioral_anomalies: List[Dict]) -> List[str]:
        """提取受影響資產"""
        assets = []
        
        for anomaly in behavioral_anomalies:
            entity_id = anomaly.get('entity_id')
            if entity_id:
                assets.append(entity_id)
        
        return list(set(assets))

    def _identify_threat_actors(self, intel_correlations: List[ThreatIndicator]) -> List[str]:
        """識別威脅行為者"""
        actors = []
        
        for indicator in intel_correlations:
            if 'threat_actor' in indicator.context:
                actors.append(indicator.context['threat_actor'])
        
        return list(set(actors))

    def _generate_campaign_id(self) -> str:
        """生成活動ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"CAMPAIGN_{timestamp}"

    def _save_campaign(self, campaign: ThreatCampaign):
        """儲存威脅活動"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO threat_campaigns 
            (id, name, description, threat_category, start_time, end_time,
             attack_patterns, affected_assets, threat_actors, severity, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            campaign.id, campaign.name, campaign.description, campaign.threat_category.value,
            campaign.start_time.isoformat(), campaign.end_time.isoformat() if campaign.end_time else None,
            json.dumps([p.id for p in campaign.attack_patterns]),
            json.dumps(campaign.affected_assets),
            json.dumps(campaign.threat_actors),
            campaign.severity.value, campaign.status
        ))
        self.db_conn.commit()

    def _start_background_analysis(self):
        """啟動背景分析"""
        def analysis_loop():
            while True:
                try:
                    # 定期分析行為檔案
                    self._update_behavioral_profiles()
                    
                    # 更新攻擊圖
                    self._update_attack_graph()
                    
                    time.sleep(3600)  # 每小時分析一次
                
                except Exception as e:
                    logger.error(f"背景分析錯誤: {e}")
                    time.sleep(1800)  # 錯誤時等待30分鐘
        
        analysis_thread = threading.Thread(target=analysis_loop, daemon=True)
        analysis_thread.start()

    def _update_behavioral_profiles(self):
        """更新行為檔案"""
        # 簡化的行為檔案更新邏輯
        pass

    def _update_attack_graph(self):
        """更新攻擊圖"""
        # 簡化的攻擊圖更新邏輯
        pass

    def get_threat_intelligence(self) -> Dict[str, Any]:
        """獲取威脅情報"""
        return {
            'total_indicators': len(self.threat_indicators),
            'total_patterns': len(self.attack_patterns),
            'active_campaigns': len([c for c in self.threat_campaigns.values() if c.status == "ACTIVE"]),
            'hunting_stats': self.hunting_stats,
            'threat_categories': {
                category.value: len([c for c in self.threat_campaigns.values() if c.threat_category == category])
                for category in ThreatCategory
            }
        }

def main():
    """主程式"""
    config = {
        'anomaly_threshold': 0.7,
        'pattern_match_threshold': 0.7,
        'analysis_interval': 3600
    }
    
    hunter = AdvancedThreatHunter(config)
    
    # 測試威脅獵殺
    test_data = {
        'entity_id': 'test_host_001',
        'source_ip': '192.168.1.100',
        'domain': 'malicious.example.com',
        'events': [
            {'type': 'reconnaissance', 'timestamp': datetime.now()},
            {'type': 'exploit', 'timestamp': datetime.now()},
            {'type': 'persistence', 'timestamp': datetime.now()}
        ],
        'network_activity': {
            'packet_count': 1000,
            'bytes_transferred': 50000,
            'unique_connections': 10,
            'failed_connections': 5,
            'port_scan_attempts': 2
        },
        'system_activity': {
            'process_count': 50,
            'file_operations': 200,
            'registry_changes': 10,
            'service_starts': 2,
            'user_logins': 1
        }
    }
    
    campaigns = hunter.hunt_threats(test_data)
    print(f"檢測到 {len(campaigns)} 個威脅活動")
    
    for campaign in campaigns:
        print(f"活動: {campaign.name}, 類別: {campaign.threat_category.value}, 嚴重程度: {campaign.severity.value}")
    
    # 顯示統計
    stats = hunter.get_threat_intelligence()
    print(f"威脅情報統計: {stats}")

if __name__ == "__main__":
    main()


