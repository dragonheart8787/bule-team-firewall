#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級AI威脅獵捕系統
實作 ML模型檢測異常流量、UEBA、AI驅動威脅獵捕
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
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import joblib

# 設定日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AnomalyType(Enum):
    """異常類型枚舉"""
    NETWORK_ANOMALY = "network_anomaly"
    USER_BEHAVIOR_ANOMALY = "user_behavior_anomaly"
    SYSTEM_ANOMALY = "system_anomaly"
    DATA_ANOMALY = "data_anomaly"
    TEMPORAL_ANOMALY = "temporal_anomaly"

class ThreatLevel(Enum):
    """威脅等級枚舉"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class UserBehavior:
    """用戶行為資料結構"""
    user_id: str
    timestamp: str
    action: str
    resource: str
    source_ip: str
    success: bool
    duration: float
    data_volume: int
    risk_score: float

@dataclass
class NetworkFlow:
    """網路流資料結構"""
    id: str
    timestamp: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    duration: float
    packets_sent: int
    packets_received: int

@dataclass
class AnomalyDetection:
    """異常檢測結果資料結構"""
    id: str
    anomaly_type: AnomalyType
    entity_id: str
    timestamp: str
    confidence: float
    threat_level: ThreatLevel
    description: str
    features: Dict[str, float]
    model_used: str

class MLAnomalyDetector:
    """機器學習異常檢測器"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_importance = {}
        self._init_models()
    
    def _init_models(self):
        """初始化 ML 模型"""
        try:
            # 網路異常檢測模型
            self.models['network_anomaly'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            # 用戶行為異常檢測模型
            self.models['user_behavior'] = IsolationForest(
                contamination=0.05,
                random_state=42,
                n_estimators=100
            )
            
            # 系統異常檢測模型
            self.models['system_anomaly'] = IsolationForest(
                contamination=0.15,
                random_state=42,
                n_estimators=100
            )
            
            # 特徵標準化器
            self.scalers['network'] = StandardScaler()
            self.scalers['user_behavior'] = StandardScaler()
            self.scalers['system'] = StandardScaler()
            
            logger.info("ML 模型初始化完成")
        except Exception as e:
            logger.error(f"ML 模型初始化錯誤: {e}")
    
    def train_network_anomaly_model(self, network_data: List[NetworkFlow]) -> Dict[str, Any]:
        """訓練網路異常檢測模型"""
        try:
            # 提取特徵
            features = self._extract_network_features(network_data)
            
            if len(features) < 10:
                return {'success': False, 'error': '訓練數據不足'}
            
            # 標準化特徵
            features_scaled = self.scalers['network'].fit_transform(features)
            
            # 訓練模型
            self.models['network_anomaly'].fit(features_scaled)
            
            # 計算特徵重要性
            self.feature_importance['network'] = self._calculate_feature_importance(
                features_scaled, self.models['network_anomaly']
            )
            
            return {
                'success': True,
                'model_trained': True,
                'training_samples': len(features),
                'feature_count': features.shape[1],
                'feature_importance': self.feature_importance['network']
            }
        except Exception as e:
            logger.error(f"網路異常模型訓練錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def train_user_behavior_model(self, user_data: List[UserBehavior]) -> Dict[str, Any]:
        """訓練用戶行為異常檢測模型"""
        try:
            # 提取特徵
            features = self._extract_user_behavior_features(user_data)
            
            if len(features) < 10:
                return {'success': False, 'error': '訓練數據不足'}
            
            # 標準化特徵
            features_scaled = self.scalers['user_behavior'].fit_transform(features)
            
            # 訓練模型
            self.models['user_behavior'].fit(features_scaled)
            
            # 計算特徵重要性
            self.feature_importance['user_behavior'] = self._calculate_feature_importance(
                features_scaled, self.models['user_behavior']
            )
            
            return {
                'success': True,
                'model_trained': True,
                'training_samples': len(features),
                'feature_count': features.shape[1],
                'feature_importance': self.feature_importance['user_behavior']
            }
        except Exception as e:
            logger.error(f"用戶行為異常模型訓練錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def detect_network_anomalies(self, network_data: List[NetworkFlow]) -> List[AnomalyDetection]:
        """檢測網路異常"""
        try:
            if 'network_anomaly' not in self.models:
                return []
            
            # 提取特徵
            features = self._extract_network_features(network_data)
            
            if len(features) == 0:
                return []
            
            # 標準化特徵
            features_scaled = self.scalers['network'].transform(features)
            
            # 預測異常
            anomaly_scores = self.models['network_anomaly'].decision_function(features_scaled)
            predictions = self.models['network_anomaly'].predict(features_scaled)
            
            # 生成異常檢測結果
            anomalies = []
            for i, (flow, score, prediction) in enumerate(zip(network_data, anomaly_scores, predictions)):
                if prediction == -1:  # 異常
                    confidence = abs(score)
                    threat_level = self._determine_threat_level(confidence)
                    
                    anomaly = AnomalyDetection(
                        id=f"network_anomaly_{i}",
                        anomaly_type=AnomalyType.NETWORK_ANOMALY,
                        entity_id=flow.id,
                        timestamp=flow.timestamp,
                        confidence=confidence,
                        threat_level=threat_level,
                        description=f"Network anomaly detected: {flow.source_ip} -> {flow.dest_ip}",
                        features=self._get_network_feature_dict(features[i]),
                        model_used="IsolationForest"
                    )
                    anomalies.append(anomaly)
            
            return anomalies
        except Exception as e:
            logger.error(f"網路異常檢測錯誤: {e}")
            return []
    
    def detect_user_behavior_anomalies(self, user_data: List[UserBehavior]) -> List[AnomalyDetection]:
        """檢測用戶行為異常"""
        try:
            if 'user_behavior' not in self.models:
                return []
            
            # 提取特徵
            features = self._extract_user_behavior_features(user_data)
            
            if len(features) == 0:
                return []
            
            # 標準化特徵
            features_scaled = self.scalers['user_behavior'].transform(features)
            
            # 預測異常
            anomaly_scores = self.models['user_behavior'].decision_function(features_scaled)
            predictions = self.models['user_behavior'].predict(features_scaled)
            
            # 生成異常檢測結果
            anomalies = []
            for i, (behavior, score, prediction) in enumerate(zip(user_data, anomaly_scores, predictions)):
                if prediction == -1:  # 異常
                    confidence = abs(score)
                    threat_level = self._determine_threat_level(confidence)
                    
                    anomaly = AnomalyDetection(
                        id=f"user_behavior_anomaly_{i}",
                        anomaly_type=AnomalyType.USER_BEHAVIOR_ANOMALY,
                        entity_id=behavior.user_id,
                        timestamp=behavior.timestamp,
                        confidence=confidence,
                        threat_level=threat_level,
                        description=f"User behavior anomaly detected: {behavior.user_id} - {behavior.action}",
                        features=self._get_user_behavior_feature_dict(features[i]),
                        model_used="IsolationForest"
                    )
                    anomalies.append(anomaly)
            
            return anomalies
        except Exception as e:
            logger.error(f"用戶行為異常檢測錯誤: {e}")
            return []
    
    def _extract_network_features(self, network_data: List[NetworkFlow]) -> np.ndarray:
        """提取網路特徵"""
        try:
            features = []
            for flow in network_data:
                # 處理字典格式的資料
                if isinstance(flow, dict):
                    feature_vector = [
                        flow.get('bytes_sent', 0),
                        flow.get('bytes_received', 0),
                        flow.get('duration', 0.0),
                        flow.get('packets_sent', 0),
                        flow.get('packets_received', 0),
                        flow.get('source_port', 0),
                        flow.get('dest_port', 0),
                        self._ip_to_numeric(flow.get('source_ip', '0.0.0.0')),
                        self._ip_to_numeric(flow.get('dest_ip', '0.0.0.0')),
                        self._protocol_to_numeric(flow.get('protocol', 'TCP'))
                    ]
                else:
                    # 處理物件格式的資料
                    feature_vector = [
                        flow.bytes_sent,
                        flow.bytes_received,
                        flow.duration,
                        flow.packets_sent,
                        flow.packets_received,
                        flow.source_port,
                        flow.dest_port,
                        self._ip_to_numeric(flow.source_ip),
                        self._ip_to_numeric(flow.dest_ip),
                        self._protocol_to_numeric(flow.protocol)
                    ]
                features.append(feature_vector)
            
            return np.array(features)
        except Exception as e:
            logger.error(f"提取網路特徵錯誤: {e}")
            return np.array([])
    
    def _extract_user_behavior_features(self, user_data: List[UserBehavior]) -> np.ndarray:
        """提取用戶行為特徵"""
        try:
            features = []
            for behavior in user_data:
                # 處理字典格式的資料
                if isinstance(behavior, dict):
                    feature_vector = [
                        behavior.get('duration', 0.0),
                        behavior.get('data_volume', 0),
                        self._action_to_numeric(behavior.get('action', 'unknown')),
                        self._ip_to_numeric(behavior.get('source_ip', '0.0.0.0')),
                        1 if behavior.get('success', False) else 0,
                        behavior.get('risk_score', 0.0)
                    ]
                else:
                    # 處理物件格式的資料
                    feature_vector = [
                        behavior.duration,
                        behavior.data_volume,
                        self._action_to_numeric(behavior.action),
                        self._ip_to_numeric(behavior.source_ip),
                        1 if behavior.success else 0,
                        behavior.risk_score
                    ]
                features.append(feature_vector)
            
            return np.array(features)
        except Exception as e:
            logger.error(f"提取用戶行為特徵錯誤: {e}")
            return np.array([])
    
    def _ip_to_numeric(self, ip_address: str) -> float:
        """將 IP 地址轉換為數值"""
        try:
            parts = ip_address.split('.')
            if len(parts) == 4:
                return sum(int(part) * (256 ** (3 - i)) for i, part in enumerate(parts))
            return 0.0
        except:
            return 0.0
    
    def _protocol_to_numeric(self, protocol: str) -> int:
        """將協議轉換為數值"""
        protocol_map = {
            'TCP': 1,
            'UDP': 2,
            'ICMP': 3,
            'HTTP': 4,
            'HTTPS': 5,
            'DNS': 6
        }
        return protocol_map.get(protocol.upper(), 0)
    
    def _action_to_numeric(self, action: str) -> int:
        """將動作轉換為數值"""
        action_map = {
            'login': 1,
            'logout': 2,
            'file_access': 3,
            'database_query': 4,
            'network_access': 5,
            'system_command': 6
        }
        return action_map.get(action.lower(), 0)
    
    def _calculate_feature_importance(self, features: np.ndarray, model) -> Dict[str, float]:
        """計算特徵重要性"""
        try:
            # 簡化實作，實際應該使用更複雜的方法
            feature_names = [
                'bytes_sent', 'bytes_received', 'duration', 'packets_sent', 'packets_received',
                'source_port', 'dest_port', 'source_ip', 'dest_ip', 'protocol'
            ]
            
            importance = {}
            for i, name in enumerate(feature_names):
                if i < features.shape[1]:
                    importance[name] = float(np.std(features[:, i]))
            
            return importance
        except Exception as e:
            logger.error(f"計算特徵重要性錯誤: {e}")
            return {}
    
    def _determine_threat_level(self, confidence: float) -> ThreatLevel:
        """確定威脅等級"""
        if confidence >= 0.8:
            return ThreatLevel.CRITICAL
        elif confidence >= 0.6:
            return ThreatLevel.HIGH
        elif confidence >= 0.4:
            return ThreatLevel.MEDIUM
        elif confidence >= 0.2:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFO
    
    def _get_network_feature_dict(self, features: np.ndarray) -> Dict[str, float]:
        """獲取網路特徵字典"""
        feature_names = [
            'bytes_sent', 'bytes_received', 'duration', 'packets_sent', 'packets_received',
            'source_port', 'dest_port', 'source_ip', 'dest_ip', 'protocol'
        ]
        
        feature_dict = {}
        for i, name in enumerate(feature_names):
            if i < len(features):
                feature_dict[name] = float(features[i])
        
        return feature_dict
    
    def _get_user_behavior_feature_dict(self, features: np.ndarray) -> Dict[str, float]:
        """獲取用戶行為特徵字典"""
        feature_names = [
            'duration', 'data_volume', 'action', 'source_ip', 'success', 'risk_score'
        ]
        
        feature_dict = {}
        for i, name in enumerate(feature_names):
            if i < len(features):
                feature_dict[name] = float(features[i])
        
        return feature_dict

class UEBAEngine:
    """用戶與實體行為分析引擎"""
    
    def __init__(self):
        self.user_profiles = {}
        self.behavior_baselines = {}
        self.anomaly_thresholds = {
            'login_time': 0.3,
            'resource_access': 0.4,
            'data_volume': 0.5,
            'geographic_location': 0.6
        }
    
    def build_user_profile(self, user_id: str, behavior_data: List[UserBehavior]) -> Dict[str, Any]:
        """建立用戶檔案"""
        try:
            if not behavior_data:
                return {'success': False, 'error': '沒有行為數據'}
            
            # 分析用戶行為模式
            profile = {
                'user_id': user_id,
                'total_actions': len(behavior_data),
                'unique_actions': len(set(b.action for b in behavior_data)),
                'unique_resources': len(set(b.resource for b in behavior_data)),
                'unique_ips': len(set(b.source_ip for b in behavior_data)),
                'success_rate': sum(1 for b in behavior_data if b.success) / len(behavior_data),
                'avg_duration': np.mean([b.duration for b in behavior_data]),
                'avg_data_volume': np.mean([b.data_volume for b in behavior_data]),
                'risk_score_avg': np.mean([b.risk_score for b in behavior_data]),
                'action_frequency': self._calculate_action_frequency(behavior_data),
                'resource_frequency': self._calculate_resource_frequency(behavior_data),
                'ip_frequency': self._calculate_ip_frequency(behavior_data),
                'time_patterns': self._analyze_time_patterns(behavior_data)
            }
            
            self.user_profiles[user_id] = profile
            
            return {
                'success': True,
                'profile': profile,
                'message': f'用戶檔案已建立: {user_id}'
            }
        except Exception as e:
            logger.error(f"建立用戶檔案錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def detect_user_anomalies(self, user_id: str, current_behavior: UserBehavior) -> Dict[str, Any]:
        """檢測用戶異常"""
        try:
            if user_id not in self.user_profiles:
                return {'anomaly_detected': False, 'reason': 'No user profile found'}
            
            profile = self.user_profiles[user_id]
            anomalies = []
            anomaly_score = 0.0
            
            # 檢查動作頻率異常
            action_freq = profile['action_frequency'].get(current_behavior.action, 0)
            if action_freq < 0.1:  # 很少執行的動作
                anomalies.append(f"Unusual action: {current_behavior.action}")
                anomaly_score += 0.3
            
            # 檢查資源存取異常
            resource_freq = profile['resource_frequency'].get(current_behavior.resource, 0)
            if resource_freq < 0.05:  # 很少存取的資源
                anomalies.append(f"Unusual resource access: {current_behavior.resource}")
                anomaly_score += 0.2
            
            # 檢查 IP 地址異常
            ip_freq = profile['ip_frequency'].get(current_behavior.source_ip, 0)
            if ip_freq < 0.1:  # 很少使用的 IP
                anomalies.append(f"Unusual source IP: {current_behavior.source_ip}")
                anomaly_score += 0.2
            
            # 檢查數據量異常
            if current_behavior.data_volume > profile['avg_data_volume'] * 3:
                anomalies.append(f"Unusual data volume: {current_behavior.data_volume}")
                anomaly_score += 0.2
            
            # 檢查持續時間異常
            if current_behavior.duration > profile['avg_duration'] * 5:
                anomalies.append(f"Unusual duration: {current_behavior.duration}")
                anomaly_score += 0.1
            
            return {
                'anomaly_detected': len(anomalies) > 0,
                'anomaly_score': min(anomaly_score, 1.0),
                'anomalies': anomalies,
                'threat_level': self._determine_ueba_threat_level(anomaly_score)
            }
        except Exception as e:
            logger.error(f"檢測用戶異常錯誤: {e}")
            return {'anomaly_detected': False, 'error': str(e)}
    
    def _calculate_action_frequency(self, behavior_data: List[UserBehavior]) -> Dict[str, float]:
        """計算動作頻率"""
        action_counts = {}
        total_actions = len(behavior_data)
        
        for behavior in behavior_data:
            action_counts[behavior.action] = action_counts.get(behavior.action, 0) + 1
        
        return {action: count / total_actions for action, count in action_counts.items()}
    
    def _calculate_resource_frequency(self, behavior_data: List[UserBehavior]) -> Dict[str, float]:
        """計算資源頻率"""
        resource_counts = {}
        total_actions = len(behavior_data)
        
        for behavior in behavior_data:
            resource_counts[behavior.resource] = resource_counts.get(behavior.resource, 0) + 1
        
        return {resource: count / total_actions for resource, count in resource_counts.items()}
    
    def _calculate_ip_frequency(self, behavior_data: List[UserBehavior]) -> Dict[str, float]:
        """計算 IP 頻率"""
        ip_counts = {}
        total_actions = len(behavior_data)
        
        for behavior in behavior_data:
            ip_counts[behavior.source_ip] = ip_counts.get(behavior.source_ip, 0) + 1
        
        return {ip: count / total_actions for ip, count in ip_counts.items()}
    
    def _analyze_time_patterns(self, behavior_data: List[UserBehavior]) -> Dict[str, Any]:
        """分析時間模式"""
        try:
            hours = []
            for behavior in behavior_data:
                timestamp = datetime.fromisoformat(behavior.timestamp.replace('Z', '+00:00'))
                hours.append(timestamp.hour)
            
            return {
                'peak_hours': self._find_peak_hours(hours),
                'activity_distribution': self._calculate_hourly_distribution(hours)
            }
        except Exception as e:
            logger.error(f"分析時間模式錯誤: {e}")
            return {'peak_hours': [], 'activity_distribution': {}}
    
    def _find_peak_hours(self, hours: List[int]) -> List[int]:
        """找到高峰時段"""
        hour_counts = {}
        for hour in hours:
            hour_counts[hour] = hour_counts.get(hour, 0) + 1
        
        # 返回活動最多的前3個小時
        sorted_hours = sorted(hour_counts.items(), key=lambda x: x[1], reverse=True)
        return [hour for hour, count in sorted_hours[:3]]
    
    def _calculate_hourly_distribution(self, hours: List[int]) -> Dict[int, float]:
        """計算每小時分佈"""
        hour_counts = {}
        total_hours = len(hours)
        
        for hour in hours:
            hour_counts[hour] = hour_counts.get(hour, 0) + 1
        
        return {hour: count / total_hours for hour, count in hour_counts.items()}
    
    def _determine_ueba_threat_level(self, anomaly_score: float) -> ThreatLevel:
        """確定 UEBA 威脅等級"""
        if anomaly_score >= 0.7:
            return ThreatLevel.CRITICAL
        elif anomaly_score >= 0.5:
            return ThreatLevel.HIGH
        elif anomaly_score >= 0.3:
            return ThreatLevel.MEDIUM
        elif anomaly_score >= 0.1:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFO

class AIThreatHunting:
    """AI 驅動威脅獵捕"""
    
    def __init__(self):
        self.ml_detector = MLAnomalyDetector()
        self.ueba_engine = UEBAEngine()
        self.threat_patterns = {}
        self.hunting_queries = []
        self._init_threat_patterns()
    
    def _init_threat_patterns(self):
        """初始化威脅模式"""
        self.threat_patterns = {
            'lateral_movement': {
                'description': '橫向移動模式',
                'indicators': ['SMB', 'RDP', 'WMI', 'PowerShell'],
                'threshold': 0.7
            },
            'data_exfiltration': {
                'description': '數據外洩模式',
                'indicators': ['large_transfer', 'unusual_protocol', 'off_hours'],
                'threshold': 0.8
            },
            'persistence': {
                'description': '持久化模式',
                'indicators': ['scheduled_task', 'registry_modification', 'service_creation'],
                'threshold': 0.6
            },
            'privilege_escalation': {
                'description': '權限提升模式',
                'indicators': ['admin_access', 'system_command', 'vulnerability_exploit'],
                'threshold': 0.9
            }
        }
    
    def comprehensive_ai_hunting(self, hunting_scope: Dict[str, Any]) -> Dict[str, Any]:
        """執行綜合 AI 威脅獵捕"""
        try:
            results = {}
            
            # 1. 訓練 ML 模型
            logger.info("訓練 ML 模型...")
            training_results = self._train_ml_models(hunting_scope)
            results['model_training'] = training_results
            
            # 2. 異常檢測
            logger.info("執行異常檢測...")
            anomaly_results = self._detect_anomalies(hunting_scope)
            results['anomaly_detection'] = anomaly_results
            
            # 3. UEBA 分析
            logger.info("執行 UEBA 分析...")
            ueba_results = self._perform_ueba_analysis(hunting_scope)
            results['ueba_analysis'] = ueba_results
            
            # 4. 威脅模式識別
            logger.info("執行威脅模式識別...")
            pattern_results = self._identify_threat_patterns(anomaly_results, ueba_results)
            results['threat_patterns'] = pattern_results
            
            # 5. 威脅評分
            logger.info("執行威脅評分...")
            scoring_results = self._calculate_threat_scores(results)
            results['threat_scoring'] = scoring_results
            
            return {
                'success': True,
                'results': results,
                'summary': self._generate_ai_hunting_summary(results)
            }
        except Exception as e:
            logger.error(f"綜合 AI 威脅獵捕錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _train_ml_models(self, hunting_scope: Dict[str, Any]) -> Dict[str, Any]:
        """訓練 ML 模型"""
        try:
            results = {}
            
            # 訓練網路異常模型
            if 'network_data' in hunting_scope:
                network_data = hunting_scope['network_data']
                network_result = self.ml_detector.train_network_anomaly_model(network_data)
                results['network_model'] = network_result
            
            # 訓練用戶行為模型
            if 'user_behavior_data' in hunting_scope:
                user_data = hunting_scope['user_behavior_data']
                user_result = self.ml_detector.train_user_behavior_model(user_data)
                results['user_behavior_model'] = user_result
            
            return {
                'success': True,
                'models_trained': len(results),
                'training_results': results
            }
        except Exception as e:
            logger.error(f"訓練 ML 模型錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _detect_anomalies(self, hunting_scope: Dict[str, Any]) -> Dict[str, Any]:
        """檢測異常"""
        try:
            results = {}
            
            # 網路異常檢測
            if 'network_data' in hunting_scope:
                network_data = hunting_scope['network_data']
                network_anomalies = self.ml_detector.detect_network_anomalies(network_data)
                results['network_anomalies'] = network_anomalies
            
            # 用戶行為異常檢測
            if 'user_behavior_data' in hunting_scope:
                user_data = hunting_scope['user_behavior_data']
                user_anomalies = self.ml_detector.detect_user_behavior_anomalies(user_data)
                results['user_behavior_anomalies'] = user_anomalies
            
            return {
                'success': True,
                'total_anomalies': sum(len(anomalies) for anomalies in results.values() if isinstance(anomalies, list)),
                'anomaly_results': results
            }
        except Exception as e:
            logger.error(f"異常檢測錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _perform_ueba_analysis(self, hunting_scope: Dict[str, Any]) -> Dict[str, Any]:
        """執行 UEBA 分析"""
        try:
            results = {}
            
            if 'user_behavior_data' in hunting_scope:
                user_data = hunting_scope['user_behavior_data']
                
                # 按用戶分組
                users = {}
                for behavior in user_data:
                    # 處理字典格式的資料
                    if isinstance(behavior, dict):
                        user_id = behavior.get('user_id', 'unknown')
                        if user_id not in users:
                            users[user_id] = []
                        users[user_id].append(behavior)
                    else:
                        # 處理物件格式的資料
                        if behavior.user_id not in users:
                            users[behavior.user_id] = []
                        users[behavior.user_id].append(behavior)
                
                # 為每個用戶建立檔案
                for user_id, behaviors in users.items():
                    profile_result = self.ueba_engine.build_user_profile(user_id, behaviors)
                    if profile_result.get('success', False):
                        results[f'user_{user_id}'] = profile_result['profile']
                
                # 檢測用戶異常
                ueba_anomalies = []
                for behavior in user_data:
                    # 處理字典格式的資料
                    if isinstance(behavior, dict):
                        user_id = behavior.get('user_id', 'unknown')
                        timestamp = behavior.get('timestamp', datetime.now().isoformat())
                    else:
                        # 處理物件格式的資料
                        user_id = behavior.user_id
                        timestamp = behavior.timestamp
                    
                    anomaly_result = self.ueba_engine.detect_user_anomalies(user_id, behavior)
                    if anomaly_result.get('anomaly_detected', False):
                        ueba_anomalies.append({
                            'user_id': user_id,
                            'timestamp': timestamp,
                            'anomaly_score': anomaly_result['anomaly_score'],
                            'anomalies': anomaly_result['anomalies'],
                            'threat_level': anomaly_result['threat_level'].value
                        })
                
                results['ueba_anomalies'] = ueba_anomalies
            
            return {
                'success': True,
                'users_analyzed': len([k for k in results.keys() if k.startswith('user_')]),
                'ueba_anomalies': len(results.get('ueba_anomalies', [])),
                'ueba_results': results
            }
        except Exception as e:
            logger.error(f"UEBA 分析錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _identify_threat_patterns(self, anomaly_results: Dict[str, Any], ueba_results: Dict[str, Any]) -> Dict[str, Any]:
        """識別威脅模式"""
        try:
            identified_patterns = {}
            
            # 分析異常結果中的威脅模式
            if 'anomaly_results' in anomaly_results:
                for anomaly_type, anomalies in anomaly_results['anomaly_results'].items():
                    if isinstance(anomalies, list):
                        for anomaly in anomalies:
                            pattern = self._classify_anomaly_pattern(anomaly)
                            if pattern:
                                if pattern not in identified_patterns:
                                    identified_patterns[pattern] = []
                                identified_patterns[pattern].append(anomaly)
            
            # 分析 UEBA 結果中的威脅模式
            if 'ueba_results' in ueba_results and 'ueba_anomalies' in ueba_results['ueba_results']:
                for ueba_anomaly in ueba_results['ueba_results']['ueba_anomalies']:
                    pattern = self._classify_ueba_pattern(ueba_anomaly)
                    if pattern:
                        if pattern not in identified_patterns:
                            identified_patterns[pattern] = []
                        identified_patterns[pattern].append(ueba_anomaly)
            
            return {
                'success': True,
                'patterns_identified': len(identified_patterns),
                'threat_patterns': identified_patterns
            }
        except Exception as e:
            logger.error(f"威脅模式識別錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _classify_anomaly_pattern(self, anomaly) -> Optional[str]:
        """分類異常模式"""
        try:
            description = anomaly.description.lower()
            
            if any(indicator in description for indicator in ['smb', 'rdp', 'wmi']):
                return 'lateral_movement'
            elif any(indicator in description for indicator in ['large', 'transfer', 'exfil']):
                return 'data_exfiltration'
            elif any(indicator in description for indicator in ['task', 'registry', 'service']):
                return 'persistence'
            elif any(indicator in description for indicator in ['admin', 'system', 'privilege']):
                return 'privilege_escalation'
            
            return None
        except Exception as e:
            logger.error(f"分類異常模式錯誤: {e}")
            return None
    
    def _classify_ueba_pattern(self, ueba_anomaly: Dict[str, Any]) -> Optional[str]:
        """分類 UEBA 模式"""
        try:
            anomalies = ueba_anomaly.get('anomalies', [])
            anomaly_text = ' '.join(anomalies).lower()
            
            if any(indicator in anomaly_text for indicator in ['unusual action', 'unusual resource']):
                return 'lateral_movement'
            elif 'unusual data volume' in anomaly_text:
                return 'data_exfiltration'
            elif any(indicator in anomaly_text for indicator in ['unusual ip', 'unusual source']):
                return 'persistence'
            
            return None
        except Exception as e:
            logger.error(f"分類 UEBA 模式錯誤: {e}")
            return None
    
    def _calculate_threat_scores(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """計算威脅分數"""
        try:
            threat_scores = {}
            
            # 計算異常威脅分數
            if 'anomaly_detection' in results:
                anomaly_data = results['anomaly_detection']
                if 'anomaly_results' in anomaly_data:
                    for anomaly_type, anomalies in anomaly_data['anomaly_results'].items():
                        if isinstance(anomalies, list) and anomalies:
                            avg_confidence = np.mean([a.confidence for a in anomalies])
                            threat_scores[f'{anomaly_type}_score'] = avg_confidence
            
            # 計算 UEBA 威脅分數
            if 'ueba_analysis' in results:
                ueba_data = results['ueba_analysis']
                if 'ueba_results' in ueba_data and 'ueba_anomalies' in ueba_data['ueba_results']:
                    ueba_anomalies = ueba_data['ueba_results']['ueba_anomalies']
                    if ueba_anomalies:
                        avg_ueba_score = np.mean([a['anomaly_score'] for a in ueba_anomalies])
                        threat_scores['ueba_score'] = avg_ueba_score
            
            # 計算威脅模式分數
            if 'threat_patterns' in results:
                pattern_data = results['threat_patterns']
                if 'threat_patterns' in pattern_data:
                    for pattern_name, pattern_anomalies in pattern_data['threat_patterns'].items():
                        if pattern_anomalies:
                            threat_scores[f'{pattern_name}_score'] = len(pattern_anomalies) / 10.0  # 標準化
            
            # 計算總體威脅分數
            if threat_scores:
                overall_score = np.mean(list(threat_scores.values()))
                threat_scores['overall_threat_score'] = overall_score
                threat_scores['threat_level'] = self._determine_overall_threat_level(overall_score)
            
            return {
                'success': True,
                'threat_scores': threat_scores
            }
        except Exception as e:
            logger.error(f"計算威脅分數錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _determine_overall_threat_level(self, score: float) -> str:
        """確定總體威脅等級"""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "INFO"
    
    def _generate_ai_hunting_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成 AI 獵捕摘要"""
        summary = {
            'total_analyses': len(results),
            'successful_analyses': sum(1 for r in results.values() if isinstance(r, dict) and r.get('success', True)),
            'models_trained': 0,
            'anomalies_detected': 0,
            'ueba_anomalies': 0,
            'threat_patterns_identified': 0,
            'overall_threat_score': 0.0
        }
        
        if 'model_training' in results:
            summary['models_trained'] = results['model_training'].get('models_trained', 0)
        
        if 'anomaly_detection' in results:
            summary['anomalies_detected'] = results['anomaly_detection'].get('total_anomalies', 0)
        
        if 'ueba_analysis' in results:
            summary['ueba_anomalies'] = results['ueba_analysis'].get('ueba_anomalies', 0)
        
        if 'threat_patterns' in results:
            summary['threat_patterns_identified'] = results['threat_patterns'].get('patterns_identified', 0)
        
        if 'threat_scoring' in results and 'threat_scores' in results['threat_scoring']:
            summary['overall_threat_score'] = results['threat_scoring']['threat_scores'].get('overall_threat_score', 0.0)
        
        return summary

def main():
    """主程式"""
    print("🤖 軍事級AI威脅獵捕系統")
    print("=" * 50)
    
    # 初始化系統
    ai_hunting = AIThreatHunting()
    
    # 測試數據
    test_network_data = [
        NetworkFlow(
            id="flow_1",
            timestamp=datetime.now().isoformat(),
            source_ip="192.168.1.100",
            dest_ip="192.168.1.200",
            source_port=12345,
            dest_port=80,
            protocol="TCP",
            bytes_sent=1024,
            bytes_received=2048,
            duration=1.5,
            packets_sent=10,
            packets_received=15
        ),
        NetworkFlow(
            id="flow_2",
            timestamp=datetime.now().isoformat(),
            source_ip="192.168.1.100",
            dest_ip="192.168.1.201",
            source_port=12346,
            dest_port=445,
            protocol="TCP",
            bytes_sent=1000000,
            bytes_received=500000,
            duration=30.0,
            packets_sent=1000,
            packets_received=500
        )
    ]
    
    test_user_behavior_data = [
        UserBehavior(
            user_id="user_001",
            timestamp=datetime.now().isoformat(),
            action="login",
            resource="web_portal",
            source_ip="192.168.1.100",
            success=True,
            duration=2.5,
            data_volume=1024,
            risk_score=0.1
        ),
        UserBehavior(
            user_id="user_001",
            timestamp=datetime.now().isoformat(),
            action="file_access",
            resource="sensitive_data.xlsx",
            source_ip="192.168.1.100",
            success=True,
            duration=5.0,
            data_volume=10000000,
            risk_score=0.8
        )
    ]
    
    # 測試獵捕範圍
    test_hunting_scope = {
        'network_data': test_network_data,
        'user_behavior_data': test_user_behavior_data,
        'time_range': '24h',
        'analysis_types': ['anomaly_detection', 'ueba', 'threat_patterns']
    }
    
    # 執行綜合 AI 威脅獵捕測試
    print("開始執行綜合 AI 威脅獵捕測試...")
    results = ai_hunting.comprehensive_ai_hunting(test_hunting_scope)
    
    print(f"獵捕完成，成功: {results['success']}")
    print(f"獵捕摘要: {json.dumps(results['summary'], indent=2, ensure_ascii=False)}")
    
    print("軍事級AI威脅獵捕系統測試完成！")

if __name__ == "__main__":
    main()
