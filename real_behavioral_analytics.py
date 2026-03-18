#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實行為分析引擎
Real Behavioral Analytics Engine
用戶行為基線、異常檢測、風險評分
"""

import os
import json
import time
import logging
import threading
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score
import joblib
import hashlib
import sqlite3

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealBehavioralAnalytics:
    """真實行為分析引擎"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.analytics_threads = []
        
        # 行為數據存儲
        self.user_behaviors = {}
        self.behavior_baselines = {}
        self.anomaly_scores = {}
        self.risk_scores = {}
        
        # 機器學習模型
        self.ml_models = {}
        self.scalers = {}
        
        # 數據庫連接
        self.db_path = 'behavioral_analytics.db'
        self._init_database()
        
        # 初始化分析組件
        self._init_ml_models()
        self._init_behavior_tracking()
        
        logger.info("真實行為分析引擎初始化完成")
    
    def _init_database(self):
        """初始化數據庫"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 創建用戶行為表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_behaviors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    behavior_type TEXT NOT NULL,
                    features TEXT NOT NULL,
                    risk_score REAL DEFAULT 0.0,
                    is_anomaly BOOLEAN DEFAULT FALSE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 創建行為基線表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS behavior_baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    behavior_type TEXT NOT NULL,
                    baseline_features TEXT NOT NULL,
                    threshold REAL NOT NULL,
                    model_version TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 創建異常事件表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomaly_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    behavior_type TEXT NOT NULL,
                    anomaly_score REAL NOT NULL,
                    features TEXT NOT NULL,
                    description TEXT,
                    severity TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'open',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("行為分析數據庫初始化完成")
            
        except Exception as e:
            logger.error(f"數據庫初始化錯誤: {e}")
    
    def _init_ml_models(self):
        """初始化機器學習模型"""
        try:
            self.ml_models = {
                'login_anomaly': IsolationForest(contamination=0.1, random_state=42),
                'network_anomaly': IsolationForest(contamination=0.05, random_state=42),
                'file_access_anomaly': IsolationForest(contamination=0.1, random_state=42),
                'command_anomaly': IsolationForest(contamination=0.1, random_state=42),
                'time_anomaly': IsolationForest(contamination=0.1, random_state=42),
                'clustering_model': DBSCAN(eps=0.5, min_samples=5)
            }
            
            # 初始化特徵縮放器
            self.scalers = {
                'login_features': StandardScaler(),
                'network_features': StandardScaler(),
                'file_features': StandardScaler(),
                'command_features': StandardScaler(),
                'time_features': StandardScaler()
            }
            
            # 載入預訓練模型
            self._load_pretrained_models()
            
            logger.info("ML模型初始化完成")
            
        except Exception as e:
            logger.error(f"ML模型初始化錯誤: {e}")
    
    def _load_pretrained_models(self):
        """載入預訓練模型"""
        try:
            models_dir = 'behavioral_models'
            if not os.path.exists(models_dir):
                os.makedirs(models_dir)
            
            for model_name in self.ml_models.keys():
                model_file = os.path.join(models_dir, f"{model_name}.joblib")
                if os.path.exists(model_file):
                    self.ml_models[model_name] = joblib.load(model_file)
                    logger.info(f"載入預訓練模型: {model_name}")
                else:
                    logger.info(f"使用預設模型: {model_name}")
                    
        except Exception as e:
            logger.error(f"載入預訓練模型錯誤: {e}")
    
    def _init_behavior_tracking(self):
        """初始化行為追蹤"""
        try:
            self.behavior_types = [
                'login_behavior',
                'network_behavior',
                'file_access_behavior',
                'command_behavior',
                'time_behavior'
            ]
            
            # 初始化行為特徵提取器
            self.feature_extractors = {
                'login_behavior': self._extract_login_features,
                'network_behavior': self._extract_network_features,
                'file_access_behavior': self._extract_file_features,
                'command_behavior': self._extract_command_features,
                'time_behavior': self._extract_time_features
            }
            
            logger.info("行為追蹤初始化完成")
            
        except Exception as e:
            logger.error(f"行為追蹤初始化錯誤: {e}")
    
    def start_analytics(self) -> Dict[str, Any]:
        """啟動行為分析"""
        try:
            if self.running:
                return {'success': False, 'error': '行為分析已在運行中'}
            
            self.running = True
            
            # 啟動行為分析線程
            thread = threading.Thread(target=self._run_behavior_analysis, daemon=True)
            thread.start()
            self.analytics_threads.append(thread)
            
            # 啟動基線更新線程
            thread = threading.Thread(target=self._update_baselines, daemon=True)
            thread.start()
            self.analytics_threads.append(thread)
            
            # 啟動風險評分線程
            thread = threading.Thread(target=self._calculate_risk_scores, daemon=True)
            thread.start()
            self.analytics_threads.append(thread)
            
            logger.info("行為分析引擎已啟動")
            return {'success': True, 'message': '行為分析引擎已啟動'}
            
        except Exception as e:
            logger.error(f"啟動行為分析錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _run_behavior_analysis(self):
        """運行行為分析"""
        try:
            while self.running:
                try:
                    # 分析用戶行為
                    self._analyze_user_behaviors()
                    
                    # 檢測異常
                    self._detect_anomalies()
                    
                    # 更新風險評分
                    self._update_risk_scores()
                    
                    time.sleep(60)  # 每分鐘分析一次
                    
                except Exception as e:
                    logger.error(f"行為分析錯誤: {e}")
                    time.sleep(10)
                    
        except Exception as e:
            logger.error(f"運行行為分析錯誤: {e}")
    
    def _analyze_user_behaviors(self):
        """分析用戶行為"""
        try:
            # 從數據庫獲取最近的行為數據
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 獲取最近1小時的行為數據
            one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
            cursor.execute('''
                SELECT user_id, behavior_type, features, timestamp
                FROM user_behaviors
                WHERE timestamp > ? AND is_anomaly = FALSE
                ORDER BY timestamp DESC
            ''', (one_hour_ago,))
            
            behaviors = cursor.fetchall()
            conn.close()
            
            # 按用戶分組分析
            user_groups = {}
            for behavior in behaviors:
                user_id = behavior[0]
                if user_id not in user_groups:
                    user_groups[user_id] = []
                user_groups[user_id].append(behavior)
            
            # 分析每個用戶的行為
            for user_id, user_behaviors in user_groups.items():
                self._analyze_user_behavior_patterns(user_id, user_behaviors)
                
        except Exception as e:
            logger.error(f"分析用戶行為錯誤: {e}")
    
    def _analyze_user_behavior_patterns(self, user_id: str, behaviors: List[Tuple]):
        """分析用戶行為模式"""
        try:
            # 按行為類型分組
            behavior_groups = {}
            for behavior in behaviors:
                behavior_type = behavior[1]
                if behavior_type not in behavior_groups:
                    behavior_groups[behavior_type] = []
                behavior_groups[behavior_type].append(behavior)
            
            # 分析每種行為類型
            for behavior_type, type_behaviors in behavior_groups.items():
                self._analyze_behavior_type(user_id, behavior_type, type_behaviors)
                
        except Exception as e:
            logger.error(f"分析用戶行為模式錯誤: {e}")
    
    def _analyze_behavior_type(self, user_id: str, behavior_type: str, behaviors: List[Tuple]):
        """分析特定行為類型"""
        try:
            # 提取特徵
            features = []
            for behavior in behaviors:
                feature_data = json.loads(behavior[2])
                features.append(feature_data)
            
            if len(features) < 5:  # 需要足夠的數據點
                return
            
            # 轉換為numpy數組
            feature_array = np.array(features)
            
            # 檢查是否有對應的模型
            model_key = f"{behavior_type.split('_')[0]}_anomaly"
            if model_key in self.ml_models:
                # 預測異常
                anomaly_scores = self.ml_models[model_key].decision_function(feature_array)
                anomaly_predictions = self.ml_models[model_key].predict(feature_array)
                
                # 更新異常分數
                for i, (behavior, score, prediction) in enumerate(zip(behaviors, anomaly_scores, anomaly_predictions)):
                    behavior_id = behavior[0]  # 假設第一個元素是ID
                    self.anomaly_scores[behavior_id] = {
                        'score': float(score),
                        'is_anomaly': prediction == -1,
                        'timestamp': behavior[3]
                    }
                    
                    # 如果是異常，記錄到數據庫
                    if prediction == -1:
                        self._record_anomaly_event(user_id, behavior_type, float(score), feature_data)
                        
        except Exception as e:
            logger.error(f"分析行為類型錯誤: {e}")
    
    def _record_anomaly_event(self, user_id: str, behavior_type: str, anomaly_score: float, features: Dict[str, Any]):
        """記錄異常事件"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 確定嚴重程度
            severity = 'low'
            if anomaly_score < -0.5:
                severity = 'high'
            elif anomaly_score < -0.2:
                severity = 'medium'
            
            # 插入異常事件
            cursor.execute('''
                INSERT INTO anomaly_events 
                (user_id, timestamp, behavior_type, anomaly_score, features, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                user_id,
                datetime.now().isoformat(),
                behavior_type,
                anomaly_score,
                json.dumps(features),
                severity
            ))
            
            conn.commit()
            conn.close()
            
            logger.warning(f"記錄異常事件: 用戶 {user_id}, 行為 {behavior_type}, 分數 {anomaly_score:.3f}")
            
        except Exception as e:
            logger.error(f"記錄異常事件錯誤: {e}")
    
    def _detect_anomalies(self):
        """檢測異常"""
        try:
            # 獲取最近的異常事件
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 獲取過去24小時的異常事件
            one_day_ago = (datetime.now() - timedelta(days=1)).isoformat()
            cursor.execute('''
                SELECT user_id, behavior_type, anomaly_score, severity, timestamp
                FROM anomaly_events
                WHERE timestamp > ? AND status = 'open'
                ORDER BY timestamp DESC
            ''', (one_day_ago,))
            
            anomalies = cursor.fetchall()
            conn.close()
            
            # 分析異常模式
            self._analyze_anomaly_patterns(anomalies)
            
        except Exception as e:
            logger.error(f"檢測異常錯誤: {e}")
    
    def _analyze_anomaly_patterns(self, anomalies: List[Tuple]):
        """分析異常模式"""
        try:
            # 按用戶分組異常
            user_anomalies = {}
            for anomaly in anomalies:
                user_id = anomaly[0]
                if user_id not in user_anomalies:
                    user_anomalies[user_id] = []
                user_anomalies[user_id].append(anomaly)
            
            # 分析每個用戶的異常模式
            for user_id, user_anomalies_list in user_anomalies.items():
                self._analyze_user_anomaly_patterns(user_id, user_anomalies_list)
                
        except Exception as e:
            logger.error(f"分析異常模式錯誤: {e}")
    
    def _analyze_user_anomaly_patterns(self, user_id: str, anomalies: List[Tuple]):
        """分析用戶異常模式"""
        try:
            # 計算異常頻率
            anomaly_count = len(anomalies)
            high_severity_count = sum(1 for a in anomalies if a[3] == 'high')
            
            # 計算風險評分
            risk_score = self._calculate_user_risk_score(user_id, anomaly_count, high_severity_count)
            
            # 更新風險評分
            self.risk_scores[user_id] = {
                'score': risk_score,
                'anomaly_count': anomaly_count,
                'high_severity_count': high_severity_count,
                'last_updated': datetime.now().isoformat()
            }
            
            # 如果風險評分過高，觸發警報
            if risk_score > 0.8:
                self._trigger_high_risk_alert(user_id, risk_score, anomaly_count)
                
        except Exception as e:
            logger.error(f"分析用戶異常模式錯誤: {e}")
    
    def _calculate_user_risk_score(self, user_id: str, anomaly_count: int, high_severity_count: int) -> float:
        """計算用戶風險評分"""
        try:
            # 基礎風險評分
            base_score = min(anomaly_count * 0.1, 0.5)
            
            # 高嚴重性異常加權
            severity_score = min(high_severity_count * 0.2, 0.5)
            
            # 時間因素（最近的異常權重更高）
            time_score = 0.0
            if anomaly_count > 0:
                time_score = 0.1
            
            # 總風險評分
            total_score = min(base_score + severity_score + time_score, 1.0)
            
            return total_score
            
        except Exception as e:
            logger.error(f"計算用戶風險評分錯誤: {e}")
            return 0.0
    
    def _trigger_high_risk_alert(self, user_id: str, risk_score: float, anomaly_count: int):
        """觸發高風險警報"""
        try:
            alert = {
                'user_id': user_id,
                'risk_score': risk_score,
                'anomaly_count': anomaly_count,
                'timestamp': datetime.now().isoformat(),
                'alert_type': 'HIGH_RISK_USER',
                'description': f'用戶 {user_id} 風險評分過高: {risk_score:.3f}'
            }
            
            logger.critical(f"高風險警報: {alert}")
            
            # 這裡可以添加警報通知邏輯
            # 例如：發送郵件、Slack通知、SIEM集成等
            
        except Exception as e:
            logger.error(f"觸發高風險警報錯誤: {e}")
    
    def _update_baselines(self):
        """更新行為基線"""
        try:
            while self.running:
                try:
                    # 每小時更新一次基線
                    self._update_behavior_baselines()
                    time.sleep(3600)  # 1小時
                    
                except Exception as e:
                    logger.error(f"更新基線錯誤: {e}")
                    time.sleep(300)  # 5分鐘後重試
                    
        except Exception as e:
            logger.error(f"運行基線更新錯誤: {e}")
    
    def _update_behavior_baselines(self):
        """更新行為基線"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 獲取過去7天的正常行為數據
            seven_days_ago = (datetime.now() - timedelta(days=7)).isoformat()
            cursor.execute('''
                SELECT user_id, behavior_type, features
                FROM user_behaviors
                WHERE timestamp > ? AND is_anomaly = FALSE
            ''', (seven_days_ago,))
            
            behaviors = cursor.fetchall()
            conn.close()
            
            # 按用戶和行為類型分組
            user_behavior_groups = {}
            for behavior in behaviors:
                user_id = behavior[0]
                behavior_type = behavior[1]
                key = f"{user_id}_{behavior_type}"
                
                if key not in user_behavior_groups:
                    user_behavior_groups[key] = []
                user_behavior_groups[key].append(json.loads(behavior[2]))
            
            # 為每個用戶-行為類型組合更新基線
            for key, features_list in user_behavior_groups.items():
                if len(features_list) >= 10:  # 需要足夠的數據點
                    user_id, behavior_type = key.split('_', 1)
                    self._update_user_behavior_baseline(user_id, behavior_type, features_list)
                    
        except Exception as e:
            logger.error(f"更新行為基線錯誤: {e}")
    
    def _update_user_behavior_baseline(self, user_id: str, behavior_type: str, features_list: List[Dict[str, Any]]):
        """更新用戶行為基線"""
        try:
            # 轉換為numpy數組
            feature_array = np.array(features_list)
            
            # 計算基線統計
            baseline_mean = np.mean(feature_array, axis=0)
            baseline_std = np.std(feature_array, axis=0)
            baseline_threshold = np.mean(baseline_std) * 2  # 2倍標準差作為閾值
            
            # 保存基線
            baseline_data = {
                'mean': baseline_mean.tolist(),
                'std': baseline_std.tolist(),
                'threshold': float(baseline_threshold),
                'sample_count': len(features_list),
                'updated_at': datetime.now().isoformat()
            }
            
            # 更新數據庫
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO behavior_baselines
                (user_id, behavior_type, baseline_features, threshold, model_version)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                user_id,
                behavior_type,
                json.dumps(baseline_data),
                baseline_threshold,
                '1.0'
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"更新用戶 {user_id} 的 {behavior_type} 基線")
            
        except Exception as e:
            logger.error(f"更新用戶行為基線錯誤: {e}")
    
    def _calculate_risk_scores(self):
        """計算風險評分"""
        try:
            while self.running:
                try:
                    # 每5分鐘計算一次風險評分
                    self._update_risk_scores()
                    time.sleep(300)  # 5分鐘
                    
                except Exception as e:
                    logger.error(f"計算風險評分錯誤: {e}")
                    time.sleep(60)  # 1分鐘後重試
                    
        except Exception as e:
            logger.error(f"運行風險評分計算錯誤: {e}")
    
    def _update_risk_scores(self):
        """更新風險評分"""
        try:
            # 獲取所有用戶的風險評分
            for user_id in self.risk_scores.keys():
                self._recalculate_user_risk_score(user_id)
                
        except Exception as e:
            logger.error(f"更新風險評分錯誤: {e}")
    
    def _recalculate_user_risk_score(self, user_id: str):
        """重新計算用戶風險評分"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 獲取過去24小時的異常事件
            one_day_ago = (datetime.now() - timedelta(days=1)).isoformat()
            cursor.execute('''
                SELECT behavior_type, anomaly_score, severity
                FROM anomaly_events
                WHERE user_id = ? AND timestamp > ?
            ''', (user_id, one_day_ago))
            
            anomalies = cursor.fetchall()
            conn.close()
            
            # 計算新的風險評分
            anomaly_count = len(anomalies)
            high_severity_count = sum(1 for a in anomalies if a[2] == 'high')
            
            risk_score = self._calculate_user_risk_score(user_id, anomaly_count, high_severity_count)
            
            # 更新風險評分
            if user_id in self.risk_scores:
                self.risk_scores[user_id]['score'] = risk_score
                self.risk_scores[user_id]['anomaly_count'] = anomaly_count
                self.risk_scores[user_id]['high_severity_count'] = high_severity_count
                self.risk_scores[user_id]['last_updated'] = datetime.now().isoformat()
            
        except Exception as e:
            logger.error(f"重新計算用戶風險評分錯誤: {e}")
    
    # 特徵提取方法
    def _extract_login_features(self, data: Dict[str, Any]) -> List[float]:
        """提取登入特徵"""
        try:
            features = []
            
            # 時間特徵
            timestamp = data.get('timestamp', datetime.now())
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)
            
            features.append(timestamp.hour)  # 登入小時
            features.append(timestamp.weekday())  # 登入星期
            features.append(timestamp.day)  # 登入日期
            
            # 位置特徵
            features.append(data.get('ip_address', '0.0.0.0').count('.'))  # IP地址特徵
            features.append(len(data.get('user_agent', '')))  # 用戶代理長度
            
            # 會話特徵
            features.append(data.get('session_duration', 0))  # 會話持續時間
            features.append(data.get('login_attempts', 1))  # 登入嘗試次數
            
            return features
            
        except Exception as e:
            logger.error(f"提取登入特徵錯誤: {e}")
            return [0.0] * 7
    
    def _extract_network_features(self, data: Dict[str, Any]) -> List[float]:
        """提取網路特徵"""
        try:
            features = []
            
            # 流量特徵
            features.append(data.get('bytes_sent', 0))
            features.append(data.get('bytes_received', 0))
            features.append(data.get('packet_count', 0))
            features.append(data.get('connection_duration', 0))
            
            # 協議特徵
            protocol = data.get('protocol', '')
            features.append(len(protocol))
            features.append(1 if protocol.upper() == 'HTTPS' else 0)
            features.append(1 if protocol.upper() == 'HTTP' else 0)
            
            # 目標特徵
            dest_ip = data.get('dest_ip', '0.0.0.0')
            features.append(dest_ip.count('.'))
            features.append(1 if dest_ip.startswith('192.168.') else 0)
            features.append(1 if dest_ip.startswith('10.') else 0)
            
            return features
            
        except Exception as e:
            logger.error(f"提取網路特徵錯誤: {e}")
            return [0.0] * 10
    
    def _extract_file_features(self, data: Dict[str, Any]) -> List[float]:
        """提取檔案存取特徵"""
        try:
            features = []
            
            # 檔案特徵
            file_path = data.get('file_path', '')
            features.append(len(file_path))
            features.append(file_path.count('\\'))
            features.append(file_path.count('/'))
            
            # 檔案類型特徵
            file_ext = os.path.splitext(file_path)[1].lower()
            features.append(1 if file_ext == '.exe' else 0)
            features.append(1 if file_ext == '.dll' else 0)
            features.append(1 if file_ext == '.bat' else 0)
            features.append(1 if file_ext == '.ps1' else 0)
            
            # 存取模式特徵
            features.append(data.get('access_count', 1))
            features.append(data.get('file_size', 0))
            features.append(1 if data.get('is_write', False) else 0)
            
            return features
            
        except Exception as e:
            logger.error(f"提取檔案特徵錯誤: {e}")
            return [0.0] * 10
    
    def _extract_command_features(self, data: Dict[str, Any]) -> List[float]:
        """提取命令特徵"""
        try:
            features = []
            
            command = data.get('command', '')
            features.append(len(command))
            features.append(command.count(' '))
            features.append(command.count('|'))
            features.append(command.count('&'))
            features.append(command.count(';'))
            
            # 危險命令特徵
            dangerous_commands = ['rm', 'del', 'format', 'shutdown', 'net', 'reg', 'wmic']
            for cmd in dangerous_commands:
                features.append(1 if cmd in command.lower() else 0)
            
            # 權限特徵
            features.append(1 if data.get('is_admin', False) else 0)
            features.append(data.get('process_id', 0))
            
            return features
            
        except Exception as e:
            logger.error(f"提取命令特徵錯誤: {e}")
            return [0.0] * 12
    
    def _extract_time_features(self, data: Dict[str, Any]) -> List[float]:
        """提取時間特徵"""
        try:
            features = []
            
            timestamp = data.get('timestamp', datetime.now())
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)
            
            # 時間特徵
            features.append(timestamp.hour)
            features.append(timestamp.minute)
            features.append(timestamp.weekday())
            features.append(timestamp.day)
            features.append(timestamp.month)
            
            # 時間模式特徵
            features.append(1 if 9 <= timestamp.hour <= 17 else 0)  # 工作時間
            features.append(1 if timestamp.weekday() < 5 else 0)  # 工作日
            features.append(1 if 22 <= timestamp.hour or timestamp.hour <= 6 else 0)  # 非工作時間
            
            return features
            
        except Exception as e:
            logger.error(f"提取時間特徵錯誤: {e}")
            return [0.0] * 8
    
    def record_behavior(self, user_id: str, behavior_type: str, behavior_data: Dict[str, Any]) -> Dict[str, Any]:
        """記錄用戶行為"""
        try:
            # 提取特徵
            if behavior_type in self.feature_extractors:
                features = self.feature_extractors[behavior_type](behavior_data)
            else:
                features = [0.0] * 10  # 預設特徵
            
            # 保存到數據庫
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO user_behaviors 
                (user_id, timestamp, behavior_type, features)
                VALUES (?, ?, ?, ?)
            ''', (
                user_id,
                datetime.now().isoformat(),
                behavior_type,
                json.dumps(features)
            ))
            
            conn.commit()
            conn.close()
            
            return {'success': True, 'message': '行為記錄成功'}
            
        except Exception as e:
            logger.error(f"記錄行為錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_user_risk_score(self, user_id: str) -> Dict[str, Any]:
        """獲取用戶風險評分"""
        try:
            if user_id in self.risk_scores:
                return {
                    'success': True,
                    'user_id': user_id,
                    'risk_score': self.risk_scores[user_id]['score'],
                    'anomaly_count': self.risk_scores[user_id]['anomaly_count'],
                    'high_severity_count': self.risk_scores[user_id]['high_severity_count'],
                    'last_updated': self.risk_scores[user_id]['last_updated']
                }
            else:
                return {
                    'success': True,
                    'user_id': user_id,
                    'risk_score': 0.0,
                    'anomaly_count': 0,
                    'high_severity_count': 0,
                    'last_updated': None
                }
                
        except Exception as e:
            logger.error(f"獲取用戶風險評分錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_anomaly_events(self, user_id: str = None, limit: int = 100) -> Dict[str, Any]:
        """獲取異常事件"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if user_id:
                cursor.execute('''
                    SELECT user_id, timestamp, behavior_type, anomaly_score, severity, description
                    FROM anomaly_events
                    WHERE user_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (user_id, limit))
            else:
                cursor.execute('''
                    SELECT user_id, timestamp, behavior_type, anomaly_score, severity, description
                    FROM anomaly_events
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (limit,))
            
            events = cursor.fetchall()
            conn.close()
            
            return {
                'success': True,
                'events': [
                    {
                        'user_id': event[0],
                        'timestamp': event[1],
                        'behavior_type': event[2],
                        'anomaly_score': event[3],
                        'severity': event[4],
                        'description': event[5]
                    }
                    for event in events
                ]
            }
            
        except Exception as e:
            logger.error(f"獲取異常事件錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def stop_analytics(self) -> Dict[str, Any]:
        """停止行為分析"""
        try:
            self.running = False
            
            # 等待所有線程結束
            for thread in self.analytics_threads:
                thread.join(timeout=5)
            
            self.analytics_threads.clear()
            
            logger.info("行為分析引擎已停止")
            return {'success': True, 'message': '行為分析引擎已停止'}
            
        except Exception as e:
            logger.error(f"停止行為分析錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """獲取系統狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'tracked_users': len(self.risk_scores),
                'behavior_types': len(self.behavior_types),
                'ml_models': len(self.ml_models),
                'analytics_threads': len(self.analytics_threads)
            }
        except Exception as e:
            logger.error(f"獲取系統狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """獲取綜合報告"""
        try:
            return {
                'success': True,
                'behavioral_analytics': {
                    'risk_scores': self.risk_scores,
                    'anomaly_scores': self.anomaly_scores,
                    'behavior_types': self.behavior_types,
                    'ml_models': list(self.ml_models.keys()),
                    'tracked_users': len(self.risk_scores)
                }
            }
        except Exception as e:
            logger.error(f"獲取綜合報告錯誤: {e}")
            return {'success': False, 'error': str(e)}



