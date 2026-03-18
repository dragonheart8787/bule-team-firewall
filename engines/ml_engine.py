#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ML 實際引擎 - 使用 scikit-learn Isolation Forest / One-Class SVM
取代模擬邏輯，提供真實異常檢測
"""

import json
import pickle
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = logging.getLogger(__name__)


class MLEngine:
    """實際 ML 引擎 - Isolation Forest 異常檢測"""
    
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = Path(model_path) if model_path else Path("./models/ml_anomaly_model.pkl")
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        self.model = None
        self.feature_names = [
            'path_length', 'path_depth', 'query_params', 'body_size',
            'header_count', 'hour', 'day_of_week', 'has_suspicious_headers',
            'has_suspicious_path', 'has_suspicious_body', 'request_freq_1m'
        ]
        self._trained = False
        
        if self.model_path.exists():
            self._load_model()
    
    def _extract_features(self, method: str, path: str, headers: Dict, body: str,
                          timestamp: float, request_freq_1m: int = 0) -> np.ndarray:
        """提取請求特徵向量"""
        path_len = len(path)
        path_depth = path.count('/')
        query_params = len(path.split('?')[1].split('&')) if '?' in path else 0
        body_size = len(body) if body else 0
        header_count = len(headers) if headers else 0
        
        dt = datetime.fromtimestamp(timestamp)
        hour = dt.hour
        day_of_week = dt.weekday()
        
        suspicious_headers = [
            'X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
            'X-Remote-IP', 'X-Client-IP', 'X-Original-URL'
        ]
        has_suspicious_headers = 1 if any(h in (headers or {}) for h in suspicious_headers) else 0
        
        suspicious_paths = ['admin', 'login', 'config', 'backup', 'wp-admin', 'phpmyadmin']
        path_lower = path.lower()
        has_suspicious_path = 1 if any(p in path_lower for p in suspicious_paths) else 0
        
        suspicious_body = ['password', 'secret', 'token', 'key', 'auth']
        body_lower = (body or '').lower()
        has_suspicious_body = 1 if any(s in body_lower for s in suspicious_body) else 0
        
        features = np.array([[
            path_len, path_depth, query_params, body_size, header_count,
            hour, day_of_week, has_suspicious_headers, has_suspicious_path,
            has_suspicious_body, min(request_freq_1m, 1000)  # cap freq
        ]], dtype=np.float64)
        
        return features
    
    def fit(self, training_data: List[Dict[str, Any]]) -> bool:
        """使用正常流量訓練模型"""
        if not SKLEARN_AVAILABLE:
            logger.warning("scikit-learn 未安裝，使用 fallback 邏輯")
            return False
        
        X = []
        for sample in training_data:
            feat = self._extract_features(
                sample.get('method', 'GET'),
                sample.get('path', '/'),
                sample.get('headers', {}),
                sample.get('body', ''),
                sample.get('timestamp', 0),
                sample.get('request_freq_1m', 0)
            )
            X.append(feat[0])
        
        X = np.array(X)
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_scaled)
        self._trained = True
        self._save_model()
        logger.info(f"ML 模型訓練完成，樣本數: {len(training_data)}")
        return True
    
    def predict(self, method: str, path: str, headers: Dict, body: str,
                timestamp: Optional[float] = None, request_freq_1m: int = 0) -> Dict[str, Any]:
        """預測是否為異常"""
        import time
        ts = timestamp or time.time()
        features = self._extract_features(method, path, headers, body, ts, request_freq_1m)
        
        if not SKLEARN_AVAILABLE or not self._trained:
            return self._fallback_predict(features[0])
        
        X_scaled = self.scaler.transform(features)
        prediction = self.model.predict(X_scaled)  # -1 = anomaly, 1 = normal
        score = -self.model.score_samples(X_scaled)[0]  # 越高越異常
        
        return {
            'anomaly_score': float(np.clip(score, 0, 1)),
            'is_anomalous': prediction[0] == -1,
            'engine': 'sklearn_isolation_forest',
            'model_trained': True
        }
    
    def _fallback_predict(self, features: np.ndarray) -> Dict[str, Any]:
        """無 scikit-learn 時的 fallback"""
        path_len, path_depth, query_params, body_size = features[0], features[1], features[2], features[3]
        has_suspicious = features[7] + features[8] + features[9]
        score = 0.0
        if path_depth > 10:
            score += 0.3
        if query_params > 20:
            score += 0.2
        if has_suspicious > 0:
            score += 0.3
        if body_size > 100000:
            score += 0.2
        return {
            'anomaly_score': min(score, 1.0),
            'is_anomalous': score > 0.6,
            'engine': 'fallback_heuristic',
            'model_trained': False
        }
    
    def _save_model(self):
        """保存模型"""
        if self.model and self.scaler:
            with open(self.model_path, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'scaler': self.scaler,
                    'feature_names': self.feature_names
                }, f)
    
    def _load_model(self):
        """載入模型"""
        try:
            with open(self.model_path, 'rb') as f:
                data = pickle.load(f)
            self.model = data['model']
            self.scaler = data['scaler']
            self._trained = True
            logger.info("ML 模型已載入")
        except Exception as e:
            logger.warning(f"載入 ML 模型失敗: {e}")


# 測試
if __name__ == '__main__':
    engine = MLEngine()
    
    # 訓練
    training = [
        {'method': 'GET', 'path': '/api/users', 'headers': {}, 'body': '', 'timestamp': 0, 'request_freq_1m': 5},
        {'method': 'POST', 'path': '/api/login', 'headers': {}, 'body': '{}', 'timestamp': 0, 'request_freq_1m': 2},
    ] * 50
    engine.fit(training)
    
    # 預測
    r = engine.predict('GET', '/admin/config', {'X-Forwarded-For': '1.1.1.1'}, 'password=secret')
    print(f"異常分數: {r['anomaly_score']:.2f}, 異常: {r['is_anomalous']}")
