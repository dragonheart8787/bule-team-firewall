#!/usr/bin/env python3
"""
機器學習異常檢測模組
基於行為模式的智能防護系統
"""

import json
import time
import hashlib
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta
import logging

class MLAnomalyDetector:
    """機器學習異常檢測器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # 行為模式學習數據
        self.user_profiles = defaultdict(lambda: {
            'request_patterns': deque(maxlen=1000),
            'time_patterns': deque(maxlen=1000),
            'path_patterns': defaultdict(int),
            'method_patterns': defaultdict(int),
            'header_patterns': defaultdict(int),
            'body_patterns': deque(maxlen=100),
            'anomaly_score': 0.0,
            'last_seen': None
        })
        
        # 全局統計數據
        self.global_stats = {
            'total_requests': 0,
            'avg_request_size': 0,
            'common_paths': defaultdict(int),
            'common_methods': defaultdict(int),
            'time_distribution': defaultdict(int),
            'suspicious_ips': set(),
            'attack_patterns': defaultdict(int)
        }
        
        # 異常檢測閾值
        self.thresholds = {
            'anomaly_score': 0.7,
            'request_frequency': 50,  # 每分鐘請求數
            'path_diversity': 0.8,    # 路徑多樣性閾值
            'time_deviation': 2.0,    # 時間偏差標準差
            'size_deviation': 3.0     # 請求大小偏差標準差
        }
        
        # 學習模式開關
        self.learning_mode = True
        self.learning_duration = 3600  # 學習1小時
        self.start_time = time.time()
    
    def analyze_request(self, client_ip, method, path, headers, body, timestamp=None):
        """分析請求並檢測異常"""
        if timestamp is None:
            timestamp = time.time()
        
        # 更新全局統計
        self.global_stats['total_requests'] += 1
        
        # 獲取用戶檔案
        user_profile = self.user_profiles[client_ip]
        user_profile['last_seen'] = timestamp
        
        # 提取請求特徵
        features = self._extract_features(method, path, headers, body, timestamp)
        
        # 更新用戶行為模式
        self._update_user_profile(user_profile, features)
        
        # 計算異常分數
        anomaly_score = self._calculate_anomaly_score(client_ip, features)
        user_profile['anomaly_score'] = anomaly_score
        
        # 檢測異常
        anomalies = self._detect_anomalies(client_ip, features, anomaly_score)
        
        return {
            'anomaly_score': anomaly_score,
            'anomalies': anomalies,
            'is_anomalous': anomaly_score > self.thresholds['anomaly_score'],
            'user_profile': dict(user_profile) if not self.learning_mode else None
        }
    
    def _extract_features(self, method, path, headers, body, timestamp):
        """提取請求特徵"""
        features = {
            'method': method,
            'path': path,
            'path_length': len(path),
            'path_depth': path.count('/'),
            'query_params': len(path.split('?')[1].split('&')) if '?' in path else 0,
            'body_size': len(body) if body else 0,
            'header_count': len(headers),
            'user_agent': headers.get('User-Agent', ''),
            'referer': headers.get('Referer', ''),
            'content_type': headers.get('Content-Type', ''),
            'timestamp': timestamp,
            'hour': datetime.fromtimestamp(timestamp).hour,
            'day_of_week': datetime.fromtimestamp(timestamp).weekday(),
            'is_weekend': datetime.fromtimestamp(timestamp).weekday() >= 5,
            'has_suspicious_headers': self._check_suspicious_headers(headers),
            'has_suspicious_path': self._check_suspicious_path(path),
            'has_suspicious_body': self._check_suspicious_body(body)
        }
        
        return features
    
    def _update_user_profile(self, user_profile, features):
        """更新用戶行為檔案"""
        # 更新請求模式
        user_profile['request_patterns'].append(features)
        
        # 更新時間模式
        user_profile['time_patterns'].append(features['timestamp'])
        
        # 更新路徑模式
        user_profile['path_patterns'][features['path']] += 1
        
        # 更新方法模式
        user_profile['method_patterns'][features['method']] += 1
        
        # 更新標頭模式
        for header, value in features.items():
            if header.endswith('_header') and value:
                user_profile['header_patterns'][header] += 1
        
        # 更新請求體模式
        if features['body_size'] > 0:
            user_profile['body_patterns'].append(features['body_size'])
    
    def _calculate_anomaly_score(self, client_ip, features):
        """計算異常分數"""
        user_profile = self.user_profiles[client_ip]
        anomaly_factors = []
        
        # 1. 請求頻率異常
        freq_score = self._check_frequency_anomaly(client_ip, features['timestamp'])
        anomaly_factors.append(freq_score)
        
        # 2. 路徑異常
        path_score = self._check_path_anomaly(user_profile, features['path'])
        anomaly_factors.append(path_score)
        
        # 3. 時間模式異常
        time_score = self._check_time_anomaly(user_profile, features['timestamp'])
        anomaly_factors.append(time_score)
        
        # 4. 請求大小異常
        size_score = self._check_size_anomaly(user_profile, features['body_size'])
        anomaly_factors.append(size_score)
        
        # 5. 行為模式異常
        behavior_score = self._check_behavior_anomaly(user_profile, features)
        anomaly_factors.append(behavior_score)
        
        # 6. 可疑特徵檢測
        suspicious_score = self._check_suspicious_features(features)
        anomaly_factors.append(suspicious_score)
        
        # 計算加權平均異常分數
        weights = [0.2, 0.15, 0.15, 0.1, 0.2, 0.2]
        anomaly_score = sum(w * s for w, s in zip(weights, anomaly_factors))
        
        return min(anomaly_score, 1.0)  # 限制在 0-1 範圍
    
    def _check_frequency_anomaly(self, client_ip, timestamp):
        """檢查請求頻率異常"""
        user_profile = self.user_profiles[client_ip]
        recent_requests = [
            t for t in user_profile['time_patterns']
            if timestamp - t < 60  # 最近1分鐘
        ]
        
        if len(recent_requests) > self.thresholds['request_frequency']:
            return 1.0
        elif len(recent_requests) > self.thresholds['request_frequency'] * 0.7:
            return 0.5
        else:
            return 0.0
    
    def _check_path_anomaly(self, user_profile, path):
        """檢查路徑異常"""
        if not user_profile['path_patterns']:
            return 0.0
        
        # 檢查是否為新路徑
        if path not in user_profile['path_patterns']:
            return 0.8
        
        # 檢查路徑多樣性
        total_requests = sum(user_profile['path_patterns'].values())
        path_diversity = len(user_profile['path_patterns']) / total_requests
        
        if path_diversity > self.thresholds['path_diversity']:
            return 0.6
        
        return 0.0
    
    def _check_time_anomaly(self, user_profile, timestamp):
        """檢查時間模式異常"""
        if len(user_profile['time_patterns']) < 10:
            return 0.0
        
        # 檢查是否在異常時間請求
        hour = datetime.fromtimestamp(timestamp).hour
        is_weekend = datetime.fromtimestamp(timestamp).weekday() >= 5
        
        # 深夜或清晨請求
        if hour < 6 or hour > 23:
            return 0.7
        
        # 週末請求（如果平時不常在週末請求）
        if is_weekend and not self._is_weekend_user(user_profile):
            return 0.5
        
        return 0.0
    
    def _check_size_anomaly(self, user_profile, body_size):
        """檢查請求大小異常"""
        if not user_profile['body_patterns']:
            return 0.0
        
        sizes = list(user_profile['body_patterns'])
        if len(sizes) < 5:
            return 0.0
        
        mean_size = statistics.mean(sizes)
        std_size = statistics.stdev(sizes) if len(sizes) > 1 else 0
        
        if std_size == 0:
            return 0.0
        
        # 計算Z分數
        z_score = abs(body_size - mean_size) / std_size
        
        if z_score > self.thresholds['size_deviation']:
            return 1.0
        elif z_score > self.thresholds['size_deviation'] * 0.5:
            return 0.5
        
        return 0.0
    
    def _check_behavior_anomaly(self, user_profile, features):
        """檢查行為模式異常"""
        anomaly_score = 0.0
        
        # 檢查方法使用模式
        if features['method'] not in user_profile['method_patterns']:
            anomaly_score += 0.3
        
        # 檢查標頭模式
        if features['has_suspicious_headers']:
            anomaly_score += 0.4
        
        # 檢查路徑深度異常
        if features['path_depth'] > 10:  # 過深的路徑
            anomaly_score += 0.3
        
        # 檢查查詢參數異常
        if features['query_params'] > 20:  # 過多查詢參數
            anomaly_score += 0.2
        
        return min(anomaly_score, 1.0)
    
    def _check_suspicious_features(self, features):
        """檢查可疑特徵"""
        suspicious_score = 0.0
        
        # 檢查可疑路徑
        if features['has_suspicious_path']:
            suspicious_score += 0.5
        
        # 檢查可疑請求體
        if features['has_suspicious_body']:
            suspicious_score += 0.5
        
        # 檢查異常User-Agent
        if self._is_suspicious_user_agent(features['user_agent']):
            suspicious_score += 0.3
        
        return min(suspicious_score, 1.0)
    
    def _check_suspicious_headers(self, headers):
        """檢查可疑標頭"""
        suspicious_headers = [
            'X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
            'X-Remote-IP', 'X-Remote-Addr', 'X-Client-IP',
            'X-Host', 'X-Forwarded-Host', 'X-Original-URL',
            'X-Rewrite-URL', 'X-Forwarded-Proto'
        ]
        
        return any(header in headers for header in suspicious_headers)
    
    def _check_suspicious_path(self, path):
        """檢查可疑路徑"""
        suspicious_patterns = [
            'admin', 'administrator', 'login', 'wp-admin',
            'phpmyadmin', 'config', 'backup', 'test',
            'debug', 'dev', 'staging', 'beta'
        ]
        
        path_lower = path.lower()
        return any(pattern in path_lower for pattern in suspicious_patterns)
    
    def _check_suspicious_body(self, body):
        """檢查可疑請求體"""
        if not body:
            return False
        
        suspicious_patterns = [
            'password', 'passwd', 'pwd', 'secret',
            'token', 'key', 'auth', 'login',
            'admin', 'root', 'system'
        ]
        
        body_lower = body.lower()
        return any(pattern in body_lower for pattern in suspicious_patterns)
    
    def _is_suspicious_user_agent(self, user_agent):
        """檢查可疑User-Agent"""
        if not user_agent:
            return True
        
        suspicious_agents = [
            'curl', 'wget', 'python', 'bot', 'crawler',
            'scanner', 'spider', 'harvester'
        ]
        
        user_agent_lower = user_agent.lower()
        return any(agent in user_agent_lower for agent in suspicious_agents)
    
    def _is_weekend_user(self, user_profile):
        """檢查是否為週末用戶"""
        weekend_requests = sum(1 for t in user_profile['time_patterns']
                              if datetime.fromtimestamp(t).weekday() >= 5)
        total_requests = len(user_profile['time_patterns'])
        
        return weekend_requests / total_requests > 0.3 if total_requests > 0 else False
    
    def _detect_anomalies(self, client_ip, features, anomaly_score):
        """檢測具體異常類型"""
        anomalies = []
        
        if anomaly_score > self.thresholds['anomaly_score']:
            anomalies.append({
                'type': 'HIGH_ANOMALY_SCORE',
                'score': anomaly_score,
                'description': f'異常分數過高: {anomaly_score:.2f}'
            })
        
        # 檢查其他異常類型
        if features['has_suspicious_headers']:
            anomalies.append({
                'type': 'SUSPICIOUS_HEADERS',
                'description': '包含可疑HTTP標頭'
            })
        
        if features['has_suspicious_path']:
            anomalies.append({
                'type': 'SUSPICIOUS_PATH',
                'description': '訪問可疑路徑'
            })
        
        if features['has_suspicious_body']:
            anomalies.append({
                'type': 'SUSPICIOUS_BODY',
                'description': '請求體包含敏感信息'
            })
        
        return anomalies
    
    def get_user_profile(self, client_ip):
        """獲取用戶行為檔案"""
        if client_ip in self.user_profiles:
            profile = dict(self.user_profiles[client_ip])
            # 轉換不可序列化的對象
            profile['request_patterns'] = list(profile['request_patterns'])
            profile['time_patterns'] = list(profile['time_patterns'])
            profile['body_patterns'] = list(profile['body_patterns'])
            return profile
        return None
    
    def get_global_stats(self):
        """獲取全局統計信息"""
        return dict(self.global_stats)
    
    def update_thresholds(self, new_thresholds):
        """更新異常檢測閾值"""
        self.thresholds.update(new_thresholds)
    
    def enable_learning_mode(self, duration=3600):
        """啟用學習模式"""
        self.learning_mode = True
        self.learning_duration = duration
        self.start_time = time.time()
        self.logger.info(f"啟用學習模式，持續 {duration} 秒")
    
    def disable_learning_mode(self):
        """停用學習模式"""
        self.learning_mode = False
        self.logger.info("停用學習模式，開始正常檢測")
    
    def is_learning_mode(self):
        """檢查是否為學習模式"""
        if self.learning_mode:
            elapsed = time.time() - self.start_time
            if elapsed > self.learning_duration:
                self.disable_learning_mode()
        return self.learning_mode

# 測試函數
def test_ml_anomaly_detector():
    """測試機器學習異常檢測器"""
    detector = MLAnomalyDetector()
    
    print("🧠 測試機器學習異常檢測器...")
    
    # 模擬正常請求
    normal_requests = [
        ('192.168.1.100', 'GET', '/api/users', {'User-Agent': 'Mozilla/5.0'}, ''),
        ('192.168.1.100', 'GET', '/api/products', {'User-Agent': 'Mozilla/5.0'}, ''),
        ('192.168.1.100', 'POST', '/api/login', {'User-Agent': 'Mozilla/5.0'}, '{"username": "user"}'),
    ]
    
    # 模擬異常請求
    anomalous_requests = [
        ('192.168.1.200', 'GET', '/admin/config', {'User-Agent': 'curl/7.68.0'}, ''),
        ('192.168.1.200', 'POST', '/api/users', {'X-Forwarded-For': '1.1.1.1'}, '{"password": "secret"}'),
        ('192.168.1.200', 'GET', '/../../../etc/passwd', {'User-Agent': 'scanner'}, ''),
    ]
    
    print("\n📊 測試正常請求...")
    for ip, method, path, headers, body in normal_requests:
        result = detector.analyze_request(ip, method, path, headers, body)
        print(f"  {ip} {method} {path} - 異常分數: {result['anomaly_score']:.2f}")
    
    print("\n🚨 測試異常請求...")
    for ip, method, path, headers, body in anomalous_requests:
        result = detector.analyze_request(ip, method, path, headers, body)
        print(f"  {ip} {method} {path} - 異常分數: {result['anomaly_score']:.2f}")
        if result['anomalies']:
            for anomaly in result['anomalies']:
                print(f"    異常: {anomaly['description']}")
    
    print("\n📈 全局統計:")
    stats = detector.get_global_stats()
    print(f"  總請求數: {stats['total_requests']}")
    print(f"  可疑IP數: {len(stats['suspicious_ips'])}")

if __name__ == "__main__":
    test_ml_anomaly_detector()

