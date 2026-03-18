#!/usr/bin/env python3
"""
SOC 儀表板
安全運營中心可視化監控系統
"""

import json
import time
from datetime import datetime, timedelta
from typing import Dict, List
import logging

class SOCDashboard:
    """SOC 儀表板類"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.metrics = {
            'total_requests': 0,
            'blocked_requests': 0,
            'sql_injection_blocks': 0,
            'xss_blocks': 0,
            'path_traversal_blocks': 0,
            'command_injection_blocks': 0,
            'file_upload_blocks': 0,
            'nosql_injection_blocks': 0,
            'rate_limit_blocks': 0,
            'virtual_patch_blocks': 0,
            'threat_intel_blocks': 0,
            'ml_anomaly_blocks': 0
        }
        
        self.recent_events = []
        self.top_attackers = {}
        self.attack_timeline = []
        self.security_score = 100.0
        
    def update_metrics(self, event_type: str, client_ip: str = None):
        """更新指標"""
        self.metrics['total_requests'] += 1
        
        if event_type == 'BLOCK':
            self.metrics['blocked_requests'] += 1
            if client_ip:
                self.top_attackers[client_ip] = self.top_attackers.get(client_ip, 0) + 1
        
        # 更新特定攻擊類型計數
        if event_type in self.metrics:
            self.metrics[event_type] += 1
        
        # 記錄事件
        self._record_event(event_type, client_ip)
        
        # 更新安全分數
        self._update_security_score()
    
    def _record_event(self, event_type: str, client_ip: str = None):
        """記錄事件"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'client_ip': client_ip,
            'severity': self._get_severity(event_type)
        }
        
        self.recent_events.append(event)
        
        # 保持最近1000個事件
        if len(self.recent_events) > 1000:
            self.recent_events = self.recent_events[-1000:]
        
        # 更新攻擊時間線
        self.attack_timeline.append({
            'timestamp': datetime.now().isoformat(),
            'count': 1
        })
        
        # 保持最近24小時的數據
        cutoff_time = datetime.now() - timedelta(hours=24)
        self.attack_timeline = [
            event for event in self.attack_timeline
            if datetime.fromisoformat(event['timestamp']) > cutoff_time
        ]
    
    def _get_severity(self, event_type: str) -> str:
        """獲取事件嚴重性"""
        severity_map = {
            'sql_injection_blocks': 'CRITICAL',
            'xss_blocks': 'HIGH',
            'path_traversal_blocks': 'HIGH',
            'command_injection_blocks': 'CRITICAL',
            'file_upload_blocks': 'MEDIUM',
            'nosql_injection_blocks': 'CRITICAL',
            'rate_limit_blocks': 'LOW',
            'virtual_patch_blocks': 'HIGH',
            'threat_intel_blocks': 'HIGH',
            'ml_anomaly_blocks': 'MEDIUM'
        }
        return severity_map.get(event_type, 'LOW')
    
    def _update_security_score(self):
        """更新安全分數"""
        total_requests = self.metrics['total_requests']
        blocked_requests = self.metrics['blocked_requests']
        
        if total_requests > 0:
            block_rate = blocked_requests / total_requests
            # 安全分數基於阻擋率，阻擋率越高分數越低
            self.security_score = max(0, 100 - (block_rate * 50))
        else:
            self.security_score = 100.0
    
    def get_dashboard_data(self) -> Dict:
        """獲取儀表板數據"""
        return {
            'timestamp': datetime.now().isoformat(),
            'metrics': self.metrics,
            'security_score': round(self.security_score, 2),
            'recent_events': self.recent_events[-50:],  # 最近50個事件
            'top_attackers': self._get_top_attackers(10),
            'attack_timeline': self._get_hourly_timeline(),
            'threat_summary': self._get_threat_summary()
        }
    
    def _get_top_attackers(self, limit: int = 10) -> List[Dict]:
        """獲取頂級攻擊者"""
        sorted_attackers = sorted(
            self.top_attackers.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [
            {'ip': ip, 'attack_count': count}
            for ip, count in sorted_attackers[:limit]
        ]
    
    def _get_hourly_timeline(self) -> List[Dict]:
        """獲取每小時攻擊時間線"""
        hourly_data = {}
        current_time = datetime.now()
        
        # 初始化過去24小時的數據
        for i in range(24):
            hour = current_time - timedelta(hours=i)
            hour_key = hour.strftime('%Y-%m-%d %H:00')
            hourly_data[hour_key] = 0
        
        # 統計每小時的攻擊次數
        for event in self.attack_timeline:
            event_time = datetime.fromisoformat(event['timestamp'])
            hour_key = event_time.strftime('%Y-%m-%d %H:00')
            if hour_key in hourly_data:
                hourly_data[hour_key] += event['count']
        
        # 轉換為列表格式
        timeline = []
        for hour in sorted(hourly_data.keys()):
            timeline.append({
                'hour': hour,
                'count': hourly_data[hour]
            })
        
        return timeline[-24:]  # 返回最近24小時
    
    def _get_threat_summary(self) -> Dict:
        """獲取威脅摘要"""
        total_blocks = self.metrics['blocked_requests']
        
        if total_blocks == 0:
            return {
                'total_threats': 0,
                'threat_distribution': {},
                'risk_level': 'LOW'
            }
        
        threat_distribution = {}
        for key, value in self.metrics.items():
            if key.endswith('_blocks') and value > 0:
                threat_type = key.replace('_blocks', '').replace('_', ' ').title()
                threat_distribution[threat_type] = value
        
        # 計算風險等級
        if total_blocks > 100:
            risk_level = 'HIGH'
        elif total_blocks > 50:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'total_threats': total_blocks,
            'threat_distribution': threat_distribution,
            'risk_level': risk_level
        }
    
    def get_security_report(self) -> Dict:
        """獲取安全報告"""
        return {
            'report_time': datetime.now().isoformat(),
            'summary': {
                'total_requests': self.metrics['total_requests'],
                'blocked_requests': self.metrics['blocked_requests'],
                'block_rate': f"{(self.metrics['blocked_requests'] / max(1, self.metrics['total_requests'])) * 100:.2f}%",
                'security_score': round(self.security_score, 2)
            },
            'top_threats': self._get_top_threats(),
            'recommendations': self._get_recommendations()
        }
    
    def _get_top_threats(self) -> List[Dict]:
        """獲取主要威脅"""
        threats = []
        for key, value in self.metrics.items():
            if key.endswith('_blocks') and value > 0:
                threat_type = key.replace('_blocks', '').replace('_', ' ').title()
                threats.append({
                    'type': threat_type,
                    'count': value,
                    'severity': self._get_severity(key)
                })
        
        return sorted(threats, key=lambda x: x['count'], reverse=True)[:5]
    
    def _get_recommendations(self) -> List[str]:
        """獲取安全建議"""
        recommendations = []
        
        if self.metrics['sql_injection_blocks'] > 10:
            recommendations.append("SQL 注入攻擊頻繁，建議加強輸入驗證和參數化查詢")
        
        if self.metrics['xss_blocks'] > 5:
            recommendations.append("XSS 攻擊檢測到，建議實施內容安全策略 (CSP)")
        
        if self.metrics['rate_limit_blocks'] > 50:
            recommendations.append("大量速率限制觸發，建議檢查是否為 DDoS 攻擊")
        
        if self.security_score < 70:
            recommendations.append("安全分數較低，建議全面檢查安全配置")
        
        if not recommendations:
            recommendations.append("系統安全狀況良好，繼續保持現有防護措施")
        
        return recommendations
    
    def export_data(self, filename: str):
        """導出數據"""
        data = {
            'export_time': datetime.now().isoformat(),
            'dashboard_data': self.get_dashboard_data(),
            'security_report': self.get_security_report()
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"導出 SOC 數據到: {filename}")

# 測試函數
def test_soc_dashboard():
    """測試 SOC 儀表板"""
    dashboard = SOCDashboard()
    
    print("📊 測試 SOC 儀表板...")
    
    # 模擬一些事件
    test_events = [
        ('sql_injection_blocks', '192.168.1.100'),
        ('xss_blocks', '192.168.1.101'),
        ('path_traversal_blocks', '192.168.1.102'),
        ('command_injection_blocks', '192.168.1.100'),
        ('rate_limit_blocks', '192.168.1.103'),
        ('virtual_patch_blocks', '192.168.1.104'),
    ]
    
    for event_type, client_ip in test_events:
        dashboard.update_metrics(event_type, client_ip)
    
    # 顯示儀表板數據
    print("\n📈 儀表板數據:")
    data = dashboard.get_dashboard_data()
    print(f"  總請求數: {data['metrics']['total_requests']}")
    print(f"  阻擋請求數: {data['metrics']['blocked_requests']}")
    print(f"  安全分數: {data['security_score']}")
    print(f"  風險等級: {data['threat_summary']['risk_level']}")
    
    print("\n🎯 主要威脅:")
    for threat in data['threat_summary']['threat_distribution']:
        print(f"  - {threat}: {data['threat_summary']['threat_distribution'][threat]}")
    
    print("\n🏆 頂級攻擊者:")
    for attacker in data['top_attackers'][:3]:
        print(f"  - {attacker['ip']}: {attacker['attack_count']} 次攻擊")
    
    print("\n💡 安全建議:")
    report = dashboard.get_security_report()
    for rec in report['recommendations']:
        print(f"  - {rec}")

if __name__ == "__main__":
    test_soc_dashboard()

