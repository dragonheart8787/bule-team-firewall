#!/usr/bin/env python3
"""
高級 WAF 系統
整合所有安全模組的完整防護系統
"""

import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional

# 導入所有安全模組
from ml_anomaly_detector import MLAnomalyDetector
from virtual_patch_manager import VirtualPatchManager
from soc_dashboard import SOCDashboard

# 重新導入 WAF 代理的規則引擎
import re
import urllib.parse
import http.server
import socketserver
import urllib.request

class AdvancedWAFSystem:
    """高級 WAF 系統"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # 初始化所有安全模組
        self.ml_detector = MLAnomalyDetector()
        self.patch_manager = VirtualPatchManager()
        self.soc_dashboard = SOCDashboard()
        
        # 基本 WAF 規則
        self.basic_rules = self._load_basic_rules()
        
        # 統計數據
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'ml_anomaly_blocks': 0,
            'virtual_patch_blocks': 0,
            'basic_rule_blocks': 0
        }
    
    def _load_basic_rules(self) -> List[Dict]:
        """載入基本 WAF 規則"""
        return [
            {
                'id': 'SQL_INJECTION',
                'pattern': r'(union\s+select|drop\s+table|insert\s+into|delete\s+from|update\s+set|\'\s*union\s*select|\'\s*or\s*1\s*=\s*1)',
                'severity': 'CRITICAL',
                'action': 'BLOCK'
            },
            {
                'id': 'XSS_ATTACK',
                'pattern': r'<script[^>]*>.*?</script>|<iframe[^>]*>.*?</iframe>|javascript:|on\w+\s*=',
                'severity': 'HIGH',
                'action': 'BLOCK'
            },
            {
                'id': 'PATH_TRAVERSAL',
                'pattern': r'\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f',
                'severity': 'HIGH',
                'action': 'BLOCK'
            },
            {
                'id': 'COMMAND_INJECTION',
                'pattern': r'[;&|`$(){}[\]\\]|exec\s*\(|system\s*\(|shell_exec\s*\(',
                'severity': 'CRITICAL',
                'action': 'BLOCK'
            },
            {
                'id': 'FILE_UPLOAD',
                'pattern': r'\.(php|asp|jsp|exe|bat|cmd|sh|ps1)',
                'severity': 'MEDIUM',
                'action': 'BLOCK'
            },
            {
                'id': 'NOSQL_INJECTION',
                'pattern': r'(\$where|\$ne|\$gt|\$lt|\$regex|\$exists|\$in|\$nin|\$or|\$and)',
                'severity': 'CRITICAL',
                'action': 'BLOCK'
            }
        ]
    
    def analyze_request(self, client_ip: str, method: str, path: str, 
                       headers: Dict, body: str) -> Dict:
        """分析請求並應用所有安全檢查"""
        self.stats['total_requests'] += 1
        
        # 解碼 URL
        decoded_path = urllib.parse.unquote(path, encoding='utf-8')
        
        # 1. 基本規則檢查
        basic_result = self._check_basic_rules(method, decoded_path, headers, body)
        if basic_result['blocked']:
            self.stats['basic_rule_blocks'] += 1
            self.soc_dashboard.update_metrics(f"{basic_result['rule_id']}_blocks", client_ip)
            return basic_result
        
        # 2. 機器學習異常檢測
        ml_result = self.ml_detector.analyze_request(client_ip, method, path, headers, body)
        if ml_result['is_anomalous']:
            self.stats['ml_anomaly_blocks'] += 1
            self.soc_dashboard.update_metrics('ml_anomaly_blocks', client_ip)
            return {
                'blocked': True,
                'rule_id': 'ML_ANOMALY',
                'severity': 'HIGH',
                'message': f"機器學習檢測到異常行為，分數: {ml_result['anomaly_score']:.2f}",
                'anomalies': ml_result['anomalies']
            }
        
        # 3. 虛擬補丁檢查
        patch_result = self.patch_manager.check_request(client_ip, method, path, headers, body)
        if patch_result['blocked']:
            self.stats['virtual_patch_blocks'] += 1
            self.soc_dashboard.update_metrics('virtual_patch_blocks', client_ip)
            return {
                'blocked': True,
                'rule_id': 'VIRTUAL_PATCH',
                'severity': 'HIGH',
                'message': patch_result['message'],
                'triggered_patches': patch_result['triggered_patches']
            }
        
        # 請求通過所有檢查
        return {'blocked': False, 'message': 'Request allowed'}
    
    def _check_basic_rules(self, method: str, path: str, headers: Dict, body: str) -> Dict:
        """檢查基本 WAF 規則"""
        # 檢查路徑
        for rule in self.basic_rules:
            if re.search(rule['pattern'], path, re.IGNORECASE):
                return {
                    'blocked': True,
                    'rule_id': rule['id'],
                    'severity': rule['severity'],
                    'message': f"觸發規則 {rule['id']}",
                    'matched': path
                }
        
        # 檢查請求體
        for rule in self.basic_rules:
            if body and re.search(rule['pattern'], body, re.IGNORECASE):
                return {
                    'blocked': True,
                    'rule_id': rule['id'],
                    'severity': rule['severity'],
                    'message': f"觸發規則 {rule['id']}",
                    'matched': body[:100] + '...' if len(body) > 100 else body
                }
        
        # 檢查標頭
        for rule in self.basic_rules:
            for header_name, header_value in headers.items():
                if re.search(rule['pattern'], f"{header_name}: {header_value}", re.IGNORECASE):
                    return {
                        'blocked': True,
                        'rule_id': rule['id'],
                        'severity': rule['severity'],
                        'message': f"觸發規則 {rule['id']}",
                        'matched': f"{header_name}: {header_value}"
                    }
        
        return {'blocked': False}
    
    def get_system_status(self) -> Dict:
        """獲取系統狀態"""
        return {
            'timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'ml_status': {
                'learning_mode': self.ml_detector.is_learning_mode(),
                'user_profiles': len(self.ml_detector.user_profiles)
            },
            'patch_status': {
                'total_patches': len(self.patch_manager.patches),
                'enabled_patches': sum(1 for p in self.patch_manager.patches.values() if p.enabled)
            },
            'dashboard_data': self.soc_dashboard.get_dashboard_data()
        }
    
    def get_security_report(self) -> Dict:
        """獲取安全報告"""
        return self.soc_dashboard.get_security_report()
    
    def export_data(self, filename: str):
        """導出系統數據"""
        data = {
            'export_time': datetime.now().isoformat(),
            'system_status': self.get_system_status(),
            'security_report': self.get_security_report(),
            'ml_stats': self.ml_detector.get_global_stats(),
            'patch_stats': self.patch_manager.get_patch_stats()
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"導出系統數據到: {filename}")

class AdvancedWAFHandler(http.server.BaseHTTPRequestHandler):
    """高級 WAF 處理器"""
    
    def __init__(self, waf_system, *args, **kwargs):
        self.waf_system = waf_system
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        self._handle_request('GET')
    
    def do_POST(self):
        self._handle_request('POST')
    
    def do_PUT(self):
        self._handle_request('PUT')
    
    def do_DELETE(self):
        self._handle_request('DELETE')
    
    def _handle_request(self, method):
        """處理請求"""
        # 讀取請求體
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='ignore') if content_length > 0 else ''
        
        # 分析請求
        result = self.waf_system.analyze_request(
            self.client_address[0],
            method,
            self.path,
            dict(self.headers),
            body
        )
        
        if result['blocked']:
            # 請求被阻擋
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response = {
                'error': 'Request Blocked',
                'message': result['message'],
                'rule_id': result.get('rule_id', 'UNKNOWN'),
                'severity': result.get('severity', 'UNKNOWN'),
                'timestamp': datetime.now().isoformat()
            }
            
            self.wfile.write(json.dumps(response, indent=2).encode())
            
            # 記錄阻擋事件
            self.waf_system.stats['blocked_requests'] += 1
            self.waf_system.logger.warning(f"WAF BLOCK: {method} {self.path} - {result['message']}")
        else:
            # 請求通過，轉發到後端
            self._forward_request(method, body)
    
    def _forward_request(self, method, body):
        """轉發請求到後端服務"""
        try:
            # 構建後端請求
            backend_url = f"http://127.0.0.1:8000{self.path}"
            
            if method == 'GET':
                req = urllib.request.Request(backend_url, headers=dict(self.headers))
                response = urllib.request.urlopen(req, timeout=30)
            else:
                req = urllib.request.Request(backend_url, data=body.encode(), headers=dict(self.headers))
                req.get_method = lambda: method
                response = urllib.request.urlopen(req, timeout=30)
            
            # 轉發響應
            self.send_response(response.getcode())
            for header, value in response.headers.items():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.read())
            
        except Exception as e:
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"Backend Error: {str(e)}".encode())

def start_advanced_waf(port=8080):
    """啟動高級 WAF 系統"""
    # 設置日誌
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('advanced_waf.log'),
            logging.StreamHandler()
        ]
    )
    
    # 創建 WAF 系統
    waf_system = AdvancedWAFSystem()
    
    # 創建處理器類
    class Handler(AdvancedWAFHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(waf_system, *args, **kwargs)
    
    # 啟動服務器
    with socketserver.TCPServer(("", port), Handler) as httpd:
        logging.info(f"高級 WAF 系統啟動在端口 {port}")
        logging.info(f"後端服務: http://127.0.0.1:8000")
        logging.info(f"WAF 規則數: {len(waf_system.basic_rules)}")
        logging.info(f"虛擬補丁數: {len(waf_system.patch_manager.patches)}")
        logging.info(f"機器學習異常檢測: {'啟用' if not waf_system.ml_detector.is_learning_mode() else '學習模式'}")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logging.info("WAF 系統停止")

if __name__ == "__main__":
    start_advanced_waf()

