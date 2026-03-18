#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中央伺服器（真實運行）
接收並存儲來自安全系統的所有資料傳輸
"""

from flask import Flask, request, jsonify
import json
import os
from datetime import datetime
from collections import defaultdict
import hashlib

app = Flask(__name__)

# ==================== 中央伺服器數據存儲 ====================

class CentralServerStorage:
    """中央伺服器存儲"""
    
    def __init__(self):
        self.storage_file = "central_server_data.json"
        self.transmissions = []
        self.statistics = defaultdict(int)
        self.load_data()
        
    def load_data(self):
        """載入數據"""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.transmissions = data.get('transmissions', [])
                    self.statistics = defaultdict(int, data.get('statistics', {}))
            except:
                pass
    
    def save_data(self):
        """保存數據"""
        data = {
            'transmissions': self.transmissions,
            'statistics': dict(self.statistics),
            'last_updated': datetime.now().isoformat()
        }
        
        with open(self.storage_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def add_transmission(self, transmission):
        """添加傳輸記錄"""
        transmission['received_at'] = datetime.now().isoformat()
        transmission['server_id'] = 'CENTRAL-001'
        
        self.transmissions.append(transmission)
        
        # 更新統計
        self.statistics['total_transmissions'] += 1
        self.statistics[f"type_{transmission.get('data_type', 'unknown')}"] += 1
        
        self.save_data()
        
        return True

storage = CentralServerStorage()

# ==================== API 端點 ====================

@app.route('/api/receive', methods=['POST'])
def receive_data():
    """接收資料傳輸"""
    try:
        data = request.get_json()
        
        # 驗證必要欄位
        required_fields = ['id', 'timestamp', 'user', 'data_type', 'data', 'checksum']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"缺少欄位: {field}"}), 400
        
        # 存儲傳輸
        storage.add_transmission(data)
        
        return jsonify({
            "status": "SUCCESS",
            "message": "資料已接收",
            "transmission_id": data['id'],
            "server_time": datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/transmissions', methods=['GET'])
def get_transmissions():
    """獲取傳輸記錄"""
    limit = request.args.get('limit', 50, type=int)
    
    return jsonify({
        "total": len(storage.transmissions),
        "transmissions": storage.transmissions[-limit:],
        "server_id": "CENTRAL-001"
    })

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """獲取統計信息"""
    return jsonify({
        "statistics": dict(storage.statistics),
        "total_transmissions": storage.statistics['total_transmissions'],
        "server_status": "ONLINE"
    })

@app.route('/health', methods=['GET'])
def health():
    """健康檢查"""
    return jsonify({
        "status": "HEALTHY",
        "server_id": "CENTRAL-001",
        "uptime": "RUNNING",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/')
def index():
    """首頁"""
    return f"""
    <html>
    <head>
        <title>中央伺服器</title>
        <style>
            body {{ font-family: Arial; padding: 20px; background: #f5f5f5; }}
            .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
            h1 {{ color: #333; }}
            .status {{ color: #28a745; font-weight: bold; }}
            .stats {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            .endpoint {{ background: #e7f3ff; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🌐 中央伺服器</h1>
            <p>狀態: <span class="status">ONLINE</span></p>
            <p>伺服器 ID: CENTRAL-001</p>
            
            <div class="stats">
                <h3>📊 統計信息</h3>
                <p>總傳輸數: {storage.statistics['total_transmissions']}</p>
                <p>LOGIN_EVENT: {storage.statistics.get('type_LOGIN_EVENT', 0)}</p>
                <p>SECURITY_ALERT: {storage.statistics.get('type_SECURITY_ALERT', 0)}</p>
                <p>DATA_ACCESS: {storage.statistics.get('type_DATA_ACCESS', 0)}</p>
                <p>DATA_MODIFICATION: {storage.statistics.get('type_DATA_MODIFICATION', 0)}</p>
            </div>
            
            <h3>📡 API 端點</h3>
            <div class="endpoint">POST /api/receive - 接收資料傳輸</div>
            <div class="endpoint">GET /api/transmissions - 獲取傳輸記錄</div>
            <div class="endpoint">GET /api/statistics - 獲取統計信息</div>
            <div class="endpoint">GET /health - 健康檢查</div>
        </div>
    </body>
    </html>
    """

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("中央伺服器啟動中...")
    print("Central Server Starting...")
    print("=" * 60)
    print("\n服務端點:")
    print("  - 主頁: http://127.0.0.1:9000")
    print("  - 接收 API: http://127.0.0.1:9000/api/receive")
    print("  - 傳輸記錄: http://127.0.0.1:9000/api/transmissions")
    print("  - 統計信息: http://127.0.0.1:9000/api/statistics")
    print("  - 健康檢查: http://127.0.0.1:9000/health")
    print("\n" + "=" * 60 + "\n")
    
    app.run(host='127.0.0.1', port=9000, debug=False)


