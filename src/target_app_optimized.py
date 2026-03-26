#!/usr/bin/env python3
"""
優化的目標應用 - 提升性能
"""

from flask import Flask, request, jsonify
import logging
import time

app = Flask(__name__)

# 簡化日誌配置以提升性能
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/')
def index():
    """歡迎頁面 - 優化版"""
    return "<h1>Welcome to the Target Application</h1><p>This application is protected by the WAF. Try your attacks!</p>"

@app.route('/healthz')
def healthz():
    """健康檢查端點 - 優化版"""
    return jsonify({"status": "ok", "timestamp": time.time()})

@app.route('/search', methods=['GET'])
def search():
    """搜尋功能 - 優化版"""
    query = request.args.get('query', '')
    # 簡化處理以提升性能
    return f"<h2>Search Results for: {query}</h2><p>No results found.</p>"

@app.route('/admin')
def admin():
    """管理員頁面 - 應該被 WAF 阻擋"""
    return "<h1>Admin Panel</h1><p>This should be blocked by WAF</p>"

@app.route('/api/data', methods=['GET'])
def api_data():
    """API 端點 - 優化版"""
    return jsonify({
        "data": "sample data",
        "timestamp": time.time(),
        "status": "success"
    })

@app.route('/exec', methods=['POST'])
def execute_command():
    """命令執行端點 - 簡化版"""
    data = request.get_json()
    cmd = data.get('cmd', '') if data else ''
    
    if not cmd:
        return jsonify({"error": "No command provided"}), 400
    
    # 簡化處理，不實際執行命令
    return jsonify({
        "message": f"Command received: {cmd}",
        "status": "blocked_by_waf"
    })

if __name__ == '__main__':
    # 使用生產級配置提升性能
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,  # 關閉調試模式
        threaded=True,  # 啟用多線程
        processes=1  # 單進程但多線程
    )



