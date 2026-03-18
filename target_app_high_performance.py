#!/usr/bin/env python3
"""
高性能目標應用 - 使用 Gunicorn + 優化配置
"""

from flask import Flask, request, jsonify
import logging
import time
import os

app = Flask(__name__)

# 最小化日誌以提升性能
logging.basicConfig(level=logging.ERROR)

# 記錄啟動時間
start_time = time.time()

@app.route('/')
def index():
    """歡迎頁面 - 極簡版"""
    return "<h1>Welcome to High-Performance Target App</h1><p>Protected by Enterprise WAF</p>"

@app.route('/healthz')
def healthz():
    """健康檢查 - 極簡版"""
    return jsonify({"status": "ok", "timestamp": time.time()})

@app.route('/admin')
def admin():
    """管理員頁面 - 應該被 WAF 阻擋"""
    return "<h1>Admin Panel</h1><p>This should be blocked by WAF</p>"

@app.route('/search', methods=['GET'])
def search():
    """搜尋功能 - 極簡版"""
    query = request.args.get('query', '')
    return f"<h2>Search Results for: {query}</h2><p>No results found.</p>"

@app.route('/api/data', methods=['GET'])
def api_data():
    """API 端點 - 極簡版"""
    return jsonify({
        "data": "sample data",
        "timestamp": time.time(),
        "status": "success"
    })

@app.route('/exec', methods=['POST'])
def execute_command():
    """命令執行端點 - 極簡版"""
    data = request.get_json()
    cmd = data.get('cmd', '') if data else ''
    
    if not cmd:
        return jsonify({"error": "No command provided"}), 400
    
    return jsonify({
        "message": f"Command received: {cmd}",
        "status": "blocked_by_waf"
    })

if __name__ == '__main__':
    # 高性能配置
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True,
        processes=1
    )



