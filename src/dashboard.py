#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級防火牆監控儀表板
Military-Grade Firewall Monitoring Dashboard

功能特色：
- 即時監控
- 威脅視覺化
- 統計報表
- 告警管理
- 系統狀態
- 軍事級安全介面
"""

import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_socketio import SocketIO, emit
import sqlite3
import logging
from collections import defaultdict, deque
import psutil
import os

logger = logging.getLogger(__name__)

class FirewallDashboard:
    """防火牆監控儀表板"""
    
    def __init__(self, firewall_instance, ids_instance):
        self.firewall = firewall_instance
        self.ids = ids_instance
        self.app = Flask(__name__)
        self.app.secret_key = 'military_firewall_secret_key_2024'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # 即時資料
        self.real_time_data = {
            'packets_per_second': deque(maxlen=60),
            'threats_per_minute': deque(maxlen=60),
            'blocked_ips': set(),
            'active_connections': 0,
            'system_metrics': {}
        }
        
        # 設定路由
        self._setup_routes()
        self._setup_socketio()
        
        # 啟動背景更新
        self._start_background_updates()
        
        logger.info("監控儀表板初始化完成")

    def _setup_routes(self):
        """設定路由"""
        
        @self.app.route('/')
        def index():
            """主頁面"""
            if not session.get('authenticated'):
                return redirect(url_for('login'))
            return render_template('dashboard.html')
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            """登入頁面"""
            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')
                
                # 簡化的認證 (實際應用中應使用更安全的方式)
                if username == 'admin' and password == 'military2024':
                    session['authenticated'] = True
                    session['username'] = username
                    return redirect(url_for('index'))
                else:
                    return render_template('login.html', error='認證失敗')
            
            return render_template('login.html')
        
        @self.app.route('/logout')
        def logout():
            """登出"""
            session.clear()
            return redirect(url_for('login'))
        
        @self.app.route('/api/stats')
        def api_stats():
            """獲取統計資料API"""
            if not session.get('authenticated'):
                return jsonify({'error': '未認證'}), 401
            
            stats = self._get_comprehensive_stats()
            return jsonify(stats)
        
        @self.app.route('/api/alerts')
        def api_alerts():
            """獲取告警API"""
            if not session.get('authenticated'):
                return jsonify({'error': '未認證'}), 401
            
            limit = request.args.get('limit', 50, type=int)
            alerts = self.firewall.get_recent_alerts(limit)
            return jsonify(alerts)
        
        @self.app.route('/api/attacks')
        def api_attacks():
            """獲取攻擊事件API"""
            if not session.get('authenticated'):
                return jsonify({'error': '未認證'}), 401
            
            attack_stats = self.ids.get_attack_statistics()
            return jsonify(attack_stats)
        
        @self.app.route('/api/rules')
        def api_rules():
            """獲取防火牆規則API"""
            if not session.get('authenticated'):
                return jsonify({'error': '未認證'}), 401
            
            rules = []
            for rule in self.firewall.rules:
                rules.append({
                    'id': rule.id,
                    'name': rule.name,
                    'source_ip': rule.source_ip,
                    'dest_ip': rule.dest_ip,
                    'source_port': rule.source_port,
                    'dest_port': rule.dest_port,
                    'protocol': rule.protocol,
                    'action': rule.action.value,
                    'threat_level': rule.threat_level.value,
                    'description': rule.description,
                    'enabled': rule.enabled
                })
            
            return jsonify(rules)
        
        @self.app.route('/api/system')
        def api_system():
            """獲取系統狀態API"""
            if not session.get('authenticated'):
                return jsonify({'error': '未認證'}), 401
            
            system_info = self._get_system_info()
            return jsonify(system_info)
        
        @self.app.route('/api/block_ip', methods=['POST'])
        def api_block_ip():
            """阻擋IP API"""
            if not session.get('authenticated'):
                return jsonify({'error': '未認證'}), 401
            
            data = request.get_json()
            ip_address = data.get('ip_address')
            duration = data.get('duration', 3600)  # 預設1小時
            
            if not ip_address:
                return jsonify({'error': 'IP地址不能為空'}), 400
            
            # 新增阻擋規則
            from military_firewall import FirewallRule, Action, ThreatLevel
            rule = FirewallRule(
                id=f"block_{ip_address}_{int(time.time())}",
                name=f"手動阻擋 {ip_address}",
                source_ip=ip_address,
                dest_ip="*",
                source_port=0,
                dest_port=0,
                protocol="*",
                action=Action.DROP,
                threat_level=ThreatLevel.HIGH,
                description=f"管理員手動阻擋IP: {ip_address}"
            )
            
            self.firewall.add_rule(rule)
            
            return jsonify({'success': True, 'message': f'已阻擋IP: {ip_address}'})
        
        @self.app.route('/api/unblock_ip', methods=['POST'])
        def api_unblock_ip():
            """解除阻擋IP API"""
            if not session.get('authenticated'):
                return jsonify({'error': '未認證'}), 401
            
            data = request.get_json()
            ip_address = data.get('ip_address')
            
            if not ip_address:
                return jsonify({'error': 'IP地址不能為空'}), 400
            
            # 移除相關規則
            rules_to_remove = [
                rule for rule in self.firewall.rules
                if rule.source_ip == ip_address and rule.action == Action.DROP
            ]
            
            for rule in rules_to_remove:
                self.firewall.remove_rule(rule.id)
            
            return jsonify({'success': True, 'message': f'已解除阻擋IP: {ip_address}'})

    def _setup_socketio(self):
        """設定SocketIO事件"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """客戶端連線"""
            if not session.get('authenticated'):
                return False
            
            logger.info(f"客戶端連線: {request.sid}")
            emit('connected', {'message': '已連線到軍事級防火牆監控系統'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """客戶端斷線"""
            logger.info(f"客戶端斷線: {request.sid}")
        
        @self.socketio.on('request_update')
        def handle_request_update():
            """處理更新請求"""
            if not session.get('authenticated'):
                return
            
            stats = self._get_comprehensive_stats()
            emit('stats_update', stats)
        
        @self.socketio.on('subscribe_alerts')
        def handle_subscribe_alerts():
            """訂閱告警"""
            if not session.get('authenticated'):
                return
            
            # 加入告警房間
            from flask_socketio import join_room
            join_room('alerts')

    def _start_background_updates(self):
        """啟動背景更新"""
        def update_loop():
            while True:
                try:
                    # 更新即時資料
                    self._update_real_time_data()
                    
                    # 廣播更新
                    stats = self._get_comprehensive_stats()
                    self.socketio.emit('stats_update', stats, room='alerts')
                    
                    time.sleep(5)  # 每5秒更新一次
                
                except Exception as e:
                    logger.error(f"背景更新錯誤: {e}")
                    time.sleep(10)
        
        update_thread = threading.Thread(target=update_loop, daemon=True)
        update_thread.start()

    def _update_real_time_data(self):
        """更新即時資料"""
        try:
            # 更新封包統計
            current_stats = self.firewall.get_statistics()
            self.real_time_data['packets_per_second'].append(
                current_stats['stats']['packets_processed']
            )
            
            # 更新威脅統計
            attack_stats = self.ids.get_attack_statistics()
            self.real_time_data['threats_per_minute'].append(
                attack_stats['total_attacks']
            )
            
            # 更新系統指標
            self.real_time_data['system_metrics'] = {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'network_io': psutil.net_io_counters()._asdict()
            }
            
        except Exception as e:
            logger.error(f"更新即時資料錯誤: {e}")

    def _get_comprehensive_stats(self) -> Dict:
        """獲取綜合統計資料"""
        try:
            firewall_stats = self.firewall.get_statistics()
            attack_stats = self.ids.get_attack_statistics()
            system_info = self._get_system_info()
            
            return {
                'timestamp': datetime.now().isoformat(),
                'firewall': firewall_stats,
                'attacks': attack_stats,
                'system': system_info,
                'real_time': {
                    'packets_per_second': list(self.real_time_data['packets_per_second']),
                    'threats_per_minute': list(self.real_time_data['threats_per_minute']),
                    'blocked_ips_count': len(self.real_time_data['blocked_ips'])
                }
            }
        
        except Exception as e:
            logger.error(f"獲取統計資料錯誤: {e}")
            return {'error': str(e)}

    def _get_system_info(self) -> Dict:
        """獲取系統資訊"""
        try:
            return {
                'cpu': {
                    'percent': psutil.cpu_percent(interval=1),
                    'count': psutil.cpu_count(),
                    'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
                },
                'memory': {
                    'total': psutil.virtual_memory().total,
                    'available': psutil.virtual_memory().available,
                    'percent': psutil.virtual_memory().percent,
                    'used': psutil.virtual_memory().used
                },
                'disk': {
                    'total': psutil.disk_usage('/').total,
                    'used': psutil.disk_usage('/').used,
                    'free': psutil.disk_usage('/').free,
                    'percent': psutil.disk_usage('/').percent
                },
                'network': psutil.net_io_counters()._asdict(),
                'processes': len(psutil.pids()),
                'uptime': time.time() - psutil.boot_time()
            }
        
        except Exception as e:
            logger.error(f"獲取系統資訊錯誤: {e}")
            return {'error': str(e)}

    def run(self, host='0.0.0.0', port=5000, debug=False):
        """啟動儀表板"""
        logger.info(f"啟動監控儀表板: http://{host}:{port}")
        self.socketio.run(self.app, host=host, port=port, debug=debug)

def create_templates():
    """建立HTML模板"""
    templates_dir = 'templates'
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
    
    # 登入頁面模板
    login_template = '''<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>軍事級防火牆 - 登入</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-container {
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
        }
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .login-header h1 {
            color: #1e3c72;
            margin: 0;
            font-size: 28px;
        }
        .login-header p {
            color: #666;
            margin: 10px 0 0 0;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
        }
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            box-sizing: border-box;
        }
        .form-group input:focus {
            outline: none;
            border-color: #1e3c72;
        }
        .login-btn {
            width: 100%;
            padding: 12px;
            background: #1e3c72;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s;
        }
        .login-btn:hover {
            background: #2a5298;
        }
        .error {
            color: #e74c3c;
            text-align: center;
            margin-top: 10px;
        }
        .security-notice {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin-top: 20px;
            font-size: 14px;
            color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🛡️ 軍事級防火牆</h1>
            <p>Military-Grade Firewall System</p>
        </div>
        
        <form method="POST">
            <div class="form-group">
                <label for="username">使用者名稱</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">密碼</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="login-btn">登入</button>
            
            {% if error %}
            <div class="error">{{ error }}</div>
            {% endif %}
        </form>
        
        <div class="security-notice">
            <strong>安全提醒：</strong><br>
            此系統包含機密資訊，僅限授權人員使用。<br>
            所有活動將被記錄和監控。
        </div>
    </div>
</body>
</html>'''
    
    with open(os.path.join(templates_dir, 'login.html'), 'w', encoding='utf-8') as f:
        f.write(login_template)
    
    # 儀表板主頁面模板
    dashboard_template = '''<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>軍事級防火牆 - 監控儀表板</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 24px;
        }
        
        .header .user-info {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .logout-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            border: 1px solid rgba(255,255,255,0.3);
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
        }
        
        .logout-btn:hover {
            background: rgba(255,255,255,0.3);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #1e3c72;
        }
        
        .stat-card h3 {
            color: #666;
            font-size: 14px;
            margin-bottom: 0.5rem;
        }
        
        .stat-card .value {
            font-size: 32px;
            font-weight: bold;
            color: #1e3c72;
        }
        
        .stat-card .change {
            font-size: 12px;
            margin-top: 0.5rem;
        }
        
        .stat-card.positive .change {
            color: #27ae60;
        }
        
        .stat-card.negative .change {
            color: #e74c3c;
        }
        
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .chart-container {
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .chart-container h3 {
            margin-bottom: 1rem;
            color: #333;
        }
        
        .alerts-section {
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .alerts-section h3 {
            margin-bottom: 1rem;
            color: #333;
        }
        
        .alert-item {
            padding: 1rem;
            border-left: 4px solid #e74c3c;
            background: #fdf2f2;
            margin-bottom: 0.5rem;
            border-radius: 0 5px 5px 0;
        }
        
        .alert-item.high {
            border-left-color: #e74c3c;
            background: #fdf2f2;
        }
        
        .alert-item.medium {
            border-left-color: #f39c12;
            background: #fef9e7;
        }
        
        .alert-item.low {
            border-left-color: #27ae60;
            background: #eafaf1;
        }
        
        .alert-time {
            font-size: 12px;
            color: #666;
        }
        
        .alert-description {
            margin-top: 0.5rem;
            font-weight: 500;
        }
        
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 0.5rem;
        }
        
        .status-online {
            background: #27ae60;
        }
        
        .status-warning {
            background: #f39c12;
        }
        
        .status-offline {
            background: #e74c3c;
        }
        
        .loading {
            text-align: center;
            padding: 2rem;
            color: #666;
        }
        
        @media (max-width: 768px) {
            .charts-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ 軍事級防火牆監控系統</h1>
        <div class="user-info">
            <span>歡迎，{{ session.username }}</span>
            <a href="/logout" class="logout-btn">登出</a>
        </div>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <h3>已處理封包</h3>
                <div class="value" id="packets-processed">0</div>
                <div class="change" id="packets-change">+0 每秒</div>
            </div>
            
            <div class="stat-card">
                <h3>已阻擋封包</h3>
                <div class="value" id="packets-blocked">0</div>
                <div class="change" id="blocked-change">+0 每秒</div>
            </div>
            
            <div class="stat-card">
                <h3>威脅檢測</h3>
                <div class="value" id="threats-detected">0</div>
                <div class="change" id="threats-change">+0 每分鐘</div>
            </div>
            
            <div class="stat-card">
                <h3>系統狀態</h3>
                <div class="value">
                    <span class="status-indicator status-online"></span>
                    <span id="system-status">正常</span>
                </div>
                <div class="change" id="system-load">CPU: 0%</div>
            </div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-container">
                <h3>封包流量趨勢</h3>
                <canvas id="packetsChart"></canvas>
            </div>
            
            <div class="chart-container">
                <h3>威脅檢測趨勢</h3>
                <canvas id="threatsChart"></canvas>
            </div>
        </div>
        
        <div class="alerts-section">
            <h3>最新告警</h3>
            <div id="alerts-container">
                <div class="loading">載入中...</div>
            </div>
        </div>
    </div>
    
    <script>
        // 初始化Socket.IO
        const socket = io();
        
        // 初始化圖表
        const packetsCtx = document.getElementById('packetsChart').getContext('2d');
        const packetsChart = new Chart(packetsCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: '封包/秒',
                    data: [],
                    borderColor: '#1e3c72',
                    backgroundColor: 'rgba(30, 60, 114, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        const threatsCtx = document.getElementById('threatsChart').getContext('2d');
        const threatsChart = new Chart(threatsCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: '威脅/分鐘',
                    data: [],
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Socket.IO事件處理
        socket.on('connect', function() {
            console.log('已連線到監控系統');
        });
        
        socket.on('stats_update', function(data) {
            updateDashboard(data);
        });
        
        // 更新儀表板
        function updateDashboard(data) {
            if (data.error) {
                console.error('更新錯誤:', data.error);
                return;
            }
            
            // 更新統計卡片
            document.getElementById('packets-processed').textContent = 
                data.firewall.stats.packets_processed.toLocaleString();
            document.getElementById('packets-blocked').textContent = 
                data.firewall.stats.packets_blocked.toLocaleString();
            document.getElementById('threats-detected').textContent = 
                data.firewall.stats.threats_detected.toLocaleString();
            
            // 更新系統狀態
            if (data.system && data.system.cpu) {
                document.getElementById('system-load').textContent = 
                    `CPU: ${data.system.cpu.percent.toFixed(1)}%`;
            }
            
            // 更新圖表
            updateCharts(data);
        }
        
        // 更新圖表
        function updateCharts(data) {
            const now = new Date().toLocaleTimeString();
            
            // 更新封包圖表
            packetsChart.data.labels.push(now);
            packetsChart.data.datasets[0].data.push(
                data.real_time.packets_per_second.slice(-1)[0] || 0
            );
            
            // 更新威脅圖表
            threatsChart.data.labels.push(now);
            threatsChart.data.datasets[0].data.push(
                data.real_time.threats_per_minute.slice(-1)[0] || 0
            );
            
            // 保持最近20個數據點
            if (packetsChart.data.labels.length > 20) {
                packetsChart.data.labels.shift();
                packetsChart.data.datasets[0].data.shift();
                threatsChart.data.labels.shift();
                threatsChart.data.datasets[0].data.shift();
            }
            
            packetsChart.update('none');
            threatsChart.update('none');
        }
        
        // 載入告警
        function loadAlerts() {
            fetch('/api/alerts?limit=10')
                .then(response => response.json())
                .then(alerts => {
                    const container = document.getElementById('alerts-container');
                    if (alerts.length === 0) {
                        container.innerHTML = '<div class="loading">暫無告警</div>';
                        return;
                    }
                    
                    container.innerHTML = alerts.map(alert => `
                        <div class="alert-item ${alert.severity.toLowerCase()}">
                            <div class="alert-time">${new Date(alert.timestamp).toLocaleString()}</div>
                            <div class="alert-description">${alert.description}</div>
                        </div>
                    `).join('');
                })
                .catch(error => {
                    console.error('載入告警失敗:', error);
                });
        }
        
        // 定期載入告警
        setInterval(loadAlerts, 30000); // 每30秒更新一次
        loadAlerts(); // 初始載入
        
        // 請求初始更新
        socket.emit('request_update');
    </script>
</body>
</html>'''
    
    with open(os.path.join(templates_dir, 'dashboard.html'), 'w', encoding='utf-8') as f:
        f.write(dashboard_template)

if __name__ == "__main__":
    # 建立模板檔案
    create_templates()
    
    # 這裡需要實際的firewall和ids實例
    # dashboard = FirewallDashboard(firewall_instance, ids_instance)
    # dashboard.run(debug=True)

