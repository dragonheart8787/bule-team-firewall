#!/usr/bin/env python3
"""
監控儀表板設置腳本
建立 Prometheus 和 Grafana 的配置檔案
"""

import os
import json
import yaml

def create_prometheus_config():
    """建立 Prometheus 配置"""
    config = {
        'global': {
            'scrape_interval': '15s',
            'evaluation_interval': '15s'
        },
        'scrape_configs': [
            {
                'job_name': 'waf-proxy',
                'metrics_path': '/metrics',
                'static_configs': [
                    {'targets': ['waf-proxy-1:8080', 'waf-proxy-2:8080', 'waf-proxy-3:8080']}
                ]
            },
            {
                'job_name': 'siem-engine',
                'metrics_path': '/metrics',
                'static_configs': [
                    {'targets': ['siem-engine:8001']}
                ]
            },
            {
                'job_name': 'target-app',
                'metrics_path': '/metrics',
                'static_configs': [
                    {'targets': ['target-app:5000']}
                ]
            }
        ]
    }
    
    os.makedirs('monitoring', exist_ok=True)
    with open('monitoring/prometheus.yml', 'w') as f:
        yaml.dump(config, f, default_flow_style=False)
    
    print("Prometheus 配置已建立: monitoring/prometheus.yml")

def create_grafana_dashboard():
    """建立 Grafana 儀表板配置"""
    dashboard = {
        "dashboard": {
            "id": None,
            "title": "WAF 企業級監控儀表板",
            "tags": ["waf", "security", "enterprise"],
            "timezone": "browser",
            "panels": [
                {
                    "id": 1,
                    "title": "WAF 請求處理量",
                    "type": "graph",
                    "targets": [
                        {
                            "expr": "rate(waf_requests_total[5m])",
                            "legendFormat": "{{instance}}"
                        }
                    ],
                    "yAxes": [
                        {
                            "label": "請求/秒",
                            "min": 0
                        }
                    ]
                },
                {
                    "id": 2,
                    "title": "WAF 阻擋率",
                    "type": "stat",
                    "targets": [
                        {
                            "expr": "rate(waf_blocked_requests_total[5m]) / rate(waf_requests_total[5m]) * 100",
                            "legendFormat": "阻擋率 %"
                        }
                    ]
                },
                {
                    "id": 3,
                    "title": "SIEM 警報數量",
                    "type": "graph",
                    "targets": [
                        {
                            "expr": "siem_total_alerts",
                            "legendFormat": "總警報數"
                        }
                    ]
                },
                {
                    "id": 4,
                    "title": "系統健康狀態",
                    "type": "table",
                    "targets": [
                        {
                            "expr": "up",
                            "legendFormat": "{{job}} - {{instance}}"
                        }
                    ]
                }
            ],
            "time": {
                "from": "now-1h",
                "to": "now"
            },
            "refresh": "5s"
        }
    }
    
    os.makedirs('monitoring/grafana/dashboards', exist_ok=True)
    with open('monitoring/grafana/dashboards/waf-dashboard.json', 'w') as f:
        json.dump(dashboard, f, indent=2)
    
    print("Grafana 儀表板已建立: monitoring/grafana/dashboards/waf-dashboard.json")

def create_alert_rules():
    """建立警報規則"""
    rules = {
        'groups': [
            {
                'name': 'waf_alerts',
                'rules': [
                    {
                        'alert': 'HighWAFBlockedRequests',
                        'expr': 'sum(rate(waf_blocked_requests_total[5m])) by (instance) > 10',
                        'for': '1m',
                        'labels': {
                            'severity': 'critical'
                        },
                        'annotations': {
                            'summary': 'WAF 實例 {{ $labels.instance }} 阻擋大量請求',
                            'description': 'WAF 實例 {{ $labels.instance }} 在過去 5 分鐘內阻擋了 {{ $value }} 個請求'
                        }
                    },
                    {
                        'alert': 'WAFBackendDown',
                        'expr': 'up{job="waf-proxy"} == 0',
                        'for': '1m',
                        'labels': {
                            'severity': 'critical'
                        },
                        'annotations': {
                            'summary': 'WAF 後端實例 {{ $labels.instance }} 離線',
                            'description': 'WAF 後端實例 {{ $labels.instance }} 無法被 Prometheus 存取'
                        }
                    },
                    {
                        'alert': 'HighSIEMAlerts',
                        'expr': 'siem_total_alerts > 100',
                        'for': '5m',
                        'labels': {
                            'severity': 'warning'
                        },
                        'annotations': {
                            'summary': 'SIEM 警報數量過高',
                            'description': 'SIEM 系統目前有 {{ $value }} 個警報，可能表示有大量安全事件'
                        }
                    }
                ]
            }
        ]
    }
    
    with open('monitoring/waf_rules.yml', 'w') as f:
        yaml.dump(rules, f, default_flow_style=False)
    
    print("警報規則已建立: monitoring/waf_rules.yml")

def main():
    """主函數"""
    print("建立企業級監控配置...")
    
    try:
        create_prometheus_config()
        create_grafana_dashboard()
        create_alert_rules()
        
        print("\n監控配置建立完成！")
        print("\n下一步：")
        print("1. 執行 deploy_enterprise.bat 啟動完整系統")
        print("2. 訪問 http://localhost:3000 查看 Grafana 儀表板")
        print("3. 訪問 http://localhost:9090 查看 Prometheus 指標")
        
    except Exception as e:
        print(f"建立配置時發生錯誤: {e}")

if __name__ == "__main__":
    main()
