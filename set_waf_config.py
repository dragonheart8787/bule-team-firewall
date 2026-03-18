#!/usr/bin/env python3
"""
設置 WAF 配置
"""

import requests
import json

def set_waf_config():
    """設置 WAF 為 full 模式"""
    try:
        config_data = {
            'governance_mode': 'full',
            'small_traffic_percent': 100
        }
        
        response = requests.post('http://localhost:8080/api/config', json=config_data)
        print(f'配置設置結果: {response.status_code}')
        print(f'響應: {response.text}')
        
        # 測試管理員路徑
        print('\n測試管理員路徑...')
        test_response = requests.get('http://localhost:8080/admin')
        print(f'管理員路徑狀態碼: {test_response.status_code}')
        
    except Exception as e:
        print(f'錯誤: {e}')

if __name__ == "__main__":
    set_waf_config()



