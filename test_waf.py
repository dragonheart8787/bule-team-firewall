#!/usr/bin/env python3
"""
WAF 測試腳本
測試各種攻擊模式是否被正確阻擋
"""

import requests
import json
import time
import threading

def test_waf():
    """測試 WAF 功能"""
    base_url = "http://127.0.0.1:8080"
    
    # 測試案例
    test_cases = [
        {
            'name': '正常請求',
            'method': 'GET',
            'path': '/',
            'expected_status': [200, 502]  # 200 或 502 (後端未運行)
        },
        {
            'name': 'SQL 注入攻擊',
            'method': 'GET',
            'path': '/?id=1\' UNION SELECT * FROM users--',
            'expected_status': [403]
        },
        {
            'name': 'XSS 攻擊',
            'method': 'GET',
            'path': '/?search=<script>alert("XSS")</script>',
            'expected_status': [403]
        },
        {
            'name': '路徑遍歷攻擊',
            'method': 'GET',
            'path': '/../../../etc/passwd',
            'expected_status': [403]
        },
        {
            'name': '命令注入攻擊',
            'method': 'POST',
            'path': '/',
            'data': 'name=test; rm -rf /',
            'expected_status': [403]
        },
        {
            'name': '檔案上傳攻擊',
            'method': 'POST',
            'path': '/upload',
            'data': 'file=malicious.php',
            'expected_status': [403]
        }
    ]
    
    print("🔒 開始 WAF 測試...")
    print("=" * 50)
    
    results = []
    
    for test_case in test_cases:
        print(f"\n🧪 測試: {test_case['name']}")
        print(f"   請求: {test_case['method']} {test_case['path']}")
        
        try:
            if test_case['method'] == 'GET':
                response = requests.get(f"{base_url}{test_case['path']}", timeout=5)
            else:
                response = requests.post(
                    f"{base_url}{test_case['path']}", 
                    data=test_case.get('data', ''),
                    timeout=5
                )
            
            status_code = response.status_code
            print(f"   狀態碼: {status_code}")
            
            # 檢查是否為預期狀態碼
            if status_code in test_case['expected_status']:
                print("   ✅ 測試通過")
                result = 'PASS'
            else:
                print(f"   ❌ 測試失敗 - 期望 {test_case['expected_status']}, 得到 {status_code}")
                result = 'FAIL'
            
            # 如果是 403，顯示 WAF 響應
            if status_code == 403:
                try:
                    waf_response = response.json()
                    print(f"   🛡️  WAF 阻擋原因: {waf_response.get('message', 'Unknown')}")
                    if 'violations' in waf_response:
                        for violation in waf_response['violations']:
                            print(f"      - {violation['rule_id']}: {violation['severity']}")
                except:
                    print(f"   🛡️  WAF 響應: {response.text[:100]}...")
            
            results.append({
                'test': test_case['name'],
                'status_code': status_code,
                'result': result
            })
            
        except requests.exceptions.RequestException as e:
            print(f"   ❌ 請求失敗: {e}")
            results.append({
                'test': test_case['name'],
                'status_code': None,
                'result': 'ERROR'
            })
        
        time.sleep(0.5)  # 避免請求過快
    
    # 顯示測試結果摘要
    print("\n" + "=" * 50)
    print("📊 測試結果摘要:")
    print("=" * 50)
    
    passed = sum(1 for r in results if r['result'] == 'PASS')
    failed = sum(1 for r in results if r['result'] == 'FAIL')
    errors = sum(1 for r in results if r['result'] == 'ERROR')
    
    print(f"✅ 通過: {passed}")
    print(f"❌ 失敗: {failed}")
    print(f"⚠️  錯誤: {errors}")
    print(f"📈 總計: {len(results)}")
    
    if failed == 0 and errors == 0:
        print("\n🎉 所有測試通過！WAF 運行正常。")
    else:
        print(f"\n⚠️  有 {failed + errors} 個測試未通過，請檢查 WAF 配置。")
    
    return results

def start_backend_mock():
    """啟動模擬後端服務"""
    import http.server
    import socketserver
    
    class MockHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<h1>Backend Service Running</h1>')
        
        def do_POST(self):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "success"}')
    
    with socketserver.TCPServer(("", 8000), MockHandler) as httpd:
        print("🔧 後端模擬服務啟動在端口 8000")
        httpd.serve_forever()

if __name__ == "__main__":
    print("🚀 啟動 WAF 測試環境...")
    
    # 在背景啟動後端服務
    backend_thread = threading.Thread(target=start_backend_mock, daemon=True)
    backend_thread.start()
    
    # 等待後端服務啟動
    time.sleep(2)
    
    # 執行測試
    test_waf()
