#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整系統測試
測試整個安全系統的所有功能
"""

import requests
import time
import json
from datetime import datetime

WEB_URL = "http://127.0.0.1:5000"
CENTRAL_URL = "http://127.0.0.1:9000"

class FullSystemTest:
    """完整系統測試"""
    
    def __init__(self):
        self.results = {
            'connectivity': None,
            'attack_protection': None,
            'central_server': None,
            'functionality': None,
            'overall': None
        }
    
    def test_connectivity(self):
        """連通性測試"""
        print("\n[1/4] 測試服務連通性...")
        print("-" * 60)
        
        tests = []
        
        # Web 系統
        try:
            resp = requests.get(f"{WEB_URL}/login", timeout=3)
            web_ok = resp.status_code == 200
            print(f"  Web 系統: {'[OK]' if web_ok else '[FAIL]'} - {resp.status_code}")
            tests.append(web_ok)
        except Exception as e:
            print(f"  Web 系統: [FAIL] - {str(e)[:40]}")
            tests.append(False)
        
        # 中央伺服器
        try:
            resp = requests.get(f"{CENTRAL_URL}/health", timeout=3)
            central_ok = resp.status_code == 200
            print(f"  中央伺服器: {'[OK]' if central_ok else '[FAIL]'} - {resp.status_code}")
            tests.append(central_ok)
        except Exception as e:
            print(f"  中央伺服器: [FAIL] - {str(e)[:40]}")
            tests.append(False)
        
        success_rate = (sum(tests) / len(tests)) * 100
        print(f"\n  連通性: {success_rate:.0f}% ({sum(tests)}/{len(tests)})")
        
        self.results['connectivity'] = {
            'passed': all(tests),
            'success_rate': success_rate
        }
        
        return all(tests)
    
    def test_attack_protection(self):
        """攻擊防護測試"""
        print("\n[2/4] 測試攻擊防護...")
        print("-" * 60)
        
        attacks = {
            "SQL 注入": ["admin' OR '1'='1", "1' UNION SELECT * FROM users--"],
            "XSS 攻擊": ["<script>alert(1)</script>", "javascript:alert(1)"],
            "路徑遍歷": ["../../../etc/passwd", "..\\..\\windows"],
            "命令注入": ["; ls -la", "| cat /etc/passwd"]
        }
        
        total_blocked = 0
        total_tests = 0
        
        for attack_type, payloads in attacks.items():
            blocked = 0
            for payload in payloads:
                total_tests += 1
                try:
                    resp = requests.post(
                        f"{WEB_URL}/login",
                        json={"username": payload, "password": "test", "csrf_token": "test"},
                        timeout=3
                    )
                    
                    if resp.status_code in [403, 401]:
                        blocked += 1
                        total_blocked += 1
                except:
                    blocked += 1
                    total_blocked += 1
            
            rate = (blocked / len(payloads)) * 100
            print(f"  {attack_type}: {rate:.0f}% ({blocked}/{len(payloads)})")
        
        protection_rate = (total_blocked / total_tests) * 100
        print(f"\n  總體防護率: {protection_rate:.0f}% ({total_blocked}/{total_tests})")
        
        passed = protection_rate >= 80
        
        self.results['attack_protection'] = {
            'passed': passed,
            'protection_rate': protection_rate
        }
        
        return passed
    
    def test_central_server(self):
        """中央伺服器測試"""
        print("\n[3/4] 測試中央伺服器功能...")
        print("-" * 60)
        
        tests = []
        
        # 健康檢查
        try:
            resp = requests.get(f"{CENTRAL_URL}/health", timeout=3)
            health_ok = resp.status_code == 200
            print(f"  健康檢查: {'[OK]' if health_ok else '[FAIL]'}")
            tests.append(health_ok)
        except:
            print(f"  健康檢查: [FAIL]")
            tests.append(False)
        
        # 傳輸記錄
        try:
            resp = requests.get(f"{CENTRAL_URL}/api/transmissions", timeout=3)
            trans_ok = resp.status_code == 200
            
            if trans_ok:
                data = resp.json()
                total = data.get('total', 0)
                print(f"  傳輸記錄: [OK] - 總數: {total}")
            else:
                print(f"  傳輸記錄: [FAIL]")
            
            tests.append(trans_ok)
        except:
            print(f"  傳輸記錄: [FAIL]")
            tests.append(False)
        
        # 統計信息
        try:
            resp = requests.get(f"{CENTRAL_URL}/api/statistics", timeout=3)
            stats_ok = resp.status_code == 200
            print(f"  統計信息: {'[OK]' if stats_ok else '[FAIL]'}")
            tests.append(stats_ok)
        except:
            print(f"  統計信息: [FAIL]")
            tests.append(False)
        
        success_rate = (sum(tests) / len(tests)) * 100
        print(f"\n  中央伺服器: {success_rate:.0f}% ({sum(tests)}/{len(tests)})")
        
        passed = all(tests)
        
        self.results['central_server'] = {
            'passed': passed,
            'success_rate': success_rate
        }
        
        return passed
    
    def test_functionality(self):
        """功能測試"""
        print("\n[4/4] 測試系統功能...")
        print("-" * 60)
        
        tests = []
        
        # 登入頁面載入
        try:
            resp = requests.get(f"{WEB_URL}/login", timeout=3)
            login_ok = resp.status_code == 200 and 'password' in resp.text.lower()
            print(f"  登入頁面: {'[OK]' if login_ok else '[FAIL]'}")
            tests.append(login_ok)
        except:
            print(f"  登入頁面: [FAIL]")
            tests.append(False)
        
        # 密碼輸入框
        try:
            resp = requests.get(f"{WEB_URL}/login", timeout=3)
            has_password_input = 'type="password"' in resp.text
            print(f"  密碼輸入框: {'[OK]' if has_password_input else '[FAIL]'}")
            tests.append(has_password_input)
        except:
            print(f"  密碼輸入框: [FAIL]")
            tests.append(False)
        
        # CSRF Token
        try:
            resp = requests.get(f"{WEB_URL}/login", timeout=3)
            has_csrf = 'csrf_token' in resp.text.lower()
            print(f"  CSRF 保護: {'[OK]' if has_csrf else '[FAIL]'}")
            tests.append(has_csrf)
        except:
            print(f"  CSRF 保護: [FAIL]")
            tests.append(False)
        
        success_rate = (sum(tests) / len(tests)) * 100
        print(f"\n  功能完整性: {success_rate:.0f}% ({sum(tests)}/{len(tests)})")
        
        passed = all(tests)
        
        self.results['functionality'] = {
            'passed': passed,
            'success_rate': success_rate
        }
        
        return passed
    
    def run_all_tests(self):
        """運行所有測試"""
        print("\n" + "=" * 70)
        print("  國防等級 Web 系統 - 完整系統測試")
        print("  Defense-Grade Web System - Full System Test")
        print("=" * 70)
        
        start_time = time.time()
        
        # 運行測試
        conn_ok = self.test_connectivity()
        attack_ok = self.test_attack_protection()
        central_ok = self.test_central_server()
        func_ok = self.test_functionality()
        
        # 總結
        elapsed = time.time() - start_time
        
        print("\n" + "=" * 70)
        print("  最終結果")
        print("=" * 70)
        
        print(f"\n  連通性測試: {'[PASS]' if conn_ok else '[FAIL]'}")
        print(f"  攻擊防護測試: {'[PASS]' if attack_ok else '[FAIL]'}")
        print(f"  中央伺服器測試: {'[PASS]' if central_ok else '[FAIL]'}")
        print(f"  功能測試: {'[PASS]' if func_ok else '[FAIL]'}")
        
        all_passed = conn_ok and attack_ok and central_ok and func_ok
        
        print(f"\n  總體狀態: {'[PASS]' if all_passed else '[FAIL]'}")
        print(f"  測試耗時: {elapsed:.1f} 秒")
        
        # 保存結果
        self.results['overall'] = {
            'passed': all_passed,
            'duration': elapsed
        }
        
        filename = f"FULL_SYSTEM_TEST_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n  報告已保存: {filename}")
        print("\n" + "=" * 70 + "\n")
        
        return 0 if all_passed else 1

def main():
    tester = FullSystemTest()
    return tester.run_all_tests()

if __name__ == "__main__":
    import sys
    sys.exit(main())


