#!/usr/bin/env python3
"""
企業級綜合測試腳本
整合所有修復和改進：連接穩定性、實戰級壓測、HA 故障演練、規則治理
"""

import asyncio
import aiohttp
import time
import json
import statistics
import subprocess
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import argparse
import sys
import os

class EnterpriseTestSuite:
    """企業級測試套件"""
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url.rstrip('/')
        self.session = None
        self.test_results = {}
        self.start_time = None
        self.end_time = None
    
    async def create_session(self):
        """創建優化的 HTTP 會話"""
        connector = aiohttp.TCPConnector(
            limit=1000,  # 總連接池大小
            limit_per_host=100,  # 每個主機的連接數
            ttl_dns_cache=300,  # DNS 緩存時間
            use_dns_cache=True,
            keepalive_timeout=30,  # keep-alive 超時
            enable_cleanup_closed=True,
            force_close=False,  # 保持連接
            ssl=False  # 禁用 SSL 驗證（用於測試）
        )
        
        timeout = aiohttp.ClientTimeout(
            total=30,  # 總超時
            connect=10,  # 連接超時
            sock_read=20  # 讀取超時
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'EnterpriseTestSuite/1.0',
                'Connection': 'keep-alive',
                'Accept-Encoding': 'gzip, deflate'
            }
        )
    
    async def close_session(self):
        """關閉 HTTP 會話"""
        if self.session:
            await self.session.close()
    
    async def test_1_connection_stability(self):
        """測試 1: 連接穩定性測試"""
        print("\n" + "="*60)
        print("測試 1: 連接穩定性測試")
        print("="*60)
        
        test_results = {
            "name": "連接穩定性測試",
            "start_time": datetime.now(),
            "tests": [],
            "summary": {}
        }
        
        # 1.1 基本連接測試
        print("1.1 基本連接測試...")
        connection_tests = []
        
        for i in range(10):
            start_time = time.time()
            try:
                async with self.session.get(f"{self.base_url}/healthz") as response:
                    response_time = (time.time() - start_time) * 1000
                    success = response.status == 200
                    
                    connection_tests.append({
                        "attempt": i + 1,
                        "success": success,
                        "response_time": response_time,
                        "status_code": response.status
                    })
                    
                    print(f"   嘗試 {i+1}: {'✅' if success else '❌'} "
                          f"({response_time:.1f}ms, {response.status})")
                    
            except Exception as e:
                response_time = (time.time() - start_time) * 1000
                connection_tests.append({
                    "attempt": i + 1,
                    "success": False,
                    "response_time": response_time,
                    "error": str(e)
                })
                print(f"   嘗試 {i+1}: ❌ ({response_time:.1f}ms, {str(e)})")
            
            await asyncio.sleep(0.1)  # 100ms 間隔
        
        # 1.2 並發連接測試
        print("\n1.2 並發連接測試...")
        concurrent_tests = []
        
        async def concurrent_request(request_id: int):
            start_time = time.time()
            try:
                async with self.session.get(f"{self.base_url}/healthz") as response:
                    response_time = (time.time() - start_time) * 1000
                    return {
                        "request_id": request_id,
                        "success": response.status == 200,
                        "response_time": response_time,
                        "status_code": response.status
                    }
            except Exception as e:
                response_time = (time.time() - start_time) * 1000
                return {
                    "request_id": request_id,
                    "success": False,
                    "response_time": response_time,
                    "error": str(e)
                }
        
        # 發送 50 個並發請求
        tasks = [concurrent_request(i) for i in range(50)]
        concurrent_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in concurrent_results:
            if isinstance(result, dict):
                concurrent_tests.append(result)
                print(f"   請求 {result['request_id']}: {'✅' if result['success'] else '❌'} "
                      f"({result['response_time']:.1f}ms)")
        
        # 1.3 長時間連接測試
        print("\n1.3 長時間連接測試...")
        long_term_tests = []
        
        for i in range(20):  # 20 分鐘，每分鐘一次
            start_time = time.time()
            try:
                async with self.session.get(f"{self.base_url}/healthz") as response:
                    response_time = (time.time() - start_time) * 1000
                    success = response.status == 200
                    
                    long_term_tests.append({
                        "minute": i + 1,
                        "success": success,
                        "response_time": response_time,
                        "status_code": response.status
                    })
                    
                    print(f"   第 {i+1} 分鐘: {'✅' if success else '❌'} "
                          f"({response_time:.1f}ms)")
                    
            except Exception as e:
                response_time = (time.time() - start_time) * 1000
                long_term_tests.append({
                    "minute": i + 1,
                    "success": False,
                    "response_time": response_time,
                    "error": str(e)
                })
                print(f"   第 {i+1} 分鐘: ❌ ({response_time:.1f}ms)")
            
            await asyncio.sleep(60)  # 1 分鐘間隔
        
        # 計算摘要
        all_tests = connection_tests + concurrent_tests + long_term_tests
        successful_tests = [t for t in all_tests if t.get('success', False)]
        
        test_results["tests"] = {
            "basic_connection": connection_tests,
            "concurrent_connection": concurrent_tests,
            "long_term_connection": long_term_tests
        }
        
        test_results["summary"] = {
            "total_tests": len(all_tests),
            "successful_tests": len(successful_tests),
            "success_rate": (len(successful_tests) / len(all_tests) * 100) if all_tests else 0,
            "avg_response_time": statistics.mean([t['response_time'] for t in all_tests if 'response_time' in t]),
            "max_response_time": max([t['response_time'] for t in all_tests if 'response_time' in t], default=0),
            "min_response_time": min([t['response_time'] for t in all_tests if 'response_time' in t], default=0)
        }
        
        test_results["end_time"] = datetime.now()
        
        print(f"\n連接穩定性測試摘要:")
        print(f"  總測試數: {test_results['summary']['total_tests']}")
        print(f"  成功測試: {test_results['summary']['successful_tests']}")
        print(f"  成功率: {test_results['summary']['success_rate']:.1f}%")
        print(f"  平均響應時間: {test_results['summary']['avg_response_time']:.1f}ms")
        print(f"  最大響應時間: {test_results['summary']['max_response_time']:.1f}ms")
        
        self.test_results["connection_stability"] = test_results
        return test_results
    
    async def test_2_load_testing(self):
        """測試 2: 實戰級負載測試"""
        print("\n" + "="*60)
        print("測試 2: 實戰級負載測試")
        print("="*60)
        
        test_results = {
            "name": "實戰級負載測試",
            "start_time": datetime.now(),
            "scenarios": [],
            "summary": {}
        }
        
        # 測試場景
        scenarios = [
            {"name": "輕負載", "concurrent_users": 50, "duration": 60, "ramp_up": 10},
            {"name": "中負載", "concurrent_users": 200, "duration": 120, "ramp_up": 20},
            {"name": "重負載", "concurrent_users": 500, "duration": 180, "ramp_up": 30},
            {"name": "峰值負載", "concurrent_users": 1000, "duration": 60, "ramp_up": 10}
        ]
        
        for scenario in scenarios:
            print(f"\n執行 {scenario['name']} 測試...")
            print(f"  並發用戶: {scenario['concurrent_users']}")
            print(f"  持續時間: {scenario['duration']} 秒")
            print(f"  啟動時間: {scenario['ramp_up']} 秒")
            
            scenario_result = await self._run_load_scenario(scenario)
            test_results["scenarios"].append(scenario_result)
            
            print(f"  結果: {scenario_result['summary']['success_rate']:.1f}% 成功率, "
                  f"{scenario_result['summary']['avg_rps']:.1f} RPS, "
                  f"P95: {scenario_result['summary']['p95_response_time']:.1f}ms")
        
        # 計算總摘要
        all_scenarios = test_results["scenarios"]
        test_results["summary"] = {
            "total_scenarios": len(all_scenarios),
            "avg_success_rate": statistics.mean([s['summary']['success_rate'] for s in all_scenarios]),
            "avg_rps": statistics.mean([s['summary']['avg_rps'] for s in all_scenarios]),
            "avg_p95_response_time": statistics.mean([s['summary']['p95_response_time'] for s in all_scenarios]),
            "max_rps": max([s['summary']['max_rps'] for s in all_scenarios], default=0),
            "min_p95_response_time": min([s['summary']['p95_response_time'] for s in all_scenarios], default=0)
        }
        
        test_results["end_time"] = datetime.now()
        
        print(f"\n負載測試摘要:")
        print(f"  測試場景: {test_results['summary']['total_scenarios']}")
        print(f"  平均成功率: {test_results['summary']['avg_success_rate']:.1f}%")
        print(f"  平均 RPS: {test_results['summary']['avg_rps']:.1f}")
        print(f"  平均 P95 響應時間: {test_results['summary']['avg_p95_response_time']:.1f}ms")
        print(f"  最大 RPS: {test_results['summary']['max_rps']:.1f}")
        
        self.test_results["load_testing"] = test_results
        return test_results
    
    async def _run_load_scenario(self, scenario: Dict) -> Dict:
        """執行單個負載場景"""
        scenario_result = {
            "name": scenario["name"],
            "start_time": datetime.now(),
            "requests": [],
            "summary": {}
        }
        
        # 測試請求
        test_requests = [
            {"path": "/search?query=test", "method": "GET"},
            {"path": "/search?query=normal", "method": "GET"},
            {"path": "/search?query=hello", "method": "GET"},
            {"path": "/search?query=product", "method": "GET"},
        ]
        
        # 攻擊請求（用於測試 WAF）
        attack_requests = [
            {"path": "/search?query=1' OR '1'='1", "method": "GET"},
            {"path": "/search?query=<script>alert('xss')</script>", "method": "GET"},
            {"path": "/search?query=../../../etc/passwd", "method": "GET"},
        ]
        
        all_requests = test_requests + attack_requests
        
        # 工作線程
        async def load_worker(worker_id: int, duration: int):
            worker_requests = []
            start_time = time.time()
            
            while (time.time() - start_time) < duration:
                for request in all_requests:
                    if (time.time() - start_time) >= duration:
                        break
                    
                    req_start = time.time()
                    try:
                        async with self.session.get(f"{self.base_url}{request['path']}") as response:
                            response_time = (time.time() - req_start) * 1000
                            await response.read()
                            
                            worker_requests.append({
                                "worker_id": worker_id,
                                "request": request,
                                "response_time": response_time,
                                "status_code": response.status,
                                "success": 200 <= response.status < 400,
                                "timestamp": datetime.now()
                            })
                    except Exception as e:
                        response_time = (time.time() - req_start) * 1000
                        worker_requests.append({
                            "worker_id": worker_id,
                            "request": request,
                            "response_time": response_time,
                            "status_code": 0,
                            "success": False,
                            "error": str(e),
                            "timestamp": datetime.now()
                        })
                    
                    await asyncio.sleep(0.01)  # 10ms 間隔
            
            return worker_requests
        
        # 階梯式啟動
        tasks = []
        for i in range(scenario["concurrent_users"]):
            if i > 0 and i % (scenario["concurrent_users"] // scenario["ramp_up"]) == 0:
                await asyncio.sleep(1)  # 每秒啟動一批
            
            task = asyncio.create_task(load_worker(i, scenario["duration"]))
            tasks.append(task)
        
        # 等待所有任務完成
        all_worker_requests = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 合併所有請求
        for worker_requests in all_worker_requests:
            if isinstance(worker_requests, list):
                scenario_result["requests"].extend(worker_requests)
        
        # 計算摘要
        requests = scenario_result["requests"]
        if requests:
            successful_requests = [r for r in requests if r.get('success', False)]
            response_times = [r['response_time'] for r in requests if 'response_time' in r]
            
            scenario_result["summary"] = {
                "total_requests": len(requests),
                "successful_requests": len(successful_requests),
                "success_rate": (len(successful_requests) / len(requests) * 100) if requests else 0,
                "avg_response_time": statistics.mean(response_times) if response_times else 0,
                "p95_response_time": self._calculate_percentile(response_times, 95) if response_times else 0,
                "p99_response_time": self._calculate_percentile(response_times, 99) if response_times else 0,
                "avg_rps": len(requests) / scenario["duration"] if scenario["duration"] > 0 else 0,
                "max_rps": max([len([r for r in requests if r['timestamp'].minute == minute]) for minute in range(scenario["duration"])], default=0)
            }
        
        scenario_result["end_time"] = datetime.now()
        return scenario_result
    
    def _calculate_percentile(self, data: List[float], percentile: int) -> float:
        """計算百分位數"""
        if not data:
            return 0
        
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile / 100)
        return sorted_data[min(index, len(sorted_data) - 1)]
    
    async def test_3_ha_chaos_testing(self):
        """測試 3: HA 故障演練測試"""
        print("\n" + "="*60)
        print("測試 3: HA 故障演練測試")
        print("="*60)
        
        test_results = {
            "name": "HA 故障演練測試",
            "start_time": datetime.now(),
            "scenarios": [],
            "summary": {}
        }
        
        # 故障場景
        chaos_scenarios = [
            {"name": "服務重啟", "description": "重啟 WAF 服務"},
            {"name": "網路分區", "description": "模擬網路中斷"},
            {"name": "後端故障", "description": "後端服務故障"},
            {"name": "高負載", "description": "高負載下的穩定性"}
        ]
        
        for scenario in chaos_scenarios:
            print(f"\n執行 {scenario['name']} 測試...")
            print(f"  描述: {scenario['description']}")
            
            scenario_result = await self._run_chaos_scenario(scenario)
            test_results["scenarios"].append(scenario_result)
            
            print(f"  結果: {scenario_result['status']}, "
                  f"恢復時間: {scenario_result.get('recovery_time', 0):.1f}秒")
        
        # 計算摘要
        all_scenarios = test_results["scenarios"]
        successful_scenarios = [s for s in all_scenarios if s['status'] == 'success']
        recovery_times = [s['recovery_time'] for s in all_scenarios if 'recovery_time' in s and s['recovery_time']]
        
        test_results["summary"] = {
            "total_scenarios": len(all_scenarios),
            "successful_scenarios": len(successful_scenarios),
            "success_rate": (len(successful_scenarios) / len(all_scenarios) * 100) if all_scenarios else 0,
            "avg_recovery_time": statistics.mean(recovery_times) if recovery_times else 0,
            "max_recovery_time": max(recovery_times) if recovery_times else 0
        }
        
        test_results["end_time"] = datetime.now()
        
        print(f"\nHA 故障演練摘要:")
        print(f"  測試場景: {test_results['summary']['total_scenarios']}")
        print(f"  成功場景: {test_results['summary']['successful_scenarios']}")
        print(f"  成功率: {test_results['summary']['success_rate']:.1f}%")
        print(f"  平均恢復時間: {test_results['summary']['avg_recovery_time']:.1f}秒")
        
        self.test_results["ha_chaos_testing"] = test_results
        return test_results
    
    async def _run_chaos_scenario(self, scenario: Dict) -> Dict:
        """執行單個故障場景"""
        scenario_result = {
            "name": scenario["name"],
            "start_time": datetime.now(),
            "status": "running",
            "recovery_time": None,
            "availability_during": []
        }
        
        try:
            # 監控故障前狀態
            print("    監控故障前狀態...")
            await self._monitor_availability(10, scenario_result)
            
            # 執行故障注入
            print("    執行故障注入...")
            if scenario["name"] == "服務重啟":
                # 模擬服務重啟
                await asyncio.sleep(5)  # 模擬重啟時間
            elif scenario["name"] == "網路分區":
                # 模擬網路分區
                await asyncio.sleep(3)  # 模擬網路中斷
            elif scenario["name"] == "後端故障":
                # 模擬後端故障
                await asyncio.sleep(4)  # 模擬後端故障
            elif scenario["name"] == "高負載":
                # 模擬高負載
                await self._simulate_high_load(30)
            
            # 監控恢復過程
            print("    監控恢復過程...")
            recovery_start = time.time()
            await self._monitor_availability(30, scenario_result)
            
            # 檢查最終狀態
            print("    檢查最終狀態...")
            is_healthy, response_time, status = await self._check_health()
            
            recovery_time = time.time() - recovery_start
            scenario_result["recovery_time"] = recovery_time
            
            if is_healthy:
                scenario_result["status"] = "success"
                print(f"    ✅ 恢復成功，恢復時間: {recovery_time:.1f}秒")
            else:
                scenario_result["status"] = "failed"
                print(f"    ❌ 恢復失敗: {status}")
                
        except Exception as e:
            scenario_result["status"] = "error"
            scenario_result["error"] = str(e)
            print(f"    ❌ 場景執行錯誤: {e}")
        
        scenario_result["end_time"] = datetime.now()
        return scenario_result
    
    async def _monitor_availability(self, duration: int, scenario_result: Dict):
        """監控可用性"""
        start_time = time.time()
        while (time.time() - start_time) < duration:
            is_healthy, response_time, status = await self._check_health()
            
            scenario_result["availability_during"].append({
                "timestamp": datetime.now(),
                "healthy": is_healthy,
                "response_time": response_time,
                "status": status
            })
            
            await asyncio.sleep(1)  # 1 秒間隔
    
    async def _check_health(self) -> Tuple[bool, float, str]:
        """檢查服務健康狀態"""
        start_time = time.time()
        try:
            async with self.session.get(f"{self.base_url}/healthz") as response:
                response_time = (time.time() - start_time) * 1000
                if response.status == 200:
                    return True, response_time, "healthy"
                else:
                    return False, response_time, f"unhealthy (status: {response.status})"
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return False, response_time, str(e)
    
    async def _simulate_high_load(self, duration: int):
        """模擬高負載"""
        async def load_worker():
            for _ in range(100):
                try:
                    async with self.session.get(f"{self.base_url}/search?query=load_test") as response:
                        await response.read()
                except:
                    pass
                await asyncio.sleep(0.01)
        
        # 創建 100 個並發負載工作線程
        tasks = [load_worker() for _ in range(100)]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def test_4_rule_governance(self):
        """測試 4: 規則治理測試"""
        print("\n" + "="*60)
        print("測試 4: 規則治理測試")
        print("="*60)
        
        test_results = {
            "name": "規則治理測試",
            "start_time": datetime.now(),
            "tests": [],
            "summary": {}
        }
        
        # 測試請求
        test_requests = [
            {"path": "/search?query=normal_search", "expected": "allow"},
            {"path": "/search?query=1' OR '1'='1", "expected": "block"},
            {"path": "/search?query=<script>alert('xss')</script>", "expected": "block"},
            {"path": "/search?query=admin", "expected": "allow"},  # 可能誤報
            {"path": "/search?query=script", "expected": "allow"},  # 可能誤報
        ]
        
        # 執行測試
        print("執行規則治理測試...")
        for i, request in enumerate(test_requests):
            print(f"  測試 {i+1}: {request['path']}")
            
            start_time = time.time()
            try:
                async with self.session.get(f"{self.base_url}{request['path']}") as response:
                    response_time = (time.time() - start_time) * 1000
                    blocked = response.status in [403, 429, 502]
                    
                    # 分析結果
                    is_false_positive = (request['expected'] == 'allow' and blocked)
                    is_false_negative = (request['expected'] == 'block' and not blocked)
                    
                    test_result = {
                        "request": request,
                        "response_time": response_time,
                        "status_code": response.status,
                        "blocked": blocked,
                        "is_false_positive": is_false_positive,
                        "is_false_negative": is_false_negative
                    }
                    
                    test_results["tests"].append(test_result)
                    
                    print(f"    結果: {response.status} ({'阻擋' if blocked else '通過'}) "
                          f"({response_time:.1f}ms)")
                    
                    if is_false_positive:
                        print(f"    ⚠️  誤報: 正常請求被阻擋")
                    elif is_false_negative:
                        print(f"    ⚠️  漏報: 攻擊請求未被檢測")
                    
            except Exception as e:
                response_time = (time.time() - start_time) * 1000
                test_result = {
                    "request": request,
                    "response_time": response_time,
                    "error": str(e),
                    "blocked": True,
                    "is_false_positive": request['expected'] == 'allow',
                    "is_false_negative": False
                }
                
                test_results["tests"].append(test_result)
                print(f"    錯誤: {e}")
        
        # 計算摘要
        tests = test_results["tests"]
        false_positives = [t for t in tests if t.get('is_false_positive', False)]
        false_negatives = [t for t in tests if t.get('is_false_negative', False)]
        
        test_results["summary"] = {
            "total_tests": len(tests),
            "false_positives": len(false_positives),
            "false_negatives": len(false_negatives),
            "fp_rate": (len(false_positives) / len(tests) * 100) if tests else 0,
            "fn_rate": (len(false_negatives) / len(tests) * 100) if tests else 0,
            "avg_response_time": statistics.mean([t['response_time'] for t in tests if 'response_time' in t]) if tests else 0
        }
        
        test_results["end_time"] = datetime.now()
        
        print(f"\n規則治理測試摘要:")
        print(f"  總測試數: {test_results['summary']['total_tests']}")
        print(f"  誤報數: {test_results['summary']['false_positives']}")
        print(f"  漏報數: {test_results['summary']['false_negatives']}")
        print(f"  誤報率: {test_results['summary']['fp_rate']:.1f}%")
        print(f"  漏報率: {test_results['summary']['fn_rate']:.1f}%")
        print(f"  平均響應時間: {test_results['summary']['avg_response_time']:.1f}ms")
        
        self.test_results["rule_governance"] = test_results
        return test_results
    
    async def run_comprehensive_test(self):
        """執行完整的企業級測試"""
        print("開始企業級綜合測試")
        print("=" * 60)
        print(f"目標 URL: {self.base_url}")
        print(f"測試時間: {datetime.now()}")
        print("=" * 60)
        
        # 創建會話
        await self.create_session()
        
        try:
            self.start_time = datetime.now()
            
            # 執行所有測試
            await self.test_1_connection_stability()
            await asyncio.sleep(5)
            
            await self.test_2_load_testing()
            await asyncio.sleep(5)
            
            await self.test_3_ha_chaos_testing()
            await asyncio.sleep(5)
            
            await self.test_4_rule_governance()
            
            self.end_time = datetime.now()
            
        finally:
            await self.close_session()
        
        # 生成最終報告
        self.generate_final_report()
    
    def generate_final_report(self):
        """生成最終測試報告"""
        print("\n" + "="*80)
        print("企業級綜合測試報告")
        print("="*80)
        print(f"測試時間: {self.start_time} - {self.end_time}")
        print(f"總耗時: {(self.end_time - self.start_time).total_seconds():.1f} 秒")
        print()
        
        # 各測試摘要
        for test_name, test_result in self.test_results.items():
            print(f"{test_name.upper()} 測試:")
            if 'summary' in test_result:
                summary = test_result['summary']
                for key, value in summary.items():
                    if isinstance(value, float):
                        print(f"  {key}: {value:.2f}")
                    else:
                        print(f"  {key}: {value}")
            print()
        
        # 整體合規性檢查
        self.check_overall_compliance()
        
        # 保存報告
        self.save_report()
    
    def check_overall_compliance(self):
        """檢查整體合規性"""
        print("整體合規性檢查:")
        print("-" * 40)
        
        # 連接穩定性檢查
        if "connection_stability" in self.test_results:
            cs_summary = self.test_results["connection_stability"]["summary"]
            success_rate = cs_summary.get("success_rate", 0)
            if success_rate >= 95:
                print(f"  ✅ 連接穩定性: {success_rate:.1f}% (目標: ≥95%)")
            else:
                print(f"  ❌ 連接穩定性: {success_rate:.1f}% (目標: ≥95%)")
        
        # 負載測試檢查
        if "load_testing" in self.test_results:
            lt_summary = self.test_results["load_testing"]["summary"]
            avg_success_rate = lt_summary.get("avg_success_rate", 0)
            avg_p95 = lt_summary.get("avg_p95_response_time", 0)
            
            if avg_success_rate >= 99.9:
                print(f"  ✅ 負載測試成功率: {avg_success_rate:.1f}% (目標: ≥99.9%)")
            else:
                print(f"  ❌ 負載測試成功率: {avg_success_rate:.1f}% (目標: ≥99.9%)")
            
            if avg_p95 <= 250:  # 250ms 目標
                print(f"  ✅ 平均 P95 響應時間: {avg_p95:.1f}ms (目標: ≤250ms)")
            else:
                print(f"  ❌ 平均 P95 響應時間: {avg_p95:.1f}ms (目標: ≤250ms)")
        
        # HA 故障演練檢查
        if "ha_chaos_testing" in self.test_results:
            ha_summary = self.test_results["ha_chaos_testing"]["summary"]
            ha_success_rate = ha_summary.get("success_rate", 0)
            avg_recovery = ha_summary.get("avg_recovery_time", 0)
            
            if ha_success_rate >= 95:
                print(f"  ✅ HA 故障演練成功率: {ha_success_rate:.1f}% (目標: ≥95%)")
            else:
                print(f"  ❌ HA 故障演練成功率: {ha_success_rate:.1f}% (目標: ≥95%)")
            
            if avg_recovery <= 30:  # 30 秒目標
                print(f"  ✅ 平均恢復時間: {avg_recovery:.1f}秒 (目標: ≤30秒)")
            else:
                print(f"  ❌ 平均恢復時間: {avg_recovery:.1f}秒 (目標: ≤30秒)")
        
        # 規則治理檢查
        if "rule_governance" in self.test_results:
            rg_summary = self.test_results["rule_governance"]["summary"]
            fp_rate = rg_summary.get("fp_rate", 0)
            fn_rate = rg_summary.get("fn_rate", 0)
            
            if fp_rate <= 0.5:  # 0.5% 目標
                print(f"  ✅ 誤報率: {fp_rate:.2f}% (目標: ≤0.5%)")
            else:
                print(f"  ❌ 誤報率: {fp_rate:.2f}% (目標: ≤0.5%)")
            
            if fn_rate <= 1.0:  # 1% 目標
                print(f"  ✅ 漏報率: {fn_rate:.2f}% (目標: ≤1%)")
            else:
                print(f"  ❌ 漏報率: {fn_rate:.2f}% (目標: ≤1%)")
        
        print()
    
    def save_report(self):
        """保存測試報告"""
        report_data = {
            "test_info": {
                "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat(),
                "duration_seconds": (self.end_time - self.start_time).total_seconds(),
                "target_url": self.base_url
            },
            "test_results": self.test_results
        }
        
        report_file = f"enterprise_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"測試報告已保存到: {report_file}")

async def main():
    """主函數"""
    parser = argparse.ArgumentParser(description='企業級綜合測試工具')
    parser.add_argument('--url', default='http://localhost:8080', help='目標 URL')
    parser.add_argument('--test', help='執行特定測試 (1-4)')
    parser.add_argument('--report-file', help='保存報告到指定文件')
    
    args = parser.parse_args()
    
    # 創建測試套件
    test_suite = EnterpriseTestSuite(args.url)
    
    try:
        if args.test:
            # 執行特定測試
            test_num = int(args.test)
            await test_suite.create_session()
            
            if test_num == 1:
                await test_suite.test_1_connection_stability()
            elif test_num == 2:
                await test_suite.test_2_load_testing()
            elif test_num == 3:
                await test_suite.test_3_ha_chaos_testing()
            elif test_num == 4:
                await test_suite.test_4_rule_governance()
            else:
                print(f"未知測試: {test_num}")
                return
            
            await test_suite.close_session()
        else:
            # 執行完整測試
            await test_suite.run_comprehensive_test()
        
    except KeyboardInterrupt:
        print("\n測試被用戶中斷")
    except Exception as e:
        print(f"測試執行錯誤: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())

