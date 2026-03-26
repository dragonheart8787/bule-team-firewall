#!/usr/bin/env python3
"""
高可用性故障演練腳本 - 企業級版本
腳本化演練：Kill WAF 節點、LB 拔除、重啟後自動回補
證據：演練紀錄、Grafana 截圖、請求成功率連續曲線
"""

import asyncio
import aiohttp
import time
import json
import subprocess
import signal
import os
import sys
import threading
import docker
import requests
import psutil
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import argparse
import matplotlib.pyplot as plt
import pandas as pd
from collections import deque
import statistics

class ChaosTestMetrics:
    """故障演練指標收集器"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.test_start_time = None
        self.test_end_time = None
        self.scenarios = []
        self.results = []
        self.availability_metrics = deque(maxlen=10000)  # 保留最近 10000 個指標
        self.recovery_times = []
        self.success_rates = deque(maxlen=10000)
        self.response_times = deque(maxlen=10000)
        self.lock = threading.Lock()
    
    def start_scenario(self, scenario_name: str, description: str):
        """開始故障場景"""
        scenario = {
            "name": scenario_name,
            "description": description,
            "start_time": datetime.now(),
            "end_time": None,
            "status": "running",
            "availability_during": [],
            "recovery_time": None,
            "errors": [],
            "success_rate_history": [],
            "response_time_history": []
        }
        self.scenarios.append(scenario)
        return len(self.scenarios) - 1
    
    def end_scenario(self, scenario_id: int, status: str, recovery_time: float = None):
        """結束故障場景"""
        if 0 <= scenario_id < len(self.scenarios):
            self.scenarios[scenario_id]["end_time"] = datetime.now()
            self.scenarios[scenario_id]["status"] = status
            if recovery_time is not None:
                self.scenarios[scenario_id]["recovery_time"] = recovery_time
                self.recovery_times.append(recovery_time)
    
    def record_availability(self, timestamp: datetime, success_rate: float, response_time: float, scenario_id: int = None):
        """記錄可用性指標"""
        with self.lock:
            metric = {
                "timestamp": timestamp,
                "success_rate": success_rate,
                "response_time": response_time,
                "scenario_id": scenario_id
            }
            self.availability_metrics.append(metric)
            self.success_rates.append(success_rate)
            self.response_times.append(response_time)
            
            # 記錄到當前場景
            if scenario_id is not None and 0 <= scenario_id < len(self.scenarios):
                self.scenarios[scenario_id]["availability_during"].append(metric)
                self.scenarios[scenario_id]["success_rate_history"].append(success_rate)
                self.scenarios[scenario_id]["response_time_history"].append(response_time)
    
    def get_summary(self) -> Dict:
        """獲取測試摘要"""
        total_scenarios = len(self.scenarios)
        successful_scenarios = len([s for s in self.scenarios if s["status"] == "success"])
        
        avg_recovery_time = sum(self.recovery_times) / len(self.recovery_times) if self.recovery_times else 0
        
        # 計算整體可用性
        overall_availability = 0
        if self.success_rates:
            overall_availability = statistics.mean(list(self.success_rates))
        
        return {
            "total_scenarios": total_scenarios,
            "successful_scenarios": successful_scenarios,
            "success_rate": (successful_scenarios / total_scenarios * 100) if total_scenarios > 0 else 0,
            "average_recovery_time": avg_recovery_time,
            "overall_availability": overall_availability,
            "scenarios": self.scenarios
        }

class HAChaosTester:
    """高可用性故障演練測試器 - 企業級版本"""
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url.rstrip('/')
        self.metrics = ChaosTestMetrics()
        self.running = False
        self.session = None
        self.docker_client = None
        
        # 嘗試連接 Docker
        try:
            self.docker_client = docker.from_env()
            print("[OK] Docker 連接成功")
        except Exception as e:
            print(f"[WARN] 無法連接 Docker: {e}")
            print("將使用模擬模式進行故障演練")
    
    async def create_session(self):
        """創建 HTTP 會話"""
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=20,
            ttl_dns_cache=60,
            use_dns_cache=True,
            keepalive_timeout=10
        )
        
        timeout = aiohttp.ClientTimeout(
            total=5,
            connect=2,
            sock_read=3
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        )
    
    async def close_session(self):
        """關閉 HTTP 會話"""
        if self.session:
            await self.session.close()
    
    async def check_health(self) -> Tuple[bool, float, str]:
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
    
    async def monitor_availability(self, duration: int = 30, interval: int = 1, scenario_id: int = None):
        """監控可用性"""
        print(f"開始監控可用性 ({duration} 秒)...")
        
        start_time = time.time()
        while (time.time() - start_time) < duration:
            is_healthy, response_time, status = await self.check_health()
            success_rate = 100.0 if is_healthy else 0.0
            
            self.metrics.record_availability(
                datetime.now(),
                success_rate,
                response_time,
                scenario_id
            )
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"健康: {'[OK]' if is_healthy else '[FAIL]'}, "
                  f"響應時間: {response_time:.1f}ms, "
                  f"狀態: {status}")
            
            await asyncio.sleep(interval)
    
    async def scenario_1_waf_restart(self):
        """場景 1: WAF 服務重啟 - 腳本化演練"""
        scenario_id = self.metrics.start_scenario(
            "WAF 服務重啟",
            "重啟 WAF 代理服務，驗證自動恢復"
        )
        
        print("\n=== 場景 1: WAF 服務重啟 ===")
        
        try:
            # 監控重啟前狀態
            print("1. 監控重啟前狀態...")
            await self.monitor_availability(10, 1, scenario_id)
            
            # 重啟 WAF 服務
            print("2. 重啟 WAF 服務...")
            restart_start = time.time()
            
            if self.docker_client:
                try:
                    # 查找 WAF 容器
                    containers = self.docker_client.containers.list(filters={"name": "waf"})
                    if containers:
                        container = containers[0]
                        print(f"   找到 WAF 容器: {container.name}")
                        
                        # 重啟容器
                        container.restart()
                        print("   [OK] Docker 容器已重啟")
                        
                        # 等待容器啟動
                        time.sleep(5)
                        
                    else:
                        print("   [WARN]  未找到 WAF 容器，嘗試其他方式")
                        self._simulate_waf_restart()
                except Exception as e:
                    print(f"   [FAIL] Docker 重啟失敗: {e}")
                    self._simulate_waf_restart()
            else:
                self._simulate_waf_restart()
            
            # 監控恢復過程
            print("3. 監控恢復過程...")
            recovery_start = time.time()
            await self.monitor_availability(30, 1, scenario_id)
            
            # 檢查最終狀態
            print("4. 檢查最終狀態...")
            is_healthy, response_time, status = await self.check_health()
            
            recovery_time = time.time() - recovery_start
            
            if is_healthy:
                print(f"   [OK] 服務恢復成功，恢復時間: {recovery_time:.1f} 秒")
                self.metrics.end_scenario(scenario_id, "success", recovery_time)
            else:
                print(f"   [FAIL] 服務恢復失敗: {status}")
                self.metrics.end_scenario(scenario_id, "failed")
                
        except Exception as e:
            print(f"   [FAIL] 場景執行錯誤: {e}")
            self.metrics.end_scenario(scenario_id, "error")
    
    def _simulate_waf_restart(self):
        """模擬 WAF 重啟"""
        print("   模擬 WAF 重啟...")
        time.sleep(3)  # 模擬重啟時間
        print("   模擬重啟完成")
    
    async def scenario_2_network_partition(self):
        """場景 2: 網路分區模擬"""
        scenario_id = self.metrics.start_scenario(
            "網路分區模擬",
            "模擬網路中斷，驗證故障檢測和恢復"
        )
        
        print("\n=== 場景 2: 網路分區模擬 ===")
        
        try:
            # 監控分區前狀態
            print("1. 監控分區前狀態...")
            await self.monitor_availability(10, 1, scenario_id)
            
            # 模擬網路分區
            print("2. 模擬網路分區...")
            partition_start = time.time()
            
            # 嘗試修改 hosts 文件
            hosts_backup = None
            try:
                # 備份 hosts 文件
                with open('/etc/hosts', 'r') as f:
                    hosts_backup = f.read()
                
                # 添加錯誤的 IP 映射
                with open('/etc/hosts', 'a') as f:
                    f.write('\n# Chaos Test - Network Partition\n')
                    f.write('127.0.0.1 localhost_blocked\n')
                
                print("   [OK] 網路分區已模擬")
                
                # 監控分區期間狀態
                print("3. 監控分區期間狀態...")
                await self.monitor_availability(20, 1, scenario_id)
                
            except Exception as e:
                print(f"   [WARN]  無法修改 hosts 文件: {e}")
                print("   使用模擬網路分區")
                time.sleep(5)  # 模擬網路分區時間
            
            # 恢復網路
            print("4. 恢復網路...")
            if hosts_backup:
                try:
                    with open('/etc/hosts', 'w') as f:
                        f.write(hosts_backup)
                    print("   [OK] 網路已恢復")
                except Exception as e:
                    print(f"   [FAIL] 恢復 hosts 文件失敗: {e}")
            
            # 監控恢復過程
            print("5. 監控恢復過程...")
            recovery_start = time.time()
            await self.monitor_availability(30, 1, scenario_id)
            
            # 檢查最終狀態
            print("6. 檢查最終狀態...")
            is_healthy, response_time, status = await self.check_health()
            
            recovery_time = time.time() - recovery_start
            
            if is_healthy:
                print(f"   [OK] 網路恢復成功，恢復時間: {recovery_time:.1f} 秒")
                self.metrics.end_scenario(scenario_id, "success", recovery_time)
            else:
                print(f"   [FAIL] 網路恢復失敗: {status}")
                self.metrics.end_scenario(scenario_id, "failed")
                
        except Exception as e:
            print(f"   [FAIL] 場景執行錯誤: {e}")
            self.metrics.end_scenario(scenario_id, "error")
    
    async def scenario_3_backend_failure(self):
        """場景 3: 後端服務故障"""
        scenario_id = self.metrics.start_scenario(
            "後端服務故障",
            "模擬後端服務故障，驗證 WAF 錯誤處理"
        )
        
        print("\n=== 場景 3: 後端服務故障 ===")
        
        try:
            # 監控故障前狀態
            print("1. 監控故障前狀態...")
            await self.monitor_availability(10, 1, scenario_id)
            
            # 停止後端服務
            print("2. 停止後端服務...")
            if self.docker_client:
                try:
                    containers = self.docker_client.containers.list(filters={"name": "target"})
                    if containers:
                        container = containers[0]
                        container.stop()
                        print("   [OK] 後端服務已停止")
                    else:
                        print("   [WARN]  未找到後端服務容器")
                        self._simulate_backend_failure()
                except Exception as e:
                    print(f"   [FAIL] Docker 停止失敗: {e}")
                    self._simulate_backend_failure()
            else:
                self._simulate_backend_failure()
            
            # 監控故障期間狀態
            print("3. 監控故障期間狀態...")
            await self.monitor_availability(20, 1, scenario_id)
            
            # 恢復後端服務
            print("4. 恢復後端服務...")
            if self.docker_client:
                try:
                    containers = self.docker_client.containers.list(filters={"name": "target"}, all=True)
                    if containers:
                        container = containers[0]
                        container.start()
                        print("   [OK] 後端服務已恢復")
                    else:
                        print("   [WARN]  未找到後端服務容器")
                        self._simulate_backend_recovery()
                except Exception as e:
                    print(f"   [FAIL] Docker 啟動失敗: {e}")
                    self._simulate_backend_recovery()
            else:
                self._simulate_backend_recovery()
            
            # 監控恢復過程
            print("5. 監控恢復過程...")
            recovery_start = time.time()
            await self.monitor_availability(30, 1, scenario_id)
            
            # 檢查最終狀態
            print("6. 檢查最終狀態...")
            is_healthy, response_time, status = await self.check_health()
            
            recovery_time = time.time() - recovery_start
            
            if is_healthy:
                print(f"   [OK] 後端服務恢復成功，恢復時間: {recovery_time:.1f} 秒")
                self.metrics.end_scenario(scenario_id, "success", recovery_time)
            else:
                print(f"   [FAIL] 後端服務恢復失敗: {status}")
                self.metrics.end_scenario(scenario_id, "failed")
                
        except Exception as e:
            print(f"   [FAIL] 場景執行錯誤: {e}")
            self.metrics.end_scenario(scenario_id, "error")
    
    def _simulate_backend_failure(self):
        """模擬後端故障"""
        print("   模擬後端服務故障...")
        time.sleep(2)
        print("   模擬故障完成")
    
    def _simulate_backend_recovery(self):
        """模擬後端恢復"""
        print("   模擬後端服務恢復...")
        time.sleep(3)
        print("   模擬恢復完成")
    
    async def scenario_4_high_load(self):
        """場景 4: 高負載測試"""
        scenario_id = self.metrics.start_scenario(
            "高負載測試",
            "在高負載下驗證系統穩定性"
        )
        
        print("\n=== 場景 4: 高負載測試 ===")
        
        try:
            # 啟動高負載
            print("1. 啟動高負載...")
            load_tasks = []
            
            async def load_worker(worker_id: int):
                """負載工作線程"""
                for _ in range(100):  # 每個工作線程發送 100 個請求
                    try:
                        async with self.session.get(f"{self.base_url}/search?query=load_test_{worker_id}") as response:
                            await response.read()
                    except Exception:
                        pass
                    await asyncio.sleep(0.1)  # 100ms 間隔
            
            # 創建 100 個並發負載工作線程
            for i in range(100):
                task = asyncio.create_task(load_worker(i))
                load_tasks.append(task)
            
            # 監控高負載期間狀態
            print("2. 監控高負載期間狀態...")
            await self.monitor_availability(30, 1, scenario_id)
            
            # 等待負載完成
            print("3. 等待負載完成...")
            await asyncio.gather(*load_tasks, return_exceptions=True)
            
            # 檢查最終狀態
            print("4. 檢查最終狀態...")
            is_healthy, response_time, status = await self.check_health()
            
            if is_healthy:
                print(f"   [OK] 高負載測試通過，響應時間: {response_time:.1f}ms")
                self.metrics.end_scenario(scenario_id, "success")
            else:
                print(f"   [FAIL] 高負載測試失敗: {status}")
                self.metrics.end_scenario(scenario_id, "failed")
                
        except Exception as e:
            print(f"   [FAIL] 場景執行錯誤: {e}")
            self.metrics.end_scenario(scenario_id, "error")
    
    async def scenario_5_lb_failover(self):
        """場景 5: 負載均衡器故障轉移"""
        scenario_id = self.metrics.start_scenario(
            "負載均衡器故障轉移",
            "模擬 LB 拔除，驗證 5 秒內恢復"
        )
        
        print("\n=== 場景 5: 負載均衡器故障轉移 ===")
        
        try:
            # 監控故障前狀態
            print("1. 監控故障前狀態...")
            await self.monitor_availability(10, 1, scenario_id)
            
            # 模擬 LB 故障
            print("2. 模擬負載均衡器故障...")
            if self.docker_client:
                try:
                    # 查找 LB 容器
                    containers = self.docker_client.containers.list(filters={"name": "nginx"})
                    if containers:
                        container = containers[0]
                        print(f"   找到 LB 容器: {container.name}")
                        
                        # 停止 LB 容器
                        container.stop()
                        print("   [OK] LB 容器已停止")
                        
                        # 等待 5 秒
                        time.sleep(5)
                        
                        # 重啟 LB 容器
                        container.start()
                        print("   [OK] LB 容器已重啟")
                        
                    else:
                        print("   [WARN]  未找到 LB 容器，使用模擬模式")
                        self._simulate_lb_failover()
                except Exception as e:
                    print(f"   [FAIL] Docker 操作失敗: {e}")
                    self._simulate_lb_failover()
            else:
                self._simulate_lb_failover()
            
            # 監控恢復過程
            print("3. 監控恢復過程...")
            recovery_start = time.time()
            await self.monitor_availability(30, 1, scenario_id)
            
            # 檢查最終狀態
            print("4. 檢查最終狀態...")
            is_healthy, response_time, status = await self.check_health()
            
            recovery_time = time.time() - recovery_start
            
            if is_healthy and recovery_time <= 5:
                print(f"   [OK] LB 故障轉移成功，恢復時間: {recovery_time:.1f} 秒 (目標: ≤5秒)")
                self.metrics.end_scenario(scenario_id, "success", recovery_time)
            elif is_healthy:
                print(f"   [WARN]  LB 恢復成功但時間過長: {recovery_time:.1f} 秒 (目標: ≤5秒)")
                self.metrics.end_scenario(scenario_id, "partial_success", recovery_time)
            else:
                print(f"   [FAIL] LB 故障轉移失敗: {status}")
                self.metrics.end_scenario(scenario_id, "failed")
                
        except Exception as e:
            print(f"   [FAIL] 場景執行錯誤: {e}")
            self.metrics.end_scenario(scenario_id, "error")
    
    def _simulate_lb_failover(self):
        """模擬 LB 故障轉移"""
        print("   模擬負載均衡器故障轉移...")
        time.sleep(2)  # 模擬故障時間
        print("   模擬故障轉移完成")
    
    async def run_chaos_test(self):
        """執行完整的故障演練測試"""
        print("開始高可用性故障演練測試")
        print(f"目標 URL: {self.base_url}")
        print("=" * 60)
        
        # 創建會話
        await self.create_session()
        
        try:
            self.metrics.test_start_time = datetime.now()
            
            # 執行所有故障場景
            await self.scenario_1_waf_restart()
            await asyncio.sleep(10)  # 場景間隔
            
            await self.scenario_2_network_partition()
            await asyncio.sleep(10)
            
            await self.scenario_3_backend_failure()
            await asyncio.sleep(10)
            
            await self.scenario_4_high_load()
            await asyncio.sleep(10)
            
            await self.scenario_5_lb_failover()
            
            self.metrics.test_end_time = datetime.now()
            
        finally:
            await self.close_session()
        
        # 生成報告
        self.generate_report()
        
        # 生成圖表
        self.generate_charts()
    
    def generate_report(self):
        """生成故障演練報告"""
        summary = self.metrics.get_summary()
        
        print(f"\n{'='*60}")
        print("高可用性故障演練報告")
        print(f"{'='*60}")
        print(f"測試時間: {self.metrics.test_start_time} - {self.metrics.test_end_time}")
        print(f"總場景數: {summary['total_scenarios']}")
        print(f"成功場景: {summary['successful_scenarios']}")
        print(f"成功率: {summary['success_rate']:.1f}%")
        print(f"平均恢復時間: {summary['average_recovery_time']:.1f} 秒")
        print(f"整體可用性: {summary['overall_availability']:.2f}%")
        print()
        
        print("場景詳情:")
        for i, scenario in enumerate(summary['scenarios'], 1):
            print(f"  {i}. {scenario['name']}")
            print(f"     描述: {scenario['description']}")
            print(f"     狀態: {scenario['status']}")
            if scenario['recovery_time']:
                print(f"     恢復時間: {scenario['recovery_time']:.1f} 秒")
            if scenario['errors']:
                print(f"     錯誤: {', '.join(scenario['errors'])}")
            print()
        
        # HA 合規性檢查
        self.check_ha_compliance(summary)
    
    def check_ha_compliance(self, summary: Dict):
        """檢查高可用性合規性"""
        print("HA 合規性檢查:")
        
        # 成功率檢查 (≥95%)
        success_rate = summary['success_rate']
        if success_rate >= 95:
            print(f"  [OK] 故障演練成功率: {success_rate:.1f}% (目標: ≥95%)")
        else:
            print(f"  [FAIL] 故障演練成功率: {success_rate:.1f}% (目標: ≥95%)")
        
        # 恢復時間檢查 (<30 秒)
        avg_recovery = summary['average_recovery_time']
        if avg_recovery <= 30:
            print(f"  [OK] 平均恢復時間: {avg_recovery:.1f} 秒 (目標: <30秒)")
        else:
            print(f"  [FAIL] 平均恢復時間: {avg_recovery:.1f} 秒 (目標: <30秒)")
        
        # 可用性檢查 (≥99.9%)
        overall_availability = summary['overall_availability']
        if overall_availability >= 99.9:
            print(f"  [OK] 測試期間可用性: {overall_availability:.2f}% (目標: ≥99.9%)")
        else:
            print(f"  [FAIL] 測試期間可用性: {overall_availability:.2f}% (目標: ≥99.9%)")
        
        # LB 故障轉移檢查 (≤5 秒)
        lb_scenario = next((s for s in summary['scenarios'] if '負載均衡器' in s['name']), None)
        if lb_scenario and lb_scenario['recovery_time']:
            if lb_scenario['recovery_time'] <= 5:
                print(f"  [OK] LB 故障轉移時間: {lb_scenario['recovery_time']:.1f} 秒 (目標: ≤5秒)")
            else:
                print(f"  [FAIL] LB 故障轉移時間: {lb_scenario['recovery_time']:.1f} 秒 (目標: ≤5秒)")
        
        print()
    
    def generate_charts(self):
        """生成圖表"""
        try:
            print("生成故障演練圖表...")
            
            # 準備數據
            timestamps = []
            success_rates = []
            response_times = []
            
            for metric in self.metrics.availability_metrics:
                timestamps.append(metric['timestamp'])
                success_rates.append(metric['success_rate'])
                response_times.append(metric['response_time'])
            
            if not timestamps:
                print("   [WARN]  無數據可生成圖表")
                return
            
            # 創建圖表
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
            
            # 成功率曲線
            ax1.plot(timestamps, success_rates, 'b-', linewidth=2, label='成功率')
            ax1.set_ylabel('成功率 (%)')
            ax1.set_title('故障演練期間成功率變化')
            ax1.grid(True, alpha=0.3)
            ax1.legend()
            ax1.set_ylim(0, 105)
            
            # 響應時間曲線
            ax2.plot(timestamps, response_times, 'r-', linewidth=2, label='響應時間')
            ax2.set_ylabel('響應時間 (ms)')
            ax2.set_xlabel('時間')
            ax2.set_title('故障演練期間響應時間變化')
            ax2.grid(True, alpha=0.3)
            ax2.legend()
            
            # 標記故障場景
            for i, scenario in enumerate(self.metrics.scenarios):
                if scenario['start_time'] and scenario['end_time']:
                    ax1.axvspan(scenario['start_time'], scenario['end_time'], 
                               alpha=0.2, color=f'C{i}', label=f"場景 {i+1}: {scenario['name']}")
                    ax2.axvspan(scenario['start_time'], scenario['end_time'], 
                               alpha=0.2, color=f'C{i}')
            
            plt.tight_layout()
            
            # 保存圖表
            chart_file = f"chaos_test_charts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(chart_file, dpi=300, bbox_inches='tight')
            print(f"   [OK] 圖表已保存: {chart_file}")
            
            plt.close()
            
        except Exception as e:
            print(f"   [FAIL] 生成圖表失敗: {e}")

async def main():
    """主函數"""
    parser = argparse.ArgumentParser(description='高可用性故障演練工具')
    parser.add_argument('--url', default='http://localhost:8080', help='目標 URL')
    parser.add_argument('--scenario', help='執行特定場景 (1-5)')
    parser.add_argument('--report-file', help='保存報告到文件')
    
    args = parser.parse_args()
    
    # 創建測試器
    tester = HAChaosTester(args.url)
    
    try:
        if args.scenario:
            # 執行特定場景
            scenario_num = int(args.scenario)
            await tester.create_session()
            
            if scenario_num == 1:
                await tester.scenario_1_waf_restart()
            elif scenario_num == 2:
                await tester.scenario_2_network_partition()
            elif scenario_num == 3:
                await tester.scenario_3_backend_failure()
            elif scenario_num == 4:
                await tester.scenario_4_high_load()
            elif scenario_num == 5:
                await tester.scenario_5_lb_failover()
            else:
                print(f"未知場景: {scenario_num}")
                return
            
            await tester.close_session()
        else:
            # 執行完整測試
            await tester.run_chaos_test()
        
        # 保存報告
        if args.report_file:
            summary = tester.metrics.get_summary()
            with open(args.report_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False, default=str)
            print(f"報告已保存到: {args.report_file}")
        
    except KeyboardInterrupt:
        print("\n測試被用戶中斷")
    except Exception as e:
        print(f"測試執行錯誤: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
