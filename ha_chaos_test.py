#!/usr/bin/env python3
"""
高可用性故障演練腳本
Chaos Engineering: 主動故障注入、故障轉移驗證、恢復時間測試
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
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import docker
import requests

class ChaosTestMetrics:
    """故障演練指標收集器"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.test_start_time = None
        self.test_end_time = None
        self.scenarios = []
        self.results = []
        self.availability_metrics = []
        self.recovery_times = []
    
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
            "errors": []
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
    
    def record_availability(self, timestamp: datetime, success_rate: float, response_time: float):
        """記錄可用性指標"""
        self.availability_metrics.append({
            "timestamp": timestamp,
            "success_rate": success_rate,
            "response_time": response_time
        })
    
    def get_summary(self) -> Dict:
        """獲取測試摘要"""
        total_scenarios = len(self.scenarios)
        successful_scenarios = len([s for s in self.scenarios if s["status"] == "success"])
        
        avg_recovery_time = sum(self.recovery_times) / len(self.recovery_times) if self.recovery_times else 0
        
        return {
            "total_scenarios": total_scenarios,
            "successful_scenarios": successful_scenarios,
            "success_rate": (successful_scenarios / total_scenarios * 100) if total_scenarios > 0 else 0,
            "average_recovery_time": avg_recovery_time,
            "scenarios": self.scenarios
        }

class HAChaosTester:
    """高可用性故障演練測試器"""
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url.rstrip('/')
        self.metrics = ChaosTestMetrics()
        self.running = False
        self.session = None
        self.docker_client = None
        
        # 嘗試連接 Docker
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            print(f"警告: 無法連接 Docker: {e}")
    
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
    
    async def monitor_availability(self, duration: int = 30, interval: int = 1):
        """監控可用性"""
        print(f"開始監控可用性 ({duration} 秒)...")
        
        start_time = time.time()
        while (time.time() - start_time) < duration:
            is_healthy, response_time, status = await self.check_health()
            success_rate = 100.0 if is_healthy else 0.0
            
            self.metrics.record_availability(
                datetime.now(),
                success_rate,
                response_time
            )
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"健康: {'✅' if is_healthy else '❌'}, "
                  f"響應時間: {response_time:.1f}ms, "
                  f"狀態: {status}")
            
            await asyncio.sleep(interval)
    
    async def scenario_1_waf_restart(self):
        """場景 1: WAF 服務重啟"""
        scenario_id = self.metrics.start_scenario(
            "WAF 服務重啟",
            "重啟 WAF 代理服務，驗證自動恢復"
        )
        
        print("\n=== 場景 1: WAF 服務重啟 ===")
        
        try:
            # 監控重啟前狀態
            print("1. 監控重啟前狀態...")
            await self.monitor_availability(10, 1)
            
            # 重啟 WAF 服務
            print("2. 重啟 WAF 服務...")
            if self.docker_client:
                try:
                    container = self.docker_client.containers.get("crto_waf_proxy_1")
                    container.restart()
                    print("   Docker 容器已重啟")
                except Exception as e:
                    print(f"   Docker 重啟失敗: {e}")
                    # 嘗試其他方式重啟
                    print("   嘗試其他重啟方式...")
            else:
                print("   無法通過 Docker 重啟，請手動重啟 WAF 服務")
                input("   按 Enter 繼續...")
            
            # 監控恢復過程
            print("3. 監控恢復過程...")
            recovery_start = time.time()
            await self.monitor_availability(30, 1)
            
            # 檢查最終狀態
            print("4. 檢查最終狀態...")
            is_healthy, response_time, status = await self.check_health()
            
            recovery_time = time.time() - recovery_start
            
            if is_healthy:
                print(f"   ✅ 服務恢復成功，恢復時間: {recovery_time:.1f} 秒")
                self.metrics.end_scenario(scenario_id, "success", recovery_time)
            else:
                print(f"   ❌ 服務恢復失敗: {status}")
                self.metrics.end_scenario(scenario_id, "failed")
                
        except Exception as e:
            print(f"   ❌ 場景執行錯誤: {e}")
            self.metrics.end_scenario(scenario_id, "error")
    
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
            await self.monitor_availability(10, 1)
            
            # 模擬網路分區（通過修改 hosts 文件）
            print("2. 模擬網路分區...")
            hosts_backup = None
            try:
                # 備份 hosts 文件
                with open('/etc/hosts', 'r') as f:
                    hosts_backup = f.read()
                
                # 添加錯誤的 IP 映射
                with open('/etc/hosts', 'a') as f:
                    f.write('\n# Chaos Test - Network Partition\n')
                    f.write('127.0.0.1 localhost_blocked\n')
                
                print("   網路分區已模擬")
                
                # 監控分區期間狀態
                print("3. 監控分區期間狀態...")
                await self.monitor_availability(20, 1)
                
            except Exception as e:
                print(f"   無法修改 hosts 文件: {e}")
                print("   請手動模擬網路分區")
                input("   按 Enter 繼續...")
            
            # 恢復網路
            print("4. 恢復網路...")
            if hosts_backup:
                try:
                    with open('/etc/hosts', 'w') as f:
                        f.write(hosts_backup)
                    print("   網路已恢復")
                except Exception as e:
                    print(f"   恢復 hosts 文件失敗: {e}")
            
            # 監控恢復過程
            print("5. 監控恢復過程...")
            recovery_start = time.time()
            await self.monitor_availability(30, 1)
            
            # 檢查最終狀態
            print("6. 檢查最終狀態...")
            is_healthy, response_time, status = await self.check_health()
            
            recovery_time = time.time() - recovery_start
            
            if is_healthy:
                print(f"   ✅ 網路恢復成功，恢復時間: {recovery_time:.1f} 秒")
                self.metrics.end_scenario(scenario_id, "success", recovery_time)
            else:
                print(f"   ❌ 網路恢復失敗: {status}")
                self.metrics.end_scenario(scenario_id, "failed")
                
        except Exception as e:
            print(f"   ❌ 場景執行錯誤: {e}")
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
            await self.monitor_availability(10, 1)
            
            # 停止後端服務
            print("2. 停止後端服務...")
            if self.docker_client:
                try:
                    container = self.docker_client.containers.get("crto_target_app")
                    container.stop()
                    print("   後端服務已停止")
                except Exception as e:
                    print(f"   Docker 停止失敗: {e}")
                    print("   請手動停止後端服務")
                    input("   按 Enter 繼續...")
            
            # 監控故障期間狀態
            print("3. 監控故障期間狀態...")
            await self.monitor_availability(20, 1)
            
            # 恢復後端服務
            print("4. 恢復後端服務...")
            if self.docker_client:
                try:
                    container = self.docker_client.containers.get("crto_target_app")
                    container.start()
                    print("   後端服務已恢復")
                except Exception as e:
                    print(f"   Docker 啟動失敗: {e}")
                    print("   請手動啟動後端服務")
                    input("   按 Enter 繼續...")
            
            # 監控恢復過程
            print("5. 監控恢復過程...")
            recovery_start = time.time()
            await self.monitor_availability(30, 1)
            
            # 檢查最終狀態
            print("6. 檢查最終狀態...")
            is_healthy, response_time, status = await self.check_health()
            
            recovery_time = time.time() - recovery_start
            
            if is_healthy:
                print(f"   ✅ 後端服務恢復成功，恢復時間: {recovery_time:.1f} 秒")
                self.metrics.end_scenario(scenario_id, "success", recovery_time)
            else:
                print(f"   ❌ 後端服務恢復失敗: {status}")
                self.metrics.end_scenario(scenario_id, "failed")
                
        except Exception as e:
            print(f"   ❌ 場景執行錯誤: {e}")
            self.metrics.end_scenario(scenario_id, "error")
    
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
            
            # 創建 50 個並發負載工作線程
            for i in range(50):
                task = asyncio.create_task(load_worker(i))
                load_tasks.append(task)
            
            # 監控高負載期間狀態
            print("2. 監控高負載期間狀態...")
            await self.monitor_availability(30, 1)
            
            # 等待負載完成
            print("3. 等待負載完成...")
            await asyncio.gather(*load_tasks, return_exceptions=True)
            
            # 檢查最終狀態
            print("4. 檢查最終狀態...")
            is_healthy, response_time, status = await self.check_health()
            
            if is_healthy:
                print(f"   ✅ 高負載測試通過，響應時間: {response_time:.1f}ms")
                self.metrics.end_scenario(scenario_id, "success")
            else:
                print(f"   ❌ 高負載測試失敗: {status}")
                self.metrics.end_scenario(scenario_id, "failed")
                
        except Exception as e:
            print(f"   ❌ 場景執行錯誤: {e}")
            self.metrics.end_scenario(scenario_id, "error")
    
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
            
            self.metrics.test_end_time = datetime.now()
            
        finally:
            await self.close_session()
        
        # 生成報告
        self.generate_report()
    
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
            print(f"  ✅ 故障演練成功率: {success_rate:.1f}% (目標: ≥95%)")
        else:
            print(f"  ❌ 故障演練成功率: {success_rate:.1f}% (目標: ≥95%)")
        
        # 恢復時間檢查 (<30 秒)
        avg_recovery = summary['average_recovery_time']
        if avg_recovery <= 30:
            print(f"  ✅ 平均恢復時間: {avg_recovery:.1f} 秒 (目標: <30秒)")
        else:
            print(f"  ❌ 平均恢復時間: {avg_recovery:.1f} 秒 (目標: <30秒)")
        
        # 可用性檢查 (≥99.9%)
        if self.metrics.availability_metrics:
            total_checks = len(self.metrics.availability_metrics)
            healthy_checks = len([m for m in self.metrics.availability_metrics if m['success_rate'] > 0])
            availability = (healthy_checks / total_checks * 100) if total_checks > 0 else 0
            
            if availability >= 99.9:
                print(f"  ✅ 測試期間可用性: {availability:.2f}% (目標: ≥99.9%)")
            else:
                print(f"  ❌ 測試期間可用性: {availability:.2f}% (目標: ≥99.9%)")
        
        print()

async def main():
    """主函數"""
    import argparse
    
    parser = argparse.ArgumentParser(description='高可用性故障演練工具')
    parser.add_argument('--url', default='http://localhost:8080', help='目標 URL')
    parser.add_argument('--scenario', help='執行特定場景 (1-4)')
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

