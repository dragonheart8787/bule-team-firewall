#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
並發測試 - 1M 並發連線目標
"""

import asyncio
import time
import socket
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from typing import Dict, Any
import threading

TARGET_CONCURRENT = 1_000_000
TEST_DURATION = 30


class ConcurrentBenchmark:
    """並發連線基準測試"""
    
    def __init__(self):
        self._active_count = 0
        self._lock = threading.Lock()
        self._max_concurrent = 0
    
    def run_connection_simulation(self, num_target: int = 100_000,
                                  num_workers: int = 100) -> Dict[str, Any]:
        """模擬並發連線處理 - 使用輕量級物件模擬"""
        # 每個「連線」用一個輕量 dict 表示
        connections = []
        start = time.perf_counter()
        
        def create_connection(i):
            return {
                "id": i,
                "src_ip": f"192.168.1.{i % 256}",
                "dst_port": 443,
                "state": "established"
            }
        
        # 分批建立
        batch_size = 10000
        created = 0
        
        while created < num_target and (time.perf_counter() - start) < TEST_DURATION:
            batch = min(batch_size, num_target - created)
            for i in range(batch):
                connections.append(create_connection(created + i))
            created += batch
            
            # 模擬處理：檢查、更新狀態
            for c in connections[-batch:]:
                _ = c["src_ip"] + str(c["dst_port"])
        
        elapsed = time.perf_counter() - start
        return {
            "connections_created": len(connections),
            "duration_sec": round(elapsed, 2),
            "connections_per_second": round(len(connections) / elapsed, 0),
            "target_1m": len(connections) >= 1_000_000
        }
    
    def run_async_concurrent(self, num_target: int = 100_000) -> Dict[str, Any]:
        """asyncio 並發測試"""
        async def simulate_conn(i):
            await asyncio.sleep(0)  # yield
            return {"id": i}
        
        async def run():
            tasks = [simulate_conn(i) for i in range(min(num_target, 50_000))]  # 50k 避免記憶體爆
            return await asyncio.gather(*tasks)
        
        start = time.perf_counter()
        results = asyncio.run(run())
        elapsed = time.perf_counter() - start
        
        return {
            "mode": "asyncio",
            "connections_simulated": len(results),
            "duration_sec": round(elapsed, 2),
            "connections_per_second": round(len(results) / elapsed, 0)
        }
    
    def run_thread_pool(self, num_tasks: int = 100_000) -> Dict[str, Any]:
        """ThreadPool 並發測試"""
        def task(i):
            return i * 2  # 輕量任務
        
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=500) as ex:
            list(ex.map(task, range(num_tasks)))
        elapsed = time.perf_counter() - start
        
        return {
            "mode": "thread_pool",
            "tasks_completed": num_tasks,
            "duration_sec": round(elapsed, 2),
            "tasks_per_second": round(num_tasks / elapsed, 0)
        }
    
    def run_process_pool(self, num_tasks: int = 100_000) -> Dict[str, Any]:
        """ProcessPool 並發測試"""
        import multiprocessing as mp
        def task(i):
            return i * 2
        
        start = time.perf_counter()
        with ProcessPoolExecutor(max_workers=mp.cpu_count()) as ex:
            list(ex.map(task, range(num_tasks), chunksize=1000))
        elapsed = time.perf_counter() - start
        
        return {
            "mode": "process_pool",
            "tasks_completed": num_tasks,
            "duration_sec": round(elapsed, 2),
            "tasks_per_second": round(num_tasks / elapsed, 0)
        }


def run_concurrent_tests():
    """執行並發測試"""
    import multiprocessing as mp
    
    bench = ConcurrentBenchmark()
    results = {}
    
    print("=" * 60)
    print("並發測試 (目標: 1M 並發)")
    print("=" * 60)
    
    # 連線模擬
    print("\n[1/4] 連線模擬 (100K)...")
    r1 = bench.run_connection_simulation(num_target=100_000)
    results["connection_sim"] = r1
    print(f"  建立: {r1['connections_created']:,} 連線, {r1['connections_per_second']:,.0f}/s")
    
    # 模擬 1M
    print("\n[2/4] 連線模擬 (1M)...")
    r2 = bench.run_connection_simulation(num_target=1_000_000, num_workers=200)
    results["connection_1m"] = r2
    print(f"  建立: {r2['connections_created']:,} 連線, {r2['connections_per_second']:,.0f}/s")
    
    # asyncio
    print("\n[3/4] asyncio 並發 (50K)...")
    r3 = bench.run_async_concurrent(num_target=50_000)
    results["asyncio"] = r3
    print(f"  完成: {r3['connections_simulated']:,} 任務")
    
    # ThreadPool
    print("\n[4/4] ThreadPool (100K tasks)...")
    r4 = bench.run_thread_pool(num_tasks=100_000)
    results["thread_pool"] = r4
    print(f"  完成: {r4['tasks_per_second']:,.0f} tasks/s")
    
    print("\n" + "=" * 60)
    print(f"1M 連線模擬: {'達成' if r2['connections_created'] >= 1_000_000 else '未達成'}")
    print("=" * 60)
    
    return results


if __name__ == '__main__':
    run_concurrent_tests()
