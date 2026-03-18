#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
吞吐量實測 - 10 Gbps 目標
模擬高吞吐封包處理能力測試
"""

import time
import multiprocessing as mp
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from typing import Dict, Any
from collections import deque
import threading


# 10 Gbps = 1.25 GB/s = 1,250,000,000 bytes/s
# 假設平均封包 1500 bytes (MTU) => ~833,333 pps
# 假設平均封包 64 bytes (最小) => ~19,531,250 pps
TARGET_GBPS = 10
TARGET_MBPS = TARGET_GBPS * 1000
BYTES_PER_PACKET = 1500  # 模擬 MTU
TARGET_PPS = (TARGET_MBPS * 1_000_000 / 8) // BYTES_PER_PACKET  # ~833,333 pps


def _worker_process_packets(args: tuple) -> tuple:
    """模擬封包處理 - 模組級函數以支援 pickle, args=(packet_size, count)"""
    packet_size, count = args
    processed = 0
    bytes_done = 0
    fake_payload = b'x' * min(packet_size, 1500)
    for _ in range(count):
        _ = fake_payload.decode('utf-8', errors='replace')
        processed += 1
        bytes_done += packet_size
    return processed, bytes_done


class ThroughputBenchmark:
    """吞吐量基準測試"""
    
    def __init__(self, duration_sec: int = 10, num_workers: int = None):
        self.duration_sec = duration_sec
        self.num_workers = num_workers or max(1, mp.cpu_count() - 1)
        self._processed = mp.Value('L', 0)
        self._bytes_processed = mp.Value('L', 0)
        self._running = mp.Value('b', False)
    
    def run_single_thread(self, target_pps: int = 100_000) -> Dict[str, Any]:
        """單執行緒吞吐量測試"""
        packet_size = BYTES_PER_PACKET
        total_target = target_pps * self.duration_sec
        batch_size = min(10000, total_target // 10)
        
        start = time.perf_counter()
        processed = 0
        bytes_processed = 0
        
        while (time.perf_counter() - start) < self.duration_sec and processed < total_target:
            batch = min(batch_size, total_target - processed)
            for _ in range(batch):
                # 模擬封包處理
                _ = (b'x' * packet_size).decode('utf-8', errors='replace')
                processed += 1
                bytes_processed += packet_size
        
        elapsed = time.perf_counter() - start
        pps = processed / elapsed if elapsed > 0 else 0
        bps = bytes_processed / elapsed if elapsed > 0 else 0
        gbps = (bps * 8) / 1_000_000_000
        
        return {
            "mode": "single_thread",
            "duration_sec": elapsed,
            "packets_processed": processed,
            "bytes_processed": bytes_processed,
            "packets_per_second": round(pps, 0),
            "bytes_per_second": round(bps, 0),
            "gbps": round(gbps, 2),
            "target_10gbps_achieved": gbps >= 10
        }
    
    def run_multi_thread(self, num_threads: int = 8, target_pps: int = 500_000) -> Dict[str, Any]:
        """多執行緒吞吐量測試"""
        packet_size = BYTES_PER_PACKET
        total_target = target_pps * self.duration_sec
        per_thread = total_target // num_threads
        
        def worker():
            processed = 0
            bytes_done = 0
            end_time = time.perf_counter() + self.duration_sec
            while time.perf_counter() < end_time and processed < per_thread:
                _ = (b'x' * packet_size).decode('utf-8', errors='replace')
                processed += 1
                bytes_done += packet_size
            return processed, bytes_done
        
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=num_threads) as ex:
            futures = [ex.submit(worker) for _ in range(num_threads)]
            results = [f.result() for f in futures]
        
        total_pkts = sum(r[0] for r in results)
        total_bytes = sum(r[1] for r in results)
        elapsed = time.perf_counter() - start
        
        return {
            "mode": "multi_thread",
            "num_threads": num_threads,
            "duration_sec": round(elapsed, 2),
            "packets_processed": total_pkts,
            "bytes_processed": total_bytes,
            "packets_per_second": round(total_pkts / elapsed, 0),
            "gbps": round((total_bytes * 8 / elapsed) / 1_000_000_000, 2),
            "target_10gbps_achieved": (total_bytes * 8 / elapsed) >= 10_000_000_000
        }
    
    def run_multi_process(self, num_processes: int = 8) -> Dict[str, Any]:
        """多進程吞吐量測試 - 突破 GIL"""
        packet_size = BYTES_PER_PACKET
        per_process = int((TARGET_PPS * self.duration_sec) // num_processes)
        
        start = time.perf_counter()
        args_list = [(packet_size, per_process)] * num_processes
        with ProcessPoolExecutor(max_workers=num_processes) as ex:
            results = list(ex.map(_worker_process_packets, args_list))
        
        total_pkts = sum(r[0] for r in results)
        total_bytes = sum(r[1] for r in results)
        elapsed = time.perf_counter() - start
        
        return {
            "mode": "multi_process",
            "num_processes": num_processes,
            "duration_sec": round(elapsed, 2),
            "packets_processed": total_pkts,
            "bytes_processed": total_bytes,
            "packets_per_second": round(total_pkts / elapsed, 0),
            "gbps": round((total_bytes * 8 / elapsed) / 1_000_000_000, 2),
            "target_10gbps_achieved": (total_bytes * 8 / elapsed) >= 10_000_000_000
        }


def run_all_throughput_tests(duration: int = 5) -> Dict[str, Any]:
    """執行所有吞吐量測試"""
    results = {}
    bench = ThroughputBenchmark(duration_sec=duration)
    
    print("=" * 60)
    print("吞吐量實測 (目標: 10 Gbps)")
    print("=" * 60)
    
    # 單執行緒
    print("\n[1/3] 單執行緒測試...")
    r1 = bench.run_single_thread(target_pps=100_000)
    results["single_thread"] = r1
    print(f"  結果: {r1['packets_per_second']:,.0f} pps, {r1['gbps']} Gbps")
    
    # 多執行緒
    print("\n[2/3] 多執行緒測試 (8 threads)...")
    r2 = bench.run_multi_thread(num_threads=8, target_pps=500_000)
    results["multi_thread"] = r2
    print(f"  結果: {r2['packets_per_second']:,.0f} pps, {r2['gbps']} Gbps")
    
    # 多進程
    print("\n[3/3] 多進程測試 (8 processes)...")
    r3 = bench.run_multi_process(num_processes=8)
    results["multi_process"] = r3
    print(f"  結果: {r3['packets_per_second']:,.0f} pps, {r3['gbps']} Gbps")
    
    print("\n" + "=" * 60)
    best = max(r1['gbps'], r2['gbps'], r3['gbps'])
    print(f"最佳吞吐量: {best} Gbps")
    print(f"10 Gbps 達成: {'是' if best >= 10 else '否 (需 Go/C 高效能模組)'}")
    print("=" * 60)
    
    return results


if __name__ == '__main__':
    run_all_throughput_tests(duration=5)
