#!/usr/bin/env python3
"""
企業級實戰壓測腳本
支援 HTTP/HTTPS 分流、階梯式負載、完整指標收集、規則開關 A/B 測試
"""

import asyncio
import aiohttp
import time
import statistics
import json
import argparse
import sys
import threading
import psutil
import os
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from collections import deque, defaultdict
import signal
import ssl

class LoadTestMetrics:
    """負載測試指標收集器 - 企業級版本"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.start_time = None
        self.end_time = None
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.response_times = deque(maxlen=10000)  # 保留最近 10000 個響應時間
        self.status_codes = defaultdict(int)
        self.errors = defaultdict(int)
        self.throughput_history = deque(maxlen=3600)  # 保留 1 小時的吞吐量歷史
        self.lock = threading.Lock()
        
        # 系統資源監控
        self.cpu_usage = deque(maxlen=3600)
        self.memory_usage = deque(maxlen=3600)
        self.disk_io = deque(maxlen=3600)
        self.network_io = deque(maxlen=3600)
        
        # 規則開關統計
        self.rules_enabled_stats = defaultdict(lambda: {'requests': 0, 'blocked': 0, 'response_times': deque(maxlen=1000)})
        self.rules_disabled_stats = defaultdict(lambda: {'requests': 0, 'blocked': 0, 'response_times': deque(maxlen=1000)})
    
    def record_request(self, response_time: float, status_code: int, error: str = None, 
                      rules_enabled: bool = True, request_type: str = "normal"):
        """記錄請求結果"""
        with self.lock:
            self.total_requests += 1
            self.response_times.append(response_time)
            
            if 200 <= status_code < 400:
                self.successful_requests += 1
            else:
                self.failed_requests += 1
            
            # 記錄狀態碼
            self.status_codes[status_code] += 1
            
            # 記錄錯誤
            if error:
                self.errors[error] += 1
            
            # 記錄規則開關統計
            stats_key = f"{request_type}_{'enabled' if rules_enabled else 'disabled'}"
            if rules_enabled:
                self.rules_enabled_stats[request_type]['requests'] += 1
                self.rules_enabled_stats[request_type]['response_times'].append(response_time)
                if status_code in [403, 429, 502]:
                    self.rules_enabled_stats[request_type]['blocked'] += 1
            else:
                self.rules_disabled_stats[request_type]['requests'] += 1
                self.rules_disabled_stats[request_type]['response_times'].append(response_time)
                if status_code in [403, 429, 502]:
                    self.rules_disabled_stats[request_type]['blocked'] += 1
    
    def record_system_metrics(self):
        """記錄系統資源指標"""
        with self.lock:
            self.cpu_usage.append(psutil.cpu_percent())
            self.memory_usage.append(psutil.virtual_memory().percent)
            
            # 磁碟 I/O
            disk_io = psutil.disk_io_counters()
            if disk_io:
                self.disk_io.append({
                    'read_bytes': disk_io.read_bytes,
                    'write_bytes': disk_io.write_bytes,
                    'read_count': disk_io.read_count,
                    'write_count': disk_io.write_count
                })
            
            # 網路 I/O
            net_io = psutil.net_io_counters()
            if net_io:
                self.network_io.append({
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv
                })
    
    def calculate_percentiles(self, times: List[float]) -> Dict[str, float]:
        """計算百分位數"""
        if not times:
            return {}
        
        sorted_times = sorted(times)
        n = len(sorted_times)
        
        return {
            'p50': sorted_times[int(n * 0.5)],
            'p90': sorted_times[int(n * 0.9)],
            'p95': sorted_times[int(n * 0.95)],
            'p99': sorted_times[int(n * 0.99)],
            'p99.9': sorted_times[int(n * 0.999)] if n > 1000 else sorted_times[-1]
        }
    
    def get_summary(self) -> Dict:
        """獲取測試摘要"""
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else 0
        rps = self.total_requests / duration if duration > 0 else 0
        
        # 計算響應時間統計
        response_times_list = list(self.response_times)
        percentiles = self.calculate_percentiles(response_times_list)
        
        # 計算系統資源統計
        cpu_stats = self._calculate_resource_stats(list(self.cpu_usage))
        memory_stats = self._calculate_resource_stats(list(self.memory_usage))
        
        # 計算規則開關對比
        rules_comparison = self._calculate_rules_comparison()
        
        return {
            "duration_seconds": duration,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0,
            "requests_per_second": rps,
            "response_times": {
                "mean": statistics.mean(response_times_list) if response_times_list else 0,
                "median": statistics.median(response_times_list) if response_times_list else 0,
                "min": min(response_times_list) if response_times_list else 0,
                "max": max(response_times_list) if response_times_list else 0,
                **percentiles
            },
            "status_codes": dict(self.status_codes),
            "errors": dict(self.errors),
            "system_resources": {
                "cpu": cpu_stats,
                "memory": memory_stats
            },
            "rules_comparison": rules_comparison
        }
    
    def _calculate_resource_stats(self, data: List[float]) -> Dict:
        """計算資源統計"""
        if not data:
            return {}
        
        return {
            "avg": statistics.mean(data),
            "max": max(data),
            "min": min(data),
            "p95": self.calculate_percentiles(data).get('p95', 0)
        }
    
    def _calculate_rules_comparison(self) -> Dict:
        """計算規則開關對比"""
        comparison = {}
        
        for request_type in set(list(self.rules_enabled_stats.keys()) + list(self.rules_disabled_stats.keys())):
            enabled_stats = self.rules_enabled_stats[request_type]
            disabled_stats = self.rules_disabled_stats[request_type]
            
            if enabled_stats['requests'] > 0 and disabled_stats['requests'] > 0:
                enabled_avg_time = statistics.mean(list(enabled_stats['response_times'])) if enabled_stats['response_times'] else 0
                disabled_avg_time = statistics.mean(list(disabled_stats['response_times'])) if disabled_stats['response_times'] else 0
                
                comparison[request_type] = {
                    "enabled": {
                        "requests": enabled_stats['requests'],
                        "blocked": enabled_stats['blocked'],
                        "block_rate": (enabled_stats['blocked'] / enabled_stats['requests'] * 100) if enabled_stats['requests'] > 0 else 0,
                        "avg_response_time": enabled_avg_time
                    },
                    "disabled": {
                        "requests": disabled_stats['requests'],
                        "blocked": disabled_stats['blocked'],
                        "block_rate": (disabled_stats['blocked'] / disabled_stats['requests'] * 100) if disabled_stats['requests'] > 0 else 0,
                        "avg_response_time": disabled_avg_time
                    },
                    "performance_impact": enabled_avg_time - disabled_avg_time
                }
        
        return comparison

class EnterpriseLoadTester:
    """企業級負載測試器"""
    
    def __init__(self, base_url: str, use_https: bool = False):
        self.base_url = base_url.rstrip('/')
        self.use_https = use_https
        self.metrics = LoadTestMetrics()
        self.running = False
        self.session = None
        
        # 測試場景
        self.normal_scenarios = [
            {"path": "/search?query=test", "method": "GET", "type": "normal"},
            {"path": "/search?query=normal_search", "method": "GET", "type": "normal"},
            {"path": "/search?query=hello_world", "method": "GET", "type": "normal"},
            {"path": "/search?query=product_info", "method": "GET", "type": "normal"},
            {"path": "/search?query=user_data", "method": "GET", "type": "normal"},
        ]
        
        # 攻擊場景
        self.attack_scenarios = [
            {"path": "/search?query=1' OR '1'='1", "method": "GET", "type": "sql_injection"},
            {"path": "/search?query=<script>alert('xss')</script>", "method": "GET", "type": "xss"},
            {"path": "/search?query=../../../etc/passwd", "method": "GET", "type": "path_traversal"},
            {"path": "/search?query=; cat /etc/passwd", "method": "GET", "type": "command_injection"},
            {"path": "/search?query=UNION SELECT * FROM users", "method": "GET", "type": "sql_injection"},
        ]
        
        # 邊界案例
        self.edge_scenarios = [
            {"path": "/search?query=admin", "method": "GET", "type": "edge_case"},
            {"path": "/search?query=script", "method": "GET", "type": "edge_case"},
            {"path": "/search?query=select", "method": "GET", "type": "edge_case"},
            {"path": "/search?query=union", "method": "GET", "type": "edge_case"},
            {"path": "/search?query=or", "method": "GET", "type": "edge_case"},
        ]
    
    async def create_session(self):
        """創建 HTTP 會話"""
        if self.use_https:
            # 為自簽名證書創建 SSL 上下文
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        else:
            ssl_context = False
            
        connector = aiohttp.TCPConnector(
            limit=2000,  # 總連接池大小
            limit_per_host=200,  # 每個主機的連接數
            ttl_dns_cache=300,  # DNS 緩存時間
            use_dns_cache=True,
            keepalive_timeout=60,  # keep-alive 超時
            enable_cleanup_closed=True,
            force_close=False,
            ssl=ssl_context
        )
        
        timeout = aiohttp.ClientTimeout(
            total=30,  # 總超時
            connect=10,  # 連接超時
            sock_read=20  # 讀取超時
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'EnterpriseLoadTester/2.0'}
        )
    
    async def close_session(self):
        """關閉 HTTP 會話"""
        if self.session:
            await self.session.close()
    
    async def make_request(self, scenario: Dict, rules_enabled: bool = True) -> Tuple[float, int, str]:
        """發送單個請求"""
        start_time = time.time()
        status_code = 0
        error = None
        
        try:
            url = f"{self.base_url}{scenario['path']}"
            
            # 添加規則開關標頭
            headers = {}
            if not rules_enabled:
                headers['X-WAF-Disabled'] = 'true'
            
            async with self.session.request(
                scenario['method'],
                url,
                headers=headers,
                allow_redirects=False
            ) as response:
                status_code = response.status
                await response.read()  # 讀取響應體
                
        except asyncio.TimeoutError:
            error = "timeout"
        except aiohttp.ClientError as e:
            error = f"client_error: {str(e)}"
        except Exception as e:
            error = f"unknown_error: {str(e)}"
        
        response_time = (time.time() - start_time) * 1000  # 轉換為毫秒
        return response_time, status_code, error
    
    async def worker(self, worker_id: int, scenarios: List[Dict], duration: int, 
                    rules_enabled: bool = True, burst_mode: bool = False):
        """工作線程"""
        print(f"Worker {worker_id} started (rules: {'enabled' if rules_enabled else 'disabled'})")
        
        start_time = time.time()
        request_count = 0
        
        while self.running and (time.time() - start_time) < duration:
            for scenario in scenarios:
                if not self.running or (time.time() - start_time) >= duration:
                    break
                
                # 突發模式：短時間內發送大量請求
                if burst_mode and request_count % 100 == 0:
                    # 突發 10 個請求
                    for _ in range(10):
                        response_time, status_code, error = await self.make_request(scenario, rules_enabled)
                        self.metrics.record_request(
                            response_time, status_code, error, 
                            rules_enabled, scenario['type']
                        )
                        request_count += 1
                else:
                    response_time, status_code, error = await self.make_request(scenario, rules_enabled)
                    self.metrics.record_request(
                        response_time, status_code, error, 
                        rules_enabled, scenario['type']
                    )
                    request_count += 1
                
                # 正常間隔
                if not burst_mode:
                    await asyncio.sleep(0.01)  # 10ms 間隔
        
        print(f"Worker {worker_id} finished ({request_count} requests)")
    
    async def run_load_test(self, 
                          concurrent_users: int = 100,
                          duration: int = 60,
                          ramp_up: int = 10,
                          include_attacks: bool = False,
                          rules_ab_test: bool = False,
                          burst_test: bool = False):
        """執行負載測試"""
        print(f"Starting enterprise load test:")
        print(f"  - Base URL: {self.base_url}")
        print(f"  - Protocol: {'HTTPS' if self.use_https else 'HTTP'}")
        print(f"  - Concurrent Users: {concurrent_users}")
        print(f"  - Duration: {duration} seconds")
        print(f"  - Ramp Up: {ramp_up} seconds")
        print(f"  - Include Attacks: {include_attacks}")
        print(f"  - Rules A/B Test: {rules_ab_test}")
        print(f"  - Burst Test: {burst_test}")
        print()
        
        # 準備測試場景
        scenarios = self.normal_scenarios.copy()
        if include_attacks:
            scenarios.extend(self.attack_scenarios)
            scenarios.extend(self.edge_scenarios)
        
        # 創建會話
        await self.create_session()
        
        try:
            # 設置信號處理
            self.running = True
            self.metrics.start_time = datetime.now()
            
            # 啟動系統監控
            monitor_task = asyncio.create_task(self._system_monitor())
            
            # 創建任務
            tasks = []
            
            if rules_ab_test:
                # A/B 測試：一半用戶規則開啟，一半關閉
                half_users = concurrent_users // 2
                
                # 規則開啟的用戶
                for i in range(half_users):
                    if i > 0 and i % (half_users // ramp_up) == 0:
                        await asyncio.sleep(1)
                    
                    task = asyncio.create_task(
                        self.worker(i, scenarios, duration, rules_enabled=True, burst_mode=burst_test)
                    )
                    tasks.append(task)
                
                # 規則關閉的用戶
                for i in range(half_users, concurrent_users):
                    if i > half_users and (i - half_users) % (half_users // ramp_up) == 0:
                        await asyncio.sleep(1)
                    
                    task = asyncio.create_task(
                        self.worker(i, scenarios, duration, rules_enabled=False, burst_mode=burst_test)
                    )
                    tasks.append(task)
            else:
                # 正常測試：所有用戶使用相同配置
                for i in range(concurrent_users):
                    if i > 0 and i % (concurrent_users // ramp_up) == 0:
                        await asyncio.sleep(1)
                    
                    task = asyncio.create_task(
                        self.worker(i, scenarios, duration, rules_enabled=True, burst_mode=burst_test)
                    )
                    tasks.append(task)
            
            # 等待測試完成
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # 停止系統監控
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
            
        finally:
            self.running = False
            self.metrics.end_time = datetime.now()
            await self.close_session()
    
    async def _system_monitor(self):
        """系統資源監控"""
        while self.running:
            self.metrics.record_system_metrics()
            await asyncio.sleep(1)  # 每秒記錄一次
    
    def print_real_time_stats(self, interval: int = 5):
        """實時統計信息"""
        while self.running:
            time.sleep(interval)
            
            if self.metrics.total_requests > 0:
                duration = (datetime.now() - self.metrics.start_time).total_seconds()
                rps = self.metrics.total_requests / duration if duration > 0 else 0
                
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"Requests: {self.metrics.total_requests}, "
                      f"RPS: {rps:.1f}, "
                      f"Success: {self.metrics.successful_requests}, "
                      f"Failed: {self.metrics.failed_requests}")
    
    def generate_report(self, test_name: str = "Enterprise Load Test"):
        """生成測試報告"""
        summary = self.metrics.get_summary()
        
        print(f"\n{'='*80}")
        print(f"{test_name} - 企業級測試報告")
        print(f"{'='*80}")
        print(f"測試時間: {self.metrics.start_time} - {self.metrics.end_time}")
        print(f"持續時間: {summary['duration_seconds']:.1f} 秒")
        print(f"協議: {'HTTPS' if self.use_https else 'HTTP'}")
        print()
        
        print("請求統計:")
        print(f"  總請求數: {summary['total_requests']:,}")
        print(f"  成功請求: {summary['successful_requests']:,}")
        print(f"  失敗請求: {summary['failed_requests']:,}")
        print(f"  成功率: {summary['success_rate']:.2f}%")
        print(f"  平均 RPS: {summary['requests_per_second']:.1f}")
        print()
        
        print("響應時間 (毫秒):")
        rt = summary['response_times']
        print(f"  平均: {rt['mean']:.1f}")
        print(f"  中位數: {rt['median']:.1f}")
        print(f"  最小值: {rt['min']:.1f}")
        print(f"  最大值: {rt['max']:.1f}")
        print(f"  P50: {rt['p50']:.1f}")
        print(f"  P90: {rt['p90']:.1f}")
        print(f"  P95: {rt['p95']:.1f}")
        print(f"  P99: {rt['p99']:.1f}")
        print(f"  P99.9: {rt['p99.9']:.1f}")
        print()
        
        print("狀態碼分布:")
        for code, count in sorted(summary['status_codes'].items()):
            percentage = (count / summary['total_requests'] * 100) if summary['total_requests'] > 0 else 0
            print(f"  {code}: {count:,} ({percentage:.1f}%)")
        print()
        
        if summary['errors']:
            print("錯誤分布:")
            for error, count in summary['errors'].items():
                percentage = (count / summary['total_requests'] * 100) if summary['total_requests'] > 0 else 0
                print(f"  {error}: {count:,} ({percentage:.1f}%)")
            print()
        
        # 系統資源統計
        print("系統資源使用:")
        cpu_stats = summary['system_resources']['cpu']
        memory_stats = summary['system_resources']['memory']
        print(f"  CPU: 平均 {cpu_stats['avg']:.1f}%, 最大 {cpu_stats['max']:.1f}%, P95 {cpu_stats['p95']:.1f}%")
        print(f"  記憶體: 平均 {memory_stats['avg']:.1f}%, 最大 {memory_stats['max']:.1f}%, P95 {memory_stats['p95']:.1f}%")
        print()
        
        # 規則開關對比
        if summary['rules_comparison']:
            print("規則開關對比 (A/B 測試):")
            for request_type, comparison in summary['rules_comparison'].items():
                print(f"  {request_type}:")
                print(f"    規則開啟: {comparison['enabled']['requests']} 請求, "
                      f"{comparison['enabled']['block_rate']:.1f}% 阻擋率, "
                      f"{comparison['enabled']['avg_response_time']:.1f}ms 平均響應時間")
                print(f"    規則關閉: {comparison['disabled']['requests']} 請求, "
                      f"{comparison['disabled']['block_rate']:.1f}% 阻擋率, "
                      f"{comparison['disabled']['avg_response_time']:.1f}ms 平均響應時間")
                print(f"    效能影響: {comparison['performance_impact']:.1f}ms")
            print()
        
        # 企業級 SLA 檢查
        self.check_enterprise_sla(summary)
        
        return summary
    
    def check_enterprise_sla(self, summary: Dict):
        """檢查企業級 SLA 合規性"""
        print("企業級 SLA 合規性檢查:")
        
        # 可用性檢查 (99.9%)
        success_rate = summary['success_rate']
        if success_rate >= 99.9:
            print(f"  [OK] 可用性: {success_rate:.2f}% (目標: ≥99.9%)")
        else:
            print(f"  [FAIL] 可用性: {success_rate:.2f}% (目標: ≥99.9%)")
        
        # 響應時間檢查
        rt = summary['response_times']
        p95 = rt['p95']
        
        if self.use_https:
            # HTTPS 目標: P95 < 250ms
            if p95 < 250:
                print(f"  [OK] HTTPS P95: {p95:.1f}ms (目標: <250ms)")
            else:
                print(f"  [FAIL] HTTPS P95: {p95:.1f}ms (目標: <250ms)")
        else:
            # HTTP 目標: P95 < 150ms
            if p95 < 150:
                print(f"  [OK] HTTP P95: {p95:.1f}ms (目標: <150ms)")
            else:
                print(f"  [FAIL] HTTP P95: {p95:.1f}ms (目標: <150ms)")
        
        # 錯誤率檢查 (<0.1%)
        error_rate = 100 - success_rate
        if error_rate < 0.1:
            print(f"  [OK] 錯誤率: {error_rate:.3f}% (目標: <0.1%)")
        else:
            print(f"  [FAIL] 錯誤率: {error_rate:.3f}% (目標: <0.1%)")
        
        # 系統資源檢查
        cpu_p95 = summary['system_resources']['cpu']['p95']
        memory_p95 = summary['system_resources']['memory']['p95']
        
        if cpu_p95 < 80:
            print(f"  [OK] CPU P95: {cpu_p95:.1f}% (目標: <80%)")
        else:
            print(f"  [FAIL] CPU P95: {cpu_p95:.1f}% (目標: <80%)")
        
        if memory_p95 < 90:
            print(f"  [OK] 記憶體 P95: {memory_p95:.1f}% (目標: <90%)")
        else:
            print(f"  [FAIL] 記憶體 P95: {memory_p95:.1f}% (目標: <90%)")
        
        print()

async def main():
    """主函數"""
    parser = argparse.ArgumentParser(description='企業級負載測試工具')
    parser.add_argument('--url', default='http://localhost:8080', help='目標 URL')
    parser.add_argument('--users', type=int, default=100, help='並發用戶數')
    parser.add_argument('--duration', type=int, default=60, help='測試持續時間（秒）')
    parser.add_argument('--ramp-up', type=int, default=10, help='啟動時間（秒）')
    parser.add_argument('--attacks', action='store_true', help='包含攻擊測試')
    parser.add_argument('--https', action='store_true', help='使用 HTTPS')
    parser.add_argument('--rules-ab', action='store_true', help='規則開關 A/B 測試')
    parser.add_argument('--burst', action='store_true', help='突發測試模式')
    parser.add_argument('--report-file', help='保存報告到文件')
    
    args = parser.parse_args()
    
    # 創建測試器
    tester = EnterpriseLoadTester(args.url, args.https)
    
    # 啟動實時統計
    stats_thread = threading.Thread(
        target=tester.print_real_time_stats,
        daemon=True
    )
    stats_thread.start()
    
    try:
        # 執行測試
        await tester.run_load_test(
            concurrent_users=args.users,
            duration=args.duration,
            ramp_up=args.ramp_up,
            include_attacks=args.attacks,
            rules_ab_test=args.rules_ab,
            burst_test=args.burst
        )
        
        # 生成報告
        summary = tester.generate_report(f"企業級負載測試 ({args.users} 用戶, {args.duration}秒)")
        
        # 保存報告
        if args.report_file:
            with open(args.report_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            print(f"報告已保存到: {args.report_file}")
        
    except KeyboardInterrupt:
        print("\n測試被用戶中斷")
    except Exception as e:
        print(f"測試執行錯誤: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
