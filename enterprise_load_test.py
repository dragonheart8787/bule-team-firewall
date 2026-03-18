#!/usr/bin/env python3
"""
企業級負載測試腳本
實戰級壓測：HTTP/HTTPS 分流、階梯式負載、長時間穩定性測試
"""

import asyncio
import aiohttp
import time
import statistics
import json
import argparse
import sys
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import threading
import signal
import os

class LoadTestMetrics:
    """負載測試指標收集器"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.start_time = None
        self.end_time = None
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.response_times = []
        self.status_codes = {}
        self.errors = {}
        self.throughput_history = []
        self.lock = threading.Lock()
    
    def record_request(self, response_time: float, status_code: int, error: str = None):
        """記錄請求結果"""
        with self.lock:
            self.total_requests += 1
            self.response_times.append(response_time)
            
            if 200 <= status_code < 400:
                self.successful_requests += 1
            else:
                self.failed_requests += 1
            
            # 記錄狀態碼
            if status_code not in self.status_codes:
                self.status_codes[status_code] = 0
            self.status_codes[status_code] += 1
            
            # 記錄錯誤
            if error:
                if error not in self.errors:
                    self.errors[error] = 0
                self.errors[error] += 1
    
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
        if not self.response_times:
            return {"error": "No data collected"}
        
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else 0
        rps = self.total_requests / duration if duration > 0 else 0
        
        return {
            "duration_seconds": duration,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0,
            "requests_per_second": rps,
            "response_times": {
                "mean": statistics.mean(self.response_times),
                "median": statistics.median(self.response_times),
                "min": min(self.response_times),
                "max": max(self.response_times),
                **self.calculate_percentiles(self.response_times)
            },
            "status_codes": self.status_codes,
            "errors": self.errors
        }

class EnterpriseLoadTester:
    """企業級負載測試器"""
    
    def __init__(self, base_url: str, use_https: bool = False):
        self.base_url = base_url.rstrip('/')
        self.use_https = use_https
        self.metrics = LoadTestMetrics()
        self.running = False
        self.session = None
        
        # 測試場景
        self.test_scenarios = [
            {"path": "/search?query=test", "method": "GET"},
            {"path": "/search?query=normal_search", "method": "GET"},
            {"path": "/search?query=hello_world", "method": "GET"},
            {"path": "/search?query=product_info", "method": "GET"},
            {"path": "/search?query=user_data", "method": "GET"},
        ]
        
        # 攻擊場景（用於測試 WAF 規則）
        self.attack_scenarios = [
            {"path": "/search?query=1' OR '1'='1", "method": "GET"},
            {"path": "/search?query=<script>alert('xss')</script>", "method": "GET"},
            {"path": "/search?query=../../../etc/passwd", "method": "GET"},
            {"path": "/search?query=; cat /etc/passwd", "method": "GET"},
        ]
    
    async def create_session(self):
        """創建 HTTP 會話"""
        connector = aiohttp.TCPConnector(
            limit=1000,  # 總連接池大小
            limit_per_host=100,  # 每個主機的連接數
            ttl_dns_cache=300,  # DNS 緩存時間
            use_dns_cache=True,
            keepalive_timeout=30,  # keep-alive 超時
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(
            total=30,  # 總超時
            connect=10,  # 連接超時
            sock_read=20  # 讀取超時
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'EnterpriseLoadTester/1.0'}
        )
    
    async def close_session(self):
        """關閉 HTTP 會話"""
        if self.session:
            await self.session.close()
    
    async def make_request(self, scenario: Dict) -> Tuple[float, int, str]:
        """發送單個請求"""
        start_time = time.time()
        status_code = 0
        error = None
        
        try:
            url = f"{self.base_url}{scenario['path']}"
            
            async with self.session.request(
                scenario['method'],
                url,
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
    
    async def worker(self, worker_id: int, scenarios: List[Dict], duration: int):
        """工作線程"""
        print(f"Worker {worker_id} started")
        
        while self.running and (time.time() - self.metrics.start_time.timestamp()) < duration:
            for scenario in scenarios:
                if not self.running:
                    break
                
                response_time, status_code, error = await self.make_request(scenario)
                self.metrics.record_request(response_time, status_code, error)
        
        print(f"Worker {worker_id} finished")
    
    async def run_load_test(self, 
                          concurrent_users: int = 100,
                          duration: int = 60,
                          ramp_up: int = 10,
                          include_attacks: bool = False):
        """執行負載測試"""
        print(f"Starting load test:")
        print(f"  - Base URL: {self.base_url}")
        print(f"  - Concurrent Users: {concurrent_users}")
        print(f"  - Duration: {duration} seconds")
        print(f"  - Ramp Up: {ramp_up} seconds")
        print(f"  - Include Attacks: {include_attacks}")
        print()
        
        # 準備測試場景
        scenarios = self.test_scenarios.copy()
        if include_attacks:
            scenarios.extend(self.attack_scenarios)
        
        # 創建會話
        await self.create_session()
        
        try:
            # 設置信號處理
            self.running = True
            self.metrics.start_time = datetime.now()
            
            # 創建任務
            tasks = []
            
            # 階梯式啟動
            for i in range(concurrent_users):
                if i > 0 and i % (concurrent_users // ramp_up) == 0:
                    await asyncio.sleep(1)  # 每秒啟動一批
                
                task = asyncio.create_task(
                    self.worker(i, scenarios, duration)
                )
                tasks.append(task)
            
            # 等待測試完成
            await asyncio.gather(*tasks, return_exceptions=True)
            
        finally:
            self.running = False
            self.metrics.end_time = datetime.now()
            await self.close_session()
    
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
    
    def generate_report(self, test_name: str = "Load Test"):
        """生成測試報告"""
        summary = self.metrics.get_summary()
        
        print(f"\n{'='*60}")
        print(f"{test_name} - 測試報告")
        print(f"{'='*60}")
        print(f"測試時間: {self.metrics.start_time} - {self.metrics.end_time}")
        print(f"持續時間: {summary['duration_seconds']:.1f} 秒")
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
        
        # 企業級 SLA 檢查
        self.check_sla_compliance(summary)
        
        return summary
    
    def check_sla_compliance(self, summary: Dict):
        """檢查企業級 SLA 合規性"""
        print("SLA 合規性檢查:")
        
        # 可用性檢查 (99.9%)
        success_rate = summary['success_rate']
        if success_rate >= 99.9:
            print(f"  ✅ 可用性: {success_rate:.2f}% (目標: ≥99.9%)")
        else:
            print(f"  ❌ 可用性: {success_rate:.2f}% (目標: ≥99.9%)")
        
        # 響應時間檢查
        rt = summary['response_times']
        p95 = rt['p95']
        
        if self.use_https:
            # HTTPS 目標: P95 < 250ms
            if p95 < 250:
                print(f"  ✅ HTTPS P95: {p95:.1f}ms (目標: <250ms)")
            else:
                print(f"  ❌ HTTPS P95: {p95:.1f}ms (目標: <250ms)")
        else:
            # HTTP 目標: P95 < 150ms
            if p95 < 150:
                print(f"  ✅ HTTP P95: {p95:.1f}ms (目標: <150ms)")
            else:
                print(f"  ❌ HTTP P95: {p95:.1f}ms (目標: <150ms)")
        
        # 錯誤率檢查 (<0.1%)
        error_rate = 100 - success_rate
        if error_rate < 0.1:
            print(f"  ✅ 錯誤率: {error_rate:.3f}% (目標: <0.1%)")
        else:
            print(f"  ❌ 錯誤率: {error_rate:.3f}% (目標: <0.1%)")
        
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
            include_attacks=args.attacks
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

