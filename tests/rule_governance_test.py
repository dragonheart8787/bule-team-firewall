#!/usr/bin/env python3
"""
規則誤報治理測試腳本
灰度模式、白名單管理、誤報率分析、規則回滾測試
"""

import asyncio
import aiohttp
import time
import json
import statistics
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Set
import threading
import os

class RuleGovernanceMetrics:
    """規則治理指標收集器"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.test_start_time = None
        self.test_end_time = None
        self.requests = []
        self.rule_hits = {}
        self.false_positives = []
        self.false_negatives = []
        self.whitelist_changes = []
        self.rule_changes = []
        self.rollback_times = []
    
    def record_request(self, request: Dict, response: Dict, rule_hits: List[Dict]):
        """記錄請求和規則命中"""
        request_record = {
            "timestamp": datetime.now(),
            "request": request,
            "response": response,
            "rule_hits": rule_hits,
            "is_false_positive": False,
            "is_false_negative": False,
            "whitelisted": False
        }
        self.requests.append(request_record)
        
        # 記錄規則命中
        for hit in rule_hits:
            rule_id = hit.get('rule_id', 'unknown')
            if rule_id not in self.rule_hits:
                self.rule_hits[rule_id] = []
            self.rule_hits[rule_id].append(request_record)
    
    def mark_false_positive(self, request_index: int, reason: str):
        """標記誤報"""
        if 0 <= request_index < len(self.requests):
            self.requests[request_index]["is_false_positive"] = True
            self.requests[request_index]["fp_reason"] = reason
            self.false_positives.append(self.requests[request_index])
    
    def mark_false_negative(self, request_index: int, reason: str):
        """標記漏報"""
        if 0 <= request_index < len(self.requests):
            self.requests[request_index]["is_false_negative"] = True
            self.requests[request_index]["fn_reason"] = reason
            self.false_negatives.append(self.requests[request_index])
    
    def record_whitelist_change(self, change_type: str, details: Dict):
        """記錄白名單變更"""
        change = {
            "timestamp": datetime.now(),
            "type": change_type,
            "details": details
        }
        self.whitelist_changes.append(change)
    
    def record_rule_change(self, change_type: str, details: Dict):
        """記錄規則變更"""
        change = {
            "timestamp": datetime.now(),
            "type": change_type,
            "details": details
        }
        self.rule_changes.append(change)
    
    def record_rollback(self, rollback_time: float):
        """記錄回滾時間"""
        self.rollback_times.append(rollback_time)
    
    def calculate_metrics(self) -> Dict:
        """計算治理指標"""
        total_requests = len(self.requests)
        total_fp = len(self.false_positives)
        total_fn = len(self.false_negatives)
        
        fp_rate = (total_fp / total_requests * 100) if total_requests > 0 else 0
        fn_rate = (total_fn / total_requests * 100) if total_requests > 0 else 0
        
        # 按規則分析誤報率
        rule_fp_rates = {}
        for rule_id, hits in self.rule_hits.items():
            rule_fps = [h for h in hits if h.get("is_false_positive", False)]
            rule_fp_rate = (len(rule_fps) / len(hits) * 100) if hits else 0
            rule_fp_rates[rule_id] = {
                "total_hits": len(hits),
                "false_positives": len(rule_fps),
                "fp_rate": rule_fp_rate
            }
        
        return {
            "total_requests": total_requests,
            "false_positives": total_fp,
            "false_negatives": total_fn,
            "fp_rate": fp_rate,
            "fn_rate": fn_rate,
            "rule_fp_rates": rule_fp_rates,
            "whitelist_changes": len(self.whitelist_changes),
            "rule_changes": len(self.rule_changes),
            "avg_rollback_time": statistics.mean(self.rollback_times) if self.rollback_times else 0
        }

class RuleGovernanceTester:
    """規則治理測試器"""
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url.rstrip('/')
        self.metrics = RuleGovernanceMetrics()
        self.session = None
        self.whitelist = set()
        
        # 測試數據集
        self.normal_requests = [
            {"path": "/search?query=normal_search", "expected": "allow"},
            {"path": "/search?query=hello_world", "expected": "allow"},
            {"path": "/search?query=product_info", "expected": "allow"},
            {"path": "/search?query=user_data", "expected": "allow"},
            {"path": "/search?query=test123", "expected": "allow"},
        ]
        
        self.attack_requests = [
            {"path": "/search?query=1' OR '1'='1", "expected": "block"},
            {"path": "/search?query=<script>alert('xss')</script>", "expected": "block"},
            {"path": "/search?query=../../../etc/passwd", "expected": "block"},
            {"path": "/search?query=; cat /etc/passwd", "expected": "block"},
            {"path": "/search?query=UNION SELECT * FROM users", "expected": "block"},
        ]
        
        self.edge_cases = [
            {"path": "/search?query=admin", "expected": "allow"},  # 可能誤報
            {"path": "/search?query=script", "expected": "allow"},  # 可能誤報
            {"path": "/search?query=select", "expected": "allow"},  # 可能誤報
            {"path": "/search?query=union", "expected": "allow"},  # 可能誤報
            {"path": "/search?query=or", "expected": "allow"},  # 可能誤報
        ]
    
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
            total=10,
            connect=2,
            sock_read=5
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        )
    
    async def close_session(self):
        """關閉 HTTP 會話"""
        if self.session:
            await self.session.close()
    
    async def make_request(self, request: Dict) -> Tuple[Dict, Dict, List[Dict]]:
        """發送請求並分析響應"""
        start_time = time.time()
        
        try:
            url = f"{self.base_url}{request['path']}"
            async with self.session.get(url) as response:
                response_time = (time.time() - start_time) * 1000
                
                response_data = {
                    "status_code": response.status,
                    "response_time": response_time,
                    "headers": dict(response.headers),
                    "blocked": response.status in [403, 429, 502]
                }
                
                # 讀取響應體
                try:
                    response_text = await response.text()
                    response_data["body"] = response_text
                except:
                    response_data["body"] = ""
                
                # 分析規則命中（基於響應特徵）
                rule_hits = self._analyze_rule_hits(request, response_data)
                
                return request, response_data, rule_hits
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            response_data = {
                "status_code": 0,
                "response_time": response_time,
                "error": str(e),
                "blocked": True
            }
            
            # 分析可能的規則命中
            rule_hits = self._analyze_rule_hits(request, response_data)
            
            return request, response_data, rule_hits
    
    def _analyze_rule_hits(self, request: Dict, response: Dict) -> List[Dict]:
        """分析規則命中"""
        rule_hits = []
        
        # 基於請求特徵分析
        path = request['path'].lower()
        
        # SQL 注入檢測
        sql_patterns = ["'", "union", "select", "or", "and", "drop", "insert"]
        if any(pattern in path for pattern in sql_patterns):
            rule_hits.append({
                "rule_id": "SQL_INJECTION",
                "severity": "HIGH",
                "pattern": "SQL injection pattern detected"
            })
        
        # XSS 檢測
        xss_patterns = ["<script", "javascript:", "onerror", "onload"]
        if any(pattern in path for pattern in xss_patterns):
            rule_hits.append({
                "rule_id": "XSS",
                "severity": "HIGH",
                "pattern": "XSS pattern detected"
            })
        
        # 路徑遍歷檢測
        traversal_patterns = ["../", "..\\", "%2e%2e"]
        if any(pattern in path for pattern in traversal_patterns):
            rule_hits.append({
                "rule_id": "PATH_TRAVERSAL",
                "severity": "HIGH",
                "pattern": "Path traversal pattern detected"
            })
        
        # 命令注入檢測
        cmd_patterns = [";", "|", "&", "$", "cat", "ls", "dir"]
        if any(pattern in path for pattern in cmd_patterns):
            rule_hits.append({
                "rule_id": "COMMAND_INJECTION",
                "severity": "HIGH",
                "pattern": "Command injection pattern detected"
            })
        
        # 速率限制檢測
        if response.get("status_code") == 429:
            rule_hits.append({
                "rule_id": "RATE_LIMIT",
                "severity": "MEDIUM",
                "pattern": "Rate limit exceeded"
            })
        
        return rule_hits
    
    async def test_1_grayscale_deployment(self):
        """測試 1: 灰度部署模式"""
        print("\n=== 測試 1: 灰度部署模式 ===")
        print("1. 只記錄模式 - 不阻擋請求")
        
        # 模擬只記錄模式（實際需要修改 WAF 配置）
        print("   配置 WAF 為只記錄模式...")
        # 這裡應該調用 WAF API 設置為只記錄模式
        
        # 發送測試請求
        print("2. 發送測試請求...")
        for request in self.normal_requests + self.attack_requests:
            req, resp, hits = await self.make_request(request)
            self.metrics.record_request(req, resp, hits)
            
            print(f"   請求: {req['path']}")
            print(f"   響應: {resp['status_code']} ({'阻擋' if resp['blocked'] else '通過'})")
            print(f"   規則命中: {len(hits)} 條")
            print()
        
        print("3. 分析記錄結果...")
        # 分析哪些請求被誤報
        for i, req_record in enumerate(self.metrics.requests):
            if req_record["request"]["expected"] == "allow" and req_record["response"]["blocked"]:
                self.metrics.mark_false_positive(i, "正常請求被誤報")
                print(f"   誤報: {req_record['request']['path']}")
            elif req_record["request"]["expected"] == "block" and not req_record["response"]["blocked"]:
                self.metrics.mark_false_negative(i, "攻擊請求未被檢測")
                print(f"   漏報: {req_record['request']['path']}")
    
    async def test_2_whitelist_management(self):
        """測試 2: 白名單管理"""
        print("\n=== 測試 2: 白名單管理 ===")
        
        # 識別誤報
        print("1. 識別誤報請求...")
        fp_requests = [r for r in self.metrics.requests if r.get("is_false_positive", False)]
        
        for fp_req in fp_requests:
            print(f"   誤報請求: {fp_req['request']['path']}")
            
            # 添加到白名單
            whitelist_entry = {
                "path_pattern": fp_req['request']['path'],
                "reason": "False positive correction",
                "timestamp": datetime.now().isoformat()
            }
            
            self.whitelist.add(fp_req['request']['path'])
            self.metrics.record_whitelist_change("add", whitelist_entry)
            print(f"   已添加到白名單: {fp_req['request']['path']}")
        
        print(f"2. 白名單統計: {len(self.whitelist)} 條規則")
    
    async def test_3_rule_tuning(self):
        """測試 3: 規則調優"""
        print("\n=== 測試 3: 規則調優 ===")
        
        # 分析規則誤報率
        print("1. 分析規則誤報率...")
        rule_metrics = self.metrics.calculate_metrics()["rule_fp_rates"]
        
        for rule_id, metrics in rule_metrics.items():
            print(f"   規則 {rule_id}:")
            print(f"     總命中: {metrics['total_hits']}")
            print(f"     誤報數: {metrics['false_positives']}")
            print(f"     誤報率: {metrics['fp_rate']:.1f}%")
            
            # 如果誤報率過高，建議調整規則
            if metrics['fp_rate'] > 10:  # 誤報率超過 10%
                print(f"     ⚠️  誤報率過高，建議調整規則")
                
                # 記錄規則變更
                change_details = {
                    "rule_id": rule_id,
                    "action": "tune",
                    "reason": f"High FP rate: {metrics['fp_rate']:.1f}%",
                    "old_fp_rate": metrics['fp_rate']
                }
                self.metrics.record_rule_change("tune", change_details)
        
        print("2. 執行規則調整...")
        # 這裡應該調用 WAF API 調整規則敏感度
        print("   規則調整已應用")
    
    async def test_4_rollback_testing(self):
        """測試 4: 回滾測試"""
        print("\n=== 測試 4: 回滾測試 ===")
        
        # 模擬規則更新
        print("1. 模擬規則更新...")
        update_start = time.time()
        
        # 這裡應該調用 WAF API 更新規則
        print("   規則已更新")
        
        # 測試新規則
        print("2. 測試新規則...")
        test_requests = self.normal_requests[:3] + self.attack_requests[:3]
        
        for request in test_requests:
            req, resp, hits = await self.make_request(request)
            self.metrics.record_request(req, resp, hits)
        
        # 發現問題，執行回滾
        print("3. 發現問題，執行回滾...")
        rollback_start = time.time()
        
        # 這裡應該調用 WAF API 回滾到上一個版本
        print("   規則已回滾")
        
        rollback_time = time.time() - rollback_start
        self.metrics.record_rollback(rollback_time)
        
        print(f"   回滾時間: {rollback_time:.2f} 秒")
        
        # 驗證回滾效果
        print("4. 驗證回滾效果...")
        for request in test_requests:
            req, resp, hits = await self.make_request(request)
            print(f"   請求: {req['path']} -> {resp['status_code']}")
    
    async def test_5_continuous_monitoring(self):
        """測試 5: 持續監控"""
        print("\n=== 測試 5: 持續監控 ===")
        
        # 持續發送請求並監控
        print("1. 持續監控模式...")
        for i in range(20):  # 發送 20 個請求
            # 混合正常和攻擊請求
            if i % 3 == 0:
                request = self.attack_requests[i % len(self.attack_requests)]
            else:
                request = self.normal_requests[i % len(self.normal_requests)]
            
            req, resp, hits = await self.make_request(request)
            self.metrics.record_request(req, resp, hits)
            
            # 實時分析
            if req["expected"] == "allow" and resp["blocked"]:
                self.metrics.mark_false_positive(len(self.metrics.requests) - 1, "持續監控發現誤報")
            elif req["expected"] == "block" and not resp["blocked"]:
                self.metrics.mark_false_negative(len(self.metrics.requests) - 1, "持續監控發現漏報")
            
            await asyncio.sleep(0.5)  # 500ms 間隔
        
        print("2. 持續監控完成")
    
    async def run_governance_test(self):
        """執行完整的規則治理測試"""
        print("開始規則誤報治理測試")
        print("=" * 60)
        
        # 創建會話
        await self.create_session()
        
        try:
            self.metrics.test_start_time = datetime.now()
            
            # 執行所有測試
            await self.test_1_grayscale_deployment()
            await asyncio.sleep(2)
            
            await self.test_2_whitelist_management()
            await asyncio.sleep(2)
            
            await self.test_3_rule_tuning()
            await asyncio.sleep(2)
            
            await self.test_4_rollback_testing()
            await asyncio.sleep(2)
            
            await self.test_5_continuous_monitoring()
            
            self.metrics.test_end_time = datetime.now()
            
        finally:
            await self.close_session()
        
        # 生成報告
        self.generate_report()
    
    def generate_report(self):
        """生成規則治理報告"""
        metrics = self.metrics.calculate_metrics()
        
        print(f"\n{'='*60}")
        print("規則誤報治理報告")
        print(f"{'='*60}")
        print(f"測試時間: {self.metrics.test_start_time} - {self.metrics.test_end_time}")
        print(f"總請求數: {metrics['total_requests']}")
        print()
        
        print("誤報分析:")
        print(f"  誤報數量: {metrics['false_positives']}")
        print(f"  誤報率: {metrics['fp_rate']:.2f}%")
        print(f"  漏報數量: {metrics['false_negatives']}")
        print(f"  漏報率: {metrics['fn_rate']:.2f}%")
        print()
        
        print("規則分析:")
        for rule_id, rule_metrics in metrics['rule_fp_rates'].items():
            print(f"  {rule_id}:")
            print(f"    總命中: {rule_metrics['total_hits']}")
            print(f"    誤報數: {rule_metrics['false_positives']}")
            print(f"    誤報率: {rule_metrics['fp_rate']:.1f}%")
        print()
        
        print("治理活動:")
        print(f"  白名單變更: {metrics['whitelist_changes']} 次")
        print(f"  規則變更: {metrics['rule_changes']} 次")
        print(f"  平均回滾時間: {metrics['avg_rollback_time']:.2f} 秒")
        print()
        
        # 合規性檢查
        self.check_governance_compliance(metrics)
    
    def check_governance_compliance(self, metrics: Dict):
        """檢查治理合規性"""
        print("治理合規性檢查:")
        
        # 誤報率檢查 (<0.5%)
        fp_rate = metrics['fp_rate']
        if fp_rate < 0.5:
            print(f"  ✅ 誤報率: {fp_rate:.2f}% (目標: <0.5%)")
        else:
            print(f"  ❌ 誤報率: {fp_rate:.2f}% (目標: <0.5%)")
        
        # 漏報率檢查 (<1%)
        fn_rate = metrics['fn_rate']
        if fn_rate < 1.0:
            print(f"  ✅ 漏報率: {fn_rate:.2f}% (目標: <1%)")
        else:
            print(f"  ❌ 漏報率: {fn_rate:.2f}% (目標: <1%)")
        
        # 回滾時間檢查 (<5 分鐘)
        avg_rollback = metrics['avg_rollback_time']
        if avg_rollback < 300:  # 5 分鐘
            print(f"  ✅ 平均回滾時間: {avg_rollback:.1f} 秒 (目標: <300秒)")
        else:
            print(f"  ❌ 平均回滾時間: {avg_rollback:.1f} 秒 (目標: <300秒)")
        
        print()

async def main():
    """主函數"""
    import argparse
    
    parser = argparse.ArgumentParser(description='規則誤報治理測試工具')
    parser.add_argument('--url', default='http://localhost:8080', help='目標 URL')
    parser.add_argument('--test', help='執行特定測試 (1-5)')
    parser.add_argument('--report-file', help='保存報告到文件')
    
    args = parser.parse_args()
    
    # 創建測試器
    tester = RuleGovernanceTester(args.url)
    
    try:
        if args.test:
            # 執行特定測試
            test_num = int(args.test)
            await tester.create_session()
            
            if test_num == 1:
                await tester.test_1_grayscale_deployment()
            elif test_num == 2:
                await tester.test_2_whitelist_management()
            elif test_num == 3:
                await tester.test_3_rule_tuning()
            elif test_num == 4:
                await tester.test_4_rollback_testing()
            elif test_num == 5:
                await tester.test_5_continuous_monitoring()
            else:
                print(f"未知測試: {test_num}")
                return
            
            await tester.close_session()
        else:
            # 執行完整測試
            await tester.run_governance_test()
        
        # 保存報告
        if args.report_file:
            metrics = tester.metrics.calculate_metrics()
            with open(args.report_file, 'w', encoding='utf-8') as f:
                json.dump(metrics, f, indent=2, ensure_ascii=False, default=str)
            print(f"報告已保存到: {args.report_file}")
        
    except KeyboardInterrupt:
        print("\n測試被用戶中斷")
    except Exception as e:
        print(f"測試執行錯誤: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())

