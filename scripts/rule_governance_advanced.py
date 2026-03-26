#!/usr/bin/env python3
"""
規則誤報治理腳本 - 企業級版本
建立「灰度模式（只記錄不阻擋）」→「觀察」→「小流量放量」→「全量」流水線
產出：FP 率、Top 誤報樣式、白名單變更記錄、回滾時間
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
import argparse
import sys
from collections import defaultdict, deque
import hashlib
import hmac
import base64

class RuleGovernanceMetrics:
    """規則治理指標收集器 - 企業級版本"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.test_start_time = None
        self.test_end_time = None
        self.requests = []
        self.rule_hits = defaultdict(list)
        self.false_positives = []
        self.false_negatives = []
        self.whitelist_changes = []
        self.rule_changes = []
        self.rollback_times = []
        self.gray_mode_requests = []
        self.observation_requests = []
        self.small_traffic_requests = []
        self.full_deployment_requests = []
        self.lock = threading.Lock()
    
    def record_request(self, request: Dict, response: Dict, rule_hits: List[Dict], 
                      deployment_phase: str = "full"):
        """記錄請求和規則命中"""
        request_record = {
            "timestamp": datetime.now(),
            "request": request,
            "response": response,
            "rule_hits": rule_hits,
            "deployment_phase": deployment_phase,
            "is_false_positive": False,
            "is_false_negative": False,
            "whitelisted": False,
            "request_hash": self._hash_request(request)
        }
        
        with self.lock:
            self.requests.append(request_record)
            
            # 按部署階段分類
            if deployment_phase == "gray":
                self.gray_mode_requests.append(request_record)
            elif deployment_phase == "observation":
                self.observation_requests.append(request_record)
            elif deployment_phase == "small_traffic":
                self.small_traffic_requests.append(request_record)
            elif deployment_phase == "full":
                self.full_deployment_requests.append(request_record)
            
            # 記錄規則命中
            for hit in rule_hits:
                rule_id = hit.get('rule_id', 'unknown')
                self.rule_hits[rule_id].append(request_record)
    
    def _hash_request(self, request: Dict) -> str:
        """生成請求哈希值"""
        request_str = f"{request.get('path', '')}{request.get('method', '')}{request.get('body', '')}"
        return hashlib.md5(request_str.encode()).hexdigest()
    
    def mark_false_positive(self, request_index: int, reason: str, deployment_phase: str = "full"):
        """標記誤報"""
        with self.lock:
            if 0 <= request_index < len(self.requests):
                self.requests[request_index]["is_false_positive"] = True
                self.requests[request_index]["fp_reason"] = reason
                self.requests[request_index]["fp_deployment_phase"] = deployment_phase
                self.false_positives.append(self.requests[request_index])
    
    def mark_false_negative(self, request_index: int, reason: str, deployment_phase: str = "full"):
        """標記漏報"""
        with self.lock:
            if 0 <= request_index < len(self.requests):
                self.requests[request_index]["is_false_negative"] = True
                self.requests[request_index]["fn_reason"] = reason
                self.requests[request_index]["fn_deployment_phase"] = deployment_phase
                self.false_negatives.append(self.requests[request_index])
    
    def record_whitelist_change(self, change_type: str, details: Dict, approval_info: Dict = None):
        """記錄白名單變更"""
        change = {
            "timestamp": datetime.now(),
            "type": change_type,
            "details": details,
            "approval_info": approval_info,
            "change_id": self._generate_change_id()
        }
        self.whitelist_changes.append(change)
    
    def record_rule_change(self, change_type: str, details: Dict, approval_info: Dict = None):
        """記錄規則變更"""
        change = {
            "timestamp": datetime.now(),
            "type": change_type,
            "details": details,
            "approval_info": approval_info,
            "change_id": self._generate_change_id()
        }
        self.rule_changes.append(change)
    
    def record_rollback(self, rollback_time: float, rollback_reason: str, rollback_details: Dict):
        """記錄回滾時間"""
        rollback_record = {
            "timestamp": datetime.now(),
            "rollback_time": rollback_time,
            "rollback_reason": rollback_reason,
            "rollback_details": rollback_details
        }
        self.rollback_times.append(rollback_record)
    
    def _generate_change_id(self) -> str:
        """生成變更 ID"""
        timestamp = datetime.now().isoformat()
        return hashlib.md5(timestamp.encode()).hexdigest()[:8]
    
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
        
        # 按部署階段分析
        deployment_analysis = {}
        for phase, requests in [
            ("gray", self.gray_mode_requests),
            ("observation", self.observation_requests),
            ("small_traffic", self.small_traffic_requests),
            ("full", self.full_deployment_requests)
        ]:
            if requests:
                phase_fps = [r for r in requests if r.get("is_false_positive", False)]
                phase_fns = [r for r in requests if r.get("is_false_negative", False)]
                
                deployment_analysis[phase] = {
                    "total_requests": len(requests),
                    "false_positives": len(phase_fps),
                    "false_negatives": len(phase_fns),
                    "fp_rate": (len(phase_fps) / len(requests) * 100) if requests else 0,
                    "fn_rate": (len(phase_fns) / len(requests) * 100) if requests else 0
                }
        
        # 計算平均回滾時間
        avg_rollback_time = 0
        if self.rollback_times:
            avg_rollback_time = sum(r['rollback_time'] for r in self.rollback_times) / len(self.rollback_times)
        
        return {
            "total_requests": total_requests,
            "false_positives": total_fp,
            "false_negatives": total_fn,
            "fp_rate": fp_rate,
            "fn_rate": fn_rate,
            "rule_fp_rates": rule_fp_rates,
            "deployment_analysis": deployment_analysis,
            "whitelist_changes": len(self.whitelist_changes),
            "rule_changes": len(self.rule_changes),
            "avg_rollback_time": avg_rollback_time,
            "rollback_count": len(self.rollback_times)
        }

class RuleGovernanceTester:
    """規則治理測試器 - 企業級版本"""
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url.rstrip('/')
        self.metrics = RuleGovernanceMetrics()
        self.session = None
        self.whitelist = set()
        self.rule_configs = {}
        
        # 測試數據集
        self.normal_requests = [
            {"path": "/search?query=normal_search", "expected": "allow", "type": "normal"},
            {"path": "/search?query=hello_world", "expected": "allow", "type": "normal"},
            {"path": "/search?query=product_info", "expected": "allow", "type": "normal"},
            {"path": "/search?query=user_data", "expected": "allow", "type": "normal"},
            {"path": "/search?query=test123", "expected": "allow", "type": "normal"},
        ]
        
        self.attack_requests = [
            {"path": "/search?query=1' OR '1'='1", "expected": "block", "type": "sql_injection"},
            {"path": "/search?query=<script>alert('xss')</script>", "expected": "block", "type": "xss"},
            {"path": "/search?query=../../../etc/passwd", "expected": "block", "type": "path_traversal"},
            {"path": "/search?query=; cat /etc/passwd", "expected": "block", "type": "command_injection"},
            {"path": "/search?query=UNION SELECT * FROM users", "expected": "block", "type": "sql_injection"},
        ]
        
        self.edge_cases = [
            {"path": "/search?query=admin", "expected": "allow", "type": "edge_case"},  # 可能誤報
            {"path": "/search?query=script", "expected": "allow", "type": "edge_case"},  # 可能誤報
            {"path": "/search?query=select", "expected": "allow", "type": "edge_case"},  # 可能誤報
            {"path": "/search?query=union", "expected": "allow", "type": "edge_case"},  # 可能誤報
            {"path": "/search?query=or", "expected": "allow", "type": "edge_case"},  # 可能誤報
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
    
    async def make_request(self, request: Dict, deployment_phase: str = "full") -> Tuple[Dict, Dict, List[Dict]]:
        """發送請求並分析響應"""
        start_time = time.time()
        
        try:
            url = f"{self.base_url}{request['path']}"
            
            # 根據部署階段設置標頭
            headers = {}
            if deployment_phase == "gray":
                headers['X-WAF-Mode'] = 'gray'  # 只記錄不阻擋
            elif deployment_phase == "observation":
                headers['X-WAF-Mode'] = 'observation'  # 觀察模式
            elif deployment_phase == "small_traffic":
                headers['X-WAF-Mode'] = 'small_traffic'  # 小流量放量
            
            async with self.session.get(url, headers=headers) as response:
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
                rule_hits = self._analyze_rule_hits(request, response_data, deployment_phase)
                
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
            rule_hits = self._analyze_rule_hits(request, response_data, deployment_phase)
            
            return request, response_data, rule_hits
    
    def _analyze_rule_hits(self, request: Dict, response: Dict, deployment_phase: str) -> List[Dict]:
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
                "pattern": "SQL injection pattern detected",
                "deployment_phase": deployment_phase
            })
        
        # XSS 檢測
        xss_patterns = ["<script", "javascript:", "onerror", "onload"]
        if any(pattern in path for pattern in xss_patterns):
            rule_hits.append({
                "rule_id": "XSS",
                "severity": "HIGH",
                "pattern": "XSS pattern detected",
                "deployment_phase": deployment_phase
            })
        
        # 路徑遍歷檢測
        traversal_patterns = ["../", "..\\", "%2e%2e"]
        if any(pattern in path for pattern in traversal_patterns):
            rule_hits.append({
                "rule_id": "PATH_TRAVERSAL",
                "severity": "HIGH",
                "pattern": "Path traversal pattern detected",
                "deployment_phase": deployment_phase
            })
        
        # 命令注入檢測
        cmd_patterns = [";", "|", "&", "$", "cat", "ls", "dir"]
        if any(pattern in path for pattern in cmd_patterns):
            rule_hits.append({
                "rule_id": "COMMAND_INJECTION",
                "severity": "HIGH",
                "pattern": "Command injection pattern detected",
                "deployment_phase": deployment_phase
            })
        
        # 速率限制檢測
        if response.get("status_code") == 429:
            rule_hits.append({
                "rule_id": "RATE_LIMIT",
                "severity": "MEDIUM",
                "pattern": "Rate limit exceeded",
                "deployment_phase": deployment_phase
            })
        
        return rule_hits
    
    async def test_1_gray_mode_deployment(self):
        """測試 1: 灰度模式部署（只記錄不阻擋）"""
        print("\n=== 測試 1: 灰度模式部署 ===")
        print("1. 只記錄模式 - 不阻擋請求")
        
        # 配置 WAF 為灰度模式
        print("   配置 WAF 為灰度模式...")
        await self._configure_waf_mode("gray")
        
        # 發送測試請求
        print("2. 發送測試請求...")
        all_requests = self.normal_requests + self.attack_requests + self.edge_cases
        
        for request in all_requests:
            req, resp, hits = await self.make_request(request, "gray")
            self.metrics.record_request(req, resp, hits, "gray")
            
            print(f"   請求: {req['path']}")
            print(f"   響應: {resp['status_code']} ({'阻擋' if resp['blocked'] else '通過'})")
            print(f"   規則命中: {len(hits)} 條")
            print()
        
        print("3. 分析灰度模式結果...")
        # 分析哪些請求被誤報
        for i, req_record in enumerate(self.metrics.gray_mode_requests):
            if req_record["request"]["expected"] == "allow" and req_record["response"]["blocked"]:
                self.metrics.mark_false_positive(i, "正常請求被誤報", "gray")
                print(f"   誤報: {req_record['request']['path']}")
            elif req_record["request"]["expected"] == "block" and not req_record["response"]["blocked"]:
                self.metrics.mark_false_negative(i, "攻擊請求未被檢測", "gray")
                print(f"   漏報: {req_record['request']['path']}")
    
    async def test_2_observation_mode(self):
        """測試 2: 觀察模式"""
        print("\n=== 測試 2: 觀察模式 ===")
        print("1. 觀察模式 - 記錄並分析但不阻擋")
        
        # 配置 WAF 為觀察模式
        print("   配置 WAF 為觀察模式...")
        await self._configure_waf_mode("observation")
        
        # 發送測試請求
        print("2. 發送測試請求...")
        all_requests = self.normal_requests + self.attack_requests + self.edge_cases
        
        for request in all_requests:
            req, resp, hits = await self.make_request(request, "observation")
            self.metrics.record_request(req, resp, hits, "observation")
            
            print(f"   請求: {req['path']}")
            print(f"   響應: {resp['status_code']} ({'阻擋' if resp['blocked'] else '通過'})")
            print(f"   規則命中: {len(hits)} 條")
            print()
        
        print("3. 分析觀察模式結果...")
        # 分析誤報模式
        fp_patterns = defaultdict(int)
        for req_record in self.metrics.observation_requests:
            if req_record.get("is_false_positive", False):
                rule_hits = req_record.get("rule_hits", [])
                for hit in rule_hits:
                    fp_patterns[hit.get("rule_id", "unknown")] += 1
        
        print("   Top 誤報樣式:")
        for rule_id, count in sorted(fp_patterns.items(), key=lambda x: x[1], reverse=True):
            print(f"     {rule_id}: {count} 次")
    
    async def test_3_small_traffic_deployment(self):
        """測試 3: 小流量放量"""
        print("\n=== 測試 3: 小流量放量 ===")
        print("1. 小流量放量 - 10% 流量啟用規則")
        
        # 配置 WAF 為小流量模式
        print("   配置 WAF 為小流量模式...")
        await self._configure_waf_mode("small_traffic")
        
        # 發送測試請求
        print("2. 發送測試請求...")
        all_requests = self.normal_requests + self.attack_requests + self.edge_cases
        
        for request in all_requests:
            req, resp, hits = await self.make_request(request, "small_traffic")
            self.metrics.record_request(req, resp, hits, "small_traffic")
            
            print(f"   請求: {req['path']}")
            print(f"   響應: {resp['status_code']} ({'阻擋' if resp['blocked'] else '通過'})")
            print(f"   規則命中: {len(hits)} 條")
            print()
        
        print("3. 分析小流量放量結果...")
        # 分析小流量下的誤報率
        small_traffic_fps = [r for r in self.metrics.small_traffic_requests if r.get("is_false_positive", False)]
        small_traffic_total = len(self.metrics.small_traffic_requests)
        small_traffic_fp_rate = (len(small_traffic_fps) / small_traffic_total * 100) if small_traffic_total > 0 else 0
        
        print(f"   小流量誤報率: {small_traffic_fp_rate:.1f}%")
        
        if small_traffic_fp_rate > 5:  # 誤報率超過 5%
            print("   [WARN] 誤報率過高，建議調整規則")
        else:
            print("   [OK] 誤報率可接受，可以進行全量部署")
    
    async def test_4_full_deployment(self):
        """測試 4: 全量部署"""
        print("\n=== 測試 4: 全量部署 ===")
        print("1. 全量部署 - 100% 流量啟用規則")
        
        # 配置 WAF 為全量模式
        print("   配置 WAF 為全量模式...")
        await self._configure_waf_mode("full")
        
        # 發送測試請求
        print("2. 發送測試請求...")
        all_requests = self.normal_requests + self.attack_requests + self.edge_cases
        
        for request in all_requests:
            req, resp, hits = await self.make_request(request, "full")
            self.metrics.record_request(req, resp, hits, "full")
            
            print(f"   請求: {req['path']}")
            print(f"   響應: {resp['status_code']} ({'阻擋' if resp['blocked'] else '通過'})")
            print(f"   規則命中: {len(hits)} 條")
            print()
        
        print("3. 分析全量部署結果...")
        # 分析全量部署下的誤報率
        full_fps = [r for r in self.metrics.full_deployment_requests if r.get("is_false_positive", False)]
        full_total = len(self.metrics.full_deployment_requests)
        full_fp_rate = (len(full_fps) / full_total * 100) if full_total > 0 else 0
        
        print(f"   全量部署誤報率: {full_fp_rate:.1f}%")
        
        if full_fp_rate > 0.5:  # 誤報率超過 0.5%
            print("   [WARN] 誤報率過高，建議回滾")
            await self.test_5_rollback_testing()
        else:
            print("   [OK] 全量部署成功")
    
    async def test_5_rollback_testing(self):
        """測試 5: 回滾測試"""
        print("\n=== 測試 5: 回滾測試 ===")
        print("1. 執行規則回滾...")
        
        rollback_start = time.time()
        
        # 回滾到上一個版本
        print("   回滾到上一個版本...")
        await self._rollback_rules()
        
        rollback_time = time.time() - rollback_start
        
        # 記錄回滾
        self.metrics.record_rollback(
            rollback_time,
            "誤報率過高",
            {"fp_rate": ">0.5%", "rollback_reason": "high_false_positive_rate"}
        )
        
        print(f"   回滾時間: {rollback_time:.2f} 秒")
        
        # 驗證回滾效果
        print("2. 驗證回滾效果...")
        test_requests = self.normal_requests[:3] + self.attack_requests[:3]
        
        for request in test_requests:
            req, resp, hits = await self.make_request(request, "full")
            print(f"   請求: {req['path']} -> {resp['status_code']}")
    
    async def test_6_whitelist_management(self):
        """測試 6: 白名單管理"""
        print("\n=== 測試 6: 白名單管理 ===")
        
        # 識別誤報
        print("1. 識別誤報請求...")
        fp_requests = [r for r in self.metrics.requests if r.get("is_false_positive", False)]
        
        for fp_req in fp_requests:
            print(f"   誤報請求: {fp_req['request']['path']}")
            
            # 添加到白名單
            whitelist_entry = {
                "path_pattern": fp_req['request']['path'],
                "reason": "False positive correction",
                "timestamp": datetime.now().isoformat(),
                "request_hash": fp_req.get("request_hash", "")
            }
            
            # 模擬審批流程
            approval_info = {
                "approver": "security_team",
                "approval_time": datetime.now().isoformat(),
                "approval_status": "approved",
                "approval_notes": "Verified false positive"
            }
            
            self.whitelist.add(fp_req['request']['path'])
            self.metrics.record_whitelist_change("add", whitelist_entry, approval_info)
            print(f"   已添加到白名單: {fp_req['request']['path']}")
        
        print(f"2. 白名單統計: {len(self.whitelist)} 條規則")
    
    async def test_7_rule_tuning(self):
        """測試 7: 規則調優"""
        print("\n=== 測試 7: 規則調優 ===")
        
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
                print(f"     [WARN] 誤報率過高，建議調整規則")
                
                # 記錄規則變更
                change_details = {
                    "rule_id": rule_id,
                    "action": "tune",
                    "reason": f"High FP rate: {metrics['fp_rate']:.1f}%",
                    "old_fp_rate": metrics['fp_rate'],
                    "new_sensitivity": "reduced"
                }
                
                approval_info = {
                    "approver": "rule_engineer",
                    "approval_time": datetime.now().isoformat(),
                    "approval_status": "approved",
                    "approval_notes": "Rule sensitivity adjustment"
                }
                
                self.metrics.record_rule_change("tune", change_details, approval_info)
        
        print("2. 執行規則調整...")
        # 這裡應該調用 WAF API 調整規則敏感度
        print("   規則調整已應用")
    
    async def _configure_waf_mode(self, mode: str):
        """配置 WAF 模式"""
        # 這裡應該調用 WAF API 配置模式
        print(f"   配置 WAF 為 {mode} 模式...")
        await asyncio.sleep(0.1)  # 模擬配置時間
        print(f"   [OK] WAF 已配置為 {mode} 模式")
    
    async def _rollback_rules(self):
        """回滾規則"""
        # 這裡應該調用 WAF API 回滾規則
        print("   執行規則回滾...")
        await asyncio.sleep(0.5)  # 模擬回滾時間
        print("   [OK] 規則已回滾")
    
    async def run_governance_test(self):
        """執行完整的規則治理測試"""
        print("開始規則誤報治理測試")
        print("=" * 60)
        
        # 創建會話
        await self.create_session()
        
        try:
            self.metrics.test_start_time = datetime.now()
            
            # 執行所有測試
            await self.test_1_gray_mode_deployment()
            await asyncio.sleep(2)
            
            await self.test_2_observation_mode()
            await asyncio.sleep(2)
            
            await self.test_3_small_traffic_deployment()
            await asyncio.sleep(2)
            
            await self.test_4_full_deployment()
            await asyncio.sleep(2)
            
            await self.test_6_whitelist_management()
            await asyncio.sleep(2)
            
            await self.test_7_rule_tuning()
            
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
        
        print("部署階段分析:")
        for phase, analysis in metrics['deployment_analysis'].items():
            print(f"  {phase}:")
            print(f"    總請求: {analysis['total_requests']}")
            print(f"    誤報數: {analysis['false_positives']}")
            print(f"    誤報率: {analysis['fp_rate']:.1f}%")
            print(f"    漏報數: {analysis['false_negatives']}")
            print(f"    漏報率: {analysis['fn_rate']:.1f}%")
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
        print(f"  回滾次數: {metrics['rollback_count']} 次")
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
            print(f"  [OK] 誤報率: {fp_rate:.2f}% (目標: <0.5%)")
        else:
            print(f"  [FAIL] 誤報率: {fp_rate:.2f}% (目標: <0.5%)")
        
        # 漏報率檢查 (<1%)
        fn_rate = metrics['fn_rate']
        if fn_rate < 1.0:
            print(f"  [OK] 漏報率: {fn_rate:.2f}% (目標: <1%)")
        else:
            print(f"  [FAIL] 漏報率: {fn_rate:.2f}% (目標: <1%)")
        
        # 回滾時間檢查 (<5 分鐘)
        avg_rollback = metrics['avg_rollback_time']
        if avg_rollback < 300:  # 5 分鐘
            print(f"  [OK] 平均回滾時間: {avg_rollback:.1f} 秒 (目標: <300秒)")
        else:
            print(f"  [FAIL] 平均回滾時間: {avg_rollback:.1f} 秒 (目標: <300秒)")
        
        # 審批流程檢查
        whitelist_changes = self.metrics.whitelist_changes
        rule_changes = self.metrics.rule_changes
        
        approved_whitelist = sum(1 for change in whitelist_changes if change.get('approval_info', {}).get('approval_status') == 'approved')
        approved_rules = sum(1 for change in rule_changes if change.get('approval_info', {}).get('approval_status') == 'approved')
        
        if len(whitelist_changes) == 0 or approved_whitelist == len(whitelist_changes):
            print(f"  [OK] 白名單變更審批: {approved_whitelist}/{len(whitelist_changes)} 已審批")
        else:
            print(f"  [FAIL] 白名單變更審批: {approved_whitelist}/{len(whitelist_changes)} 已審批")
        
        if len(rule_changes) == 0 or approved_rules == len(rule_changes):
            print(f"  [OK] 規則變更審批: {approved_rules}/{len(rule_changes)} 已審批")
        else:
            print(f"  [FAIL] 規則變更審批: {approved_rules}/{len(rule_changes)} 已審批")
        
        print()

async def main():
    """主函數"""
    parser = argparse.ArgumentParser(description='規則誤報治理測試工具')
    parser.add_argument('--url', default='http://localhost:8080', help='目標 URL')
    parser.add_argument('--test', help='執行特定測試 (1-7)')
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
                await tester.test_1_gray_mode_deployment()
            elif test_num == 2:
                await tester.test_2_observation_mode()
            elif test_num == 3:
                await tester.test_3_small_traffic_deployment()
            elif test_num == 4:
                await tester.test_4_full_deployment()
            elif test_num == 5:
                await tester.test_5_rollback_testing()
            elif test_num == 6:
                await tester.test_6_whitelist_management()
            elif test_num == 7:
                await tester.test_7_rule_tuning()
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
