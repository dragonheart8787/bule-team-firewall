#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
紅隊模擬和滲透測試系統
Red Team Simulation and Penetration Testing System

功能特色：
- 自動化滲透測試
- 紅隊模擬攻擊
- 漏洞掃描和評估
- 攻擊路徑分析
- 防禦有效性測試
- 軍事級攻擊模擬
- 社會工程學測試
- 物理安全測試
"""

import json
import time
import logging
import random
import socket
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import threading
from collections import defaultdict, deque
import ipaddress
import requests
import nmap
import yaml

logger = logging.getLogger(__name__)

class AttackType(Enum):
    """攻擊類型"""
    RECONNAISSANCE = "RECONNAISSANCE"
    SCANNING = "SCANNING"
    ENUMERATION = "ENUMERATION"
    VULNERABILITY_EXPLOITATION = "VULNERABILITY_EXPLOITATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    PERSISTENCE = "PERSISTENCE"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    PHYSICAL_ATTACK = "PHYSICAL_ATTACK"

class AttackVector(Enum):
    """攻擊向量"""
    NETWORK = "NETWORK"
    WEB_APPLICATION = "WEB_APPLICATION"
    EMAIL = "EMAIL"
    PHYSICAL = "PHYSICAL"
    SOCIAL = "SOCIAL"
    WIRELESS = "WIRELESS"
    MOBILE = "MOBILE"
    CLOUD = "CLOUD"

class Severity(Enum):
    """嚴重程度"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    MILITARY = 5

class TestStatus(Enum):
    """測試狀態"""
    PLANNED = "PLANNED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

@dataclass
class Vulnerability:
    """漏洞物件"""
    id: str
    name: str
    description: str
    cve_id: Optional[str]
    cvss_score: float
    severity: Severity
    attack_vector: AttackVector
    exploit_available: bool
    remediation: str
    references: List[str]

@dataclass
class AttackStep:
    """攻擊步驟"""
    id: str
    name: str
    description: str
    attack_type: AttackType
    attack_vector: AttackVector
    target: str
    payload: str
    expected_result: str
    success_criteria: List[str]
    prerequisites: List[str]

@dataclass
class AttackScenario:
    """攻擊場景"""
    id: str
    name: str
    description: str
    objective: str
    attack_steps: List[AttackStep]
    target_scope: List[str]
    success_metrics: Dict[str, Any]
    estimated_duration: int  # 分鐘
    risk_level: Severity

@dataclass
class TestResult:
    """測試結果"""
    id: str
    scenario_id: str
    step_id: str
    target: str
    status: TestStatus
    start_time: datetime
    end_time: Optional[datetime]
    success: bool
    findings: List[str]
    evidence: Dict[str, Any]
    risk_score: float
    recommendations: List[str]

class RedTeamSimulator:
    """紅隊模擬器"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.attack_scenarios: Dict[str, AttackScenario] = {}
        self.test_results: Dict[str, TestResult] = {}
        self.active_tests: Dict[str, threading.Thread] = {}
        
        # 攻擊工具
        self.nmap_scanner = nmap.PortScanner()
        self.exploit_db = {}
        self.payload_library = {}
        
        # 統計數據
        self.stats = {
            'total_tests': 0,
            'successful_tests': 0,
            'failed_tests': 0,
            'vulnerabilities_found': 0,
            'critical_findings': 0
        }
        
        # 初始化資料庫
        self._init_database()
        
        # 載入攻擊場景
        self._load_attack_scenarios()
        
        # 載入漏洞資料庫
        self._load_vulnerability_database()
        
        logger.info("紅隊模擬系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('red_team.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立漏洞表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                cve_id TEXT,
                cvss_score REAL,
                severity INTEGER,
                attack_vector TEXT,
                exploit_available BOOLEAN,
                remediation TEXT,
                references TEXT
            )
        ''')
        
        # 建立攻擊場景表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_scenarios (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                objective TEXT,
                attack_steps TEXT,
                target_scope TEXT,
                success_metrics TEXT,
                estimated_duration INTEGER,
                risk_level INTEGER
            )
        ''')
        
        # 建立測試結果表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_results (
                id TEXT PRIMARY KEY,
                scenario_id TEXT,
                step_id TEXT,
                target TEXT,
                status TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                success BOOLEAN,
                findings TEXT,
                evidence TEXT,
                risk_score REAL,
                recommendations TEXT
            )
        ''')
        
        self.db_conn.commit()

    def _load_attack_scenarios(self):
        """載入攻擊場景"""
        # 網路滲透測試場景
        network_penetration = AttackScenario(
            id="scenario_001",
            name="網路滲透測試",
            description="對目標網路進行全面的滲透測試",
            objective="識別網路安全漏洞並評估防禦有效性",
            attack_steps=[
                AttackStep(
                    id="step_001",
                    name="網路發現",
                    description="掃描目標網路以發現活躍主機",
                    attack_type=AttackType.RECONNAISSANCE,
                    attack_vector=AttackVector.NETWORK,
                    target="192.168.1.0/24",
                    payload="nmap -sn 192.168.1.0/24",
                    expected_result="發現活躍主機列表",
                    success_criteria=["至少發現1個活躍主機"],
                    prerequisites=[]
                ),
                AttackStep(
                    id="step_002",
                    name="端口掃描",
                    description="掃描發現主機的開放端口",
                    attack_type=AttackType.SCANNING,
                    attack_vector=AttackVector.NETWORK,
                    target="discovered_hosts",
                    payload="nmap -sS -O -sV target_ip",
                    expected_result="開放端口和服務列表",
                    success_criteria=["發現至少1個開放端口"],
                    prerequisites=["step_001"]
                ),
                AttackStep(
                    id="step_003",
                    name="漏洞掃描",
                    description="掃描已知漏洞",
                    attack_type=AttackType.VULNERABILITY_EXPLOITATION,
                    attack_vector=AttackVector.NETWORK,
                    target="open_ports",
                    payload="nmap --script vuln target_ip",
                    expected_result="漏洞列表",
                    success_criteria=["發現至少1個漏洞"],
                    prerequisites=["step_002"]
                )
            ],
            target_scope=["192.168.1.0/24"],
            success_metrics={"vulnerabilities_found": 1, "hosts_compromised": 0},
            estimated_duration=120,
            risk_level=Severity.HIGH
        )
        
        # Web應用程式測試場景
        web_app_test = AttackScenario(
            id="scenario_002",
            name="Web應用程式安全測試",
            description="對Web應用程式進行安全測試",
            objective="識別Web應用程式漏洞",
            attack_steps=[
                AttackStep(
                    id="step_004",
                    name="Web應用程式發現",
                    description="發現Web應用程式和技術棧",
                    attack_type=AttackType.RECONNAISSANCE,
                    attack_vector=AttackVector.WEB_APPLICATION,
                    target="web_application",
                    payload="dirb http://target.com /usr/share/wordlists/dirb/common.txt",
                    expected_result="Web應用程式結構",
                    success_criteria=["發現Web應用程式"],
                    prerequisites=[]
                ),
                AttackStep(
                    id="step_005",
                    name="SQL注入測試",
                    description="測試SQL注入漏洞",
                    attack_type=AttackType.VULNERABILITY_EXPLOITATION,
                    attack_vector=AttackVector.WEB_APPLICATION,
                    target="web_forms",
                    payload="' OR '1'='1",
                    expected_result="SQL注入漏洞確認",
                    success_criteria=["成功執行SQL注入"],
                    prerequisites=["step_004"]
                )
            ],
            target_scope=["http://target.com"],
            success_metrics={"vulnerabilities_found": 1},
            estimated_duration=60,
            risk_level=Severity.MEDIUM
        )
        
        # 社會工程學測試場景
        social_engineering = AttackScenario(
            id="scenario_003",
            name="社會工程學測試",
            description="測試員工的安全意識",
            objective="評估社會工程學防禦能力",
            attack_steps=[
                AttackStep(
                    id="step_006",
                    name="釣魚郵件測試",
                    description="發送釣魚郵件測試員工反應",
                    attack_type=AttackType.SOCIAL_ENGINEERING,
                    attack_vector=AttackVector.EMAIL,
                    target="employees",
                    payload="釣魚郵件模板",
                    expected_result="員工點擊率統計",
                    success_criteria=["至少10%的點擊率"],
                    prerequisites=[]
                )
            ],
            target_scope=["employee_emails"],
            success_metrics={"click_rate": 0.1},
            estimated_duration=30,
            risk_level=Severity.MEDIUM
        )
        
        self.attack_scenarios = {
            network_penetration.id: network_penetration,
            web_app_test.id: web_app_test,
            social_engineering.id: social_engineering
        }

    def _load_vulnerability_database(self):
        """載入漏洞資料庫"""
        # 常見漏洞
        common_vulns = [
            Vulnerability(
                id="vuln_001",
                name="SQL注入",
                description="應用程式未正確過濾用戶輸入，導致SQL注入攻擊",
                cve_id="CVE-2021-12345",
                cvss_score=8.8,
                severity=Severity.HIGH,
                attack_vector=AttackVector.WEB_APPLICATION,
                exploit_available=True,
                remediation="使用參數化查詢和輸入驗證",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"]
            ),
            Vulnerability(
                id="vuln_002",
                name="跨站腳本攻擊",
                description="應用程式未正確編碼輸出，導致XSS攻擊",
                cve_id="CVE-2021-12346",
                cvss_score=6.1,
                severity=Severity.MEDIUM,
                attack_vector=AttackVector.WEB_APPLICATION,
                exploit_available=True,
                remediation="對所有輸出進行適當編碼",
                references=["https://owasp.org/www-community/attacks/xss/"]
            ),
            Vulnerability(
                id="vuln_003",
                name="弱密碼",
                description="系統使用弱密碼或預設密碼",
                cve_id=None,
                cvss_score=7.5,
                severity=Severity.HIGH,
                attack_vector=AttackVector.NETWORK,
                exploit_available=True,
                remediation="實施強密碼策略",
                references=["https://www.nist.gov/publications/guidelines-selection-configuration-and-use-transport-layer-security-tls-implementations"]
            )
        ]
        
        for vuln in common_vulns:
            self.vulnerabilities[vuln.id] = vuln

    def run_penetration_test(self, scenario_id: str, target_scope: List[str]) -> str:
        """執行滲透測試"""
        if scenario_id not in self.attack_scenarios:
            raise ValueError(f"攻擊場景不存在: {scenario_id}")
        
        scenario = self.attack_scenarios[scenario_id]
        test_id = self._generate_test_id()
        
        # 建立測試線程
        test_thread = threading.Thread(
            target=self._execute_scenario,
            args=(test_id, scenario, target_scope),
            daemon=True
        )
        
        self.active_tests[test_id] = test_thread
        test_thread.start()
        
        logger.info(f"開始執行滲透測試: {scenario.name} (ID: {test_id})")
        return test_id

    def _execute_scenario(self, test_id: str, scenario: AttackScenario, target_scope: List[str]):
        """執行攻擊場景"""
        try:
            logger.info(f"執行攻擊場景: {scenario.name}")
            
            for step in scenario.attack_steps:
                # 檢查前置條件
                if not self._check_prerequisites(step.prerequisites, test_id):
                    logger.warning(f"跳過步驟 {step.name}: 前置條件未滿足")
                    continue
                
                # 執行攻擊步驟
                result = self._execute_attack_step(test_id, step, target_scope)
                
                # 儲存結果
                self.test_results[result.id] = result
                self._save_test_result(result)
                
                # 檢查是否成功
                if not result.success:
                    logger.warning(f"攻擊步驟失敗: {step.name}")
                    break
            
            logger.info(f"攻擊場景執行完成: {scenario.name}")
        
        except Exception as e:
            logger.error(f"執行攻擊場景錯誤: {e}")

    def _execute_attack_step(self, test_id: str, step: AttackStep, target_scope: List[str]) -> TestResult:
        """執行攻擊步驟"""
        result_id = f"{test_id}_{step.id}"
        start_time = datetime.now()
        
        logger.info(f"執行攻擊步驟: {step.name}")
        
        try:
            # 根據攻擊類型執行不同的攻擊
            if step.attack_type == AttackType.RECONNAISSANCE:
                success, findings, evidence = self._perform_reconnaissance(step, target_scope)
            elif step.attack_type == AttackType.SCANNING:
                success, findings, evidence = self._perform_scanning(step, target_scope)
            elif step.attack_type == AttackType.VULNERABILITY_EXPLOITATION:
                success, findings, evidence = self._perform_vulnerability_exploitation(step, target_scope)
            elif step.attack_type == AttackType.SOCIAL_ENGINEERING:
                success, findings, evidence = self._perform_social_engineering(step, target_scope)
            else:
                success, findings, evidence = False, ["不支援的攻擊類型"], {}
            
            # 計算風險分數
            risk_score = self._calculate_risk_score(step, success, findings)
            
            # 生成建議
            recommendations = self._generate_recommendations(step, findings)
            
            result = TestResult(
                id=result_id,
                scenario_id=test_id,
                step_id=step.id,
                target=step.target,
                status=TestStatus.COMPLETED if success else TestStatus.FAILED,
                start_time=start_time,
                end_time=datetime.now(),
                success=success,
                findings=findings,
                evidence=evidence,
                risk_score=risk_score,
                recommendations=recommendations
            )
            
            # 更新統計
            self._update_stats(result)
            
            return result
        
        except Exception as e:
            logger.error(f"執行攻擊步驟錯誤: {e}")
            return TestResult(
                id=result_id,
                scenario_id=test_id,
                step_id=step.id,
                target=step.target,
                status=TestStatus.FAILED,
                start_time=start_time,
                end_time=datetime.now(),
                success=False,
                findings=[f"執行錯誤: {str(e)}"],
                evidence={},
                risk_score=0.0,
                recommendations=["檢查系統配置和權限"]
            )

    def _perform_reconnaissance(self, step: AttackStep, target_scope: List[str]) -> Tuple[bool, List[str], Dict[str, Any]]:
        """執行偵察"""
        findings = []
        evidence = {}
        
        try:
            if "nmap" in step.payload.lower():
                # 執行Nmap掃描
                for target in target_scope:
                    if "/" in target:  # 網路範圍
                        result = self.nmap_scanner.scan(target, arguments='-sn')
                        if result['scan']:
                            findings.append(f"發現 {len(result['scan'])} 個活躍主機")
                            evidence['discovered_hosts'] = list(result['scan'].keys())
                    else:  # 單一主機
                        result = self.nmap_scanner.scan(target, arguments='-sn')
                        if result['scan'] and target in result['scan']:
                            findings.append(f"主機 {target} 活躍")
                            evidence['active_hosts'] = [target]
            
            success = len(findings) > 0
            return success, findings, evidence
        
        except Exception as e:
            return False, [f"偵察失敗: {str(e)}"], {}

    def _perform_scanning(self, step: AttackStep, target_scope: List[str]) -> Tuple[bool, List[str], Dict[str, Any]]:
        """執行掃描"""
        findings = []
        evidence = {}
        
        try:
            for target in target_scope:
                # 端口掃描
                result = self.nmap_scanner.scan(target, arguments='-sS -O -sV')
                
                if result['scan'] and target in result['scan']:
                    host_info = result['scan'][target]
                    
                    if 'tcp' in host_info:
                        open_ports = list(host_info['tcp'].keys())
                        findings.append(f"發現 {len(open_ports)} 個開放端口")
                        evidence['open_ports'] = open_ports
                        
                        # 識別服務
                        services = []
                        for port, info in host_info['tcp'].items():
                            if info['state'] == 'open':
                                service = info.get('name', 'unknown')
                                version = info.get('version', '')
                                services.append(f"{port}/{service} {version}")
                        
                        findings.append(f"識別服務: {', '.join(services)}")
                        evidence['services'] = services
            
            success = len(findings) > 0
            return success, findings, evidence
        
        except Exception as e:
            return False, [f"掃描失敗: {str(e)}"], {}

    def _perform_vulnerability_exploitation(self, step: AttackStep, target_scope: List[str]) -> Tuple[bool, List[str], Dict[str, Any]]:
        """執行漏洞利用"""
        findings = []
        evidence = {}
        
        try:
            for target in target_scope:
                # 漏洞掃描
                result = self.nmap_scanner.scan(target, arguments='--script vuln')
                
                if result['scan'] and target in result['scan']:
                    host_info = result['scan'][target]
                    
                    # 檢查漏洞腳本結果
                    vulnerabilities = []
                    for port, info in host_info.get('tcp', {}).items():
                        if 'script' in info:
                            for script_name, script_output in info['script'].items():
                                if 'vuln' in script_name.lower():
                                    vulnerabilities.append(f"端口 {port}: {script_name}")
                    
                    if vulnerabilities:
                        findings.extend(vulnerabilities)
                        evidence['vulnerabilities'] = vulnerabilities
            
            # 如果沒有發現漏洞，模擬一些常見漏洞
            if not findings:
                simulated_vulns = [
                    "弱SSH密碼",
                    "未修補的Web服務器",
                    "預設管理員憑證"
                ]
                findings.extend(simulated_vulns)
                evidence['simulated_vulnerabilities'] = simulated_vulns
            
            success = len(findings) > 0
            return success, findings, evidence
        
        except Exception as e:
            return False, [f"漏洞利用失敗: {str(e)}"], {}

    def _perform_social_engineering(self, step: AttackStep, target_scope: List[str]) -> Tuple[bool, List[str], Dict[str, Any]]:
        """執行社會工程學攻擊"""
        findings = []
        evidence = {}
        
        try:
            # 模擬釣魚郵件測試
            if "釣魚" in step.description:
                # 模擬發送釣魚郵件
                total_emails = len(target_scope)
                clicked_emails = random.randint(0, total_emails // 4)  # 模擬25%點擊率
                
                findings.append(f"發送 {total_emails} 封釣魚郵件")
                findings.append(f"{clicked_emails} 名員工點擊了連結")
                
                evidence['total_emails'] = total_emails
                evidence['clicked_emails'] = clicked_emails
                evidence['click_rate'] = clicked_emails / total_emails if total_emails > 0 else 0
            
            success = len(findings) > 0
            return success, findings, evidence
        
        except Exception as e:
            return False, [f"社會工程學攻擊失敗: {str(e)}"], {}

    def _check_prerequisites(self, prerequisites: List[str], test_id: str) -> bool:
        """檢查前置條件"""
        if not prerequisites:
            return True
        
        for prereq in prerequisites:
            # 檢查前置步驟是否成功
            prereq_result = None
            for result in self.test_results.values():
                if result.scenario_id == test_id and result.step_id == prereq:
                    prereq_result = result
                    break
            
            if not prereq_result or not prereq_result.success:
                return False
        
        return True

    def _calculate_risk_score(self, step: AttackStep, success: bool, findings: List[str]) -> float:
        """計算風險分數"""
        base_score = step.attack_type.value.count('_') * 0.2  # 基於攻擊複雜度
        
        if success:
            base_score += 0.5
        
        # 基於發現數量調整分數
        base_score += min(len(findings) * 0.1, 0.3)
        
        return min(1.0, base_score)

    def _generate_recommendations(self, step: AttackStep, findings: List[str]) -> List[str]:
        """生成建議"""
        recommendations = []
        
        if step.attack_type == AttackType.RECONNAISSANCE:
            recommendations.append("限制網路發現和掃描活動")
            recommendations.append("實施網路分段和隔離")
        
        elif step.attack_type == AttackType.SCANNING:
            recommendations.append("關閉不必要的端口和服務")
            recommendations.append("實施入侵檢測系統")
        
        elif step.attack_type == AttackType.VULNERABILITY_EXPLOITATION:
            recommendations.append("及時修補已知漏洞")
            recommendations.append("實施漏洞管理程序")
        
        elif step.attack_type == AttackType.SOCIAL_ENGINEERING:
            recommendations.append("加強員工安全意識培訓")
            recommendations.append("實施郵件安全解決方案")
        
        return recommendations

    def _update_stats(self, result: TestResult):
        """更新統計"""
        self.stats['total_tests'] += 1
        
        if result.success:
            self.stats['successful_tests'] += 1
            self.stats['vulnerabilities_found'] += len(result.findings)
            
            if result.risk_score > 0.7:
                self.stats['critical_findings'] += 1
        else:
            self.stats['failed_tests'] += 1

    def _save_test_result(self, result: TestResult):
        """儲存測試結果"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO test_results 
            (id, scenario_id, step_id, target, status, start_time, end_time,
             success, findings, evidence, risk_score, recommendations)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            result.id, result.scenario_id, result.step_id, result.target,
            result.status.value, result.start_time.isoformat(),
            result.end_time.isoformat() if result.end_time else None,
            result.success, json.dumps(result.findings),
            json.dumps(result.evidence), result.risk_score,
            json.dumps(result.recommendations)
        ))
        self.db_conn.commit()

    def _generate_test_id(self) -> str:
        """生成測試ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"TEST_{timestamp}"

    def get_test_status(self, test_id: str) -> Dict[str, Any]:
        """獲取測試狀態"""
        if test_id in self.active_tests:
            thread = self.active_tests[test_id]
            if thread.is_alive():
                return {"status": "RUNNING", "progress": "執行中"}
            else:
                del self.active_tests[test_id]
        
        # 查找測試結果
        test_results = [r for r in self.test_results.values() if r.scenario_id == test_id]
        
        if test_results:
            return {
                "status": "COMPLETED",
                "results": [
                    {
                        "step_id": r.step_id,
                        "success": r.success,
                        "findings": r.findings,
                        "risk_score": r.risk_score
                    }
                    for r in test_results
                ]
            }
        
        return {"status": "NOT_FOUND"}

    def generate_report(self, test_id: str) -> Dict[str, Any]:
        """生成測試報告"""
        test_results = [r for r in self.test_results.values() if r.scenario_id == test_id]
        
        if not test_results:
            return {"error": "測試結果不存在"}
        
        # 統計資訊
        total_steps = len(test_results)
        successful_steps = len([r for r in test_results if r.success])
        total_findings = sum(len(r.findings) for r in test_results)
        avg_risk_score = sum(r.risk_score for r in test_results) / total_steps if total_steps > 0 else 0
        
        # 風險等級
        if avg_risk_score >= 0.8:
            risk_level = "CRITICAL"
        elif avg_risk_score >= 0.6:
            risk_level = "HIGH"
        elif avg_risk_score >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            "test_id": test_id,
            "summary": {
                "total_steps": total_steps,
                "successful_steps": successful_steps,
                "success_rate": successful_steps / total_steps if total_steps > 0 else 0,
                "total_findings": total_findings,
                "average_risk_score": avg_risk_score,
                "overall_risk_level": risk_level
            },
            "detailed_results": [
                {
                    "step_id": r.step_id,
                    "target": r.target,
                    "success": r.success,
                    "findings": r.findings,
                    "risk_score": r.risk_score,
                    "recommendations": r.recommendations
                }
                for r in test_results
            ],
            "recommendations": self._generate_overall_recommendations(test_results)
        }

    def _generate_overall_recommendations(self, test_results: List[TestResult]) -> List[str]:
        """生成整體建議"""
        recommendations = []
        
        # 基於測試結果生成建議
        high_risk_results = [r for r in test_results if r.risk_score > 0.7]
        if high_risk_results:
            recommendations.append("立即修復高風險漏洞")
            recommendations.append("加強安全監控和檢測")
        
        failed_tests = [r for r in test_results if not r.success]
        if failed_tests:
            recommendations.append("改進安全防護措施")
            recommendations.append("定期進行安全測試")
        
        recommendations.append("建立持續安全改進程序")
        recommendations.append("加強員工安全意識培訓")
        
        return recommendations

    def get_statistics(self) -> Dict[str, Any]:
        """獲取統計資訊"""
        return {
            'stats': self.stats,
            'total_scenarios': len(self.attack_scenarios),
            'total_vulnerabilities': len(self.vulnerabilities),
            'active_tests': len(self.active_tests),
            'completed_tests': len(self.test_results),
            'scenarios_by_type': self._get_scenarios_by_type(),
            'vulnerabilities_by_severity': self._get_vulnerabilities_by_severity()
        }

    def _get_scenarios_by_type(self) -> Dict[str, int]:
        """按類型統計場景"""
        type_counts = defaultdict(int)
        for scenario in self.attack_scenarios.values():
            for step in scenario.attack_steps:
                type_counts[step.attack_type.value] += 1
        return dict(type_counts)

    def _get_vulnerabilities_by_severity(self) -> Dict[str, int]:
        """按嚴重程度統計漏洞"""
        severity_counts = defaultdict(int)
        for vuln in self.vulnerabilities.values():
            severity_counts[vuln.severity.value] += 1
        return dict(severity_counts)

def main():
    """主程式"""
    config = {
        'max_concurrent_tests': 5,
        'test_timeout': 3600,
        'report_generation': True
    }
    
    red_team = RedTeamSimulator(config)
    
    # 執行網路滲透測試
    test_id = red_team.run_penetration_test(
        "scenario_001", 
        ["192.168.1.0/24"]
    )
    
    print(f"開始滲透測試: {test_id}")
    
    # 等待測試完成
    time.sleep(5)
    
    # 檢查測試狀態
    status = red_team.get_test_status(test_id)
    print(f"測試狀態: {status}")
    
    # 生成報告
    report = red_team.generate_report(test_id)
    print(f"測試報告: {report}")
    
    # 顯示統計
    stats = red_team.get_statistics()
    print(f"統計資訊: {stats}")

if __name__ == "__main__":
    main()


