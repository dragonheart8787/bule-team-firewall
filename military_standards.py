#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事標準和協議系統
Military Standards and Protocols System

功能特色：
- NIST網路安全框架
- ISO 27001資訊安全管理
- Common Criteria評估
- FIPS 140-2加密標準
- STIG安全技術實施指南
- CIS控制措施
- 軍事分類等級
- 合規性評估
"""

import json
import time
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import threading
from collections import defaultdict, deque
import yaml

logger = logging.getLogger(__name__)

class StandardType(Enum):
    """標準類型"""
    NIST = "NIST"
    ISO = "ISO"
    COMMON_CRITERIA = "COMMON_CRITERIA"
    FIPS = "FIPS"
    STIG = "STIG"
    CIS = "CIS"
    MILITARY = "MILITARY"
    CUSTOM = "CUSTOM"

class ComplianceLevel(Enum):
    """合規等級"""
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    COMPLIANT = "COMPLIANT"
    FULLY_COMPLIANT = "FULLY_COMPLIANT"

class ClassificationLevel(Enum):
    """分類等級"""
    UNCLASSIFIED = "UNCLASSIFIED"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP_SECRET"
    COMPARTMENTED = "COMPARTMENTED"
    SPECIAL_ACCESS = "SPECIAL_ACCESS"

class ControlCategory(Enum):
    """控制類別"""
    IDENTIFY = "IDENTIFY"
    PROTECT = "PROTECT"
    DETECT = "DETECT"
    RESPOND = "RESPOND"
    RECOVER = "RECOVER"

@dataclass
class SecurityControl:
    """安全控制"""
    id: str
    name: str
    description: str
    standard: StandardType
    category: ControlCategory
    priority: int
    implementation_guidance: str
    assessment_procedures: List[str]
    remediation_guidance: str
    references: List[str]

@dataclass
class ComplianceAssessment:
    """合規評估"""
    id: str
    standard: StandardType
    control_id: str
    assessment_date: datetime
    assessor: str
    compliance_level: ComplianceLevel
    evidence: List[str]
    findings: List[str]
    recommendations: List[str]
    next_assessment: datetime

@dataclass
class ClassificationPolicy:
    """分類政策"""
    id: str
    name: str
    classification_level: ClassificationLevel
    handling_requirements: Dict[str, Any]
    access_controls: List[str]
    retention_period: int
    destruction_method: str
    marking_requirements: List[str]

class MilitaryStandardsManager:
    """軍事標準管理器"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.security_controls: Dict[str, SecurityControl] = {}
        self.compliance_assessments: Dict[str, ComplianceAssessment] = {}
        self.classification_policies: Dict[str, ClassificationPolicy] = {}
        self.assessment_schedules: Dict[str, datetime] = {}
        
        # 合規統計
        self.compliance_stats = {
            'total_controls': 0,
            'compliant_controls': 0,
            'non_compliant_controls': 0,
            'assessments_completed': 0,
            'critical_findings': 0
        }
        
        # 初始化資料庫
        self._init_database()
        
        # 載入標準控制措施
        self._load_security_controls()
        
        # 載入分類政策
        self._load_classification_policies()
        
        # 啟動合規監控
        self._start_compliance_monitoring()
        
        logger.info("軍事標準管理系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('military_standards.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立安全控制表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_controls (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                standard TEXT,
                category TEXT,
                priority INTEGER,
                implementation_guidance TEXT,
                assessment_procedures TEXT,
                remediation_guidance TEXT,
                references TEXT
            )
        ''')
        
        # 建立合規評估表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_assessments (
                id TEXT PRIMARY KEY,
                standard TEXT,
                control_id TEXT,
                assessment_date TIMESTAMP,
                assessor TEXT,
                compliance_level TEXT,
                evidence TEXT,
                findings TEXT,
                recommendations TEXT,
                next_assessment TIMESTAMP
            )
        ''')
        
        # 建立分類政策表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS classification_policies (
                id TEXT PRIMARY KEY,
                name TEXT,
                classification_level TEXT,
                handling_requirements TEXT,
                access_controls TEXT,
                retention_period INTEGER,
                destruction_method TEXT,
                marking_requirements TEXT
            )
        ''')
        
        self.db_conn.commit()

    def _load_security_controls(self):
        """載入安全控制措施"""
        # NIST網路安全框架控制措施
        nist_controls = [
            SecurityControl(
                id="NIST-AC-1",
                name="存取控制政策和程序",
                description="建立、記錄、審查和更新存取控制政策和程序",
                standard=StandardType.NIST,
                category=ControlCategory.PROTECT,
                priority=1,
                implementation_guidance="制定明確的存取控制政策，包括角色定義、權限管理和定期審查程序",
                assessment_procedures=["檢查存取控制政策文件", "驗證政策實施情況", "審查定期更新記錄"],
                remediation_guidance="如發現政策缺失或過時，應立即制定或更新相關政策",
                references=["NIST SP 800-53", "NIST Cybersecurity Framework"]
            ),
            SecurityControl(
                id="NIST-AC-2",
                name="帳戶管理",
                description="管理資訊系統帳戶，包括建立、啟用、修改、停用和移除",
                standard=StandardType.NIST,
                category=ControlCategory.PROTECT,
                priority=1,
                implementation_guidance="實施自動化帳戶管理程序，包括生命週期管理和定期審查",
                assessment_procedures=["檢查帳戶管理程序", "驗證帳戶生命週期管理", "審查帳戶審查記錄"],
                remediation_guidance="建立自動化帳戶管理系統，實施定期帳戶審查",
                references=["NIST SP 800-53", "NIST Cybersecurity Framework"]
            ),
            SecurityControl(
                id="NIST-SC-1",
                name="系統和通訊保護政策和程序",
                description="建立、記錄、審查和更新系統和通訊保護政策和程序",
                standard=StandardType.NIST,
                category=ControlCategory.PROTECT,
                priority=1,
                implementation_guidance="制定系統和通訊保護政策，包括加密、網路分段和通訊安全",
                assessment_procedures=["檢查保護政策文件", "驗證加密實施", "審查網路分段配置"],
                remediation_guidance="實施強加密和網路分段，建立通訊安全程序",
                references=["NIST SP 800-53", "NIST Cybersecurity Framework"]
            )
        ]
        
        # ISO 27001控制措施
        iso_controls = [
            SecurityControl(
                id="ISO-A.9.1",
                name="存取控制業務需求",
                description="存取控制應基於業務和資訊安全需求",
                standard=StandardType.ISO,
                category=ControlCategory.PROTECT,
                priority=1,
                implementation_guidance="根據業務需求定義存取控制要求，包括最小權限原則",
                assessment_procedures=["檢查存取控制需求文件", "驗證業務需求對應", "審查權限分配"],
                remediation_guidance="重新評估存取控制需求，確保符合業務要求",
                references=["ISO/IEC 27001", "ISO/IEC 27002"]
            ),
            SecurityControl(
                id="ISO-A.10.1",
                name="密碼學控制",
                description="應使用密碼學來保護資訊的機密性、真實性或完整性",
                standard=StandardType.ISO,
                category=ControlCategory.PROTECT,
                priority=1,
                implementation_guidance="實施適當的密碼學控制，包括加密算法和密鑰管理",
                assessment_procedures=["檢查密碼學政策", "驗證加密實施", "審查密鑰管理程序"],
                remediation_guidance="更新密碼學政策，實施強加密和密鑰管理",
                references=["ISO/IEC 27001", "ISO/IEC 27002"]
            )
        ]
        
        # FIPS 140-2控制措施
        fips_controls = [
            SecurityControl(
                id="FIPS-140-2-1",
                name="密碼學模組安全",
                description="密碼學模組應符合FIPS 140-2安全要求",
                standard=StandardType.FIPS,
                category=ControlCategory.PROTECT,
                priority=1,
                implementation_guidance="使用FIPS 140-2認證的密碼學模組，確保安全等級符合要求",
                assessment_procedures=["檢查FIPS認證證書", "驗證模組配置", "審查安全等級"],
                remediation_guidance="更換為FIPS 140-2認證的密碼學模組",
                references=["FIPS 140-2", "NIST SP 800-140B"]
            )
        ]
        
        # 合併所有控制措施
        all_controls = nist_controls + iso_controls + fips_controls
        
        for control in all_controls:
            self.security_controls[control.id] = control
            self._save_security_control(control)

    def _load_classification_policies(self):
        """載入分類政策"""
        classification_policies = [
            ClassificationPolicy(
                id="POL-001",
                name="機密資訊處理政策",
                classification_level=ClassificationLevel.CONFIDENTIAL,
                handling_requirements={
                    "storage": "加密儲存",
                    "transmission": "加密傳輸",
                    "access": "需要授權",
                    "disposal": "安全銷毀"
                },
                access_controls=["身份驗證", "授權檢查", "審計記錄"],
                retention_period=7,  # 年
                destruction_method="物理銷毀或加密擦除",
                marking_requirements=["文件標記", "系統標記", "傳輸標記"]
            ),
            ClassificationPolicy(
                id="POL-002",
                name="機密資訊處理政策",
                classification_level=ClassificationLevel.SECRET,
                handling_requirements={
                    "storage": "強加密儲存",
                    "transmission": "強加密傳輸",
                    "access": "多因子認證",
                    "disposal": "物理銷毀"
                },
                access_controls=["多因子認證", "角色授權", "完整審計", "背景調查"],
                retention_period=10,  # 年
                destruction_method="物理銷毀",
                marking_requirements=["文件標記", "系統標記", "傳輸標記", "人員標記"]
            ),
            ClassificationPolicy(
                id="POL-003",
                name="最高機密資訊處理政策",
                classification_level=ClassificationLevel.TOP_SECRET,
                handling_requirements={
                    "storage": "最高級加密儲存",
                    "transmission": "最高級加密傳輸",
                    "access": "生物識別認證",
                    "disposal": "物理銷毀"
                },
                access_controls=["生物識別認證", "最高級授權", "完整審計", "深度背景調查"],
                retention_period=20,  # 年
                destruction_method="物理銷毀",
                marking_requirements=["文件標記", "系統標記", "傳輸標記", "人員標記", "設施標記"]
            )
        ]
        
        for policy in classification_policies:
            self.classification_policies[policy.id] = policy
            self._save_classification_policy(policy)

    def assess_compliance(self, standard: StandardType, 
                         control_id: str, assessor: str) -> ComplianceAssessment:
        """執行合規評估"""
        if control_id not in self.security_controls:
            raise ValueError(f"安全控制不存在: {control_id}")
        
        control = self.security_controls[control_id]
        
        # 執行評估程序
        findings = []
        evidence = []
        compliance_level = ComplianceLevel.COMPLIANT
        
        for procedure in control.assessment_procedures:
            # 模擬評估程序
            result = self._execute_assessment_procedure(procedure, control)
            evidence.append(f"{procedure}: {result['status']}")
            
            if result['status'] == 'FAILED':
                findings.append(f"{procedure}: {result['finding']}")
                if compliance_level == ComplianceLevel.COMPLIANT:
                    compliance_level = ComplianceLevel.PARTIALLY_COMPLIANT
                elif compliance_level == ComplianceLevel.PARTIALLY_COMPLIANT:
                    compliance_level = ComplianceLevel.NON_COMPLIANT
        
        # 生成建議
        recommendations = self._generate_recommendations(control, findings)
        
        assessment = ComplianceAssessment(
            id=self._generate_assessment_id(),
            standard=standard,
            control_id=control_id,
            assessment_date=datetime.now(),
            assessor=assessor,
            compliance_level=compliance_level,
            evidence=evidence,
            findings=findings,
            recommendations=recommendations,
            next_assessment=datetime.now() + timedelta(days=90)
        )
        
        self.compliance_assessments[assessment.id] = assessment
        self._save_compliance_assessment(assessment)
        
        # 更新統計
        self._update_compliance_stats(assessment)
        
        logger.info(f"合規評估完成: {control.name} - {compliance_level.value}")
        return assessment

    def _execute_assessment_procedure(self, procedure: str, control: SecurityControl) -> Dict[str, Any]:
        """執行評估程序"""
        # 模擬評估程序執行
        import random
        
        # 基於控制類型模擬不同的成功率
        if control.standard == StandardType.NIST:
            success_rate = 0.8
        elif control.standard == StandardType.ISO:
            success_rate = 0.75
        elif control.standard == StandardType.FIPS:
            success_rate = 0.7
        else:
            success_rate = 0.6
        
        if random.random() < success_rate:
            return {
                'status': 'PASSED',
                'finding': '符合要求'
            }
        else:
            return {
                'status': 'FAILED',
                'finding': '發現合規問題'
            }

    def _generate_recommendations(self, control: SecurityControl, findings: List[str]) -> List[str]:
        """生成建議"""
        recommendations = []
        
        if findings:
            recommendations.append(control.remediation_guidance)
            recommendations.append("實施定期監控和審查程序")
            recommendations.append("加強員工培訓和意識提升")
        else:
            recommendations.append("維持現有控制措施")
            recommendations.append("定期審查和更新控制措施")
        
        return recommendations

    def get_compliance_status(self, standard: StandardType) -> Dict[str, Any]:
        """獲取合規狀態"""
        standard_assessments = [
            assessment for assessment in self.compliance_assessments.values()
            if assessment.standard == standard
        ]
        
        if not standard_assessments:
            return {
                'standard': standard.value,
                'status': 'NOT_ASSESSED',
                'compliance_rate': 0.0,
                'total_controls': 0,
                'assessed_controls': 0
            }
        
        total_controls = len([c for c in self.security_controls.values() if c.standard == standard])
        assessed_controls = len(standard_assessments)
        
        compliant_count = len([a for a in standard_assessments if a.compliance_level in [ComplianceLevel.COMPLIANT, ComplianceLevel.FULLY_COMPLIANT]])
        compliance_rate = compliant_count / assessed_controls if assessed_controls > 0 else 0.0
        
        return {
            'standard': standard.value,
            'status': 'ASSESSED',
            'compliance_rate': compliance_rate,
            'total_controls': total_controls,
            'assessed_controls': assessed_controls,
            'compliant_controls': compliant_count,
            'non_compliant_controls': assessed_controls - compliant_count,
            'last_assessment': max(a.assessment_date for a in standard_assessments).isoformat()
        }

    def classify_information(self, information: str, 
                           classification_level: ClassificationLevel) -> Dict[str, Any]:
        """分類資訊"""
        if classification_level not in [p.classification_level for p in self.classification_policies.values()]:
            raise ValueError(f"不支援的分類等級: {classification_level}")
        
        # 找到對應的分類政策
        policy = None
        for p in self.classification_policies.values():
            if p.classification_level == classification_level:
                policy = p
                break
        
        classification_result = {
            'information_id': self._generate_information_id(),
            'classification_level': classification_level.value,
            'classification_date': datetime.now().isoformat(),
            'handling_requirements': policy.handling_requirements,
            'access_controls': policy.access_controls,
            'retention_period': policy.retention_period,
            'destruction_method': policy.destruction_method,
            'marking_requirements': policy.marking_requirements,
            'policy_id': policy.id
        }
        
        logger.info(f"資訊已分類: {classification_level.value}")
        return classification_result

    def generate_compliance_report(self, standard: StandardType) -> Dict[str, Any]:
        """生成合規報告"""
        standard_controls = [c for c in self.security_controls.values() if c.standard == standard]
        standard_assessments = [a for a in self.compliance_assessments.values() if a.standard == standard]
        
        # 統計資訊
        total_controls = len(standard_controls)
        assessed_controls = len(standard_assessments)
        compliant_controls = len([a for a in standard_assessments if a.compliance_level in [ComplianceLevel.COMPLIANT, ComplianceLevel.FULLY_COMPLIANT]])
        
        # 按類別統計
        category_stats = {}
        for category in ControlCategory:
            category_controls = [c for c in standard_controls if c.category == category]
            category_assessments = [a for a in standard_assessments if a.control_id in [c.id for c in category_controls]]
            category_compliant = len([a for a in category_assessments if a.compliance_level in [ComplianceLevel.COMPLIANT, ComplianceLevel.FULLY_COMPLIANT]])
            
            category_stats[category.value] = {
                'total_controls': len(category_controls),
                'assessed_controls': len(category_assessments),
                'compliant_controls': category_compliant,
                'compliance_rate': category_compliant / len(category_assessments) if category_assessments else 0.0
            }
        
        # 關鍵發現
        critical_findings = []
        for assessment in standard_assessments:
            if assessment.compliance_level == ComplianceLevel.NON_COMPLIANT:
                critical_findings.extend(assessment.findings)
        
        return {
            'report_date': datetime.now().isoformat(),
            'standard': standard.value,
            'summary': {
                'total_controls': total_controls,
                'assessed_controls': assessed_controls,
                'compliant_controls': compliant_controls,
                'overall_compliance_rate': compliant_controls / assessed_controls if assessed_controls > 0 else 0.0
            },
            'category_statistics': category_stats,
            'critical_findings': critical_findings,
            'recommendations': self._generate_overall_recommendations(standard_assessments)
        }

    def _generate_overall_recommendations(self, assessments: List[ComplianceAssessment]) -> List[str]:
        """生成整體建議"""
        recommendations = []
        
        non_compliant_assessments = [a for a in assessments if a.compliance_level == ComplianceLevel.NON_COMPLIANT]
        
        if non_compliant_assessments:
            recommendations.append("立即修復不合規的控制措施")
            recommendations.append("加強安全控制實施和監控")
            recommendations.append("提供額外的員工培訓")
        
        recommendations.append("建立持續合規監控程序")
        recommendations.append("定期審查和更新安全控制措施")
        recommendations.append("實施自動化合規評估工具")
        
        return recommendations

    def _start_compliance_monitoring(self):
        """啟動合規監控"""
        def monitoring_loop():
            while True:
                try:
                    # 檢查需要重新評估的控制措施
                    self._check_assessment_schedules()
                    
                    # 更新合規統計
                    self._update_compliance_statistics()
                    
                    time.sleep(86400)  # 每天檢查一次
                
                except Exception as e:
                    logger.error(f"合規監控錯誤: {e}")
                    time.sleep(3600)  # 錯誤時等待1小時
        
        monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitoring_thread.start()

    def _check_assessment_schedules(self):
        """檢查評估排程"""
        current_time = datetime.now()
        
        for assessment in self.compliance_assessments.values():
            if current_time >= assessment.next_assessment:
                logger.info(f"控制措施 {assessment.control_id} 需要重新評估")
                # 這裡可以觸發自動重新評估

    def _update_compliance_statistics(self):
        """更新合規統計"""
        self.compliance_stats['total_controls'] = len(self.security_controls)
        self.compliance_stats['compliant_controls'] = len([
            a for a in self.compliance_assessments.values()
            if a.compliance_level in [ComplianceLevel.COMPLIANT, ComplianceLevel.FULLY_COMPLIANT]
        ])
        self.compliance_stats['non_compliant_controls'] = len([
            a for a in self.compliance_assessments.values()
            if a.compliance_level == ComplianceLevel.NON_COMPLIANT
        ])
        self.compliance_stats['assessments_completed'] = len(self.compliance_assessments)
        self.compliance_stats['critical_findings'] = len([
            f for a in self.compliance_assessments.values()
            for f in a.findings
        ])

    def _update_compliance_stats(self, assessment: ComplianceAssessment):
        """更新合規統計"""
        if assessment.compliance_level in [ComplianceLevel.COMPLIANT, ComplianceLevel.FULLY_COMPLIANT]:
            self.compliance_stats['compliant_controls'] += 1
        else:
            self.compliance_stats['non_compliant_controls'] += 1
        
        self.compliance_stats['assessments_completed'] += 1
        self.compliance_stats['critical_findings'] += len(assessment.findings)

    def _save_security_control(self, control: SecurityControl):
        """儲存安全控制"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO security_controls 
            (id, name, description, standard, category, priority, 
             implementation_guidance, assessment_procedures, remediation_guidance, references)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            control.id, control.name, control.description, control.standard.value,
            control.category.value, control.priority, control.implementation_guidance,
            json.dumps(control.assessment_procedures), control.remediation_guidance,
            json.dumps(control.references)
        ))
        self.db_conn.commit()

    def _save_compliance_assessment(self, assessment: ComplianceAssessment):
        """儲存合規評估"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO compliance_assessments 
            (id, standard, control_id, assessment_date, assessor, compliance_level,
             evidence, findings, recommendations, next_assessment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            assessment.id, assessment.standard.value, assessment.control_id,
            assessment.assessment_date.isoformat(), assessment.assessor,
            assessment.compliance_level.value, json.dumps(assessment.evidence),
            json.dumps(assessment.findings), json.dumps(assessment.recommendations),
            assessment.next_assessment.isoformat()
        ))
        self.db_conn.commit()

    def _save_classification_policy(self, policy: ClassificationPolicy):
        """儲存分類政策"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO classification_policies 
            (id, name, classification_level, handling_requirements, access_controls,
             retention_period, destruction_method, marking_requirements)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            policy.id, policy.name, policy.classification_level.value,
            json.dumps(policy.handling_requirements), json.dumps(policy.access_controls),
            policy.retention_period, policy.destruction_method,
            json.dumps(policy.marking_requirements)
        ))
        self.db_conn.commit()

    def _generate_assessment_id(self) -> str:
        """生成評估ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"ASSESS_{timestamp}"

    def _generate_information_id(self) -> str:
        """生成資訊ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"INFO_{timestamp}"

    def get_statistics(self) -> Dict[str, Any]:
        """獲取統計資訊"""
        return {
            'compliance_stats': self.compliance_stats,
            'total_standards': len(StandardType),
            'total_controls': len(self.security_controls),
            'total_assessments': len(self.compliance_assessments),
            'total_policies': len(self.classification_policies),
            'controls_by_standard': {
                standard.value: len([c for c in self.security_controls.values() if c.standard == standard])
                for standard in StandardType
            },
            'controls_by_category': {
                category.value: len([c for c in self.security_controls.values() if c.category == category])
                for category in ControlCategory
            }
        }

def main():
    """主程式"""
    config = {
        'assessment_interval': 90,  # 天
        'compliance_threshold': 0.8,
        'auto_assessment': True
    }
    
    standards_manager = MilitaryStandardsManager(config)
    
    # 執行合規評估
    assessment = standards_manager.assess_compliance(
        StandardType.NIST, 
        "NIST-AC-1", 
        "security_auditor"
    )
    
    print(f"合規評估結果: {assessment.compliance_level.value}")
    print(f"發現: {assessment.findings}")
    print(f"建議: {assessment.recommendations}")
    
    # 獲取合規狀態
    compliance_status = standards_manager.get_compliance_status(StandardType.NIST)
    print(f"NIST合規狀態: {compliance_status}")
    
    # 分類資訊
    classification = standards_manager.classify_information(
        "機密軍事資訊", 
        ClassificationLevel.SECRET
    )
    print(f"資訊分類: {classification}")
    
    # 生成合規報告
    report = standards_manager.generate_compliance_report(StandardType.NIST)
    print(f"合規報告: {report['summary']}")
    
    # 顯示統計
    stats = standards_manager.get_statistics()
    print(f"統計資訊: {stats}")

if __name__ == "__main__":
    main()


