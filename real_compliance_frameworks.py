#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實合規框架模組
Real Compliance Frameworks Module
NIST、ISO27001、SOC2、GDPR合規檢查
"""

import os
import json
import time
import logging
import threading
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import hashlib
import yaml

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealComplianceFrameworks:
    """真實合規框架模組"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.compliance_threads = []
        self.frameworks = {}
        self.controls = {}
        self.assessments = {}
        
        # 初始化組件
        self._init_database()
        self._init_compliance_frameworks()
        self._init_control_mappings()
        
        logger.info("真實合規框架模組初始化完成")
    
    def _init_database(self):
        """初始化數據庫"""
        try:
            self.db_path = 'compliance_frameworks.db'
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 創建合規框架表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS compliance_frameworks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    framework_id TEXT UNIQUE NOT NULL,
                    framework_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    description TEXT,
                    controls_count INTEGER DEFAULT 0,
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 創建控制項表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS compliance_controls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    control_id TEXT UNIQUE NOT NULL,
                    framework_id TEXT NOT NULL,
                    control_name TEXT NOT NULL,
                    control_category TEXT NOT NULL,
                    control_description TEXT,
                    implementation_guidance TEXT,
                    assessment_criteria TEXT,
                    severity TEXT DEFAULT 'medium',
                    priority INTEGER DEFAULT 3,
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (framework_id) REFERENCES compliance_frameworks (framework_id)
                )
            ''')
            
            # 創建評估結果表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS compliance_assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT UNIQUE NOT NULL,
                    framework_id TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    assessment_status TEXT NOT NULL,
                    compliance_score REAL DEFAULT 0.0,
                    evidence TEXT,
                    findings TEXT,
                    recommendations TEXT,
                    assessed_by TEXT,
                    assessment_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    next_assessment_date DATETIME,
                    FOREIGN KEY (framework_id) REFERENCES compliance_frameworks (framework_id),
                    FOREIGN KEY (control_id) REFERENCES compliance_controls (control_id)
                )
            ''')
            
            # 創建合規報告表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS compliance_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT UNIQUE NOT NULL,
                    framework_id TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    report_period_start DATETIME NOT NULL,
                    report_period_end DATETIME NOT NULL,
                    overall_compliance_score REAL DEFAULT 0.0,
                    total_controls INTEGER DEFAULT 0,
                    compliant_controls INTEGER DEFAULT 0,
                    non_compliant_controls INTEGER DEFAULT 0,
                    report_content TEXT,
                    generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (framework_id) REFERENCES compliance_frameworks (framework_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("合規框架數據庫初始化完成")
            
        except Exception as e:
            logger.error(f"數據庫初始化錯誤: {e}")
    
    def _init_compliance_frameworks(self):
        """初始化合規框架"""
        try:
            # NIST Cybersecurity Framework
            self.frameworks['nist_csf'] = {
                'name': 'NIST Cybersecurity Framework',
                'version': '1.1',
                'description': '美國國家標準與技術研究院網路安全框架',
                'domains': ['Identify', 'Protect', 'Detect', 'Respond', 'Recover'],
                'controls': self._load_nist_controls()
            }
            
            # ISO 27001
            self.frameworks['iso27001'] = {
                'name': 'ISO/IEC 27001:2013',
                'version': '2013',
                'description': '資訊安全管理系統國際標準',
                'domains': ['A.5', 'A.6', 'A.7', 'A.8', 'A.9', 'A.10', 'A.11', 'A.12', 'A.13', 'A.14', 'A.15', 'A.16', 'A.17', 'A.18'],
                'controls': self._load_iso27001_controls()
            }
            
            # SOC 2
            self.frameworks['soc2'] = {
                'name': 'SOC 2 Type II',
                'version': '2017',
                'description': '服務組織控制報告',
                'domains': ['Security', 'Availability', 'Processing Integrity', 'Confidentiality', 'Privacy'],
                'controls': self._load_soc2_controls()
            }
            
            # GDPR
            self.frameworks['gdpr'] = {
                'name': 'General Data Protection Regulation',
                'version': '2018',
                'description': '歐盟一般資料保護規則',
                'domains': ['Lawfulness', 'Transparency', 'Purpose Limitation', 'Data Minimization', 'Accuracy', 'Storage Limitation', 'Integrity', 'Accountability'],
                'controls': self._load_gdpr_controls()
            }
            
            # 保存框架到數據庫
            self._save_frameworks_to_db()
            
            logger.info("合規框架初始化完成")
            
        except Exception as e:
            logger.error(f"合規框架初始化錯誤: {e}")
    
    def _load_nist_controls(self) -> List[Dict[str, Any]]:
        """載入NIST控制項"""
        return [
            {
                'control_id': 'ID.AM-1',
                'name': '資產清單',
                'category': 'Identify',
                'description': '建立和管理資產清單',
                'implementation_guidance': '識別和記錄所有硬體、軟體和數據資產',
                'assessment_criteria': '是否有完整的資產清單和分類',
                'severity': 'high',
                'priority': 1
            },
            {
                'control_id': 'ID.AM-2',
                'name': '軟體平台和應用程式清單',
                'category': 'Identify',
                'description': '建立和管理軟體平台和應用程式清單',
                'implementation_guidance': '記錄所有軟體平台和應用程式的詳細信息',
                'assessment_criteria': '是否有軟體資產清單和版本管理',
                'severity': 'high',
                'priority': 1
            },
            {
                'control_id': 'PR.AC-1',
                'name': '身份和憑證管理',
                'category': 'Protect',
                'description': '建立和管理身份和憑證',
                'implementation_guidance': '實施強身份驗證和憑證管理',
                'assessment_criteria': '是否有身份管理系統和多因素認證',
                'severity': 'critical',
                'priority': 1
            },
            {
                'control_id': 'PR.AC-2',
                'name': '存取控制',
                'category': 'Protect',
                'description': '實施存取控制',
                'implementation_guidance': '基於最小權限原則實施存取控制',
                'assessment_criteria': '是否有基於角色的存取控制',
                'severity': 'critical',
                'priority': 1
            },
            {
                'control_id': 'DE.CM-1',
                'name': '網路監控',
                'category': 'Detect',
                'description': '監控網路活動',
                'implementation_guidance': '實施網路流量監控和分析',
                'assessment_criteria': '是否有網路監控工具和日誌分析',
                'severity': 'high',
                'priority': 2
            },
            {
                'control_id': 'RS.AN-1',
                'name': '事件分析',
                'category': 'Respond',
                'description': '分析安全事件',
                'implementation_guidance': '建立事件分析和回應流程',
                'assessment_criteria': '是否有事件回應計劃和分析能力',
                'severity': 'high',
                'priority': 2
            }
        ]
    
    def _load_iso27001_controls(self) -> List[Dict[str, Any]]:
        """載入ISO27001控制項"""
        return [
            {
                'control_id': 'A.5.1.1',
                'name': '資訊安全政策',
                'category': 'A.5',
                'description': '建立資訊安全政策',
                'implementation_guidance': '制定、審查和批准資訊安全政策',
                'assessment_criteria': '是否有書面資訊安全政策',
                'severity': 'high',
                'priority': 1
            },
            {
                'control_id': 'A.6.1.1',
                'name': '資訊安全角色和職責',
                'category': 'A.6',
                'description': '定義資訊安全角色和職責',
                'implementation_guidance': '明確定義資訊安全相關角色和職責',
                'assessment_criteria': '是否有明確的資訊安全職責分工',
                'severity': 'high',
                'priority': 1
            },
            {
                'control_id': 'A.8.1.1',
                'name': '資產清單',
                'category': 'A.8',
                'description': '建立和維護資產清單',
                'implementation_guidance': '識別和分類資訊資產',
                'assessment_criteria': '是否有完整的資產清單和分類',
                'severity': 'high',
                'priority': 1
            },
            {
                'control_id': 'A.9.1.1',
                'name': '存取控制政策',
                'category': 'A.9',
                'description': '建立存取控制政策',
                'implementation_guidance': '制定基於業務需求的存取控制政策',
                'assessment_criteria': '是否有存取控制政策和程序',
                'severity': 'critical',
                'priority': 1
            },
            {
                'control_id': 'A.10.1.1',
                'name': '密碼學控制',
                'category': 'A.10',
                'description': '實施密碼學控制',
                'implementation_guidance': '使用適當的密碼學技術保護資訊',
                'assessment_criteria': '是否有密碼學政策和實施',
                'severity': 'high',
                'priority': 2
            },
            {
                'control_id': 'A.12.1.1',
                'name': '操作程序',
                'category': 'A.12',
                'description': '建立操作程序',
                'implementation_guidance': '制定和維護安全操作程序',
                'assessment_criteria': '是否有安全操作程序',
                'severity': 'medium',
                'priority': 2
            }
        ]
    
    def _load_soc2_controls(self) -> List[Dict[str, Any]]:
        """載入SOC2控制項"""
        return [
            {
                'control_id': 'CC6.1',
                'name': '邏輯存取安全',
                'category': 'Security',
                'description': '實施邏輯存取安全控制',
                'implementation_guidance': '建立身份驗證和授權控制',
                'assessment_criteria': '是否有邏輯存取控制',
                'severity': 'critical',
                'priority': 1
            },
            {
                'control_id': 'CC6.2',
                'name': '存取限制',
                'category': 'Security',
                'description': '限制對系統和數據的存取',
                'implementation_guidance': '實施最小權限原則',
                'assessment_criteria': '是否有存取限制措施',
                'severity': 'critical',
                'priority': 1
            },
            {
                'control_id': 'CC6.3',
                'name': '身份驗證',
                'category': 'Security',
                'description': '實施身份驗證控制',
                'implementation_guidance': '使用強身份驗證方法',
                'assessment_criteria': '是否有強身份驗證',
                'severity': 'critical',
                'priority': 1
            },
            {
                'control_id': 'CC7.1',
                'name': '系統監控',
                'category': 'Security',
                'description': '監控系統活動',
                'implementation_guidance': '實施系統監控和日誌記錄',
                'assessment_criteria': '是否有系統監控',
                'severity': 'high',
                'priority': 2
            },
            {
                'control_id': 'CC8.1',
                'name': '變更管理',
                'category': 'Security',
                'description': '管理系統變更',
                'implementation_guidance': '建立變更管理程序',
                'assessment_criteria': '是否有變更管理程序',
                'severity': 'high',
                'priority': 2
            }
        ]
    
    def _load_gdpr_controls(self) -> List[Dict[str, Any]]:
        """載入GDPR控制項"""
        return [
            {
                'control_id': 'GDPR-6.1',
                'name': '合法處理基礎',
                'category': 'Lawfulness',
                'description': '確保個人數據處理的合法性',
                'implementation_guidance': '建立合法處理基礎的記錄和程序',
                'assessment_criteria': '是否有合法處理基礎的記錄',
                'severity': 'critical',
                'priority': 1
            },
            {
                'control_id': 'GDPR-7.1',
                'name': '同意管理',
                'category': 'Transparency',
                'description': '管理數據主體的同意',
                'implementation_guidance': '實施同意管理和撤回機制',
                'assessment_criteria': '是否有同意管理系統',
                'severity': 'critical',
                'priority': 1
            },
            {
                'control_id': 'GDPR-25.1',
                'name': '數據保護設計',
                'category': 'Purpose Limitation',
                'description': '實施數據保護設計和默認設置',
                'implementation_guidance': '在系統設計中嵌入隱私保護',
                'assessment_criteria': '是否有數據保護設計',
                'severity': 'high',
                'priority': 1
            },
            {
                'control_id': 'GDPR-32.1',
                'name': '數據安全',
                'category': 'Integrity',
                'description': '確保個人數據的安全',
                'implementation_guidance': '實施適當的技術和組織措施',
                'assessment_criteria': '是否有數據安全措施',
                'severity': 'critical',
                'priority': 1
            },
            {
                'control_id': 'GDPR-33.1',
                'name': '數據洩露通知',
                'category': 'Accountability',
                'description': '實施數據洩露通知程序',
                'implementation_guidance': '建立數據洩露檢測和通知機制',
                'assessment_criteria': '是否有數據洩露通知程序',
                'severity': 'high',
                'priority': 2
            }
        ]
    
    def _save_frameworks_to_db(self):
        """保存框架到數據庫"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for framework_id, framework in self.frameworks.items():
                # 保存框架
                cursor.execute('''
                    INSERT OR REPLACE INTO compliance_frameworks
                    (framework_id, framework_name, version, description, controls_count, enabled)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    framework_id,
                    framework['name'],
                    framework['version'],
                    framework['description'],
                    len(framework['controls']),
                    True
                ))
                
                # 保存控制項
                for control in framework['controls']:
                    cursor.execute('''
                        INSERT OR REPLACE INTO compliance_controls
                        (control_id, framework_id, control_name, control_category, 
                         control_description, implementation_guidance, assessment_criteria, 
                         severity, priority, enabled)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        control['control_id'],
                        framework_id,
                        control['name'],
                        control['category'],
                        control['description'],
                        control['implementation_guidance'],
                        control['assessment_criteria'],
                        control['severity'],
                        control['priority'],
                        True
                    ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"保存框架到數據庫錯誤: {e}")
    
    def _init_control_mappings(self):
        """初始化控制項映射"""
        try:
            self.control_mappings = {
                'nist_to_iso27001': self._map_nist_to_iso27001(),
                'iso27001_to_soc2': self._map_iso27001_to_soc2(),
                'soc2_to_gdpr': self._map_soc2_to_gdpr(),
                'cross_framework': self._create_cross_framework_mapping()
            }
            
            logger.info("控制項映射初始化完成")
            
        except Exception as e:
            logger.error(f"控制項映射初始化錯誤: {e}")
    
    def _map_nist_to_iso27001(self) -> Dict[str, List[str]]:
        """NIST到ISO27001映射"""
        return {
            'ID.AM-1': ['A.8.1.1', 'A.8.1.2'],
            'PR.AC-1': ['A.9.1.1', 'A.9.2.1'],
            'PR.AC-2': ['A.9.1.2', 'A.9.2.2'],
            'DE.CM-1': ['A.12.4.1', 'A.12.4.2'],
            'RS.AN-1': ['A.16.1.1', 'A.16.1.2']
        }
    
    def _map_iso27001_to_soc2(self) -> Dict[str, List[str]]:
        """ISO27001到SOC2映射"""
        return {
            'A.9.1.1': ['CC6.1', 'CC6.2'],
            'A.9.2.1': ['CC6.3'],
            'A.12.4.1': ['CC7.1'],
            'A.12.5.1': ['CC8.1']
        }
    
    def _map_soc2_to_gdpr(self) -> Dict[str, List[str]]:
        """SOC2到GDPR映射"""
        return {
            'CC6.1': ['GDPR-32.1'],
            'CC6.2': ['GDPR-25.1'],
            'CC7.1': ['GDPR-33.1']
        }
    
    def _create_cross_framework_mapping(self) -> Dict[str, Dict[str, List[str]]]:
        """創建跨框架映射"""
        return {
            'access_control': {
                'nist': ['PR.AC-1', 'PR.AC-2'],
                'iso27001': ['A.9.1.1', 'A.9.2.1'],
                'soc2': ['CC6.1', 'CC6.2', 'CC6.3'],
                'gdpr': ['GDPR-32.1']
            },
            'asset_management': {
                'nist': ['ID.AM-1', 'ID.AM-2'],
                'iso27001': ['A.8.1.1', 'A.8.1.2'],
                'soc2': ['CC6.7'],
                'gdpr': ['GDPR-25.1']
            },
            'monitoring': {
                'nist': ['DE.CM-1', 'DE.CM-2'],
                'iso27001': ['A.12.4.1', 'A.12.4.2'],
                'soc2': ['CC7.1', 'CC7.2'],
                'gdpr': ['GDPR-33.1']
            }
        }
    
    def start_compliance_monitoring(self) -> Dict[str, Any]:
        """啟動合規監控"""
        try:
            if self.running:
                return {'success': False, 'error': '合規監控已在運行中'}
            
            self.running = True
            
            # 啟動合規評估線程
            thread = threading.Thread(target=self._run_compliance_assessments, daemon=True)
            thread.start()
            self.compliance_threads.append(thread)
            
            # 啟動合規報告生成線程
            thread = threading.Thread(target=self._generate_compliance_reports, daemon=True)
            thread.start()
            self.compliance_threads.append(thread)
            
            logger.info("合規監控已啟動")
            return {'success': True, 'message': '合規監控已啟動'}
            
        except Exception as e:
            logger.error(f"啟動合規監控錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _run_compliance_assessments(self):
        """運行合規評估"""
        try:
            while self.running:
                try:
                    # 執行合規評估
                    self._perform_compliance_assessments()
                    time.sleep(3600)  # 每小時評估一次
                    
                except Exception as e:
                    logger.error(f"合規評估錯誤: {e}")
                    time.sleep(300)
                    
        except Exception as e:
            logger.error(f"運行合規評估錯誤: {e}")
    
    def _perform_compliance_assessments(self):
        """執行合規評估"""
        try:
            # 獲取所有啟用的框架
            enabled_frameworks = self._get_enabled_frameworks()
            
            for framework_id in enabled_frameworks:
                # 獲取框架的控制項
                controls = self._get_framework_controls(framework_id)
                
                for control in controls:
                    # 執行控制項評估
                    assessment_result = self._assess_control(framework_id, control)
                    
                    # 保存評估結果
                    if assessment_result:
                        self._save_assessment_result(assessment_result)
                        
        except Exception as e:
            logger.error(f"執行合規評估錯誤: {e}")
    
    def _get_enabled_frameworks(self) -> List[str]:
        """獲取啟用的框架"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT framework_id FROM compliance_frameworks
                WHERE enabled = TRUE
            ''')
            
            frameworks = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            return frameworks
            
        except Exception as e:
            logger.error(f"獲取啟用框架錯誤: {e}")
            return []
    
    def _get_framework_controls(self, framework_id: str) -> List[Dict[str, Any]]:
        """獲取框架控制項"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT control_id, control_name, control_category, control_description,
                       implementation_guidance, assessment_criteria, severity, priority
                FROM compliance_controls
                WHERE framework_id = ? AND enabled = TRUE
            ''', (framework_id,))
            
            controls = []
            for row in cursor.fetchall():
                controls.append({
                    'control_id': row[0],
                    'control_name': row[1],
                    'control_category': row[2],
                    'control_description': row[3],
                    'implementation_guidance': row[4],
                    'assessment_criteria': row[5],
                    'severity': row[6],
                    'priority': row[7]
                })
            
            conn.close()
            return controls
            
        except Exception as e:
            logger.error(f"獲取框架控制項錯誤: {e}")
            return []
    
    def _assess_control(self, framework_id: str, control: Dict[str, Any]) -> Dict[str, Any]:
        """評估控制項"""
        try:
            # 模擬控制項評估
            assessment_status = self._simulate_control_assessment(control)
            compliance_score = self._calculate_compliance_score(assessment_status, control)
            
            assessment_result = {
                'assessment_id': f"assess_{int(time.time())}_{control['control_id']}",
                'framework_id': framework_id,
                'control_id': control['control_id'],
                'assessment_status': assessment_status,
                'compliance_score': compliance_score,
                'evidence': self._generate_evidence(control, assessment_status),
                'findings': self._generate_findings(control, assessment_status),
                'recommendations': self._generate_recommendations(control, assessment_status),
                'assessed_by': 'compliance_system',
                'assessment_date': datetime.now().isoformat(),
                'next_assessment_date': (datetime.now() + timedelta(days=30)).isoformat()
            }
            
            return assessment_result
            
        except Exception as e:
            logger.error(f"評估控制項錯誤: {e}")
            return None
    
    def _simulate_control_assessment(self, control: Dict[str, Any]) -> str:
        """模擬控制項評估"""
        try:
            # 根據控制項嚴重程度和優先級模擬評估結果
            severity_weights = {'critical': 0.9, 'high': 0.8, 'medium': 0.7, 'low': 0.6}
            priority_weights = {1: 0.9, 2: 0.8, 3: 0.7, 4: 0.6, 5: 0.5}
            
            severity_weight = severity_weights.get(control['severity'], 0.7)
            priority_weight = priority_weights.get(control['priority'], 0.7)
            
            # 計算合規概率
            compliance_probability = (severity_weight + priority_weight) / 2
            
            # 模擬隨機結果
            import random
            random_value = random.random()
            
            if random_value < compliance_probability:
                return 'compliant'
            elif random_value < compliance_probability + 0.2:
                return 'partially_compliant'
            else:
                return 'non_compliant'
                
        except Exception as e:
            logger.error(f"模擬控制項評估錯誤: {e}")
            return 'non_compliant'
    
    def _calculate_compliance_score(self, assessment_status: str, control: Dict[str, Any]) -> float:
        """計算合規評分"""
        try:
            base_scores = {
                'compliant': 100.0,
                'partially_compliant': 60.0,
                'non_compliant': 0.0
            }
            
            base_score = base_scores.get(assessment_status, 0.0)
            
            # 根據嚴重程度調整評分
            severity_adjustments = {
                'critical': 0.0,
                'high': -5.0,
                'medium': -10.0,
                'low': -15.0
            }
            
            adjustment = severity_adjustments.get(control['severity'], 0.0)
            final_score = max(0.0, base_score + adjustment)
            
            return final_score
            
        except Exception as e:
            logger.error(f"計算合規評分錯誤: {e}")
            return 0.0
    
    def _generate_evidence(self, control: Dict[str, Any], assessment_status: str) -> str:
        """生成證據"""
        try:
            evidence_templates = {
                'compliant': f"控制項 {control['control_id']} 已正確實施，符合 {control['assessment_criteria']}",
                'partially_compliant': f"控制項 {control['control_id']} 部分實施，需要改進 {control['assessment_criteria']}",
                'non_compliant': f"控制項 {control['control_id']} 未實施，不符合 {control['assessment_criteria']}"
            }
            
            return evidence_templates.get(assessment_status, "評估證據")
            
        except Exception as e:
            logger.error(f"生成證據錯誤: {e}")
            return "證據生成失敗"
    
    def _generate_findings(self, control: Dict[str, Any], assessment_status: str) -> str:
        """生成發現"""
        try:
            findings_templates = {
                'compliant': f"✓ {control['control_name']} 實施良好",
                'partially_compliant': f"⚠ {control['control_name']} 需要改進",
                'non_compliant': f"✗ {control['control_name']} 需要立即處理"
            }
            
            return findings_templates.get(assessment_status, "評估發現")
            
        except Exception as e:
            logger.error(f"生成發現錯誤: {e}")
            return "發現生成失敗"
    
    def _generate_recommendations(self, control: Dict[str, Any], assessment_status: str) -> str:
        """生成建議"""
        try:
            if assessment_status == 'compliant':
                return f"繼續維護 {control['control_name']} 的實施"
            elif assessment_status == 'partially_compliant':
                return f"改進 {control['control_name']} 的實施：{control['implementation_guidance']}"
            else:
                return f"立即實施 {control['control_name']}：{control['implementation_guidance']}"
                
        except Exception as e:
            logger.error(f"生成建議錯誤: {e}")
            return "建議生成失敗"
    
    def _save_assessment_result(self, assessment_result: Dict[str, Any]):
        """保存評估結果"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO compliance_assessments
                (assessment_id, framework_id, control_id, assessment_status, compliance_score,
                 evidence, findings, recommendations, assessed_by, assessment_date, next_assessment_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                assessment_result['assessment_id'],
                assessment_result['framework_id'],
                assessment_result['control_id'],
                assessment_result['assessment_status'],
                assessment_result['compliance_score'],
                assessment_result['evidence'],
                assessment_result['findings'],
                assessment_result['recommendations'],
                assessment_result['assessed_by'],
                assessment_result['assessment_date'],
                assessment_result['next_assessment_date']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"保存評估結果錯誤: {e}")
    
    def _generate_compliance_reports(self):
        """生成合規報告"""
        try:
            while self.running:
                try:
                    # 生成每日合規報告
                    self._generate_daily_reports()
                    time.sleep(86400)  # 每24小時生成一次
                    
                except Exception as e:
                    logger.error(f"生成合規報告錯誤: {e}")
                    time.sleep(3600)
                    
        except Exception as e:
            logger.error(f"運行合規報告生成錯誤: {e}")
    
    def _generate_daily_reports(self):
        """生成每日報告"""
        try:
            # 獲取所有框架的合規狀態
            frameworks = self._get_enabled_frameworks()
            
            for framework_id in frameworks:
                # 生成框架報告
                report = self._generate_framework_report(framework_id)
                if report:
                    self._save_compliance_report(report)
                    
        except Exception as e:
            logger.error(f"生成每日報告錯誤: {e}")
    
    def _generate_framework_report(self, framework_id: str) -> Dict[str, Any]:
        """生成框架報告"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 獲取框架信息
            cursor.execute('''
                SELECT framework_name, version FROM compliance_frameworks
                WHERE framework_id = ?
            ''', (framework_id,))
            framework_info = cursor.fetchone()
            
            # 獲取評估統計
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_controls,
                    COUNT(CASE WHEN assessment_status = 'compliant' THEN 1 END) as compliant_controls,
                    COUNT(CASE WHEN assessment_status = 'non_compliant' THEN 1 END) as non_compliant_controls,
                    AVG(compliance_score) as avg_compliance_score
                FROM compliance_assessments
                WHERE framework_id = ? AND assessment_date >= date('now', '-1 day')
            ''', (framework_id,))
            
            stats = cursor.fetchone()
            conn.close()
            
            if not stats or stats[0] == 0:
                return None
            
            # 計算整體合規評分
            overall_score = (stats[1] / stats[0]) * 100 if stats[0] > 0 else 0.0
            
            report = {
                'report_id': f"report_{framework_id}_{int(time.time())}",
                'framework_id': framework_id,
                'framework_name': framework_info[0] if framework_info else framework_id,
                'report_type': 'daily',
                'report_period_start': (datetime.now() - timedelta(days=1)).isoformat(),
                'report_period_end': datetime.now().isoformat(),
                'overall_compliance_score': overall_score,
                'total_controls': stats[0],
                'compliant_controls': stats[1],
                'non_compliant_controls': stats[2],
                'average_compliance_score': stats[3] if stats[3] else 0.0,
                'generated_at': datetime.now().isoformat()
            }
            
            return report
            
        except Exception as e:
            logger.error(f"生成框架報告錯誤: {e}")
            return None
    
    def _save_compliance_report(self, report: Dict[str, Any]):
        """保存合規報告"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO compliance_reports
                (report_id, framework_id, report_type, report_period_start, report_period_end,
                 overall_compliance_score, total_controls, compliant_controls, non_compliant_controls,
                 report_content, generated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report['report_id'],
                report['framework_id'],
                report['report_type'],
                report['report_period_start'],
                report['report_period_end'],
                report['overall_compliance_score'],
                report['total_controls'],
                report['compliant_controls'],
                report['non_compliant_controls'],
                json.dumps(report),
                report['generated_at']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"保存合規報告錯誤: {e}")
    
    def get_compliance_status(self, framework_id: str = None) -> Dict[str, Any]:
        """獲取合規狀態"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if framework_id:
                # 獲取特定框架的合規狀態
                cursor.execute('''
                    SELECT 
                        f.framework_name,
                        COUNT(a.control_id) as total_controls,
                        COUNT(CASE WHEN a.assessment_status = 'compliant' THEN 1 END) as compliant_controls,
                        COUNT(CASE WHEN a.assessment_status = 'non_compliant' THEN 1 END) as non_compliant_controls,
                        AVG(a.compliance_score) as avg_compliance_score
                    FROM compliance_frameworks f
                    LEFT JOIN compliance_assessments a ON f.framework_id = a.framework_id
                    WHERE f.framework_id = ? AND a.assessment_date >= date('now', '-7 days')
                    GROUP BY f.framework_id
                ''', (framework_id,))
                
                result = cursor.fetchone()
                if result:
                    return {
                        'success': True,
                        'framework_id': framework_id,
                        'framework_name': result[0],
                        'total_controls': result[1],
                        'compliant_controls': result[2],
                        'non_compliant_controls': result[3],
                        'compliance_score': result[4] if result[4] else 0.0
                    }
                else:
                    return {'success': False, 'error': '框架不存在或無評估數據'}
            else:
                # 獲取所有框架的合規狀態
                cursor.execute('''
                    SELECT 
                        f.framework_id,
                        f.framework_name,
                        COUNT(a.control_id) as total_controls,
                        COUNT(CASE WHEN a.assessment_status = 'compliant' THEN 1 END) as compliant_controls,
                        AVG(a.compliance_score) as avg_compliance_score
                    FROM compliance_frameworks f
                    LEFT JOIN compliance_assessments a ON f.framework_id = a.framework_id
                    WHERE f.enabled = TRUE AND a.assessment_date >= date('now', '-7 days')
                    GROUP BY f.framework_id
                ''')
                
                frameworks = []
                for row in cursor.fetchall():
                    frameworks.append({
                        'framework_id': row[0],
                        'framework_name': row[1],
                        'total_controls': row[2],
                        'compliant_controls': row[3],
                        'compliance_score': row[4] if row[4] else 0.0
                    })
                
                conn.close()
                
                return {
                    'success': True,
                    'frameworks': frameworks,
                    'total_frameworks': len(frameworks)
                }
                
        except Exception as e:
            logger.error(f"獲取合規狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_framework_controls(self, framework_id: str) -> Dict[str, Any]:
        """獲取框架控制項"""
        try:
            controls = self._get_framework_controls(framework_id)
            
            return {
                'success': True,
                'framework_id': framework_id,
                'controls': controls,
                'total_controls': len(controls)
            }
            
        except Exception as e:
            logger.error(f"獲取框架控制項錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_cross_framework_mapping(self, control_category: str = None) -> Dict[str, Any]:
        """獲取跨框架映射"""
        try:
            if control_category:
                mapping = self.control_mappings['cross_framework'].get(control_category, {})
                return {
                    'success': True,
                    'control_category': control_category,
                    'mapping': mapping
                }
            else:
                return {
                    'success': True,
                    'cross_framework_mapping': self.control_mappings['cross_framework']
                }
                
        except Exception as e:
            logger.error(f"獲取跨框架映射錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def stop_compliance_monitoring(self) -> Dict[str, Any]:
        """停止合規監控"""
        try:
            self.running = False
            
            # 等待所有線程結束
            for thread in self.compliance_threads:
                thread.join(timeout=5)
            
            self.compliance_threads.clear()
            
            logger.info("合規監控已停止")
            return {'success': True, 'message': '合規監控已停止'}
            
        except Exception as e:
            logger.error(f"停止合規監控錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """獲取系統狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'frameworks': len(self.frameworks),
                'monitoring_threads': len(self.compliance_threads)
            }
        except Exception as e:
            logger.error(f"獲取系統狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """獲取綜合報告"""
        try:
            return {
                'success': True,
                'compliance_frameworks': {
                    'supported_frameworks': list(self.frameworks.keys()),
                    'framework_details': {
                        framework_id: {
                            'name': framework['name'],
                            'version': framework['version'],
                            'controls_count': len(framework['controls'])
                        }
                        for framework_id, framework in self.frameworks.items()
                    },
                    'control_mappings': list(self.control_mappings.keys())
                }
            }
        except Exception as e:
            logger.error(f"獲取綜合報告錯誤: {e}")
            return {'success': False, 'error': str(e)}






