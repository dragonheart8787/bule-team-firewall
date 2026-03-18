#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級報告系統
實作 攻擊路徑圖, 證據收集, 風險評估 等功能
"""

import os
import sys
import json
import time
import hashlib
import base64
import struct
import socket
import threading
import subprocess
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

# 設定日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ReportType(Enum):
    """報告類型枚舉"""
    INCIDENT_RESPONSE = "incident_response"
    THREAT_ANALYSIS = "threat_analysis"
    PENETRATION_TEST = "penetration_test"
    COMPLIANCE_AUDIT = "compliance_audit"
    RISK_ASSESSMENT = "risk_assessment"
    EXECUTIVE_SUMMARY = "executive_summary"

class EvidenceType(Enum):
    """證據類型枚舉"""
    LOG_FILE = "log_file"
    MEMORY_DUMP = "memory_dump"
    NETWORK_PCAP = "network_pcap"
    SCREENSHOT = "screenshot"
    SYSTEM_FILE = "system_file"
    REGISTRY_KEY = "registry_key"
    DATABASE_RECORD = "database_record"

class RiskLevel(Enum):
    """風險等級枚舉"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class AttackNode:
    """攻擊節點資料結構"""
    id: str
    name: str
    type: str  # host, network, user, service
    ip_address: str = None
    hostname: str = None
    user: str = None
    service: str = None
    compromised: bool = False
    timestamp: str = None
    evidence: List[str] = None

@dataclass
class AttackEdge:
    """攻擊邊資料結構"""
    source: str
    target: str
    technique: str
    description: str
    timestamp: str
    confidence: float
    evidence: List[str] = None

@dataclass
class Evidence:
    """證據資料結構"""
    id: str
    type: EvidenceType
    name: str
    path: str
    hash_value: str
    size: int
    timestamp: str
    description: str
    metadata: Dict[str, Any] = None

@dataclass
class RiskAssessment:
    """風險評估資料結構"""
    id: str
    asset: str
    threat: str
    vulnerability: str
    impact: str
    likelihood: str
    risk_level: RiskLevel
    score: float
    mitigation: str
    timestamp: str

class AttackPathVisualizer:
    """攻擊路徑視覺化工具"""
    
    def __init__(self):
        self.nodes = []
        self.edges = []
        self.attack_graph = {}
    
    def add_attack_node(self, node: AttackNode) -> Dict[str, Any]:
        """添加攻擊節點"""
        try:
            self.nodes.append(node)
            self.attack_graph[node.id] = {
                'node': node,
                'connections': []
            }
            
            return {
                'success': True,
                'node_id': node.id,
                'message': f'攻擊節點已添加: {node.name}'
            }
        except Exception as e:
            logger.error(f"添加攻擊節點錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def add_attack_edge(self, edge: AttackEdge) -> Dict[str, Any]:
        """添加攻擊邊"""
        try:
            self.edges.append(edge)
            
            # 更新圖形結構
            if edge.source in self.attack_graph:
                self.attack_graph[edge.source]['connections'].append(edge.target)
            
            return {
                'success': True,
                'edge_id': f"{edge.source}_{edge.target}",
                'message': f'攻擊邊已添加: {edge.source} -> {edge.target}'
            }
        except Exception as e:
            logger.error(f"添加攻擊邊錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def generate_attack_path_diagram(self) -> Dict[str, Any]:
        """生成攻擊路徑圖"""
        try:
            # 生成 Mermaid 圖表
            mermaid_code = self._generate_mermaid_diagram()
            
            # 生成 Graphviz DOT 格式
            dot_code = self._generate_dot_diagram()
            
            # 生成 JSON 格式的圖形資料
            graph_data = self._generate_graph_data()
            
            return {
                'success': True,
                'mermaid_code': mermaid_code,
                'dot_code': dot_code,
                'graph_data': graph_data,
                'total_nodes': len(self.nodes),
                'total_edges': len(self.edges)
            }
        except Exception as e:
            logger.error(f"生成攻擊路徑圖錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _generate_mermaid_diagram(self) -> str:
        """生成 Mermaid 圖表"""
        mermaid_lines = ["graph TD"]
        
        # 添加節點
        for node in self.nodes:
            node_style = "fill:#ff6b6b" if node.compromised else "fill:#4ecdc4"
            mermaid_lines.append(f'    {node.id}["{node.name}"]')
        
        # 添加邊
        for edge in self.edges:
            mermaid_lines.append(f'    {edge.source} -->|"{edge.technique}"| {edge.target}')
        
        return "\n".join(mermaid_lines)
    
    def _generate_dot_diagram(self) -> str:
        """生成 Graphviz DOT 圖表"""
        dot_lines = ["digraph AttackPath {"]
        dot_lines.append("    rankdir=LR;")
        dot_lines.append("    node [shape=box, style=filled];")
        
        # 添加節點
        for node in self.nodes:
            color = "red" if node.compromised else "lightblue"
            dot_lines.append(f'    {node.id} [label="{node.name}", fillcolor={color}];')
        
        # 添加邊
        for edge in self.edges:
            dot_lines.append(f'    {edge.source} -> {edge.target} [label="{edge.technique}"];')
        
        dot_lines.append("}")
        return "\n".join(dot_lines)
    
    def _generate_graph_data(self) -> Dict[str, Any]:
        """生成圖形資料"""
        return {
            'nodes': [self._node_to_dict(node) for node in self.nodes],
            'edges': [self._edge_to_dict(edge) for edge in self.edges],
            'metadata': {
                'total_nodes': len(self.nodes),
                'total_edges': len(self.edges),
                'compromised_nodes': len([n for n in self.nodes if n.compromised]),
                'generated_at': datetime.now().isoformat()
            }
        }
    
    def _node_to_dict(self, node: AttackNode) -> Dict[str, Any]:
        """將節點轉換為字典"""
        return {
            'id': node.id,
            'name': node.name,
            'type': node.type,
            'ip_address': node.ip_address,
            'hostname': node.hostname,
            'user': node.user,
            'service': node.service,
            'compromised': node.compromised,
            'timestamp': node.timestamp,
            'evidence': node.evidence
        }
    
    def _edge_to_dict(self, edge: AttackEdge) -> Dict[str, Any]:
        """將邊轉換為字典"""
        return {
            'source': edge.source,
            'target': edge.target,
            'technique': edge.technique,
            'description': edge.description,
            'timestamp': edge.timestamp,
            'confidence': edge.confidence,
            'evidence': edge.evidence
        }

class EvidenceCollector:
    """證據收集工具"""
    
    def __init__(self):
        self.db_path = "evidence.db"
        self.evidence_list = []
        self._init_database()
    
    def _init_database(self):
        """初始化資料庫"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL,
                    hash_value TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    description TEXT NOT NULL,
                    metadata TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"資料庫初始化錯誤: {e}")
    
    def collect_evidence(self, evidence_path: str, evidence_type: EvidenceType, 
                        description: str = "") -> Dict[str, Any]:
        """收集證據"""
        try:
            if not os.path.exists(evidence_path):
                return {'success': False, 'error': '證據檔案不存在'}
            
            # 計算檔案雜湊
            with open(evidence_path, 'rb') as f:
                content = f.read()
                hash_value = hashlib.sha256(content).hexdigest()
            
            # 獲取檔案資訊
            stat = os.stat(evidence_path)
            
            evidence = Evidence(
                id=f"evidence_{int(time.time())}",
                type=evidence_type,
                name=os.path.basename(evidence_path),
                path=evidence_path,
                hash_value=hash_value,
                size=stat.st_size,
                timestamp=datetime.now().isoformat(),
                description=description,
                metadata={
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'permissions': oct(stat.st_mode)
                }
            )
            
            # 儲存到資料庫
            self._save_evidence(evidence)
            self.evidence_list.append(evidence)
            
            return {
                'success': True,
                'evidence_id': evidence.id,
                'message': f'證據已收集: {evidence.name}'
            }
        except Exception as e:
            logger.error(f"證據收集錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _save_evidence(self, evidence: Evidence):
        """儲存證據到資料庫"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO evidence 
                (id, type, name, path, hash_value, size, timestamp, description, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                evidence.id, evidence.type.value, evidence.name, evidence.path,
                evidence.hash_value, evidence.size, evidence.timestamp, evidence.description,
                json.dumps(evidence.metadata) if evidence.metadata else None
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"證據儲存錯誤: {e}")
    
    def get_evidence_by_type(self, evidence_type: EvidenceType) -> List[Evidence]:
        """根據類型獲取證據"""
        return [e for e in self.evidence_list if e.type == evidence_type]
    
    def get_evidence_summary(self) -> Dict[str, Any]:
        """獲取證據摘要"""
        summary = {
            'total_evidence': len(self.evidence_list),
            'evidence_by_type': {},
            'total_size': sum(e.size for e in self.evidence_list),
            'evidence_timeline': []
        }
        
        # 按類型分組
        for evidence in self.evidence_list:
            evidence_type = evidence.type.value
            if evidence_type not in summary['evidence_by_type']:
                summary['evidence_by_type'][evidence_type] = 0
            summary['evidence_by_type'][evidence_type] += 1
        
        # 時間線
        for evidence in sorted(self.evidence_list, key=lambda x: x.timestamp):
            summary['evidence_timeline'].append({
                'timestamp': evidence.timestamp,
                'name': evidence.name,
                'type': evidence.type.value,
                'size': evidence.size
            })
        
        return summary

class RiskAssessmentEngine:
    """風險評估引擎"""
    
    def __init__(self):
        self.assessments = []
        self.risk_matrix = self._init_risk_matrix()
    
    def _init_risk_matrix(self) -> Dict[str, Dict[str, float]]:
        """初始化風險矩陣"""
        return {
            'impact': {
                'critical': 5.0,
                'high': 4.0,
                'medium': 3.0,
                'low': 2.0,
                'info': 1.0
            },
            'likelihood': {
                'very_high': 5.0,
                'high': 4.0,
                'medium': 3.0,
                'low': 2.0,
                'very_low': 1.0
            }
        }
    
    def assess_risk(self, asset: str, threat: str, vulnerability: str, 
                   impact: str, likelihood: str) -> Dict[str, Any]:
        """評估風險"""
        try:
            # 計算風險分數
            impact_score = self.risk_matrix['impact'].get(impact.lower(), 1.0)
            likelihood_score = self.risk_matrix['likelihood'].get(likelihood.lower(), 1.0)
            risk_score = impact_score * likelihood_score
            
            # 確定風險等級
            if risk_score >= 20.0:
                risk_level = RiskLevel.CRITICAL
            elif risk_score >= 15.0:
                risk_level = RiskLevel.HIGH
            elif risk_score >= 10.0:
                risk_level = RiskLevel.MEDIUM
            elif risk_score >= 5.0:
                risk_level = RiskLevel.LOW
            else:
                risk_level = RiskLevel.INFO
            
            # 生成緩解建議
            mitigation = self._generate_mitigation_recommendations(risk_level, threat, vulnerability)
            
            assessment = RiskAssessment(
                id=f"risk_{int(time.time())}",
                asset=asset,
                threat=threat,
                vulnerability=vulnerability,
                impact=impact,
                likelihood=likelihood,
                risk_level=risk_level,
                score=risk_score,
                mitigation=mitigation,
                timestamp=datetime.now().isoformat()
            )
            
            self.assessments.append(assessment)
            
            return {
                'success': True,
                'assessment_id': assessment.id,
                'risk_score': risk_score,
                'risk_level': risk_level.value,
                'mitigation': mitigation
            }
        except Exception as e:
            logger.error(f"風險評估錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _generate_mitigation_recommendations(self, risk_level: RiskLevel, threat: str, vulnerability: str) -> str:
        """生成緩解建議"""
        recommendations = []
        
        if risk_level == RiskLevel.CRITICAL:
            recommendations.extend([
                "立即實施緊急緩解措施",
                "隔離受影響的系統",
                "通知高階管理層",
                "啟動事件回應程序"
            ])
        elif risk_level == RiskLevel.HIGH:
            recommendations.extend([
                "優先修復漏洞",
                "加強監控和檢測",
                "實施額外的安全控制",
                "定期安全評估"
            ])
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.extend([
                "制定修復計劃",
                "加強安全意識培訓",
                "實施預防措施",
                "定期檢查和更新"
            ])
        else:
            recommendations.extend([
                "持續監控",
                "定期評估",
                "保持安全最佳實踐"
            ])
        
        # 根據威脅類型添加特定建議
        if "malware" in threat.lower():
            recommendations.append("部署進階惡意軟體防護")
        if "phishing" in threat.lower():
            recommendations.append("實施電子郵件安全解決方案")
        if "insider" in threat.lower():
            recommendations.append("加強存取控制和監控")
        
        return "; ".join(recommendations)
    
    def get_risk_summary(self) -> Dict[str, Any]:
        """獲取風險摘要"""
        if not self.assessments:
            return {'total_assessments': 0, 'risk_distribution': {}, 'average_score': 0.0}
        
        risk_distribution = {}
        total_score = 0.0
        
        for assessment in self.assessments:
            risk_level = assessment.risk_level.value
            if risk_level not in risk_distribution:
                risk_distribution[risk_level] = 0
            risk_distribution[risk_level] += 1
            total_score += assessment.score
        
        return {
            'total_assessments': len(self.assessments),
            'risk_distribution': risk_distribution,
            'average_score': total_score / len(self.assessments),
            'highest_risk': max(self.assessments, key=lambda x: x.score).risk_level.value if self.assessments else None
        }

class ReportGenerator:
    """報告生成器"""
    
    def __init__(self):
        self.attack_visualizer = AttackPathVisualizer()
        self.evidence_collector = EvidenceCollector()
        self.risk_assessor = RiskAssessmentEngine()
        self.reports = []
    
    def generate_incident_report(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """生成事件回應報告"""
        try:
            report_id = f"incident_report_{int(time.time())}"
            
            # 生成攻擊路徑圖
            attack_path = self._generate_attack_path_from_incident(incident_data)
            
            # 收集證據
            evidence_summary = self.evidence_collector.get_evidence_summary()
            
            # 風險評估
            risk_summary = self.risk_assessor.get_risk_summary()
            
            # 生成報告內容
            report_content = {
                'report_id': report_id,
                'report_type': ReportType.INCIDENT_RESPONSE.value,
                'title': f"事件回應報告 - {incident_data.get('incident_id', 'Unknown')}",
                'executive_summary': self._generate_executive_summary(incident_data, evidence_summary, risk_summary),
                'incident_details': incident_data,
                'attack_path': attack_path,
                'evidence_summary': evidence_summary,
                'risk_assessment': risk_summary,
                'recommendations': self._generate_incident_recommendations(incident_data, risk_summary),
                'timeline': self._generate_incident_timeline(incident_data),
                'generated_at': datetime.now().isoformat(),
                'generated_by': 'Military Reporting System'
            }
            
            self.reports.append(report_content)
            
            return {
                'success': True,
                'report_id': report_id,
                'report_content': report_content
            }
        except Exception as e:
            logger.error(f"生成事件回應報告錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def generate_threat_analysis_report(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """生成威脅分析報告"""
        try:
            report_id = f"threat_analysis_{int(time.time())}"
            
            report_content = {
                'report_id': report_id,
                'report_type': ReportType.THREAT_ANALYSIS.value,
                'title': f"威脅分析報告 - {threat_data.get('threat_name', 'Unknown Threat')}",
                'threat_overview': threat_data,
                'attack_vectors': threat_data.get('attack_vectors', []),
                'indicators_of_compromise': threat_data.get('iocs', []),
                'mitigation_strategies': threat_data.get('mitigation', []),
                'risk_assessment': self.risk_assessor.get_risk_summary(),
                'generated_at': datetime.now().isoformat(),
                'generated_by': 'Military Reporting System'
            }
            
            self.reports.append(report_content)
            
            return {
                'success': True,
                'report_id': report_id,
                'report_content': report_content
            }
        except Exception as e:
            logger.error(f"生成威脅分析報告錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def generate_executive_summary(self, all_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """生成執行摘要"""
        try:
            summary = {
                'report_id': f"executive_summary_{int(time.time())}",
                'report_type': ReportType.EXECUTIVE_SUMMARY.value,
                'title': "執行摘要報告",
                'total_incidents': len([r for r in all_reports if r.get('report_type') == ReportType.INCIDENT_RESPONSE.value]),
                'total_threats': len([r for r in all_reports if r.get('report_type') == ReportType.THREAT_ANALYSIS.value]),
                'key_findings': self._extract_key_findings(all_reports),
                'risk_overview': self._generate_risk_overview(all_reports),
                'recommendations': self._generate_executive_recommendations(all_reports),
                'generated_at': datetime.now().isoformat(),
                'generated_by': 'Military Reporting System'
            }
            
            return {
                'success': True,
                'summary': summary
            }
        except Exception as e:
            logger.error(f"生成執行摘要錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def export_report(self, report_id: str, format: str = "json") -> Dict[str, Any]:
        """匯出報告"""
        try:
            report = None
            for r in self.reports:
                if r.get('report_id') == report_id:
                    report = r
                    break
            
            if not report:
                return {'success': False, 'error': '報告不存在'}
            
            if format == "json":
                filename = f"{report_id}.json"
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(report, f, ensure_ascii=False, indent=2)
            elif format == "html":
                filename = f"{report_id}.html"
                html_content = self._generate_html_report(report)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            else:
                return {'success': False, 'error': '不支援的格式'}
            
            return {
                'success': True,
                'filename': filename,
                'message': f'報告已匯出: {filename}'
            }
        except Exception as e:
            logger.error(f"匯出報告錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _generate_attack_path_from_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """從事件資料生成攻擊路徑"""
        # 模擬攻擊路徑生成
        nodes = [
            AttackNode(
                id="external",
                name="外部網路",
                type="network",
                ip_address="0.0.0.0",
                compromised=False
            ),
            AttackNode(
                id="dmz",
                name="DMZ 區域",
                type="network",
                ip_address="192.168.1.0/24",
                compromised=True
            ),
            AttackNode(
                id="internal",
                name="內部網路",
                type="network",
                ip_address="192.168.2.0/24",
                compromised=True
            ),
            AttackNode(
                id="database",
                name="資料庫伺服器",
                type="host",
                ip_address="192.168.2.100",
                hostname="DB-SERVER",
                compromised=True
            )
        ]
        
        edges = [
            AttackEdge(
                source="external",
                target="dmz",
                technique="Phishing",
                description="透過釣魚郵件獲得初始存取",
                timestamp=datetime.now().isoformat(),
                confidence=0.9
            ),
            AttackEdge(
                source="dmz",
                target="internal",
                technique="Lateral Movement",
                description="橫向移動到內部網路",
                timestamp=datetime.now().isoformat(),
                confidence=0.8
            ),
            AttackEdge(
                source="internal",
                target="database",
                technique="Privilege Escalation",
                description="提升權限存取資料庫",
                timestamp=datetime.now().isoformat(),
                confidence=0.7
            )
        ]
        
        # 添加到視覺化工具
        for node in nodes:
            self.attack_visualizer.add_attack_node(node)
        
        for edge in edges:
            self.attack_visualizer.add_attack_edge(edge)
        
        # 生成攻擊路徑圖
        return self.attack_visualizer.generate_attack_path_diagram()
    
    def _generate_executive_summary(self, incident_data: Dict[str, Any], 
                                  evidence_summary: Dict[str, Any], 
                                  risk_summary: Dict[str, Any]) -> str:
        """生成執行摘要"""
        return f"""
        本報告概述了安全事件的詳細分析結果。事件涉及 {incident_data.get('affected_systems', 0)} 個受影響系統，
        收集了 {evidence_summary.get('total_evidence', 0)} 項證據，識別出 {risk_summary.get('total_assessments', 0)} 個風險項目。
        建議立即採取適當的緩解措施以降低安全風險。
        """
    
    def _generate_incident_recommendations(self, incident_data: Dict[str, Any], 
                                         risk_summary: Dict[str, Any]) -> List[str]:
        """生成事件建議"""
        recommendations = [
            "立即修復已識別的漏洞",
            "加強網路監控和檢測",
            "更新安全政策和程序",
            "進行員工安全意識培訓",
            "實施定期安全評估"
        ]
        
        if risk_summary.get('highest_risk') == 'critical':
            recommendations.insert(0, "立即啟動緊急回應程序")
        
        return recommendations
    
    def _generate_incident_timeline(self, incident_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """生成事件時間線"""
        return [
            {
                'timestamp': '2024-01-01T09:00:00Z',
                'event': '檢測到可疑活動',
                'description': 'SIEM 系統檢測到異常網路流量'
            },
            {
                'timestamp': '2024-01-01T09:15:00Z',
                'event': '啟動事件回應',
                'description': '安全團隊啟動事件回應程序'
            },
            {
                'timestamp': '2024-01-01T10:00:00Z',
                'event': '隔離受影響系統',
                'description': '隔離受影響的系統以防止進一步損害'
            }
        ]
    
    def _extract_key_findings(self, all_reports: List[Dict[str, Any]]) -> List[str]:
        """提取關鍵發現"""
        findings = []
        
        for report in all_reports:
            if 'key_findings' in report:
                findings.extend(report['key_findings'])
            elif 'incident_details' in report:
                findings.append(f"事件: {report['incident_details'].get('incident_id', 'Unknown')}")
        
        return findings[:10]  # 限制前10個發現
    
    def _generate_risk_overview(self, all_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """生成風險概覽"""
        total_risks = 0
        critical_risks = 0
        high_risks = 0
        
        for report in all_reports:
            if 'risk_assessment' in report:
                risk_data = report['risk_assessment']
                total_risks += risk_data.get('total_assessments', 0)
                risk_dist = risk_data.get('risk_distribution', {})
                critical_risks += risk_dist.get('critical', 0)
                high_risks += risk_dist.get('high', 0)
        
        return {
            'total_risks': total_risks,
            'critical_risks': critical_risks,
            'high_risks': high_risks,
            'risk_trend': 'increasing' if critical_risks > 0 else 'stable'
        }
    
    def _generate_executive_recommendations(self, all_reports: List[Dict[str, Any]]) -> List[str]:
        """生成執行建議"""
        return [
            "加強整體安全態勢",
            "投資進階威脅檢測技術",
            "建立更強的事件回應能力",
            "定期進行安全評估和測試",
            "提升員工安全意識"
        ]
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """生成 HTML 報告"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{report.get('title', 'Security Report')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; }}
                .risk-critical {{ color: #d32f2f; font-weight: bold; }}
                .risk-high {{ color: #f57c00; font-weight: bold; }}
                .risk-medium {{ color: #fbc02d; font-weight: bold; }}
                .risk-low {{ color: #388e3c; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{report.get('title', 'Security Report')}</h1>
                <p>生成時間: {report.get('generated_at', 'Unknown')}</p>
                <p>生成者: {report.get('generated_by', 'Unknown')}</p>
            </div>
            
            <div class="section">
                <h2>執行摘要</h2>
                <p>{report.get('executive_summary', 'No summary available')}</p>
            </div>
            
            <div class="section">
                <h2>風險評估</h2>
                <p>總風險數: {report.get('risk_assessment', {}).get('total_assessments', 0)}</p>
                <p>平均風險分數: {report.get('risk_assessment', {}).get('average_score', 0):.2f}</p>
            </div>
            
            <div class="section">
                <h2>建議</h2>
                <ul>
                    {''.join(f'<li>{rec}</li>' for rec in report.get('recommendations', []))}
                </ul>
            </div>
        </body>
        </html>
        """
        return html

class MilitaryReportingSystem:
    """軍事級報告系統主類別"""
    
    def __init__(self):
        self.report_generator = ReportGenerator()
        self.report_log = []
    
    def comprehensive_reporting(self, reporting_scope: Dict[str, Any]) -> Dict[str, Any]:
        """執行綜合報告生成"""
        try:
            results = {}
            
            # 1. 事件回應報告
            if 'incident_data' in reporting_scope:
                logger.info("生成事件回應報告...")
                incident_report = self.report_generator.generate_incident_report(reporting_scope['incident_data'])
                results['incident_report'] = incident_report
            
            # 2. 威脅分析報告
            if 'threat_data' in reporting_scope:
                logger.info("生成威脅分析報告...")
                threat_report = self.report_generator.generate_threat_analysis_report(reporting_scope['threat_data'])
                results['threat_report'] = threat_report
            
            # 3. 執行摘要
            logger.info("生成執行摘要...")
            all_reports = [r for r in self.report_generator.reports]
            executive_summary = self.report_generator.generate_executive_summary(all_reports)
            results['executive_summary'] = executive_summary
            
            # 4. 報告匯出
            logger.info("匯出報告...")
            export_results = self._export_all_reports()
            results['export_results'] = export_results
            
            return {
                'success': True,
                'results': results,
                'summary': self._generate_reporting_summary(results)
            }
        except Exception as e:
            logger.error(f"綜合報告生成錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _export_all_reports(self) -> Dict[str, Any]:
        """匯出所有報告"""
        try:
            export_results = []
            
            for report in self.report_generator.reports:
                # 匯出 JSON 格式
                json_result = self.report_generator.export_report(report['report_id'], 'json')
                if json_result.get('success', False):
                    export_results.append(json_result)
                
                # 匯出 HTML 格式
                html_result = self.report_generator.export_report(report['report_id'], 'html')
                if html_result.get('success', False):
                    export_results.append(html_result)
            
            return {
                'success': True,
                'exported_reports': len(export_results),
                'export_results': export_results
            }
        except Exception as e:
            logger.error(f"報告匯出錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _generate_reporting_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成報告摘要"""
        summary = {
            'total_reports': len(self.report_generator.reports),
            'exported_files': 0,
            'report_types': set(),
            'generation_successful': True
        }
        
        if 'export_results' in results:
            summary['exported_files'] = results['export_results'].get('exported_reports', 0)
        
        for report in self.report_generator.reports:
            summary['report_types'].add(report.get('report_type', 'unknown'))
        
        summary['report_types'] = list(summary['report_types'])
        
        return summary
    
    def get_report_log(self) -> List[Dict[str, Any]]:
        """獲取報告日誌"""
        return self.report_log
    
    def export_results(self, filename: str) -> bool:
        """匯出結果"""
        try:
            data = {
                'report_log': self.report_log,
                'reports': self.report_generator.reports,
                'timestamp': datetime.now().isoformat(),
                'system_info': {
                    'platform': sys.platform,
                    'python_version': sys.version
                }
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"結果已匯出到: {filename}")
            return True
        except Exception as e:
            logger.error(f"匯出結果錯誤: {e}")
            return False

def main():
    """主程式"""
    print("📊 軍事級報告系統")
    print("=" * 50)
    
    # 初始化系統
    reporting_system = MilitaryReportingSystem()
    
    # 測試報告範圍
    test_reporting_scope = {
        'incident_data': {
            'incident_id': 'INC-2024-001',
            'affected_systems': 5,
            'severity': 'HIGH',
            'status': 'RESOLVED'
        },
        'threat_data': {
            'threat_name': 'APT Group',
            'attack_vectors': ['Phishing', 'Lateral Movement'],
            'iocs': ['192.168.1.100', 'malicious.com'],
            'mitigation': ['Network Segmentation', 'Email Security']
        }
    }
    
    # 執行綜合報告生成測試
    print("開始執行綜合報告生成測試...")
    results = reporting_system.comprehensive_reporting(test_reporting_scope)
    
    print(f"報告生成完成，成功: {results['success']}")
    print(f"報告摘要: {json.dumps(results['summary'], indent=2, ensure_ascii=False)}")
    
    # 匯出結果
    reporting_system.export_results("reporting_system_results.json")
    
    print("軍事級報告系統測試完成！")

if __name__ == "__main__":
    main()

