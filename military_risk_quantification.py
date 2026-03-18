#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級風險量化系統
實作 FAIR (Factor Analysis of Information Risk) 模組、金融風險影響分析
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
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

# 設定日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RiskCategory(Enum):
    """風險類別枚舉"""
    CYBERSECURITY = "cybersecurity"
    OPERATIONAL = "operational"
    COMPLIANCE = "compliance"
    REPUTATIONAL = "reputational"
    FINANCIAL = "financial"
    STRATEGIC = "strategic"

class ThreatLevel(Enum):
    """威脅等級枚舉"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"

class VulnerabilityLevel(Enum):
    """脆弱性等級枚舉"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"

class LossMagnitude(Enum):
    """損失幅度枚舉"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"

@dataclass
class FAIRRiskFactor:
    """FAIR 風險因子資料結構"""
    factor_name: str
    factor_type: str
    value: float
    confidence: float
    description: str
    impact: str

@dataclass
class RiskScenario:
    """風險情境資料結構"""
    id: str
    name: str
    description: str
    category: RiskCategory
    threat_level: ThreatLevel
    vulnerability_level: VulnerabilityLevel
    loss_magnitude: LossMagnitude
    frequency: float
    impact: float
    risk_score: float
    financial_impact: float
    mitigation_cost: float
    residual_risk: float

@dataclass
class FinancialImpact:
    """財務影響資料結構"""
    direct_costs: float
    indirect_costs: float
    reputational_costs: float
    regulatory_costs: float
    total_cost: float
    cost_category: str
    impact_duration: int  # 天數
    recovery_cost: float

class FAIRRiskModel:
    """FAIR 風險模型"""
    
    def __init__(self):
        self.risk_factors = {}
        self.scenarios = {}
        self._init_fair_parameters()
    
    def _init_fair_parameters(self):
        """初始化 FAIR 參數"""
        try:
            # 威脅事件頻率 (TEF) 參數
            self.risk_factors['tef'] = {
                'very_low': {'min': 0.001, 'max': 0.01, 'most_likely': 0.005},
                'low': {'min': 0.01, 'max': 0.1, 'most_likely': 0.05},
                'medium': {'min': 0.1, 'max': 1.0, 'most_likely': 0.5},
                'high': {'min': 1.0, 'max': 10.0, 'most_likely': 5.0},
                'critical': {'min': 10.0, 'max': 100.0, 'most_likely': 50.0}
            }
            
            # 威脅能力 (TC) 參數
            self.risk_factors['tc'] = {
                'very_low': {'min': 0.1, 'max': 0.3, 'most_likely': 0.2},
                'low': {'min': 0.3, 'max': 0.5, 'most_likely': 0.4},
                'medium': {'min': 0.5, 'max': 0.7, 'most_likely': 0.6},
                'high': {'min': 0.7, 'max': 0.9, 'most_likely': 0.8},
                'critical': {'min': 0.9, 'max': 1.0, 'most_likely': 0.95}
            }
            
            # 控制強度 (CS) 參數
            self.risk_factors['cs'] = {
                'very_low': {'min': 0.0, 'max': 0.2, 'most_likely': 0.1},
                'low': {'min': 0.2, 'max': 0.4, 'most_likely': 0.3},
                'medium': {'min': 0.4, 'max': 0.6, 'most_likely': 0.5},
                'high': {'min': 0.6, 'max': 0.8, 'most_likely': 0.7},
                'critical': {'min': 0.8, 'max': 1.0, 'most_likely': 0.9}
            }
            
            # 損失幅度 (LM) 參數
            self.risk_factors['lm'] = {
                'very_low': {'min': 1000, 'max': 10000, 'most_likely': 5000},
                'low': {'min': 10000, 'max': 100000, 'most_likely': 50000},
                'medium': {'min': 100000, 'max': 1000000, 'most_likely': 500000},
                'high': {'min': 1000000, 'max': 10000000, 'most_likely': 5000000},
                'critical': {'min': 10000000, 'max': 100000000, 'most_likely': 50000000}
            }
            
            logger.info("FAIR 參數初始化完成")
        except Exception as e:
            logger.error(f"FAIR 參數初始化錯誤: {e}")
    
    def calculate_fair_risk(self, scenario_data: Dict[str, Any]) -> Dict[str, Any]:
        """計算 FAIR 風險"""
        try:
            # 提取風險參數
            threat_level = ThreatLevel(scenario_data.get('threat_level', 'medium'))
            vulnerability_level = VulnerabilityLevel(scenario_data.get('vulnerability_level', 'medium'))
            loss_magnitude = LossMagnitude(scenario_data.get('loss_magnitude', 'medium'))
            
            # 計算威脅事件頻率 (TEF)
            tef_params = self.risk_factors['tef'][threat_level.value]
            tef = self._calculate_triangular_distribution(tef_params)
            
            # 計算脆弱性 (V)
            tc_params = self.risk_factors['tc'][threat_level.value]
            cs_params = self.risk_factors['cs'][vulnerability_level.value]
            
            tc = self._calculate_triangular_distribution(tc_params)
            cs = self._calculate_triangular_distribution(cs_params)
            
            # 脆弱性 = 威脅能力 * (1 - 控制強度)
            vulnerability = tc * (1 - cs)
            
            # 計算損失事件頻率 (LEF)
            lef = tef * vulnerability
            
            # 計算損失幅度 (LM)
            lm_params = self.risk_factors['lm'][loss_magnitude.value]
            lm = self._calculate_triangular_distribution(lm_params)
            
            # 計算年度損失期望值 (ALE)
            ale = lef * lm
            
            # 計算風險分數
            risk_score = self._calculate_risk_score(lef, lm)
            
            return {
                'success': True,
                'fair_analysis': {
                    'threat_event_frequency': tef,
                    'vulnerability': vulnerability,
                    'loss_event_frequency': lef,
                    'loss_magnitude': lm,
                    'annual_loss_expectancy': ale,
                    'risk_score': risk_score
                },
                'parameters': {
                    'threat_level': threat_level.value,
                    'vulnerability_level': vulnerability_level.value,
                    'loss_magnitude': loss_magnitude.value
                }
            }
        except Exception as e:
            logger.error(f"計算 FAIR 風險錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _calculate_triangular_distribution(self, params: Dict[str, float]) -> float:
        """計算三角分佈"""
        try:
            min_val = params['min']
            max_val = params['max']
            most_likely = params['most_likely']
            
            # 使用三角分佈公式
            u = np.random.random()
            
            if u < (most_likely - min_val) / (max_val - min_val):
                return min_val + np.sqrt(u * (max_val - min_val) * (most_likely - min_val))
            else:
                return max_val - np.sqrt((1 - u) * (max_val - min_val) * (max_val - most_likely))
        except Exception as e:
            logger.error(f"計算三角分佈錯誤: {e}")
            return params.get('most_likely', 0.0)
    
    def _calculate_risk_score(self, lef: float, lm: float) -> float:
        """計算風險分數"""
        try:
            # 標準化風險分數 (0-100)
            lef_score = min(lef * 100, 100)
            lm_score = min(np.log10(lm) * 10, 100)
            
            # 加權平均
            risk_score = (lef_score * 0.4 + lm_score * 0.6)
            
            return min(risk_score, 100)
        except Exception as e:
            logger.error(f"計算風險分數錯誤: {e}")
            return 0.0

class FinancialImpactAnalyzer:
    """財務影響分析器"""
    
    def __init__(self):
        self.cost_models = {}
        self._init_cost_models()
    
    def _init_cost_models(self):
        """初始化成本模型"""
        try:
            # 網路安全事件成本模型
            self.cost_models['cybersecurity'] = {
                'direct_costs': {
                    'incident_response': 0.3,
                    'system_restoration': 0.25,
                    'forensic_investigation': 0.15,
                    'legal_fees': 0.1,
                    'notification_costs': 0.1,
                    'credit_monitoring': 0.1
                },
                'indirect_costs': {
                    'business_disruption': 0.4,
                    'productivity_loss': 0.3,
                    'customer_attrition': 0.2,
                    'supplier_impact': 0.1
                },
                'reputational_costs': {
                    'brand_damage': 0.5,
                    'market_share_loss': 0.3,
                    'stock_price_impact': 0.2
                },
                'regulatory_costs': {
                    'fines_penalties': 0.6,
                    'compliance_remediation': 0.3,
                    'audit_costs': 0.1
                }
            }
            
            # 營運風險成本模型
            self.cost_models['operational'] = {
                'direct_costs': {
                    'equipment_replacement': 0.4,
                    'system_downtime': 0.3,
                    'staff_overtime': 0.2,
                    'contractor_costs': 0.1
                },
                'indirect_costs': {
                    'lost_revenue': 0.5,
                    'customer_satisfaction': 0.3,
                    'operational_efficiency': 0.2
                },
                'reputational_costs': {
                    'service_reliability': 0.6,
                    'customer_trust': 0.4
                },
                'regulatory_costs': {
                    'safety_violations': 0.7,
                    'environmental_impact': 0.3
                }
            }
            
            logger.info("成本模型初始化完成")
        except Exception as e:
            logger.error(f"成本模型初始化錯誤: {e}")
    
    def calculate_financial_impact(self, scenario_data: Dict[str, Any]) -> Dict[str, Any]:
        """計算財務影響"""
        try:
            category = RiskCategory(scenario_data.get('category', 'cybersecurity'))
            base_cost = scenario_data.get('base_cost', 1000000)
            severity = scenario_data.get('severity', 'medium')
            
            # 獲取對應的成本模型
            cost_model = self.cost_models.get(category.value, self.cost_models['cybersecurity'])
            
            # 計算各類成本
            direct_costs = self._calculate_direct_costs(base_cost, cost_model['direct_costs'], severity)
            indirect_costs = self._calculate_indirect_costs(base_cost, cost_model['indirect_costs'], severity)
            reputational_costs = self._calculate_reputational_costs(base_cost, cost_model['reputational_costs'], severity)
            regulatory_costs = self._calculate_regulatory_costs(base_cost, cost_model['regulatory_costs'], severity)
            
            # 計算總成本
            total_cost = direct_costs + indirect_costs + reputational_costs + regulatory_costs
            
            # 計算恢復成本
            recovery_cost = self._calculate_recovery_cost(total_cost, severity)
            
            # 計算影響持續時間
            impact_duration = self._calculate_impact_duration(severity)
            
            financial_impact = FinancialImpact(
                direct_costs=direct_costs,
                indirect_costs=indirect_costs,
                reputational_costs=reputational_costs,
                regulatory_costs=regulatory_costs,
                total_cost=total_cost,
                cost_category=category.value,
                impact_duration=impact_duration,
                recovery_cost=recovery_cost
            )
            
            return {
                'success': True,
                'financial_impact': self._financial_impact_to_dict(financial_impact),
                'cost_breakdown': {
                    'direct_costs_percentage': (direct_costs / total_cost) * 100,
                    'indirect_costs_percentage': (indirect_costs / total_cost) * 100,
                    'reputational_costs_percentage': (reputational_costs / total_cost) * 100,
                    'regulatory_costs_percentage': (regulatory_costs / total_cost) * 100
                }
            }
        except Exception as e:
            logger.error(f"計算財務影響錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _calculate_direct_costs(self, base_cost: float, cost_components: Dict[str, float], severity: str) -> float:
        """計算直接成本"""
        try:
            severity_multipliers = {
                'very_low': 0.1,
                'low': 0.3,
                'medium': 0.6,
                'high': 1.0,
                'critical': 2.0
            }
            
            multiplier = severity_multipliers.get(severity, 0.6)
            total_direct_cost = 0.0
            
            for component, percentage in cost_components.items():
                component_cost = base_cost * percentage * multiplier
                total_direct_cost += component_cost
            
            return total_direct_cost
        except Exception as e:
            logger.error(f"計算直接成本錯誤: {e}")
            return 0.0
    
    def _calculate_indirect_costs(self, base_cost: float, cost_components: Dict[str, float], severity: str) -> float:
        """計算間接成本"""
        try:
            severity_multipliers = {
                'very_low': 0.05,
                'low': 0.15,
                'medium': 0.4,
                'high': 0.8,
                'critical': 1.5
            }
            
            multiplier = severity_multipliers.get(severity, 0.4)
            total_indirect_cost = 0.0
            
            for component, percentage in cost_components.items():
                component_cost = base_cost * percentage * multiplier
                total_indirect_cost += component_cost
            
            return total_indirect_cost
        except Exception as e:
            logger.error(f"計算間接成本錯誤: {e}")
            return 0.0
    
    def _calculate_reputational_costs(self, base_cost: float, cost_components: Dict[str, float], severity: str) -> float:
        """計算聲譽成本"""
        try:
            severity_multipliers = {
                'very_low': 0.02,
                'low': 0.08,
                'medium': 0.2,
                'high': 0.5,
                'critical': 1.0
            }
            
            multiplier = severity_multipliers.get(severity, 0.2)
            total_reputational_cost = 0.0
            
            for component, percentage in cost_components.items():
                component_cost = base_cost * percentage * multiplier
                total_reputational_cost += component_cost
            
            return total_reputational_cost
        except Exception as e:
            logger.error(f"計算聲譽成本錯誤: {e}")
            return 0.0
    
    def _calculate_regulatory_costs(self, base_cost: float, cost_components: Dict[str, float], severity: str) -> float:
        """計算監管成本"""
        try:
            severity_multipliers = {
                'very_low': 0.01,
                'low': 0.05,
                'medium': 0.15,
                'high': 0.4,
                'critical': 0.8
            }
            
            multiplier = severity_multipliers.get(severity, 0.15)
            total_regulatory_cost = 0.0
            
            for component, percentage in cost_components.items():
                component_cost = base_cost * percentage * multiplier
                total_regulatory_cost += component_cost
            
            return total_regulatory_cost
        except Exception as e:
            logger.error(f"計算監管成本錯誤: {e}")
            return 0.0
    
    def _calculate_recovery_cost(self, total_cost: float, severity: str) -> float:
        """計算恢復成本"""
        try:
            recovery_multipliers = {
                'very_low': 0.1,
                'low': 0.2,
                'medium': 0.3,
                'high': 0.5,
                'critical': 0.8
            }
            
            multiplier = recovery_multipliers.get(severity, 0.3)
            return total_cost * multiplier
        except Exception as e:
            logger.error(f"計算恢復成本錯誤: {e}")
            return 0.0
    
    def _calculate_impact_duration(self, severity: str) -> int:
        """計算影響持續時間"""
        try:
            duration_days = {
                'very_low': 1,
                'low': 7,
                'medium': 30,
                'high': 90,
                'critical': 365
            }
            
            return duration_days.get(severity, 30)
        except Exception as e:
            logger.error(f"計算影響持續時間錯誤: {e}")
            return 30
    
    def _financial_impact_to_dict(self, financial_impact: FinancialImpact) -> Dict[str, Any]:
        """將財務影響轉換為字典"""
        return {
            'direct_costs': financial_impact.direct_costs,
            'indirect_costs': financial_impact.indirect_costs,
            'reputational_costs': financial_impact.reputational_costs,
            'regulatory_costs': financial_impact.regulatory_costs,
            'total_cost': financial_impact.total_cost,
            'cost_category': financial_impact.cost_category,
            'impact_duration': financial_impact.impact_duration,
            'recovery_cost': financial_impact.recovery_cost
        }

class RiskQuantificationEngine:
    """風險量化引擎"""
    
    def __init__(self):
        self.fair_model = FAIRRiskModel()
        self.financial_analyzer = FinancialImpactAnalyzer()
        self.risk_scenarios = {}
        self.risk_metrics = {}
    
    def comprehensive_risk_quantification(self, analysis_scope: Dict[str, Any]) -> Dict[str, Any]:
        """執行綜合風險量化"""
        try:
            results = {}
            
            # 1. FAIR 風險分析
            logger.info("執行 FAIR 風險分析...")
            fair_results = self._perform_fair_analysis(analysis_scope)
            results['fair_analysis'] = fair_results
            
            # 2. 財務影響分析
            logger.info("執行財務影響分析...")
            financial_results = self._perform_financial_analysis(analysis_scope)
            results['financial_analysis'] = financial_results
            
            # 3. 風險情境分析
            logger.info("執行風險情境分析...")
            scenario_results = self._analyze_risk_scenarios(analysis_scope)
            results['scenario_analysis'] = scenario_results
            
            # 4. 風險優先級排序
            logger.info("執行風險優先級排序...")
            prioritization_results = self._prioritize_risks(results)
            results['risk_prioritization'] = prioritization_results
            
            # 5. 風險緩解建議
            logger.info("生成風險緩解建議...")
            mitigation_results = self._generate_mitigation_recommendations(results)
            results['mitigation_recommendations'] = mitigation_results
            
            return {
                'success': True,
                'results': results,
                'summary': self._generate_risk_quantification_summary(results)
            }
        except Exception as e:
            logger.error(f"綜合風險量化錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _perform_fair_analysis(self, analysis_scope: Dict[str, Any]) -> Dict[str, Any]:
        """執行 FAIR 分析"""
        try:
            fair_results = {}
            
            # 分析多個風險情境
            scenarios = analysis_scope.get('risk_scenarios', [])
            if not scenarios:
                # 使用預設情境
                scenarios = [
                    {
                        'name': 'Data Breach',
                        'threat_level': 'high',
                        'vulnerability_level': 'medium',
                        'loss_magnitude': 'high'
                    },
                    {
                        'name': 'Ransomware Attack',
                        'threat_level': 'critical',
                        'vulnerability_level': 'high',
                        'loss_magnitude': 'critical'
                    },
                    {
                        'name': 'Insider Threat',
                        'threat_level': 'medium',
                        'vulnerability_level': 'low',
                        'loss_magnitude': 'medium'
                    }
                ]
            
            for scenario in scenarios:
                fair_result = self.fair_model.calculate_fair_risk(scenario)
                if fair_result['success']:
                    fair_results[scenario['name']] = fair_result
            
            return {
                'success': True,
                'fair_results': fair_results,
                'total_scenarios': len(fair_results)
            }
        except Exception as e:
            logger.error(f"執行 FAIR 分析錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _perform_financial_analysis(self, analysis_scope: Dict[str, Any]) -> Dict[str, Any]:
        """執行財務分析"""
        try:
            financial_results = {}
            
            # 分析多個財務情境
            scenarios = analysis_scope.get('financial_scenarios', [])
            if not scenarios:
                # 使用預設情境
                scenarios = [
                    {
                        'name': 'Cybersecurity Incident',
                        'category': 'cybersecurity',
                        'base_cost': 1000000,
                        'severity': 'high'
                    },
                    {
                        'name': 'Operational Disruption',
                        'category': 'operational',
                        'base_cost': 500000,
                        'severity': 'medium'
                    },
                    {
                        'name': 'Compliance Violation',
                        'category': 'compliance',
                        'base_cost': 2000000,
                        'severity': 'critical'
                    }
                ]
            
            for scenario in scenarios:
                financial_result = self.financial_analyzer.calculate_financial_impact(scenario)
                if financial_result['success']:
                    financial_results[scenario['name']] = financial_result
            
            return {
                'success': True,
                'financial_results': financial_results,
                'total_scenarios': len(financial_results)
            }
        except Exception as e:
            logger.error(f"執行財務分析錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _analyze_risk_scenarios(self, analysis_scope: Dict[str, Any]) -> Dict[str, Any]:
        """分析風險情境"""
        try:
            scenario_analysis = {}
            
            # 結合 FAIR 和財務分析結果
            if 'fair_analysis' in analysis_scope and 'financial_analysis' in analysis_scope:
                fair_data = analysis_scope['fair_analysis']
                financial_data = analysis_scope['financial_analysis']
                
                for scenario_name in fair_data.get('fair_results', {}):
                    if scenario_name in financial_data.get('financial_results', {}):
                        fair_result = fair_data['fair_results'][scenario_name]
                        financial_result = financial_data['financial_results'][scenario_name]
                        
                        # 計算綜合風險分數
                        fair_score = fair_result['fair_analysis']['risk_score']
                        financial_cost = financial_result['financial_impact']['total_cost']
                        
                        # 標準化財務成本為風險分數
                        financial_score = min(np.log10(financial_cost) * 10, 100)
                        
                        # 綜合風險分數
                        combined_risk_score = (fair_score * 0.6 + financial_score * 0.4)
                        
                        scenario_analysis[scenario_name] = {
                            'fair_risk_score': fair_score,
                            'financial_impact': financial_cost,
                            'financial_risk_score': financial_score,
                            'combined_risk_score': combined_risk_score,
                            'risk_level': self._determine_risk_level(combined_risk_score)
                        }
            
            return {
                'success': True,
                'scenario_analysis': scenario_analysis,
                'total_scenarios': len(scenario_analysis)
            }
        except Exception as e:
            logger.error(f"分析風險情境錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _prioritize_risks(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """風險優先級排序"""
        try:
            prioritization = []
            
            if 'scenario_analysis' in results and 'scenario_analysis' in results['scenario_analysis']:
                scenario_data = results['scenario_analysis']['scenario_analysis']
                
                for scenario_name, scenario_info in scenario_data.items():
                    prioritization.append({
                        'scenario_name': scenario_name,
                        'risk_score': scenario_info['combined_risk_score'],
                        'risk_level': scenario_info['risk_level'],
                        'financial_impact': scenario_info['financial_impact'],
                        'priority_rank': 0  # 稍後計算
                    })
                
                # 按風險分數排序
                prioritization.sort(key=lambda x: x['risk_score'], reverse=True)
                
                # 分配優先級排名
                for i, item in enumerate(prioritization):
                    item['priority_rank'] = i + 1
            
            return {
                'success': True,
                'prioritized_risks': prioritization,
                'total_risks': len(prioritization)
            }
        except Exception as e:
            logger.error(f"風險優先級排序錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _generate_mitigation_recommendations(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成風險緩解建議"""
        try:
            recommendations = []
            
            if 'risk_prioritization' in results and 'prioritized_risks' in results['risk_prioritization']:
                prioritized_risks = results['risk_prioritization']['prioritized_risks']
                
                for risk in prioritized_risks:
                    scenario_name = risk['scenario_name']
                    risk_level = risk['risk_level']
                    financial_impact = risk['financial_impact']
                    
                    # 基於風險等級生成建議
                    if risk_level == 'critical':
                        recommendations.append({
                            'scenario': scenario_name,
                            'priority': 'IMMEDIATE',
                            'recommendations': [
                                '立即實施緊急應變計畫',
                                '部署額外的安全控制措施',
                                '啟動事件回應團隊',
                                '通知相關利益相關者'
                            ],
                            'estimated_cost': financial_impact * 0.1,
                            'implementation_time': '1-7 days'
                        })
                    elif risk_level == 'high':
                        recommendations.append({
                            'scenario': scenario_name,
                            'priority': 'HIGH',
                            'recommendations': [
                                '加強現有安全控制',
                                '實施額外監控措施',
                                '更新安全政策',
                                '進行安全培訓'
                            ],
                            'estimated_cost': financial_impact * 0.05,
                            'implementation_time': '1-4 weeks'
                        })
                    elif risk_level == 'medium':
                        recommendations.append({
                            'scenario': scenario_name,
                            'priority': 'MEDIUM',
                            'recommendations': [
                                '評估現有控制措施',
                                '制定改進計畫',
                                '定期安全評估',
                                '員工安全意識培訓'
                            ],
                            'estimated_cost': financial_impact * 0.02,
                            'implementation_time': '1-3 months'
                        })
                    else:
                        recommendations.append({
                            'scenario': scenario_name,
                            'priority': 'LOW',
                            'recommendations': [
                                '監控風險指標',
                                '定期審查',
                                '持續改進'
                            ],
                            'estimated_cost': financial_impact * 0.01,
                            'implementation_time': '3-6 months'
                        })
            
            return {
                'success': True,
                'recommendations': recommendations,
                'total_recommendations': len(recommendations)
            }
        except Exception as e:
            logger.error(f"生成風險緩解建議錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """確定風險等級"""
        if risk_score >= 80:
            return 'critical'
        elif risk_score >= 60:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        elif risk_score >= 20:
            return 'low'
        else:
            return 'very_low'
    
    def _generate_risk_quantification_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成風險量化摘要"""
        summary = {
            'total_analyses': len(results),
            'successful_analyses': sum(1 for r in results.values() if isinstance(r, dict) and r.get('success', True)),
            'fair_scenarios_analyzed': 0,
            'financial_scenarios_analyzed': 0,
            'total_risks_prioritized': 0,
            'total_recommendations': 0,
            'average_risk_score': 0.0,
            'total_financial_impact': 0.0
        }
        
        if 'fair_analysis' in results:
            summary['fair_scenarios_analyzed'] = results['fair_analysis'].get('total_scenarios', 0)
        
        if 'financial_analysis' in results:
            summary['financial_scenarios_analyzed'] = results['financial_analysis'].get('total_scenarios', 0)
        
        if 'risk_prioritization' in results:
            summary['total_risks_prioritized'] = results['risk_prioritization'].get('total_risks', 0)
        
        if 'mitigation_recommendations' in results:
            summary['total_recommendations'] = results['mitigation_recommendations'].get('total_recommendations', 0)
        
        if 'scenario_analysis' in results and 'scenario_analysis' in results['scenario_analysis']:
            scenario_data = results['scenario_analysis']['scenario_analysis']
            if scenario_data:
                summary['average_risk_score'] = np.mean([s['combined_risk_score'] for s in scenario_data.values()])
                summary['total_financial_impact'] = sum([s['financial_impact'] for s in scenario_data.values()])
        
        return summary

def main():
    """主程式"""
    print("💰 軍事級風險量化系統")
    print("=" * 50)
    
    # 初始化系統
    risk_quantification = RiskQuantificationEngine()
    
    # 測試分析範圍
    test_analysis_scope = {
        'risk_scenarios': [
            {
                'name': 'Advanced Persistent Threat',
                'threat_level': 'critical',
                'vulnerability_level': 'high',
                'loss_magnitude': 'critical'
            },
            {
                'name': 'Insider Data Theft',
                'threat_level': 'medium',
                'vulnerability_level': 'low',
                'loss_magnitude': 'high'
            }
        ],
        'financial_scenarios': [
            {
                'name': 'Critical Infrastructure Attack',
                'category': 'cybersecurity',
                'base_cost': 5000000,
                'severity': 'critical'
            },
            {
                'name': 'Supply Chain Disruption',
                'category': 'operational',
                'base_cost': 2000000,
                'severity': 'high'
            }
        ]
    }
    
    # 執行綜合風險量化測試
    print("開始執行綜合風險量化測試...")
    results = risk_quantification.comprehensive_risk_quantification(test_analysis_scope)
    
    print(f"量化完成，成功: {results['success']}")
    print(f"量化摘要: {json.dumps(results['summary'], indent=2, ensure_ascii=False)}")
    
    print("軍事級風險量化系統測試完成！")

if __name__ == "__main__":
    main()

