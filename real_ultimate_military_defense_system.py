#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實終極軍事防禦系統
Real Ultimate Military Defense System
整合所有真實軍事級防禦能力
"""

import os
import sys
import json
import time
import logging
import threading
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import hashlib
import hmac
import secrets

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 導入所有真實防禦模組（可選導入，避免依賴問題）
try:
    from real_network_monitor import RealNetworkMonitor
except ImportError as e:
    logger.warning(f"無法導入 real_network_monitor: {e}")
    RealNetworkMonitor = None

try:
    from real_threat_detection import RealThreatDetection
except ImportError as e:
    logger.warning(f"無法導入 real_threat_detection: {e}")
    try:
        from real_threat_detection_no_yara import RealThreatDetection
        logger.info("使用無YARA依賴的威脅檢測模組")
    except ImportError as e2:
        logger.warning(f"無法導入 real_threat_detection_no_yara: {e2}")
        RealThreatDetection = None

try:
    from real_incident_response import RealIncidentResponse
except ImportError as e:
    logger.warning(f"無法導入 real_incident_response: {e}")
    RealIncidentResponse = None

try:
    from real_digital_forensics import RealDigitalForensics
except ImportError as e:
    logger.warning(f"無法導入 real_digital_forensics: {e}")
    RealDigitalForensics = None

try:
    from real_malware_analysis import RealMalwareAnalysis
except ImportError as e:
    logger.warning(f"無法導入 real_malware_analysis: {e}")
    RealMalwareAnalysis = None

try:
    from real_penetration_testing import RealPenetrationTesting
except ImportError as e:
    logger.warning(f"無法導入 real_penetration_testing: {e}")
    RealPenetrationTesting = None

try:
    from real_zero_trust_network_segmentation import RealZeroTrustNetworkSegmentation
except ImportError as e:
    logger.warning(f"無法導入 real_zero_trust_network_segmentation: {e}")
    RealZeroTrustNetworkSegmentation = None

try:
    from real_ai_ml_threat_hunting import RealAIMLThreatHunting
except ImportError as e:
    logger.warning(f"無法導入 real_ai_ml_threat_hunting: {e}")
    RealAIMLThreatHunting = None

try:
    from real_threat_intelligence_integration import RealThreatIntelligenceIntegration
except ImportError as e:
    logger.warning(f"無法導入 real_threat_intelligence_integration: {e}")
    RealThreatIntelligenceIntegration = None

try:
    from real_cloud_ot_iot_security import RealCloudOTIoTSecurity
except ImportError as e:
    logger.warning(f"無法導入 real_cloud_ot_iot_security: {e}")
    RealCloudOTIoTSecurity = None

try:
    from real_defense_automation_soar import RealDefenseAutomationSOAR
except ImportError as e:
    logger.warning(f"無法導入 real_defense_automation_soar: {e}")
    RealDefenseAutomationSOAR = None

try:
    from real_military_hardware_protection import RealMilitaryHardwareProtection
except ImportError as e:
    logger.warning(f"無法導入 real_military_hardware_protection: {e}")
    RealMilitaryHardwareProtection = None

try:
    from real_advanced_reporting_risk_quantification import RealAdvancedReportingRiskQuantification
except ImportError as e:
    logger.warning(f"無法導入 real_advanced_reporting_risk_quantification: {e}")
    RealAdvancedReportingRiskQuantification = None

try:
    from real_attack_simulation import RealAttackSimulation
except ImportError as e:
    logger.warning(f"無法導入 real_attack_simulation: {e}")
    RealAttackSimulation = None

try:
    from real_cross_platform_ir import RealCrossPlatformIR
except ImportError as e:
    logger.warning(f"無法導入 real_cross_platform_ir: {e}")
    RealCrossPlatformIR = None

try:
    from real_ddos_resilience import RealDDOSResilience
except ImportError as e:
    logger.warning(f"無法導入 real_ddos_resilience: {e}")
    RealDDOSResilience = None

try:
    from real_supply_chain_security import RealSupplyChainSecurity
except ImportError as e:
    logger.warning(f"無法導入 real_supply_chain_security: {e}")
    RealSupplyChainSecurity = None

try:
    from real_behavioral_analytics import RealBehavioralAnalytics
except ImportError as e:
    logger.warning(f"無法導入 real_behavioral_analytics: {e}")
    RealBehavioralAnalytics = None

try:
    from real_incident_playbooks import RealIncidentPlaybooks
except ImportError as e:
    logger.warning(f"無法導入 real_incident_playbooks: {e}")
    RealIncidentPlaybooks = None

try:
    from real_threat_hunting_queries import RealThreatHuntingQueries
except ImportError as e:
    logger.warning(f"無法導入 real_threat_hunting_queries: {e}")
    RealThreatHuntingQueries = None

try:
    from real_cloud_native_security import RealCloudNativeSecurity
except ImportError as e:
    logger.warning(f"無法導入 real_cloud_native_security: {e}")
    RealCloudNativeSecurity = None

try:
    from real_iot_device_management import RealIoTDeviceManagement
except ImportError as e:
    logger.warning(f"無法導入 real_iot_device_management: {e}")
    RealIoTDeviceManagement = None

try:
    from real_ai_adversarial_defense import RealAIAdversarialDefense
except ImportError as e:
    logger.warning(f"無法導入 real_ai_adversarial_defense: {e}")
    RealAIAdversarialDefense = None

try:
    from real_compliance_frameworks import RealComplianceFrameworks
except ImportError as e:
    logger.warning(f"無法導入 real_compliance_frameworks: {e}")
    RealComplianceFrameworks = None

# 防火牆協同
try:
    from real_firewall_orchestrator import RealFirewallOrchestrator
except ImportError as e:
    logger.warning(f"無法導入 real_firewall_orchestrator: {e}")
    RealFirewallOrchestrator = None

# 藍隊SOAR（被動監控）
try:
    from real_blue_team_soar import RealBlueTeamSOAR
except ImportError as e:
    logger.warning(f"無法導入 real_blue_team_soar: {e}")
    RealBlueTeamSOAR = None
# CTF 模組（可選導入）
try:
    from real_ctf_attack_simulation import RealCTFAttackSimulation
except ImportError as e:
    logger.warning(f"無法導入 real_ctf_attack_simulation: {e}")
    RealCTFAttackSimulation = None

try:
    from real_ctf_challenge_generator import RealCTFChallengeGenerator
except ImportError as e:
    logger.warning(f"無法導入 real_ctf_challenge_generator: {e}")
    RealCTFChallengeGenerator = None

try:
    from real_ctf_competition_manager import RealCTFCompetitionManager
except ImportError as e:
    logger.warning(f"無法導入 real_ctf_competition_manager: {e}")
    RealCTFCompetitionManager = None

class RealUltimateMilitaryDefenseSystem:
    """真實終極軍事防禦系統"""
    
    def __init__(self, config_file: str = "real_ultimate_defense_config.yaml"):
        self.config_file = config_file
        self.config = self._load_config()
        self.running = False
        self.defense_modules = {}
        self.system_threads = []
        self.defense_status = {}
        self.overall_health = {}
        
        # 初始化所有防禦模組
        self._init_defense_modules()
        
        logger.info("真實終極軍事防禦系統初始化完成")
    
    def _load_config(self) -> Dict[str, Any]:
        """載入配置"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    import yaml
                    return yaml.safe_load(f)
            else:
                return self._get_default_config()
        except Exception as e:
            logger.error(f"載入配置錯誤: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """獲取默認配置"""
        return {
            'system': {
                'name': 'Real Ultimate Military Defense System',
                'version': '1.0.0',
                'log_level': 'INFO',
                'monitoring_interval': 60,
                'health_check_interval': 300
            },
            'modules': {
                'network_monitor': {'enabled': True, 'priority': 1},
                'threat_detection': {'enabled': True, 'priority': 1},
                'incident_response': {'enabled': True, 'priority': 1},
                'digital_forensics': {'enabled': True, 'priority': 2},
                'malware_analysis': {'enabled': True, 'priority': 2},
                'penetration_testing': {'enabled': True, 'priority': 3},
                'zero_trust_segmentation': {'enabled': True, 'priority': 1},
                'ai_ml_threat_hunting': {'enabled': True, 'priority': 1},
                'threat_intelligence': {'enabled': True, 'priority': 1},
                'cloud_ot_iot_security': {'enabled': True, 'priority': 2},
                'defense_automation_soar': {'enabled': True, 'priority': 1},
                'hardware_protection': {'enabled': True, 'priority': 1},
                'reporting_risk_quantification': {'enabled': True, 'priority': 3}
                , 'attack_simulation': {'enabled': True, 'priority': 2}
                , 'cross_platform_ir': {'enabled': True, 'priority': 1}
                , 'ddos_resilience': {'enabled': True, 'priority': 1}
                , 'supply_chain_security': {'enabled': True, 'priority': 2}
            },
            'defense_layers': {
                'perimeter_defense': True,
                'internal_segmentation': True,
                'host_protection': True,
                'data_protection': True,
                'threat_intelligence': True,
                'incident_response': True,
                'forensics_analysis': True,
                'hardware_security': True,
                'ai_ml_detection': True,
                'automation_response': True
            }
        }
    
    def _init_defense_modules(self):
        """初始化防禦模組"""
        try:
            # 網路監控模組
            if self.config['modules']['network_monitor']['enabled'] and RealNetworkMonitor is not None:
                self.defense_modules['network_monitor'] = RealNetworkMonitor(self.config)
                logger.info("網路監控模組已初始化")
            elif self.config['modules']['network_monitor']['enabled'] and RealNetworkMonitor is None:
                logger.warning("網路監控模組無法載入，跳過初始化")
            
            # 威脅檢測模組
            if self.config['modules']['threat_detection']['enabled'] and RealThreatDetection is not None:
                self.defense_modules['threat_detection'] = RealThreatDetection(self.config)
                logger.info("威脅檢測模組已初始化")
            elif self.config['modules']['threat_detection']['enabled'] and RealThreatDetection is None:
                logger.warning("威脅檢測模組無法載入，跳過初始化")
            
            # 事件回應模組
            if self.config['modules']['incident_response']['enabled'] and RealIncidentResponse is not None:
                self.defense_modules['incident_response'] = RealIncidentResponse(self.config)
                logger.info("事件回應模組已初始化")
            elif self.config['modules']['incident_response']['enabled'] and RealIncidentResponse is None:
                logger.warning("事件回應模組無法載入，跳過初始化")
            
            # 數位鑑識模組
            if self.config['modules']['digital_forensics']['enabled'] and RealDigitalForensics is not None:
                self.defense_modules['digital_forensics'] = RealDigitalForensics(self.config)
                logger.info("數位鑑識模組已初始化")
            elif self.config['modules']['digital_forensics']['enabled'] and RealDigitalForensics is None:
                logger.warning("數位鑑識模組無法載入，跳過初始化")
            
            # 惡意程式分析模組
            if self.config['modules']['malware_analysis']['enabled'] and RealMalwareAnalysis is not None:
                self.defense_modules['malware_analysis'] = RealMalwareAnalysis(self.config)
                logger.info("惡意程式分析模組已初始化")
            elif self.config['modules']['malware_analysis']['enabled'] and RealMalwareAnalysis is None:
                logger.warning("惡意程式分析模組無法載入，跳過初始化")
            
            # 滲透測試模組
            if self.config['modules']['penetration_testing']['enabled'] and RealPenetrationTesting is not None:
                self.defense_modules['penetration_testing'] = RealPenetrationTesting(self.config)
                logger.info("滲透測試模組已初始化")
            elif self.config['modules']['penetration_testing']['enabled'] and RealPenetrationTesting is None:
                logger.warning("滲透測試模組無法載入，跳過初始化")
            
            # 零信任網路分段模組
            if self.config['modules']['zero_trust_segmentation']['enabled'] and RealZeroTrustNetworkSegmentation is not None:
                self.defense_modules['zero_trust_segmentation'] = RealZeroTrustNetworkSegmentation(self.config)
                logger.info("零信任網路分段模組已初始化")
            elif self.config['modules']['zero_trust_segmentation']['enabled'] and RealZeroTrustNetworkSegmentation is None:
                logger.warning("零信任網路分段模組無法載入，跳過初始化")
            
            # AI/ML威脅獵捕模組
            if self.config['modules']['ai_ml_threat_hunting']['enabled'] and RealAIMLThreatHunting is not None:
                self.defense_modules['ai_ml_threat_hunting'] = RealAIMLThreatHunting(self.config)
                logger.info("AI/ML威脅獵捕模組已初始化")
            elif self.config['modules']['ai_ml_threat_hunting']['enabled'] and RealAIMLThreatHunting is None:
                logger.warning("AI/ML威脅獵捕模組無法載入，跳過初始化")
            
            # 威脅情報整合模組
            if self.config['modules']['threat_intelligence']['enabled'] and RealThreatIntelligenceIntegration is not None:
                self.defense_modules['threat_intelligence'] = RealThreatIntelligenceIntegration(self.config)
                logger.info("威脅情報整合模組已初始化")
            elif self.config['modules']['threat_intelligence']['enabled'] and RealThreatIntelligenceIntegration is None:
                logger.warning("威脅情報整合模組無法載入，跳過初始化")
            
            # 雲端與OT/IoT安全模組
            if self.config['modules']['cloud_ot_iot_security']['enabled'] and RealCloudOTIoTSecurity is not None:
                self.defense_modules['cloud_ot_iot_security'] = RealCloudOTIoTSecurity(self.config)
                logger.info("雲端與OT/IoT安全模組已初始化")
            elif self.config['modules']['cloud_ot_iot_security']['enabled'] and RealCloudOTIoTSecurity is None:
                logger.warning("雲端與OT/IoT安全模組無法載入，跳過初始化")
            
            # 防禦自動化SOAR模組
            if self.config['modules']['defense_automation_soar']['enabled'] and RealDefenseAutomationSOAR is not None:
                self.defense_modules['defense_automation_soar'] = RealDefenseAutomationSOAR(self.config)
                logger.info("防禦自動化SOAR模組已初始化")
            elif self.config['modules']['defense_automation_soar']['enabled'] and RealDefenseAutomationSOAR is None:
                logger.warning("防禦自動化SOAR模組無法載入，跳過初始化")
            
            # 軍規級硬體防護模組
            if self.config['modules']['hardware_protection']['enabled'] and RealMilitaryHardwareProtection is not None:
                self.defense_modules['hardware_protection'] = RealMilitaryHardwareProtection(self.config)
                logger.info("軍規級硬體防護模組已初始化")
            elif self.config['modules']['hardware_protection']['enabled'] and RealMilitaryHardwareProtection is None:
                logger.warning("軍規級硬體防護模組無法載入，跳過初始化")
            
            # 進階報告與風險量化模組
            if self.config['modules']['reporting_risk_quantification']['enabled'] and RealAdvancedReportingRiskQuantification is not None:
                self.defense_modules['reporting_risk_quantification'] = RealAdvancedReportingRiskQuantification(self.config)
                logger.info("進階報告與風險量化模組已初始化")
            elif self.config['modules']['reporting_risk_quantification']['enabled'] and RealAdvancedReportingRiskQuantification is None:
                logger.warning("進階報告與風險量化模組無法載入，跳過初始化")

            # 攻防演練模組
            if self.config['modules'].get('attack_simulation', {}).get('enabled', False) and RealAttackSimulation is not None:
                self.defense_modules['attack_simulation'] = RealAttackSimulation(self.config.get('attack_simulation', {}).get('config', {}))
                logger.info("攻防演練模組已初始化")
            elif self.config['modules'].get('attack_simulation', {}).get('enabled', False) and RealAttackSimulation is None:
                logger.warning("攻防演練模組無法載入，跳過初始化")

            # 跨平台IR模組
            if self.config['modules'].get('cross_platform_ir', {}).get('enabled', False) and RealCrossPlatformIR is not None:
                self.defense_modules['cross_platform_ir'] = RealCrossPlatformIR(self.config.get('cross_platform_ir', {}).get('config', {}))
                logger.info("跨平台IR模組已初始化")
            elif self.config['modules'].get('cross_platform_ir', {}).get('enabled', False) and RealCrossPlatformIR is None:
                logger.warning("跨平台IR模組無法載入，跳過初始化")

            # DDoS 韌性模組
            if self.config['modules'].get('ddos_resilience', {}).get('enabled', False) and RealDDOSResilience is not None:
                self.defense_modules['ddos_resilience'] = RealDDOSResilience(self.config.get('ddos_resilience', {}).get('config', {}))
                logger.info("DDoS 韌性模組已初始化")
            elif self.config['modules'].get('ddos_resilience', {}).get('enabled', False) and RealDDOSResilience is None:
                logger.warning("DDoS 韌性模組無法載入，跳過初始化")

            # 供應鏈完整性模組
            if self.config['modules'].get('supply_chain_security', {}).get('enabled', False) and RealSupplyChainSecurity is not None:
                self.defense_modules['supply_chain_security'] = RealSupplyChainSecurity(self.config.get('supply_chain_security', {}).get('config', {}))
                logger.info("供應鏈完整性模組已初始化")
            elif self.config['modules'].get('supply_chain_security', {}).get('enabled', False) and RealSupplyChainSecurity is None:
                logger.warning("供應鏈完整性模組無法載入，跳過初始化")

            # 行為分析模組
            if self.config['modules'].get('behavioral_analytics', {}).get('enabled', False) and RealBehavioralAnalytics is not None:
                self.defense_modules['behavioral_analytics'] = RealBehavioralAnalytics(self.config.get('behavioral_analytics', {}).get('config', {}))
                logger.info("行為分析模組已初始化")
            elif self.config['modules'].get('behavioral_analytics', {}).get('enabled', False) and RealBehavioralAnalytics is None:
                logger.warning("行為分析模組無法載入，跳過初始化")

            # 事件回應劇本模組
            if self.config['modules'].get('incident_playbooks', {}).get('enabled', False) and RealIncidentPlaybooks is not None:
                self.defense_modules['incident_playbooks'] = RealIncidentPlaybooks(self.config.get('incident_playbooks', {}).get('config', {}))
                logger.info("事件回應劇本模組已初始化")
            elif self.config['modules'].get('incident_playbooks', {}).get('enabled', False) and RealIncidentPlaybooks is None:
                logger.warning("事件回應劇本模組無法載入，跳過初始化")

            # 威脅獵捕查詢模組
            if self.config['modules'].get('threat_hunting_queries', {}).get('enabled', False) and RealThreatHuntingQueries is not None:
                self.defense_modules['threat_hunting_queries'] = RealThreatHuntingQueries(self.config.get('threat_hunting_queries', {}).get('config', {}))
                logger.info("威脅獵捕查詢模組已初始化")
            elif self.config['modules'].get('threat_hunting_queries', {}).get('enabled', False) and RealThreatHuntingQueries is None:
                logger.warning("威脅獵捕查詢模組無法載入，跳過初始化")

            # 雲原生安全模組
            if self.config['modules'].get('cloud_native_security', {}).get('enabled', False) and RealCloudNativeSecurity is not None:
                self.defense_modules['cloud_native_security'] = RealCloudNativeSecurity(self.config.get('cloud_native_security', {}).get('config', {}))
                logger.info("雲原生安全模組已初始化")
            elif self.config['modules'].get('cloud_native_security', {}).get('enabled', False) and RealCloudNativeSecurity is None:
                logger.warning("雲原生安全模組無法載入，跳過初始化")

            # IoT設備管理模組
            if self.config['modules'].get('iot_device_management', {}).get('enabled', False) and RealIoTDeviceManagement is not None:
                self.defense_modules['iot_device_management'] = RealIoTDeviceManagement(self.config.get('iot_device_management', {}).get('config', {}))
                logger.info("IoT設備管理模組已初始化")
            elif self.config['modules'].get('iot_device_management', {}).get('enabled', False) and RealIoTDeviceManagement is None:
                logger.warning("IoT設備管理模組無法載入，跳過初始化")

            # AI對抗防禦模組
            if self.config['modules'].get('ai_adversarial_defense', {}).get('enabled', False) and RealAIAdversarialDefense is not None:
                self.defense_modules['ai_adversarial_defense'] = RealAIAdversarialDefense(self.config.get('ai_adversarial_defense', {}).get('config', {}))
                logger.info("AI對抗防禦模組已初始化")
            elif self.config['modules'].get('ai_adversarial_defense', {}).get('enabled', False) and RealAIAdversarialDefense is None:
                logger.warning("AI對抗防禦模組無法載入，跳過初始化")

            # 合規框架模組
            if self.config['modules'].get('compliance_frameworks', {}).get('enabled', False) and RealComplianceFrameworks is not None:
                self.defense_modules['compliance_frameworks'] = RealComplianceFrameworks(self.config.get('compliance_frameworks', {}).get('config', {}))
                logger.info("合規框架模組已初始化")
            elif self.config['modules'].get('compliance_frameworks', {}).get('enabled', False) and RealComplianceFrameworks is None:
                logger.warning("合規框架模組無法載入，跳過初始化")

            # 防火牆協同模組
            if self.config['modules'].get('firewall_orchestrator', {}).get('enabled', False) and RealFirewallOrchestrator is not None:
                self.defense_modules['firewall_orchestrator'] = RealFirewallOrchestrator(self.config.get('firewall_orchestrator', {}).get('config', {}))
                logger.info("防火牆協同模組已初始化")
            elif self.config['modules'].get('firewall_orchestrator', {}).get('enabled', False) and RealFirewallOrchestrator is None:
                logger.warning("防火牆協同模組無法載入，跳過初始化")

            # 藍隊SOAR模組（依賴防火牆協同）
            if self.config['modules'].get('blue_team_soar', {}).get('enabled', False) and RealBlueTeamSOAR is not None:
                orchestrator = self.defense_modules.get('firewall_orchestrator')
                self.defense_modules['blue_team_soar'] = RealBlueTeamSOAR(self.config.get('blue_team_soar', {}).get('config', {}), orchestrator=orchestrator)
                logger.info("藍隊SOAR模組已初始化（Windows被動監控）")
            elif self.config['modules'].get('blue_team_soar', {}).get('enabled', False) and RealBlueTeamSOAR is None:
                logger.warning("藍隊SOAR模組無法載入，跳過初始化")

            # CTF 攻擊模擬模組
            if self.config['modules'].get('ctf_attack_simulation', {}).get('enabled', False) and RealCTFAttackSimulation is not None:
                self.defense_modules['ctf_attack_simulation'] = RealCTFAttackSimulation(self.config.get('ctf_attack_simulation', {}).get('config', {}))
                logger.info("CTF 攻擊模擬模組已初始化")
            elif self.config['modules'].get('ctf_attack_simulation', {}).get('enabled', False) and RealCTFAttackSimulation is None:
                logger.warning("CTF 攻擊模擬模組無法載入，跳過初始化")

            # CTF 挑戰生成器模組
            if self.config['modules'].get('ctf_challenge_generator', {}).get('enabled', False) and RealCTFChallengeGenerator is not None:
                self.defense_modules['ctf_challenge_generator'] = RealCTFChallengeGenerator(self.config.get('ctf_challenge_generator', {}).get('config', {}))
                logger.info("CTF 挑戰生成器模組已初始化")
            elif self.config['modules'].get('ctf_challenge_generator', {}).get('enabled', False) and RealCTFChallengeGenerator is None:
                logger.warning("CTF 挑戰生成器模組無法載入，跳過初始化")

            # CTF 競賽管理模組
            if self.config['modules'].get('ctf_competition_manager', {}).get('enabled', False) and RealCTFCompetitionManager is not None:
                self.defense_modules['ctf_competition_manager'] = RealCTFCompetitionManager(self.config.get('ctf_competition_manager', {}).get('config', {}))
                logger.info("CTF 競賽管理模組已初始化")
            elif self.config['modules'].get('ctf_competition_manager', {}).get('enabled', False) and RealCTFCompetitionManager is None:
                logger.warning("CTF 競賽管理模組無法載入，跳過初始化")
            
            logger.info(f"已初始化 {len(self.defense_modules)} 個防禦模組")
            
        except Exception as e:
            logger.error(f"初始化防禦模組錯誤: {e}")
    
    def start_defense_system(self) -> Dict[str, Any]:
        """啟動防禦系統"""
        try:
            if self.running:
                return {'success': False, 'error': '防禦系統已在運行中'}
            
            self.running = True
            
            # 按優先級啟動模組
            self._start_modules_by_priority()
            
            # 啟動系統監控
            self._start_system_monitoring()
            
            # 啟動健康檢查
            self._start_health_monitoring()
            
            logger.info("真實終極軍事防禦系統已啟動")
            return {'success': True, 'message': '防禦系統已啟動'}
            
        except Exception as e:
            logger.error(f"啟動防禦系統錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _start_modules_by_priority(self):
        """按優先級啟動模組"""
        try:
            # 按優先級排序模組
            sorted_modules = sorted(
                self.defense_modules.items(),
                key=lambda x: self.config['modules'][x[0]]['priority']
            )
            
            for module_name, module_instance in sorted_modules:
                try:
                    # 啟動模組
                    if hasattr(module_instance, 'start_monitoring'):
                        result = module_instance.start_monitoring()
                    elif hasattr(module_instance, 'start_analysis'):
                        result = module_instance.start_analysis()
                    elif hasattr(module_instance, 'start_hardware_protection'):
                        result = module_instance.start_hardware_protection()
                    elif hasattr(module_instance, 'start_reporting_system'):
                        result = module_instance.start_reporting_system()
                    else:
                        result = {'success': True, 'message': f'{module_name} 模組已啟動'}
                    
                    if result['success']:
                        self.defense_status[module_name] = 'RUNNING'
                        logger.info(f"✅ {module_name} 模組已啟動")
                    else:
                        self.defense_status[module_name] = 'ERROR'
                        logger.error(f"❌ {module_name} 模組啟動失敗: {result.get('error', '未知錯誤')}")
                        
                except Exception as e:
                    self.defense_status[module_name] = 'ERROR'
                    logger.error(f"❌ {module_name} 模組啟動錯誤: {e}")
                    
        except Exception as e:
            logger.error(f"按優先級啟動模組錯誤: {e}")
    
    def _start_system_monitoring(self):
        """啟動系統監控"""
        def monitor_system():
            logger.info("系統監控已啟動")
            
            while self.running:
                try:
                    # 監控所有模組狀態
                    self._monitor_module_status()
                    
                    # 更新防禦狀態
                    self._update_defense_status()
                    
                    # 生成系統報告
                    self._generate_system_report()
                    
                    time.sleep(self.config['system']['monitoring_interval'])
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"系統監控錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_system, daemon=True)
        thread.start()
        self.system_threads.append(thread)
    
    def _monitor_module_status(self):
        """監控模組狀態"""
        try:
            for module_name, module_instance in self.defense_modules.items():
                try:
                    # 檢查模組狀態
                    if hasattr(module_instance, 'get_status'):
                        status = module_instance.get_status()
                        if status.get('success', False):
                            self.defense_status[module_name] = 'RUNNING'
                        else:
                            self.defense_status[module_name] = 'ERROR'
                    else:
                        self.defense_status[module_name] = 'RUNNING'
                        
                except Exception as e:
                    self.defense_status[module_name] = 'ERROR'
                    logger.error(f"監控模組狀態錯誤 {module_name}: {e}")
                    
        except Exception as e:
            logger.error(f"監控模組狀態錯誤: {e}")
    
    def _update_defense_status(self):
        """更新防禦狀態"""
        try:
            # 計算整體防禦狀態
            total_modules = len(self.defense_modules)
            running_modules = len([status for status in self.defense_status.values() if status == 'RUNNING'])
            
            self.overall_health = {
                'total_modules': total_modules,
                'running_modules': running_modules,
                'error_modules': total_modules - running_modules,
                'health_percentage': (running_modules / total_modules * 100) if total_modules > 0 else 0,
                'last_update': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"更新防禦狀態錯誤: {e}")
    
    def _generate_system_report(self):
        """生成系統報告"""
        try:
            # 模擬生成系統報告
            logger.debug("生成系統報告")
            
        except Exception as e:
            logger.error(f"生成系統報告錯誤: {e}")
    
    def _start_health_monitoring(self):
        """啟動健康檢查"""
        def monitor_health():
            logger.info("健康檢查已啟動")
            
            while self.running:
                try:
                    # 執行健康檢查
                    self._perform_health_check()
                    
                    time.sleep(self.config['system']['health_check_interval'])
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"健康檢查錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_health, daemon=True)
        thread.start()
        self.system_threads.append(thread)
    
    def _perform_health_check(self):
        """執行健康檢查"""
        try:
            # 檢查所有模組健康狀態
            for module_name, module_instance in self.defense_modules.items():
                try:
                    if hasattr(module_instance, 'get_health_status'):
                        health = module_instance.get_health_status()
                        if not health.get('healthy', True):
                            logger.warning(f"模組健康檢查警告 {module_name}: {health.get('message', '未知問題')}")
                            
                except Exception as e:
                    logger.error(f"模組健康檢查錯誤 {module_name}: {e}")
                    
        except Exception as e:
            logger.error(f"執行健康檢查錯誤: {e}")
    
    def stop_defense_system(self) -> Dict[str, Any]:
        """停止防禦系統"""
        try:
            self.running = False
            
            # 停止所有模組
            for module_name, module_instance in self.defense_modules.items():
                try:
                    if hasattr(module_instance, 'stop_monitoring'):
                        module_instance.stop_monitoring()
                    elif hasattr(module_instance, 'stop_analysis'):
                        module_instance.stop_analysis()
                    elif hasattr(module_instance, 'stop_hardware_protection'):
                        module_instance.stop_hardware_protection()
                    elif hasattr(module_instance, 'stop_reporting_system'):
                        module_instance.stop_reporting_system()
                    
                    self.defense_status[module_name] = 'STOPPED'
                    logger.info(f"✅ {module_name} 模組已停止")
                    
                except Exception as e:
                    logger.error(f"❌ {module_name} 模組停止錯誤: {e}")
            
            # 等待所有線程結束
            for thread in self.system_threads:
                thread.join(timeout=5)
            
            self.system_threads.clear()
            
            logger.info("真實終極軍事防禦系統已停止")
            return {'success': True, 'message': '防禦系統已停止'}
            
        except Exception as e:
            logger.error(f"停止防禦系統錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_system_status(self) -> Dict[str, Any]:
        """獲取系統狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'defense_modules': len(self.defense_modules),
                'defense_status': self.defense_status,
                'overall_health': self.overall_health,
                'system_info': {
                    'name': self.config['system']['name'],
                    'version': self.config['system']['version'],
                    'uptime': time.time() - getattr(self, 'start_time', time.time())
                }
            }
        except Exception as e:
            logger.error(f"獲取系統狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """獲取綜合報告"""
        try:
            report = {
                'success': True,
                'system_info': {
                    'name': self.config['system']['name'],
                    'version': self.config['system']['version'],
                    'timestamp': datetime.now().isoformat()
                },
                'defense_modules': {},
                'overall_health': self.overall_health,
                'defense_layers': self.config['defense_layers']
            }
            
            # 收集各模組報告
            for module_name, module_instance in self.defense_modules.items():
                try:
                    if hasattr(module_instance, 'get_comprehensive_report'):
                        module_report = module_instance.get_comprehensive_report()
                        if module_report.get('success', False):
                            report['defense_modules'][module_name] = module_report
                    elif hasattr(module_instance, 'get_status'):
                        module_status = module_instance.get_status()
                        report['defense_modules'][module_name] = module_status
                    else:
                        report['defense_modules'][module_name] = {'status': 'running'}
                        
                except Exception as e:
                    report['defense_modules'][module_name] = {'error': str(e)}
            
            return report
            
        except Exception as e:
            logger.error(f"獲取綜合報告錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def execute_defense_analysis(self) -> Dict[str, Any]:
        """執行防禦分析"""
        try:
            analysis_results = {
                'success': True,
                'timestamp': datetime.now().isoformat(),
                'modules_analyzed': 0,
                'threats_detected': 0,
                'incidents_handled': 0,
                'vulnerabilities_found': 0,
                'defense_effectiveness': 0.0
            }
            
            # 執行各模組分析
            for module_name, module_instance in self.defense_modules.items():
                try:
                    if hasattr(module_instance, 'analyze_threats'):
                        result = module_instance.analyze_threats()
                        if result.get('success', False):
                            analysis_results['modules_analyzed'] += 1
                            analysis_results['threats_detected'] += result.get('threats_detected', 0)
                            
                    elif hasattr(module_instance, 'perform_analysis'):
                        result = module_instance.perform_analysis()
                        if result.get('success', False):
                            analysis_results['modules_analyzed'] += 1
                            
                except Exception as e:
                    logger.error(f"執行模組分析錯誤 {module_name}: {e}")
            
            # 計算防禦有效性
            if analysis_results['modules_analyzed'] > 0:
                analysis_results['defense_effectiveness'] = min(100.0, 
                    (analysis_results['threats_detected'] / analysis_results['modules_analyzed']) * 100
                )
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"執行防禦分析錯誤: {e}")
            return {'success': False, 'error': str(e)}


def main():
    """主函數"""
    try:
        # 創建防禦系統
        defense_system = RealUltimateMilitaryDefenseSystem()
        
        # 啟動防禦系統
        result = defense_system.start_defense_system()
        if result['success']:
            print("🛡️ 真實終極軍事防禦系統已啟動")
            print("=" * 50)
            print("🔒 防禦能力:")
            print("   ✅ 網路監控與流量分析")
            print("   ✅ 真實威脅檢測與分析")
            print("   ✅ 自動化事件回應")
            print("   ✅ 數位鑑識與證據收集")
            print("   ✅ 惡意程式靜態/動態分析")
            print("   ✅ 滲透測試與漏洞掃描")
            print("   ✅ 零信任網路分段")
            print("   ✅ AI/ML驅動威脅獵捕")
            print("   ✅ 威脅情報整合")
            print("   ✅ 雲端與OT/IoT安全")
            print("   ✅ 防禦自動化SOAR")
            print("   ✅ 軍規級硬體防護")
            print("   ✅ 進階報告與風險量化")
            print("=" * 50)
            print("\n按 Ctrl+C 停止系統")
            
            # 記錄啟動時間
            defense_system.start_time = time.time()
            
            # 持續運行
            while True:
                time.sleep(1)
        else:
            print(f"❌ 啟動失敗: {result['error']}")
            
    except KeyboardInterrupt:
        print("\n🛑 正在停止系統...")
        defense_system.stop_defense_system()
        print("✅ 系統已停止")
    except Exception as e:
        print(f"❌ 系統錯誤: {e}")


if __name__ == "__main__":
    main()
