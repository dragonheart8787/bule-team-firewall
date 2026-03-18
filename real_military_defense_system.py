#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實軍事級防禦系統
Real Military Defense System
"""

import os
import sys
import json
import time
import logging
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional

# 導入真實防禦模組
from real_network_monitor import RealNetworkMonitor
from real_threat_detection import RealThreatDetector
from real_incident_response import RealIncidentResponse
from real_digital_forensics import RealDigitalForensics
from real_malware_analysis import RealMalwareAnalysis
from real_penetration_testing import RealPenetrationTesting

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealMilitaryDefenseSystem:
    """真實軍事級防禦系統"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.defense_modules = {}
        self.system_status = {}
        self.defense_threads = []
        
        # 初始化防禦模組
        self._init_defense_modules()
        
        logger.info("真實軍事級防禦系統初始化完成")
    
    def _init_defense_modules(self):
        """初始化防禦模組"""
        try:
            # 網路監控模組
            self.defense_modules['network_monitor'] = RealNetworkMonitor({
                'monitor_interface': 'any',
                'log_level': 'INFO'
            })
            
            # 威脅檢測模組
            self.defense_modules['threat_detector'] = RealThreatDetector({
                'log_level': 'INFO',
                'scan_interval': 30
            })
            
            # 事件回應模組
            self.defense_modules['incident_response'] = RealIncidentResponse({
                'quarantine_dir': 'quarantine',
                'evidence_dir': 'evidence',
                'log_level': 'INFO'
            })
            
            # 數位鑑識模組
            self.defense_modules['digital_forensics'] = RealDigitalForensics({
                'forensics_dir': 'forensics',
                'temp_dir': 'temp_forensics',
                'log_level': 'INFO'
            })
            
            # 惡意程式分析模組
            self.defense_modules['malware_analysis'] = RealMalwareAnalysis({
                'sandbox_dir': 'sandbox',
                'quarantine_dir': 'quarantine',
                'analysis_dir': 'malware_analysis',
                'log_level': 'INFO'
            })
            
            # 滲透測試模組
            self.defense_modules['penetration_testing'] = RealPenetrationTesting({
                'reports_dir': 'penetration_reports',
                'tools_dir': 'penetration_tools',
                'log_level': 'INFO'
            })
            
            logger.info("防禦模組初始化完成")
            
        except Exception as e:
            logger.error(f"防禦模組初始化錯誤: {e}")
    
    def start_defense_system(self) -> Dict[str, Any]:
        """啟動防禦系統"""
        try:
            if self.running:
                return {'success': False, 'error': '防禦系統已在運行中'}
            
            self.running = True
            
            # 啟動所有防禦模組
            for module_name, module in self.defense_modules.items():
                try:
                    if hasattr(module, 'start_monitoring'):
                        result = module.start_monitoring()
                    elif hasattr(module, 'start_detection'):
                        result = module.start_detection()
                    elif hasattr(module, 'start_response_system'):
                        result = module.start_response_system()
                    elif hasattr(module, 'start_forensics'):
                        result = module.start_forensics()
                    elif hasattr(module, 'start_analysis'):
                        result = module.start_analysis()
                    elif hasattr(module, 'start_penetration_testing'):
                        result = module.start_penetration_testing()
                    else:
                        result = {'success': False, 'error': f'模組 {module_name} 沒有啟動方法'}
                    
                    if result['success']:
                        logger.info(f"✅ {module_name} 模組已啟動")
                    else:
                        logger.error(f"❌ {module_name} 模組啟動失敗: {result.get('error', '未知錯誤')}")
                        
                except Exception as e:
                    logger.error(f"啟動 {module_name} 模組錯誤: {e}")
            
            # 啟動系統監控
            self._start_system_monitoring()
            
            logger.info("真實軍事級防禦系統已啟動")
            return {'success': True, 'message': '防禦系統已啟動'}
            
        except Exception as e:
            logger.error(f"啟動防禦系統錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _start_system_monitoring(self):
        """啟動系統監控"""
        def monitor_system():
            logger.info("系統監控已啟動")
            
            while self.running:
                try:
                    # 監控各模組狀態
                    self._monitor_module_status()
                    
                    # 生成系統報告
                    self._generate_system_report()
                    
                    time.sleep(60)  # 每分鐘監控一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"系統監控錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_system, daemon=True)
        thread.start()
        self.defense_threads.append(thread)
    
    def _monitor_module_status(self):
        """監控模組狀態"""
        try:
            for module_name, module in self.defense_modules.items():
                try:
                    if hasattr(module, 'get_monitoring_status'):
                        status = module.get_monitoring_status()
                    elif hasattr(module, 'get_detection_status'):
                        status = module.get_detection_status()
                    elif hasattr(module, 'get_response_status'):
                        status = module.get_response_status()
                    elif hasattr(module, 'get_forensics_status'):
                        status = module.get_forensics_status()
                    elif hasattr(module, 'get_analysis_status'):
                        status = module.get_analysis_status()
                    elif hasattr(module, 'get_penetration_status'):
                        status = module.get_penetration_status()
                    else:
                        status = {'success': False, 'error': f'模組 {module_name} 沒有狀態方法'}
                    
                    self.system_status[module_name] = status
                    
                except Exception as e:
                    logger.error(f"監控 {module_name} 模組狀態錯誤: {e}")
                    self.system_status[module_name] = {'success': False, 'error': str(e)}
                    
        except Exception as e:
            logger.error(f"監控模組狀態錯誤: {e}")
    
    def _generate_system_report(self):
        """生成系統報告"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'system_status': self.system_status,
                'defense_summary': self._get_defense_summary()
            }
            
            # 保存報告
            report_file = f"defense_report_{int(time.time())}.json"
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"系統報告已生成: {report_file}")
            
        except Exception as e:
            logger.error(f"生成系統報告錯誤: {e}")
    
    def _get_defense_summary(self) -> Dict[str, Any]:
        """獲取防禦摘要"""
        try:
            summary = {
                'total_modules': len(self.defense_modules),
                'active_modules': 0,
                'threats_detected': 0,
                'incidents_handled': 0,
                'vulnerabilities_found': 0,
                'system_health': 'OPERATIONAL'
            }
            
            # 統計各模組狀態
            for module_name, status in self.system_status.items():
                if status.get('success', False):
                    summary['active_modules'] += 1
                
                # 統計威脅和事件
                if module_name == 'threat_detector':
                    summary['threats_detected'] = status.get('total_threats_detected', 0)
                elif module_name == 'incident_response':
                    summary['incidents_handled'] = status.get('active_incidents', 0)
                elif module_name == 'penetration_testing':
                    summary['vulnerabilities_found'] = status.get('vulnerabilities_found', 0)
            
            # 計算系統健康狀態
            if summary['active_modules'] < len(self.defense_modules) * 0.8:
                summary['system_health'] = 'DEGRADED'
            elif summary['active_modules'] < len(self.defense_modules) * 0.5:
                summary['system_health'] = 'CRITICAL'
            
            return summary
            
        except Exception as e:
            logger.error(f"獲取防禦摘要錯誤: {e}")
            return {}
    
    def stop_defense_system(self) -> Dict[str, Any]:
        """停止防禦系統"""
        try:
            self.running = False
            
            # 停止所有防禦模組
            for module_name, module in self.defense_modules.items():
                try:
                    if hasattr(module, 'stop_monitoring'):
                        result = module.stop_monitoring()
                    elif hasattr(module, 'stop_detection'):
                        result = module.stop_detection()
                    elif hasattr(module, 'stop_response_system'):
                        result = module.stop_response_system()
                    elif hasattr(module, 'stop_forensics'):
                        result = module.stop_forensics()
                    elif hasattr(module, 'stop_analysis'):
                        result = module.stop_analysis()
                    elif hasattr(module, 'stop_penetration_testing'):
                        result = module.stop_penetration_testing()
                    else:
                        result = {'success': False, 'error': f'模組 {module_name} 沒有停止方法'}
                    
                    if result['success']:
                        logger.info(f"✅ {module_name} 模組已停止")
                    else:
                        logger.error(f"❌ {module_name} 模組停止失敗: {result.get('error', '未知錯誤')}")
                        
                except Exception as e:
                    logger.error(f"停止 {module_name} 模組錯誤: {e}")
            
            # 等待所有線程結束
            for thread in self.defense_threads:
                thread.join(timeout=5)
            
            self.defense_threads.clear()
            
            logger.info("真實軍事級防禦系統已停止")
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
                'system_status': self.system_status,
                'defense_summary': self._get_defense_summary(),
                'modules': list(self.defense_modules.keys())
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
                    'timestamp': datetime.now().isoformat(),
                    'system_status': self.system_status,
                    'defense_summary': self._get_defense_summary()
                },
                'module_reports': {}
            }
            
            # 獲取各模組報告
            for module_name, module in self.defense_modules.items():
                try:
                    if hasattr(module, 'get_detailed_report'):
                        report['module_reports'][module_name] = module.get_detailed_report()
                    elif hasattr(module, 'get_threat_report'):
                        report['module_reports'][module_name] = module.get_threat_report()
                    elif hasattr(module, 'get_incident_report'):
                        report['module_reports'][module_name] = module.get_incident_report()
                    elif hasattr(module, 'get_forensics_report'):
                        report['module_reports'][module_name] = module.get_forensics_report()
                    elif hasattr(module, 'get_analysis_report'):
                        report['module_reports'][module_name] = module.get_analysis_report()
                    elif hasattr(module, 'get_penetration_report'):
                        report['module_reports'][module_name] = module.get_penetration_report()
                    else:
                        report['module_reports'][module_name] = {'success': False, 'error': f'模組 {module_name} 沒有報告方法'}
                        
                except Exception as e:
                    logger.error(f"獲取 {module_name} 模組報告錯誤: {e}")
                    report['module_reports'][module_name] = {'success': False, 'error': str(e)}
            
            return report
            
        except Exception as e:
            logger.error(f"獲取綜合報告錯誤: {e}")
            return {'success': False, 'error': str(e)}


def main():
    """主函數"""
    config = {
        'log_level': 'INFO',
        'system_name': 'Real Military Defense System'
    }
    
    defense_system = RealMilitaryDefenseSystem(config)
    
    try:
        # 啟動防禦系統
        result = defense_system.start_defense_system()
        if result['success']:
            print("✅ 真實軍事級防禦系統已啟動")
            print("🛡️ 防禦模組:")
            print("   - 網路監控")
            print("   - 威脅檢測")
            print("   - 事件回應")
            print("   - 數位鑑識")
            print("   - 惡意程式分析")
            print("   - 滲透測試")
            print("\n按 Ctrl+C 停止系統")
            
            # 持續運行
            while True:
                time.sleep(1)
        else:
            print(f"❌ 啟動失敗: {result['error']}")
            
    except KeyboardInterrupt:
        print("\n🛑 正在停止防禦系統...")
        defense_system.stop_defense_system()
        print("✅ 防禦系統已停止")
    except Exception as e:
        print(f"❌ 系統錯誤: {e}")


if __name__ == "__main__":
    main()

