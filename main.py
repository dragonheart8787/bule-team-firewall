#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級防火牆系統主程式
Military-Grade Firewall System Main Program

整合所有模組的統一入口點
"""

import sys
import os
import time
import signal
import logging
import argparse
import threading
from datetime import datetime
from typing import Dict, Any

# 添加 src/ 目錄到 Python 路徑（核心模組所在位置）
_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, _ROOT)

# 導入所有模組
from military_firewall import MilitaryFirewall
from intrusion_detection import IntrusionDetectionSystem
from threat_intelligence import ThreatIntelligenceManager
from packet_filter import PacketFilterEngine
from config_manager import ConfigurationManager
from audit_logger import AuditLogger
from dashboard import FirewallDashboard, create_templates
from military_crypto import MilitaryCryptography
from advanced_threat_hunting import AdvancedThreatHunter
from zero_trust_architecture import ZeroTrustEngine
from red_team_simulation import RedTeamSimulator
from quantum_resistance import QuantumResistantCrypto
from military_standards import MilitaryStandardsManager

# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('military_firewall.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class MilitaryFirewallSystem:
    """軍事級防火牆系統主類別"""
    
    def __init__(self, config_file: str = "config/firewall_config.yaml"):
        self.config_file = config_file
        self.running = False
        self.threads = []
        
        # 初始化所有組件
        self._init_components()
        
        logger.info("軍事級防火牆系統初始化完成")

    def _init_components(self):
        """初始化所有組件"""
        try:
            # 建立配置管理器
            self.config_manager = ConfigurationManager()
            
            # 建立審計日誌器
            audit_config = {
                'log_dir': 'logs',
                'retention_days': 30
            }
            self.audit_logger = AuditLogger(audit_config)
            
            # 建立軍事級加密系統
            crypto_config = {
                'key_rotation_interval': 86400,
                'max_key_usage': 1000000,
                'default_key_lifetime': 365
            }
            self.military_crypto = MilitaryCryptography(crypto_config)
            
            # 建立量子抗性加密系統
            quantum_config = {
                'key_rotation_interval': 86400,
                'quantum_threat_assessment': True,
                'hybrid_system_enabled': True
            }
            self.quantum_crypto = QuantumResistantCrypto(quantum_config)
            
            # 建立威脅情報管理器
            threat_intel_config = {
                'threat_intel': {
                    'enabled': True,
                    'update_interval': 3600,
                    'sources': []
                }
            }
            self.threat_intel = ThreatIntelligenceManager(threat_intel_config)
            
            # 建立高級威脅獵殺系統
            hunting_config = {
                'anomaly_threshold': 0.7,
                'pattern_match_threshold': 0.7,
                'analysis_interval': 3600
            }
            self.threat_hunter = AdvancedThreatHunter(hunting_config)
            
            # 建立零信任架構
            zt_config = {
                'trust_decay_rate': 0.1,
                'verification_interval': 300,
                'policy_evaluation_timeout': 5
            }
            self.zero_trust = ZeroTrustEngine(zt_config)
            
            # 建立紅隊模擬器
            red_team_config = {
                'max_concurrent_tests': 5,
                'test_timeout': 3600,
                'report_generation': True
            }
            self.red_team = RedTeamSimulator(red_team_config)
            
            # 建立軍事標準管理器
            standards_config = {
                'assessment_interval': 90,
                'compliance_threshold': 0.8,
                'auto_assessment': True
            }
            self.military_standards = MilitaryStandardsManager(standards_config)
            
            # 建立入侵檢測系統
            ids_config = {
                'ids': {
                    'enabled': True,
                    'signature_database': 'signatures.db',
                    'anomaly_detection': True,
                    'ml_detection': True,
                    'sensitivity': 7
                }
            }
            self.ids = IntrusionDetectionSystem(ids_config)
            
            # 建立封包過濾引擎
            self.packet_filter = PacketFilterEngine()
            
            # 建立主防火牆
            self.firewall = MilitaryFirewall(self.config_file)
            
            # 建立監控儀表板
            self.dashboard = FirewallDashboard(self.firewall, self.ids)
            
            logger.info("所有組件初始化成功")
            
        except Exception as e:
            logger.error(f"組件初始化失敗: {e}")
            raise

    def start(self):
        """啟動系統"""
        if self.running:
            logger.warning("系統已在運行中")
            return
        
        try:
            logger.info("正在啟動軍事級防火牆系統...")
            
            # 記錄系統啟動
            self.audit_logger.log_event(
                level=logging.INFO,
                event_type="SYSTEM",
                message="軍事級防火牆系統啟動",
                source="main",
                user_id="system",
                details={"version": "1.0.0", "config_file": self.config_file}
            )
            
            # 啟動威脅情報監控
            self.threat_intel.start_monitoring()
            
            # 啟動防火牆監控
            self.firewall.start_monitoring()
            
            # 啟動儀表板
            dashboard_thread = threading.Thread(
                target=self._run_dashboard,
                daemon=True
            )
            dashboard_thread.start()
            self.threads.append(dashboard_thread)
            
            # 啟動系統監控
            monitor_thread = threading.Thread(
                target=self._system_monitor,
                daemon=True
            )
            monitor_thread.start()
            self.threads.append(monitor_thread)
            
            self.running = True
            logger.info("軍事級防火牆系統啟動完成")
            
            # 顯示系統狀態
            self._display_system_status()
            
        except Exception as e:
            logger.error(f"系統啟動失敗: {e}")
            self.stop()
            raise

    def stop(self):
        """停止系統"""
        if not self.running:
            return
        
        logger.info("正在停止軍事級防火牆系統...")
        
        try:
            # 記錄系統停止
            self.audit_logger.log_event(
                level=logging.INFO,
                event_type="SYSTEM",
                message="軍事級防火牆系統停止",
                source="main",
                user_id="system"
            )
            
            # 停止防火牆
            self.firewall.stop_monitoring()
            
            # 停止威脅情報監控
            self.threat_intel.stop_monitoring()
            
            # 等待所有線程結束
            for thread in self.threads:
                thread.join(timeout=5)
            
            self.running = False
            logger.info("軍事級防火牆系統已停止")
            
        except Exception as e:
            logger.error(f"系統停止錯誤: {e}")

    def _run_dashboard(self):
        """運行儀表板"""
        try:
            self.dashboard.run(host='0.0.0.0', port=5000, debug=False)
        except Exception as e:
            logger.error(f"儀表板運行錯誤: {e}")

    def _system_monitor(self):
        """系統監控"""
        while self.running:
            try:
                # 獲取系統統計
                firewall_stats = self.firewall.get_statistics()
                ids_stats = self.ids.get_attack_statistics()
                threat_intel_stats = self.threat_intel.get_statistics()
                audit_stats = self.audit_logger.get_statistics()
                
                # 記錄系統狀態
                if firewall_stats['stats']['packets_processed'] % 1000 == 0:
                    logger.info(f"系統狀態 - 封包: {firewall_stats['stats']['packets_processed']}, "
                              f"威脅: {ids_stats['total_attacks']}, "
                              f"指標: {threat_intel_stats['total_indicators']}")
                
                time.sleep(60)  # 每分鐘檢查一次
            
            except Exception as e:
                logger.error(f"系統監控錯誤: {e}")
                time.sleep(60)

    def _display_system_status(self):
        """顯示系統狀態"""
        print("\n" + "="*60)
        print("🛡️  軍事級防火牆系統")
        print("="*60)
        print(f"啟動時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"配置檔案: {self.config_file}")
        print("\n系統組件:")
        print("✅ 核心防火牆引擎")
        print("✅ 入侵檢測系統 (IDS)")
        print("✅ 威脅情報管理")
        print("✅ 封包過濾引擎")
        print("✅ 配置管理器")
        print("✅ 審計日誌系統")
        print("✅ 監控儀表板")
        print("✅ 軍事級加密系統")
        print("✅ 量子抗性加密")
        print("✅ 高級威脅獵殺")
        print("✅ 零信任架構")
        print("✅ 紅隊模擬器")
        print("✅ 軍事標準管理")
        print("\n監控儀表板: http://localhost:5000")
        print("預設帳號: admin / military2024")
        print("\n按 Ctrl+C 停止系統")
        print("="*60)

    def get_system_status(self) -> Dict[str, Any]:
        """獲取系統狀態"""
        return {
            'running': self.running,
            'start_time': datetime.now().isoformat(),
            'components': {
                'firewall': self.firewall.get_statistics(),
                'ids': self.ids.get_attack_statistics(),
                'threat_intel': self.threat_intel.get_statistics(),
                'audit_logger': self.audit_logger.get_statistics(),
                'config_manager': self.config_manager.get_statistics(),
                'military_crypto': self.military_crypto.get_key_statistics(),
                'quantum_crypto': self.quantum_crypto.get_quantum_resistance_status(),
                'threat_hunter': self.threat_hunter.get_threat_intelligence(),
                'zero_trust': self.zero_trust.get_statistics(),
                'red_team': self.red_team.get_statistics(),
                'military_standards': self.military_standards.get_statistics()
            }
        }

def signal_handler(signum, frame):
    """信號處理器"""
    logger.info(f"收到信號 {signum}，正在關閉系統...")
    if 'firewall_system' in globals():
        firewall_system.stop()
    sys.exit(0)

def main():
    """主程式"""
    parser = argparse.ArgumentParser(description='軍事級防火牆系統')
    parser.add_argument('--config', '-c', default='config/firewall_config.yaml',
                       help='配置檔案路徑')
    parser.add_argument('--daemon', '-d', action='store_true',
                       help='以守護進程模式運行')
    parser.add_argument('--status', '-s', action='store_true',
                       help='顯示系統狀態')
    
    args = parser.parse_args()
    
    # 設定信號處理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # 建立系統實例
        global firewall_system
        firewall_system = MilitaryFirewallSystem(args.config)
        
        if args.status:
            # 顯示狀態
            status = firewall_system.get_system_status()
            print(json.dumps(status, indent=2, ensure_ascii=False))
            return
        
        # 建立HTML模板
        create_templates()
        
        # 啟動系統
        firewall_system.start()
        
        # 主循環
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("收到中斷信號")
        finally:
            firewall_system.stop()
    
    except Exception as e:
        logger.error(f"系統運行錯誤: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
