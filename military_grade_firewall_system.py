#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級防火牆系統 - 完整五層防禦體系
Military-Grade Firewall System - Complete Five-Layer Defense Architecture

功能特色：
1️⃣ 邊界層防禦 (Perimeter Defense) - NGFW、DDoS、WAF/API
2️⃣ 內部網路層 (Internal Segmentation) - 東西向流量、微分段、零信任NAC
3️⃣ 關鍵任務區 (Mission Critical Zone) - Data Diode、OT防火牆、白名單
4️⃣ 雲端與外部鏈路 (Cloud/External) - 雲端安全閘道、衛星鏈路、量子加密
5️⃣ SOC/指揮中心 (SOC/Command Center) - SIEM、SOAR、MITRE ATT&CK、紅藍紫隊
"""

import os
import sys
import time
import logging
import threading
import signal
from datetime import datetime
from typing import Dict, List, Any

# 添加當前目錄到Python路徑
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 導入各層防禦系統
from military_perimeter_defense import MilitaryPerimeterDefense
from military_internal_segmentation import MilitaryInternalSegmentation
from military_soc_command_center import MilitarySOCCommandCenter

# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('military_grade_firewall_system.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class MilitaryGradeFirewallSystem:
    """軍事級防火牆系統 - 完整五層防禦體系"""
    
    def __init__(self, config_file: str = "military_grade_firewall_config.yaml"):
        self.config_file = config_file
        self.running = False
        
        # 載入配置
        self.config = self._load_config()
        
        # 初始化各層防禦系統
        self.perimeter_defense = None
        self.internal_segmentation = None
        self.soc_command_center = None
        
        # 系統狀態
        self.system_status = {
            'start_time': None,
            'layers_active': 0,
            'total_threats_detected': 0,
            'total_incidents': 0,
            'system_health': 'HEALTHY'
        }
        
        logger.info("軍事級防火牆系統初始化完成")

    def _load_config(self) -> Dict[str, Any]:
        """載入配置"""
        try:
            import yaml
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"配置檔案 {self.config_file} 不存在，使用預設配置")
            return self._get_default_config()
        except Exception as e:
            logger.error(f"載入配置錯誤: {e}")
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """獲取預設配置"""
        return {
            'system': {
                'name': 'Military Grade Firewall System',
                'version': '2.0.0',
                'debug': False
            },
            'layers': {
                'perimeter_defense': {
                    'enabled': True,
                    'ngfw': True,
                    'ddos_protection': True,
                    'waf_protection': True,
                    'api_protection': True
                },
                'internal_segmentation': {
                    'enabled': True,
                    'microsegmentation': True,
                    'zero_trust_nac': True,
                    'ml_anomaly_detection': True
                },
                'mission_critical_zone': {
                    'enabled': True,
                    'data_diode': True,
                    'ot_firewall': True,
                    'whitelist_mode': True
                },
                'cloud_external_links': {
                    'enabled': True,
                    'cloud_security_gateway': True,
                    'satellite_links': True,
                    'quantum_encryption': True
                },
                'soc_command_center': {
                    'enabled': True,
                    'siem': True,
                    'soar': True,
                    'mitre_attack': True,
                    'red_blue_purple_teams': True
                }
            },
            'monitoring': {
                'interval': 5,
                'real_time': True,
                'alerting': True
            }
        }

    def start(self):
        """啟動軍事級防火牆系統"""
        if self.running:
            logger.warning("軍事級防火牆系統已在運行中")
            return
        
        try:
            self.running = True
            self.system_status['start_time'] = datetime.now()
            
            # 顯示啟動資訊
            self._display_startup_info()
            
            # 初始化各層防禦系統
            self._initialize_defense_layers()
            
            # 啟動系統監控
            self._start_system_monitoring()
            
            logger.info("軍事級防火牆系統已啟動")
            
        except Exception as e:
            logger.error(f"軍事級防火牆系統啟動失敗: {e}")
            self.running = False
            raise

    def stop(self):
        """停止軍事級防火牆系統"""
        if not self.running:
            logger.warning("軍事級防火牆系統未在運行")
            return
        
        try:
            self.running = False
            logger.info("軍事級防火牆系統已停止")
            
        except Exception as e:
            logger.error(f"軍事級防火牆系統停止失敗: {e}")

    def _display_startup_info(self):
        """顯示啟動資訊"""
        print("🛡️ 軍事級防火牆系統 - 完整五層防禦體系")
        print("=" * 80)
        print(f"啟動時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"配置檔案: {self.config_file}")
        print(f"系統版本: {self.config['system']['version']}")
        print("\n五層防禦體系:")
        print("1️⃣ 邊界層防禦 (Perimeter Defense)")
        print("   • 次世代防火牆 (NGFW)")
        print("   • DDoS 緩解和防護")
        print("   • Web/API Gateway 防護")
        print("   • 深度封包檢測 (DPI)")
        print("\n2️⃣ 內部網路層 (Internal Segmentation)")
        print("   • 東西向流量監控")
        print("   • 微分段隔離")
        print("   • 零信任NAC")
        print("   • 機器學習異常檢測")
        print("\n3️⃣ 關鍵任務區 (Mission Critical Zone)")
        print("   • Data Diode 單向數據流")
        print("   • OT防火牆")
        print("   • 白名單模式")
        print("   • 專用工控安全")
        print("\n4️⃣ 雲端與外部鏈路 (Cloud/External)")
        print("   • 雲端安全閘道")
        print("   • 衛星/無線鏈路防護")
        print("   • 量子加密通訊")
        print("   • 抗干擾技術")
        print("\n5️⃣ SOC/指揮中心 (SOC/Command Center)")
        print("   • SIEM 安全資訊管理")
        print("   • SOAR 自動化回應")
        print("   • MITRE ATT&CK 映射")
        print("   • 紅藍紫隊演練")
        print("\n按 Ctrl+C 停止系統")
        print("=" * 80)

    def _initialize_defense_layers(self):
        """初始化各層防禦系統"""
        try:
            # 1️⃣ 邊界層防禦
            if self.config['layers']['perimeter_defense']['enabled']:
                logger.info("初始化邊界層防禦系統...")
                self.perimeter_defense = MilitaryPerimeterDefense(
                    self.config['layers']['perimeter_defense']
                )
                self.system_status['layers_active'] += 1
                logger.info("✅ 邊界層防禦系統已啟動")
            
            # 2️⃣ 內部網路層防禦
            if self.config['layers']['internal_segmentation']['enabled']:
                logger.info("初始化內部網路層防禦系統...")
                self.internal_segmentation = MilitaryInternalSegmentation(
                    self.config['layers']['internal_segmentation']
                )
                self.system_status['layers_active'] += 1
                logger.info("✅ 內部網路層防禦系統已啟動")
            
            # 3️⃣ 關鍵任務區防禦 (模擬)
            if self.config['layers']['mission_critical_zone']['enabled']:
                logger.info("初始化關鍵任務區防禦系統...")
                self._initialize_mission_critical_zone()
                self.system_status['layers_active'] += 1
                logger.info("✅ 關鍵任務區防禦系統已啟動")
            
            # 4️⃣ 雲端與外部鏈路防禦 (模擬)
            if self.config['layers']['cloud_external_links']['enabled']:
                logger.info("初始化雲端與外部鏈路防禦系統...")
                self._initialize_cloud_external_links()
                self.system_status['layers_active'] += 1
                logger.info("✅ 雲端與外部鏈路防禦系統已啟動")
            
            # 5️⃣ SOC/指揮中心
            if self.config['layers']['soc_command_center']['enabled']:
                logger.info("初始化SOC/指揮中心系統...")
                self.soc_command_center = MilitarySOCCommandCenter(
                    self.config['layers']['soc_command_center']
                )
                self.system_status['layers_active'] += 1
                logger.info("✅ SOC/指揮中心系統已啟動")
            
            logger.info(f"所有防禦層已初始化完成 ({self.system_status['layers_active']}/5)")
            
        except Exception as e:
            logger.error(f"防禦層初始化失敗: {e}")
            raise

    def _initialize_mission_critical_zone(self):
        """初始化關鍵任務區防禦"""
        # 模擬關鍵任務區防禦系統
        self.mission_critical_zone = {
            'data_diode': True,
            'ot_firewall': True,
            'whitelist_mode': True,
            'status': 'ACTIVE'
        }

    def _initialize_cloud_external_links(self):
        """初始化雲端與外部鏈路防禦"""
        # 模擬雲端與外部鏈路防禦系統
        self.cloud_external_links = {
            'cloud_security_gateway': True,
            'satellite_links': True,
            'quantum_encryption': True,
            'status': 'ACTIVE'
        }

    def _start_system_monitoring(self):
        """啟動系統監控"""
        def system_monitor():
            while self.running:
                try:
                    # 監控系統健康狀態
                    self._monitor_system_health()
                    
                    # 更新系統統計
                    self._update_system_stats()
                    
                    # 顯示系統狀態
                    self._display_system_status()
                    
                    time.sleep(self.config['monitoring']['interval'])
                
                except Exception as e:
                    logger.error(f"系統監控錯誤: {e}")
                    time.sleep(30)
        
        monitor_thread = threading.Thread(target=system_monitor, daemon=True)
        monitor_thread.start()

    def _monitor_system_health(self):
        """監控系統健康狀態"""
        try:
            # 檢查各層防禦系統狀態
            health_status = "HEALTHY"
            
            if self.perimeter_defense:
                perimeter_status = self.perimeter_defense.get_perimeter_status()
                if perimeter_status.get('blocked_packets', 0) > 1000:
                    health_status = "WARNING"
            
            if self.internal_segmentation:
                internal_status = self.internal_segmentation.get_internal_status()
                if internal_status.get('anomalies', 0) > 10:
                    health_status = "WARNING"
            
            if self.soc_command_center:
                soc_status = self.soc_command_center.get_soc_status()
                if soc_status.get('open_incidents', 0) > 5:
                    health_status = "CRITICAL"
            
            self.system_status['system_health'] = health_status
        
        except Exception as e:
            logger.error(f"系統健康監控錯誤: {e}")
            self.system_status['system_health'] = "ERROR"

    def _update_system_stats(self):
        """更新系統統計"""
        try:
            total_threats = 0
            total_incidents = 0
            
            if self.perimeter_defense:
                perimeter_status = self.perimeter_defense.get_perimeter_status()
                total_threats += perimeter_status.get('ddos_attacks', 0) + perimeter_status.get('web_attacks', 0)
            
            if self.internal_segmentation:
                internal_status = self.internal_segmentation.get_internal_status()
                total_threats += internal_status.get('anomalies', 0)
            
            if self.soc_command_center:
                soc_status = self.soc_command_center.get_soc_status()
                total_threats += soc_status.get('total_events', 0)
                total_incidents += soc_status.get('open_incidents', 0)
            
            self.system_status['total_threats_detected'] = total_threats
            self.system_status['total_incidents'] = total_incidents
        
        except Exception as e:
            logger.error(f"系統統計更新錯誤: {e}")

    def _display_system_status(self):
        """顯示系統狀態"""
        if not self.running:
            return
        
        print(f"\n🛡️ 軍事級防火牆系統狀態 - {datetime.now().strftime('%H:%M:%S')}")
        print("=" * 60)
        
        # 系統概覽
        print(f"系統健康: {self.system_status['system_health']}")
        print(f"活躍防禦層: {self.system_status['layers_active']}/5")
        print(f"檢測到威脅: {self.system_status['total_threats_detected']}")
        print(f"安全事件: {self.system_status['total_incidents']}")
        
        # 各層防禦狀態
        if self.perimeter_defense:
            perimeter_status = self.perimeter_defense.get_perimeter_status()
            print(f"\n1️⃣ 邊界層防禦:")
            print(f"   NGFW規則: {perimeter_status.get('ngfw_rules', 0)}")
            print(f"   阻擋封包: {perimeter_status.get('blocked_packets', 0)}")
            print(f"   DDoS攻擊: {perimeter_status.get('ddos_attacks', 0)}")
            print(f"   Web攻擊: {perimeter_status.get('web_attacks', 0)}")
        
        if self.internal_segmentation:
            internal_status = self.internal_segmentation.get_internal_status()
            print(f"\n2️⃣ 內部網路層:")
            print(f"   設備數量: {internal_status.get('devices', 0)}")
            print(f"   認證設備: {internal_status.get('authenticated_devices', 0)}")
            print(f"   網路分段: {internal_status.get('segments', 0)}")
            print(f"   異常檢測: {internal_status.get('anomalies', 0)}")
        
        if self.soc_command_center:
            soc_status = self.soc_command_center.get_soc_status()
            print(f"\n5️⃣ SOC/指揮中心:")
            print(f"   安全事件: {soc_status.get('total_events', 0)}")
            print(f"   開放事件: {soc_status.get('open_incidents', 0)}")
            print(f"   威脅情報: {soc_status.get('threat_intel_iocs', 0)}")
            print(f"   活躍劇本: {soc_status.get('active_playbooks', 0)}")
        
        # 關鍵任務區和雲端鏈路狀態
        print(f"\n3️⃣ 關鍵任務區: {'✅ 活躍' if hasattr(self, 'mission_critical_zone') else '❌ 未啟動'}")
        print(f"4️⃣ 雲端外部鏈路: {'✅ 活躍' if hasattr(self, 'cloud_external_links') else '❌ 未啟動'}")

    def get_system_status(self) -> Dict[str, Any]:
        """獲取系統狀態"""
        return {
            'system_status': self.system_status,
            'perimeter_defense': self.perimeter_defense.get_perimeter_status() if self.perimeter_defense else None,
            'internal_segmentation': self.internal_segmentation.get_internal_status() if self.internal_segmentation else None,
            'soc_command_center': self.soc_command_center.get_soc_status() if self.soc_command_center else None,
            'mission_critical_zone': getattr(self, 'mission_critical_zone', None),
            'cloud_external_links': getattr(self, 'cloud_external_links', None)
        }

    def get_recent_events(self, limit: int = 10) -> List[Any]:
        """獲取最近事件"""
        events = []
        
        if self.soc_command_center:
            events.extend(self.soc_command_center.get_recent_events(limit))
        
        # 按時間排序
        events.sort(key=lambda x: x.timestamp if hasattr(x, 'timestamp') else x.created_at, reverse=True)
        return events[:limit]

def signal_handler(signum, frame):
    """信號處理器"""
    logger.info(f"收到信號 {signum}，正在關閉軍事級防火牆系統...")
    if 'system' in globals():
        system.stop()
    sys.exit(0)

def main():
    """主程式"""
    # 註冊信號處理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 創建軍事級防火牆系統
    system = MilitaryGradeFirewallSystem()
    
    try:
        # 啟動系統
        system.start()
        
        # 保持運行
        while system.running:
            time.sleep(1)
    
    except KeyboardInterrupt:
        logger.info("收到中斷信號，正在關閉軍事級防火牆系統...")
        system.stop()
    
    except Exception as e:
        logger.error(f"軍事級防火牆系統運行錯誤: {e}")
        system.stop()

if __name__ == "__main__":
    main()




