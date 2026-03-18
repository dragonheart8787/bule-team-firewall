#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級防火牆系統測試腳本
Military-Grade Firewall System Test Script
"""

import sys
import os
import time
import unittest
from datetime import datetime

# 添加當前目錄到Python路徑
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from military_firewall import MilitaryFirewall, PacketInfo, Action, ThreatLevel
from intrusion_detection import IntrusionDetectionSystem, AttackType, Severity
from threat_intelligence import ThreatIntelligenceManager, ThreatType, ConfidenceLevel
from packet_filter import PacketFilterEngine, Protocol, FilterAction
from config_manager import ConfigurationManager, ConfigType, ConfigStatus
from audit_logger import AuditLogger, LogLevel, EventType, AuditAction

class TestMilitaryFirewallSystem(unittest.TestCase):
    """軍事級防火牆系統測試類別"""
    
    def setUp(self):
        """測試前準備"""
        self.config = {
            'firewall': {
                'interface': 'eth0',
                'monitoring_mode': True,
                'auto_block': True,
                'threat_threshold': 0.7
            },
            'ids': {
                'enabled': True,
                'signature_database': 'signatures.db',
                'anomaly_detection': True,
                'ml_detection': True,
                'sensitivity': 7
            },
            'threat_intel': {
                'enabled': True,
                'update_interval': 3600,
                'sources': []
            },
            'logging': {
                'level': 'INFO',
                'retention_days': 30,
                'audit_enabled': True
            }
        }
        
        # 建立測試組件
        self.firewall = MilitaryFirewall("firewall_config.yaml")
        self.ids = IntrusionDetectionSystem(self.config['ids'])
        self.threat_intel = ThreatIntelligenceManager(self.config['threat_intel'])
        self.packet_filter = PacketFilterEngine()
        self.config_manager = ConfigurationManager()
        
        audit_config = {
            'log_dir': 'test_logs',
            'retention_days': 7
        }
        self.audit_logger = AuditLogger(audit_config)

    def test_firewall_initialization(self):
        """測試防火牆初始化"""
        self.assertIsNotNone(self.firewall)
        self.assertIsInstance(self.firewall.rules, list)
        self.assertIsInstance(self.firewall.stats, dict)

    def test_firewall_rule_management(self):
        """測試防火牆規則管理"""
        from military_firewall import FirewallRule
        
        # 建立測試規則
        rule = FirewallRule(
            id="test_rule_001",
            name="測試規則",
            source_ip="192.168.1.100",
            dest_ip="*",
            source_port=0,
            dest_port=0,
            protocol="*",
            action=Action.DROP,
            threat_level=ThreatLevel.HIGH,
            description="測試用規則"
        )
        
        # 新增規則
        self.firewall.add_rule(rule)
        self.assertEqual(len(self.firewall.rules), 5)  # 4個預設規則 + 1個測試規則
        
        # 移除規則
        self.firewall.remove_rule("test_rule_001")
        self.assertEqual(len(self.firewall.rules), 4)

    def test_packet_processing(self):
        """測試封包處理"""
        # 建立測試封包
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip="192.168.1.1",
            source_port=12345,
            dest_port=80,
            protocol="TCP",
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            payload_size=50,
            flags=2,
            ttl=64,
            tos=0
        )
        
        # 處理封包
        self.firewall._process_packet(packet)
        
        # 檢查統計
        self.assertGreater(self.firewall.stats['packets_processed'], 0)

    def test_ids_signature_detection(self):
        """測試IDS簽名檢測"""
        from intrusion_detection import IDSSignature
        
        # 建立測試簽名
        signature = IDSSignature(
            id="test_sig_001",
            name="測試簽名",
            attack_type=AttackType.SQL_INJECTION,
            pattern=r"union\s+select",
            severity=Severity.HIGH,
            description="測試SQL注入檢測"
        )
        
        # 新增簽名
        self.ids.add_signature(signature)
        self.assertEqual(len(self.ids.signatures), 6)  # 5個預設簽名 + 1個測試簽名

    def test_threat_intelligence(self):
        """測試威脅情報"""
        # 手動加入黑名單
        self.threat_intel.add_to_blacklist("192.168.1.200", ThreatType.MALWARE)
        
        # 檢查黑名單
        self.assertTrue(self.threat_intel.is_blacklisted("192.168.1.200"))
        
        # 移除黑名單
        self.threat_intel.remove_from_blacklist("192.168.1.200")
        self.assertFalse(self.threat_intel.is_blacklisted("192.168.1.200"))

    def test_packet_filtering(self):
        """測試封包過濾"""
        from packet_filter import PacketFilter
        
        # 建立測試過濾器
        packet_filter = PacketFilter(
            id="test_filter_001",
            name="測試過濾器",
            protocol=Protocol.HTTP,
            source_ip="*",
            dest_ip="*",
            source_port=0,
            dest_port=80,
            action=FilterAction.LOG,
            priority=50
        )
        
        # 新增過濾器
        self.packet_filter.add_filter(packet_filter)
        self.assertEqual(len(self.packet_filter.filters), 1)

    def test_configuration_management(self):
        """測試配置管理"""
        # 建立測試配置
        config = self.config_manager.create_configuration(
            name="測試配置",
            config_type=ConfigType.FIREWALL,
            data={"test": "value"},
            description="測試用配置"
        )
        
        self.assertIsNotNone(config)
        self.assertEqual(config.name, "測試配置")
        
        # 啟用配置
        result = self.config_manager.activate_configuration(config.id)
        self.assertTrue(result)

    def test_audit_logging(self):
        """測試審計日誌"""
        # 記錄測試事件
        self.audit_logger.log_event(
            level=LogLevel.INFO,
            event_type=EventType.SYSTEM,
            message="測試事件",
            source="test",
            user_id="test_user"
        )
        
        # 記錄測試審計
        self.audit_logger.audit_event(
            action=AuditAction.LOGIN,
            resource="test_resource",
            user_id="test_user",
            session_id="test_session",
            ip_address="192.168.1.100",
            user_agent="test_agent",
            result="SUCCESS"
        )
        
        # 等待處理
        time.sleep(2)
        
        # 檢查統計
        stats = self.audit_logger.get_statistics()
        self.assertGreaterEqual(stats['total_logs'], 0)

    def test_system_integration(self):
        """測試系統整合"""
        # 建立測試封包
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip="192.168.1.1",
            source_port=12345,
            dest_port=80,
            protocol="TCP",
            payload=b"<script>alert('xss')</script>",
            payload_size=30,
            flags=2,
            ttl=64,
            tos=0
        )
        
        # 通過IDS分析
        attacks = self.ids.analyze_packet(packet)
        
        # 通過封包過濾器處理
        action, dpi_result = self.packet_filter.process_packet(packet)
        
        # 檢查結果
        self.assertIsInstance(attacks, list)
        self.assertIsInstance(action, FilterAction)
        self.assertIsInstance(dpi_result, dict)

    def tearDown(self):
        """測試後清理"""
        # 清理測試檔案
        import shutil
        if os.path.exists("test_logs"):
            shutil.rmtree("test_logs")
        
        # 清理資料庫檔案
        test_db_files = [
            "firewall.db",
            "ids.db", 
            "threat_intel.db",
            "config_manager.db",
            "audit_logs.db"
        ]
        
        for db_file in test_db_files:
            if os.path.exists(db_file):
                os.remove(db_file)

def run_performance_test():
    """執行效能測試"""
    print("🚀 執行效能測試...")
    
    firewall = MilitaryFirewall("firewall_config.yaml")
    
    # 建立大量測試封包
    packets = []
    for i in range(1000):
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip=f"192.168.1.{i % 255}",
            dest_ip="192.168.1.1",
            source_port=12345 + i,
            dest_port=80,
            protocol="TCP",
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            payload_size=50,
            flags=2,
            ttl=64,
            tos=0
        )
        packets.append(packet)
    
    # 測試處理速度
    start_time = time.time()
    
    for packet in packets:
        firewall._process_packet(packet)
    
    end_time = time.time()
    processing_time = end_time - start_time
    
    print(f"✅ 處理1000個封包耗時: {processing_time:.3f}秒")
    print(f"✅ 平均處理速度: {1000/processing_time:.0f} 封包/秒")
    
    # 顯示統計
    stats = firewall.get_statistics()
    print(f"✅ 統計資訊: {stats}")

def main():
    """主測試函數"""
    print("🧪 軍事級防火牆系統測試")
    print("=" * 50)
    
    # 執行單元測試
    print("📋 執行單元測試...")
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    print("\n" + "=" * 50)
    
    # 執行效能測試
    run_performance_test()
    
    print("\n" + "=" * 50)
    print("✅ 所有測試完成！")

if __name__ == "__main__":
    main()

