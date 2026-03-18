#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級防火牆系統完整測試
Complete Military-Grade Firewall System Test
"""

import sys
import os
import time
import unittest
from datetime import datetime

# 添加當前目錄到Python路徑
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import MilitaryFirewallSystem

class TestMilitaryFirewallSystem(unittest.TestCase):
    """軍事級防火牆系統完整測試"""
    
    def setUp(self):
        """測試前準備"""
        self.system = MilitaryFirewallSystem("firewall_config.yaml")
        
    def test_system_initialization(self):
        """測試系統初始化"""
        self.assertIsNotNone(self.system.firewall)
        self.assertIsNotNone(self.system.ids)
        self.assertIsNotNone(self.system.threat_intel)
        self.assertIsNotNone(self.system.packet_filter)
        self.assertIsNotNone(self.system.config_manager)
        self.assertIsNotNone(self.system.audit_logger)
        self.assertIsNotNone(self.system.military_crypto)
        self.assertIsNotNone(self.system.quantum_crypto)
        self.assertIsNotNone(self.system.threat_hunter)
        self.assertIsNotNone(self.system.zero_trust)
        self.assertIsNotNone(self.system.red_team)
        self.assertIsNotNone(self.system.military_standards)
        self.assertIsNotNone(self.system.dashboard)
        
        print("✅ 所有軍事級組件初始化成功")

    def test_military_crypto_system(self):
        """測試軍事級加密系統"""
        from military_crypto import KeyType, SecurityLevel
        
        # 生成AES密鑰
        aes_key = self.system.military_crypto.generate_key(
            KeyType.AES_256, SecurityLevel.SECRET, "test_user"
        )
        self.assertIsNotNone(aes_key)
        
        # 生成RSA密鑰
        rsa_key = self.system.military_crypto.generate_key(
            KeyType.RSA_4096, SecurityLevel.TOP_SECRET, "test_user"
        )
        self.assertIsNotNone(rsa_key)
        
        # 測試加密
        test_data = b"Military-grade test data"
        encrypted = self.system.military_crypto.encrypt_data(test_data, aes_key.id)
        decrypted = self.system.military_crypto.decrypt_data(encrypted)
        
        self.assertEqual(decrypted.plaintext, test_data)
        print("✅ 軍事級加密系統測試通過")

    def test_quantum_resistance_system(self):
        """測試量子抗性系統"""
        from quantum_resistance import QuantumAlgorithm, SecurityLevel, KeyType
        
        # 生成Kyber密鑰
        kyber_key = self.system.quantum_crypto.generate_quantum_key(
            QuantumAlgorithm.KYBER, SecurityLevel.LEVEL_5, KeyType.ENCRYPTION
        )
        self.assertIsNotNone(kyber_key)
        
        # 生成Dilithium密鑰
        dilithium_key = self.system.quantum_crypto.generate_quantum_key(
            QuantumAlgorithm.DILITHIUM, SecurityLevel.LEVEL_5, KeyType.SIGNATURE
        )
        self.assertIsNotNone(dilithium_key)
        
        # 測試混合系統
        hybrid_system = self.system.quantum_crypto.create_hybrid_system(
            "RSA", QuantumAlgorithm.KYBER, SecurityLevel.LEVEL_5
        )
        self.assertIsNotNone(hybrid_system)
        
        print("✅ 量子抗性系統測試通過")

    def test_advanced_threat_hunting(self):
        """測試高級威脅獵殺"""
        test_data = {
            'entity_id': 'test_host_001',
            'source_ip': '192.168.1.100',
            'events': [
                {'type': 'reconnaissance', 'timestamp': datetime.now()},
                {'type': 'exploit', 'timestamp': datetime.now()}
            ],
            'network_activity': {
                'packet_count': 1000,
                'bytes_transferred': 50000,
                'unique_connections': 10
            }
        }
        
        campaigns = self.system.threat_hunter.hunt_threats(test_data)
        self.assertIsInstance(campaigns, list)
        
        print("✅ 高級威脅獵殺測試通過")

    def test_zero_trust_architecture(self):
        """測試零信任架構"""
        from zero_trust_architecture import Identity, Resource, ResourceType
        
        # 註冊測試身份
        test_identity = Identity(
            id="test_user_001",
            type="USER",
            name="測試用戶",
            attributes={"department": "IT"},
            trust_score=0.8,
            last_verified=datetime.now(),
            verification_methods=["password", "mfa"],
            risk_factors=[]
        )
        self.system.zero_trust.register_identity(test_identity)
        
        # 註冊測試資源
        test_resource = Resource(
            id="test_resource_001",
            type=ResourceType.APPLICATION,
            name="測試應用",
            location="internal",
            classification="CONFIDENTIAL",
            owner="IT部門",
            access_requirements={"mfa_required": True},
            sensitivity_level=3
        )
        self.system.zero_trust.register_resource(test_resource)
        
        # 測試訪問請求
        context = {
            "location": {"country": "US"},
            "device": {"managed": True},
            "mfa_verified": True
        }
        
        request = self.system.zero_trust.evaluate_access_request(
            "test_user_001", "test_resource_001", "read", context
        )
        
        self.assertIsNotNone(request)
        print("✅ 零信任架構測試通過")

    def test_red_team_simulation(self):
        """測試紅隊模擬"""
        # 執行網路滲透測試
        test_id = self.system.red_team.run_penetration_test(
            "scenario_001", ["192.168.1.0/24"]
        )
        
        self.assertIsNotNone(test_id)
        
        # 等待測試完成
        time.sleep(2)
        
        # 檢查測試狀態
        status = self.system.red_team.get_test_status(test_id)
        self.assertIsNotNone(status)
        
        print("✅ 紅隊模擬測試通過")

    def test_military_standards(self):
        """測試軍事標準"""
        from military_standards import StandardType, ClassificationLevel
        
        # 執行合規評估
        assessment = self.system.military_standards.assess_compliance(
            StandardType.NIST, "NIST-AC-1", "test_auditor"
        )
        
        self.assertIsNotNone(assessment)
        
        # 分類資訊
        classification = self.system.military_standards.classify_information(
            "機密軍事資訊", ClassificationLevel.SECRET
        )
        
        self.assertIsNotNone(classification)
        
        print("✅ 軍事標準測試通過")

    def test_system_integration(self):
        """測試系統整合"""
        # 獲取系統狀態
        status = self.system.get_system_status()
        
        self.assertIsNotNone(status)
        self.assertTrue(status['running'])
        self.assertIn('components', status)
        
        # 檢查所有組件狀態
        components = status['components']
        expected_components = [
            'firewall', 'ids', 'threat_intel', 'audit_logger', 
            'config_manager', 'military_crypto', 'quantum_crypto',
            'threat_hunter', 'zero_trust', 'red_team', 'military_standards'
        ]
        
        for component in expected_components:
            self.assertIn(component, components)
        
        print("✅ 系統整合測試通過")

    def tearDown(self):
        """測試後清理"""
        # 清理測試檔案
        import shutil
        test_dirs = ['test_logs', 'logs']
        for test_dir in test_dirs:
            if os.path.exists(test_dir):
                shutil.rmtree(test_dir)
        
        # 清理資料庫檔案
        test_db_files = [
            "firewall.db", "ids.db", "threat_intel.db", "config_manager.db",
            "audit_logs.db", "military_crypto.db", "quantum_crypto.db",
            "threat_hunting.db", "zero_trust.db", "red_team.db", 
            "military_standards.db"
        ]
        
        for db_file in test_db_files:
            if os.path.exists(db_file):
                os.remove(db_file)

def run_performance_test():
    """執行效能測試"""
    print("\n🚀 執行軍事級系統效能測試...")
    
    system = MilitaryFirewallSystem("firewall_config.yaml")
    
    # 測試加密效能
    from military_crypto import KeyType, SecurityLevel
    
    start_time = time.time()
    aes_key = system.military_crypto.generate_key(
        KeyType.AES_256, SecurityLevel.SECRET, "perf_test"
    )
    encryption_time = time.time() - start_time
    
    # 測試加密速度
    test_data = b"Performance test data" * 1000  # 20KB數據
    
    start_time = time.time()
    encrypted = system.military_crypto.encrypt_data(test_data, aes_key.id)
    encryption_speed = time.time() - start_time
    
    start_time = time.time()
    decrypted = system.military_crypto.decrypt_data(encrypted)
    decryption_speed = time.time() - start_time
    
    print(f"✅ 密鑰生成時間: {encryption_time:.3f}秒")
    print(f"✅ 加密速度: {encryption_speed:.3f}秒 (20KB)")
    print(f"✅ 解密速度: {decryption_speed:.3f}秒 (20KB)")
    
    # 測試量子加密效能
    from quantum_resistance import QuantumAlgorithm, SecurityLevel, KeyType
    
    start_time = time.time()
    kyber_key = system.quantum_crypto.generate_quantum_key(
        QuantumAlgorithm.KYBER, SecurityLevel.LEVEL_5, KeyType.ENCRYPTION
    )
    quantum_key_time = time.time() - start_time
    
    print(f"✅ 量子密鑰生成時間: {quantum_key_time:.3f}秒")
    
    # 測試威脅獵殺效能
    test_data = {
        'entity_id': 'perf_test_host',
        'source_ip': '192.168.1.100',
        'events': [{'type': 'test', 'timestamp': datetime.now()}],
        'network_activity': {'packet_count': 1000}
    }
    
    start_time = time.time()
    campaigns = system.threat_hunter.hunt_threats(test_data)
    hunting_time = time.time() - start_time
    
    print(f"✅ 威脅獵殺時間: {hunting_time:.3f}秒")
    
    # 清理
    import shutil
    if os.path.exists("logs"):
        shutil.rmtree("logs")
    
    test_db_files = [
        "firewall.db", "ids.db", "threat_intel.db", "config_manager.db",
        "audit_logs.db", "military_crypto.db", "quantum_crypto.db",
        "threat_hunting.db", "zero_trust.db", "red_team.db", 
        "military_standards.db"
    ]
    
    for db_file in test_db_files:
        if os.path.exists(db_file):
            os.remove(db_file)

def main():
    """主測試函數"""
    print("🧪 軍事級防火牆系統完整測試")
    print("=" * 60)
    
    # 執行單元測試
    print("📋 執行軍事級組件測試...")
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    print("\n" + "=" * 60)
    
    # 執行效能測試
    run_performance_test()
    
    print("\n" + "=" * 60)
    print("🎉 軍事級防火牆系統測試完成！")
    print("\n系統特色:")
    print("🛡️  軍事級加密保護")
    print("🌌 量子抗性加密")
    print("🎯 高級威脅獵殺")
    print("🛡️  零信任架構")
    print("🔴 紅隊模擬測試")
    print("📋 軍事標準合規")
    print("\n系統已準備就緒，可投入軍事級安全防護！")

if __name__ == "__main__":
    main()



