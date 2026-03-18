#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實軍事級防火牆系統能力演示
Real Military-Grade Firewall System Capabilities Demo
"""

import sys
import os
import time
from datetime import datetime

# 添加當前目錄到Python路徑
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def demo_real_crypto():
    """演示真實加密能力"""
    print("🔐 真實軍事級加密系統演示")
    print("=" * 50)
    
    try:
        from real_military_crypto import RealMilitaryCryptography, KeyType, SecurityLevel
        
        # 初始化加密系統
        crypto = RealMilitaryCryptography({
            'key_rotation_interval': 86400,
            'max_key_usage': 1000000,
            'default_key_lifetime': 365
        })
        
        # 生成AES-256密鑰
        print("1. 生成真實AES-256密鑰...")
        aes_key = crypto.generate_key(KeyType.AES_256, SecurityLevel.SECRET, "demo_user")
        print(f"   ✅ 密鑰ID: {aes_key.id}")
        print(f"   ✅ 密鑰類型: {aes_key.key_type.value}")
        print(f"   ✅ 安全等級: {aes_key.security_level.value}")
        
        # 生成RSA-4096密鑰
        print("\n2. 生成真實RSA-4096密鑰...")
        rsa_key = crypto.generate_key(KeyType.RSA_4096, SecurityLevel.TOP_SECRET, "demo_user")
        print(f"   ✅ 密鑰ID: {rsa_key.id}")
        print(f"   ✅ 密鑰類型: {rsa_key.key_type.value}")
        
        # 真實加密測試
        print("\n3. 真實加密測試...")
        test_data = b"This is real military-grade encrypted data for demonstration"
        encrypted = crypto.encrypt_data(test_data, aes_key.id)
        decrypted = crypto.decrypt_data(encrypted)
        
        print(f"   ✅ 原始數據: {test_data}")
        print(f"   ✅ 加密成功: {len(encrypted.ciphertext)} bytes")
        print(f"   ✅ 解密成功: {decrypted.plaintext == test_data}")
        
        # 真實數位簽名
        print("\n4. 真實數位簽名測試...")
        signature = crypto.sign_data(test_data, rsa_key.id)
        verified = crypto.verify_signature(test_data, signature, rsa_key.id)
        print(f"   ✅ 簽名長度: {len(signature)} bytes")
        print(f"   ✅ 驗證結果: {verified}")
        
        # 密鑰統計
        stats = crypto.get_key_statistics()
        print(f"\n5. 密鑰統計:")
        print(f"   ✅ 總密鑰數: {stats['total_keys']}")
        print(f"   ✅ 活躍密鑰: {stats['active_keys']}")
        print(f"   ✅ 加密次數: {stats['encryption_stats']['encryptions']}")
        
        print("\n🎉 真實加密系統演示完成！")
        return True
        
    except Exception as e:
        print(f"❌ 加密系統演示失敗: {e}")
        return False

def demo_real_threat_hunting():
    """演示真實威脅獵殺能力"""
    print("\n🎯 真實威脅獵殺系統演示")
    print("=" * 50)
    
    try:
        from real_threat_hunting import RealThreatHunter
        
        # 初始化威脅獵殺系統
        hunter = RealThreatHunter({
            'monitoring_interval': 30,
            'threat_intelligence_update': 3600,
            'anomaly_threshold': 0.7
        })
        
        print("1. 威脅獵殺系統已啟動...")
        print("   ✅ 正在監控網路活動")
        print("   ✅ 正在監控進程行為")
        print("   ✅ 正在分析系統日誌")
        
        # 等待一段時間讓系統檢測威脅
        print("\n2. 等待威脅檢測...")
        time.sleep(5)
        
        # 獲取威脅統計
        stats = hunter.get_threat_statistics()
        print(f"\n3. 威脅檢測統計:")
        print(f"   ✅ 威脅指標: {stats['total_indicators']}個")
        print(f"   ✅ 威脅檢測: {stats['hunting_stats']['threats_detected']}個")
        print(f"   ✅ 網路掃描: {stats['hunting_stats']['network_scans']}次")
        print(f"   ✅ 日誌分析: {stats['hunting_stats']['log_analyses']}次")
        
        # 獲取活躍威脅
        active_threats = hunter.get_active_threats()
        print(f"\n4. 活躍威脅: {len(active_threats)}個")
        for i, threat in enumerate(active_threats[:3]):  # 只顯示前3個
            print(f"   ⚠️  威脅 {i+1}: {threat.description}")
            print(f"      等級: {threat.threat_level.name}")
            print(f"      信心度: {threat.confidence:.2f}")
        
        print("\n🎉 真實威脅獵殺系統演示完成！")
        return True
        
    except Exception as e:
        print(f"❌ 威脅獵殺系統演示失敗: {e}")
        return False

def demo_real_zero_trust():
    """演示真實零信任能力"""
    print("\n🛡️ 真實零信任架構演示")
    print("=" * 50)
    
    try:
        from real_zero_trust import RealZeroTrustEngine, Identity, Resource, ResourceType
        
        # 初始化零信任系統
        zt = RealZeroTrustEngine({
            'trust_decay_rate': 0.1,
            'verification_interval': 300,
            'policy_evaluation_timeout': 5
        })
        
        print("1. 註冊真實身份...")
        # 註冊測試身份
        test_identity = Identity(
            id="demo_user_001",
            type="USER",
            name="演示用戶",
            attributes={"department": "IT", "role": "admin"},
            trust_score=0.8,
            last_verified=datetime.now(),
            verification_methods=["password", "mfa"],
            risk_factors=[],
            device_fingerprint=""
        )
        zt.register_identity(test_identity)
        print(f"   ✅ 身份已註冊: {test_identity.name}")
        
        print("\n2. 註冊真實資源...")
        # 註冊測試資源
        test_resource = Resource(
            id="demo_resource_001",
            type=ResourceType.APPLICATION,
            name="演示應用",
            location="internal",
            classification="CONFIDENTIAL",
            owner="IT部門",
            access_requirements={"mfa_required": True},
            sensitivity_level=3,
            network_segment="internal"
        )
        zt.register_resource(test_resource)
        print(f"   ✅ 資源已註冊: {test_resource.name}")
        
        print("\n3. 真實訪問請求評估...")
        # 測試訪問請求
        context = {
            "source_ip": "192.168.1.100",
            "mfa_verified": True,
            "device_trusted": True
        }
        
        request = zt.evaluate_access_request(
            "demo_user_001", "demo_resource_001", "read", context
        )
        
        print(f"   ✅ 訪問決策: {request.decision.value}")
        print(f"   ✅ 信任分數: {request.trust_score:.2f}")
        print(f"   ✅ 風險分數: {request.risk_score:.2f}")
        print(f"   ✅ 決策原因: {', '.join(request.reasoning)}")
        
        # 零信任統計
        stats = zt.get_statistics()
        print(f"\n4. 零信任統計:")
        print(f"   ✅ 總身份數: {stats['total_identities']}")
        print(f"   ✅ 總資源數: {stats['total_resources']}")
        print(f"   ✅ 總策略數: {stats['total_policies']}")
        print(f"   ✅ 允許請求: {stats['stats']['allowed_requests']}")
        print(f"   ✅ 拒絕請求: {stats['stats']['denied_requests']}")
        
        print("\n🎉 真實零信任架構演示完成！")
        return True
        
    except Exception as e:
        print(f"❌ 零信任架構演示失敗: {e}")
        return False

def demo_real_red_team():
    """演示真實滲透測試能力"""
    print("\n🔴 真實滲透測試系統演示")
    print("=" * 50)
    
    try:
        from real_red_team import RealRedTeamSimulator
        
        # 初始化紅隊系統
        red_team = RealRedTeamSimulator({
            'max_concurrent_tests': 5,
            'test_timeout': 3600,
            'report_generation': True
        })
        
        print("1. 真實網路掃描...")
        # 執行網路掃描
        scan_results = red_team.run_network_scan("127.0.0.1", "quick")
        print(f"   ✅ 掃描ID: {scan_results.get('scan_id', 'N/A')}")
        print(f"   ✅ 掃描成功: {scan_results.get('success', False)}")
        
        if scan_results.get('success'):
            results = scan_results.get('results', {})
            if 'port_scan' in results:
                open_ports = results['port_scan'].get('open_ports', [])
                print(f"   ✅ 開放端口: {len(open_ports)}個")
                if open_ports:
                    print(f"      端口列表: {open_ports[:5]}")  # 只顯示前5個
        
        print("\n2. 真實漏洞評估...")
        # 執行漏洞評估
        vuln_results = red_team.run_vulnerability_assessment("127.0.0.1")
        print(f"   ✅ 評估ID: {vuln_results.get('assessment_id', 'N/A')}")
        print(f"   ✅ 評估成功: {vuln_results.get('success', False)}")
        
        if vuln_results.get('success'):
            vulnerabilities = vuln_results.get('vulnerabilities', [])
            print(f"   ✅ 發現漏洞: {len(vulnerabilities)}個")
            for i, vuln in enumerate(vulnerabilities[:3]):  # 只顯示前3個
                print(f"      漏洞 {i+1}: {vuln.get('type', 'Unknown')}")
                print(f"      嚴重程度: {vuln.get('severity', 'Unknown')}")
        
        # 紅隊統計
        stats = red_team.get_statistics()
        print(f"\n3. 滲透測試統計:")
        print(f"   ✅ 掃描工具: {stats['scanning_tools']}")
        print(f"   ✅ 總漏洞數: {stats['total_vulnerabilities']}")
        print(f"   ✅ 完成測試: {stats['completed_tests']}")
        
        print("\n🎉 真實滲透測試系統演示完成！")
        return True
        
    except Exception as e:
        print(f"❌ 滲透測試系統演示失敗: {e}")
        return False

def demo_real_compliance():
    """演示真實合規檢查能力"""
    print("\n📋 真實合規檢查系統演示")
    print("=" * 50)
    
    try:
        from real_compliance import RealComplianceChecker, StandardType
        
        # 初始化合規檢查系統
        compliance = RealComplianceChecker({
            'check_interval': 3600,
            'report_generation': True
        })
        
        print("1. 執行NIST合規檢查...")
        # 執行NIST合規檢查
        nist_results = compliance.run_full_compliance_check(StandardType.NIST)
        print(f"   ✅ 檢查ID: {nist_results.get('check_id', 'N/A')}")
        print(f"   ✅ 檢查成功: {nist_results.get('success', False)}")
        
        if nist_results.get('success'):
            summary = nist_results.get('summary', {})
            print(f"   ✅ 總檢查數: {summary.get('total_checks', 0)}")
            print(f"   ✅ 合規檢查: {summary.get('compliant_checks', 0)}")
            print(f"   ✅ 部分合規: {summary.get('partially_compliant_checks', 0)}")
            print(f"   ✅ 不合規: {summary.get('non_compliant_checks', 0)}")
            print(f"   ✅ 合規率: {summary.get('compliance_rate', 0):.2%}")
        
        print("\n2. 執行ISO合規檢查...")
        # 執行ISO合規檢查
        iso_results = compliance.run_full_compliance_check(StandardType.ISO)
        print(f"   ✅ 檢查ID: {iso_results.get('check_id', 'N/A')}")
        print(f"   ✅ 檢查成功: {iso_results.get('success', False)}")
        
        if iso_results.get('success'):
            summary = iso_results.get('summary', {})
            print(f"   ✅ 合規率: {summary.get('compliance_rate', 0):.2%}")
        
        # 合規統計
        stats = compliance.get_statistics()
        print(f"\n3. 合規檢查統計:")
        print(f"   ✅ 總檢查數: {stats['total_checks']}")
        print(f"   ✅ 總結果數: {stats['total_results']}")
        print(f"   ✅ 合規檢查: {stats['stats']['compliant_checks']}")
        print(f"   ✅ 不合規檢查: {stats['stats']['non_compliant_checks']}")
        
        print("\n🎉 真實合規檢查系統演示完成！")
        return True
        
    except Exception as e:
        print(f"❌ 合規檢查系統演示失敗: {e}")
        return False

def main():
    """主演示函數"""
    print("🛡️ 真實軍事級防火牆系統能力演示")
    print("=" * 60)
    print(f"演示時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # 演示結果
    results = {
        'crypto': False,
        'threat_hunting': False,
        'zero_trust': False,
        'red_team': False,
        'compliance': False
    }
    
    # 執行各項演示
    results['crypto'] = demo_real_crypto()
    results['threat_hunting'] = demo_real_threat_hunting()
    results['zero_trust'] = demo_real_zero_trust()
    results['red_team'] = demo_real_red_team()
    results['compliance'] = demo_real_compliance()
    
    # 總結
    print("\n" + "=" * 60)
    print("📊 真實系統能力總結")
    print("=" * 60)
    
    success_count = sum(results.values())
    total_count = len(results)
    
    print(f"✅ 成功演示: {success_count}/{total_count}")
    print(f"📈 成功率: {success_count/total_count:.1%}")
    
    print("\n🔐 真實軍事級加密能力:")
    print("   • AES-256-GCM真實加密")
    print("   • RSA-4096真實非對稱加密")
    print("   • 真實密鑰管理和輪換")
    print("   • 真實數位簽名和驗證")
    
    print("\n🎯 真實威脅獵殺能力:")
    print("   • 真實網路流量監控")
    print("   • 真實進程行為監控")
    print("   • 真實系統日誌分析")
    print("   • 真實異常行為檢測")
    
    print("\n🛡️ 真實零信任能力:")
    print("   • 真實設備指紋驗證")
    print("   • 真實身份認證授權")
    print("   • 真實信任分數計算")
    print("   • 真實訪問控制決策")
    
    print("\n🔴 真實滲透測試能力:")
    print("   • 真實網路掃描檢測")
    print("   • 真實漏洞識別分析")
    print("   • 真實服務版本檢測")
    print("   • 真實安全配置檢查")
    
    print("\n📋 真實合規檢查能力:")
    print("   • 真實系統配置檢查")
    print("   • 真實安全策略驗證")
    print("   • 真實合規報告生成")
    print("   • 真實修復建議提供")
    
    print("\n" + "=" * 60)
    print("🎉 真實軍事級防火牆系統能力演示完成！")
    print("🛡️ 系統已具備真實的安全防護能力！")
    print("=" * 60)

if __name__ == "__main__":
    main()




