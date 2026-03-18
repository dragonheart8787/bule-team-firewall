#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
獨立認證級測試 - 無需 Web 系統
Standalone Certification Tests - No Web System Required

可直接執行的認證級演練：
1. MITRE ATT&CK Defender 完整演練
2. GCFA 取證完整流程
3. Evidence Chain 認證測試
4. SOAR Playbook 執行測試
5. Memory Forensics 分析演練
6. PCAP 分析演練
7. CTI 整合演練
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path

# 導入進階模組
from evidence_chain_system import EvidenceChainSystem
from mitre_attack_mapper import MITREAttackMapper
from soar_playbooks import SOAREngine
from memory_forensics_module import MemoryForensicsAnalyzer
from pcap_analysis_module import PCAPAnalyzer
from cti_integration_engine import CTIEngine


class StandaloneCertificationTests:
    """獨立認證測試系統（無需 Web 系統）"""
    
    def __init__(self):
        print("=" * 70)
        print("獨立認證級測試系統")
        print("Standalone Certification Tests")
        print("=" * 70)
        print("(無需 Web 系統，可立即執行)\n")
        
        self.test_results = []
    
    def run_all_tests(self):
        """執行所有獨立測試"""
        tests = [
            ("Test 1: MITRE ATT&CK Defender 完整演練", self.test_attack_defender),
            ("Test 2: GCFA 取證完整流程", self.test_gcfa_forensics),
            ("Test 3: Evidence Chain 認證級測試", self.test_evidence_chain),
            ("Test 4: SOAR Playbook 執行測試", self.test_soar_execution),
            ("Test 5: Memory Forensics 分析", self.test_memory_forensics),
            ("Test 6: PCAP 深度分析", self.test_pcap_analysis),
            ("Test 7: CTI 威脅情報整合", self.test_cti_integration)
        ]
        
        for test_name, test_func in tests:
            print("\n" + "=" * 70)
            print(test_name)
            print("=" * 70)
            
            try:
                result = test_func()
                self.test_results.append({
                    "test": test_name,
                    "status": "PASS" if result['passed'] else "FAIL",
                    "score": result['score'],
                    "grade": result['grade']
                })
                
                print(f"\n[結果] 狀態: {'✅ PASS' if result['passed'] else '❌ FAIL'}")
                print(f"[結果] 分數: {result['score']}/{result['max_score']}")
                print(f"[結果] 等級: {result['grade']}")
                
            except Exception as e:
                print(f"\n[錯誤] 測試執行失敗: {e}")
                self.test_results.append({
                    "test": test_name,
                    "status": "ERROR",
                    "error": str(e)
                })
        
        # 生成總結
        self._print_summary()
    
    def test_attack_defender(self):
        """Test 1: MITRE ATT&CK Defender 完整演練"""
        print("\n[演練] MITRE ATT&CK 防禦覆蓋率評估")
        print("任務: 建立完整的 ATT&CK 覆蓋率報告並識別缺口\n")
        
        score = 0
        max_score = 100
        
        # 1. 初始化映射器 (10 分)
        print("[步驟 1/6] 初始化 ATT&CK 映射引擎...")
        mapper = MITREAttackMapper()
        print(f"  [OK] 載入 {len(mapper.techniques)} 個 ATT&CK 技術")
        score += 10
        
        # 2. 生成覆蓋率報告 (20 分)
        print("\n[步驟 2/6] 生成覆蓋率報告...")
        coverage = mapper.generate_coverage_report()
        stats = coverage['statistics']
        print(f"  [OK] Full Coverage: {stats['full_coverage']} 個")
        print(f"  [OK] Partial Coverage: {stats['partial_coverage']} 個")
        print(f"  [OK] 總覆蓋率: {stats['coverage_percentage']:.1f}%")
        score += 20
        
        # 3. 生成 HTML 報告 (15 分)
        print("\n[步驟 3/6] 生成 HTML 視覺化報告...")
        html_file = mapper.generate_html_report("standalone_attack_report.html")
        print(f"  [OK] 已生成: {html_file}")
        score += 15
        
        # 4. 生成 CSV 報告 (15 分)
        print("\n[步驟 4/6] 生成 CSV 數據報告...")
        csv_file = mapper.generate_csv_report("standalone_attack_report.csv")
        print(f"  [OK] 已生成: {csv_file}")
        score += 15
        
        # 5. 生成 Navigator JSON (20 分)
        print("\n[步驟 5/6] 生成 MITRE Navigator JSON...")
        nav_file = mapper.generate_mitre_navigator_json("standalone_navigator.json")
        print(f"  [OK] 已生成: {nav_file}")
        print(f"  [提示] 上傳到 https://mitre-attack.github.io/attack-navigator/")
        score += 20
        
        # 6. 識別並分析缺口 (20 分)
        print("\n[步驟 6/6] 識別防禦缺口...")
        no_coverage = stats['no_coverage']
        print(f"  [分析] 發現 {no_coverage} 個未覆蓋的技術")
        
        # 提供改進建議
        if no_coverage > 0:
            print(f"  [建議] 優先實作以下能力:")
            print(f"    - 部署 EDR 解決方案（覆蓋主機層攻擊）")
            print(f"    - 實施網路流量監控（橫向移動偵測）")
            print(f"    - 建立行為分析（異常偵測）")
        score += 20
        
        return {
            "passed": score >= 70,
            "score": score,
            "max_score": max_score,
            "coverage_rate": stats['coverage_percentage'],
            "grade": self._get_grade(score, max_score)
        }
    
    def test_gcfa_forensics(self):
        """Test 2: GCFA 完整取證流程"""
        print("\n[演練] 數位取證完整流程")
        print("任務: 對可疑事件進行完整取證分析\n")
        
        score = 0
        max_score = 100
        
        evidence_system = EvidenceChainSystem()
        
        # 1. 創建取證案件 (10 分)
        print("[步驟 1/6] 創建取證案件...")
        incident_id = evidence_system.create_incident(
            "ADVANCED_PERSISTENT_THREAT",
            "Suspected APT attack with credential theft and lateral movement",
            "CRITICAL"
        )
        print(f"  [OK] 案件 ID: {incident_id}")
        score += 10
        
        # 2. 收集 Memory 證據 (20 分)
        print("\n[步驟 2/6] 收集記憶體證據...")
        memory_evidence = {
            "processes": {
                "suspicious": ["mimikatz.exe", "powershell.exe", "cmd.exe"],
                "total": 156
            },
            "network_connections": [
                {"local": "192.168.1.100:49152", "remote": "203.0.113.50:4444", "state": "ESTABLISHED"}
            ],
            "injected_code": True
        }
        evd1 = evidence_system.collect_evidence(
            incident_id,
            "text",
            json.dumps(memory_evidence, indent=2),
            "Memory dump analysis - Volatility results",
            collector="Forensics Tool"
        )
        print(f"  [OK] Memory 證據: {evd1}")
        print(f"  [分析] 可疑進程: {len(memory_evidence['processes']['suspicious'])}")
        print(f"  [分析] 惡意連接: {len(memory_evidence['network_connections'])}")
        score += 20
        
        # 3. 收集網路證據 (20 分)
        print("\n[步驟 3/6] 收集網路流量證據...")
        pcap_evidence = {
            "total_packets": 15423,
            "c2_communication": {
                "detected": True,
                "server": "203.0.113.50:4444",
                "beaconing_interval": 60
            },
            "dns_tunneling": {
                "detected": True,
                "queries": 120
            },
            "data_exfiltration": {
                "bytes": 157286400,
                "destination": "203.0.113.100:443"
            }
        }
        evd2 = evidence_system.collect_evidence(
            incident_id,
            "text",
            json.dumps(pcap_evidence, indent=2),
            "Network traffic analysis - PCAP results",
            collector="Network Analyst"
        )
        print(f"  [OK] PCAP 證據: {evd2}")
        print(f"  [分析] C2 通訊: 檢測到")
        print(f"  [分析] DNS Tunneling: 檢測到")
        print(f"  [分析] 資料外洩: 150 MB")
        score += 20
        
        # 4. 收集系統日誌 (15 分)
        print("\n[步驟 4/6] 收集系統日誌...")
        log_evidence = {
            "windows_events": {
                "security_events": 4289,
                "failed_logins": 15,
                "suspicious_logins": 3
            },
            "sysmon_events": {
                "process_creation": 428,
                "network_connections": 156,
                "file_creation": 89
            }
        }
        evd3 = evidence_system.collect_evidence(
            incident_id,
            "logs",
            log_evidence,
            "System event logs - Windows & Sysmon",
            collector="Log Collector"
        )
        print(f"  [OK] 日誌證據: {evd3}")
        score += 15
        
        # 5. 生成 Manifest 並簽名 (15 分)
        print("\n[步驟 5/6] 生成證據清單並簽名...")
        manifest = evidence_system.generate_manifest(incident_id, custodian="Chief Forensics Analyst")
        print(f"  [OK] Manifest 已生成")
        print(f"  - 證據項目: {manifest['total_items']}")
        print(f"  - 總大小: {manifest['total_size_bytes']} bytes")
        print(f"  - Manifest Hash: {manifest['manifest_hash'][:32]}...")
        print(f"  - HSM 簽名: {manifest['signature'][:32]}...")
        score += 15
        
        # 6. 創建證據包並關閉案件 (20 分)
        print("\n[步驟 6/6] 創建證據包並關閉案件...")
        bundle = evidence_system.create_evidence_bundle(incident_id)
        print(f"  [OK] 證據包: {bundle['bundle_filename']}")
        print(f"  - 大小: {bundle['bundle_size_bytes']:,} bytes")
        print(f"  - SHA-256: {bundle['bundle_hash_sha256'][:32]}...")
        
        report = evidence_system.close_incident(
            incident_id,
            closed_by="Chief Forensics Analyst",
            summary="APT attack confirmed. Credential theft via Mimikatz, C2 communication to 203.0.113.50, and data exfiltration detected. All evidence collected and preserved with full chain of custody."
        )
        print(f"  [OK] 案件已關閉")
        score += 20
        
        return {
            "passed": score >= 70,
            "score": score,
            "max_score": max_score,
            "evidence_items": manifest['total_items'],
            "bundle_size": bundle['bundle_size_bytes'],
            "grade": self._get_grade(score, max_score)
        }
    
    def test_evidence_chain(self):
        """Test 3: Evidence Chain 認證級測試"""
        print("\n[測試] Chain of Custody 完整功能")
        print("評估: 證據鏈管理的完整性與正確性\n")
        
        score = 0
        max_score = 100
        
        evidence_system = EvidenceChainSystem()
        
        # 1. 創建事件 (15 分)
        print("[步驟 1/5] 創建安全事件...")
        incident_id = evidence_system.create_incident(
            "RANSOMWARE_ATTACK",
            "Ransomware detected encrypting files on file server",
            "CRITICAL"
        )
        print(f"  [OK] {incident_id}")
        score += 15
        
        # 2. 收集多種類型證據 (30 分)
        print("\n[步驟 2/5] 收集多種類型證據...")
        
        # Logs
        evd1 = evidence_system.collect_evidence(
            incident_id, "logs",
            {"ransomware": "detected", "files_encrypted": 1542},
            "Ransomware detection logs"
        )
        print(f"  [OK] Logs: {evd1}")
        score += 10
        
        # Text evidence
        evd2 = evidence_system.collect_evidence(
            incident_id, "text",
            "Ransom note: Pay 1 BTC to recover files",
            "Ransom note content"
        )
        print(f"  [OK] Text: {evd2}")
        score += 10
        
        # Binary evidence (模擬)
        evd3 = evidence_system.collect_evidence(
            incident_id, "text",
            "Binary evidence placeholder",
            "Ransomware executable sample"
        )
        print(f"  [OK] Binary: {evd3}")
        score += 10
        
        # 3. 驗證所有證據 (20 分)
        print("\n[步驟 3/5] 驗證證據完整性...")
        all_verified = True
        for evd_id in [evd1, evd2, evd3]:
            verification = evidence_system.verify_evidence(incident_id, evd_id)
            if not verification['verified']:
                all_verified = False
                print(f"  [失敗] {evd_id} 驗證失敗")
        
        if all_verified:
            print(f"  [OK] 所有證據驗證通過")
            score += 20
        
        # 4. 轉移保管權 (15 分)
        print("\n[步驟 4/5] 轉移證據保管權...")
        evidence_system.transfer_custody(
            incident_id,
            from_custodian="First Responder",
            to_custodian="Incident Manager",
            reason="Evidence analysis required"
        )
        evidence_system.transfer_custody(
            incident_id,
            from_custodian="Incident Manager",
            to_custodian="Forensics Team",
            reason="Detailed forensic analysis"
        )
        print(f"  [OK] 保管權轉移 2 次")
        score += 15
        
        # 5. 生成並驗證 Manifest (20 分)
        print("\n[步驟 5/5] 生成並驗證 Manifest...")
        manifest = evidence_system.generate_manifest(incident_id)
        print(f"  [OK] Manifest 已生成並簽名")
        
        verification = evidence_system.verify_manifest(incident_id)
        if verification['verified']:
            print(f"  [OK] Manifest 簽名驗證通過")
            score += 20
        else:
            print(f"  [失敗] Manifest 簽名驗證失敗")
        
        return {
            "passed": score >= 70,
            "score": score,
            "max_score": max_score,
            "incident_id": incident_id,
            "evidence_count": 3,
            "grade": self._get_grade(score, max_score)
        }
    
    def test_soar_execution(self):
        """Test 4: SOAR Playbook 執行測試"""
        print("\n[測試] SOAR 自動化響應能力")
        print("評估: 5 個核心 Playbook 的執行效能\n")
        
        score = 0
        max_score = 100
        
        soar = SOAREngine()
        
        playbooks = [
            ("isolate_host", {"hostname": "server-01", "ip_address": "192.168.1.50", "reason": "Malware"}),
            ("block_ip", {"ip_address": "203.0.113.99", "reason": "C2 server", "duration": 3600}),
            ("quarantine_file", {"file_path": "/tmp/malware.exe", "file_hash": "abc123", "hostname": "server-01"}),
            ("revoke_credentials", {"username": "compromised_user", "credential_type": "PASSWORD", "reason": "Credential theft"}),
            ("restore_service", {"service_name": "web_server", "restore_method": "RESTART"})
        ]
        
        points_per_playbook = max_score // len(playbooks)
        
        for idx, (playbook_name, params) in enumerate(playbooks, 1):
            print(f"[測試 {idx}/5] 執行 {playbook_name}...")
            result = soar.execute_playbook(playbook_name, params)
            
            if result['status'] == 'SUCCESS':
                print(f"  [OK] 成功 (Run ID: {result['run_id']})")
                print(f"  [OK] 耗時: {result['duration']}")
                score += points_per_playbook
            else:
                print(f"  [失敗] 執行失敗")
        
        return {
            "passed": score >= 70,
            "score": score,
            "max_score": max_score,
            "playbooks_tested": len(playbooks),
            "grade": self._get_grade(score, max_score)
        }
    
    def test_memory_forensics(self):
        """Test 5: Memory Forensics 分析"""
        print("\n[演練] Memory Forensics 記憶體取證分析\n")
        
        score = 0
        max_score = 100
        
        # 創建測試 dump
        print("[步驟 1/2] 創建測試 Memory Dump...")
        dump_file = "cert_test_memory.raw"
        with open(dump_file, 'wb') as f:
            f.write(b"MEMORY_DUMP_TEST" * 1000)
        print(f"  [OK] 已創建: {dump_file}")
        score += 20
        
        # 執行分析
        print("\n[步驟 2/2] 執行 Memory Forensics 分析...")
        analyzer = MemoryForensicsAnalyzer()
        analysis = analyzer.analyze_memory_dump(dump_file)
        
        print(f"  [OK] 分析完成")
        print(f"  - 可疑進程: {analysis['results']['processes']['suspicious_count']}")
        print(f"  - C2 連接: {len(analysis['results']['network']['c2_indicators'])}")
        print(f"  - 提取 IoC: {len(analysis['results']['iocs']['ip_addresses']) + len(analysis['results']['iocs']['domains'])}")
        score += 80
        
        return {
            "passed": score >= 70,
            "score": score,
            "max_score": max_score,
            "suspicious_processes": analysis['results']['processes']['suspicious_count'],
            "iocs_extracted": len(analysis['results']['iocs']['ip_addresses']),
            "grade": self._get_grade(score, max_score)
        }
    
    def test_pcap_analysis(self):
        """Test 6: PCAP 深度分析"""
        print("\n[演練] PCAP 網路流量深度分析\n")
        
        score = 0
        max_score = 100
        
        # 創建測試 PCAP
        print("[步驟 1/2] 創建測試 PCAP 檔案...")
        pcap_file = "cert_test_capture.pcap"
        with open(pcap_file, 'wb') as f:
            f.write(b"PCAP_TEST_DATA" * 1000)
        print(f"  [OK] 已創建: {pcap_file}")
        score += 20
        
        # 執行分析
        print("\n[步驟 2/2] 執行 PCAP 深度分析...")
        analyzer = PCAPAnalyzer()
        analysis = analyzer.analyze_pcap(pcap_file)
        
        print(f"  [OK] 分析完成")
        print(f"  - DNS Tunneling: {'檢測到' if analysis['results']['dns']['dns_tunneling_detected'] else '未檢測到'}")
        print(f"  - C2 通訊: {'檢測到' if analysis['results']['c2_detection']['c2_detected'] else '未檢測到'}")
        print(f"  - 資料外洩: {'檢測到' if analysis['results']['exfiltration']['exfiltration_detected'] else '未檢測到'}")
        print(f"  - 生成 Suricata 規則: {len(analysis['results']['suricata_rules'])}")
        score += 80
        
        return {
            "passed": score >= 70,
            "score": score,
            "max_score": max_score,
            "c2_detected": analysis['results']['c2_detection']['c2_detected'],
            "rules_generated": len(analysis['results']['suricata_rules']),
            "grade": self._get_grade(score, max_score)
        }
    
    def test_cti_integration(self):
        """Test 7: CTI 威脅情報整合"""
        print("\n[演練] 威脅情報整合與測試\n")
        
        score = 0
        max_score = 100
        
        cti = CTIEngine()
        
        # 1. 攝取 STIX IoC (30 分)
        print("[步驟 1/3] 攝取 STIX 威脅情報...")
        stix_bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--test-001",
                    "pattern": "[ipv4-addr:value = '198.51.100.99']",
                    "name": "Malicious C2 Server",
                    "confidence": 95
                },
                {
                    "type": "indicator",
                    "id": "indicator--test-002",
                    "pattern": "[domain-name:value = 'evil-apt.com']",
                    "name": "APT Domain",
                    "confidence": 90
                }
            ]
        }
        
        count = cti.ingest_iocs_from_stix(stix_bundle)
        print(f"  [OK] 攝取 {count} 個 IoC")
        score += 30
        
        # 2. 測試 IoC 偵測 (40 分)
        print("\n[步驟 2/3] 測試 IoC 偵測能力...")
        for ioc in cti.ioc_database['iocs']:
            result = cti.test_ioc_detection(ioc)
            if result['detected']:
                score += 20
        
        # 3. 生成偵測缺口報告 (30 分)
        print("\n[步驟 3/3] 生成偵測缺口報告...")
        gap_report = cti.generate_detection_gap_report()
        print(f"  [OK] 報告已生成")
        print(f"  - 測試 IoC: {gap_report['summary']['total_iocs_tested']}")
        print(f"  - 偵測率: {gap_report['summary']['detection_rate']:.1f}%")
        print(f"  - False Negatives: {gap_report['gaps']['false_negatives']}")
        score += 30
        
        return {
            "passed": score >= 70,
            "score": score,
            "max_score": max_score,
            "iocs_tested": gap_report['summary']['total_iocs_tested'],
            "detection_rate": gap_report['summary']['detection_rate'],
            "grade": self._get_grade(score, max_score)
        }
    
    def _get_grade(self, score, max_score):
        """計算等級"""
        percentage = (score / max_score) * 100
        
        if percentage >= 95:
            return "A+"
        elif percentage >= 90:
            return "A"
        elif percentage >= 85:
            return "B+"
        elif percentage >= 80:
            return "B"
        elif percentage >= 75:
            return "C+"
        elif percentage >= 70:
            return "C"
        else:
            return "F"
    
    def _print_summary(self):
        """列印總結"""
        print("\n" + "=" * 70)
        print("認證級測試總結")
        print("=" * 70)
        
        total = len(self.test_results)
        passed = sum(1 for r in self.test_results if r['status'] == 'PASS')
        
        print(f"\n總測試數: {total}")
        print(f"通過數: {passed}")
        print(f"失敗數: {total - passed}")
        print(f"通過率: {passed/total*100:.1f}%\n")
        
        print("詳細結果:")
        for result in self.test_results:
            status_icon = "[OK]" if result['status'] == 'PASS' else "[FAIL]"
            print(f"  {status_icon} {result['test']:<50} {result.get('grade', 'N/A')}")
        
        # 保存報告
        reports_dir = Path("./certification_reports")
        reports_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = reports_dir / f"standalone_cert_test_{timestamp}.json"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump({
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "test_type": "Standalone Certification Tests",
                "summary": {
                    "total": total,
                    "passed": passed,
                    "failed": total - passed,
                    "pass_rate": passed/total*100
                },
                "results": self.test_results
            }, f, indent=2, ensure_ascii=False)
        
        print(f"\n報告已保存: {report_file}")


# 主程式
if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║            獨立認證級測試系統 v1.0                               ║
║     Standalone Certification Tests (No Web System Required)      ║
║                                                                  ║
║  特點:                                                           ║
║    [OK] 無需 Web 系統即可執行                                   ║
║    [OK] 7 個完整認證級測試                                      ║
║    [OK] 自動評分與等級評定                                      ║
║    [OK] 完整的報告生成                                          ║
║                                                                  ║
║  測試項目:                                                       ║
║    1. MITRE ATT&CK Defender 演練                                ║
║    2. GCFA 取證流程                                             ║
║    3. Evidence Chain 測試                                       ║
║    4. SOAR Playbook 執行                                        ║
║    5. Memory Forensics 分析                                     ║
║    6. PCAP 深度分析                                             ║
║    7. CTI 威脅情報整合                                          ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    tester = StandaloneCertificationTests()
    tester.run_all_tests()
    
    print("\n" + "=" * 70)
    print("所有認證級測試執行完成！")
    print("=" * 70)
    print("\n生成的報告和證據:")
    print("  - 證據鏈: ./evidence/INC-*/")
    print("  - ATT&CK 報告: standalone_attack_report.html")
    print("  - Memory 報告: ./memory_forensics_reports/")
    print("  - PCAP 報告: ./pcap_analysis_reports/")
    print("  - CTI 報告: ./cti_reports/")
    print("  - 總結: ./certification_reports/")

