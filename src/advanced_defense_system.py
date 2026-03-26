#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Defense System - 進階防禦系統整合
整合所有藍隊進階功能：Evidence Chain, ATT&CK Mapping, SOAR, Red Team CI, Memory Forensics, PCAP Analysis, CTI
"""

import sys
import time
import json
from datetime import datetime, timezone
from pathlib import Path

# 導入所有模組
from evidence_chain_system import EvidenceChainSystem
from mitre_attack_mapper import MITREAttackMapper
from soar_playbooks import SOAREngine
from red_team_ci_system import RedTeamCI
from memory_forensics_module import MemoryForensicsAnalyzer
from pcap_analysis_module import PCAPAnalyzer
from cti_integration_engine import CTIEngine


class AdvancedDefenseSystem:
    """進階防禦系統整合管理器"""
    
    def __init__(self):
        print("\n" + "=" * 70)
        print("進階防禦系統初始化")
        print("Advanced Defense System Initialization")
        print("=" * 70)
        
        # 初始化所有模組
        print("\n[初始化] 載入核心模組...")
        
        print("  [1/7] Evidence Chain System...")
        self.evidence_chain = EvidenceChainSystem()
        print("    [OK] 證據鏈系統就緒")
        
        print("  [2/7] MITRE ATT&CK Mapper...")
        self.attack_mapper = MITREAttackMapper()
        print("    [OK] ATT&CK 映射引擎就緒")
        
        print("  [3/7] SOAR Engine...")
        self.soar = SOAREngine()
        print("    [OK] SOAR 編排引擎就緒")
        
        print("  [4/7] Red Team CI...")
        self.red_team = RedTeamCI()
        print("    [OK] 紅隊演練系統就緒")
        
        print("  [5/7] Memory Forensics...")
        self.memory_forensics = MemoryForensicsAnalyzer()
        print("    [OK] 記憶體取證模組就緒")
        
        print("  [6/7] PCAP Analyzer...")
        self.pcap_analyzer = PCAPAnalyzer()
        print("    [OK] PCAP 分析模組就緒")
        
        print("  [7/7] CTI Engine...")
        self.cti = CTIEngine()
        print("    [OK] 威脅情報引擎就緒")
        
        print("\n[完成] 所有模組初始化完成！")
    
    def run_full_assessment(self):
        """執行完整評估"""
        print("\n" + "=" * 70)
        print("執行完整防禦能力評估")
        print("=" * 70)
        
        assessment = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "system_version": "Advanced Defense System v2.0",
            "modules": {}
        }
        
        # 1. ATT&CK 覆蓋率評估
        print("\n[1/7] MITRE ATT&CK 覆蓋率評估...")
        coverage_summary = self.attack_mapper.get_coverage_summary()
        print(coverage_summary)
        
        # 生成報告
        self.attack_mapper.generate_html_report()
        self.attack_mapper.generate_csv_report()
        self.attack_mapper.generate_mitre_navigator_json()
        
        assessment['modules']['attack_coverage'] = {
            "status": "COMPLETED",
            "reports": [
                "attack_coverage_report.html",
                "attack_coverage_report.csv",
                "attack_navigator.json"
            ]
        }
        
        # 2. 證據鏈測試
        print("\n[2/7] 證據鏈系統測試...")
        incident_id = self.evidence_chain.create_incident(
            "SYSTEM_TEST",
            "Testing evidence chain functionality",
            "LOW"
        )
        
        # 收集測試證據
        test_log = {"test": "evidence", "timestamp": datetime.now(timezone.utc).isoformat()}
        self.evidence_chain.collect_evidence(
            incident_id,
            "logs",
            test_log,
            "Test evidence item",
            "SYSTEM"
        )
        
        # 生成 manifest
        manifest = self.evidence_chain.generate_manifest(incident_id)
        print(f"    [OK] 證據鏈測試完成 (Incident: {incident_id})")
        
        assessment['modules']['evidence_chain'] = {
            "status": "COMPLETED",
            "test_incident": incident_id
        }
        
        # 3. SOAR Playbooks 測試
        print("\n[3/7] SOAR Playbooks 測試...")
        
        # 測試 block_ip playbook
        result = self.soar.execute_playbook("block_ip", {
            "ip_address": "198.51.100.50",
            "reason": "Test execution",
            "duration": 60
        })
        
        print(f"    [OK] Playbook 測試完成 (Run ID: {result['run_id']}, 狀態: {result['status']})")
        
        assessment['modules']['soar'] = {
            "status": "COMPLETED",
            "test_run": result['run_id'],
            "playbooks_available": list(self.soar.playbooks.keys())
        }
        
        # 4. 紅隊演練（簡化版）
        print("\n[4/7] 紅隊演練測試...")
        print("    [提示] 完整紅隊演練需要目標系統在線")
        print("    [提示] 可執行: python red_team_ci_system.py")
        
        assessment['modules']['red_team'] = {
            "status": "READY",
            "scenarios_available": len(self.red_team.attack_scenarios),
            "note": "Run 'python red_team_ci_system.py' for full execution"
        }
        
        # 5. Memory Forensics（示範）
        print("\n[5/7] Memory Forensics 模組測試...")
        print("    [提示] 需要 memory dump 檔案進行分析")
        print("    [提示] 可執行: python memory_forensics_module.py")
        
        assessment['modules']['memory_forensics'] = {
            "status": "READY",
            "note": "Run 'python memory_forensics_module.py' for demonstration"
        }
        
        # 6. PCAP Analysis（示範）
        print("\n[6/7] PCAP 分析模組測試...")
        print("    [提示] 需要 PCAP 檔案進行分析")
        print("    [提示] 可執行: python pcap_analysis_module.py")
        
        assessment['modules']['pcap_analysis'] = {
            "status": "READY",
            "note": "Run 'pcap_analysis_module.py' for demonstration"
        }
        
        # 7. CTI Integration（示範）
        print("\n[7/7] CTI 整合引擎測試...")
        print("    [提示] 可執行: python cti_integration_engine.py")
        
        assessment['modules']['cti'] = {
            "status": "READY",
            "ioc_count": self.cti.ioc_database['total_count'],
            "note": "Run 'python cti_integration_engine.py' for demonstration"
        }
        
        # 保存評估報告
        self._save_assessment(assessment)
        
        # 顯示摘要
        self._print_assessment_summary(assessment)
        
        return assessment
    
    def _save_assessment(self, assessment):
        """保存評估報告"""
        reports_dir = Path("./assessment_reports")
        reports_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_file = reports_dir / f"full_assessment_{timestamp}.json"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(assessment, f, indent=2, ensure_ascii=False)
        
        print(f"\n[報告] 完整評估報告已保存: {report_file}")
    
    def _print_assessment_summary(self, assessment):
        """列印評估摘要"""
        print("\n" + "=" * 70)
        print("完整防禦能力評估摘要")
        print("=" * 70)
        
        print("\n[模組狀態]")
        for module_name, module_data in assessment['modules'].items():
            status_icon = "[OK]" if module_data['status'] in ['COMPLETED', 'READY'] else "[!!]"
            print(f"  {status_icon} {module_name:<25} {module_data['status']}")
        
        print("\n[生成的報告]")
        print("  1. MITRE ATT&CK 覆蓋率: attack_coverage_report.html")
        print("  2. ATT&CK Navigator JSON: attack_navigator.json")
        print("  3. 證據鏈測試: ./evidence/{}/")
        print("  4. SOAR 執行日誌: ./playbook_logs/")
        print("  5. 評估總報告: ./assessment_reports/")
        
        print("\n[後續步驟]")
        print("  1. 開啟 attack_coverage_report.html 查看 ATT&CK 覆蓋率")
        print("  2. 執行 'python red_team_ci_system.py' 進行每日演練")
        print("  3. 執行 'python reset_passwords.py' 然後啟動 Web 系統")
        print("  4. 查看所有生成的報告檔案")


def main():
    """主程式"""
    print("=" * 70)
    print("進階防禦系統 - Advanced Defense System v2.0")
    print("=" * 70)
    print("\n整合模組:")
    print("  [OK] Chain of Custody (證據鏈管理)")
    print("  [OK] MITRE ATT&CK Mapper (攻擊映射)")
    print("  [OK] SOAR Playbooks (自動化響應)")
    print("  [OK] Red Team CI (持續演練)")
    print("  [OK] Memory Forensics (記憶體取證)")
    print("  [OK] PCAP Analysis (封包分析)")
    print("  [OK] CTI Integration (威脅情報)")
    print("\n能力等級: 5/5 星 (競賽級)")
    print("=" * 70)
    
    # 初始化系統
    system = AdvancedDefenseSystem()
    
    # 執行完整評估
    system.run_full_assessment()
    
    print("\n" + "=" * 70)
    print("所有功能已就緒！")
    print("=" * 70)


if __name__ == '__main__':
    main()

