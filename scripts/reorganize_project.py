#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
專案結構整理腳本 - 將根目錄雜物移至子目錄
"""

import os
import sys
import shutil
from pathlib import Path

def safe_print(msg):
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        print("[moved]", flush=True)

ROOT = Path(__file__).parent.parent

# 要移動到 docs/ 的檔案模式
DOC_PATTERNS = [
    "*README*.md", "*_GUIDE*.md", "*_REPORT*.md", "*_SUMMARY*.md",
    "*_CHRONICLE*.md", "*_ANALYSIS*.md", "*_CERTIFICATION*.md",
    "*THESIS*.md", "*_進階*.md", "*指南*.md", "*報告*.md", "*總結*.md",
    "TEST_MODE_CLARIFICATION.md", "TEST_RESULTS.md", "TEST_STATUS.md",
    "IMPLEMENTATION_SUMMARY.md", "START_HERE.md", "QUICK_START.md",
    "COMPLETE_SYSTEM_GUIDE.md", "SECURE_SYSTEM_*.md", "WEB_SYSTEM_*.md",
    "FOCUSED_THESIS_REPORT.md", "ADVANCED_THESIS_REPORT.md",
]
# 排除根目錄保留的
KEEP_IN_ROOT = ["README.md"]

# 要移動到 reports/ 的檔案
REPORT_EXT = [".json", ".html", ".csv"]
REPORT_PATTERNS = ["*_REPORT_*.json", "*_report_*.json", "*_result*.json",
                   "*_results*.json", "*_report*.html", "*_report*.csv",
                   "benchmark_report.json", "verification_report.json",
                   "attack_coverage_report.*", "standalone_attack_report.*",
                   "standalone_navigator.json", "soar_playbook_report.json",
                   "compliance_report*.json", "comprehensive_test_report*.json",
                   "firewall_test_report_*.json", "national_defense_test_report_*.json",
                   "enterprise_deployment_report_*.json", "quick_test_results_*.json",
                   "*_achievement.json", "final_completion_report.json",
                   "kill_chain_test_result.json", "military_advanced_defense_results.json",
                   "ioc_database.json", "secure_web_data.json", "central_server_data.json",
                   "siem_cluster_config.json", "waf_blocklist.json",
                   "basic_test_results.json", "test_results.json",
                   "final_improvement_summary.json", "100_percent_achievement.json",
                   "attack_navigator.json", "comprehensive_test_report.json",
                   "full_assessment_*.json",
]

# 要移動到 scripts/ 的檔案
SCRIPT_PATTERNS = ["*.bat", "start.sh", "deploy_*.bat", "run_*.bat", "stop_*.bat",
                   "install_*.bat", "final_validation.bat", "generate_ssl_cert.ps1"]

# 根目錄保留的腳本（主要入口）
KEEP_BAT = {"deploy_and_test_secure_system.bat", "start_web_system.bat", "run_all_tests.bat"}

# 排除的檔案（不移動，可能被程式引用）
SKIP_FILES = {"custom.rules", "suricata.yaml", "sysmonconfig.xml",
              "defense_config.yaml", "firewall_config.yaml",
              "ultimate_firewall_config.yaml", "ultimate_military_firewall_config.yaml",
              "military_grade_firewall_config.yaml",
              "real_ultimate_defense_config.yaml", "real_ultimate_military_defense_config.yaml",
              "docker-compose.yml", "docker-compose.ha.yml", "docker-compose.simple.yml",
              "docker-compose.waf.yml", "Dockerfile", "Dockerfile.siem", "Dockerfile.target_app",
              ".gitignore", "requirements.txt", "README.md",
              "siem_cluster_config.json", "waf_blocklist.json", "secure_web_data.json",
              "central_server_data.json", "ioc_database.json",  # 執行時讀取
              }


def main():
    docs_dir = ROOT / "docs"
    reports_dir = ROOT / "reports"
    scripts_dir = ROOT / "scripts"
    
    for d in [docs_dir, reports_dir]:
        d.mkdir(exist_ok=True)
    
    moved_docs = 0
    moved_reports = 0
    moved_scripts = 0
    
    for f in ROOT.iterdir():
        if not f.is_file():
            continue
        name = f.name
        if name in SKIP_FILES:
            continue
        
        # Docs
        if name.endswith(".md") and name not in KEEP_IN_ROOT:
            dest = docs_dir / name
            if f.exists() and (not dest.exists() or f.stat().st_mtime > dest.stat().st_mtime):
                shutil.move(str(f), str(dest))
                moved_docs += 1
                safe_print(f"  docs/ {name}")
            continue
        
        # Reports (JSON, HTML, CSV)
        if name.endswith((".json", ".html", ".csv")):
            if name in SKIP_FILES or "config" in name.lower() or "blocklist" in name.lower():
                continue  # 保留設定類
            dest = reports_dir / name
            if f.exists() and not dest.exists():
                shutil.move(str(f), str(dest))
                moved_reports += 1
                safe_print(f"  reports/ {name}")
            continue
        
        # Scripts (bat, sh) - 保留主要入口在根目錄
        if (name.endswith((".bat", ".ps1")) or name == "start.sh") and name not in KEEP_BAT:
            dest = scripts_dir / name
            if f.exists() and not dest.exists():
                shutil.move(str(f), str(dest))
                moved_scripts += 1
                safe_print(f"  scripts/ {name}")
            continue
        
        # Result txt, log
        if name.endswith(("_result.txt", "_result_fixed.txt", "_results.txt")) or name.endswith(".log"):
            dest = reports_dir / name
            if f.exists() and not dest.exists():
                shutil.move(str(f), str(dest))
                moved_reports += 1
                safe_print(f"  reports/ {name}")
    
    safe_print(f"\nMoved: docs={moved_docs}, reports={moved_reports}, scripts={moved_scripts}")


if __name__ == "__main__":
    main()
