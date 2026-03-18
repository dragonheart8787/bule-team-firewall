#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 MITRE ATT&CK 覆蓋率報告"""
from mitre_attack_mapper import MITREAttackMapper
m = MITREAttackMapper()
m.generate_coverage_report()
m.generate_html_report()
m.generate_csv_report()
m.generate_mitre_navigator_json()
print("[OK] ATT&CK 報告生成完成")
