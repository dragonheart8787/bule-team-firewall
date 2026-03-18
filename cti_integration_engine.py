#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTI Integration Engine - 威脅情報整合引擎
STIX/TAXII 整合、自動 IoC 測試、False Positive/Negative 追蹤
"""

import json
import hashlib
import requests
import uuid
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict


class CTIEngine:
    """威脅情報整合引擎"""
    
    def __init__(self, ioc_database_file="ioc_database.json"):
        self.ioc_database_file = ioc_database_file
        self.ioc_database = self._load_ioc_database()
        self.test_results = []
        
        # TAXII 伺服器配置
        self.taxii_servers = [
            {
                "name": "AlienVault OTX",
                "url": "https://otx.alienvault.com/taxii",
                "collection": "default",
                "api_key": "YOUR_API_KEY"
            },
            {
                "name": "MISP",
                "url": "https://misp.local/taxii2",
                "collection": "indicators",
                "api_key": "YOUR_API_KEY"
            }
        ]
    
    def _load_ioc_database(self):
        """載入 IoC 資料庫"""
        if Path(self.ioc_database_file).exists():
            with open(self.ioc_database_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        return {
            "iocs": [],
            "last_updated": None,
            "total_count": 0
        }
    
    def ingest_iocs_from_stix(self, stix_bundle):
        """從 STIX Bundle 攝取 IoC"""
        print(f"\n[攝取] 處理 STIX Bundle...")
        
        ingested_count = 0
        
        # 解析 STIX Bundle（簡化版）
        if 'objects' in stix_bundle:
            for obj in stix_bundle['objects']:
                if obj.get('type') == 'indicator':
                    ioc = self._parse_stix_indicator(obj)
                    self._add_ioc(ioc)
                    ingested_count += 1
        
        print(f"  [OK] 攝取 {ingested_count} 個 IoC")
        
        return ingested_count
    
    def _parse_stix_indicator(self, stix_object):
        """解析 STIX Indicator"""
        return {
            "id": stix_object.get('id', f"ioc-{uuid.uuid4().hex[:16]}"),
            "type": self._extract_ioc_type(stix_object.get('pattern', '')),
            "value": self._extract_ioc_value(stix_object.get('pattern', '')),
            "name": stix_object.get('name', 'Unknown'),
            "description": stix_object.get('description', ''),
            "labels": stix_object.get('labels', []),
            "confidence": stix_object.get('confidence', 50),
            "created": stix_object.get('created'),
            "modified": stix_object.get('modified'),
            "source": "STIX",
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            "tested": False,
            "test_results": []
        }
    
    def _extract_ioc_type(self, pattern):
        """從 STIX 模式提取 IoC 類型"""
        if 'ipv4-addr' in pattern:
            return 'IP'
        elif 'domain-name' in pattern:
            return 'Domain'
        elif 'url' in pattern:
            return 'URL'
        elif 'file:hashes' in pattern:
            return 'Hash'
        else:
            return 'Unknown'
    
    def _extract_ioc_value(self, pattern):
        """從 STIX 模式提取 IoC 值"""
        # 簡化的提取（實際需要完整的 STIX 解析器）
        import re
        match = re.search(r"= '([^']+)'", pattern)
        if match:
            return match.group(1)
        return "Unknown"
    
    def _add_ioc(self, ioc):
        """添加 IoC 到資料庫"""
        # 檢查是否已存在
        for existing_ioc in self.ioc_database['iocs']:
            if existing_ioc['value'] == ioc['value']:
                # 更新現有 IoC
                existing_ioc.update(ioc)
                return
        
        # 添加新 IoC
        self.ioc_database['iocs'].append(ioc)
        self.ioc_database['total_count'] += 1
        self.ioc_database['last_updated'] = datetime.now(timezone.utc).isoformat()
        
        # 保存
        self._save_ioc_database()
    
    def test_ioc_detection(self, ioc):
        """測試 IoC 是否會被系統偵測"""
        print(f"\n[測試] IoC: {ioc['type']} - {ioc['value']}")
        
        test_result = {
            "ioc_id": ioc['id'],
            "ioc_value": ioc['value'],
            "ioc_type": ioc['type'],
            "tested_at": datetime.now(timezone.utc).isoformat(),
            "detected": False,
            "blocked": False,
            "detection_methods": []
        }
        
        # 根據 IoC 類型進行測試
        if ioc['type'] == 'IP':
            test_result.update(self._test_ip_ioc(ioc['value']))
        elif ioc['type'] == 'Domain':
            test_result.update(self._test_domain_ioc(ioc['value']))
        elif ioc['type'] == 'URL':
            test_result.update(self._test_url_ioc(ioc['value']))
        elif ioc['type'] == 'Hash':
            test_result.update(self._test_hash_ioc(ioc['value']))
        
        # 記錄測試結果
        ioc['tested'] = True
        ioc['test_results'].append(test_result)
        self.test_results.append(test_result)
        
        # 判定
        if test_result['detected']:
            print(f"  [偵測] 成功偵測")
            if test_result['blocked']:
                print(f"  [阻擋] 成功阻擋")
            else:
                print(f"  [警告] 未阻擋（False Negative）")
        else:
            print(f"  [警告] 未偵測（False Negative）")
        
        return test_result
    
    def _test_ip_ioc(self, ip_value):
        """測試 IP IoC"""
        # 檢查是否在 WAF 黑名單
        detected = False
        blocked = False
        methods = []
        
        # 模擬測試 - 實際應查詢 WAF/防火牆配置
        # 這裡假設我們有 API 可以查詢
        try:
            # 嘗試訪問該 IP（在隔離環境中）
            response = requests.get(f"http://{ip_value}", timeout=2)
            detected = False
            blocked = False
        except requests.exceptions.ConnectionError:
            # 如果連接被拒絕，可能是被封鎖
            detected = True
            blocked = True
            methods.append("Firewall Block")
        except:
            pass
        
        return {
            "detected": detected,
            "blocked": blocked,
            "detection_methods": methods
        }
    
    def _test_domain_ioc(self, domain_value):
        """測試 Domain IoC"""
        methods = []
        
        # 檢查 DNS 黑洞
        # 模擬檢查
        blocked_domains = ["malicious.com", "evil-c2.net", "attacker.com"]
        
        if domain_value in blocked_domains:
            return {
                "detected": True,
                "blocked": True,
                "detection_methods": ["DNS Sinkhole", "Domain Blacklist"]
            }
        
        return {
            "detected": False,
            "blocked": False,
            "detection_methods": []
        }
    
    def _test_url_ioc(self, url_value):
        """測試 URL IoC"""
        # 檢查 WAF 規則
        return {
            "detected": False,
            "blocked": False,
            "detection_methods": []
        }
    
    def _test_hash_ioc(self, hash_value):
        """測試 Hash IoC"""
        # 檢查惡意軟體沙箱
        return {
            "detected": False,
            "blocked": False,
            "detection_methods": []
        }
    
    def generate_detection_gap_report(self):
        """生成偵測缺口報告"""
        print("\n[報告] 生成偵測缺口分析...")
        
        total_tested = len(self.test_results)
        detected = sum(1 for r in self.test_results if r['detected'])
        blocked = sum(1 for r in self.test_results if r['blocked'])
        
        false_negatives = [r for r in self.test_results if not r['detected']]
        detected_but_not_blocked = [r for r in self.test_results if r['detected'] and not r['blocked']]
        
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_iocs_tested": total_tested,
                "detected": detected,
                "blocked": blocked,
                "detection_rate": detected / total_tested * 100 if total_tested > 0 else 0,
                "block_rate": blocked / total_tested * 100 if total_tested > 0 else 0
            },
            "gaps": {
                "false_negatives": len(false_negatives),
                "detected_not_blocked": len(detected_but_not_blocked)
            },
            "false_negative_list": false_negatives,
            "detected_not_blocked_list": detected_but_not_blocked,
            "recommendations": self._generate_gap_recommendations(false_negatives, detected_but_not_blocked)
        }
        
        # 保存報告
        reports_dir = Path("./cti_reports")
        reports_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_file = reports_dir / f"detection_gap_report_{timestamp}.json"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"  [OK] 報告已保存: {report_file}")
        
        return report
    
    def _generate_gap_recommendations(self, false_negatives, detected_not_blocked):
        """生成缺口改進建議"""
        recommendations = []
        
        # 按 IoC 類型分組
        fn_by_type = defaultdict(list)
        for fn in false_negatives:
            fn_by_type[fn['ioc_type']].append(fn)
        
        for ioc_type, items in fn_by_type.items():
            recommendations.append({
                "issue": f"{len(items)} {ioc_type} IoCs not detected",
                "priority": "HIGH",
                "action": f"Add detection rules for {ioc_type} indicators",
                "examples": [item['ioc_value'] for item in items[:3]]
            })
        
        # 對於偵測但未阻擋的
        if detected_not_blocked:
            recommendations.append({
                "issue": f"{len(detected_not_blocked)} IoCs detected but not blocked",
                "priority": "MEDIUM",
                "action": "Review and update blocking policies",
                "examples": [item['ioc_value'] for item in detected_not_blocked[:3]]
            })
        
        return recommendations
    
    def _save_ioc_database(self):
        """保存 IoC 資料庫"""
        with open(self.ioc_database_file, 'w', encoding='utf-8') as f:
            json.dump(self.ioc_database, f, indent=2, ensure_ascii=False)


# 使用範例
if __name__ == '__main__':
    print("=" * 60)
    print("CTI Integration Engine - 示範")
    print("=" * 60)
    
    # 初始化
    cti = CTIEngine()
    
    # 模擬 STIX Bundle
    print("\n[1/3] 攝取 STIX Bundle...")
    stix_bundle = {
        "type": "bundle",
        "id": "bundle--test-001",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--001",
                "pattern": "[ipv4-addr:value = '203.0.113.50']",
                "name": "Malicious C2 Server",
                "description": "Known C2 server used by APT group",
                "labels": ["malicious-activity", "c2"],
                "confidence": 90,
                "created": "2025-10-11T10:00:00Z"
            },
            {
                "type": "indicator",
                "id": "indicator--002",
                "pattern": "[domain-name:value = 'malicious.com']",
                "name": "Phishing Domain",
                "description": "Domain used in phishing campaigns",
                "labels": ["malicious-activity", "phishing"],
                "confidence": 85,
                "created": "2025-10-11T10:00:00Z"
            }
        ]
    }
    
    count = cti.ingest_iocs_from_stix(stix_bundle)
    
    # 測試 IoC 偵測
    print("\n[2/3] 測試 IoC 偵測能力...")
    for ioc in cti.ioc_database['iocs']:
        cti.test_ioc_detection(ioc)
    
    # 生成缺口報告
    print("\n[3/3] 生成偵測缺口報告...")
    gap_report = cti.generate_detection_gap_report()
    
    print("\n" + "=" * 60)
    print("CTI 整合摘要")
    print("=" * 60)
    print(f"總 IoC 數: {gap_report['summary']['total_iocs_tested']}")
    print(f"偵測率: {gap_report['summary']['detection_rate']:.1f}%")
    print(f"阻擋率: {gap_report['summary']['block_rate']:.1f}%")
    print(f"False Negatives: {gap_report['gaps']['false_negatives']}")
    
    if gap_report['recommendations']:
        print("\n建議改進:")
        for rec in gap_report['recommendations']:
            print(f"  [{rec['priority']}] {rec['action']}")
    
    print("\n詳細報告已保存到: ./cti_reports/")

