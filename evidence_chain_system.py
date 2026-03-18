#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chain of Custody - 證據鏈管理系統
實作完整的取證證據收集、簽名、驗證與管理
"""

import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
import hmac
import zipfile


class EvidenceChainSystem:
    """證據鏈管理系統"""
    
    def __init__(self, evidence_root="./evidence"):
        self.evidence_root = Path(evidence_root)
        self.evidence_root.mkdir(exist_ok=True)
        
        # HSM 模擬（實際應用應使用真實 HSM）
        self.signing_key = b"hsm_private_key_simulation_only_do_not_use_in_production"
        
    def create_incident(self, incident_type, description, severity="MEDIUM"):
        """創建新的事件並開始證據收集"""
        incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{str(uuid.uuid4())[:8]}"
        incident_dir = self.evidence_root / incident_id
        incident_dir.mkdir(exist_ok=True)
        
        incident = {
            "incident_id": incident_id,
            "type": incident_type,
            "description": description,
            "severity": severity,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "OPEN",
            "evidence_items": [],
            "chain_of_custody": []
        }
        
        # 記錄初始保管鏈
        self._add_custody_record(incident, "SYSTEM", "Incident created and evidence collection initiated")
        
        # 保存事件元數據
        self._save_incident(incident)
        
        return incident_id
    
    def collect_evidence(self, incident_id, evidence_type, data, description, collector="SYSTEM"):
        """收集證據項目"""
        incident = self._load_incident(incident_id)
        incident_dir = self.evidence_root / incident_id
        
        # 生成證據 ID
        evidence_id = f"EVD-{len(incident['evidence_items']) + 1:03d}"
        
        # 保存證據資料
        if evidence_type == "logs":
            filename = f"{evidence_id}_logs.json"
            filepath = incident_dir / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        
        elif evidence_type == "pcap":
            filename = f"{evidence_id}_capture.pcap"
            filepath = incident_dir / filename
            with open(filepath, 'wb') as f:
                f.write(data)
        
        elif evidence_type == "memory_dump":
            filename = f"{evidence_id}_memory.raw"
            filepath = incident_dir / filename
            with open(filepath, 'wb') as f:
                f.write(data)
        
        elif evidence_type == "screenshot":
            filename = f"{evidence_id}_screenshot.png"
            filepath = incident_dir / filename
            with open(filepath, 'wb') as f:
                f.write(data)
        
        elif evidence_type == "text":
            filename = f"{evidence_id}_text.txt"
            filepath = incident_dir / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(data)
        
        else:
            filename = f"{evidence_id}_data.bin"
            filepath = incident_dir / filename
            with open(filepath, 'wb') as f:
                f.write(data if isinstance(data, bytes) else str(data).encode())
        
        # 計算檔案雜湊
        file_hash = self._calculate_file_hash(filepath)
        
        # 建立證據記錄
        evidence_item = {
            "evidence_id": evidence_id,
            "type": evidence_type,
            "description": description,
            "filename": filename,
            "filepath": str(filepath),
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "collected_by": collector,
            "size_bytes": filepath.stat().st_size,
            "hash_sha256": file_hash,
            "hash_md5": self._calculate_file_hash(filepath, algorithm='md5'),
            "verified": True
        }
        
        # 添加到事件
        incident['evidence_items'].append(evidence_item)
        
        # 記錄保管鏈
        self._add_custody_record(
            incident, 
            collector, 
            f"Evidence collected: {evidence_type} - {description}"
        )
        
        # 保存更新
        self._save_incident(incident)
        
        return evidence_id
    
    def generate_manifest(self, incident_id, custodian="SOC Analyst"):
        """生成證據清單 (Manifest)"""
        incident = self._load_incident(incident_id)
        incident_dir = self.evidence_root / incident_id
        
        manifest = {
            "manifest_version": "1.0",
            "incident_id": incident_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generated_by": custodian,
            "incident_info": {
                "type": incident['type'],
                "description": incident['description'],
                "severity": incident['severity'],
                "created_at": incident['created_at'],
                "status": incident['status']
            },
            "evidence_items": incident['evidence_items'],
            "chain_of_custody": incident['chain_of_custody'],
            "total_items": len(incident['evidence_items']),
            "total_size_bytes": sum(item['size_bytes'] for item in incident['evidence_items'])
        }
        
        # 計算 manifest 雜湊
        manifest_json = json.dumps(manifest, sort_keys=True, ensure_ascii=False)
        manifest['manifest_hash'] = hashlib.sha256(manifest_json.encode()).hexdigest()
        
        # HSM 簽名
        signature = self._hsm_sign(manifest_json)
        manifest['signature'] = signature
        manifest['signature_algorithm'] = "HMAC-SHA256"
        manifest['signature_timestamp'] = datetime.now(timezone.utc).isoformat()
        
        # 保存 manifest
        manifest_file = incident_dir / "manifest.json"
        with open(manifest_file, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        
        # 記錄保管鏈
        self._add_custody_record(
            incident,
            custodian,
            "Evidence manifest generated and signed"
        )
        self._save_incident(incident)
        
        return manifest
    
    def verify_evidence(self, incident_id, evidence_id):
        """驗證證據完整性"""
        incident = self._load_incident(incident_id)
        
        # 找到證據項目
        evidence_item = None
        for item in incident['evidence_items']:
            if item['evidence_id'] == evidence_id:
                evidence_item = item
                break
        
        if not evidence_item:
            return {"verified": False, "error": "Evidence not found"}
        
        # 重新計算雜湊
        filepath = Path(evidence_item['filepath'])
        if not filepath.exists():
            return {"verified": False, "error": "Evidence file not found"}
        
        current_hash = self._calculate_file_hash(filepath)
        original_hash = evidence_item['hash_sha256']
        
        verified = (current_hash == original_hash)
        
        return {
            "verified": verified,
            "evidence_id": evidence_id,
            "original_hash": original_hash,
            "current_hash": current_hash,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    def verify_manifest(self, incident_id):
        """驗證 manifest 簽名"""
        incident_dir = self.evidence_root / incident_id
        manifest_file = incident_dir / "manifest.json"
        
        if not manifest_file.exists():
            return {"verified": False, "error": "Manifest not found"}
        
        with open(manifest_file, 'r', encoding='utf-8') as f:
            manifest = json.load(f)
        
        # 移除簽名欄位以重新計算
        signature = manifest.pop('signature', None)
        signature_timestamp = manifest.pop('signature_timestamp', None)
        
        # 重新計算雜湊
        manifest_json = json.dumps(manifest, sort_keys=True, ensure_ascii=False)
        expected_signature = self._hsm_sign(manifest_json)
        
        verified = (signature == expected_signature)
        
        # 還原
        manifest['signature'] = signature
        manifest['signature_timestamp'] = signature_timestamp
        
        return {
            "verified": verified,
            "manifest_hash": manifest.get('manifest_hash'),
            "signature_algorithm": manifest.get('signature_algorithm'),
            "signature_timestamp": signature_timestamp,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    def create_evidence_bundle(self, incident_id):
        """創建完整的證據包（ZIP）"""
        incident = self._load_incident(incident_id)
        incident_dir = self.evidence_root / incident_id
        
        # 先生成 manifest
        self.generate_manifest(incident_id)
        
        # 創建 ZIP
        bundle_filename = f"{incident_id}_evidence_bundle.zip"
        bundle_path = self.evidence_root / bundle_filename
        
        with zipfile.ZipFile(bundle_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # 添加所有證據檔案
            for item in incident_dir.iterdir():
                if item.is_file():
                    zipf.write(item, arcname=f"{incident_id}/{item.name}")
        
        # 計算 bundle 雜湊
        bundle_hash = self._calculate_file_hash(bundle_path)
        
        bundle_info = {
            "bundle_filename": bundle_filename,
            "bundle_path": str(bundle_path),
            "bundle_size_bytes": bundle_path.stat().st_size,
            "bundle_hash_sha256": bundle_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "incident_id": incident_id,
            "evidence_count": len(incident['evidence_items'])
        }
        
        # 保存 bundle 資訊
        bundle_info_file = incident_dir / "bundle_info.json"
        with open(bundle_info_file, 'w', encoding='utf-8') as f:
            json.dump(bundle_info, f, indent=2, ensure_ascii=False)
        
        return bundle_info
    
    def transfer_custody(self, incident_id, from_custodian, to_custodian, reason):
        """轉移證據保管權"""
        incident = self._load_incident(incident_id)
        
        self._add_custody_record(
            incident,
            to_custodian,
            f"Evidence custody transferred from {from_custodian}. Reason: {reason}"
        )
        
        self._save_incident(incident)
        
        return True
    
    def close_incident(self, incident_id, closed_by, summary):
        """關閉事件"""
        incident = self._load_incident(incident_id)
        
        incident['status'] = "CLOSED"
        incident['closed_at'] = datetime.now(timezone.utc).isoformat()
        incident['closed_by'] = closed_by
        incident['summary'] = summary
        
        self._add_custody_record(
            incident,
            closed_by,
            f"Incident closed. Summary: {summary}"
        )
        
        self._save_incident(incident)
        
        # 生成最終報告
        report = self._generate_final_report(incident)
        
        return report
    
    def _calculate_file_hash(self, filepath, algorithm='sha256'):
        """計算檔案雜湊"""
        if algorithm == 'sha256':
            hash_func = hashlib.sha256()
        elif algorithm == 'md5':
            hash_func = hashlib.md5()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def _hsm_sign(self, data):
        """HSM 簽名模擬"""
        if isinstance(data, str):
            data = data.encode()
        return hmac.new(self.signing_key, data, hashlib.sha256).hexdigest()
    
    def _add_custody_record(self, incident, custodian, action):
        """添加保管鏈記錄"""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "custodian": custodian,
            "action": action
        }
        incident['chain_of_custody'].append(record)
    
    def _save_incident(self, incident):
        """保存事件資料"""
        incident_dir = self.evidence_root / incident['incident_id']
        incident_file = incident_dir / "incident.json"
        with open(incident_file, 'w', encoding='utf-8') as f:
            json.dump(incident, f, indent=2, ensure_ascii=False)
    
    def _load_incident(self, incident_id):
        """載入事件資料"""
        incident_dir = self.evidence_root / incident_id
        incident_file = incident_dir / "incident.json"
        with open(incident_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _generate_final_report(self, incident):
        """生成最終報告"""
        incident_dir = self.evidence_root / incident['incident_id']
        
        report = {
            "report_type": "Final Incident Report",
            "incident_id": incident['incident_id'],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            
            "incident_summary": {
                "type": incident['type'],
                "description": incident['description'],
                "severity": incident['severity'],
                "status": incident['status'],
                "created_at": incident['created_at'],
                "closed_at": incident.get('closed_at'),
                "closed_by": incident.get('closed_by'),
                "duration": self._calculate_duration(
                    incident['created_at'],
                    incident.get('closed_at')
                )
            },
            
            "evidence_summary": {
                "total_items": len(incident['evidence_items']),
                "total_size_bytes": sum(item['size_bytes'] for item in incident['evidence_items']),
                "evidence_types": self._count_evidence_types(incident['evidence_items']),
                "all_verified": all(item.get('verified', False) for item in incident['evidence_items'])
            },
            
            "custody_summary": {
                "total_transfers": len(incident['chain_of_custody']),
                "custodians": list(set(record['custodian'] for record in incident['chain_of_custody'])),
                "chain_of_custody": incident['chain_of_custody']
            },
            
            "summary": incident.get('summary', ''),
            
            "recommendations": self._generate_recommendations(incident)
        }
        
        # 保存報告
        report_file = incident_dir / "final_report.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # 生成 HTML 報告
        self._generate_html_report(report, incident_dir)
        
        return report
    
    def _calculate_duration(self, start_time, end_time):
        """計算持續時間"""
        if not end_time:
            return "Ongoing"
        
        start = datetime.fromisoformat(start_time)
        end = datetime.fromisoformat(end_time)
        duration = end - start
        
        hours = duration.total_seconds() / 3600
        return f"{hours:.2f} hours"
    
    def _count_evidence_types(self, evidence_items):
        """統計證據類型"""
        types = {}
        for item in evidence_items:
            evidence_type = item['type']
            types[evidence_type] = types.get(evidence_type, 0) + 1
        return types
    
    def _generate_recommendations(self, incident):
        """生成建議"""
        recommendations = []
        
        # 根據事件類型生成建議
        if incident['type'] == 'SQL_INJECTION':
            recommendations.append("Implement parameterized queries")
            recommendations.append("Update WAF rules")
            recommendations.append("Conduct security code review")
        
        elif incident['type'] == 'BRUTE_FORCE':
            recommendations.append("Enforce stronger password policies")
            recommendations.append("Implement multi-factor authentication")
            recommendations.append("Review account lockout policies")
        
        elif incident['type'] == 'DDOS':
            recommendations.append("Review rate limiting configurations")
            recommendations.append("Consider CDN/DDoS mitigation service")
            recommendations.append("Implement IP reputation filtering")
        
        # 通用建議
        recommendations.append("Review and update security monitoring rules")
        recommendations.append("Conduct team training on incident response")
        recommendations.append("Update incident response playbooks")
        
        return recommendations
    
    def _generate_html_report(self, report, output_dir):
        """生成 HTML 格式報告"""
        html = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <title>Final Incident Report - {report['incident_id']}</title>
    <style>
        body {{
            font-family: 'Microsoft JhengHei', Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .section {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #f8f9fa;
            font-weight: bold;
        }}
        .severity-HIGH {{ color: #dc3545; font-weight: bold; }}
        .severity-MEDIUM {{ color: #ffc107; font-weight: bold; }}
        .severity-LOW {{ color: #28a745; font-weight: bold; }}
        .status-CLOSED {{ color: #28a745; font-weight: bold; }}
        .recommendations {{
            list-style-type: none;
            padding: 0;
        }}
        .recommendations li {{
            padding: 10px;
            margin: 5px 0;
            background: #e8f4f8;
            border-left: 4px solid #17a2b8;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Final Incident Report</h1>
        <p><strong>Incident ID:</strong> {report['incident_id']}</p>
        <p><strong>Generated:</strong> {report['generated_at']}</p>
    </div>
    
    <div class="section">
        <h2>Incident Summary</h2>
        <table>
            <tr>
                <th>Type</th>
                <td>{report['incident_summary']['type']}</td>
            </tr>
            <tr>
                <th>Description</th>
                <td>{report['incident_summary']['description']}</td>
            </tr>
            <tr>
                <th>Severity</th>
                <td class="severity-{report['incident_summary']['severity']}">{report['incident_summary']['severity']}</td>
            </tr>
            <tr>
                <th>Status</th>
                <td class="status-{report['incident_summary']['status']}">{report['incident_summary']['status']}</td>
            </tr>
            <tr>
                <th>Created</th>
                <td>{report['incident_summary']['created_at']}</td>
            </tr>
            <tr>
                <th>Closed</th>
                <td>{report['incident_summary'].get('closed_at', 'N/A')}</td>
            </tr>
            <tr>
                <th>Duration</th>
                <td>{report['incident_summary']['duration']}</td>
            </tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Evidence Summary</h2>
        <table>
            <tr>
                <th>Total Evidence Items</th>
                <td>{report['evidence_summary']['total_items']}</td>
            </tr>
            <tr>
                <th>Total Size</th>
                <td>{report['evidence_summary']['total_size_bytes']:,} bytes</td>
            </tr>
            <tr>
                <th>All Verified</th>
                <td>{'Yes' if report['evidence_summary']['all_verified'] else 'No'}</td>
            </tr>
        </table>
        
        <h3>Evidence Types</h3>
        <table>
            <tr>
                <th>Type</th>
                <th>Count</th>
            </tr>
            {''.join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in report['evidence_summary']['evidence_types'].items())}
        </table>
    </div>
    
    <div class="section">
        <h2>Chain of Custody</h2>
        <p><strong>Total Transfers:</strong> {report['custody_summary']['total_transfers']}</p>
        <p><strong>Custodians:</strong> {', '.join(report['custody_summary']['custodians'])}</p>
        
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Custodian</th>
                <th>Action</th>
            </tr>
            {''.join(f"<tr><td>{record['timestamp']}</td><td>{record['custodian']}</td><td>{record['action']}</td></tr>" for record in report['custody_summary']['chain_of_custody'])}
        </table>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul class="recommendations">
            {''.join(f"<li>{rec}</li>" for rec in report['recommendations'])}
        </ul>
    </div>
</body>
</html>"""
        
        report_file = output_dir / "final_report.html"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)


# 使用範例
if __name__ == '__main__':
    # 初始化系統
    evidence_system = EvidenceChainSystem()
    
    print("=" * 60)
    print("Chain of Custody 證據鏈管理系統 - 示範")
    print("=" * 60)
    
    # 1. 創建事件
    print("\n[1/6] 創建新事件...")
    incident_id = evidence_system.create_incident(
        incident_type="SQL_INJECTION",
        description="Detected SQL injection attempt on /api/login endpoint",
        severity="HIGH"
    )
    print(f"  [OK] 事件已創建: {incident_id}")
    
    # 2. 收集證據
    print("\n[2/6] 收集證據...")
    
    # 收集日誌
    log_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": "192.168.1.100",
        "request": "POST /api/login",
        "payload": "username=admin' OR '1'='1&password=test",
        "blocked": True
    }
    evd1 = evidence_system.collect_evidence(
        incident_id,
        "logs",
        log_data,
        "Attack request log from WAF",
        collector="WAF System"
    )
    print(f"  [OK] 證據已收集: {evd1}")
    
    # 收集文字證據
    text_data = "Alert: SQL injection detected\nAttacker IP: 192.168.1.100\nBlocked by WAF"
    evd2 = evidence_system.collect_evidence(
        incident_id,
        "text",
        text_data,
        "WAF alert message",
        collector="SIEM System"
    )
    print(f"  [OK] 證據已收集: {evd2}")
    
    # 3. 生成 Manifest
    print("\n[3/6] 生成證據清單...")
    manifest = evidence_system.generate_manifest(incident_id, custodian="SOC Analyst John")
    print(f"  [OK] Manifest 已生成並簽名")
    print(f"  - 證據項目: {manifest['total_items']}")
    print(f"  - 總大小: {manifest['total_size_bytes']} bytes")
    print(f"  - Manifest Hash: {manifest['manifest_hash'][:32]}...")
    
    # 4. 驗證證據
    print("\n[4/6] 驗證證據完整性...")
    verification1 = evidence_system.verify_evidence(incident_id, evd1)
    print(f"  [OK] {evd1}: {'通過' if verification1['verified'] else '失敗'}")
    
    verification2 = evidence_system.verify_evidence(incident_id, evd2)
    print(f"  [OK] {evd2}: {'通過' if verification2['verified'] else '失敗'}")
    
    # 5. 創建證據包
    print("\n[5/6] 創建證據包...")
    bundle = evidence_system.create_evidence_bundle(incident_id)
    print(f"  [OK] 證據包已創建: {bundle['bundle_filename']}")
    print(f"  - 大小: {bundle['bundle_size_bytes']:,} bytes")
    print(f"  - SHA-256: {bundle['bundle_hash_sha256'][:32]}...")
    
    # 6. 關閉事件
    print("\n[6/6] 關閉事件...")
    report = evidence_system.close_incident(
        incident_id,
        closed_by="Incident Manager Jane",
        summary="SQL injection attempt successfully blocked by WAF. Attacker IP has been added to blocklist. No data compromise detected."
    )
    print(f"  [OK] 事件已關閉")
    print(f"  - 持續時間: {report['incident_summary']['duration']}")
    print(f"  - 證據項目: {report['evidence_summary']['total_items']}")
    print(f"  - 保管鏈記錄: {report['custody_summary']['total_transfers']}")
    
    print("\n" + "=" * 60)
    print("證據鏈系統示範完成！")
    print("=" * 60)
    print(f"\n證據位置: ./evidence/{incident_id}/")
    print(f"最終報告: ./evidence/{incident_id}/final_report.html")

