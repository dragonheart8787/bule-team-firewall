#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
供應鏈完整性：SBOM 生成/驗證 與 映像簽章驗證（Sigstore/Cosign 介面預留）
"""

import os
import json
import logging
import subprocess
from datetime import datetime
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class RealSupplyChainSecurity:
    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.reports = []

    def generate_sbom(self, target_path: str) -> Dict[str, Any]:
        """使用 syft 生成 SBOM（若無 syft 則降級為檔案摘要清單）"""
        try:
            syft_bin = self.config.get('sbom', {}).get('syft_path', 'syft')
            try:
                completed = subprocess.run([syft_bin, target_path, '-o', 'json'], capture_output=True, text=True, timeout=300)
                if completed.returncode == 0 and completed.stdout:
                    sbom = json.loads(completed.stdout)
                    report = { 'type': 'sbom', 'target': target_path, 'sbom': sbom, 'time': datetime.now().isoformat() }
                    self.reports.append(report)
                    return { 'success': True, 'report': report }
            except FileNotFoundError:
                pass
            # 降級：以目錄檔案列表+大小
            listing = []
            for root, _, files in os.walk(target_path):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        listing.append({ 'path': fp, 'size': os.path.getsize(fp) })
                    except Exception:
                        continue
            report = { 'type': 'sbom(fallback)', 'target': target_path, 'files': listing[:2000], 'time': datetime.now().isoformat() }
            self.reports.append(report)
            return { 'success': True, 'report': report }
        except Exception as e:
            logger.error(f'SBOM 生成錯誤: {e}')
            return { 'success': False, 'error': str(e) }

    def verify_container_signature(self, image_ref: str) -> Dict[str, Any]:
        """驗證容器映像簽章（cosign），若無則回報需補簽"""
        try:
            cosign = self.config.get('sign', {}).get('cosign_path', 'cosign')
            try:
                completed = subprocess.run([cosign, 'verify', image_ref], capture_output=True, text=True, timeout=120)
                ok = (completed.returncode == 0)
                report = { 'type': 'signature', 'image': image_ref, 'verified': ok, 'stdout': (completed.stdout or '')[-2000:], 'stderr': (completed.stderr or '')[-2000:], 'time': datetime.now().isoformat() }
                self.reports.append(report)
                return { 'success': ok, 'report': report }
            except FileNotFoundError:
                msg = 'cosign 未安裝，無法完成映像簽章驗證'
                report = { 'type': 'signature', 'image': image_ref, 'verified': False, 'error': msg, 'time': datetime.now().isoformat() }
                self.reports.append(report)
                return { 'success': False, 'report': report }
        except Exception as e:
            logger.error(f'簽章驗證錯誤: {e}')
            return { 'success': False, 'error': str(e) }

    def get_status(self) -> Dict[str, Any]:
        return { 'success': True, 'reports': len(self.reports), 'recent': self.reports[-5:] if self.reports else [] }

    def get_comprehensive_report(self) -> Dict[str, Any]:
        return { 'success': True, 'supply_chain_security': { 'reports': self.reports } }



