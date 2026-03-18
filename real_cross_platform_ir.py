#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
跨平台即時查詢與遠端鑑識模組
整合 osquery / Velociraptor / GRR（以可用即插欄位與本地降級路徑實作）
"""

import os
import json
import time
import logging
import threading
import subprocess
from datetime import datetime
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class RealCrossPlatformIR:
    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.running = False
        self.threads: List[threading.Thread] = []
        self.findings: List[Dict[str, Any]] = []

    def start_ir(self) -> Dict[str, Any]:
        if self.running:
            return { 'success': False, 'error': 'IR 已在運行中' }
        self.running = True
        if self.config.get('enable_osquery', True):
            t = threading.Thread(target=self._baseline_osquery, daemon=True)
            t.start()
            self.threads.append(t)
        if self.config.get('enable_velociraptor', False):
            t = threading.Thread(target=self._baseline_velociraptor, daemon=True)
            t.start()
            self.threads.append(t)
        if self.config.get('enable_grr', False):
            t = threading.Thread(target=self._baseline_grr, daemon=True)
            t.start()
            self.threads.append(t)
        logger.info('跨平台IR模組已啟動')
        return { 'success': True }

    def _baseline_osquery(self):
        try:
            query = self.config.get('osquery', {}).get('startup_query', 'select name, path, pid from processes limit 5;')
            osqueryi = self.config.get('osquery', {}).get('osqueryi_path', 'osqueryi')
            output_format = '--json'
            try:
                completed = subprocess.run([osqueryi, output_format, query], capture_output=True, text=True, timeout=30)
                if completed.returncode == 0:
                    data = json.loads(completed.stdout or '[]')
                    self.findings.append({ 'tool': 'osquery', 'data': data, 'time': datetime.now().isoformat() })
                else:
                    self.findings.append({ 'tool': 'osquery', 'error': completed.stderr[-1000:], 'time': datetime.now().isoformat() })
            except FileNotFoundError:
                # 降級：以 ps 資料替代
                fallback = []
                try:
                    if os.name == 'nt':
                        p = subprocess.run(['powershell', '-NoProfile', 'Get-Process | Select-Object -First 5 | ConvertTo-Json'], capture_output=True, text=True, timeout=30)
                        fallback = json.loads(p.stdout) if p.returncode == 0 and p.stdout else []
                    else:
                        p = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=30)
                        fallback = (p.stdout or '').splitlines()[:10]
                except Exception:
                    pass
                self.findings.append({ 'tool': 'osquery(fallback)', 'data': fallback, 'time': datetime.now().isoformat() })
        except Exception as e:
            logger.error(f'osquery 基線錯誤: {e}')

    def _baseline_velociraptor(self):
        # 預留：可呼叫 velociraptor artifact collection API
        self.findings.append({ 'tool': 'velociraptor', 'status': 'ready', 'time': datetime.now().isoformat() })

    def _baseline_grr(self):
        # 預留：可呼叫 GRR flows API
        self.findings.append({ 'tool': 'grr', 'status': 'ready', 'time': datetime.now().isoformat() })

    def stop_ir(self) -> Dict[str, Any]:
        self.running = False
        for t in self.threads:
            t.join(timeout=3)
        self.threads.clear()
        return { 'success': True }

    def get_status(self) -> Dict[str, Any]:
        return { 'success': True, 'running': self.running, 'findings': len(self.findings), 'recent': self.findings[-5:] if self.findings else [] }

    def get_comprehensive_report(self) -> Dict[str, Any]:
        return { 'success': True, 'cross_platform_ir': { 'findings': self.findings } }


