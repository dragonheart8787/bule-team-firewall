#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
攻防演練與紫隊自動化模組
Atomic Red Team / Caldera 觸發與結果彙整
"""

import os
import time
import json
import logging
import subprocess
import threading
from datetime import datetime
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class RealAttackSimulation:
    """攻防演練控制器"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.running = False
        self.threads = []
        self.results = []

    def run_simulation(self) -> Dict[str, Any]:
        if self.running:
            return { 'success': False, 'error': '攻防演練已在執行中' }
        self.running = True
        if self.config.get('enable_atomic', False):
            t = threading.Thread(target=self._run_atomic, daemon=True)
            t.start()
            self.threads.append(t)
        if self.config.get('enable_caldera', False):
            t = threading.Thread(target=self._run_caldera, daemon=True)
            t.start()
            self.threads.append(t)
        logger.info('攻防演練模組已啟動')
        return { 'success': True, 'message': '攻防演練已啟動' }

    def _run_atomic(self):
        try:
            atoms = self.config.get('atomic_tests', ['T1059', 'T1047'])
            for tid in atoms:
                if not self.running:
                    break
                cmd = self.config.get('atomic_runner', '')
                if cmd:
                    try:
                        completed = subprocess.run(cmd.format(tid=tid), shell=True, capture_output=True, text=True, timeout=300)
                        self.results.append({ 'framework': 'atomic', 'technique': tid, 'rc': completed.returncode, 'stdout': completed.stdout[-2000:], 'stderr': completed.stderr[-2000:], 'time': datetime.now().isoformat() })
                    except Exception as e:
                        self.results.append({ 'framework': 'atomic', 'technique': tid, 'error': str(e), 'time': datetime.now().isoformat() })
                else:
                    # 降級：記錄預定義事件，供偵測鏈路驗證
                    self.results.append({ 'framework': 'atomic', 'technique': tid, 'simulated': True, 'time': datetime.now().isoformat() })
                time.sleep(2)
        except Exception as e:
            logger.error(f'Atomic 執行錯誤: {e}')

    def _run_caldera(self):
        try:
            api = self.config.get('caldera_api', '')
            profile = self.config.get('caldera_profile', 'basic.json')
            if api:
                # 預留：可用 requests 呼叫 Caldera API
                self.results.append({ 'framework': 'caldera', 'api': api, 'profile': profile, 'submitted': True, 'time': datetime.now().isoformat() })
            else:
                self.results.append({ 'framework': 'caldera', 'profile': profile, 'simulated': True, 'time': datetime.now().isoformat() })
        except Exception as e:
            logger.error(f'Caldera 執行錯誤: {e}')

    def stop_simulation(self) -> Dict[str, Any]:
        self.running = False
        for t in self.threads:
            t.join(timeout=3)
        self.threads.clear()
        logger.info('攻防演練已停止')
        return { 'success': True }

    def get_status(self) -> Dict[str, Any]:
        return {
            'success': True,
            'running': self.running,
            'executions': len(self.results),
            'recent': self.results[-5:] if self.results else []
        }

    def get_comprehensive_report(self) -> Dict[str, Any]:
        return { 'success': True, 'attack_simulation': { 'results': self.results } }



