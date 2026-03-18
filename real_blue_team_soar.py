#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
藍隊SOAR（Windows 被動監控）
從 Suricata EVE 與 Sysmon 事件做自動化回應：
- 高嚴重度網路告警 → 觸發防火牆封鎖來源IP（Windows）
- 可設定白名單/黑名單與封鎖TTL（由上層協同模組管理）
"""

import os
import json
import time
import logging
import threading
from datetime import datetime
from typing import Dict, Any, Optional, Set

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class RealBlueTeamSOAR:
    """藍隊SOAR模組（被動監控）"""

    def __init__(self, config: Dict[str, Any], orchestrator=None):
        self.config = config or {}
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.orchestrator = orchestrator  # 依賴注入 RealFirewallOrchestrator 實例

        # 來源日誌
        self.suricata_eve = self._cfg(['sources', 'suricata_eve'], default='C:\\ProgramData\\Suricata\\logs\\eve.json')
        self.sysmon_enabled = bool(self._cfg(['sources', 'consume_sysmon'], default=False))
        # Windows 環境：被動監控
        self.auto_block_enabled = bool(self._cfg(['actions', 'auto_block'], default=True))
        self.block_ttl_minutes = int(self._cfg(['actions', 'block_ttl_minutes'], default=60))
        self.min_severity = int(self._cfg(['policy', 'min_severity'], default=2))  # Suricata severity: 1高 2中 3低
        self.whitelist: Set[str] = set(self._cfg(['policy', 'whitelist'], default=[]))

        logger.info("藍隊SOAR模組初始化完成（Windows被動監控模式）")

    def _cfg(self, path: list, default=None):
        cur = self.config
        for key in path:
            if not isinstance(cur, dict) or key not in cur:
                return default
            cur = cur[key]
        return cur

    def start_monitoring(self) -> Dict[str, Any]:
        if self.running:
            return {'success': False, 'error': '藍隊SOAR已在運行中'}
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        logger.info("藍隊SOAR已啟動")
        return {'success': True, 'message': '藍隊SOAR已啟動'}

    def stop_monitoring(self) -> Dict[str, Any]:
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("藍隊SOAR已停止")
        return {'success': True, 'message': '藍隊SOAR已停止'}

    def _run_loop(self):
        # 目前重點監控 Suricata EVE（Windows 被動監控）
        self._tail_eve_json()

    def _tail_eve_json(self):
        path = self.suricata_eve
        last_size = 0
        while self.running:
            try:
                if not os.path.exists(path):
                    time.sleep(2)
                    continue
                size = os.path.getsize(path)
                if size < last_size:
                    # 檔案輪替
                    last_size = 0
                if size > last_size:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(last_size)
                        for line in f:
                            self._handle_eve_line(line)
                        last_size = f.tell()
                time.sleep(1)
            except Exception as e:
                logger.error(f"EVE 讀取錯誤: {e}")
                time.sleep(2)

    def _handle_eve_line(self, line: str):
        line = line.strip()
        if not line:
            return
        try:
            evt = json.loads(line)
        except Exception:
            return
        # 只處理 alert 類型
        if evt.get('event_type') != 'alert':
            return
        alert = evt.get('alert', {})
        severity = int(alert.get('severity', 3))
        src_ip = evt.get('src_ip') or ''
        if not src_ip:
            return
        if src_ip in self.whitelist:
            return
        # 高嚴重度（1高/2中）才動作
        if severity <= self.min_severity and self.auto_block_enabled and self.orchestrator:
            self._block_source_ip(src_ip, alert)

    def _block_source_ip(self, ip: str, alert: Dict[str, Any]):
        try:
            reason = f"Suricata:{alert.get('signature', 'alert')} (sev:{alert.get('severity')})"
            result = self.orchestrator.block_ip(ip)
            if result.get('success'):
                logger.info(f"已自動封鎖來源IP: {ip}，原因: {reason}")
            else:
                logger.error(f"封鎖失敗 {ip}: {result.get('error')}")
        except Exception as e:
            logger.error(f"封鎖IP錯誤 {ip}: {e}")

    def get_status(self) -> Dict[str, Any]:
        return {'success': True, 'running': self.running, 'auto_block': self.auto_block_enabled}

    def get_comprehensive_report(self) -> Dict[str, Any]:
        return {
            'success': True,
            'blue_team_soar': {
                'mode': 'passive-windows',
                'suricata_eve': self.suricata_eve,
                'auto_block': self.auto_block_enabled,
                'min_severity': self.min_severity,
                'whitelist': list(self.whitelist),
                'last_update': datetime.now().isoformat()
            }
        }






