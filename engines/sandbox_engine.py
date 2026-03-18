#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
沙箱實際引擎 - Cuckoo Sandbox API 整合
支援 Cuckoo 2.x REST API 提交檔案並取得分析報告
"""

import json
import hashlib
import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)


class SandboxEngine:
    """Cuckoo Sandbox 實際引擎"""
    
    def __init__(self, api_url: str = "http://localhost:8090", api_key: Optional[str] = None):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.timeout = 300
        self._available = self._check_availability()
    
    def _check_availability(self) -> bool:
        """檢查 Cuckoo API 是否可用"""
        if not REQUESTS_AVAILABLE:
            return False
        try:
            headers = {}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            r = requests.get(f"{self.api_url}/", timeout=5, headers=headers)
            return r.status_code == 200
        except Exception as e:
            logger.debug(f"Cuckoo 不可用: {e}")
            return False
    
    def submit_file(self, file_path: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """提交檔案至 Cuckoo 沙箱"""
        if not self._available:
            return self._fallback_submit(file_path)
        
        path = Path(file_path)
        if not path.exists():
            return {"error": "檔案不存在", "task_id": None}
        
        try:
            headers = {}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            with open(path, 'rb') as f:
                files = {'file': (path.name, f)}
                r = requests.post(
                    f"{self.api_url}/tasks/create/file",
                    files=files,
                    headers=headers,
                    timeout=30
                )
            
            if r.status_code != 200:
                return {"error": r.text, "task_id": None}
            
            data = r.json()
            task_id = data.get('task_ids', [None])[0]
            return {"task_id": task_id, "submitted": True}
        except Exception as e:
            logger.warning(f"提交沙箱失敗: {e}")
            return self._fallback_submit(file_path)
    
    def get_report(self, task_id: int) -> Dict[str, Any]:
        """取得 Cuckoo 分析報告"""
        if not self._available:
            return self._fallback_report(task_id)
        
        try:
            headers = {}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            r = requests.get(
                f"{self.api_url}/tasks/report/{task_id}/json",
                headers=headers,
                timeout=60
            )
            
            if r.status_code != 200:
                return {"error": "報告尚未就緒", "task_id": task_id}
            
            report = r.json()
            return self._parse_cuckoo_report(report)
        except Exception as e:
            return {"error": str(e), "task_id": task_id}
    
    def analyze_file(self, file_path: str, wait: bool = False,
                    max_wait_sec: int = 300) -> Dict[str, Any]:
        """提交並可選等待分析完成"""
        result = self.submit_file(file_path)
        if result.get('error') or not result.get('task_id'):
            return result
        
        task_id = result['task_id']
        if not wait:
            return {"task_id": task_id, "status": "submitted", "message": "請稍後查詢報告"}
        
        start = time.time()
        while time.time() - start < max_wait_sec:
            report = self.get_report(task_id)
            if 'error' not in report or '尚未就緒' not in str(report.get('error', '')):
                return report
            time.sleep(10)
        
        return {"task_id": task_id, "error": "分析逾時", "status": "timeout"}
    
    def _parse_cuckoo_report(self, report: Dict) -> Dict[str, Any]:
        """解析 Cuckoo JSON 報告"""
        info = report.get('info', {})
        score = info.get('score', 0)  # 0-10, 越高越惡意
        signatures = report.get('signatures', [])
        network = report.get('network', {})
        
        malicious_actions = []
        for sig in signatures:
            if sig.get('severity', 0) >= 2:
                malicious_actions.append(sig.get('name', 'Unknown'))
        
        return {
            "malicious_score": min(score * 10, 100),  # 轉為 0-100
            "malicious_actions": malicious_actions[:20],
            "network_connections": len(network.get('hosts', [])),
            "files_created": len(report.get('behavior', {}).get('summary', {}).get('files', [])),
            "registry_modified": len(report.get('behavior', {}).get('summary', {}).get('registry', [])),
            "is_malicious": score >= 5,
            "engine": "cuckoo_sandbox",
            "task_id": info.get('id')
        }
    
    def _fallback_submit(self, file_path: str) -> Dict[str, Any]:
        """Cuckoo 不可用時的 fallback - 啟發式分析"""
        path = Path(file_path)
        if not path.exists():
            return {"error": "檔案不存在", "task_id": None}
        
        content = path.read_bytes()
        score = 0
        
        # 簡單啟發式
        suspicious = [b'powershell', b'cmd.exe', b'mimikatz', b'meterpreter', b'VirtualAlloc']
        for s in suspicious:
            if s in content.lower():
                score += 25
        
        if len(content) > 10 * 1024 * 1024:  # 10MB
            score += 10
        
        return {
            "task_id": hash(file_path) % 100000,
            "malicious_score": min(score, 100),
            "engine": "fallback_heuristic",
            "submitted": False
        }
    
    def _fallback_report(self, task_id: int) -> Dict[str, Any]:
        """Fallback 報告"""
        return {
            "task_id": task_id,
            "malicious_score": 0,
            "engine": "fallback",
            "error": "Cuckoo 未運行，使用啟發式"
        }


# 測試
if __name__ == '__main__':
    engine = SandboxEngine()
    print(f"Cuckoo 可用: {engine._available}")
    r = engine.analyze_file(__file__, wait=False)
    print(json.dumps(r, indent=2, ensure_ascii=False))
