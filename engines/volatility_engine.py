#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Volatility 實際引擎 - 呼叫 Volatility3 (vol3) 執行記憶體取證
"""

import json
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class VolatilityEngine:
    """Volatility3 實際執行引擎"""
    
    def __init__(self, volatility_cmd: str = "vol", plugin_path: Optional[str] = None):
        """
        volatility_cmd: vol (Volatility3) 或 vol.py
        """
        self.volatility_cmd = volatility_cmd
        self.plugin_path = plugin_path
        self._available = self._check_volatility()
    
    def _check_volatility(self) -> bool:
        """檢查 Volatility 是否已安裝"""
        try:
            result = subprocess.run(
                [self.volatility_cmd, "-h"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except FileNotFoundError:
            logger.warning("Volatility 未安裝，請安裝: pip install volatility3")
            return False
    
    def run_plugin(self, dump_file: str, plugin: str, profile: str = "Win10x64",
                   output: str = "json") -> Dict[str, Any]:
        """執行 Volatility 插件"""
        dump_path = Path(dump_file)
        if not dump_path.exists():
            return {"error": f"記憶體 dump 不存在: {dump_file}"}
        
        cmd = [
            self.volatility_cmd,
            "-f", str(dump_path),
            "-o", output,
            "windows." + plugin
        ]
        
        if self.plugin_path:
            cmd.extend(["--plugins", self.plugin_path])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                return {
                    "error": result.stderr or result.stdout,
                    "plugin": plugin,
                    "returncode": result.returncode
                }
            
            if output == "json":
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return {"raw_output": result.stdout, "plugin": plugin}
            
            return {"raw_output": result.stdout, "plugin": plugin}
        except subprocess.TimeoutExpired:
            return {"error": "執行逾時", "plugin": plugin}
        except Exception as e:
            return {"error": str(e), "plugin": plugin}
    
    def pslist(self, dump_file: str) -> Dict[str, Any]:
        """進程列表 - 對應 volatility pslist"""
        return self.run_plugin(dump_file, "pslist")
    
    def netscan(self, dump_file: str) -> Dict[str, Any]:
        """網路連接 - 對應 volatility netscan"""
        return self.run_plugin(dump_file, "netscan")
    
    def cmdline(self, dump_file: str) -> Dict[str, Any]:
        """命令列 - 對應 volatility cmdline"""
        return self.run_plugin(dump_file, "cmdline")
    
    def malfind(self, dump_file: str) -> Dict[str, Any]:
        """惡意代碼掃描 - 對應 volatility malfind"""
        return self.run_plugin(dump_file, "malfind")
    
    def dlllist(self, dump_file: str) -> Dict[str, Any]:
        """DLL 列表 - 檢測注入"""
        return self.run_plugin(dump_file, "dlllist")
    
    def analyze_memory_dump(self, dump_file: str, os_profile: str = "Win10x64") -> Dict[str, Any]:
        """完整記憶體分析 - 整合多個插件"""
        if not self._available:
            return self._fallback_analysis(dump_file)
        
        analysis = {
            "dump_file": dump_file,
            "analyzed_at": datetime.utcnow().isoformat() + "Z",
            "engine": "volatility3",
            "results": {}
        }
        
        plugins = ["pslist", "netscan", "cmdline", "malfind", "dlllist"]
        for plugin in plugins:
            try:
                result = self.run_plugin(dump_file, plugin, profile=os_profile)
                analysis["results"][plugin] = result
            except Exception as e:
                analysis["results"][plugin] = {"error": str(e)}
        
        # 提取 IoC
        analysis["iocs"] = self._extract_iocs(analysis["results"])
        
        return analysis
    
    def _extract_iocs(self, results: Dict) -> Dict[str, List[str]]:
        """從 Volatility 結果提取 IoC"""
        iocs = {"ip_addresses": [], "domains": [], "processes": []}
        
        netscan = results.get("netscan", {})
        if isinstance(netscan, dict) and "rows" in netscan:
            for row in netscan.get("rows", []):
                if isinstance(row, dict):
                    remote = row.get("RemoteAddress", "") or row.get("RemoteAddr", "")
                    if remote and remote != "-":
                        iocs["ip_addresses"].append(remote.split(":")[0])
        
        cmdline = results.get("cmdline", {})
        if isinstance(cmdline, dict) and "rows" in cmdline:
            for row in cmdline.get("rows", []):
                if isinstance(row, dict):
                    proc = row.get("Process", "") or row.get("CommandLine", "")
                    if proc:
                        iocs["processes"].append(str(proc)[:200])
        
        iocs["ip_addresses"] = list(set(iocs["ip_addresses"]))
        iocs["processes"] = list(set(iocs["processes"]))[:50]
        
        return iocs
    
    def _fallback_analysis(self, dump_file: str) -> Dict[str, Any]:
        """Volatility 不可用時的 fallback"""
        return {
            "dump_file": dump_file,
            "engine": "fallback",
            "error": "Volatility3 未安裝。請執行: pip install volatility3",
            "results": {},
            "iocs": {"ip_addresses": [], "domains": [], "processes": []}
        }


# 測試
if __name__ == '__main__':
    engine = VolatilityEngine()
    print(f"Volatility 可用: {engine._available}")
    # 需要實際 memory dump 才能測試
    # r = engine.analyze_memory_dump("memory.dmp")
