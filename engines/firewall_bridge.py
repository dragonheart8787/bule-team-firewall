#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
防火牆與實際引擎橋接
將 ML、沙箱、Volatility、PCAP 實際引擎接上 NationalDefenseFirewall
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# 可選載入實際引擎
_ml_engine = None
_sandbox_engine = None
_volatility_engine = None
_pcap_engine = None


def get_ml_engine():
    global _ml_engine
    if _ml_engine is None:
        try:
            from .ml_engine import MLEngine
            _ml_engine = MLEngine()
        except Exception as e:
            logger.debug(f"ML 引擎載入失敗: {e}")
    return _ml_engine


def get_sandbox_engine(api_url: str = "http://localhost:8090"):
    global _sandbox_engine
    if _sandbox_engine is None:
        try:
            from .sandbox_engine import SandboxEngine
            _sandbox_engine = SandboxEngine(api_url=api_url)
        except Exception as e:
            logger.debug(f"沙箱引擎載入失敗: {e}")
    return _sandbox_engine


def get_volatility_engine():
    global _volatility_engine
    if _volatility_engine is None:
        try:
            from .volatility_engine import VolatilityEngine
            _volatility_engine = VolatilityEngine()
        except Exception as e:
            logger.debug(f"Volatility 引擎載入失敗: {e}")
    return _volatility_engine


def get_pcap_engine():
    global _pcap_engine
    if _pcap_engine is None:
        try:
            from .pcap_engine import PCAPEngine
            _pcap_engine = PCAPEngine()
        except Exception as e:
            logger.debug(f"PCAP 引擎載入失敗: {e}")
    return _pcap_engine


def ml_analyze_request(method: str, path: str, headers: Dict, body: str,
                       request_freq_1m: int = 0) -> Dict[str, Any]:
    """使用實際 ML 引擎分析請求"""
    engine = get_ml_engine()
    if engine:
        return engine.predict(method, path, headers, body, request_freq_1m=request_freq_1m)
    return {"anomaly_score": 0, "is_anomalous": False, "engine": "none"}


def sandbox_analyze_file(file_path: str) -> Dict[str, Any]:
    """使用實際沙箱分析檔案"""
    engine = get_sandbox_engine()
    if engine and engine._available:
        return engine.analyze_file(file_path, wait=False)
    return {"malicious_score": 0, "engine": "fallback"}


def volatility_analyze_dump(dump_file: str) -> Dict[str, Any]:
    """使用實際 Volatility 分析記憶體 dump"""
    engine = get_volatility_engine()
    if engine and engine._available:
        return engine.analyze_memory_dump(dump_file)
    return {"error": "Volatility 未就緒", "engine": "fallback"}


def pcap_analyze_file(pcap_file: str) -> Dict[str, Any]:
    """使用實際 PCAP 引擎分析"""
    engine = get_pcap_engine()
    if engine:
        return engine.analyze_pcap(pcap_file)
    return {"error": "PCAP 引擎未就緒", "engine": "fallback"}
