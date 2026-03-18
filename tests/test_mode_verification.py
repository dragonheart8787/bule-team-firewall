#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試模式驗證 - 確認 Real/Replay/Simulation 標示正確
驗證各模組實際執行模式
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_ml_engine_real():
    """ML 引擎：有 scikit-learn 時為 [Real]"""
    try:
        from engines.ml_engine import MLEngine
        engine = MLEngine()
        has_sklearn = hasattr(engine, '_trained') or (hasattr(engine, 'model') and engine.model is not None)
        # 未訓練時 model 可能為 None，但 SKLEARN_AVAILABLE 決定是否 Real
        from engines import ml_engine
        mode = "Real" if ml_engine.SKLEARN_AVAILABLE else "Simulation"
        return {"mode": mode, "sklearn_available": ml_engine.SKLEARN_AVAILABLE}
    except Exception as e:
        return {"mode": "Error", "error": str(e)}


def test_pcap_engine_real():
    """PCAP 引擎：有 dpkt 時為 [Real]"""
    try:
        from engines.pcap_engine import PCAPEngine
        engine = PCAPEngine()
        mode = "Real" if engine._available else "Simulation"
        return {"mode": mode, "dpkt_available": engine._available}
    except Exception as e:
        return {"mode": "Error", "error": str(e)}


def test_throughput_simulation():
    """吞吐量測試：確認為 [Simulation]"""
    # 驗證 benchmark 為 CPU 模擬，非真實網路
    from performance.benchmark_throughput import _worker_process_packets
    r = _worker_process_packets((1500, 1000))
    assert isinstance(r, tuple)
    assert r[0] == 1000
    assert r[1] == 1500 * 1000
    return {"mode": "Simulation", "verified": True}


def test_dpi_real():
    """DPI 檢測：實際呼叫為 [Real]"""
    from national_defense_firewall import NationalDefenseFirewall
    fw = NationalDefenseFirewall()
    r = fw.deep_packet_inspection({"id": "1", "payload": "1' OR '1'='1"})
    assert r["blocked"] == True
    assert any(t["type"] == "SQL Injection" for t in r["threats_found"])
    return {"mode": "Real", "verified": True}


def run_all():
    """執行測試模式驗證"""
    results = {}
    tests = [
        ("ML Engine", test_ml_engine_real),
        ("PCAP Engine", test_pcap_engine_real),
        ("Throughput Benchmark", test_throughput_simulation),
        ("DPI Detection", test_dpi_real),
    ]
    print("=" * 60)
    print("測試模式驗證 (Real/Replay/Simulation)")
    print("=" * 60)
    for name, fn in tests:
        try:
            r = fn()
            results[name] = r
            mode = r.get("mode", "?")
            print(f"  {name}: [{mode}]")
        except Exception as e:
            results[name] = {"mode": "Error", "error": str(e)}
            print(f"  {name}: Error - {e}")
    print("=" * 60)
    return results


if __name__ == "__main__":
    run_all()
