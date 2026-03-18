#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
執行完整效能實測
- 吞吐量 (10 Gbps 目標)
- 並發 (1M 目標)
- 實際引擎驗證
"""

import sys
import json
from pathlib import Path

# 加入專案路徑
sys.path.insert(0, str(Path(__file__).parent))


def main():
    print("=" * 70)
    print("籃隊防禦系統 - 效能實測")
    print("=" * 70)
    
    results = {}
    
    # 1. 吞吐量測試
    print("\n" + "=" * 70)
    print("1. 吞吐量實測 (目標: 10 Gbps)")
    print("=" * 70)
    try:
        from performance.benchmark_throughput import run_all_throughput_tests
        results["throughput"] = run_all_throughput_tests(duration=5)
    except Exception as e:
        print(f"  錯誤: {e}")
        results["throughput"] = {"error": str(e)}
    
    # 2. 並發測試
    print("\n" + "=" * 70)
    print("2. 並發測試 (目標: 1M)")
    print("=" * 70)
    try:
        from performance.benchmark_concurrent import run_concurrent_tests
        results["concurrent"] = run_concurrent_tests()
    except Exception as e:
        print(f"  錯誤: {e}")
        results["concurrent"] = {"error": str(e)}
    
    # 3. 實際引擎驗證
    print("\n" + "=" * 70)
    print("3. 實際引擎狀態")
    print("=" * 70)
    try:
        from engines.ml_engine import MLEngine
        from engines.sandbox_engine import SandboxEngine
        from engines.volatility_engine import VolatilityEngine
        from engines.pcap_engine import PCAPEngine
        
        ml = MLEngine()
        sb = SandboxEngine()
        vol = VolatilityEngine()
        pcap = PCAPEngine()
        
        engine_status = {
            "ML (scikit-learn)": "OK" if hasattr(ml, '_trained') else "Fallback",
            "沙箱 (Cuckoo)": "OK" if sb._available else "Fallback (Cuckoo 未運行)",
            "Volatility3": "OK" if vol._available else "Fallback (未安裝)",
            "PCAP (dpkt)": "OK" if pcap._available else "Fallback (未安裝)"
        }
        
        for name, status in engine_status.items():
            print(f"  {name}: {status}")
        
        results["engines"] = engine_status
    except Exception as e:
        print(f"  錯誤: {e}")
        results["engines"] = {"error": str(e)}
    
    # 4. 封包擷取
    print("\n" + "=" * 70)
    print("4. 封包擷取模組")
    print("=" * 70)
    try:
        from packet_capture.live_capture import LivePacketCapture
        cap = LivePacketCapture()
        cap.start()
        import time
        time.sleep(2)
        cap.stop()
        stats = cap.get_stats()
        print(f"  擷取: {stats.get('packets_captured', 0)} 封包")
        print(f"  吞吐: {stats.get('mbps', 0):.2f} Mbps")
        results["packet_capture"] = stats
    except Exception as e:
        print(f"  錯誤: {e}")
        results["packet_capture"] = {"error": str(e)}
    
    # 儲存報告
    Path("reports").mkdir(exist_ok=True)
    report_path = Path("reports/benchmark_report.json")
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 70)
    print(f"報告已儲存: {report_path}")
    print("=" * 70)


if __name__ == '__main__':
    main()
