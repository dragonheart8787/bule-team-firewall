#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
即時封包擷取與流量處理
支援 Windows (Npcap) / Linux (libpcap)
"""

import threading
import time
import logging
from collections import defaultdict, deque
from typing import Callable, Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

# 嘗試載入 pcap 綁定
try:
    import pcap
    PCAP_AVAILABLE = True
except ImportError:
    try:
        from scapy.all import sniff
        SCAPY_AVAILABLE = True
        PCAP_AVAILABLE = False
    except ImportError:
        SCAPY_AVAILABLE = False
        PCAP_AVAILABLE = False

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False


class LivePacketCapture:
    """即時封包擷取與處理"""
    
    def __init__(self, interface: Optional[str] = None, bpf_filter: Optional[str] = None,
                 max_queue_size: int = 100000):
        self.interface = interface
        self.bpf_filter = bpf_filter or "tcp or udp"
        self.max_queue_size = max_queue_size
        self._running = False
        self._thread = None
        self._packet_queue = deque(maxlen=max_queue_size)
        self._stats = {
            "packets_captured": 0,
            "packets_dropped": 0,
            "bytes_captured": 0,
            "start_time": None,
            "last_packet_time": None
        }
        self._callbacks = []
        self._lock = threading.Lock()
    
    def add_callback(self, callback: Callable[[Dict], None]):
        """新增封包處理回調"""
        self._callbacks.append(callback)
    
    def _process_packet(self, raw_data: bytes, timestamp: float) -> Optional[Dict]:
        """解析封包為結構化資料"""
        if not DPKT_AVAILABLE:
            return {"raw_len": len(raw_data), "timestamp": timestamp}
        
        try:
            eth = dpkt.ethernet.Ethernet(raw_data)
            if not isinstance(eth.data, dpkt.ip.IP):
                return None
            
            ip = eth.data
            src_ip = self._ip_to_str(ip.src)
            dst_ip = self._ip_to_str(ip.dst)
            proto = "TCP" if isinstance(ip.data, dpkt.tcp.TCP) else "UDP" if isinstance(ip.data, dpkt.udp.UDP) else "OTHER"
            
            sport = dport = 0
            if isinstance(ip.data, dpkt.tcp.TCP):
                sport = ip.data.sport
                dport = ip.data.dport
            elif isinstance(ip.data, dpkt.udp.UDP):
                sport = ip.data.sport
                dport = ip.data.dport
            
            return {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "sport": sport,
                "dport": dport,
                "length": len(raw_data),
                "payload_len": len(ip.data.data) if hasattr(ip.data, 'data') and ip.data.data else 0
            }
        except Exception as e:
            logger.debug(f"解析封包失敗: {e}")
            return {"raw_len": len(raw_data), "timestamp": timestamp}
    
    def _ip_to_str(self, ip):
        """IP 轉字串"""
        try:
            import socket
            return socket.inet_ntoa(ip) if hasattr(socket, 'inet_ntoa') else str(ip)
        except Exception:
            return str(ip)
    
    def _capture_loop_scapy(self):
        """使用 Scapy 擷取"""
        from scapy.all import sniff
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=lambda p: self._on_packet(bytes(p), time.time()),
            stop_filter=lambda _: not self._running,
            store=False
        )
    
    def _capture_loop_pcap(self):
        """使用 pcap 擷取"""
        pc = pcap.pcap(name=self.interface, promisc=True, immediate=True)
        pc.setfilter(self.bpf_filter)
        for ts, buf in pc:
            if not self._running:
                break
            self._on_packet(buf, ts)
    
    def _on_packet(self, raw: bytes, timestamp: float):
        """封包到達處理"""
        with self._lock:
            self._stats["packets_captured"] += 1
            self._stats["bytes_captured"] += len(raw)
            self._stats["last_packet_time"] = timestamp
            
            if len(self._packet_queue) >= self.max_queue_size:
                self._packet_queue.popleft()
                self._stats["packets_dropped"] += 1
            
            pkt_info = self._process_packet(raw, timestamp)
            if pkt_info:
                self._packet_queue.append(pkt_info)
                
                for cb in self._callbacks:
                    try:
                        cb(pkt_info)
                    except Exception as e:
                        logger.warning(f"Callback 錯誤: {e}")
    
    def start(self):
        """開始擷取"""
        if self._running:
            return
        self._running = True
        self._stats["start_time"] = time.time()
        
        if SCAPY_AVAILABLE:
            self._thread = threading.Thread(target=self._capture_loop_scapy, daemon=True)
        elif PCAP_AVAILABLE:
            self._thread = threading.Thread(target=self._capture_loop_pcap, daemon=True)
        else:
            logger.warning("無可用擷取庫 (scapy/pcap)，使用模擬模式")
            self._thread = threading.Thread(target=self._simulate_capture, daemon=True)
        
        self._thread.start()
        logger.info("封包擷取已啟動")
    
    def _simulate_capture(self):
        """模擬擷取（無 pcap 時）"""
        while self._running:
            time.sleep(0.1)
            # 模擬封包
            self._on_packet(b'\x00' * 60, time.time())
    
    def stop(self):
        """停止擷取"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("封包擷取已停止")
    
    def get_stats(self) -> Dict[str, Any]:
        """取得統計"""
        with self._lock:
            s = dict(self._stats)
        if s["start_time"]:
            elapsed = time.time() - s["start_time"]
            s["duration_seconds"] = elapsed
            s["packets_per_second"] = s["packets_captured"] / elapsed if elapsed > 0 else 0
            s["bytes_per_second"] = s["bytes_captured"] / elapsed if elapsed > 0 else 0
            s["mbps"] = (s["bytes_per_second"] * 8) / 1_000_000
        return s
    
    def get_queue_size(self) -> int:
        """佇列中封包數"""
        return len(self._packet_queue)
    
    def drain_queue(self, max_count: int = 1000) -> list:
        """取出佇列中的封包"""
        result = []
        with self._lock:
            for _ in range(min(max_count, len(self._packet_queue))):
                if self._packet_queue:
                    result.append(self._packet_queue.popleft())
        return result


# 測試
if __name__ == '__main__':
    cap = LivePacketCapture()
    def on_pkt(p):
        print(f"封包: {p.get('src_ip', '?')} -> {p.get('dst_ip', '?')} {p.get('protocol', '')}")
    cap.add_callback(on_pkt)
    cap.start()
    try:
        time.sleep(5)
    finally:
        cap.stop()
    print("統計:", cap.get_stats())
