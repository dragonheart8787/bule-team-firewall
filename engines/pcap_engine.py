#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAP 實際引擎 - 使用 dpkt 解析真實封包
dpkt 輕量高效，適合高吞吐量分析
"""

import socket
import struct
import json
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

logger = __import__('logging').getLogger(__name__)


class PCAPEngine:
    """PCAP 實際解析引擎 - dpkt"""
    
    def __init__(self):
        self._available = DPKT_AVAILABLE
        self.c2_ports = {4444, 5555, 6666, 8080, 31337}
        self.suspicious_ua_patterns = [
            r'curl', r'wget', r'python-requests', r'MSIE 6\.0',
            r'^$'  # 空 UA
        ]
    
    def analyze_pcap(self, pcap_file: str) -> Dict[str, Any]:
        """分析 PCAP 檔案"""
        path = Path(pcap_file)
        if not path.exists():
            return {"error": f"檔案不存在: {pcap_file}"}
        
        if not self._available:
            return self._fallback_analysis(pcap_file)
        
        analysis = {
            "pcap_file": str(path),
            "pcap_size": path.stat().st_size,
            "pcap_hash_sha256": self._hash_file(pcap_file),
            "analyzed_at": datetime.utcnow().isoformat() + "Z",
            "engine": "dpkt",
            "results": {}
        }
        
        try:
            with open(pcap_file, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                stats = self._analyze_statistics(pcap)
                analysis["results"]["statistics"] = stats
                
                # 重新讀取以進行協議分析
                f.seek(0)
                pcap = dpkt.pcap.Reader(f)
                dns_data = self._analyze_dns(pcap)
                analysis["results"]["dns"] = dns_data
                
                f.seek(0)
                pcap = dpkt.pcap.Reader(f)
                http_data = self._analyze_http(pcap)
                analysis["results"]["http"] = http_data
                
                f.seek(0)
                pcap = dpkt.pcap.Reader(f)
                c2_data = self._detect_c2(pcap)
                analysis["results"]["c2_detection"] = c2_data
            
            analysis["results"]["iocs"] = self._extract_iocs(analysis["results"])
            analysis["results"]["suricata_rules"] = self._generate_suricata_rules(
                analysis["results"]["iocs"]
            )
            
        except Exception as e:
            analysis["error"] = str(e)
            analysis["results"] = self._fallback_results()
        
        return analysis
    
    def _analyze_statistics(self, pcap: 'dpkt.pcap.Reader') -> Dict:
        """流量統計"""
        total_packets = 0
        total_bytes = 0
        protocols = defaultdict(int)
        top_talkers = defaultdict(lambda: {"packets": 0, "bytes": 0})
        start_ts = end_ts = None
        
        for ts, buf in pcap:
            total_packets += 1
            total_bytes += len(buf)
            if start_ts is None:
                start_ts = ts
            end_ts = ts
            
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    src = socket.inet_ntoa(ip.src) if isinstance(ip.src, bytes) else str(ip.src)
                    dst = socket.inet_ntoa(ip.dst) if isinstance(ip.dst, bytes) else str(ip.dst)
                    top_talkers[src]["packets"] += 1
                    top_talkers[src]["bytes"] += len(buf)
                    top_talkers[dst]["packets"] += 1
                    top_talkers[dst]["bytes"] += len(buf)
                    
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        protocols["TCP"] += 1
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        protocols["UDP"] += 1
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        protocols["ICMP"] += 1
            except Exception:
                pass
        
        top = sorted(top_talkers.items(), key=lambda x: x[1]["bytes"], reverse=True)[:10]
        
        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "duration_seconds": (end_ts - start_ts) if start_ts and end_ts else 0,
            "protocols": dict(protocols),
            "top_talkers": [{"ip": ip, "packets": d["packets"], "bytes": d["bytes"]} for ip, d in top]
        }
    
    def _analyze_dns(self, pcap: 'dpkt.pcap.Reader') -> Dict:
        """DNS 分析"""
        queries = []
        suspicious = []
        
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    if isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        if udp.dport == 53 or udp.sport == 53:
                            dns = dpkt.dns.DNS(udp.data)
                            for q in dns.qd:
                                qname = q.name if hasattr(q, 'name') else str(q)
                                queries.append(qname)
                                if len(qname) > 50 or re.search(r'[0-9a-f]{32,}', qname):
                                    suspicious.append({
                                        "query": qname,
                                        "suspicious": True,
                                        "reasons": ["Long subdomain" if len(qname) > 50 else "Hex-encoded"]
                                    })
            except Exception:
                pass
        
        return {
            "total_queries": len(queries),
            "suspicious_count": len(suspicious),
            "suspicious_queries": suspicious[:20],
            "dns_tunneling_detected": len(suspicious) > 0
        }
    
    def _analyze_http(self, pcap: 'dpkt.pcap.Reader') -> Dict:
        """HTTP 分析"""
        requests_list = []
        suspicious = []
        
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        if tcp.dport == 80 or tcp.sport == 80:
                            if len(tcp.data) > 0:
                                try:
                                    http = dpkt.http.Request(tcp.data)
                                    method = getattr(http, 'method', 'GET')
                                    uri = getattr(http, 'uri', '')
                                    headers = getattr(http, 'headers', {})
                                    ua = headers.get('user-agent', '')
                                    
                                    req = {"method": method, "uri": uri, "user_agent": ua}
                                    requests_list.append(req)
                                    
                                    is_suspicious = any(re.search(p, ua, re.I) for p in self.suspicious_ua_patterns)
                                    if is_suspicious or 'admin' in uri.lower() or 'config' in uri.lower():
                                        suspicious.append({
                                            "method": method, "uri": uri, "user_agent": ua,
                                            "suspicious": True
                                        })
                                except Exception:
                                    pass
            except Exception:
                pass
        
        return {
            "total_requests": len(requests_list),
            "suspicious_count": len(suspicious),
            "suspicious_requests": suspicious[:20]
        }
    
    def _detect_c2(self, pcap: 'dpkt.pcap.Reader') -> Dict:
        """C2 通訊檢測"""
        connections = defaultdict(list)
        c2_indicators = []
        
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        dst = socket.inet_ntoa(ip.dst) if isinstance(ip.dst, bytes) else str(ip.dst)
                        if tcp.dport in self.c2_ports:
                            c2_indicators.append({
                                "dest_ip": dst,
                                "dest_port": tcp.dport,
                                "confidence": "HIGH",
                                "reason": f"Known C2 port {tcp.dport}"
                            })
            except Exception:
                pass
        
        return {
            "c2_detected": len(c2_indicators) > 0,
            "c2_count": len(set((i["dest_ip"], i["dest_port"]) for i in c2_indicators)),
            "c2_indicators": c2_indicators[:20]
        }
    
    def _extract_iocs(self, results: Dict) -> Dict[str, List[str]]:
        """提取 IoC"""
        iocs = {"ip_addresses": set(), "domains": set(), "urls": set()}
        
        for c2 in results.get("c2_detection", {}).get("c2_indicators", []):
            iocs["ip_addresses"].add(c2.get("dest_ip", ""))
        
        for q in results.get("dns", {}).get("suspicious_queries", []):
            iocs["domains"].add(q.get("query", "").split(".")[-2] + "." + q.get("query", "").split(".")[-1] if "." in q.get("query", "") else q.get("query", ""))
        
        for r in results.get("http", {}).get("suspicious_requests", []):
            iocs["urls"].add(r.get("uri", ""))
        
        return {
            "ip_addresses": sorted(list(iocs["ip_addresses"])),
            "domains": sorted(list(iocs["domains"])),
            "urls": sorted(list(iocs["urls"])),
            "user_agents": [],
            "ja3_hashes": []
        }
    
    def _generate_suricata_rules(self, iocs: Dict) -> List[str]:
        """生成 Suricata 規則"""
        rules = []
        rid = 2000001
        for ip in iocs.get("ip_addresses", [])[:50]:
            rules.append(f'alert ip any any -> {ip} any (msg:"Traffic to IoC IP {ip}"; sid:{rid}; rev:1;)')
            rid += 1
        for domain in iocs.get("domains", [])[:50]:
            rules.append(f'alert dns any any -> any any (msg:"DNS to IoC domain"; dns.query; content:"{domain}"; sid:{rid}; rev:1;)')
            rid += 1
        return rules
    
    def _hash_file(self, path: str) -> str:
        """計算檔案 SHA256"""
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                h.update(block)
        return h.hexdigest()
    
    def _fallback_analysis(self, pcap_file: str) -> Dict:
        """dpkt 不可用時的 fallback"""
        return {
            "pcap_file": pcap_file,
            "engine": "fallback",
            "error": "dpkt 未安裝。請執行: pip install dpkt",
            "results": self._fallback_results()
        }
    
    def _fallback_results(self) -> Dict:
        return {
            "statistics": {"total_packets": 0, "total_bytes": 0},
            "dns": {"total_queries": 0, "suspicious_count": 0},
            "http": {"total_requests": 0, "suspicious_count": 0},
            "c2_detection": {"c2_detected": False, "c2_count": 0},
            "iocs": {"ip_addresses": [], "domains": [], "urls": [], "user_agents": [], "ja3_hashes": []},
            "suricata_rules": []
        }


# 測試
if __name__ == '__main__':
    engine = PCAPEngine()
    print(f"dpkt 可用: {engine._available}")
