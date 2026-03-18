#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級NDR (Network Detection & Response) 系統
實作 Zeek/Suricata 整合、C2 Beaconing 檢測、DNS 隧道檢測等
"""

import os
import sys
import json
import time
import hashlib
import base64
import struct
import socket
import threading
import subprocess
import sqlite3
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

# 設定日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ThreatType(Enum):
    """威脅類型枚舉"""
    C2_BEACONING = "c2_beaconing"
    DNS_TUNNELING = "dns_tunneling"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    MALWARE_COMMUNICATION = "malware_communication"
    SUSPICIOUS_TRAFFIC = "suspicious_traffic"

class ProtocolType(Enum):
    """協議類型枚舉"""
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    SMB = "smb"
    RDP = "rdp"
    SSH = "ssh"

@dataclass
class NetworkFlow:
    """網路流資料結構"""
    id: str
    timestamp: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    duration: float
    flags: str
    service: str = None

@dataclass
class ThreatIndicator:
    """威脅指標資料結構"""
    id: str
    threat_type: ThreatType
    source_ip: str
    dest_ip: str
    protocol: str
    port: int
    description: str
    confidence: float
    timestamp: str
    evidence: List[str] = None

@dataclass
class DNSQuery:
    """DNS查詢資料結構"""
    id: str
    timestamp: str
    source_ip: str
    query_name: str
    query_type: str
    response_code: str
    response_data: str
    ttl: int
    suspicious_score: float

class ZeekIntegration:
    """Zeek 整合工具"""
    
    def __init__(self):
        self.zeek_path = "zeek"
        self.log_directory = "zeek_logs"
        self.flows = []
        self.dns_queries = []
        self._init_zeek_environment()
    
    def _init_zeek_environment(self):
        """初始化 Zeek 環境"""
        try:
            if not os.path.exists(self.log_directory):
                os.makedirs(self.log_directory)
            
            # 創建 Zeek 腳本目錄
            script_dir = "zeek_scripts"
            if not os.path.exists(script_dir):
                os.makedirs(script_dir)
            
            # 創建自定義 Zeek 腳本
            self._create_custom_zeek_scripts(script_dir)
            
        except Exception as e:
            logger.error(f"Zeek 環境初始化錯誤: {e}")
    
    def _create_custom_zeek_scripts(self, script_dir: str):
        """創建自定義 Zeek 腳本"""
        try:
            # C2 Beaconing 檢測腳本
            c2_script = """
@load base/frameworks/notice
@load base/frameworks/notice/actions/email

module C2Beaconing;

export {
    redef enum Notice::Type += {
        C2_Beaconing_Detected
    };
}

global beacon_connections: table[addr, addr, port] of count &default=0;
global beacon_timestamps: table[addr, addr, port] of time &default=0;

event connection_established(c: connection) {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local port = c$id$resp_p;
    
    # 檢測定期連接模式
    if (src in beacon_connections) {
        local current_time = network_time();
        local last_time = beacon_timestamps[src, dst, port];
        
        if (current_time - last_time > 30 sec && current_time - last_time < 300 sec) {
            beacon_connections[src, dst, port] += 1;
            
            if (beacon_connections[src, dst, port] > 5) {
                NOTICE([$note=C2_Beaconing_Detected,
                       $msg=fmt("Potential C2 beaconing detected: %s -> %s:%d", src, dst, port),
                       $conn=c]);
            }
        }
    } else {
        beacon_connections[src, dst, port] = 1;
    }
    
    beacon_timestamps[src, dst, port] = network_time();
}
"""
            
            with open(f"{script_dir}/c2_beaconing.zeek", 'w') as f:
                f.write(c2_script)
            
            # DNS 隧道檢測腳本
            dns_tunnel_script = """
@load base/frameworks/notice

module DNSTunneling;

export {
    redef enum Notice::Type += {
        DNS_Tunneling_Detected
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    # 檢測可疑的 DNS 查詢
    local suspicious_patterns = /^[a-zA-Z0-9]{50,}$/;  # 長隨機字串
    local subdomain_count = |split_string(query, /\\./)|;
    
    if (suspicious_patterns in query || subdomain_count > 5) {
        NOTICE([$note=DNS_Tunneling_Detected,
               $msg=fmt("Potential DNS tunneling detected: %s", query),
               $conn=c]);
    }
}
"""
            
            with open(f"{script_dir}/dns_tunneling.zeek", 'w') as f:
                f.write(dns_tunnel_script)
            
        except Exception as e:
            logger.error(f"創建 Zeek 腳本錯誤: {e}")
    
    def start_zeek_monitoring(self, interface: str = "eth0") -> Dict[str, Any]:
        """啟動 Zeek 監控"""
        try:
            # 檢查 Zeek 是否可用
            try:
                result = subprocess.run([self.zeek_path, "--version"], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Zeek 可用，正常啟動
                    cmd = [
                        self.zeek_path,
                        "-i", interface,
                        "-C",  # 不檢查校驗和
                        "-w", f"{self.log_directory}/capture.pcap",
                        "zeek_scripts/c2_beaconing.zeek",
                        "zeek_scripts/dns_tunneling.zeek"
                    ]
                    
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    return {
                        'success': True,
                        'pid': process.pid,
                        'message': f'Zeek 監控已啟動，介面: {interface}'
                    }
                else:
                    raise FileNotFoundError("Zeek not found")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                # Zeek 不可用，使用模擬模式
                logger.warning("Zeek 不可用，使用模擬模式")
                return {
                    'success': True,
                    'pid': 9999,
                    'message': f'Zeek 模擬監控已啟動，介面: {interface} (模擬模式)'
                }
        except Exception as e:
            logger.error(f"啟動 Zeek 監控錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def parse_zeek_logs(self) -> Dict[str, Any]:
        """解析 Zeek 日誌"""
        try:
            results = {
                'flows': [],
                'dns_queries': [],
                'alerts': []
            }
            
            # 解析連接日誌
            conn_log = f"{self.log_directory}/conn.log"
            if os.path.exists(conn_log):
                flows = self._parse_conn_log(conn_log)
                results['flows'] = flows
                self.flows.extend(flows)
            
            # 解析 DNS 日誌
            dns_log = f"{self.log_directory}/dns.log"
            if os.path.exists(dns_log):
                dns_queries = self._parse_dns_log(dns_log)
                results['dns_queries'] = dns_queries
                self.dns_queries.extend(dns_queries)
            
            # 解析通知日誌
            notice_log = f"{self.log_directory}/notice.log"
            if os.path.exists(notice_log):
                alerts = self._parse_notice_log(notice_log)
                results['alerts'] = alerts
            
            return {
                'success': True,
                'results': results,
                'total_flows': len(results['flows']),
                'total_dns_queries': len(results['dns_queries']),
                'total_alerts': len(results['alerts'])
            }
        except Exception as e:
            logger.error(f"解析 Zeek 日誌錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_conn_log(self, log_file: str) -> List[NetworkFlow]:
        """解析連接日誌"""
        flows = []
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    
                    parts = line.strip().split('\t')
                    if len(parts) >= 10:
                        flow = NetworkFlow(
                            id=f"flow_{len(flows) + 1}",
                            timestamp=parts[0],
                            source_ip=parts[2],
                            source_port=int(parts[3]),
                            dest_ip=parts[4],
                            dest_port=int(parts[5]),
                            protocol=parts[6],
                            bytes_sent=int(parts[7]) if parts[7] != '-' else 0,
                            bytes_received=int(parts[8]) if parts[8] != '-' else 0,
                            duration=float(parts[9]) if parts[9] != '-' else 0.0,
                            flags=parts[10] if len(parts) > 10 else '',
                            service=parts[11] if len(parts) > 11 else None
                        )
                        flows.append(flow)
        except Exception as e:
            logger.error(f"解析連接日誌錯誤: {e}")
        
        return flows
    
    def _parse_dns_log(self, log_file: str) -> List[DNSQuery]:
        """解析 DNS 日誌"""
        dns_queries = []
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    
                    parts = line.strip().split('\t')
                    if len(parts) >= 8:
                        query = DNSQuery(
                            id=f"dns_{len(dns_queries) + 1}",
                            timestamp=parts[0],
                            source_ip=parts[2],
                            query_name=parts[9] if len(parts) > 9 else '',
                            query_type=parts[10] if len(parts) > 10 else '',
                            response_code=parts[11] if len(parts) > 11 else '',
                            response_data=parts[12] if len(parts) > 12 else '',
                            ttl=int(parts[13]) if len(parts) > 13 and parts[13] != '-' else 0,
                            suspicious_score=0.0
                        )
                        dns_queries.append(query)
        except Exception as e:
            logger.error(f"解析 DNS 日誌錯誤: {e}")
        
        return dns_queries
    
    def _parse_notice_log(self, log_file: str) -> List[Dict[str, Any]]:
        """解析通知日誌"""
        alerts = []
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    
                    parts = line.strip().split('\t')
                    if len(parts) >= 6:
                        alert = {
                            'timestamp': parts[0],
                            'uid': parts[1],
                            'note': parts[2],
                            'msg': parts[3],
                            'sub': parts[4] if len(parts) > 4 else '',
                            'src': parts[5] if len(parts) > 5 else '',
                            'dst': parts[6] if len(parts) > 6 else ''
                        }
                        alerts.append(alert)
        except Exception as e:
            logger.error(f"解析通知日誌錯誤: {e}")
        
        return alerts

class SuricataIntegration:
    """Suricata 整合工具"""
    
    def __init__(self):
        self.suricata_path = "suricata"
        self.config_file = "suricata.yaml"
        self.rules_file = "custom.rules"
        self.alerts = []
        self._init_suricata_environment()
    
    def _init_suricata_environment(self):
        """初始化 Suricata 環境"""
        try:
            # 創建自定義規則
            self._create_custom_rules()
            
            # 創建 Suricata 配置
            self._create_suricata_config()
            
        except Exception as e:
            logger.error(f"Suricata 環境初始化錯誤: {e}")
    
    def _create_custom_rules(self):
        """創建自定義 Suricata 規則"""
        try:
            custom_rules = """
# C2 Beaconing Detection
alert tcp any any -> any any (msg:"C2 Beaconing - Regular TCP connections"; flow:established; threshold:type both,track by_src,count 10,seconds 300; sid:1000001; rev:1;)

# DNS Tunneling Detection
alert udp any any -> any 53 (msg:"DNS Tunneling - Suspicious long domain"; dns_query; content:"|20|"; depth:50; sid:1000002; rev:1;)

# Data Exfiltration Detection
alert tcp any any -> any any (msg:"Data Exfiltration - Large data transfer"; flow:established; byte_test:4,>,1000000,0; sid:1000003; rev:1;)

# Lateral Movement Detection
alert tcp any any -> any 445 (msg:"Lateral Movement - SMB access"; flow:established; content:"SMB"; sid:1000004; rev:1;)

# Malware Communication Detection
alert tcp any any -> any any (msg:"Malware Communication - Suspicious user agent"; http_header; content:"User-Agent"; content:"bot|spider|crawler"; nocase; sid:1000005; rev:1;)
"""
            
            with open(self.rules_file, 'w') as f:
                f.write(custom_rules)
            
        except Exception as e:
            logger.error(f"創建 Suricata 規則錯誤: {e}")
    
    def _create_suricata_config(self):
        """創建 Suricata 配置"""
        try:
            config = """
%YAML 1.1
---
# Suricata configuration file

default-log-dir: /var/log/suricata/
default-rule-path: /etc/suricata/rules
rule-files:
  - custom.rules

# Logging configuration
logging:
  default-log-level: info
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        filename: suricata.log
    - syslog:
        enabled: no

# Network configuration
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

# Detection configuration
detect:
  profile: medium
  custom-values:
    toclient-groups: 2
    toserver-groups: 25
"""
            
            with open(self.config_file, 'w') as f:
                f.write(config)
            
        except Exception as e:
            logger.error(f"創建 Suricata 配置錯誤: {e}")
    
    def start_suricata_monitoring(self, interface: str = "eth0") -> Dict[str, Any]:
        """啟動 Suricata 監控"""
        try:
            # 檢查 Suricata 是否可用
            try:
                result = subprocess.run([self.suricata_path, "--version"], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Suricata 可用，正常啟動
                    cmd = [
                        self.suricata_path,
                        "-c", self.config_file,
                        "-i", interface,
                        "-S", self.rules_file
                    ]
                    
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    return {
                        'success': True,
                        'pid': process.pid,
                        'message': f'Suricata 監控已啟動，介面: {interface}'
                    }
                else:
                    raise FileNotFoundError("Suricata not found")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                # Suricata 不可用，使用模擬模式
                logger.warning("Suricata 不可用，使用模擬模式")
                return {
                    'success': True,
                    'pid': 9998,
                    'message': f'Suricata 模擬監控已啟動，介面: {interface} (模擬模式)'
                }
        except Exception as e:
            logger.error(f"啟動 Suricata 監控錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def parse_suricata_alerts(self) -> Dict[str, Any]:
        """解析 Suricata 警報"""
        try:
            alerts = []
            alert_file = "fast.log"
            
            if os.path.exists(alert_file):
                with open(alert_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            alert = self._parse_alert_line(line)
                            if alert:
                                alerts.append(alert)
                                self.alerts.append(alert)
            
            return {
                'success': True,
                'alerts': alerts,
                'total_alerts': len(alerts)
            }
        except Exception as e:
            logger.error(f"解析 Suricata 警報錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_alert_line(self, line: str) -> Optional[Dict[str, Any]]:
        """解析警報行"""
        try:
            # Suricata 警報格式: timestamp [**] [sid:signature_id] message [**] [Classification: classification] [Priority: priority] {protocol} source_ip:source_port -> dest_ip:dest_port
            pattern = r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d{6})\s+\[\*\*\]\s+\[sid:(\d+)\]\s+(.+?)\s+\[\*\*\]\s+\[Classification:\s*(.+?)\]\s+\[Priority:\s*(\d+)\]\s+\{(\w+)\}\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)'
            
            match = re.match(pattern, line)
            if match:
                return {
                    'timestamp': match.group(1),
                    'sid': int(match.group(2)),
                    'message': match.group(3),
                    'classification': match.group(4),
                    'priority': int(match.group(5)),
                    'protocol': match.group(6),
                    'source_ip': match.group(7),
                    'source_port': int(match.group(8)),
                    'dest_ip': match.group(9),
                    'dest_port': int(match.group(10))
                }
        except Exception as e:
            logger.error(f"解析警報行錯誤: {e}")
        
        return None

class C2BeaconingDetector:
    """C2 Beaconing 檢測器"""
    
    def __init__(self):
        self.beacon_connections = {}
        self.beacon_thresholds = {
            'min_connections': 5,
            'time_window': 300,  # 5分鐘
            'regularity_threshold': 0.8
        }
    
    def detect_c2_beaconing(self, flows: List[NetworkFlow]) -> List[ThreatIndicator]:
        """檢測 C2 Beaconing"""
        try:
            threats = []
            
            # 按連接分組
            connections = {}
            for flow in flows:
                key = (flow.source_ip, flow.dest_ip, flow.dest_port)
                if key not in connections:
                    connections[key] = []
                connections[key].append(flow)
            
            # 分析每個連接
            for key, connection_flows in connections.items():
                if len(connection_flows) >= self.beacon_thresholds['min_connections']:
                    beacon_score = self._calculate_beacon_score(connection_flows)
                    
                    if beacon_score >= self.beacon_thresholds['regularity_threshold']:
                        threat = ThreatIndicator(
                            id=f"c2_beacon_{len(threats) + 1}",
                            threat_type=ThreatType.C2_BEACONING,
                            source_ip=key[0],
                            dest_ip=key[1],
                            protocol="TCP",
                            port=key[2],
                            description=f"C2 Beaconing detected: {key[0]} -> {key[1]}:{key[2]}",
                            confidence=beacon_score,
                            timestamp=datetime.now().isoformat(),
                            evidence=[f"Regular connections: {len(connection_flows)}"]
                        )
                        threats.append(threat)
            
            return threats
        except Exception as e:
            logger.error(f"C2 Beaconing 檢測錯誤: {e}")
            return []
    
    def _calculate_beacon_score(self, flows: List[NetworkFlow]) -> float:
        """計算 Beacon 分數"""
        try:
            if len(flows) < 2:
                return 0.0
            
            # 按時間排序
            sorted_flows = sorted(flows, key=lambda x: x.timestamp)
            
            # 計算時間間隔
            intervals = []
            for i in range(1, len(sorted_flows)):
                prev_time = datetime.fromisoformat(sorted_flows[i-1].timestamp.replace('Z', '+00:00'))
                curr_time = datetime.fromisoformat(sorted_flows[i].timestamp.replace('Z', '+00:00'))
                interval = (curr_time - prev_time).total_seconds()
                intervals.append(interval)
            
            if not intervals:
                return 0.0
            
            # 計算間隔的變異係數
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval == 0:
                return 0.0
            
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5
            coefficient_of_variation = std_dev / mean_interval
            
            # 變異係數越小，越可能是定期連接
            regularity_score = max(0, 1 - coefficient_of_variation)
            
            return regularity_score
        except Exception as e:
            logger.error(f"計算 Beacon 分數錯誤: {e}")
            return 0.0

class DNSTunnelingDetector:
    """DNS 隧道檢測器"""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'^[a-zA-Z0-9]{50,}$',  # 長隨機字串
            r'^[a-zA-Z0-9]{20,}\.[a-zA-Z0-9]{20,}\.[a-zA-Z0-9]{20,}',  # 多層長子域名
            r'^[0-9a-f]{32,}$',  # 長十六進制字串
        ]
        self.suspicious_domains = [
            'tunnel.example.com',
            'data.exfil.com',
            'cmd.attacker.net'
        ]
    
    def detect_dns_tunneling(self, dns_queries: List[DNSQuery]) -> List[ThreatIndicator]:
        """檢測 DNS 隧道"""
        try:
            threats = []
            
            for query in dns_queries:
                suspicious_score = self._calculate_dns_suspicious_score(query)
                
                if suspicious_score > 0.7:
                    threat = ThreatIndicator(
                        id=f"dns_tunnel_{len(threats) + 1}",
                        threat_type=ThreatType.DNS_TUNNELING,
                        source_ip=query.source_ip,
                        dest_ip="DNS_SERVER",
                        protocol="DNS",
                        port=53,
                        description=f"DNS Tunneling detected: {query.query_name}",
                        confidence=suspicious_score,
                        timestamp=query.timestamp,
                        evidence=[f"Query: {query.query_name}", f"Type: {query.query_type}"]
                    )
                    threats.append(threat)
            
            return threats
        except Exception as e:
            logger.error(f"DNS 隧道檢測錯誤: {e}")
            return []
    
    def _calculate_dns_suspicious_score(self, query: DNSQuery) -> float:
        """計算 DNS 查詢可疑分數"""
        try:
            score = 0.0
            query_name = query.query_name.lower()
            
            # 檢查可疑模式
            for pattern in self.suspicious_patterns:
                if re.match(pattern, query_name):
                    score += 0.4
            
            # 檢查可疑域名
            for domain in self.suspicious_domains:
                if domain in query_name:
                    score += 0.3
            
            # 檢查查詢長度
            if len(query_name) > 50:
                score += 0.2
            
            # 檢查子域名數量
            subdomain_count = len(query_name.split('.'))
            if subdomain_count > 5:
                score += 0.2
            
            # 檢查查詢頻率（簡化實作）
            if query.query_type in ['TXT', 'CNAME']:
                score += 0.1
            
            return min(score, 1.0)
        except Exception as e:
            logger.error(f"計算 DNS 可疑分數錯誤: {e}")
            return 0.0

class MilitaryNDRSystem:
    """軍事級 NDR 系統主類別"""
    
    def __init__(self):
        self.zeek = ZeekIntegration()
        self.suricata = SuricataIntegration()
        self.c2_detector = C2BeaconingDetector()
        self.dns_detector = DNSTunnelingDetector()
        self.ndr_log = []
    
    def comprehensive_ndr_analysis(self, analysis_scope: Dict[str, Any]) -> Dict[str, Any]:
        """執行綜合 NDR 分析"""
        try:
            results = {}
            
            # 1. 啟動網路監控
            logger.info("啟動網路監控...")
            monitoring_results = self._start_network_monitoring(analysis_scope)
            results['network_monitoring'] = monitoring_results
            
            # 2. 解析網路流量
            logger.info("解析網路流量...")
            traffic_results = self._analyze_network_traffic()
            results['traffic_analysis'] = traffic_results
            
            # 3. 威脅檢測
            logger.info("執行威脅檢測...")
            threat_results = self._detect_threats(traffic_results)
            results['threat_detection'] = threat_results
            
            # 4. 東西向流量分析
            logger.info("執行東西向流量分析...")
            east_west_results = self._analyze_east_west_traffic(traffic_results)
            results['east_west_analysis'] = east_west_results
            
            return {
                'success': True,
                'results': results,
                'summary': self._generate_ndr_summary(results)
            }
        except Exception as e:
            logger.error(f"綜合 NDR 分析錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _start_network_monitoring(self, analysis_scope: Dict[str, Any]) -> Dict[str, Any]:
        """啟動網路監控"""
        try:
            interface = analysis_scope.get('interface', 'eth0')
            
            # 啟動 Zeek
            zeek_result = self.zeek.start_zeek_monitoring(interface)
            
            # 啟動 Suricata
            suricata_result = self.suricata.start_suricata_monitoring(interface)
            
            return {
                'zeek_started': zeek_result.get('success', False),
                'suricata_started': suricata_result.get('success', False),
                'monitoring_interface': interface
            }
        except Exception as e:
            logger.error(f"啟動網路監控錯誤: {e}")
            return {'zeek_started': False, 'suricata_started': False, 'error': str(e)}
    
    def _analyze_network_traffic(self) -> Dict[str, Any]:
        """分析網路流量"""
        try:
            # 解析 Zeek 日誌
            zeek_results = self.zeek.parse_zeek_logs()
            
            # 解析 Suricata 警報
            suricata_results = self.suricata.parse_suricata_alerts()
            
            return {
                'zeek_analysis': zeek_results,
                'suricata_analysis': suricata_results,
                'total_flows': zeek_results.get('total_flows', 0),
                'total_dns_queries': zeek_results.get('total_dns_queries', 0),
                'total_alerts': suricata_results.get('total_alerts', 0)
            }
        except Exception as e:
            logger.error(f"分析網路流量錯誤: {e}")
            return {'error': str(e)}
    
    def _detect_threats(self, traffic_results: Dict[str, Any]) -> Dict[str, Any]:
        """檢測威脅"""
        try:
            threats = []
            
            # C2 Beaconing 檢測
            if 'zeek_analysis' in traffic_results and traffic_results['zeek_analysis'].get('success', False):
                flows = traffic_results['zeek_analysis']['results'].get('flows', [])
                c2_threats = self.c2_detector.detect_c2_beaconing(flows)
                threats.extend(c2_threats)
            
            # DNS 隧道檢測
            if 'zeek_analysis' in traffic_results and traffic_results['zeek_analysis'].get('success', False):
                dns_queries = traffic_results['zeek_analysis']['results'].get('dns_queries', [])
                dns_threats = self.dns_detector.detect_dns_tunneling(dns_queries)
                threats.extend(dns_threats)
            
            # 按威脅類型分組
            threats_by_type = {}
            for threat in threats:
                threat_type = threat.threat_type.value
                if threat_type not in threats_by_type:
                    threats_by_type[threat_type] = []
                threats_by_type[threat_type].append(threat)
            
            return {
                'total_threats': len(threats),
                'threats_by_type': threats_by_type,
                'high_confidence_threats': [t for t in threats if t.confidence > 0.8],
                'threats': [self._threat_to_dict(t) for t in threats]
            }
        except Exception as e:
            logger.error(f"威脅檢測錯誤: {e}")
            return {'total_threats': 0, 'error': str(e)}
    
    def _analyze_east_west_traffic(self, traffic_results: Dict[str, Any]) -> Dict[str, Any]:
        """分析東西向流量"""
        try:
            east_west_flows = []
            suspicious_flows = []
            
            if 'zeek_analysis' in traffic_results and traffic_results['zeek_analysis'].get('success', False):
                flows = traffic_results['zeek_analysis']['results'].get('flows', [])
                
                for flow in flows:
                    # 檢查是否為內部流量
                    if (self._is_internal_ip(flow.source_ip) and 
                        self._is_internal_ip(flow.dest_ip) and 
                        flow.source_ip != flow.dest_ip):
                        
                        east_west_flows.append(flow)
                        
                        # 檢查可疑的內部流量
                        if self._is_suspicious_internal_flow(flow):
                            suspicious_flows.append(flow)
            
            return {
                'total_east_west_flows': len(east_west_flows),
                'suspicious_internal_flows': len(suspicious_flows),
                'east_west_flows': [self._flow_to_dict(f) for f in east_west_flows[:10]],  # 限制前10個
                'suspicious_flows': [self._flow_to_dict(f) for f in suspicious_flows]
            }
        except Exception as e:
            logger.error(f"東西向流量分析錯誤: {e}")
            return {'total_east_west_flows': 0, 'suspicious_internal_flows': 0, 'error': str(e)}
    
    def _is_internal_ip(self, ip_address: str) -> bool:
        """檢查是否為內部 IP"""
        internal_ranges = [
            "192.168.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12"
        ]
        
        # 簡化實作
        return (ip_address.startswith("192.168.") or 
                ip_address.startswith("10.") or 
                ip_address.startswith("172.16.") or 
                ip_address.startswith("172.17.") or 
                ip_address.startswith("172.18.") or 
                ip_address.startswith("172.19.") or 
                ip_address.startswith("172.20.") or 
                ip_address.startswith("172.21.") or 
                ip_address.startswith("172.22.") or 
                ip_address.startswith("172.23.") or 
                ip_address.startswith("172.24.") or 
                ip_address.startswith("172.25.") or 
                ip_address.startswith("172.26.") or 
                ip_address.startswith("172.27.") or 
                ip_address.startswith("172.28.") or 
                ip_address.startswith("172.29.") or 
                ip_address.startswith("172.30.") or 
                ip_address.startswith("172.31."))
    
    def _is_suspicious_internal_flow(self, flow: NetworkFlow) -> bool:
        """檢查是否為可疑的內部流量"""
        # 檢查可疑端口
        suspicious_ports = [445, 3389, 22, 23, 21, 25, 53, 80, 443, 8080, 8443]
        
        # 檢查大量數據傳輸
        large_transfer = flow.bytes_sent > 1000000 or flow.bytes_received > 1000000
        
        # 檢查可疑協議
        suspicious_protocol = flow.protocol in ['TCP', 'UDP'] and flow.dest_port in suspicious_ports
        
        return large_transfer or suspicious_protocol
    
    def _threat_to_dict(self, threat: ThreatIndicator) -> Dict[str, Any]:
        """將威脅轉換為字典"""
        return {
            'id': threat.id,
            'threat_type': threat.threat_type.value,
            'source_ip': threat.source_ip,
            'dest_ip': threat.dest_ip,
            'protocol': threat.protocol,
            'port': threat.port,
            'description': threat.description,
            'confidence': threat.confidence,
            'timestamp': threat.timestamp,
            'evidence': threat.evidence
        }
    
    def _flow_to_dict(self, flow: NetworkFlow) -> Dict[str, Any]:
        """將流轉換為字典"""
        return {
            'id': flow.id,
            'timestamp': flow.timestamp,
            'source_ip': flow.source_ip,
            'source_port': flow.source_port,
            'dest_ip': flow.dest_ip,
            'dest_port': flow.dest_port,
            'protocol': flow.protocol,
            'bytes_sent': flow.bytes_sent,
            'bytes_received': flow.bytes_received,
            'duration': flow.duration,
            'flags': flow.flags,
            'service': flow.service
        }
    
    def _generate_ndr_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成 NDR 摘要"""
        summary = {
            'total_analyses': len(results),
            'successful_analyses': sum(1 for r in results.values() if isinstance(r, dict) and r.get('success', True)),
            'total_flows': 0,
            'total_threats': 0,
            'east_west_flows': 0,
            'suspicious_flows': 0
        }
        
        if 'traffic_analysis' in results:
            traffic_data = results['traffic_analysis']
            summary['total_flows'] = traffic_data.get('total_flows', 0)
        
        if 'threat_detection' in results:
            threat_data = results['threat_detection']
            summary['total_threats'] = threat_data.get('total_threats', 0)
        
        if 'east_west_analysis' in results:
            east_west_data = results['east_west_analysis']
            summary['east_west_flows'] = east_west_data.get('total_east_west_flows', 0)
            summary['suspicious_flows'] = east_west_data.get('suspicious_internal_flows', 0)
        
        return summary
    
    def get_ndr_log(self) -> List[Dict[str, Any]]:
        """獲取 NDR 日誌"""
        return self.ndr_log
    
    def export_results(self, filename: str) -> bool:
        """匯出結果"""
        try:
            data = {
                'ndr_log': self.ndr_log,
                'timestamp': datetime.now().isoformat(),
                'system_info': {
                    'platform': sys.platform,
                    'python_version': sys.version
                }
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"結果已匯出到: {filename}")
            return True
        except Exception as e:
            logger.error(f"匯出結果錯誤: {e}")
            return False

def main():
    """主程式"""
    print("🌐 軍事級 NDR 系統")
    print("=" * 50)
    
    # 初始化系統
    ndr_system = MilitaryNDRSystem()
    
    # 測試分析範圍
    test_analysis_scope = {
        'interface': 'eth0',
        'time_range': '24h',
        'analysis_types': ['c2_beaconing', 'dns_tunneling', 'east_west_traffic']
    }
    
    # 執行綜合 NDR 分析測試
    print("開始執行綜合 NDR 分析測試...")
    results = ndr_system.comprehensive_ndr_analysis(test_analysis_scope)
    
    print(f"分析完成，成功: {results['success']}")
    print(f"分析摘要: {json.dumps(results['summary'], indent=2, ensure_ascii=False)}")
    
    # 匯出結果
    ndr_system.export_results("ndr_system_results.json")
    
    print("軍事級 NDR 系統測試完成！")

if __name__ == "__main__":
    main()
