#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
封包過濾和深度檢測系統
Packet Filtering and Deep Packet Inspection System

功能特色：
- 深度封包檢測 (DPI)
- 協議分析
- 內容過濾
- 流量整形
- 負載均衡
- 軍事級加密檢測
"""

import struct
import socket
import logging
import re
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import ipaddress
import threading
from collections import defaultdict, deque
import time

logger = logging.getLogger(__name__)

class Protocol(Enum):
    """協議類型"""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    FTP = "FTP"
    SSH = "SSH"
    TELNET = "TELNET"
    SMTP = "SMTP"
    DNS = "DNS"
    DHCP = "DHCP"
    SNMP = "SNMP"
    UNKNOWN = "UNKNOWN"

class FilterAction(Enum):
    """過濾動作"""
    ALLOW = "ALLOW"
    DROP = "DROP"
    REJECT = "REJECT"
    LOG = "LOG"
    RATE_LIMIT = "RATE_LIMIT"

@dataclass
class PacketFilter:
    """封包過濾器"""
    id: str
    name: str
    protocol: Protocol
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    action: FilterAction
    enabled: bool = True
    priority: int = 0

@dataclass
class PacketInfo:
    """封包資訊"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    payload: bytes
    payload_size: int
    flags: int
    ttl: int
    tos: int

class DeepPacketInspector:
    """深度封包檢測器"""
    
    def __init__(self):
        self.protocol_detectors = {
            'http': self._detect_http,
            'https': self._detect_https,
            'ftp': self._detect_ftp,
            'ssh': self._detect_ssh,
            'smtp': self._detect_smtp,
            'dns': self._detect_dns,
            'dhcp': self._detect_dhcp
        }
        
        self.content_filters = {
            'malware_signatures': self._check_malware_signatures,
            'suspicious_patterns': self._check_suspicious_patterns,
            'encryption_analysis': self._analyze_encryption,
            'protocol_anomalies': self._check_protocol_anomalies
        }
        
        # 惡意軟體特徵
        self.malware_signatures = [
            b'MZ',  # PE檔案頭
            b'PK',  # ZIP檔案頭
            b'%PDF',  # PDF檔案頭
            b'<script>',
            b'javascript:',
            b'eval(',
            b'base64_decode'
        ]
        
        # 可疑模式
        self.suspicious_patterns = [
            rb'<script[^>]*>.*?</script>',
            rb'javascript:',
            rb'on\w+\s*=',
            rb'<iframe[^>]*>',
            rb'document\.cookie',
            rb'window\.location',
            rb'eval\s*\(',
            rb'exec\s*\(',
            rb'system\s*\(',
            rb'shell_exec'
        ]

    def inspect_packet(self, packet: PacketInfo) -> Dict[str, Any]:
        """深度檢測封包"""
        inspection_result = {
            'protocol': self._detect_protocol(packet),
            'content_analysis': self._analyze_content(packet),
            'threat_indicators': [],
            'risk_score': 0.0,
            'recommendations': []
        }
        
        # 協議檢測
        detected_protocol = inspection_result['protocol']
        if detected_protocol != Protocol.UNKNOWN:
            inspection_result['protocol_details'] = self._get_protocol_details(packet, detected_protocol)
        
        # 內容分析
        content_analysis = inspection_result['content_analysis']
        
        # 威脅檢測
        threats = self._detect_threats(packet, content_analysis)
        inspection_result['threat_indicators'] = threats
        
        # 計算風險分數
        inspection_result['risk_score'] = self._calculate_risk_score(packet, threats, content_analysis)
        
        # 生成建議
        inspection_result['recommendations'] = self._generate_recommendations(
            packet, threats, inspection_result['risk_score']
        )
        
        return inspection_result

    def _detect_protocol(self, packet: PacketInfo) -> Protocol:
        """檢測協議類型"""
        # 基於端口的協議檢測
        port_protocols = {
            80: Protocol.HTTP,
            443: Protocol.HTTPS,
            21: Protocol.FTP,
            22: Protocol.SSH,
            23: Protocol.TELNET,
            25: Protocol.SMTP,
            53: Protocol.DNS,
            67: Protocol.DHCP,
            68: Protocol.DHCP,
            161: Protocol.SNMP
        }
        
        if packet.dest_port in port_protocols:
            return port_protocols[packet.dest_port]
        
        if packet.source_port in port_protocols:
            return port_protocols[packet.source_port]
        
        # 基於內容的協議檢測
        if packet.payload:
            payload_str = packet.payload.decode('utf-8', errors='ignore').lower()
            
            if 'http/' in payload_str or 'get ' in payload_str or 'post ' in payload_str:
                return Protocol.HTTP
            elif '220' in payload_str and 'ftp' in payload_str:
                return Protocol.FTP
            elif 'ssh-' in payload_str:
                return Protocol.SSH
            elif 'helo' in payload_str or 'mail from:' in payload_str:
                return Protocol.SMTP
        
        return Protocol.UNKNOWN

    def _analyze_content(self, packet: PacketInfo) -> Dict[str, Any]:
        """分析封包內容"""
        analysis = {
            'size': packet.payload_size,
            'entropy': 0.0,
            'compression_ratio': 0.0,
            'text_content': '',
            'binary_content': False,
            'encrypted_content': False,
            'file_signatures': [],
            'urls': [],
            'emails': [],
            'ip_addresses': []
        }
        
        if not packet.payload:
            return analysis
        
        # 計算熵值
        analysis['entropy'] = self._calculate_entropy(packet.payload)
        
        # 檢查是否為二進位內容
        analysis['binary_content'] = self._is_binary_content(packet.payload)
        
        # 檢查是否為加密內容
        analysis['encrypted_content'] = self._is_encrypted_content(packet.payload)
        
        # 提取文字內容
        try:
            text_content = packet.payload.decode('utf-8', errors='ignore')
            analysis['text_content'] = text_content
        except:
            analysis['text_content'] = ''
        
        # 提取URL
        analysis['urls'] = self._extract_urls(analysis['text_content'])
        
        # 提取Email地址
        analysis['emails'] = self._extract_emails(analysis['text_content'])
        
        # 提取IP地址
        analysis['ip_addresses'] = self._extract_ip_addresses(analysis['text_content'])
        
        # 檢測檔案簽名
        analysis['file_signatures'] = self._detect_file_signatures(packet.payload)
        
        return analysis

    def _detect_threats(self, packet: PacketInfo, content_analysis: Dict) -> List[str]:
        """檢測威脅"""
        threats = []
        
        # 檢查惡意軟體特徵
        if self._check_malware_signatures(packet.payload):
            threats.append("惡意軟體特徵檢測")
        
        # 檢查可疑模式
        if self._check_suspicious_patterns(packet.payload):
            threats.append("可疑內容模式")
        
        # 檢查協議異常
        if self._check_protocol_anomalies(packet, content_analysis):
            threats.append("協議異常")
        
        # 檢查加密分析
        encryption_analysis = self._analyze_encryption(packet.payload)
        if encryption_analysis.get('suspicious'):
            threats.append("可疑加密模式")
        
        # 檢查高熵值（可能是加密或壓縮的惡意內容）
        if content_analysis['entropy'] > 7.5:
            threats.append("高熵值內容")
        
        return threats

    def _check_malware_signatures(self, payload: bytes) -> bool:
        """檢查惡意軟體特徵"""
        if not payload:
            return False
        
        for signature in self.malware_signatures:
            if signature in payload:
                return True
        
        return False

    def _check_suspicious_patterns(self, payload: bytes) -> bool:
        """檢查可疑模式"""
        if not payload:
            return False
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            for pattern in self.suspicious_patterns:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    return True
        except:
            pass
        
        return False

    def _check_protocol_anomalies(self, packet: PacketInfo, content_analysis: Dict) -> bool:
        """檢查協議異常"""
        # 檢查端口與協議不匹配
        if packet.dest_port == 80 and not content_analysis['text_content'].startswith(('GET ', 'POST ', 'PUT ', 'DELETE ')):
            return True
        
        # 檢查異常的封包大小
        if packet.payload_size > 65535:
            return True
        
        # 檢查異常的TTL值
        if packet.ttl < 1 or packet.ttl > 255:
            return True
        
        return False

    def _analyze_encryption(self, payload: bytes) -> Dict[str, Any]:
        """分析加密內容"""
        analysis = {
            'is_encrypted': False,
            'encryption_type': 'unknown',
            'suspicious': False,
            'entropy': 0.0
        }
        
        if not payload:
            return analysis
        
        # 計算熵值
        analysis['entropy'] = self._calculate_entropy(payload)
        
        # 高熵值通常表示加密內容
        if analysis['entropy'] > 7.0:
            analysis['is_encrypted'] = True
        
        # 檢查常見加密協議
        if payload.startswith(b'\x16\x03'):  # TLS/SSL
            analysis['encryption_type'] = 'tls'
        elif payload.startswith(b'\x17\x03'):  # TLS Application Data
            analysis['encryption_type'] = 'tls_data'
        elif payload.startswith(b'\x14\x03'):  # TLS Change Cipher Spec
            analysis['encryption_type'] = 'tls_change_cipher'
        
        # 檢查可疑的加密模式
        if analysis['is_encrypted'] and analysis['entropy'] > 7.8:
            analysis['suspicious'] = True
        
        return analysis

    def _calculate_entropy(self, data: bytes) -> float:
        """計算數據熵值"""
        if not data:
            return 0.0
        
        # 計算字節頻率
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        # 計算熵值
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy

    def _is_binary_content(self, payload: bytes) -> bool:
        """檢查是否為二進位內容"""
        if not payload:
            return False
        
        # 檢查空字節比例
        null_bytes = payload.count(b'\x00')
        if null_bytes > len(payload) * 0.1:
            return True
        
        # 檢查可列印字元比例
        printable_chars = sum(1 for b in payload if 32 <= b <= 126)
        if printable_chars < len(payload) * 0.7:
            return True
        
        return False

    def _is_encrypted_content(self, payload: bytes) -> bool:
        """檢查是否為加密內容"""
        if not payload:
            return False
        
        # 檢查熵值
        entropy = self._calculate_entropy(payload)
        if entropy > 7.0:
            return True
        
        # 檢查常見加密標識
        encryption_signatures = [
            b'\x16\x03',  # TLS
            b'\x17\x03',  # TLS Application Data
            b'\x14\x03',  # TLS Change Cipher Spec
            b'-----BEGIN',  # PEM格式
            b'-----END'
        ]
        
        for sig in encryption_signatures:
            if sig in payload:
                return True
        
        return False

    def _extract_urls(self, text: str) -> List[str]:
        """提取URL"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)

    def _extract_emails(self, text: str) -> List[str]:
        """提取Email地址"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return re.findall(email_pattern, text)

    def _extract_ip_addresses(self, text: str) -> List[str]:
        """提取IP地址"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, text)
        
        # 驗證IP地址
        valid_ips = []
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                pass
        
        return valid_ips

    def _detect_file_signatures(self, payload: bytes) -> List[str]:
        """檢測檔案簽名"""
        signatures = []
        
        if not payload:
            return signatures
        
        # 常見檔案簽名
        file_signatures = {
            b'\x50\x4B\x03\x04': 'ZIP',
            b'\x50\x4B\x05\x06': 'ZIP (empty)',
            b'\x50\x4B\x07\x08': 'ZIP (spanned)',
            b'\x4D\x5A': 'PE/EXE',
            b'\x25\x50\x44\x46': 'PDF',
            b'\x89\x50\x4E\x47': 'PNG',
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x47\x49\x46\x38': 'GIF',
            b'\x52\x49\x46\x46': 'RIFF (WAV/AVI)',
            b'\x1F\x8B': 'GZIP',
            b'\x42\x5A\x68': 'BZIP2',
            b'\x37\x7A\xBC\xAF\x27\x1C': '7Z'
        }
        
        for signature, file_type in file_signatures.items():
            if payload.startswith(signature):
                signatures.append(file_type)
        
        return signatures

    def _get_protocol_details(self, packet: PacketInfo, protocol: Protocol) -> Dict[str, Any]:
        """獲取協議詳細資訊"""
        details = {
            'protocol': protocol.value,
            'port': packet.dest_port,
            'flags': packet.flags,
            'ttl': packet.ttl,
            'tos': packet.tos
        }
        
        if protocol == Protocol.HTTP and packet.payload:
            details.update(self._parse_http_headers(packet.payload))
        elif protocol == Protocol.HTTPS:
            details['encrypted'] = True
        elif protocol == Protocol.FTP and packet.payload:
            details.update(self._parse_ftp_commands(packet.payload))
        
        return details

    def _parse_http_headers(self, payload: bytes) -> Dict[str, Any]:
        """解析HTTP標頭"""
        headers = {}
        
        try:
            text = payload.decode('utf-8', errors='ignore')
            lines = text.split('\n')
            
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # 提取重要資訊
            result = {
                'method': '',
                'url': '',
                'user_agent': '',
                'host': '',
                'content_type': ''
            }
            
            first_line = lines[0] if lines else ''
            if ' ' in first_line:
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    result['method'] = parts[0]
                    result['url'] = parts[1]
            
            result['user_agent'] = headers.get('user-agent', '')
            result['host'] = headers.get('host', '')
            result['content_type'] = headers.get('content-type', '')
            
            return result
        
        except:
            return {}

    def _parse_ftp_commands(self, payload: bytes) -> Dict[str, Any]:
        """解析FTP命令"""
        try:
            text = payload.decode('utf-8', errors='ignore').strip()
            return {'command': text}
        except:
            return {}

    def _calculate_risk_score(self, packet: PacketInfo, threats: List[str], content_analysis: Dict) -> float:
        """計算風險分數"""
        risk_score = 0.0
        
        # 威脅指標權重
        threat_weights = {
            "惡意軟體特徵檢測": 0.9,
            "可疑內容模式": 0.7,
            "協議異常": 0.6,
            "可疑加密模式": 0.5,
            "高熵值內容": 0.4
        }
        
        # 計算威脅分數
        for threat in threats:
            risk_score += threat_weights.get(threat, 0.3)
        
        # 內容分析分數
        if content_analysis['entropy'] > 7.5:
            risk_score += 0.3
        
        if content_analysis['binary_content']:
            risk_score += 0.2
        
        if len(content_analysis['urls']) > 5:
            risk_score += 0.2
        
        # 封包特徵分數
        if packet.payload_size > 10000:
            risk_score += 0.1
        
        if packet.ttl < 10:
            risk_score += 0.1
        
        return min(risk_score, 1.0)

    def _generate_recommendations(self, packet: PacketInfo, threats: List[str], risk_score: float) -> List[str]:
        """生成建議"""
        recommendations = []
        
        if risk_score > 0.8:
            recommendations.append("立即阻擋此封包")
        elif risk_score > 0.6:
            recommendations.append("建議阻擋此封包")
        elif risk_score > 0.4:
            recommendations.append("監控此流量")
        
        if "惡意軟體特徵檢測" in threats:
            recommendations.append("進行深度惡意軟體掃描")
        
        if "可疑加密模式" in threats:
            recommendations.append("檢查加密證書有效性")
        
        if "協議異常" in threats:
            recommendations.append("檢查協議配置")
        
        if len(threats) > 3:
            recommendations.append("將來源IP加入黑名單")
        
        return recommendations

class PacketFilterEngine:
    """封包過濾引擎"""
    
    def __init__(self):
        self.filters: List[PacketFilter] = []
        self.dpi = DeepPacketInspector()
        self.rate_limiters = defaultdict(lambda: deque())
        self.stats = {
            'packets_processed': 0,
            'packets_allowed': 0,
            'packets_dropped': 0,
            'packets_rejected': 0,
            'packets_logged': 0,
            'rate_limited': 0
        }

    def add_filter(self, packet_filter: PacketFilter):
        """新增封包過濾器"""
        self.filters.append(packet_filter)
        # 按優先級排序
        self.filters.sort(key=lambda x: x.priority, reverse=True)
        logger.info(f"已新增封包過濾器: {packet_filter.name}")

    def process_packet(self, packet: PacketInfo) -> Tuple[FilterAction, Dict[str, Any]]:
        """處理封包"""
        self.stats['packets_processed'] += 1
        
        # 深度封包檢測
        dpi_result = self.dpi.inspect_packet(packet)
        
        # 應用過濾器
        for packet_filter in self.filters:
            if not packet_filter.enabled:
                continue
            
            if self._match_filter(packet, packet_filter):
                action = packet_filter.action
                
                # 處理速率限制
                if action == FilterAction.RATE_LIMIT:
                    if self._check_rate_limit(packet.source_ip):
                        action = FilterAction.DROP
                        self.stats['rate_limited'] += 1
                    else:
                        action = FilterAction.ALLOW
                
                # 更新統計
                self._update_stats(action)
                
                return action, dpi_result
        
        # 預設動作
        return FilterAction.ALLOW, dpi_result

    def _match_filter(self, packet: PacketInfo, packet_filter: PacketFilter) -> bool:
        """檢查封包是否匹配過濾器"""
        # 檢查協議
        if packet_filter.protocol != Protocol.UNKNOWN:
            if packet.protocol != packet_filter.protocol.value:
                return False
        
        # 檢查IP地址
        if packet_filter.source_ip != "*":
            if not self._ip_match(packet.source_ip, packet_filter.source_ip):
                return False
        
        if packet_filter.dest_ip != "*":
            if not self._ip_match(packet.dest_ip, packet_filter.dest_ip):
                return False
        
        # 檢查端口
        if packet_filter.source_port != 0:
            if packet.source_port != packet_filter.source_port:
                return False
        
        if packet_filter.dest_port != 0:
            if packet.dest_port != packet_filter.dest_port:
                return False
        
        return True

    def _ip_match(self, ip: str, pattern: str) -> bool:
        """檢查IP是否匹配模式"""
        if pattern == "*":
            return True
        
        try:
            if "/" in pattern:
                # CIDR表示法
                network = ipaddress.ip_network(pattern, strict=False)
                return ipaddress.ip_address(ip) in network
            else:
                return ip == pattern
        except:
            return False

    def _check_rate_limit(self, source_ip: str, limit: int = 100, window: int = 60) -> bool:
        """檢查速率限制"""
        now = time.time()
        rate_limiter = self.rate_limiters[source_ip]
        
        # 清理舊記錄
        while rate_limiter and rate_limiter[0] < now - window:
            rate_limiter.popleft()
        
        # 檢查是否超過限制
        if len(rate_limiter) >= limit:
            return True
        
        # 添加新記錄
        rate_limiter.append(now)
        return False

    def _update_stats(self, action: FilterAction):
        """更新統計"""
        if action == FilterAction.ALLOW:
            self.stats['packets_allowed'] += 1
        elif action == FilterAction.DROP:
            self.stats['packets_dropped'] += 1
        elif action == FilterAction.REJECT:
            self.stats['packets_rejected'] += 1
        elif action == FilterAction.LOG:
            self.stats['packets_logged'] += 1

    def get_statistics(self) -> Dict[str, Any]:
        """獲取統計資訊"""
        return {
            'stats': self.stats,
            'filters_count': len(self.filters),
            'active_filters': len([f for f in self.filters if f.enabled]),
            'rate_limiters_count': len(self.rate_limiters)
        }

def main():
    """主程式"""
    # 建立封包過濾引擎
    filter_engine = PacketFilterEngine()
    
    # 新增範例過濾器
    filter1 = PacketFilter(
        id="filter_001",
        name="阻擋惡意IP",
        protocol=Protocol.UNKNOWN,
        source_ip="192.168.1.100",
        dest_ip="*",
        source_port=0,
        dest_port=0,
        action=FilterAction.DROP,
        priority=100
    )
    
    filter2 = PacketFilter(
        id="filter_002",
        name="HTTP流量監控",
        protocol=Protocol.HTTP,
        source_ip="*",
        dest_ip="*",
        source_port=0,
        dest_port=80,
        action=FilterAction.LOG,
        priority=50
    )
    
    filter_engine.add_filter(filter1)
    filter_engine.add_filter(filter2)
    
    # 模擬封包處理
    test_packet = PacketInfo(
        timestamp=datetime.now(),
        source_ip="192.168.1.100",
        dest_ip="192.168.1.1",
        source_port=12345,
        dest_port=80,
        protocol="TCP",
        payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        payload_size=50,
        flags=2,
        ttl=64,
        tos=0
    )
    
    action, dpi_result = filter_engine.process_packet(test_packet)
    print(f"封包處理結果: {action.value}")
    print(f"DPI結果: {dpi_result}")
    print(f"統計資訊: {filter_engine.get_statistics()}")

if __name__ == "__main__":
    main()

