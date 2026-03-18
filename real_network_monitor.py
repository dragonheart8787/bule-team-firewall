#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實網路監控系統
Real Network Monitoring System
"""

import socket
import struct
import threading
import time
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import psutil
import subprocess
import os
import sys

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealNetworkMonitor:
    """真實網路監控系統"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.monitor_threads = []
        self.captured_packets = []
        self.network_stats = {}
        self.suspicious_activities = []
        
        # 初始化監控介面
        self.interfaces = self._get_network_interfaces()
        self.monitor_interface = config.get('monitor_interface', 'any')
        
        # 初始化統計數據
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'suspicious_packets': 0,
            'blocked_connections': 0
        }
        
        logger.info("真實網路監控系統初始化完成")
    
    def _get_network_interfaces(self) -> List[str]:
        """獲取網路介面列表"""
        try:
            interfaces = []
            for interface, addrs in psutil.net_if_addrs().items():
                if interface != 'lo':  # 排除回環介面
                    interfaces.append(interface)
            return interfaces
        except Exception as e:
            logger.error(f"獲取網路介面錯誤: {e}")
            return ['eth0', 'wlan0']  # 預設介面
    
    def start_monitoring(self) -> Dict[str, Any]:
        """開始網路監控"""
        try:
            if self.running:
                return {'success': False, 'error': '監控已在運行中'}
            
            self.running = True
            
            # 啟動多個監控線程
            self._start_packet_capture()
            self._start_connection_monitoring()
            self._start_traffic_analysis()
            self._start_intrusion_detection()
            self._start_ddos_detection()
            
            logger.info("真實網路監控已啟動")
            return {'success': True, 'message': '網路監控已啟動'}
            
        except Exception as e:
            logger.error(f"啟動監控錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _start_packet_capture(self):
        """啟動封包捕獲"""
        def capture_packets():
            try:
                # 使用原始套接字捕獲封包
                if os.name == 'nt':  # Windows
                    # Windows 需要管理員權限
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                    sock.bind(('0.0.0.0', 0))
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                else:  # Linux/Unix
                    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                
                logger.info("封包捕獲已啟動")
                
                while self.running:
                    try:
                        packet, addr = sock.recvfrom(65565)
                        self._process_packet(packet, addr)
                    except Exception as e:
                        if self.running:
                            logger.error(f"封包捕獲錯誤: {e}")
                        break
                
                sock.close()
                
            except PermissionError:
                logger.error("需要管理員權限才能捕獲封包")
            except Exception as e:
                logger.error(f"封包捕獲初始化錯誤: {e}")
        
        thread = threading.Thread(target=capture_packets, daemon=True)
        thread.start()
        self.monitor_threads.append(thread)
    
    def _process_packet(self, packet: bytes, addr: tuple):
        """處理捕獲的封包"""
        try:
            self.stats['total_packets'] += 1
            
            # 解析 IP 標頭
            ip_header = packet[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            
            ttl = iph[5]
            protocol = iph[6]
            source_ip = socket.inet_ntoa(iph[8])
            dest_ip = socket.inet_ntoa(iph[9])
            
            # 解析傳輸層協議
            if protocol == 6:  # TCP
                self.stats['tcp_packets'] += 1
                self._analyze_tcp_packet(packet, iph_length, source_ip, dest_ip)
            elif protocol == 17:  # UDP
                self.stats['udp_packets'] += 1
                self._analyze_udp_packet(packet, iph_length, source_ip, dest_ip)
            elif protocol == 1:  # ICMP
                self.stats['icmp_packets'] += 1
                self._analyze_icmp_packet(packet, iph_length, source_ip, dest_ip)
            
            # 檢查可疑活動
            self._check_suspicious_activity(source_ip, dest_ip, protocol, packet)
            
        except Exception as e:
            logger.error(f"封包處理錯誤: {e}")
    
    def _analyze_tcp_packet(self, packet: bytes, iph_length: int, source_ip: str, dest_ip: str):
        """分析 TCP 封包"""
        try:
            tcp_header = packet[iph_length:iph_length + 20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            
            source_port = tcph[0]
            dest_port = tcph[1]
            flags = tcph[5]
            
            # 檢查常見的攻擊端口
            suspicious_ports = [22, 23, 80, 443, 3389, 5900, 8080, 8443]
            if dest_port in suspicious_ports:
                self._log_suspicious_connection(source_ip, dest_ip, source_port, dest_port, 'TCP')
            
            # 檢查 SYN 洪水攻擊
            if flags & 0x02:  # SYN flag
                self._check_syn_flood(source_ip, dest_ip, dest_port)
                
        except Exception as e:
            logger.error(f"TCP 封包分析錯誤: {e}")
    
    def _analyze_udp_packet(self, packet: bytes, iph_length: int, source_ip: str, dest_ip: str):
        """分析 UDP 封包"""
        try:
            udp_header = packet[iph_length:iph_length + 8]
            udph = struct.unpack('!HHHH', udp_header)
            
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            
            # 檢查 DNS 隧道
            if dest_port == 53:
                self._check_dns_tunneling(packet, iph_length + 8, source_ip, dest_ip)
            
            # 檢查可疑的 UDP 流量
            if length > 1024:  # 大於 1KB 的 UDP 封包
                self._log_suspicious_connection(source_ip, dest_ip, source_port, dest_port, 'UDP')
                
        except Exception as e:
            logger.error(f"UDP 封包分析錯誤: {e}")
    
    def _analyze_icmp_packet(self, packet: bytes, iph_length: int, source_ip: str, dest_ip: str):
        """分析 ICMP 封包"""
        try:
            icmp_header = packet[iph_length:iph_length + 8]
            icmph = struct.unpack('!BBHHH', icmp_header)
            
            icmp_type = icmph[0]
            icmp_code = icmph[1]
            
            # 檢查 ICMP 隧道
            if icmp_type == 0 or icmp_type == 8:  # Echo Request/Reply
                data_length = len(packet) - iph_length - 8
                if data_length > 32:  # 異常大的 ICMP 封包
                    self._log_suspicious_activity({
                        'type': 'ICMP_TUNNELING',
                        'source_ip': source_ip,
                        'dest_ip': dest_ip,
                        'icmp_type': icmp_type,
                        'data_length': data_length,
                        'timestamp': datetime.now().isoformat()
                    })
                    
        except Exception as e:
            logger.error(f"ICMP 封包分析錯誤: {e}")
    
    def _start_connection_monitoring(self):
        """啟動連接監控"""
        def monitor_connections():
            logger.info("連接監控已啟動")
            
            while self.running:
                try:
                    # 獲取當前網路連接
                    connections = psutil.net_connections(kind='inet')
                    
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            self._analyze_connection(conn)
                    
                    time.sleep(1)  # 每秒檢查一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"連接監控錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_connections, daemon=True)
        thread.start()
        self.monitor_threads.append(thread)
    
    def _analyze_connection(self, conn):
        """分析網路連接"""
        try:
            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "unknown"
            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "unknown"
            
            # 檢查可疑的連接
            if conn.raddr and conn.raddr.port in [22, 23, 3389, 5900]:
                self._log_suspicious_connection(
                    conn.raddr.ip, 
                    conn.laddr.ip, 
                    conn.raddr.port, 
                    conn.laddr.port, 
                    conn.type
                )
            
            # 檢查大量連接
            self._check_connection_flood(conn.raddr.ip if conn.raddr else None)
            
        except Exception as e:
            logger.error(f"連接分析錯誤: {e}")
    
    def _start_traffic_analysis(self):
        """啟動流量分析"""
        def analyze_traffic():
            logger.info("流量分析已啟動")
            
            while self.running:
                try:
                    # 獲取網路統計
                    net_io = psutil.net_io_counters(pernic=True)
                    
                    for interface, stats in net_io.items():
                        self._analyze_interface_traffic(interface, stats)
                    
                    time.sleep(5)  # 每5秒分析一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"流量分析錯誤: {e}")
                    break
        
        thread = threading.Thread(target=analyze_traffic, daemon=True)
        thread.start()
        self.monitor_threads.append(thread)
    
    def _analyze_interface_traffic(self, interface: str, stats):
        """分析介面流量"""
        try:
            # 計算流量速率
            if interface in self.network_stats:
                prev_stats = self.network_stats[interface]
                bytes_sent_rate = stats.bytes_sent - prev_stats['bytes_sent']
                bytes_recv_rate = stats.bytes_recv - prev_stats['bytes_recv']
                
                # 檢查異常流量
                if bytes_sent_rate > 100 * 1024 * 1024:  # 100MB/s
                    self._log_suspicious_activity({
                        'type': 'HIGH_OUTBOUND_TRAFFIC',
                        'interface': interface,
                        'bytes_sent_rate': bytes_sent_rate,
                        'timestamp': datetime.now().isoformat()
                    })
                
                if bytes_recv_rate > 100 * 1024 * 1024:  # 100MB/s
                    self._log_suspicious_activity({
                        'type': 'HIGH_INBOUND_TRAFFIC',
                        'interface': interface,
                        'bytes_recv_rate': bytes_recv_rate,
                        'timestamp': datetime.now().isoformat()
                    })
            
            # 更新統計
            self.network_stats[interface] = {
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv,
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"介面流量分析錯誤: {e}")
    
    def _start_intrusion_detection(self):
        """啟動入侵檢測"""
        def detect_intrusions():
            logger.info("入侵檢測已啟動")
            
            while self.running:
                try:
                    # 檢查端口掃描
                    self._detect_port_scanning()
                    
                    # 檢查暴力破解
                    self._detect_brute_force()
                    
                    # 檢查異常進程
                    self._detect_suspicious_processes()
                    
                    time.sleep(10)  # 每10秒檢查一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"入侵檢測錯誤: {e}")
                    break
        
        thread = threading.Thread(target=detect_intrusions, daemon=True)
        thread.start()
        self.monitor_threads.append(thread)
    
    def _detect_port_scanning(self):
        """檢測端口掃描"""
        try:
            # 獲取當前連接
            connections = psutil.net_connections(kind='inet')
            
            # 按遠端 IP 分組
            ip_connections = {}
            for conn in connections:
                if conn.raddr:
                    ip = conn.raddr.ip
                    if ip not in ip_connections:
                        ip_connections[ip] = []
                    ip_connections[ip].append(conn.raddr.port)
            
            # 檢查每個 IP 的連接數
            for ip, ports in ip_connections.items():
                if len(ports) > 10:  # 超過10個端口連接
                    self._log_suspicious_activity({
                        'type': 'PORT_SCANNING',
                        'source_ip': ip,
                        'port_count': len(ports),
                        'ports': ports[:20],  # 只記錄前20個端口
                        'timestamp': datetime.now().isoformat()
                    })
                    
        except Exception as e:
            logger.error(f"端口掃描檢測錯誤: {e}")
    
    def _detect_brute_force(self):
        """檢測暴力破解"""
        try:
            # 檢查 SSH 連接失敗
            if os.name != 'nt':  # Linux/Unix 系統
                try:
                    result = subprocess.run(['journalctl', '-u', 'ssh', '--since', '1 minute ago'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        failed_attempts = [line for line in lines if 'Failed password' in line]
                        
                        if len(failed_attempts) > 5:
                            self._log_suspicious_activity({
                                'type': 'BRUTE_FORCE_SSH',
                                'failed_attempts': len(failed_attempts),
                                'timestamp': datetime.now().isoformat()
                            })
                except Exception:
                    pass  # 忽略 journalctl 錯誤
                    
        except Exception as e:
            logger.error(f"暴力破解檢測錯誤: {e}")
    
    def _detect_suspicious_processes(self):
        """檢測可疑進程"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'connections']):
                try:
                    proc_info = proc.info
                    name = proc_info['name'].lower()
                    cmdline = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
                    
                    # 檢查可疑進程名稱
                    suspicious_names = ['nc', 'netcat', 'ncat', 'socat', 'wget', 'curl', 'powershell']
                    if any(susp in name for susp in suspicious_names):
                        self._log_suspicious_activity({
                            'type': 'SUSPICIOUS_PROCESS',
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': cmdline,
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    # 檢查網路連接
                    if proc_info['connections']:
                        for conn in proc_info['connections']:
                            if conn.raddr and conn.raddr.port in [4444, 8080, 9999]:
                                self._log_suspicious_activity({
                                    'type': 'SUSPICIOUS_CONNECTION',
                                    'pid': proc_info['pid'],
                                    'name': proc_info['name'],
                                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                                    'timestamp': datetime.now().isoformat()
                                })
                                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"可疑進程檢測錯誤: {e}")
    
    def _start_ddos_detection(self):
        """啟動 DDoS 檢測"""
        def detect_ddos():
            logger.info("DDoS 檢測已啟動")
            
            while self.running:
                try:
                    # 檢查 SYN 洪水
                    self._check_syn_flood_global()
                    
                    # 檢查 UDP 洪水
                    self._check_udp_flood()
                    
                    # 檢查 ICMP 洪水
                    self._check_icmp_flood()
                    
                    time.sleep(5)  # 每5秒檢查一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"DDoS 檢測錯誤: {e}")
                    break
        
        thread = threading.Thread(target=detect_ddos, daemon=True)
        thread.start()
        self.monitor_threads.append(thread)
    
    def _check_syn_flood_global(self):
        """檢查全域 SYN 洪水"""
        try:
            # 獲取 TCP 連接統計
            connections = psutil.net_connections(kind='tcp')
            
            # 統計 SYN 狀態連接
            syn_connections = [conn for conn in connections if conn.status == 'SYN_SENT']
            
            if len(syn_connections) > 100:  # 超過100個 SYN 連接
                self._log_suspicious_activity({
                    'type': 'SYN_FLOOD',
                    'syn_connections': len(syn_connections),
                    'timestamp': datetime.now().isoformat()
                })
                
        except Exception as e:
            logger.error(f"SYN 洪水檢測錯誤: {e}")
    
    def _check_udp_flood(self):
        """檢查 UDP 洪水"""
        try:
            # 獲取 UDP 連接
            connections = psutil.net_connections(kind='udp')
            
            if len(connections) > 1000:  # 超過1000個 UDP 連接
                self._log_suspicious_activity({
                    'type': 'UDP_FLOOD',
                    'udp_connections': len(connections),
                    'timestamp': datetime.now().isoformat()
                })
                
        except Exception as e:
            logger.error(f"UDP 洪水檢測錯誤: {e}")
    
    def _check_icmp_flood(self):
        """檢查 ICMP 洪水"""
        try:
            # 使用 netstat 檢查 ICMP 統計
            if os.name != 'nt':
                try:
                    result = subprocess.run(['netstat', '-s'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        icmp_lines = [line for line in lines if 'ICMP' in line]
                        
                        # 簡單的 ICMP 洪水檢測
                        if len(icmp_lines) > 10:
                            self._log_suspicious_activity({
                                'type': 'ICMP_FLOOD',
                                'icmp_activity': len(icmp_lines),
                                'timestamp': datetime.now().isoformat()
                            })
                except Exception:
                    pass
                    
        except Exception as e:
            logger.error(f"ICMP 洪水檢測錯誤: {e}")
    
    def _check_suspicious_activity(self, source_ip: str, dest_ip: str, protocol: int, packet: bytes):
        """檢查可疑活動"""
        try:
            # 檢查已知的惡意 IP
            malicious_ips = [
                '192.168.1.100',  # 示例惡意 IP
                '10.0.0.100',     # 示例惡意 IP
            ]
            
            if source_ip in malicious_ips or dest_ip in malicious_ips:
                self._log_suspicious_activity({
                    'type': 'MALICIOUS_IP',
                    'source_ip': source_ip,
                    'dest_ip': dest_ip,
                    'protocol': protocol,
                    'timestamp': datetime.now().isoformat()
                })
            
            # 檢查異常大的封包
            if len(packet) > 1500:  # 超過 MTU
                self._log_suspicious_activity({
                    'type': 'OVERSIZED_PACKET',
                    'source_ip': source_ip,
                    'dest_ip': dest_ip,
                    'packet_size': len(packet),
                    'timestamp': datetime.now().isoformat()
                })
                
        except Exception as e:
            logger.error(f"可疑活動檢查錯誤: {e}")
    
    def _check_syn_flood(self, source_ip: str, dest_ip: str, dest_port: int):
        """檢查 SYN 洪水攻擊"""
        try:
            # 簡單的 SYN 洪水檢測
            key = f"{source_ip}:{dest_ip}:{dest_port}"
            if not hasattr(self, '_syn_connections'):
                self._syn_connections = {}
            
            if key not in self._syn_connections:
                self._syn_connections[key] = []
            
            self._syn_connections[key].append(time.time())
            
            # 清理舊記錄
            current_time = time.time()
            self._syn_connections[key] = [
                timestamp for timestamp in self._syn_connections[key]
                if current_time - timestamp < 60  # 保留1分鐘內的記錄
            ]
            
            # 檢查是否超過閾值
            if len(self._syn_connections[key]) > 10:  # 1分鐘內超過10個 SYN
                self._log_suspicious_activity({
                    'type': 'SYN_FLOOD_ATTACK',
                    'source_ip': source_ip,
                    'dest_ip': dest_ip,
                    'dest_port': dest_port,
                    'syn_count': len(self._syn_connections[key]),
                    'timestamp': datetime.now().isoformat()
                })
                
        except Exception as e:
            logger.error(f"SYN 洪水檢查錯誤: {e}")
    
    def _check_dns_tunneling(self, packet: bytes, dns_offset: int, source_ip: str, dest_ip: str):
        """檢查 DNS 隧道"""
        try:
            if len(packet) > dns_offset + 12:
                dns_data = packet[dns_offset:]
                
                # 檢查 DNS 查詢長度
                if len(dns_data) > 100:  # 異常長的 DNS 查詢
                    self._log_suspicious_activity({
                        'type': 'DNS_TUNNELING',
                        'source_ip': source_ip,
                        'dest_ip': dest_ip,
                        'dns_length': len(dns_data),
                        'timestamp': datetime.now().isoformat()
                    })
                    
        except Exception as e:
            logger.error(f"DNS 隧道檢查錯誤: {e}")
    
    def _check_connection_flood(self, ip: str):
        """檢查連接洪水"""
        try:
            if not ip:
                return
            
            if not hasattr(self, '_connection_counts'):
                self._connection_counts = {}
            
            if ip not in self._connection_counts:
                self._connection_counts[ip] = []
            
            self._connection_counts[ip].append(time.time())
            
            # 清理舊記錄
            current_time = time.time()
            self._connection_counts[ip] = [
                timestamp for timestamp in self._connection_counts[ip]
                if current_time - timestamp < 60  # 保留1分鐘內的記錄
            ]
            
            # 檢查是否超過閾值
            if len(self._connection_counts[ip]) > 50:  # 1分鐘內超過50個連接
                self._log_suspicious_activity({
                    'type': 'CONNECTION_FLOOD',
                    'source_ip': ip,
                    'connection_count': len(self._connection_counts[ip]),
                    'timestamp': datetime.now().isoformat()
                })
                
        except Exception as e:
            logger.error(f"連接洪水檢查錯誤: {e}")
    
    def _log_suspicious_connection(self, source_ip: str, dest_ip: str, source_port: int, dest_port: int, protocol: str):
        """記錄可疑連接"""
        try:
            activity = {
                'type': 'SUSPICIOUS_CONNECTION',
                'source_ip': source_ip,
                'dest_ip': dest_ip,
                'source_port': source_port,
                'dest_port': dest_port,
                'protocol': protocol,
                'timestamp': datetime.now().isoformat()
            }
            
            self.suspicious_activities.append(activity)
            self.stats['suspicious_packets'] += 1
            
            logger.warning(f"可疑連接: {source_ip}:{source_port} -> {dest_ip}:{dest_port} ({protocol})")
            
        except Exception as e:
            logger.error(f"記錄可疑連接錯誤: {e}")
    
    def _log_suspicious_activity(self, activity: Dict[str, Any]):
        """記錄可疑活動"""
        try:
            self.suspicious_activities.append(activity)
            self.stats['suspicious_packets'] += 1
            
            logger.warning(f"可疑活動: {activity['type']} - {activity}")
            
        except Exception as e:
            logger.error(f"記錄可疑活動錯誤: {e}")
    
    def stop_monitoring(self) -> Dict[str, Any]:
        """停止監控"""
        try:
            self.running = False
            
            # 等待所有線程結束
            for thread in self.monitor_threads:
                thread.join(timeout=5)
            
            self.monitor_threads.clear()
            
            logger.info("網路監控已停止")
            return {'success': True, 'message': '監控已停止'}
            
        except Exception as e:
            logger.error(f"停止監控錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """獲取監控狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'interfaces': self.interfaces,
                'monitor_interface': self.monitor_interface,
                'stats': self.stats,
                'suspicious_activities_count': len(self.suspicious_activities),
                'recent_activities': self.suspicious_activities[-10:] if self.suspicious_activities else []
            }
        except Exception as e:
            logger.error(f"獲取監控狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_detailed_report(self) -> Dict[str, Any]:
        """獲取詳細報告"""
        try:
            return {
                'success': True,
                'monitoring_duration': time.time() - getattr(self, 'start_time', time.time()),
                'total_packets_analyzed': self.stats['total_packets'],
                'suspicious_activities': self.suspicious_activities,
                'network_statistics': self.network_stats,
                'threat_summary': {
                    'total_threats': len(self.suspicious_activities),
                    'threat_types': list(set(activity['type'] for activity in self.suspicious_activities)),
                    'top_source_ips': self._get_top_source_ips(),
                    'top_dest_ports': self._get_top_dest_ports()
                }
            }
        except Exception as e:
            logger.error(f"獲取詳細報告錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _get_top_source_ips(self) -> List[Dict[str, Any]]:
        """獲取最活躍的來源 IP"""
        try:
            ip_counts = {}
            for activity in self.suspicious_activities:
                if 'source_ip' in activity:
                    ip = activity['source_ip']
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
            return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        except Exception as e:
            logger.error(f"獲取頂級來源 IP 錯誤: {e}")
            return []
    
    def _get_top_dest_ports(self) -> List[Dict[str, Any]]:
        """獲取最活躍的目的端口"""
        try:
            port_counts = {}
            for activity in self.suspicious_activities:
                if 'dest_port' in activity:
                    port = activity['dest_port']
                    port_counts[port] = port_counts.get(port, 0) + 1
            
            return sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        except Exception as e:
            logger.error(f"獲取頂級目的端口錯誤: {e}")
            return []


def main():
    """主函數"""
    config = {
        'monitor_interface': 'any',
        'log_level': 'INFO'
    }
    
    monitor = RealNetworkMonitor(config)
    
    try:
        # 啟動監控
        result = monitor.start_monitoring()
        if result['success']:
            print("✅ 真實網路監控系統已啟動")
            print("按 Ctrl+C 停止監控")
            
            # 持續運行
            while True:
                time.sleep(1)
        else:
            print(f"❌ 啟動失敗: {result['error']}")
            
    except KeyboardInterrupt:
        print("\n🛑 正在停止監控...")
        monitor.stop_monitoring()
        print("✅ 監控已停止")
    except Exception as e:
        print(f"❌ 系統錯誤: {e}")


if __name__ == "__main__":
    main()

