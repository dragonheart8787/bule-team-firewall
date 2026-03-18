#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級工控/IoT防禦系統
實作 Modbus、DNP3、CAN Bus 監控、OT/SCADA 專用防禦
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
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

# 設定日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class OTProtocol(Enum):
    """OT協議類型枚舉"""
    MODBUS = "modbus"
    DNP3 = "dnp3"
    CAN_BUS = "can_bus"
    PROFINET = "profinet"
    OPC_UA = "opc_ua"
    IEC_61850 = "iec_61850"
    BACNET = "bacnet"
    ETHERNET_IP = "ethernet_ip"

class DeviceType(Enum):
    """裝置類型枚舉"""
    PLC = "plc"
    HMI = "hmi"
    SCADA = "scada"
    RTU = "rtu"
    IED = "ied"
    SENSOR = "sensor"
    ACTUATOR = "actuator"
    GATEWAY = "gateway"
    UNKNOWN = "unknown"

class ThreatLevel(Enum):
    """威脅等級枚舉"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class OTDevice:
    """OT裝置資料結構"""
    id: str
    name: str
    ip_address: str
    mac_address: str
    device_type: DeviceType
    protocol: OTProtocol
    vendor: str
    model: str
    firmware_version: str
    last_seen: str
    status: str
    risk_score: float

@dataclass
class OTMessage:
    """OT訊息資料結構"""
    id: str
    timestamp: str
    source_ip: str
    dest_ip: str
    protocol: OTProtocol
    function_code: int
    data: bytes
    length: int
    suspicious: bool
    threat_level: ThreatLevel

@dataclass
class OTThreat:
    """OT威脅資料結構"""
    id: str
    threat_type: str
    source_device: str
    target_device: str
    protocol: OTProtocol
    description: str
    severity: ThreatLevel
    timestamp: str
    evidence: List[str]

class ModbusMonitor:
    """Modbus 監控器"""
    
    def __init__(self):
        self.modbus_functions = {
            0x01: "Read Coils",
            0x02: "Read Discrete Inputs",
            0x03: "Read Holding Registers",
            0x04: "Read Input Registers",
            0x05: "Write Single Coil",
            0x06: "Write Single Register",
            0x0F: "Write Multiple Coils",
            0x10: "Write Multiple Registers"
        }
        self.suspicious_functions = [0x05, 0x06, 0x0F, 0x10]  # 寫入操作
        self.known_devices = {}
    
    def parse_modbus_message(self, data: bytes, source_ip: str, dest_ip: str) -> Optional[OTMessage]:
        """解析 Modbus 訊息"""
        try:
            if len(data) < 8:  # Modbus TCP 最小長度
                return None
            
            # 解析 Modbus TCP 標頭
            transaction_id = struct.unpack('>H', data[0:2])[0]
            protocol_id = struct.unpack('>H', data[2:4])[0]
            length = struct.unpack('>H', data[4:6])[0]
            unit_id = data[6]
            function_code = data[7]
            
            # 檢查是否為 Modbus TCP
            if protocol_id != 0:
                return None
            
            # 檢查功能碼是否有效
            if function_code not in self.modbus_functions:
                return None
            
            # 判斷是否可疑
            suspicious = function_code in self.suspicious_functions
            
            # 確定威脅等級
            if function_code in self.suspicious_functions:
                threat_level = ThreatLevel.HIGH
            elif function_code in [0x01, 0x02, 0x03, 0x04]:
                threat_level = ThreatLevel.LOW
            else:
                threat_level = ThreatLevel.MEDIUM
            
            message = OTMessage(
                id=f"modbus_{int(time.time())}_{transaction_id}",
                timestamp=datetime.now().isoformat(),
                source_ip=source_ip,
                dest_ip=dest_ip,
                protocol=OTProtocol.MODBUS,
                function_code=function_code,
                data=data,
                length=len(data),
                suspicious=suspicious,
                threat_level=threat_level
            )
            
            return message
        except Exception as e:
            logger.error(f"解析 Modbus 訊息錯誤: {e}")
            return None
    
    def detect_modbus_anomalies(self, messages: List[OTMessage]) -> List[OTThreat]:
        """檢測 Modbus 異常"""
        try:
            threats = []
            
            # 檢測異常寫入操作
            write_operations = [msg for msg in messages if msg.function_code in self.suspicious_functions]
            
            for msg in write_operations:
                threat = OTThreat(
                    id=f"modbus_threat_{len(threats) + 1}",
                    threat_type="Modbus Write Operation",
                    source_device=msg.source_ip,
                    target_device=msg.dest_ip,
                    protocol=OTProtocol.MODBUS,
                    description=f"Suspicious Modbus write operation: {self.modbus_functions.get(msg.function_code, 'Unknown')}",
                    severity=ThreatLevel.HIGH,
                    timestamp=msg.timestamp,
                    evidence=[f"Function code: 0x{msg.function_code:02X}", f"Data length: {msg.length}"]
                )
                threats.append(threat)
            
            # 檢測頻繁讀取操作
            read_operations = [msg for msg in messages if msg.function_code in [0x01, 0x02, 0x03, 0x04]]
            if len(read_operations) > 100:  # 閾值
                threat = OTThreat(
                    id=f"modbus_threat_{len(threats) + 1}",
                    threat_type="Modbus Reconnaissance",
                    source_device="Multiple",
                    target_device="Multiple",
                    protocol=OTProtocol.MODBUS,
                    description="Excessive Modbus read operations detected",
                    severity=ThreatLevel.MEDIUM,
                    timestamp=datetime.now().isoformat(),
                    evidence=[f"Read operations count: {len(read_operations)}"]
                )
                threats.append(threat)
            
            return threats
        except Exception as e:
            logger.error(f"檢測 Modbus 異常錯誤: {e}")
            return []

class DNP3Monitor:
    """DNP3 監控器"""
    
    def __init__(self):
        self.dnp3_functions = {
            0x00: "Confirm",
            0x01: "Read",
            0x02: "Write",
            0x03: "Select",
            0x04: "Operate",
            0x05: "Direct Operate",
            0x06: "Direct Operate No Response",
            0x07: "Immediate Freeze",
            0x08: "Immediate Freeze No Response",
            0x09: "Freeze Clear",
            0x0A: "Freeze Clear No Response",
            0x0B: "Freeze At Time",
            0x0C: "Freeze At Time No Response",
            0x0D: "Cold Restart",
            0x0E: "Warm Restart",
            0x0F: "Initialize Data",
            0x10: "Initialize Application",
            0x11: "Start Application",
            0x12: "Stop Application",
            0x13: "Save Configuration",
            0x14: "Enable Unsolicited",
            0x15: "Disable Unsolicited",
            0x16: "Assign Class",
            0x17: "Delay Measurement",
            0x18: "Record Current Time",
            0x19: "Open File",
            0x1A: "Close File",
            0x1B: "Delete File",
            0x1C: "Get File Info",
            0x1D: "Authenticate",
            0x1E: "Abort",
            0x81: "Response",
            0x82: "Unsolicited Response"
        }
        self.critical_functions = [0x02, 0x04, 0x05, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13]
    
    def parse_dnp3_message(self, data: bytes, source_ip: str, dest_ip: str) -> Optional[OTMessage]:
        """解析 DNP3 訊息"""
        try:
            if len(data) < 10:  # DNP3 最小長度
                return None
            
            # 檢查 DNP3 標頭
            if data[0] != 0x05 or data[1] != 0x64:  # DNP3 起始字節
                return None
            
            # 解析 DNP3 標頭
            length = struct.unpack('>H', data[2:4])[0]
            control = data[4]
            destination = struct.unpack('>H', data[5:7])[0]
            source = struct.unpack('>H', data[7:9])[0]
            
            # 檢查是否有應用層數據
            if len(data) < 10 + length:
                return None
            
            # 解析應用層
            app_control = data[10]
            function_code = data[11]
            
            # 判斷是否可疑
            suspicious = function_code in self.critical_functions
            
            # 確定威脅等級
            if function_code in self.critical_functions:
                threat_level = ThreatLevel.CRITICAL
            elif function_code in [0x01, 0x81, 0x82]:
                threat_level = ThreatLevel.LOW
            else:
                threat_level = ThreatLevel.MEDIUM
            
            message = OTMessage(
                id=f"dnp3_{int(time.time())}_{source}_{destination}",
                timestamp=datetime.now().isoformat(),
                source_ip=source_ip,
                dest_ip=dest_ip,
                protocol=OTProtocol.DNP3,
                function_code=function_code,
                data=data,
                length=len(data),
                suspicious=suspicious,
                threat_level=threat_level
            )
            
            return message
        except Exception as e:
            logger.error(f"解析 DNP3 訊息錯誤: {e}")
            return None
    
    def detect_dnp3_anomalies(self, messages: List[OTMessage]) -> List[OTThreat]:
        """檢測 DNP3 異常"""
        try:
            threats = []
            
            # 檢測關鍵操作
            critical_operations = [msg for msg in messages if msg.function_code in self.critical_functions]
            
            for msg in critical_operations:
                threat = OTThreat(
                    id=f"dnp3_threat_{len(threats) + 1}",
                    threat_type="DNP3 Critical Operation",
                    source_device=msg.source_ip,
                    target_device=msg.dest_ip,
                    protocol=OTProtocol.DNP3,
                    description=f"Critical DNP3 operation: {self.dnp3_functions.get(msg.function_code, 'Unknown')}",
                    severity=ThreatLevel.CRITICAL,
                    timestamp=msg.timestamp,
                    evidence=[f"Function code: 0x{msg.function_code:02X}", f"Data length: {msg.length}"]
                )
                threats.append(threat)
            
            # 檢測未授權操作
            unauthorized_operations = [msg for msg in messages if msg.function_code in [0x02, 0x04, 0x05]]
            if len(unauthorized_operations) > 10:
                threat = OTThreat(
                    id=f"dnp3_threat_{len(threats) + 1}",
                    threat_type="DNP3 Unauthorized Operations",
                    source_device="Multiple",
                    target_device="Multiple",
                    protocol=OTProtocol.DNP3,
                    description="Multiple unauthorized DNP3 operations detected",
                    severity=ThreatLevel.HIGH,
                    timestamp=datetime.now().isoformat(),
                    evidence=[f"Unauthorized operations count: {len(unauthorized_operations)}"]
                )
                threats.append(threat)
            
            return threats
        except Exception as e:
            logger.error(f"檢測 DNP3 異常錯誤: {e}")
            return []

class CANBusMonitor:
    """CAN Bus 監控器"""
    
    def __init__(self):
        self.can_ids = {}
        self.suspicious_ids = set()
        self.known_devices = {}
    
    def parse_can_message(self, data: bytes, source_ip: str, dest_ip: str) -> Optional[OTMessage]:
        """解析 CAN Bus 訊息"""
        try:
            if len(data) < 8:  # CAN 最小長度
                return None
            
            # 解析 CAN 標頭
            can_id = struct.unpack('>I', data[0:4])[0]
            can_id = can_id & 0x1FFFFFFF  # 移除擴展標識符位
            
            # 檢查是否為可疑的 CAN ID
            suspicious = can_id in self.suspicious_ids
            
            # 確定威脅等級
            if suspicious:
                threat_level = ThreatLevel.HIGH
            elif can_id in self.can_ids:
                threat_level = ThreatLevel.LOW
            else:
                threat_level = ThreatLevel.MEDIUM
            
            message = OTMessage(
                id=f"can_{int(time.time())}_{can_id}",
                timestamp=datetime.now().isoformat(),
                source_ip=source_ip,
                dest_ip=dest_ip,
                protocol=OTProtocol.CAN_BUS,
                function_code=can_id,
                data=data,
                length=len(data),
                suspicious=suspicious,
                threat_level=threat_level
            )
            
            return message
        except Exception as e:
            logger.error(f"解析 CAN Bus 訊息錯誤: {e}")
            return None
    
    def detect_can_anomalies(self, messages: List[OTMessage]) -> List[OTThreat]:
        """檢測 CAN Bus 異常"""
        try:
            threats = []
            
            # 檢測異常 CAN ID
            for msg in messages:
                if msg.suspicious:
                    threat = OTThreat(
                        id=f"can_threat_{len(threats) + 1}",
                        threat_type="CAN Bus Anomaly",
                        source_device=msg.source_ip,
                        target_device=msg.dest_ip,
                        protocol=OTProtocol.CAN_BUS,
                        description=f"Suspicious CAN ID detected: 0x{msg.function_code:08X}",
                        severity=ThreatLevel.HIGH,
                        timestamp=msg.timestamp,
                        evidence=[f"CAN ID: 0x{msg.function_code:08X}", f"Data length: {msg.length}"]
                    )
                    threats.append(threat)
            
            # 檢測頻繁通訊
            can_id_counts = {}
            for msg in messages:
                can_id = msg.function_code
                if can_id not in can_id_counts:
                    can_id_counts[can_id] = 0
                can_id_counts[can_id] += 1
            
            for can_id, count in can_id_counts.items():
                if count > 1000:  # 閾值
                    threat = OTThreat(
                        id=f"can_threat_{len(threats) + 1}",
                        threat_type="CAN Bus Flooding",
                        source_device="Multiple",
                        target_device="Multiple",
                        protocol=OTProtocol.CAN_BUS,
                        description=f"CAN ID flooding detected: 0x{can_id:08X}",
                        severity=ThreatLevel.MEDIUM,
                        timestamp=datetime.now().isoformat(),
                        evidence=[f"CAN ID: 0x{can_id:08X}", f"Message count: {count}"]
                    )
                    threats.append(threat)
            
            return threats
        except Exception as e:
            logger.error(f"檢測 CAN Bus 異常錯誤: {e}")
            return []

class OTDeviceDiscovery:
    """OT裝置發現"""
    
    def __init__(self):
        self.devices = {}
        self.device_signatures = {
            '192.168.1.100': {'type': DeviceType.PLC, 'vendor': 'Siemens', 'model': 'S7-1200'},
            '192.168.1.101': {'type': DeviceType.HMI, 'vendor': 'Schneider', 'model': 'Magelis'},
            '192.168.1.102': {'type': DeviceType.SCADA, 'vendor': 'Wonderware', 'model': 'InTouch'},
            '192.168.1.103': {'type': DeviceType.RTU, 'vendor': 'Honeywell', 'model': 'RTU2020'},
            '192.168.1.104': {'type': DeviceType.IED, 'vendor': 'ABB', 'model': 'REF615'}
        }
    
    def discover_ot_devices(self, network_range: str = "192.168.1.0/24") -> Dict[str, Any]:
        """發現 OT 裝置"""
        try:
            discovered_devices = []
            
            # 模擬裝置發現
            for ip, signature in self.device_signatures.items():
                device = OTDevice(
                    id=f"device_{ip.replace('.', '_')}",
                    name=f"{signature['vendor']} {signature['model']}",
                    ip_address=ip,
                    mac_address=f"00:11:22:33:44:{ip.split('.')[-1].zfill(2)}",
                    device_type=signature['type'],
                    protocol=OTProtocol.MODBUS,  # 預設協議
                    vendor=signature['vendor'],
                    model=signature['model'],
                    firmware_version="1.0.0",
                    last_seen=datetime.now().isoformat(),
                    status="online",
                    risk_score=0.3
                )
                
                self.devices[device.id] = device
                discovered_devices.append(device)
            
            return {
                'success': True,
                'discovered_devices': len(discovered_devices),
                'devices': [self._device_to_dict(d) for d in discovered_devices]
            }
        except Exception as e:
            logger.error(f"OT 裝置發現錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _device_to_dict(self, device: OTDevice) -> Dict[str, Any]:
        """將裝置轉換為字典"""
        return {
            'id': device.id,
            'name': device.name,
            'ip_address': device.ip_address,
            'mac_address': device.mac_address,
            'device_type': device.device_type.value,
            'protocol': device.protocol.value,
            'vendor': device.vendor,
            'model': device.model,
            'firmware_version': device.firmware_version,
            'last_seen': device.last_seen,
            'status': device.status,
            'risk_score': device.risk_score
        }

class MilitaryOTIoTDefense:
    """軍事級工控/IoT防禦主類別"""
    
    def __init__(self):
        self.modbus_monitor = ModbusMonitor()
        self.dnp3_monitor = DNP3Monitor()
        self.can_monitor = CANBusMonitor()
        self.device_discovery = OTDeviceDiscovery()
        self.ot_log = []
    
    def comprehensive_ot_iot_analysis(self, analysis_scope: Dict[str, Any]) -> Dict[str, Any]:
        """執行綜合工控/IoT分析"""
        try:
            results = {}
            
            # 1. 裝置發現
            logger.info("執行 OT 裝置發現...")
            device_results = self.device_discovery.discover_ot_devices()
            results['device_discovery'] = device_results
            
            # 2. 協議監控
            logger.info("執行協議監控...")
            protocol_results = self._monitor_ot_protocols(analysis_scope)
            results['protocol_monitoring'] = protocol_results
            
            # 3. 威脅檢測
            logger.info("執行威脅檢測...")
            threat_results = self._detect_ot_threats(protocol_results)
            results['threat_detection'] = threat_results
            
            # 4. 安全評估
            logger.info("執行安全評估...")
            security_results = self._assess_ot_security(results)
            results['security_assessment'] = security_results
            
            return {
                'success': True,
                'results': results,
                'summary': self._generate_ot_summary(results)
            }
        except Exception as e:
            logger.error(f"綜合工控/IoT分析錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _monitor_ot_protocols(self, analysis_scope: Dict[str, Any]) -> Dict[str, Any]:
        """監控 OT 協議"""
        try:
            results = {
                'modbus_messages': [],
                'dnp3_messages': [],
                'can_messages': [],
                'total_messages': 0
            }
            
            # 模擬協議監控
            # Modbus 監控
            modbus_data = b'\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0A'  # 讀取保持寄存器
            modbus_msg = self.modbus_monitor.parse_modbus_message(modbus_data, "192.168.1.100", "192.168.1.101")
            if modbus_msg:
                results['modbus_messages'].append(modbus_msg)
            
            # DNP3 監控
            dnp3_data = b'\x05\x64\x00\x0A\xC0\x01\x00\x00\x00\xC0\x01\x00\x00\x00'  # DNP3 讀取
            dnp3_msg = self.dnp3_monitor.parse_dnp3_message(dnp3_data, "192.168.1.102", "192.168.1.103")
            if dnp3_msg:
                results['dnp3_messages'].append(dnp3_msg)
            
            # CAN Bus 監控
            can_data = b'\x00\x00\x00\x01\x01\x02\x03\x04'  # CAN 訊息
            can_msg = self.can_monitor.parse_can_message(can_data, "192.168.1.104", "192.168.1.105")
            if can_msg:
                results['can_messages'].append(can_msg)
            
            results['total_messages'] = len(results['modbus_messages']) + len(results['dnp3_messages']) + len(results['can_messages'])
            
            return results
        except Exception as e:
            logger.error(f"OT 協議監控錯誤: {e}")
            return {'error': str(e)}
    
    def _detect_ot_threats(self, protocol_results: Dict[str, Any]) -> Dict[str, Any]:
        """檢測 OT 威脅"""
        try:
            threats = []
            
            # Modbus 威脅檢測
            if 'modbus_messages' in protocol_results:
                modbus_threats = self.modbus_monitor.detect_modbus_anomalies(protocol_results['modbus_messages'])
                threats.extend(modbus_threats)
            
            # DNP3 威脅檢測
            if 'dnp3_messages' in protocol_results:
                dnp3_threats = self.dnp3_monitor.detect_dnp3_anomalies(protocol_results['dnp3_messages'])
                threats.extend(dnp3_threats)
            
            # CAN Bus 威脅檢測
            if 'can_messages' in protocol_results:
                can_threats = self.can_monitor.detect_can_anomalies(protocol_results['can_messages'])
                threats.extend(can_threats)
            
            # 按威脅類型分組
            threats_by_type = {}
            for threat in threats:
                threat_type = threat.threat_type
                if threat_type not in threats_by_type:
                    threats_by_type[threat_type] = []
                threats_by_type[threat_type].append(threat)
            
            return {
                'total_threats': len(threats),
                'threats_by_type': threats_by_type,
                'critical_threats': [t for t in threats if t.severity == ThreatLevel.CRITICAL],
                'high_threats': [t for t in threats if t.severity == ThreatLevel.HIGH],
                'threats': [self._threat_to_dict(t) for t in threats]
            }
        except Exception as e:
            logger.error(f"OT 威脅檢測錯誤: {e}")
            return {'total_threats': 0, 'error': str(e)}
    
    def _assess_ot_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """評估 OT 安全"""
        try:
            security_score = 100.0
            vulnerabilities = []
            recommendations = []
            
            # 檢查裝置安全
            if 'device_discovery' in results and results['device_discovery'].get('success', False):
                devices = results['device_discovery'].get('devices', [])
                for device in devices:
                    if device.get('risk_score', 0) > 0.5:
                        security_score -= 10
                        vulnerabilities.append(f"High risk device: {device['name']}")
            
            # 檢查威脅
            if 'threat_detection' in results:
                threat_data = results['threat_detection']
                critical_threats = len(threat_data.get('critical_threats', []))
                high_threats = len(threat_data.get('high_threats', []))
                
                security_score -= critical_threats * 20
                security_score -= high_threats * 10
                
                if critical_threats > 0:
                    vulnerabilities.append(f"{critical_threats} critical threats detected")
                if high_threats > 0:
                    vulnerabilities.append(f"{high_threats} high threats detected")
            
            # 生成建議
            if security_score < 70:
                recommendations.extend([
                    "Implement network segmentation",
                    "Deploy OT-specific firewalls",
                    "Enable protocol whitelisting",
                    "Implement device authentication",
                    "Deploy anomaly detection"
                ])
            elif security_score < 90:
                recommendations.extend([
                    "Monitor OT protocols continuously",
                    "Implement access controls",
                    "Regular security assessments"
                ])
            else:
                recommendations.append("Maintain current security posture")
            
            return {
                'security_score': max(security_score, 0),
                'security_level': self._determine_security_level(security_score),
                'vulnerabilities': vulnerabilities,
                'recommendations': recommendations,
                'compliance_status': 'COMPLIANT' if security_score >= 80 else 'NON_COMPLIANT'
            }
        except Exception as e:
            logger.error(f"OT 安全評估錯誤: {e}")
            return {'security_score': 0, 'error': str(e)}
    
    def _determine_security_level(self, score: float) -> str:
        """確定安全等級"""
        if score >= 90:
            return "EXCELLENT"
        elif score >= 80:
            return "GOOD"
        elif score >= 70:
            return "FAIR"
        elif score >= 50:
            return "POOR"
        else:
            return "CRITICAL"
    
    def _threat_to_dict(self, threat: OTThreat) -> Dict[str, Any]:
        """將威脅轉換為字典"""
        return {
            'id': threat.id,
            'threat_type': threat.threat_type,
            'source_device': threat.source_device,
            'target_device': threat.target_device,
            'protocol': threat.protocol.value,
            'description': threat.description,
            'severity': threat.severity.value,
            'timestamp': threat.timestamp,
            'evidence': threat.evidence
        }
    
    def _generate_ot_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成 OT 摘要"""
        summary = {
            'total_analyses': len(results),
            'successful_analyses': sum(1 for r in results.values() if isinstance(r, dict) and r.get('success', True)),
            'discovered_devices': 0,
            'total_messages': 0,
            'total_threats': 0,
            'security_score': 0
        }
        
        if 'device_discovery' in results:
            summary['discovered_devices'] = results['device_discovery'].get('discovered_devices', 0)
        
        if 'protocol_monitoring' in results:
            summary['total_messages'] = results['protocol_monitoring'].get('total_messages', 0)
        
        if 'threat_detection' in results:
            summary['total_threats'] = results['threat_detection'].get('total_threats', 0)
        
        if 'security_assessment' in results:
            summary['security_score'] = results['security_assessment'].get('security_score', 0)
        
        return summary
    
    def get_ot_log(self) -> List[Dict[str, Any]]:
        """獲取 OT 日誌"""
        return self.ot_log
    
    def export_results(self, filename: str) -> bool:
        """匯出結果"""
        try:
            data = {
                'ot_log': self.ot_log,
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
    print("🏭 軍事級工控/IoT防禦系統")
    print("=" * 50)
    
    # 初始化系統
    ot_iot_defense = MilitaryOTIoTDefense()
    
    # 測試分析範圍
    test_analysis_scope = {
        'network_range': '192.168.1.0/24',
        'protocols': ['modbus', 'dnp3', 'can_bus'],
        'monitoring_duration': '24h'
    }
    
    # 執行綜合工控/IoT分析測試
    print("開始執行綜合工控/IoT分析測試...")
    results = ot_iot_defense.comprehensive_ot_iot_analysis(test_analysis_scope)
    
    print(f"分析完成，成功: {results['success']}")
    print(f"分析摘要: {json.dumps(results['summary'], indent=2, ensure_ascii=False)}")
    
    # 匯出結果
    ot_iot_defense.export_results("ot_iot_defense_results.json")
    
    print("軍事級工控/IoT防禦系統測試完成！")

if __name__ == "__main__":
    main()

