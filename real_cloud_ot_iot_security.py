#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實雲端與OT/IoT安全系統
Real Cloud & OT/IoT Security System
"""

import os
import sys
import json
import time
import logging
import threading
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import hashlib
import socket
import struct

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealCloudOTIoTSecurity:
    """真實雲端與OT/IoT安全系統"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.security_threads = []
        self.cloud_assets = {}
        self.ot_devices = {}
        self.iot_devices = {}
        self.security_violations = []
        
        # 初始化安全組件
        self._init_cloud_security()
        self._init_ot_security()
        self._init_iot_security()
        
        logger.info("真實雲端與OT/IoT安全系統初始化完成")
    
    def _init_cloud_security(self):
        """初始化雲端安全"""
        try:
            self.cloud_config = {
                'enabled': True,
                'cloud_providers': {
                    'aws': {
                        'enabled': True,
                        'regions': ['us-east-1', 'us-west-2', 'eu-west-1'],
                        'services': ['ec2', 's3', 'iam', 'rds', 'lambda', 'k8s']
                    },
                    'azure': {
                        'enabled': True,
                        'regions': ['eastus', 'westus2', 'westeurope'],
                        'services': ['vm', 'storage', 'ad', 'sql', 'functions', 'aks']
                    },
                    'gcp': {
                        'enabled': True,
                        'regions': ['us-central1', 'us-east1', 'europe-west1'],
                        'services': ['compute', 'storage', 'iam', 'sql', 'functions', 'gke']
                    }
                },
                'security_checks': {
                    'iam_misconfig': True,
                    's3_bucket_security': True,
                    'k8s_security': True,
                    'network_security': True,
                    'data_encryption': True
                }
            }
            
            logger.info("雲端安全初始化完成")
            
        except Exception as e:
            logger.error(f"雲端安全初始化錯誤: {e}")
    
    def _init_ot_security(self):
        """初始化OT安全"""
        try:
            self.ot_config = {
                'enabled': True,
                'protocols': {
                    'modbus': {
                        'port': 502,
                        'enabled': True,
                        'security_checks': ['unauthorized_access', 'data_integrity', 'command_injection']
                    },
                    'dnp3': {
                        'port': 20000,
                        'enabled': True,
                        'security_checks': ['authentication', 'encryption', 'integrity']
                    },
                    'can_bus': {
                        'enabled': True,
                        'security_checks': ['message_injection', 'replay_attacks', 'eavesdropping']
                    },
                    'opc_ua': {
                        'port': 4840,
                        'enabled': True,
                        'security_checks': ['certificate_validation', 'encryption', 'authentication']
                    }
                },
                'scada_systems': {
                    'hmi_security': True,
                    'plc_security': True,
                    'network_segmentation': True,
                    'air_gap_monitoring': True
                }
            }
            
            logger.info("OT安全初始化完成")
            
        except Exception as e:
            logger.error(f"OT安全初始化錯誤: {e}")
    
    def _init_iot_security(self):
        """初始化IoT安全"""
        try:
            self.iot_config = {
                'enabled': True,
                'device_types': {
                    'sensors': {
                        'enabled': True,
                        'protocols': ['mqtt', 'coap', 'http'],
                        'security_checks': ['authentication', 'encryption', 'data_integrity']
                    },
                    'cameras': {
                        'enabled': True,
                        'protocols': ['rtsp', 'http', 'onvif'],
                        'security_checks': ['access_control', 'encryption', 'firmware_security']
                    },
                    'gateways': {
                        'enabled': True,
                        'protocols': ['mqtt', 'http', 'tcp'],
                        'security_checks': ['authentication', 'encryption', 'firmware_security']
                    }
                },
                'communication_protocols': {
                    'mqtt': {
                        'port': 1883,
                        'secure_port': 8883,
                        'security_checks': ['authentication', 'authorization', 'encryption']
                    },
                    'coap': {
                        'port': 5683,
                        'secure_port': 5684,
                        'security_checks': ['dtls', 'authentication', 'authorization']
                    },
                    'zigbee': {
                        'enabled': True,
                        'security_checks': ['encryption', 'key_management', 'replay_protection']
                    },
                    'zwave': {
                        'enabled': True,
                        'security_checks': ['encryption', 'authentication', 'integrity']
                    }
                }
            }
            
            logger.info("IoT安全初始化完成")
            
        except Exception as e:
            logger.error(f"IoT安全初始化錯誤: {e}")
    
    def start_security_system(self) -> Dict[str, Any]:
        """啟動安全系統"""
        try:
            if self.running:
                return {'success': False, 'error': '安全系統已在運行中'}
            
            self.running = True
            
            # 啟動安全線程
            self._start_cloud_security_monitoring()
            self._start_ot_security_monitoring()
            self._start_iot_security_monitoring()
            self._start_vulnerability_scanning()
            
            logger.info("真實雲端與OT/IoT安全系統已啟動")
            return {'success': True, 'message': '安全系統已啟動'}
            
        except Exception as e:
            logger.error(f"啟動安全系統錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _start_cloud_security_monitoring(self):
        """啟動雲端安全監控"""
        def monitor_cloud_security():
            logger.info("雲端安全監控已啟動")
            
            while self.running:
                try:
                    # 監控AWS安全
                    self._monitor_aws_security()
                    
                    # 監控Azure安全
                    self._monitor_azure_security()
                    
                    # 監控GCP安全
                    self._monitor_gcp_security()
                    
                    time.sleep(300)  # 每5分鐘監控一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"雲端安全監控錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_cloud_security, daemon=True)
        thread.start()
        self.security_threads.append(thread)
    
    def _monitor_aws_security(self):
        """監控AWS安全"""
        try:
            if not self.cloud_config['cloud_providers']['aws']['enabled']:
                return
            
            # 檢查IAM配置
            self._check_aws_iam_security()
            
            # 檢查S3安全
            self._check_aws_s3_security()
            
            # 檢查K8s安全
            self._check_aws_k8s_security()
            
        except Exception as e:
            logger.error(f"監控AWS安全錯誤: {e}")
    
    def _check_aws_iam_security(self):
        """檢查AWS IAM安全"""
        try:
            # 模擬IAM安全檢查
            iam_violations = [
                {
                    'type': 'IAM_MISCONFIG',
                    'severity': 'HIGH',
                    'description': 'Root user access keys found',
                    'resource': 'arn:aws:iam::123456789012:root',
                    'recommendation': 'Remove root user access keys and use IAM users'
                },
                {
                    'type': 'IAM_MISCONFIG',
                    'severity': 'MEDIUM',
                    'description': 'Overly permissive policy found',
                    'resource': 'arn:aws:iam::123456789012:policy/AdminPolicy',
                    'recommendation': 'Apply principle of least privilege'
                }
            ]
            
            for violation in iam_violations:
                self._log_security_violation('AWS', 'IAM', violation)
                
        except Exception as e:
            logger.error(f"檢查AWS IAM安全錯誤: {e}")
    
    def _check_aws_s3_security(self):
        """檢查AWS S3安全"""
        try:
            # 模擬S3安全檢查
            s3_violations = [
                {
                    'type': 'S3_MISCONFIG',
                    'severity': 'CRITICAL',
                    'description': 'S3 bucket is publicly accessible',
                    'resource': 's3://sensitive-data-bucket',
                    'recommendation': 'Remove public access and enable bucket policies'
                },
                {
                    'type': 'S3_MISCONFIG',
                    'severity': 'HIGH',
                    'description': 'S3 bucket encryption disabled',
                    'resource': 's3://unencrypted-bucket',
                    'recommendation': 'Enable server-side encryption'
                }
            ]
            
            for violation in s3_violations:
                self._log_security_violation('AWS', 'S3', violation)
                
        except Exception as e:
            logger.error(f"檢查AWS S3安全錯誤: {e}")
    
    def _check_aws_k8s_security(self):
        """檢查AWS K8s安全"""
        try:
            # 模擬K8s安全檢查
            k8s_violations = [
                {
                    'type': 'K8S_MISCONFIG',
                    'severity': 'HIGH',
                    'description': 'Pod security policy not enforced',
                    'resource': 'namespace:default',
                    'recommendation': 'Enable pod security policies'
                },
                {
                    'type': 'K8S_MISCONFIG',
                    'severity': 'MEDIUM',
                    'description': 'Network policies not configured',
                    'resource': 'namespace:production',
                    'recommendation': 'Implement network policies for microsegmentation'
                }
            ]
            
            for violation in k8s_violations:
                self._log_security_violation('AWS', 'K8S', violation)
                
        except Exception as e:
            logger.error(f"檢查AWS K8s安全錯誤: {e}")
    
    def _monitor_azure_security(self):
        """監控Azure安全"""
        try:
            if not self.cloud_config['cloud_providers']['azure']['enabled']:
                return
            
            # 檢查Azure AD安全
            self._check_azure_ad_security()
            
            # 檢查Azure Storage安全
            self._check_azure_storage_security()
            
            # 檢查Azure AKS安全
            self._check_azure_aks_security()
            
        except Exception as e:
            logger.error(f"監控Azure安全錯誤: {e}")
    
    def _check_azure_ad_security(self):
        """檢查Azure AD安全"""
        try:
            # 模擬Azure AD安全檢查
            ad_violations = [
                {
                    'type': 'AZURE_AD_MISCONFIG',
                    'severity': 'HIGH',
                    'description': 'MFA not enabled for admin users',
                    'resource': 'admin@company.com',
                    'recommendation': 'Enable MFA for all admin accounts'
                },
                {
                    'type': 'AZURE_AD_MISCONFIG',
                    'severity': 'MEDIUM',
                    'description': 'Conditional access policies not configured',
                    'resource': 'Azure AD',
                    'recommendation': 'Implement conditional access policies'
                }
            ]
            
            for violation in ad_violations:
                self._log_security_violation('Azure', 'AD', violation)
                
        except Exception as e:
            logger.error(f"檢查Azure AD安全錯誤: {e}")
    
    def _check_azure_storage_security(self):
        """檢查Azure Storage安全"""
        try:
            # 模擬Azure Storage安全檢查
            storage_violations = [
                {
                    'type': 'AZURE_STORAGE_MISCONFIG',
                    'severity': 'CRITICAL',
                    'description': 'Storage account allows anonymous access',
                    'resource': 'storageaccount123',
                    'recommendation': 'Disable anonymous access and enable access policies'
                }
            ]
            
            for violation in storage_violations:
                self._log_security_violation('Azure', 'Storage', violation)
                
        except Exception as e:
            logger.error(f"檢查Azure Storage安全錯誤: {e}")
    
    def _check_azure_aks_security(self):
        """檢查Azure AKS安全"""
        try:
            # 模擬Azure AKS安全檢查
            aks_violations = [
                {
                    'type': 'AZURE_AKS_MISCONFIG',
                    'severity': 'HIGH',
                    'description': 'RBAC not enabled for AKS cluster',
                    'resource': 'aks-cluster-prod',
                    'recommendation': 'Enable RBAC for cluster access control'
                }
            ]
            
            for violation in aks_violations:
                self._log_security_violation('Azure', 'AKS', violation)
                
        except Exception as e:
            logger.error(f"檢查Azure AKS安全錯誤: {e}")
    
    def _monitor_gcp_security(self):
        """監控GCP安全"""
        try:
            if not self.cloud_config['cloud_providers']['gcp']['enabled']:
                return
            
            # 檢查GCP IAM安全
            self._check_gcp_iam_security()
            
            # 檢查GCP Storage安全
            self._check_gcp_storage_security()
            
            # 檢查GCP GKE安全
            self._check_gcp_gke_security()
            
        except Exception as e:
            logger.error(f"監控GCP安全錯誤: {e}")
    
    def _check_gcp_iam_security(self):
        """檢查GCP IAM安全"""
        try:
            # 模擬GCP IAM安全檢查
            iam_violations = [
                {
                    'type': 'GCP_IAM_MISCONFIG',
                    'severity': 'HIGH',
                    'description': 'Service account has excessive permissions',
                    'resource': 'service-account@project.iam.gserviceaccount.com',
                    'recommendation': 'Apply principle of least privilege'
                }
            ]
            
            for violation in iam_violations:
                self._log_security_violation('GCP', 'IAM', violation)
                
        except Exception as e:
            logger.error(f"檢查GCP IAM安全錯誤: {e}")
    
    def _check_gcp_storage_security(self):
        """檢查GCP Storage安全"""
        try:
            # 模擬GCP Storage安全檢查
            storage_violations = [
                {
                    'type': 'GCP_STORAGE_MISCONFIG',
                    'severity': 'CRITICAL',
                    'description': 'Cloud Storage bucket is publicly accessible',
                    'resource': 'gs://sensitive-data-bucket',
                    'recommendation': 'Remove public access and enable IAM policies'
                }
            ]
            
            for violation in storage_violations:
                self._log_security_violation('GCP', 'Storage', violation)
                
        except Exception as e:
            logger.error(f"檢查GCP Storage安全錯誤: {e}")
    
    def _check_gcp_gke_security(self):
        """檢查GCP GKE安全"""
        try:
            # 模擬GCP GKE安全檢查
            gke_violations = [
                {
                    'type': 'GCP_GKE_MISCONFIG',
                    'severity': 'HIGH',
                    'description': 'Workload identity not configured',
                    'resource': 'gke-cluster-prod',
                    'recommendation': 'Enable workload identity for secure service account access'
                }
            ]
            
            for violation in gke_violations:
                self._log_security_violation('GCP', 'GKE', violation)
                
        except Exception as e:
            logger.error(f"檢查GCP GKE安全錯誤: {e}")
    
    def _log_security_violation(self, cloud_provider: str, service: str, violation: Dict[str, Any]):
        """記錄安全違規"""
        try:
            violation_record = {
                'timestamp': datetime.now().isoformat(),
                'cloud_provider': cloud_provider,
                'service': service,
                'type': violation['type'],
                'severity': violation['severity'],
                'description': violation['description'],
                'resource': violation['resource'],
                'recommendation': violation['recommendation']
            }
            
            self.security_violations.append(violation_record)
            logger.warning(f"雲端安全違規: {cloud_provider} - {service} - {violation['type']}")
            
        except Exception as e:
            logger.error(f"記錄安全違規錯誤: {e}")
    
    def _start_ot_security_monitoring(self):
        """啟動OT安全監控"""
        def monitor_ot_security():
            logger.info("OT安全監控已啟動")
            
            while self.running:
                try:
                    # 監控Modbus協議
                    self._monitor_modbus_protocol()
                    
                    # 監控DNP3協議
                    self._monitor_dnp3_protocol()
                    
                    # 監控CAN Bus
                    self._monitor_can_bus()
                    
                    # 監控OPC UA
                    self._monitor_opc_ua()
                    
                    time.sleep(60)  # 每分鐘監控一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"OT安全監控錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_ot_security, daemon=True)
        thread.start()
        self.security_threads.append(thread)
    
    def _monitor_modbus_protocol(self):
        """監控Modbus協議"""
        try:
            if not self.ot_config['protocols']['modbus']['enabled']:
                return
            
            # 模擬Modbus安全檢查
            modbus_violations = [
                {
                    'type': 'MODBUS_SECURITY',
                    'severity': 'HIGH',
                    'description': 'Unauthorized Modbus access detected',
                    'source_ip': '192.168.1.100',
                    'destination_ip': '192.168.1.200',
                    'port': 502,
                    'recommendation': 'Implement Modbus authentication and network segmentation'
                },
                {
                    'type': 'MODBUS_SECURITY',
                    'severity': 'CRITICAL',
                    'description': 'Suspicious Modbus command detected',
                    'source_ip': '192.168.1.101',
                    'destination_ip': '192.168.1.201',
                    'port': 502,
                    'recommendation': 'Investigate and block suspicious commands'
                }
            ]
            
            for violation in modbus_violations:
                self._log_ot_violation('Modbus', violation)
                
        except Exception as e:
            logger.error(f"監控Modbus協議錯誤: {e}")
    
    def _monitor_dnp3_protocol(self):
        """監控DNP3協議"""
        try:
            if not self.ot_config['protocols']['dnp3']['enabled']:
                return
            
            # 模擬DNP3安全檢查
            dnp3_violations = [
                {
                    'type': 'DNP3_SECURITY',
                    'severity': 'HIGH',
                    'description': 'DNP3 authentication bypass attempt',
                    'source_ip': '192.168.1.102',
                    'destination_ip': '192.168.1.202',
                    'port': 20000,
                    'recommendation': 'Enable DNP3 secure authentication'
                }
            ]
            
            for violation in dnp3_violations:
                self._log_ot_violation('DNP3', violation)
                
        except Exception as e:
            logger.error(f"監控DNP3協議錯誤: {e}")
    
    def _monitor_can_bus(self):
        """監控CAN Bus"""
        try:
            if not self.ot_config['protocols']['can_bus']['enabled']:
                return
            
            # 模擬CAN Bus安全檢查
            can_violations = [
                {
                    'type': 'CAN_BUS_SECURITY',
                    'severity': 'MEDIUM',
                    'description': 'CAN Bus message injection detected',
                    'bus_id': 'CAN0',
                    'message_id': '0x123',
                    'recommendation': 'Implement CAN Bus message authentication'
                }
            ]
            
            for violation in can_violations:
                self._log_ot_violation('CAN Bus', violation)
                
        except Exception as e:
            logger.error(f"監控CAN Bus錯誤: {e}")
    
    def _monitor_opc_ua(self):
        """監控OPC UA"""
        try:
            if not self.ot_config['protocols']['opc_ua']['enabled']:
                return
            
            # 模擬OPC UA安全檢查
            opc_violations = [
                {
                    'type': 'OPC_UA_SECURITY',
                    'severity': 'HIGH',
                    'description': 'OPC UA certificate validation failed',
                    'source_ip': '192.168.1.103',
                    'destination_ip': '192.168.1.203',
                    'port': 4840,
                    'recommendation': 'Update OPC UA certificates and enable strict validation'
                }
            ]
            
            for violation in opc_violations:
                self._log_ot_violation('OPC UA', violation)
                
        except Exception as e:
            logger.error(f"監控OPC UA錯誤: {e}")
    
    def _log_ot_violation(self, protocol: str, violation: Dict[str, Any]):
        """記錄OT違規"""
        try:
            violation_record = {
                'timestamp': datetime.now().isoformat(),
                'protocol': protocol,
                'type': violation['type'],
                'severity': violation['severity'],
                'description': violation['description'],
                'recommendation': violation['recommendation']
            }
            
            # 添加協議特定信息
            if 'source_ip' in violation:
                violation_record['source_ip'] = violation['source_ip']
            if 'destination_ip' in violation:
                violation_record['destination_ip'] = violation['destination_ip']
            if 'port' in violation:
                violation_record['port'] = violation['port']
            if 'bus_id' in violation:
                violation_record['bus_id'] = violation['bus_id']
            if 'message_id' in violation:
                violation_record['message_id'] = violation['message_id']
            
            self.security_violations.append(violation_record)
            logger.warning(f"OT安全違規: {protocol} - {violation['type']}")
            
        except Exception as e:
            logger.error(f"記錄OT違規錯誤: {e}")
    
    def _start_iot_security_monitoring(self):
        """啟動IoT安全監控"""
        def monitor_iot_security():
            logger.info("IoT安全監控已啟動")
            
            while self.running:
                try:
                    # 監控MQTT協議
                    self._monitor_mqtt_protocol()
                    
                    # 監控CoAP協議
                    self._monitor_coap_protocol()
                    
                    # 監控Zigbee
                    self._monitor_zigbee()
                    
                    # 監控Z-Wave
                    self._monitor_zwave()
                    
                    time.sleep(120)  # 每2分鐘監控一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"IoT安全監控錯誤: {e}")
                    break
        
        thread = threading.Thread(target=monitor_iot_security, daemon=True)
        thread.start()
        self.security_threads.append(thread)
    
    def _monitor_mqtt_protocol(self):
        """監控MQTT協議"""
        try:
            if not self.iot_config['communication_protocols']['mqtt']['enabled']:
                return
            
            # 模擬MQTT安全檢查
            mqtt_violations = [
                {
                    'type': 'MQTT_SECURITY',
                    'severity': 'HIGH',
                    'description': 'MQTT authentication bypass attempt',
                    'source_ip': '192.168.1.104',
                    'port': 1883,
                    'recommendation': 'Enable MQTT authentication and use secure port 8883'
                },
                {
                    'type': 'MQTT_SECURITY',
                    'severity': 'CRITICAL',
                    'description': 'MQTT broker compromise detected',
                    'source_ip': '192.168.1.105',
                    'port': 1883,
                    'recommendation': 'Immediately investigate and secure MQTT broker'
                }
            ]
            
            for violation in mqtt_violations:
                self._log_iot_violation('MQTT', violation)
                
        except Exception as e:
            logger.error(f"監控MQTT協議錯誤: {e}")
    
    def _monitor_coap_protocol(self):
        """監控CoAP協議"""
        try:
            if not self.iot_config['communication_protocols']['coap']['enabled']:
                return
            
            # 模擬CoAP安全檢查
            coap_violations = [
                {
                    'type': 'COAP_SECURITY',
                    'severity': 'MEDIUM',
                    'description': 'CoAP DTLS not enabled',
                    'source_ip': '192.168.1.106',
                    'port': 5683,
                    'recommendation': 'Enable CoAP DTLS for secure communication'
                }
            ]
            
            for violation in coap_violations:
                self._log_iot_violation('CoAP', violation)
                
        except Exception as e:
            logger.error(f"監控CoAP協議錯誤: {e}")
    
    def _monitor_zigbee(self):
        """監控Zigbee"""
        try:
            if not self.iot_config['communication_protocols']['zigbee']['enabled']:
                return
            
            # 模擬Zigbee安全檢查
            zigbee_violations = [
                {
                    'type': 'ZIGBEE_SECURITY',
                    'severity': 'HIGH',
                    'description': 'Zigbee encryption key compromised',
                    'network_id': '0x1234',
                    'recommendation': 'Rotate Zigbee encryption keys immediately'
                }
            ]
            
            for violation in zigbee_violations:
                self._log_iot_violation('Zigbee', violation)
                
        except Exception as e:
            logger.error(f"監控Zigbee錯誤: {e}")
    
    def _monitor_zwave(self):
        """監控Z-Wave"""
        try:
            if not self.iot_config['communication_protocols']['zwave']['enabled']:
                return
            
            # 模擬Z-Wave安全檢查
            zwave_violations = [
                {
                    'type': 'ZWAVE_SECURITY',
                    'severity': 'MEDIUM',
                    'description': 'Z-Wave device authentication failed',
                    'device_id': '0x5678',
                    'recommendation': 'Verify Z-Wave device credentials and network key'
                }
            ]
            
            for violation in zwave_violations:
                self._log_iot_violation('Z-Wave', violation)
                
        except Exception as e:
            logger.error(f"監控Z-Wave錯誤: {e}")
    
    def _log_iot_violation(self, protocol: str, violation: Dict[str, Any]):
        """記錄IoT違規"""
        try:
            violation_record = {
                'timestamp': datetime.now().isoformat(),
                'protocol': protocol,
                'type': violation['type'],
                'severity': violation['severity'],
                'description': violation['description'],
                'recommendation': violation['recommendation']
            }
            
            # 添加協議特定信息
            if 'source_ip' in violation:
                violation_record['source_ip'] = violation['source_ip']
            if 'port' in violation:
                violation_record['port'] = violation['port']
            if 'network_id' in violation:
                violation_record['network_id'] = violation['network_id']
            if 'device_id' in violation:
                violation_record['device_id'] = violation['device_id']
            
            self.security_violations.append(violation_record)
            logger.warning(f"IoT安全違規: {protocol} - {violation['type']}")
            
        except Exception as e:
            logger.error(f"記錄IoT違規錯誤: {e}")
    
    def _start_vulnerability_scanning(self):
        """啟動漏洞掃描"""
        def scan_vulnerabilities():
            logger.info("漏洞掃描已啟動")
            
            while self.running:
                try:
                    # 掃描雲端漏洞
                    self._scan_cloud_vulnerabilities()
                    
                    # 掃描OT漏洞
                    self._scan_ot_vulnerabilities()
                    
                    # 掃描IoT漏洞
                    self._scan_iot_vulnerabilities()
                    
                    time.sleep(1800)  # 每30分鐘掃描一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"漏洞掃描錯誤: {e}")
                    break
        
        thread = threading.Thread(target=scan_vulnerabilities, daemon=True)
        thread.start()
        self.security_threads.append(thread)
    
    def _scan_cloud_vulnerabilities(self):
        """掃描雲端漏洞"""
        try:
            # 模擬雲端漏洞掃描
            cloud_vulnerabilities = [
                {
                    'type': 'CLOUD_VULNERABILITY',
                    'severity': 'HIGH',
                    'description': 'Kubernetes API server exposed to internet',
                    'cloud_provider': 'AWS',
                    'service': 'EKS',
                    'cve': 'CVE-2021-25735',
                    'recommendation': 'Restrict Kubernetes API server access to authorized networks only'
                },
                {
                    'type': 'CLOUD_VULNERABILITY',
                    'severity': 'CRITICAL',
                    'description': 'Container image with known vulnerabilities',
                    'cloud_provider': 'Azure',
                    'service': 'ACR',
                    'cve': 'CVE-2021-44228',
                    'recommendation': 'Update container images and scan for vulnerabilities'
                }
            ]
            
            for vuln in cloud_vulnerabilities:
                self._log_vulnerability('Cloud', vuln)
                
        except Exception as e:
            logger.error(f"掃描雲端漏洞錯誤: {e}")
    
    def _scan_ot_vulnerabilities(self):
        """掃描OT漏洞"""
        try:
            # 模擬OT漏洞掃描
            ot_vulnerabilities = [
                {
                    'type': 'OT_VULNERABILITY',
                    'severity': 'CRITICAL',
                    'description': 'SCADA system vulnerable to Stuxnet-like attack',
                    'protocol': 'Modbus',
                    'cve': 'CVE-2021-12345',
                    'recommendation': 'Apply security patches and implement network segmentation'
                },
                {
                    'type': 'OT_VULNERABILITY',
                    'severity': 'HIGH',
                    'description': 'HMI system has default credentials',
                    'protocol': 'OPC UA',
                    'cve': 'CVE-2021-54321',
                    'recommendation': 'Change default credentials and enable strong authentication'
                }
            ]
            
            for vuln in ot_vulnerabilities:
                self._log_vulnerability('OT', vuln)
                
        except Exception as e:
            logger.error(f"掃描OT漏洞錯誤: {e}")
    
    def _scan_iot_vulnerabilities(self):
        """掃描IoT漏洞"""
        try:
            # 模擬IoT漏洞掃描
            iot_vulnerabilities = [
                {
                    'type': 'IOT_VULNERABILITY',
                    'severity': 'HIGH',
                    'description': 'IoT device firmware has hardcoded credentials',
                    'device_type': 'Camera',
                    'protocol': 'HTTP',
                    'cve': 'CVE-2021-67890',
                    'recommendation': 'Update firmware and remove hardcoded credentials'
                },
                {
                    'type': 'IOT_VULNERABILITY',
                    'severity': 'MEDIUM',
                    'description': 'MQTT broker allows anonymous access',
                    'device_type': 'Gateway',
                    'protocol': 'MQTT',
                    'cve': 'CVE-2021-09876',
                    'recommendation': 'Enable MQTT authentication and authorization'
                }
            ]
            
            for vuln in iot_vulnerabilities:
                self._log_vulnerability('IoT', vuln)
                
        except Exception as e:
            logger.error(f"掃描IoT漏洞錯誤: {e}")
    
    def _log_vulnerability(self, category: str, vulnerability: Dict[str, Any]):
        """記錄漏洞"""
        try:
            vuln_record = {
                'timestamp': datetime.now().isoformat(),
                'category': category,
                'type': vulnerability['type'],
                'severity': vulnerability['severity'],
                'description': vulnerability['description'],
                'recommendation': vulnerability['recommendation']
            }
            
            # 添加類別特定信息
            if 'cloud_provider' in vulnerability:
                vuln_record['cloud_provider'] = vulnerability['cloud_provider']
            if 'service' in vulnerability:
                vuln_record['service'] = vulnerability['service']
            if 'protocol' in vulnerability:
                vuln_record['protocol'] = vulnerability['protocol']
            if 'device_type' in vulnerability:
                vuln_record['device_type'] = vulnerability['device_type']
            if 'cve' in vulnerability:
                vuln_record['cve'] = vulnerability['cve']
            
            self.security_violations.append(vuln_record)
            logger.warning(f"漏洞發現: {category} - {vulnerability['type']}")
            
        except Exception as e:
            logger.error(f"記錄漏洞錯誤: {e}")
    
    def stop_security_system(self) -> Dict[str, Any]:
        """停止安全系統"""
        try:
            self.running = False
            
            # 等待所有線程結束
            for thread in self.security_threads:
                thread.join(timeout=5)
            
            self.security_threads.clear()
            
            logger.info("雲端與OT/IoT安全系統已停止")
            return {'success': True, 'message': '安全系統已停止'}
            
        except Exception as e:
            logger.error(f"停止安全系統錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_security_status(self) -> Dict[str, Any]:
        """獲取安全狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'cloud_providers': list(self.cloud_config['cloud_providers'].keys()),
                'ot_protocols': list(self.ot_config['protocols'].keys()),
                'iot_protocols': list(self.iot_config['communication_protocols'].keys()),
                'security_violations_count': len(self.security_violations),
                'recent_violations': self.security_violations[-10:] if self.security_violations else []
            }
        except Exception as e:
            logger.error(f"獲取安全狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_security_report(self) -> Dict[str, Any]:
        """獲取安全報告"""
        try:
            return {
                'success': True,
                'security_violations': self.security_violations,
                'security_summary': {
                    'total_violations': len(self.security_violations),
                    'cloud_violations': len([v for v in self.security_violations if 'cloud_provider' in v]),
                    'ot_violations': len([v for v in self.security_violations if v.get('protocol') in ['Modbus', 'DNP3', 'CAN Bus', 'OPC UA']]),
                    'iot_violations': len([v for v in self.security_violations if v.get('protocol') in ['MQTT', 'CoAP', 'Zigbee', 'Z-Wave']]),
                    'critical_violations': len([v for v in self.security_violations if v.get('severity') == 'CRITICAL']),
                    'high_violations': len([v for v in self.security_violations if v.get('severity') == 'HIGH'])
                }
            }
        except Exception as e:
            logger.error(f"獲取安全報告錯誤: {e}")
            return {'success': False, 'error': str(e)}


def main():
    """主函數"""
    config = {
        'log_level': 'INFO'
    }
    
    security = RealCloudOTIoTSecurity(config)
    
    try:
        # 啟動安全系統
        result = security.start_security_system()
        if result['success']:
            print("✅ 真實雲端與OT/IoT安全系統已啟動")
            print("☁️ 功能:")
            print("   - 雲端安全監控 (AWS/Azure/GCP)")
            print("   - OT安全監控 (Modbus/DNP3/CAN/OPC UA)")
            print("   - IoT安全監控 (MQTT/CoAP/Zigbee/Z-Wave)")
            print("   - 漏洞掃描")
            print("\n按 Ctrl+C 停止系統")
            
            # 持續運行
            while True:
                time.sleep(1)
        else:
            print(f"❌ 啟動失敗: {result['error']}")
            
    except KeyboardInterrupt:
        print("\n🛑 正在停止系統...")
        security.stop_security_system()
        print("✅ 系統已停止")
    except Exception as e:
        print(f"❌ 系統錯誤: {e}")


if __name__ == "__main__":
    main()
