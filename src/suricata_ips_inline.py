#!/usr/bin/env python3
"""
Suricata IPS 內聯配置模組
Windows 環境下的被動監控與自動封鎖
"""

import os
import json
import time
import subprocess
import logging
from datetime import datetime
from typing import Dict, List, Optional
import threading

class SuricataIPSInline:
    """Suricata IPS 內聯管理器"""
    
    def __init__(self, config_file: str = "config/suricata.yaml"):
        self.logger = logging.getLogger(__name__)
        self.config_file = config_file
        self.eve_log_path = r"C:\ProgramData\Suricata\logs\eve.json"
        self.running = False
        self.monitor_thread = None
        self.blocked_ips = set()
        self.whitelist = set()
        self.load_config()
    
    def load_config(self):
        """載入配置"""
        self.config = {
            'severity_threshold': 2,  # 只處理嚴重度 <= 2 的告警
            'block_duration': 3600,   # 封鎖時間（秒）
            'max_blocked_ips': 1000,  # 最大封鎖IP數
            'whitelist_ips': [
                '127.0.0.1',
                '::1',
                '192.168.1.0/24',  # 內網段
                '10.0.0.0/8'        # 內網段
            ]
        }
        
        # 載入白名單
        for ip in self.config['whitelist_ips']:
            self.whitelist.add(ip)
    
    def is_ip_whitelisted(self, ip: str) -> bool:
        """檢查IP是否在白名單中"""
        for whitelist_ip in self.whitelist:
            if '/' in whitelist_ip:  # CIDR格式
                if self._ip_in_cidr(ip, whitelist_ip):
                    return True
            else:  # 單一IP
                if ip == whitelist_ip:
                    return True
        return False
    
    def _ip_in_cidr(self, ip: str, cidr: str) -> bool:
        """檢查IP是否在CIDR範圍內"""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
        except:
            return False
    
    def parse_eve_log(self, log_line: str) -> Optional[Dict]:
        """解析EVE日誌行"""
        try:
            event = json.loads(log_line.strip())
            
            # 只處理告警事件
            if event.get('event_type') != 'alert':
                return None
            
            alert = event.get('alert', {})
            severity = alert.get('severity', 99)
            
            # 只處理高嚴重度告警
            if severity > self.config['severity_threshold']:
                return None
            
            return {
                'timestamp': event.get('timestamp'),
                'severity': severity,
                'signature': alert.get('signature', 'Unknown'),
                'src_ip': event.get('src_ip'),
                'dest_ip': event.get('dest_ip'),
                'proto': event.get('proto'),
                'sport': event.get('sport'),
                'dport': event.get('dport')
            }
        except Exception as e:
            self.logger.error(f"解析EVE日誌失敗: {e}")
            return None
    
    def block_ip(self, ip: str, reason: str):
        """封鎖IP地址"""
        if self.is_ip_whitelisted(ip):
            self.logger.info(f"IP {ip} 在白名單中，跳過封鎖")
            return False
        
        if ip in self.blocked_ips:
            self.logger.info(f"IP {ip} 已被封鎖")
            return True
        
        try:
            # 使用Windows防火牆封鎖
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=f"Suricata-Block-{ip}"',
                'dir=in',
                'action=block',
                f'remoteip={ip}',
                'enable=yes'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                self.logger.info(f"成功封鎖IP {ip}: {reason}")
                
                # 設定自動解封時間
                threading.Timer(
                    self.config['block_duration'],
                    self.unblock_ip,
                    args=[ip]
                ).start()
                
                return True
            else:
                self.logger.error(f"封鎖IP {ip} 失敗: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"封鎖IP {ip} 時發生錯誤: {e}")
            return False
    
    def unblock_ip(self, ip: str):
        """解封IP地址"""
        try:
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name=Suricata-Block-{ip}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.blocked_ips.discard(ip)
                self.logger.info(f"成功解封IP {ip}")
            else:
                self.logger.warning(f"解封IP {ip} 失敗: {result.stderr}")
                
        except Exception as e:
            self.logger.error(f"解封IP {ip} 時發生錯誤: {e}")
    
    def monitor_eve_log(self):
        """監控EVE日誌文件"""
        if not os.path.exists(self.eve_log_path):
            self.logger.warning(f"EVE日誌文件不存在: {self.eve_log_path}")
            return
        
        self.logger.info(f"開始監控EVE日誌: {self.eve_log_path}")
        
        with open(self.eve_log_path, 'r', encoding='utf-8') as f:
            # 跳到文件末尾
            f.seek(0, 2)
            
            while self.running:
                line = f.readline()
                if line:
                    event = self.parse_eve_log(line)
                    if event:
                        self.process_alert(event)
                else:
                    time.sleep(1)  # 沒有新日誌時等待
    
    def process_alert(self, alert: Dict):
        """處理告警事件"""
        src_ip = alert.get('src_ip')
        if not src_ip:
            return
        
        # 檢查是否已達到最大封鎖數量
        if len(self.blocked_ips) >= self.config['max_blocked_ips']:
            self.logger.warning("已達到最大封鎖IP數量限制")
            return
        
        reason = f"{alert['signature']} (嚴重度: {alert['severity']})"
        self.block_ip(src_ip, reason)
    
    def start_monitoring(self):
        """開始監控"""
        if self.running:
            self.logger.warning("監控已在運行中")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self.monitor_eve_log)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.logger.info("Suricata IPS 監控已啟動")
    
    def stop_monitoring(self):
        """停止監控"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("Suricata IPS 監控已停止")
    
    def get_status(self) -> Dict:
        """獲取狀態信息"""
        return {
            'running': self.running,
            'blocked_ips_count': len(self.blocked_ips),
            'blocked_ips': list(self.blocked_ips),
            'whitelist_count': len(self.whitelist),
            'config': self.config
        }

def test_suricata_ips():
    """測試Suricata IPS功能"""
    print("測試Suricata IPS內聯模組...")
    
    ips = SuricataIPSInline()
    
    # 測試白名單檢查
    print(f"127.0.0.1 在白名單中: {ips.is_ip_whitelisted('127.0.0.1')}")
    print(f"192.168.1.100 在白名單中: {ips.is_ip_whitelisted('192.168.1.100')}")
    print(f"8.8.8.8 在白名單中: {ips.is_ip_whitelisted('8.8.8.8')}")
    
    # 顯示狀態
    status = ips.get_status()
    print(f"狀態: {status}")
    
    print("Suricata IPS 測試完成")

if __name__ == "__main__":
    test_suricata_ips()

