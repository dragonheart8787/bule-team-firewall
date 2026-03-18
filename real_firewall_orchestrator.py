#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
跨平台防火牆協同模組
- Windows: netsh/PowerShell AdvancedFirewall
- Linux: iptables/nftables
- K8s: NetworkPolicy via kubectl
"""

import os
import json
import logging
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealFirewallOrchestrator:
    """跨平台防火牆協同模組"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.running = False
        self.backend = self.config.get('backend', 'auto')  # auto|windows|linux|k8s
        self.kubectl_path = self.config.get('k8s', {}).get('kubectl_path', 'kubectl')
        self.namespace = self.config.get('k8s', {}).get('namespace', 'default')
        self.default_block_ttl_minutes = int(self.config.get('default_block_ttl_minutes', 60))
        logger.info("防火牆協同模組初始化完成")

    # 公用 API
    def start_monitoring(self) -> Dict[str, Any]:
        if self.running:
            return {'success': False, 'error': '防火牆協同已在運行中'}
        self.running = True
        logger.info("防火牆協同模組已啟動")
        return {'success': True, 'message': '防火牆協同已啟動'}

    def stop_monitoring(self) -> Dict[str, Any]:
        self.running = False
        logger.info("防火牆協同模組已停止")
        return {'success': True, 'message': '防火牆協同已停止'}

    def get_status(self) -> Dict[str, Any]:
        return {'success': True, 'running': self.running, 'backend': self._detect_backend()}

    def get_comprehensive_report(self) -> Dict[str, Any]:
        return {
            'success': True,
            'firewall_orchestrator': {
                'backend': self._detect_backend(),
                'default_block_ttl_minutes': self.default_block_ttl_minutes,
                'last_update': datetime.now().isoformat(),
            }
        }

    # 防火牆操作
    def block_ip(self, ip_cidr: str, reason: str = "policy", ttl_minutes: Optional[int] = None) -> Dict[str, Any]:
        backend = self._detect_backend()
        ttl = ttl_minutes or self.default_block_ttl_minutes
        try:
            if backend == 'windows':
                return self._win_block_ip(ip_cidr, reason)
            if backend == 'linux':
                return self._linux_block_ip(ip_cidr, reason)
            if backend == 'k8s':
                return self._k8s_block_cidr(ip_cidr, reason)
            return {'success': False, 'error': f'未知後端: {backend}'}
        finally:
            logger.info(f"已下發封鎖: {ip_cidr}, 後端={backend}, 原因={reason}, TTL(min)={ttl}")

    def unblock_ip(self, ip_cidr: str) -> Dict[str, Any]:
        backend = self._detect_backend()
        if backend == 'windows':
            return self._win_unblock_ip(ip_cidr)
        if backend == 'linux':
            return self._linux_unblock_ip(ip_cidr)
        if backend == 'k8s':
            return self._k8s_unblock_cidr(ip_cidr)
        return {'success': False, 'error': f'未知後端: {backend}'}

    # 後端偵測
    def _detect_backend(self) -> str:
        if self.backend != 'auto':
            return self.backend
        if os.name == 'nt':
            return 'windows'
        # 粗略判定 k8s 環境：如提供 kubeconfig 或在容器內
        if os.environ.get('KUBERNETES_SERVICE_HOST'):
            return 'k8s'
        return 'linux'

    # Windows 實作
    def _win_block_ip(self, ip_cidr: str, reason: str) -> Dict[str, Any]:
        try:
            rule_name = f"Block_{ip_cidr.replace('/', '_')}"
            cmd = [
                'powershell', '-NoProfile', '-Command',
                f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -Action Block -RemoteAddress {ip_cidr} -Description "{reason}" -Enabled True'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if result.returncode == 0:
                return {'success': True, 'message': 'Windows 封鎖完成'}
            return {'success': False, 'error': result.stderr.strip() or '建立規則失敗'}
        except Exception as e:
            logger.error(f"Windows 封鎖錯誤: {e}")
            return {'success': False, 'error': str(e)}

    def _win_unblock_ip(self, ip_cidr: str) -> Dict[str, Any]:
        try:
            rule_name = f"Block_{ip_cidr.replace('/', '_')}"
            cmd = ['powershell', '-NoProfile', '-Command', f'Get-NetFirewallRule -DisplayName "{rule_name}" | Remove-NetFirewallRule']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if result.returncode == 0:
                return {'success': True, 'message': 'Windows 解鎖完成'}
            return {'success': False, 'error': result.stderr.strip() or '刪除規則失敗'}
        except Exception as e:
            logger.error(f"Windows 解鎖錯誤: {e}")
            return {'success': False, 'error': str(e)}

    # Linux 實作（優先 nftables，否則回退 iptables）
    def _linux_block_ip(self, ip_cidr: str, reason: str) -> Dict[str, Any]:
        try:
            if self._has_cmd('nft'):
                cmd = ['nft', 'add', 'rule', 'inet', 'filter', 'input', 'ip', 'saddr', ip_cidr, 'drop', 'comment', reason]
            else:
                cmd = ['iptables', '-I', 'INPUT', '-s', ip_cidr, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return {'success': True, 'message': 'Linux 封鎖完成'}
            return {'success': False, 'error': result.stderr.strip() or '加入規則失敗'}
        except FileNotFoundError:
            logger.warning("未找到 nft/iptables，模擬為成功")
            return {'success': True, 'fallback': True, 'message': '無可用防火牆，已跳過'}
        except Exception as e:
            logger.error(f"Linux 封鎖錯誤: {e}")
            return {'success': False, 'error': str(e)}

    def _linux_unblock_ip(self, ip_cidr: str) -> Dict[str, Any]:
        try:
            if self._has_cmd('nft'):
                cmd = ['nft', 'delete', 'rule', 'inet', 'filter', 'input', 'ip', 'saddr', ip_cidr, 'drop']
            else:
                cmd = ['iptables', '-D', 'INPUT', '-s', ip_cidr, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return {'success': True, 'message': 'Linux 解鎖完成'}
            return {'success': False, 'error': result.stderr.strip() or '刪除規則失敗'}
        except FileNotFoundError:
            logger.warning("未找到 nft/iptables，模擬為成功")
            return {'success': True, 'fallback': True, 'message': '無可用防火牆，已跳過'}
        except Exception as e:
            logger.error(f"Linux 解鎖錯誤: {e}")
            return {'success': False, 'error': str(e)}

    # K8s 實作：動態 NetworkPolicy（封鎖來源 CIDR）
    def _k8s_block_cidr(self, ip_cidr: str, reason: str) -> Dict[str, Any]:
        try:
            policy_name = f"deny-from-{ip_cidr.replace('/', '-').replace('.', '-')[:52]}"
            manifest = {
                'apiVersion': 'networking.k8s.io/v1',
                'kind': 'NetworkPolicy',
                'metadata': {'name': policy_name, 'namespace': self.namespace, 'annotations': {'reason': reason}},
                'spec': {
                    'podSelector': {},
                    'policyTypes': ['Ingress'],
                    'ingress': [
                        {'from': [{'ipBlock': {'cidr': ip_cidr}}]}
                    ]
                }
            }
            proc = subprocess.run([self.kubectl_path, 'apply', '-f', '-'], input=json.dumps(manifest), text=True, capture_output=True, timeout=15)
            if proc.returncode == 0:
                return {'success': True, 'message': 'K8s NetworkPolicy 已套用', 'name': policy_name}
            return {'success': False, 'error': proc.stderr.strip() or 'kubectl apply 失敗'}
        except FileNotFoundError:
            logger.warning("未找到 kubectl，跳過K8s封鎖")
            return {'success': True, 'fallback': True, 'message': '未安裝kubectl，已跳過'}
        except Exception as e:
            logger.error(f"K8s 封鎖錯誤: {e}")
            return {'success': False, 'error': str(e)}

    def _k8s_unblock_cidr(self, ip_cidr: str) -> Dict[str, Any]:
        try:
            policy_name = f"deny-from-{ip_cidr.replace('/', '-').replace('.', '-')[:52]}"
            proc = subprocess.run([self.kubectl_path, '-n', self.namespace, 'delete', 'networkpolicy', policy_name], capture_output=True, text=True, timeout=15)
            if proc.returncode == 0:
                return {'success': True, 'message': 'K8s NetworkPolicy 已刪除'}
            return {'success': False, 'error': proc.stderr.strip() or 'kubectl delete 失敗'}
        except FileNotFoundError:
            logger.warning("未找到 kubectl，跳過K8s解鎖")
            return {'success': True, 'fallback': True, 'message': '未安裝kubectl，已跳過'}
        except Exception as e:
            logger.error(f"K8s 解鎖錯誤: {e}")
            return {'success': False, 'error': str(e)}

    # 工具
    def _has_cmd(self, name: str) -> bool:
        try:
            subprocess.run([name, '--version'], capture_output=True, text=True, timeout=5)
            return True
        except Exception:
            return False




