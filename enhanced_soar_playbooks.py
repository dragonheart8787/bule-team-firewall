#!/usr/bin/env python3
"""
強化SOAR藍隊劇本
封鎖/隔離/通知/證據化
"""

import json
import time
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum
import subprocess
import os

class PlaybookStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class PlaybookAction:
    """劇本動作基類"""
    
    def __init__(self, action_id: str, name: str, description: str):
        self.action_id = action_id
        self.name = name
        self.description = description
        self.status = PlaybookStatus.PENDING
        self.start_time = None
        self.end_time = None
        self.result = None
        self.error = None
    
    def execute(self, context: Dict) -> Dict:
        """執行動作"""
        self.status = PlaybookStatus.RUNNING
        self.start_time = datetime.now()
        
        try:
            result = self._execute_impl(context)
            self.status = PlaybookStatus.COMPLETED
            self.result = result
            return result
        except Exception as e:
            self.status = PlaybookStatus.FAILED
            self.error = str(e)
            raise
        finally:
            self.end_time = datetime.now()
    
    def _execute_impl(self, context: Dict) -> Dict:
        """實現具體的執行邏輯"""
        raise NotImplementedError

class BlockIPAction(PlaybookAction):
    """封鎖IP動作"""
    
    def __init__(self):
        super().__init__("block_ip", "封鎖IP地址", "使用防火牆封鎖惡意IP")
    
    def _execute_impl(self, context: Dict) -> Dict:
        ip = context.get('src_ip')
        if not ip:
            raise ValueError("缺少來源IP")
        
        # 使用Windows防火牆封鎖
        cmd = [
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name=SOAR-Block-{ip}',
            'dir=in',
            'action=block',
            f'remoteip={ip}',
            'enable=yes'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            return {
                'success': True,
                'message': f'成功封鎖IP {ip}',
                'blocked_ip': ip
            }
        else:
            raise Exception(f'封鎖IP失敗: {result.stderr}')

class IsolateHostAction(PlaybookAction):
    """隔離主機動作"""
    
    def __init__(self):
        super().__init__("isolate_host", "隔離主機", "將受感染主機隔離到隔離網段")
    
    def _execute_impl(self, context: Dict) -> Dict:
        host_ip = context.get('host_ip')
        if not host_ip:
            raise ValueError("缺少主機IP")
        
        # 模擬隔離操作
        isolation_commands = [
            f'將主機 {host_ip} 移動到隔離網段',
            f'更新網路配置以隔離 {host_ip}',
            f'通知網路管理員隔離 {host_ip}'
        ]
        
        # 記錄隔離操作
        isolation_log = {
            'host_ip': host_ip,
            'timestamp': datetime.now().isoformat(),
            'actions': isolation_commands,
            'status': 'isolated'
        }
        
        return {
            'success': True,
            'message': f'主機 {host_ip} 已隔離',
            'isolation_log': isolation_log
        }

class SendNotificationAction(PlaybookAction):
    """發送通知動作"""
    
    def __init__(self, notification_type: str = "email"):
        super().__init__("send_notification", "發送通知", f"發送{notification_type}通知")
        self.notification_type = notification_type
    
    def _execute_impl(self, context: Dict) -> Dict:
        alert = context.get('alert', {})
        recipients = context.get('recipients', ['admin@company.com'])
        
        # 構建通知內容
        subject = f"安全告警: {alert.get('rule_name', 'Unknown')}"
        body = f"""
安全告警詳情:
- 規則: {alert.get('rule_name', 'Unknown')}
- 嚴重度: {alert.get('severity', 'Unknown')}
- 來源IP: {alert.get('event', {}).get('src_ip', 'Unknown')}
- 時間: {alert.get('timestamp', 'Unknown')}
- 描述: {alert.get('event', {}).get('description', 'No description')}

請立即檢查並採取相應措施。
        """
        
        # 模擬發送通知
        notification = {
            'type': self.notification_type,
            'recipients': recipients,
            'subject': subject,
            'body': body,
            'timestamp': datetime.now().isoformat(),
            'sent': True
        }
        
        return {
            'success': True,
            'message': f'通知已發送給 {len(recipients)} 個收件人',
            'notification': notification
        }

class CollectEvidenceAction(PlaybookAction):
    """收集證據動作"""
    
    def __init__(self):
        super().__init__("collect_evidence", "收集證據", "收集和保存攻擊證據")
    
    def _execute_evidence(self, context: Dict) -> Dict:
        alert = context.get('alert', {})
        evidence_dir = f"evidence/{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # 創建證據目錄
        os.makedirs(evidence_dir, exist_ok=True)
        
        # 收集各種證據
        evidence = {
            'alert_data': alert,
            'network_logs': self._collect_network_logs(alert),
            'system_logs': self._collect_system_logs(alert),
            'memory_dump': self._collect_memory_dump(alert),
            'file_hashes': self._collect_file_hashes(alert),
            'timeline': self._create_timeline(alert)
        }
        
        # 保存證據到文件
        evidence_file = f"{evidence_dir}/evidence.json"
        with open(evidence_file, 'w', encoding='utf-8') as f:
            json.dump(evidence, f, indent=2, ensure_ascii=False)
        
        return {
            'success': True,
            'message': f'證據已收集到 {evidence_dir}',
            'evidence_dir': evidence_dir,
            'evidence_files': [evidence_file]
        }
    
    def _collect_network_logs(self, alert: Dict) -> Dict:
        """收集網路日誌"""
        return {
            'firewall_logs': '模擬防火牆日誌',
            'proxy_logs': '模擬代理日誌',
            'dns_logs': '模擬DNS日誌'
        }
    
    def _collect_system_logs(self, alert: Dict) -> Dict:
        """收集系統日誌"""
        return {
            'windows_logs': '模擬Windows事件日誌',
            'application_logs': '模擬應用程式日誌',
            'security_logs': '模擬安全日誌'
        }
    
    def _collect_memory_dump(self, alert: Dict) -> Dict:
        """收集記憶體轉儲"""
        return {
            'process_list': '模擬進程列表',
            'network_connections': '模擬網路連接',
            'loaded_modules': '模擬載入模組'
        }
    
    def _collect_file_hashes(self, alert: Dict) -> Dict:
        """收集檔案雜湊"""
        return {
            'suspicious_files': ['file1.exe', 'file2.dll'],
            'hashes': {
                'file1.exe': 'abc123def456',
                'file2.dll': 'def456ghi789'
            }
        }
    
    def _create_timeline(self, alert: Dict) -> List[Dict]:
        """創建時間線"""
        return [
            {
                'timestamp': alert.get('timestamp'),
                'event': '告警觸發',
                'details': alert.get('rule_name')
            },
            {
                'timestamp': datetime.now().isoformat(),
                'event': '證據收集開始',
                'details': '開始收集攻擊證據'
            }
        ]

class SOARPlaybook:
    """SOAR劇本"""
    
    def __init__(self, playbook_id: str, name: str, description: str):
        self.playbook_id = playbook_id
        self.name = name
        self.description = description
        self.actions = []
        self.conditions = []
        self.status = PlaybookStatus.PENDING
        self.start_time = None
        self.end_time = None
        self.results = []
        self.logger = logging.getLogger(f"playbook.{playbook_id}")
    
    def add_action(self, action: PlaybookAction):
        """添加動作"""
        self.actions.append(action)
    
    def add_condition(self, field: str, operator: str, value: Any):
        """添加觸發條件"""
        self.conditions.append({
            'field': field,
            'operator': operator,
            'value': value
        })
    
    def should_trigger(self, context: Dict) -> bool:
        """檢查是否應該觸發劇本"""
        for condition in self.conditions:
            field_value = self._get_field_value(context, condition['field'])
            if not self._evaluate_condition(field_value, condition['operator'], condition['value']):
                return False
        return True
    
    def _get_field_value(self, context: Dict, field: str) -> Any:
        """獲取字段值"""
        if '.' in field:
            parts = field.split('.')
            value = context
            for part in parts:
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    return None
            return value
        else:
            return context.get(field)
    
    def _evaluate_condition(self, field_value: Any, operator: str, expected_value: Any) -> bool:
        """評估條件"""
        if field_value is None:
            return False
        
        if operator == 'equals':
            return field_value == expected_value
        elif operator == 'contains':
            return expected_value in str(field_value)
        elif operator == 'greater_than':
            return field_value > expected_value
        elif operator == 'less_than':
            return field_value < expected_value
        
        return False
    
    def execute(self, context: Dict) -> Dict:
        """執行劇本"""
        if not self.should_trigger(context):
            return {
                'success': False,
                'message': '劇本條件不滿足',
                'playbook_id': self.playbook_id
            }
        
        self.status = PlaybookStatus.RUNNING
        self.start_time = datetime.now()
        self.results = []
        
        self.logger.info(f"開始執行劇本: {self.name}")
        
        try:
            for action in self.actions:
                self.logger.info(f"執行動作: {action.name}")
                result = action.execute(context)
                self.results.append({
                    'action_id': action.action_id,
                    'action_name': action.name,
                    'status': action.status.value,
                    'result': result,
                    'error': action.error
                })
                
                # 如果動作失敗，停止執行
                if action.status == PlaybookStatus.FAILED:
                    self.status = PlaybookStatus.FAILED
                    break
            
            if self.status == PlaybookStatus.RUNNING:
                self.status = PlaybookStatus.COMPLETED
            
            self.end_time = datetime.now()
            
            return {
                'success': self.status == PlaybookStatus.COMPLETED,
                'playbook_id': self.playbook_id,
                'status': self.status.value,
                'results': self.results,
                'execution_time': (self.end_time - self.start_time).total_seconds()
            }
            
        except Exception as e:
            self.status = PlaybookStatus.FAILED
            self.end_time = datetime.now()
            self.logger.error(f"劇本執行失敗: {e}")
            
            return {
                'success': False,
                'playbook_id': self.playbook_id,
                'status': self.status.value,
                'error': str(e),
                'results': self.results
            }

class SOARPlaybookManager:
    """SOAR劇本管理器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.playbooks = {}
        self.execution_history = []
        self.load_default_playbooks()
    
    def load_default_playbooks(self):
        """載入默認劇本"""
        # 惡意IP封鎖劇本
        block_malicious_ip = SOARPlaybook(
            "PB001", "惡意IP封鎖劇本",
            "檢測到惡意IP時自動封鎖"
        )
        block_malicious_ip.add_condition('alert.severity', 'equals', 'HIGH')
        block_malicious_ip.add_condition('alert.event.src_ip', 'contains', '192.168.')
        block_malicious_ip.add_action(BlockIPAction())
        block_malicious_ip.add_action(SendNotificationAction())
        self.add_playbook(block_malicious_ip)
        
        # 主機隔離劇本
        isolate_host = SOARPlaybook(
            "PB002", "主機隔離劇本",
            "檢測到受感染主機時自動隔離"
        )
        isolate_host.add_condition('alert.rule_name', 'contains', 'malware')
        isolate_host.add_condition('alert.severity', 'equals', 'CRITICAL')
        isolate_host.add_action(IsolateHostAction())
        isolate_host.add_action(CollectEvidenceAction())
        isolate_host.add_action(SendNotificationAction())
        self.add_playbook(isolate_host)
        
        # 證據收集劇本
        collect_evidence = SOARPlaybook(
            "PB003", "證據收集劇本",
            "檢測到攻擊時自動收集證據"
        )
        collect_evidence.add_condition('alert.severity', 'equals', 'CRITICAL')
        collect_evidence.add_action(CollectEvidenceAction())
        collect_evidence.add_action(SendNotificationAction())
        self.add_playbook(collect_evidence)
        
        # 通知升級劇本
        escalate_notification = SOARPlaybook(
            "PB004", "通知升級劇本",
            "高嚴重度告警時升級通知"
        )
        escalate_notification.add_condition('alert.severity', 'equals', 'CRITICAL')
        escalate_notification.add_action(SendNotificationAction('sms'))
        escalate_notification.add_action(SendNotificationAction('email'))
        self.add_playbook(escalate_notification)
    
    def add_playbook(self, playbook: SOARPlaybook):
        """添加劇本"""
        self.playbooks[playbook.playbook_id] = playbook
        self.logger.info(f"添加劇本: {playbook.name}")
    
    def process_alert(self, alert: Dict) -> List[Dict]:
        """處理告警"""
        context = {'alert': alert}
        executed_playbooks = []
        
        for playbook in self.playbooks.values():
            if playbook.should_trigger(context):
                self.logger.info(f"觸發劇本: {playbook.name}")
                result = playbook.execute(context)
                executed_playbooks.append(result)
                self.execution_history.append({
                    'timestamp': datetime.now().isoformat(),
                    'playbook_id': playbook.playbook_id,
                    'playbook_name': playbook.name,
                    'alert': alert,
                    'result': result
                })
        
        return executed_playbooks
    
    def get_execution_history(self, limit: int = 100) -> List[Dict]:
        """獲取執行歷史"""
        return self.execution_history[-limit:]
    
    def get_playbook_status(self) -> Dict:
        """獲取劇本狀態"""
        status = {
            'total_playbooks': len(self.playbooks),
            'playbooks': {}
        }
        
        for playbook_id, playbook in self.playbooks.items():
            status['playbooks'][playbook_id] = {
                'name': playbook.name,
                'status': playbook.status.value,
                'actions_count': len(playbook.actions),
                'conditions_count': len(playbook.conditions)
            }
        
        return status

def test_soar_playbooks():
    """測試SOAR劇本"""
    print("測試SOAR劇本系統...")
    
    manager = SOARPlaybookManager()
    
    # 測試告警
    test_alerts = [
        {
            'rule_name': 'SSH暴力破解檢測',
            'severity': 'HIGH',
            'event': {
                'src_ip': '192.168.1.100',
                'dest_ip': '192.168.1.1',
                'description': '檢測到SSH暴力破解攻擊'
            },
            'timestamp': datetime.now().isoformat()
        },
        {
            'rule_name': '惡意軟體檢測',
            'severity': 'CRITICAL',
            'event': {
                'src_ip': '10.0.0.50',
                'dest_ip': '192.168.1.10',
                'description': '檢測到惡意軟體'
            },
            'timestamp': datetime.now().isoformat()
        }
    ]
    
    # 處理告警
    for alert in test_alerts:
        print(f"\n處理告警: {alert['rule_name']}")
        results = manager.process_alert(alert)
        for result in results:
            print(f"  劇本結果: {result}")
    
    # 顯示狀態
    status = manager.get_playbook_status()
    print(f"\n劇本狀態: {json.dumps(status, indent=2, ensure_ascii=False)}")
    
    print("SOAR劇本測試完成")

if __name__ == "__main__":
    test_soar_playbooks()

