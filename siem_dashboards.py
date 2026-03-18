#!/usr/bin/env python3
"""
SIEM儀表板與規則系統
ELK/ATT&CK覆蓋的SOC儀表板
"""

import json
import time
import logging
import os
import asyncio
from queue import Queue
from datetime import datetime, timedelta
from typing import Dict, List, Any
from collections import defaultdict, Counter
import threading
from fastapi import FastAPI
from starlette.responses import JSONResponse
import uvicorn
import requests

# ==============================================================================
# 1. 結構化日誌 (JSON Logging)
# ==============================================================================
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "source": "siem_engine"
        }
        # 將 logging.extra 內容併入輸出（若存在）
        for key, value in record.__dict__.items():
            if key not in (
                'name','msg','args','levelname','levelno','pathname','filename','module',
                'exc_info','exc_text','stack_info','lineno','funcName','created','msecs',
                'relativeCreated','thread','threadName','processName','process'
            ):
                # 避免覆蓋核心欄位
                if key not in log_record:
                    log_record[key] = value
        return json.dumps(log_record)

def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)

setup_logging()

# ==============================================================================
# 2. 外部化設定 (Externalized Configuration)
# ==============================================================================
RANSOMWARE_FILE_COUNT_THRESHOLD = int(os.environ.get("RANSOMWARE_FILE_COUNT_THRESHOLD", 100))
CORRELATION_ALERT_THRESHOLD = int(os.environ.get("CORRELATION_ALERT_THRESHOLD", 3))
CORRELATION_WINDOW_MINUTES = int(os.environ.get("CORRELATION_WINDOW_MINUTES", 5))
C2_BEACONING_INTERVAL_SECONDS = int(os.environ.get("C2_BEACONING_INTERVAL_SECONDS", 60))
C2_BEACONING_THRESHOLD = int(os.environ.get("C2_BEACONING_THRESHOLD", 10))
WAF_BASE_URL = os.environ.get("WAF_BASE_URL", "http://localhost:8080")

# 固定 SLO 門檻（與文件一致）
SLO_THRESHOLDS = {
    "availability": float(os.environ.get("SLO_AVAILABILITY", 99.95)),
    "https_p95_ms": float(os.environ.get("SLO_HTTPS_P95_MS", 220.0)),
    "error_rate": float(os.environ.get("SLO_ERROR_RATE", 0.1))
}


class ATTACKFramework:
    """MITRE ATT&CK框架映射"""
    
    def __init__(self):
        self.tactics = {
            'TA0001': 'Initial Access',
            'TA0002': 'Execution',
            'TA0003': 'Persistence',
            'TA0004': 'Privilege Escalation',
            'TA0005': 'Defense Evasion',
            'TA0006': 'Credential Access',
            'TA0007': 'Discovery',
            'TA0008': 'Lateral Movement',
            'TA0009': 'Collection',
            'TA0010': 'Exfiltration',
            'TA0011': 'Command and Control',
            'TA0040': 'Impact'
        }
        
        self.techniques = {
            'T1071': 'Application Layer Protocol',
            'T1078': 'Valid Accounts',
            'T1055': 'Process Injection',
            'T1027': 'Obfuscated Files or Information',
            'T1059': 'Command and Scripting Interpreter',
            'T1083': 'File and Directory Discovery',
            'T1018': 'Remote System Discovery',
            'T1041': 'Exfiltration Over C2 Channel',
            'T1048': 'Exfiltration Over Alternative Protocol',
            'T1074': 'Data Staged',
            'T1001': 'Data Obfuscation',
            'T1021': 'Remote Services'
        }
    
    def get_tactic_name(self, tactic_id: str) -> str:
        """獲取戰術名稱"""
        return self.tactics.get(tactic_id, 'Unknown')
    
    def get_technique_name(self, technique_id: str) -> str:
        """獲取技術名稱"""
        # 擴充以包含子技術
        technique_map = {
            'T1071.001': 'Web Protocols',
            'T1003.001': 'LSASS Memory',
            'T1566.001': 'Spearphishing Attachment',
            'T1059.003': 'Windows Command Shell',
            'T1053.005': 'Scheduled Task',
            'T1021.002': 'SMB/Windows Admin Shares',
            'T1486': 'Data Encrypted for Impact',
            'T1078': 'Valid Accounts',
            'T1610': 'Container Escape'
        }
        base_id = technique_id.split('.')[0]
        return technique_map.get(technique_id, self.techniques.get(base_id, 'Unknown'))
    
    def map_event_to_attack(self, event: Dict) -> List[str]:
        """將事件映射到ATT&CK技術"""
        mapped_techniques = []
        
        event_type = event.get('event_type', '')
        
        if 'ssh' in event_type.lower():
            mapped_techniques.append('T1078')
        elif 'http' in event_type.lower():
            mapped_techniques.append('T1071')
        elif event.get('process_name') == 'cmd.exe' and 'whoami' in event.get('command_line', ''):
             mapped_techniques.append('T1059.003')
        elif 'injection' in event_type.lower():
            mapped_techniques.append('T1055')
        
        return mapped_techniques

class SIEMRule:
    """SIEM規則"""
    
    def __init__(self, rule_id: str, name: str, description: str, 
                 severity: str = "MEDIUM", enabled: bool = True):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.enabled = enabled
        self.conditions = []
        self.actions = []
        self.trigger_count = 0
        self.last_triggered = None
        self.soar_playbook_id = None
    
    def add_condition(self, field: str, operator: str, value: Any):
        self.conditions.append({'field': field, 'operator': operator, 'value': value})
    
    def add_action(self, action_type: str, params: Dict = None):
        self.actions.append({'type': action_type, 'params': params or {}})
    
    def evaluate(self, event: Dict) -> bool:
        if not self.enabled:
            return False
        
        for condition in self.conditions:
            field_value = self._get_field_value(event, condition['field'])
            if not self._evaluate_condition(field_value, condition['operator'], condition['value']):
                return False
        
        return True
    
    def _get_field_value(self, event: Dict, field: str) -> Any:
        if '.' in field:
            parts = field.split('.')
            value = event
            for part in parts:
                value = value.get(part) if isinstance(value, dict) else None
                if value is None: return None
            return value
        else:
            return event.get(field)
    
    def _evaluate_condition(self, field_value: Any, operator: str, expected_value: Any) -> bool:
        if field_value is None: return False
        if operator == 'equals': return field_value == expected_value
        if operator == 'contains': return expected_value in str(field_value)
        if operator == 'starts_with': return str(field_value).startswith(str(expected_value))
        if operator == 'ends_with': return str(field_value).endswith(str(expected_value))
        if operator == 'greater_than': return field_value > expected_value
        if operator == 'less_than': return field_value < expected_value
        if operator == 'regex':
            import re
            return bool(re.search(expected_value, str(field_value)))
        return False
    
    def trigger(self, event: Dict):
        self.trigger_count += 1
        self.last_triggered = datetime.now()
        # 執行動作的邏輯將移至 SOCDashboard
    
    def _execute_action(self, action: Dict, event: Dict):
        action_type, ip = action['type'], event.get('src_ip')
        if action_type == 'alert': print(f"ALERT: {self.name} - {self.description}")
        elif action_type == 'block_ip' and ip: print(f"BLOCK IP: {ip}")
        elif action_type == 'log': print(f"LOG: {self.name} triggered by {event.get('src_ip', 'unknown')}")

    def set_soar_playbook(self, playbook_id: str):
        """為此規則綁定一個 SOAR Playbook"""
        self.soar_playbook_id = playbook_id

class SOCDashboard:
    """SOC儀表板"""
    
    def __init__(self):
        self.event_queue = Queue()
        self.rules: Dict[str, SIEMRule] = {}
        self.events: List[Dict] = []
        self.alerts: List[Dict] = []
        self.attack_framework = ATTACKFramework()
        self.metrics = {
            'total_events': 0, 'total_alerts': 0, 'blocked_ips': set(),
            'attack_techniques': Counter(), 'severity_counts': Counter(),
            'hourly_events': defaultdict(int),
            'processing_times': []
        }
        # 初始化狀態追蹤器
        self._ransomware_tracker = {}
        self._cloud_logon_tracker = defaultdict(set) # 用於 R012
        self._c2_beacon_tracker = defaultdict(list) # 用於 R016
        self.load_default_rules()
        self._initialize_soar_playbooks() # 初始化 SOAR
        # SLO 狀態
        self.slo_thresholds = dict(SLO_THRESHOLDS)
        self.last_slo = {}
        # 啟動 SLO 監控
        self._slo_thread = threading.Thread(target=self._slo_monitor_loop, daemon=True)
        self._slo_thread.start()
        
        # 啟動事件處理工作執行緒
        self.processing_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.processing_thread.start()
    
    def shutdown(self):
        """優雅地關閉背景執行緒"""
        self.event_queue.put(None)
        self.processing_thread.join()
        # 無需顯式停止 SLO 監控執行緒（daemon）

    def _slo_monitor_loop(self):
        """定期從 WAF 讀取 /slo，若違反門檻則產生告警"""
        while True:
            try:
                resp = requests.get(f"{WAF_BASE_URL}/slo", timeout=3)
                if resp.status_code == 200:
                    data = resp.json()
                    self.last_slo = data
                    passed = data.get('passed', {})
                    # 若任一指標不達標，產生 SIEM 告警
                    violations = [k for k, v in passed.items() if v is False]
                    if violations:
                        event = {
                            'event_type': 'slo_violation',
                            'violations': violations,
                            'slo': data,
                            'timestamp': datetime.now().isoformat()
                        }
                        # 直接建立一筆特殊告警（不走規則引擎）
                        alert_like_rule = SIEMRule('SLO001', 'SLO違反告警', 'WAF SLO 指標未達標', 'HIGH')
                        self._create_alert(alert_like_rule, event)
                # 間隔 15 秒
                time.sleep(15)
            except Exception as e:
                logging.warning("SLO monitor error", extra={"error": str(e)})
                time.sleep(15)

    def _initialize_soar_playbooks(self):
        """初始化 SOAR Playbook"""
        self.playbooks = {
            'PB001_BLOCK_IP_AT_WAF': self.playbook_block_ip_at_waf
        }
        # 模擬 WAF 的 API 或控制介面
        self.waf_instance = WAFControlInterface()

    def load_default_rules(self):
        brute_force_rule = SIEMRule('R001', 'SSH暴力破解檢測', '檢測SSH登錄失敗次數過多', 'HIGH')
        brute_force_rule.add_condition('event_type', 'equals', 'ssh_failed_login')
        brute_force_rule.add_condition('count', 'greater_than', 5)
        self.add_rule(brute_force_rule)
        
        sql_injection_rule = SIEMRule('R002', 'SQL注入攻擊檢測', '檢測SQL注入攻擊模式', 'CRITICAL')
        sql_injection_rule.add_condition('event_type', 'equals', 'web_request')
        sql_injection_rule.add_condition('payload', 'regex', r'(union|select|insert|delete|drop|update).*from')
        self.add_rule(sql_injection_rule)

        anomaly_rule = SIEMRule('R003', '異常流量檢測', '檢測異常高的流量', 'MEDIUM')
        anomaly_rule.add_condition('event_type', 'equals', 'network_flow')
        anomaly_rule.add_condition('bytes', 'greater_than', 1000000)
        self.add_rule(anomaly_rule)

        lateral_movement_rule = SIEMRule('R004', '橫向移動檢測', '檢測內部網路橫向移動', 'HIGH')
        lateral_movement_rule.add_condition('event_type', 'equals', 'lateral_movement')
        lateral_movement_rule.add_condition('src_ip', 'regex', r'192\.168\.\d+\.\d+')
        lateral_movement_rule.add_condition('dest_ip', 'regex', r'192\.168\.\d+\.\d+')
        self.add_rule(lateral_movement_rule)

        suspicious_cmd_rule = SIEMRule('R005', '可疑的命令列活動 (T1059.003)', '檢測到 cmd.exe 執行了可疑的指令', 'HIGH')
        suspicious_cmd_rule.add_condition('event_type', 'equals', 'process_creation')
        suspicious_cmd_rule.add_condition('process_name', 'equals', 'cmd.exe')
        suspicious_cmd_rule.add_condition('command_line', 'regex', r'(whoami|net user|systeminfo|tasklist|certutil|bitsadmin)')
        self.add_rule(suspicious_cmd_rule)
        
        lsass_dump_rule = SIEMRule('R006', 'OS憑證傾印: LSASS記憶體 (T1003.001)', '檢測到針對LSASS行程的可疑存取', 'CRITICAL')
        lsass_dump_rule.add_condition('event_type', 'equals', 'process_access')
        lsass_dump_rule.add_condition('target_process_name', 'equals', 'lsass.exe')
        lsass_dump_rule.add_condition('source_process_name', 'regex', r'(procdump\.exe|rundll32\.exe|taskmgr\.exe)')
        self.add_rule(lsass_dump_rule)

        c2_traffic_rule = SIEMRule('R007', 'C2通訊: 連線至已知惡意域名 (T1071.001)', '檢測到網路連線至已知的C2伺服器', 'HIGH')
        c2_traffic_rule.add_condition('event_type', 'equals', 'network_connection')
        c2_traffic_rule.add_condition('dest_domain', 'regex', r'(evil-c2\.com|malicious-domain\.net|not-a-legit-site\.org)')
        self.add_rule(c2_traffic_rule)

        phishing_attachment_rule = SIEMRule('R008', '釣魚附件: Office應用程式產生可疑子程序 (T1566.001)', '檢測到Office應用程式 (如Word, Excel) 產生了可疑的子程序', 'HIGH')
        phishing_attachment_rule.add_condition('event_type', 'equals', 'process_creation')
        phishing_attachment_rule.add_condition('parent_process_name', 'regex', r'(winword\.exe|excel\.exe|powerpnt\.exe)')
        phishing_attachment_rule.add_condition('process_name', 'regex', r'(powershell\.exe|cmd\.exe|wscript\.exe|mshta\.exe)')
        self.add_rule(phishing_attachment_rule)

        ransomware_rule = SIEMRule('R009', '勒索軟體行為: 大量檔案重新命名 (T1486)', '檢測到單一程序在短時間內大量重新命名檔案', 'CRITICAL')
        ransomware_rule.add_condition('event_type', 'equals', 'file_renamed')
        ransomware_rule.add_condition('rename_count', 'greater_than', RANSOMWARE_FILE_COUNT_THRESHOLD) 
        self.add_rule(ransomware_rule)

        scheduled_task_rule = SIEMRule('R010', '持久化: 建立可疑的排程任務 (T1053.005)', '檢測到使用 schtasks.exe 建立新的排程任務', 'HIGH')
        scheduled_task_rule.add_condition('event_type', 'equals', 'process_creation')
        scheduled_task_rule.add_condition('process_name', 'equals', 'schtasks.exe')
        scheduled_task_rule.add_condition('command_line', 'regex', r'\/create')
        self.add_rule(scheduled_task_rule)

        lateral_movement_rule_smb = SIEMRule('R011', '橫向移動: 存取管理員共用 (T1021.002)', '檢測到對遠端主機的管理員共用資料夾 (C$, ADMIN$) 的存取', 'CRITICAL')
        lateral_movement_rule_smb.add_condition('event_type', 'equals', 'smb_connection')
        lateral_movement_rule_smb.add_condition('share_name', 'regex', r'\\\\[^\\]+\\(C|ADMIN)\$')
        lateral_movement_rule_smb.add_condition('source_hostname', 'regex', r'^(?!BACKUP-SRV|ADMIN-PC).*') 
        self.add_rule(lateral_movement_rule_smb)

        correlated_attack_rule = SIEMRule('C001', '多階段攻擊 (攻擊鏈)', '在短時間內從單一來源偵測到多個高嚴重性警報', 'CRITICAL')
        self.add_rule(correlated_attack_rule)

        cloud_logon_anomaly_rule = SIEMRule('R012', '雲端登入異常: 從未見過的國家登入 (T1078)', '偵測到使用者從一個新的、之前未曾記錄過的國家/地區登入雲端控制台', 'HIGH')
        cloud_logon_anomaly_rule.add_condition('event_type', 'equals', 'cloud_logon_anomaly')
        self.add_rule(cloud_logon_anomaly_rule)

        container_escape_rule = SIEMRule('R013', '容器逃逸嘗試 (T1610)', '偵測到從容器內部發起的、對主機敏感資源的存取嘗試', 'CRITICAL')
        container_escape_rule.add_condition('event_type', 'equals', 'process_creation')
        container_escape_rule.add_condition('parent_process_name', 'regex', r'(containerd-shim-runc-v2|docker-containerd-shim)')
        container_escape_rule.add_condition('command_line', 'regex', r'(\/etc\/shadow|\/proc\/sys|\/var\/run\/docker\.sock|dmesg|iptables)')
        self.add_rule(container_escape_rule)

        # ======================================================================
        # CRTO 2 規則
        # ======================================================================
        golden_ticket_rule = SIEMRule('R014', '黃金票據攻擊 (T1558.001)', '偵測到針對 krbtgt 帳戶的可疑 Kerberos 服務票據請求', 'CRITICAL')
        golden_ticket_rule.add_condition('event_type', 'equals', 'kerberos_ticket_request')
        golden_ticket_rule.add_condition('service_name', 'regex', r'krbtgt')
        golden_ticket_rule.add_condition('result', 'equals', 'success')
        # 在真實世界中，會過濾掉來自DC的請求
        golden_ticket_rule.add_condition('client_ip', 'regex', r'^(?!10\.0\.0\.1$|127\.0\.0\.1$).*') 
        self.add_rule(golden_ticket_rule)

        pass_the_hash_rule = SIEMRule('R015', '哈希傳遞攻擊 (T1550.002)', '偵測到使用 NTLM 進行的可疑遠端登入', 'HIGH')
        pass_the_hash_rule.add_condition('event_type', 'equals', 'authentication_success')
        pass_the_hash_rule.add_condition('logon_type', 'equals', 9) # LogonType 9: NewCredentials
        pass_the_hash_rule.add_condition('authentication_package', 'equals', 'NTLM')
        self.add_rule(pass_the_hash_rule)

        c2_beaconing_rule = SIEMRule('R016', 'C2 心跳包模式偵測 (T1071.001)', '偵測到固定間隔、類似心跳包的出站網路連線', 'MEDIUM')
        c2_beaconing_rule.add_condition('event_type', 'equals', 'c2_beaconing_detected') # 由特殊邏輯觸發
        self.add_rule(c2_beaconing_rule)

        # ======================================================================
        # EDR 規則 & SOAR 觸發
        # ======================================================================
        mimikatz_rule = SIEMRule(
            'R017', 'EDR: 偵測到 Mimikatz 執行 (T1003.001)', 
            'EDR Agent 回報有企圖執行認證竊取工具 Mimikatz 的行為', 'CRITICAL'
        )
        mimikatz_rule.add_condition('event_type', 'equals', 'edr_alert')
        mimikatz_rule.add_condition('process_name', 'regex', r'(mimikatz|mimidog)\.exe')
        mimikatz_rule.set_soar_playbook('PB001_BLOCK_IP_AT_WAF') # 綁定 SOAR Playbook
        self.add_rule(mimikatz_rule)

        powershell_lolbas_rule = SIEMRule(
            'R018', 'EDR: 偵測到可疑的 PowerShell 執行 (T1059.001)',
            'EDR Agent 回報有可疑的 PowerShell "Living off the Land" 行為', 'HIGH'
        )
        powershell_lolbas_rule.add_condition('event_type', 'equals', 'edr_alert')
        powershell_lolbas_rule.add_condition('process_name', 'equals', 'powershell.exe')
        powershell_lolbas_rule.add_condition('command_line', 'regex', r'(-enc|-nop|-w hidden|IEX)')
        powershell_lolbas_rule.set_soar_playbook('PB001_BLOCK_IP_AT_WAF') # 綁定 SOAR Playbook
        self.add_rule(powershell_lolbas_rule)


    def add_rule(self, rule: SIEMRule):
        self.rules[rule.rule_id] = rule
        logging.info("Added SIEM rule", extra={"rule_id": rule.rule_id, "rule_name": rule.name})
    
    def submit_event(self, event: Dict):
        """非同步提交事件到佇列"""
        self.event_queue.put(event)

    def _process_queue(self):
        """從佇列中取出事件並處理 (在獨立執行緒中運行)"""
        while True:
            try:
                event = self.event_queue.get()
                if event is None: # 哨兵值，用於停止執行緒
                    break
                self._process_event_internal(event)
                self.event_queue.task_done()
            except Exception as e:
                logging.error("Error processing event from queue", extra={"error": str(e)})

    def _process_event_internal(self, event: Dict):
        """實際的事件處理邏輯"""
        start_time = time.perf_counter()
        
        self.events.append(event)
        self.metrics['total_events'] += 1
        self._update_metrics(event)

        # 狀態化分析邏輯
        event_type = event.get('event_type')
        if event_type == 'file_renamed':
            self._handle_ransomware_detection(event)
        elif event_type == 'cloud_console_login':
            self._handle_cloud_logon_anomaly(event)
        elif event_type == 'network_connection':
            self._handle_c2_beacon_detection(event)

        # 無狀態規則匹配
        # 排除由特殊處理函數觸發的規則
        rules_to_evaluate = [
            rule for rule in self.rules.values()
            if rule.rule_id not in ['R009', 'R012', 'R016', 'C001']
        ]

        for rule in rules_to_evaluate:
            if rule.evaluate(event):
                rule.trigger(event)
                self._create_alert(rule, event)
                # 觸發 SOAR Playbook (如果已綁定)
                if rule.soar_playbook_id:
                    self._trigger_soar_playbook(rule.soar_playbook_id, event)
                
        end_time = time.perf_counter()
        processing_time = (end_time - start_time) * 1000 # 轉換為毫秒
        self.metrics['processing_times'].append(processing_time)

    def _update_metrics(self, event: Dict):
        self.metrics['severity_counts'][event.get('severity', 'UNKNOWN')] += 1
        self.metrics['hourly_events'][datetime.now().hour] += 1
        for tech in self.attack_framework.map_event_to_attack(event):
            self.metrics['attack_techniques'][tech] += 1
    
    def _handle_ransomware_detection(self, event: Dict):
        """處理勒索軟體偵測的特殊邏輯"""
        process_id = event.get('process_id')
        if not process_id:
            return

        now = time.time()
        
        # 初始化計數器 (如果不存在)
        if not hasattr(self, '_ransomware_tracker'):
            self._ransomware_tracker = {}

        # 移除過期的事件
        self._ransomware_tracker = {
            pid: [(ts, path) for ts, path in records if now - ts < 10] 
            for pid, records in self._ransomware_tracker.items()
        }

        # 添加新事件
        if process_id not in self._ransomware_tracker:
            self._ransomware_tracker[process_id] = []
        self._ransomware_tracker[process_id].append((now, event.get('new_path')))

        # 檢查是否觸發規則
        if len(self._ransomware_tracker[process_id]) > RANSOMWARE_FILE_COUNT_THRESHOLD:
            ransomware_event = {
                'event_type': 'file_renamed',
                'rename_count': len(self._ransomware_tracker[process_id]),
                'process_id': process_id,
                'process_name': event.get('process_name'),
                'src_ip': event.get('src_ip'),
                'hostname': event.get('hostname'),
                'timestamp': datetime.now().isoformat()
            }
            # 手動觸發 R009
            if 'R009' in self.rules and self.rules['R009'].evaluate(ransomware_event):
                self.rules['R009'].trigger(ransomware_event)
                self._create_alert(self.rules['R009'], ransomware_event)
                # 清空計數器以避免重複告警
                self._ransomware_tracker[process_id] = []

    def _handle_cloud_logon_anomaly(self, event: Dict):
        """處理雲端登入異常的狀態化邏輯"""
        user = event.get('user', {}).get('name')
        country = event.get('source', {}).get('geo', {}).get('country')
        result = event.get('result')

        if not all([user, country, result == 'success']):
            return

        known_countries = self._cloud_logon_tracker[user]
        
        if country not in known_countries:
            # 首次從此國家登入
            known_countries.add(country)

            # 如果用戶之前已經從其他地方登入過，那麼這次就是異常
            if len(known_countries) > 1:
                anomaly_event = {
                    'event_type': 'cloud_logon_anomaly',
                    'user': user,
                    'new_country': country,
                    'known_countries': list(known_countries - {country}),
                    'src_ip': event.get('src_ip'),
                    'timestamp': datetime.now().isoformat()
                }
                rule = self.rules.get('R012')
                if rule and rule.evaluate(anomaly_event):
                    rule.trigger(anomaly_event)
                    self._create_alert(rule, anomaly_event)

    def _handle_c2_beacon_detection(self, event: Dict):
        """處理 C2 心跳包偵測的狀態化邏輯"""
        src_ip = event.get('src_ip')
        dest_ip = event.get('dest_ip')
        
        if not all([src_ip, dest_ip]):
            return

        now = time.time()
        key = f"{src_ip}-{dest_ip}"
        
        # 移除超過時間窗口的舊紀錄
        self._c2_beacon_tracker[key] = [
            ts for ts in self._c2_beacon_tracker[key] 
            if now - ts < C2_BEACONING_INTERVAL_SECONDS
        ]
        
        self._c2_beacon_tracker[key].append(now)

        if len(self._c2_beacon_tracker[key]) >= C2_BEACONING_THRESHOLD:
            intervals = [self._c2_beacon_tracker[key][i] - self._c2_beacon_tracker[key][i-1] for i in range(1, len(self._c2_beacon_tracker[key]))]
            if not intervals: return
            
            avg_interval = sum(intervals) / len(intervals)
            # 檢查間隔的變異數是否夠小 (表示間隔很規律)
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)

            if variance < 5: # 變異數閾值，可調整
                beacon_event = {
                    'event_type': 'c2_beaconing_detected',
                    'src_ip': src_ip,
                    'dest_ip': dest_ip,
                    'connection_count': len(self._c2_beacon_tracker[key]),
                    'time_window_seconds': C2_BEACONING_INTERVAL_SECONDS,
                    'average_interval': round(avg_interval, 2),
                    'interval_variance': round(variance, 2),
                    'timestamp': datetime.now().isoformat()
                }
                rule = self.rules.get('R016')
                if rule and rule.evaluate(beacon_event):
                    rule.trigger(beacon_event)
                    self._create_alert(rule, beacon_event)
                    # 重置追蹤器以避免警報風暴
                    self._c2_beacon_tracker[key] = []

    def _create_alert(self, rule: SIEMRule, event: Dict):
        alert = {
            'alert_id': f"ALERT_{len(self.alerts) + 1}", 'rule_id': rule.rule_id,
            'rule_name': rule.name, 'severity': rule.severity,
            'timestamp': datetime.now().isoformat(), 'event': event,
            'attack_techniques': self.attack_framework.map_event_to_attack(event)
        }
        self.alerts.append(alert)
        self.metrics['total_alerts'] += 1
        
        src_ip = event.get('src_ip')
        if src_ip:
            self.metrics['blocked_ips'].add(src_ip)
            logging.info("IP added to block list", extra={"ip": src_ip, "rule_id": rule.rule_id})

        logging.warning("Alert triggered", extra={
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "severity": rule.severity,
            "client_ip": event.get('src_ip', 'unknown')
        })
    
        # 僅當觸發的不是關聯規則 C001 本身時，才去檢查關聯規則
        if rule.rule_id != 'C001':
            self._check_correlation_rules(alert)

    def _check_correlation_rules(self, new_alert: Dict):
        """檢查並觸發關聯規則"""
        src_ip = new_alert.get('event', {}).get('src_ip')
        severity = new_alert.get('severity')
        
        if not src_ip or severity not in ['HIGH', 'CRITICAL']:
            return

        now = self._parse_timestamp(new_alert['timestamp'])
        time_window = timedelta(minutes=CORRELATION_WINDOW_MINUTES)
        
        # 篩選出來自同一 IP 且在時間窗口內的高/嚴重警報
        related_alerts = [
            a for a in self.alerts 
            if a.get('event', {}).get('src_ip') == src_ip 
            and a.get('severity') in ['HIGH', 'CRITICAL']
            and now - self._parse_timestamp(a['timestamp']) <= time_window
        ]
        
        # 觸發 C001 規則
        if len(related_alerts) >= CORRELATION_ALERT_THRESHOLD:
            correlation_rule = self.rules.get('C001')
            if correlation_rule and correlation_rule.enabled:
                # 為了避免重複觸發，檢查是否已經為此 IP 觸發過關聯警報
                already_triggered = any(
                    a.get('rule_id') == 'C001' and a.get('event', {}).get('correlated_ip') == src_ip
                    # 在一個小的時間窗口內避免重複的關聯告警
                    and (now - self._parse_timestamp(a['timestamp'])).total_seconds() < 300
                    for a in self.alerts
                )

                if not already_triggered:
                    # 確保我們關聯的是獨立的告警，而不是之前的關聯告警
                    unique_involved_rules = sorted(list(set(a['rule_id'] for a in related_alerts if a['rule_id'] != 'C001')))

                    # 設定一個更有意義的觸發閾值，例如至少涉及2個不同的高危規則
                    if len(unique_involved_rules) < 2:
                        return

                    correlation_event = {
                        'event_type': 'correlated_attack',
                        'correlated_ip': src_ip,
                        'triggered_alert_count': len(related_alerts),
                        'involved_rules': unique_involved_rules,
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': src_ip # 方便日誌記錄
                    }
                    correlation_rule.trigger(correlation_event)
                    self._create_alert(correlation_rule, correlation_event)


    def get_dashboard_data(self) -> Dict:
        now, last_hour = datetime.now(), datetime.now() - timedelta(hours=1)
        recent_events = [e for e in self.events if self._parse_timestamp(e.get('timestamp', '')) > last_hour]
        recent_alerts = [a for a in self.alerts if self._parse_timestamp(a.get('timestamp', '')) > last_hour]
        
        avg_processing_time = sum(self.metrics['processing_times']) / len(self.metrics['processing_times']) if self.metrics['processing_times'] else 0

        return {
            'overview': {'total_events': self.metrics['total_events'], 'total_alerts': self.metrics['total_alerts'],
                         'blocked_ips_count': len(self.metrics['blocked_ips']), 
                         'active_rules': len([r for r in self.rules.values() if r.enabled]),
                         'avg_processing_time_ms': round(avg_processing_time, 2)},
            'recent_activity': {'events_last_hour': len(recent_events), 'alerts_last_hour': len(recent_alerts),
                                'top_source_ips': self._get_top_source_ips(recent_events),
                                'top_attack_techniques': self._get_top_attack_techniques()},
            'severity_breakdown': dict(self.metrics['severity_counts']),
            'hourly_trends': dict(self.metrics['hourly_events']),
            'attack_techniques': dict(self.metrics['attack_techniques']),
            'recent_alerts': recent_alerts[-10:],
            'blocked_ips': list(self.metrics['blocked_ips'])
        }
    
    def _parse_timestamp(self, ts: str) -> datetime:
        try: return datetime.fromisoformat(ts.replace('Z', '+00:00'))
        except: return datetime.min
    
    def _get_top_source_ips(self, events: List[Dict]) -> List[Dict]:
        ip_counts = Counter(e.get('src_ip') for e in events if e.get('src_ip'))
        return [{'ip': ip, 'count': count} for ip, count in ip_counts.most_common(10)]
    
    def _get_top_attack_techniques(self) -> List[Dict]:
        return [{'technique_id': tid, 'name': self.attack_framework.get_technique_name(tid), 'count': count}
                for tid, count in self.metrics['attack_techniques'].most_common(10)]

    def _trigger_soar_playbook(self, playbook_id: str, event: Dict):
        """執行指定的 SOAR Playbook"""
        playbook_func = self.playbooks.get(playbook_id)
        if playbook_func:
            source_ip = event.get('src_ip')
            if source_ip:
                logging.info("SOAR Playbook triggered", extra={"playbook_id": playbook_id, "src_ip": source_ip})
                playbook_func(source_ip=source_ip, event=event)
            else:
                logging.warning("SOAR Playbook skipped: missing src_ip", extra={"playbook_id": playbook_id})
        else:
            logging.error("SOAR Playbook not found", extra={"playbook_id": playbook_id})
    
    def playbook_block_ip_at_waf(self, source_ip: str, event: Dict):
        """
        一個 SOAR Playbook 的範例，用於在 WAF 上封鎖 IP。
        在真實世界中，這裡會是呼叫 WAF API 的程式碼。
        """
        logging.info("SOAR action: blocking IP at WAF", extra={"ip": source_ip})
        result = self.waf_instance.block_ip(source_ip)
        if result:
            logging.info("SOAR action: IP blocked successfully", extra={"ip": source_ip, "rule_id": event.get('rule_id')})
        else:
            logging.warning("SOAR action: IP already blocked", extra={"ip": source_ip, "rule_id": event.get('rule_id')})
        
        # 豐富化警報或通知 SOC
        rule_name = event.get('rule_name', 'N/A')
        logging.info("SOAR notification sent", extra={"rule_name": rule_name, "ip": source_ip})

# ======================================================================
# 模擬 WAF 控制介面
# ======================================================================
class WAFControlInterface:
    """一個 WAF API 的模擬器，用於 SOAR Playbook"""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(WAFControlInterface, cls).__new__(cls)
            cls._instance.blocked_ips = set()
        return cls._instance

    def block_ip(self, ip_address: str) -> bool:
        if ip_address not in self.blocked_ips:
            self.blocked_ips.add(ip_address)
            return True
        return False

    def get_blocked_ips(self) -> set:
        return self.blocked_ips

# ======================================================================
# 主應用程式
# ======================================================================
app = FastAPI(title="CRTO Lab SIEM Dashboard API", description="查看藍隊偵測警報的即時反饋")
dashboard = SOCDashboard()

@app.get("/alerts", summary="獲取所有觸發的警報")
def get_alerts():
    """
    返回一個包含所有已觸發警報的列表，最新的警報在最前面。
    這是紅隊操作員用來檢查攻擊是否被偵測到的主要端點。
    """
    return JSONResponse(content=sorted(dashboard.alerts, key=lambda x: x['timestamp'], reverse=True))

@app.get("/alerts/latest", summary="獲取最新一筆警報")
def get_latest_alert():
    """
    快速返回最新觸發的一筆警報。
    """
    if not dashboard.alerts:
        return JSONResponse(content={"message": "No alerts triggered yet."}, status_code=404)
    latest_alert = max(dashboard.alerts, key=lambda x: x['timestamp'])
    return JSONResponse(content=latest_alert)

@app.get("/dashboard", summary="獲取儀表板的總覽數據")
def get_dashboard_summary():
    """
    返回 SIEM 儀表板的總覽數據，包括指標和統計。
    """
    return JSONResponse(content=dashboard.get_dashboard_data())

@app.get("/healthz", summary="健康檢查")
def healthz():
    return JSONResponse(content={"status": "ok"})

@app.get("/status", summary="系統狀態")
def status():
    """系統狀態端點"""
    return JSONResponse(content={
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "uptime": time.time() - dashboard.start_time if hasattr(dashboard, 'start_time') else 0,
        "rules_active": len(dashboard.rules),
        "events_processed": dashboard.metrics['total_events'],
        "alerts_triggered": dashboard.metrics['total_alerts'],
        "waf_slo_status": getattr(dashboard, 'waf_slo_status', {}),
        "slo_thresholds": getattr(dashboard, 'slo_thresholds', {
            "availability": 99.95,
            "p95_latency_ms": 220,
            "error_rate": 0.1
        })
    })

@app.get("/metrics", summary="系統指標（簡化版）")
def metrics():
    data = dashboard.get_dashboard_data()
    # 暫以 Prometheus-like 純文字格式輸出基本指標
    lines = [
        f"siem_total_events {data['overview']['total_events']}",
        f"siem_total_alerts {data['overview']['total_alerts']}",
        f"siem_blocked_ips_count {data['overview']['blocked_ips_count']}",
        f"siem_active_rules {data['overview']['active_rules']}",
        f"siem_avg_processing_time_ms {data['overview']['avg_processing_time_ms']}"
    ]
    return JSONResponse(content={"metrics": "\n".join(lines)})

@app.get("/slo", summary="查詢目前 SLO 狀態 與 門檻")
def get_slo():
    payload = {
        "thresholds": dashboard.slo_thresholds,
        "last_waf_slo": dashboard.last_slo or {},
        "waf_url": WAF_BASE_URL
    }
    return JSONResponse(content=payload)

@app.post("/config", summary="更新 SIEM 設定（SLO 門檻、WAF URL）")
def update_config(body: Dict):
    try:
        if 'slo' in body and isinstance(body['slo'], dict):
            for k in ['availability', 'https_p95_ms', 'error_rate']:
                if k in body['slo']:
                    dashboard.slo_thresholds[k] = float(body['slo'][k])
        global WAF_BASE_URL
        if 'waf_url' in body and isinstance(body['waf_url'], str) and body['waf_url']:
            WAF_BASE_URL = body['waf_url'].rstrip('/')
        return JSONResponse(content={"status": "ok", "slo": dashboard.slo_thresholds, "waf_url": WAF_BASE_URL})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)

def run_api_server():
    """啟動 FastAPI 伺服器"""
    logging.info("Starting SIEM API server", extra={"port": 8001})
    uvicorn.run(app, host="0.0.0.0", port=8001)

if __name__ == "__main__":
    # 在主執行緒中運行 API 伺服器
    # 事件處理在背景執行緒中異步進行
    try:
        run_api_server()
    finally:
        dashboard.shutdown()

