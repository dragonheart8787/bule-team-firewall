#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實CTF競賽管理系統
Real CTF Competition Manager
團隊管理、計分系統、排行榜
"""

import os
import json
import time
import logging
import threading
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import hashlib
import random

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealCTFCompetitionManager:
    """真實CTF競賽管理系統"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.competition_threads = []
        self.teams = {}
        self.challenges = {}
        self.submissions = {}
        
        # 初始化組件
        self._init_database()
        self._init_competition_system()
        
        logger.info("真實CTF競賽管理系統初始化完成")
    
    def _init_database(self):
        """初始化數據庫"""
        try:
            self.db_path = 'ctf_competition.db'
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 創建團隊表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS teams (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    team_id TEXT UNIQUE NOT NULL,
                    team_name TEXT NOT NULL,
                    team_members TEXT NOT NULL,
                    team_token TEXT NOT NULL,
                    total_points INTEGER DEFAULT 0,
                    rank INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_submission DATETIME
                )
            ''')
            
            # 創建挑戰表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS competition_challenges (
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
                    solved_by TEXT,
                    solve_count INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 創建提交表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    submission_id TEXT UNIQUE NOT NULL,
                    team_id TEXT NOT NULL,
                    challenge_id TEXT NOT NULL,
                    flag TEXT NOT NULL,
                    correct BOOLEAN DEFAULT FALSE,
                    points INTEGER DEFAULT 0,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (team_id) REFERENCES teams (team_id),
                    FOREIGN KEY (challenge_id) REFERENCES competition_challenges (challenge_id)
                )
            ''')
            
            # 創建競賽表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS competitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    competition_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    start_time DATETIME NOT NULL,
                    end_time DATETIME NOT NULL,
                    status TEXT DEFAULT 'upcoming',
                    max_teams INTEGER DEFAULT 100,
                    current_teams INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("CTF競賽管理數據庫初始化完成")
            
        except Exception as e:
            logger.error(f"數據庫初始化錯誤: {e}")
    
    def _init_competition_system(self):
        """初始化競賽系統"""
        try:
            self.competition_config = {
                'max_teams': self.config.get('max_teams', 100),
                'competition_duration': self.config.get('competition_duration', 24),  # 小時
                'scoring_system': self.config.get('scoring_system', 'dynamic'),
                'penalty_time': self.config.get('penalty_time', 5),  # 分鐘
                'hint_penalty': self.config.get('hint_penalty', 0.1)  # 10%分數懲罰
            }
            
            # 初始化計分系統
            self.scoring_systems = {
                'static': self._calculate_static_score,
                'dynamic': self._calculate_dynamic_score,
                'jeopardy': self._calculate_jeopardy_score
            }
            
            logger.info("競賽系統初始化完成")
            
        except Exception as e:
            logger.error(f"競賽系統初始化錯誤: {e}")
    
    def create_competition(self, competition_id: str, name: str, description: str, 
                          start_time: str, end_time: str, **kwargs) -> Dict[str, Any]:
        """創建競賽"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO competitions
                (competition_id, name, description, start_time, end_time, max_teams)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                competition_id,
                name,
                description,
                start_time,
                end_time,
                kwargs.get('max_teams', 100)
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"創建競賽: {competition_id} - {name}")
            
            return {
                'success': True,
                'competition_id': competition_id,
                'message': '競賽創建成功'
            }
            
        except Exception as e:
            logger.error(f"創建競賽錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def register_team(self, team_id: str, team_name: str, team_members: List[str]) -> Dict[str, Any]:
        """註冊團隊"""
        try:
            # 生成團隊令牌
            team_token = self._generate_team_token(team_id, team_name)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO teams
                (team_id, team_name, team_members, team_token)
                VALUES (?, ?, ?, ?)
            ''', (
                team_id,
                team_name,
                json.dumps(team_members),
                team_token
            ))
            
            conn.commit()
            conn.close()
            
            # 更新內存中的團隊信息
            self.teams[team_id] = {
                'team_name': team_name,
                'team_members': team_members,
                'team_token': team_token,
                'total_points': 0,
                'rank': 0
            }
            
            logger.info(f"註冊團隊: {team_id} - {team_name}")
            
            return {
                'success': True,
                'team_id': team_id,
                'team_token': team_token,
                'message': '團隊註冊成功'
            }
            
        except Exception as e:
            logger.error(f"註冊團隊錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _generate_team_token(self, team_id: str, team_name: str) -> str:
        """生成團隊令牌"""
        try:
            token_string = f"{team_id}_{team_name}_{int(time.time())}"
            return hashlib.sha256(token_string.encode()).hexdigest()[:32]
        except Exception as e:
            logger.error(f"生成團隊令牌錯誤: {e}")
            return f"token_{int(time.time())}"
    
    def add_challenge(self, challenge_id: str, category: str, name: str, 
                     description: str, difficulty: str, points: int, flag: str, **kwargs) -> Dict[str, Any]:
        """添加挑戰"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO competition_challenges
                (challenge_id, category, name, description, difficulty, points, 
                 flag, flag_format, hints)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                challenge_id,
                category,
                name,
                description,
                difficulty,
                points,
                flag,
                kwargs.get('flag_format', 'flag{.*}'),
                json.dumps(kwargs.get('hints', []))
            ))
            
            conn.commit()
            conn.close()
            
            # 更新內存中的挑戰信息
            self.challenges[challenge_id] = {
                'category': category,
                'name': name,
                'description': description,
                'difficulty': difficulty,
                'points': points,
                'flag': flag,
                'solved_by': [],
                'solve_count': 0
            }
            
            logger.info(f"添加挑戰: {challenge_id} - {name}")
            
            return {
                'success': True,
                'challenge_id': challenge_id,
                'message': '挑戰添加成功'
            }
            
        except Exception as e:
            logger.error(f"添加挑戰錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def submit_flag(self, team_id: str, challenge_id: str, flag: str) -> Dict[str, Any]:
        """提交flag"""
        try:
            # 驗證團隊
            if team_id not in self.teams:
                return {'success': False, 'error': '團隊不存在'}
            
            # 驗證挑戰
            if challenge_id not in self.challenges:
                return {'success': False, 'error': '挑戰不存在'}
            
            # 檢查是否已經解決
            if self._is_challenge_solved(team_id, challenge_id):
                return {'success': False, 'error': '挑戰已經解決'}
            
            # 驗證flag
            correct_flag = self.challenges[challenge_id]['flag']
            is_correct = self._validate_flag(flag, correct_flag)
            
            # 生成提交ID
            submission_id = f"sub_{int(time.time())}_{team_id}_{challenge_id}"
            
            # 計算分數
            points = 0
            if is_correct:
                points = self._calculate_challenge_points(challenge_id, team_id)
            
            # 記錄提交
            self._record_submission(submission_id, team_id, challenge_id, flag, is_correct, points)
            
            if is_correct:
                # 更新團隊分數
                self._update_team_score(team_id, points)
                
                # 更新挑戰解決狀態
                self._update_challenge_solve_status(challenge_id, team_id)
                
                # 更新排行榜
                self._update_leaderboard()
                
                logger.info(f"Flag提交成功: {team_id} - {challenge_id} - {points}分")
                
                return {
                    'success': True,
                    'correct': True,
                    'points': points,
                    'message': f'Flag正確！獲得{points}分'
                }
            else:
                logger.info(f"Flag提交失敗: {team_id} - {challenge_id}")
                
                return {
                    'success': True,
                    'correct': False,
                    'points': 0,
                    'message': 'Flag錯誤'
                }
                
        except Exception as e:
            logger.error(f"提交flag錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _validate_flag(self, submitted_flag: str, correct_flag: str) -> bool:
        """驗證flag"""
        try:
            # 簡單的字符串比較
            return submitted_flag.strip() == correct_flag.strip()
        except Exception as e:
            logger.error(f"驗證flag錯誤: {e}")
            return False
    
    def _calculate_challenge_points(self, challenge_id: str, team_id: str) -> int:
        """計算挑戰分數"""
        try:
            challenge = self.challenges[challenge_id]
            base_points = challenge['points']
            
            # 根據計分系統計算分數
            scoring_system = self.competition_config['scoring_system']
            if scoring_system in self.scoring_systems:
                return self.scoring_systems[scoring_system](challenge_id, team_id, base_points)
            else:
                return base_points
                
        except Exception as e:
            logger.error(f"計算挑戰分數錯誤: {e}")
            return 0
    
    def _calculate_static_score(self, challenge_id: str, team_id: str, base_points: int) -> int:
        """靜態計分"""
        return base_points
    
    def _calculate_dynamic_score(self, challenge_id: str, team_id: str, base_points: int) -> int:
        """動態計分"""
        try:
            # 動態計分：根據解決人數調整分數
            solve_count = self.challenges[challenge_id]['solve_count']
            
            if solve_count == 0:
                return base_points
            else:
                # 分數隨解決人數增加而減少
                dynamic_points = int(base_points * (1.0 - solve_count * 0.1))
                return max(dynamic_points, base_points // 2)
                
        except Exception as e:
            logger.error(f"計算動態分數錯誤: {e}")
            return base_points
    
    def _calculate_jeopardy_score(self, challenge_id: str, team_id: str, base_points: int) -> int:
        """Jeopardy計分"""
        try:
            # Jeopardy計分：根據難度和解決時間
            difficulty = self.challenges[challenge_id]['difficulty']
            
            difficulty_multiplier = {
                'easy': 1.0,
                'medium': 1.2,
                'hard': 1.5,
                'expert': 2.0
            }
            
            multiplier = difficulty_multiplier.get(difficulty, 1.0)
            return int(base_points * multiplier)
            
        except Exception as e:
            logger.error(f"計算Jeopardy分數錯誤: {e}")
            return base_points
    
    def _is_challenge_solved(self, team_id: str, challenge_id: str) -> bool:
        """檢查挑戰是否已解決"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT COUNT(*) FROM submissions
                WHERE team_id = ? AND challenge_id = ? AND correct = TRUE
            ''', (team_id, challenge_id))
            
            count = cursor.fetchone()[0]
            conn.close()
            
            return count > 0
            
        except Exception as e:
            logger.error(f"檢查挑戰解決狀態錯誤: {e}")
            return False
    
    def _record_submission(self, submission_id: str, team_id: str, challenge_id: str, 
                          flag: str, is_correct: bool, points: int):
        """記錄提交"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO submissions
                (submission_id, team_id, challenge_id, flag, correct, points)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (submission_id, team_id, challenge_id, flag, is_correct, points))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"記錄提交錯誤: {e}")
    
    def _update_team_score(self, team_id: str, points: int):
        """更新團隊分數"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE teams
                SET total_points = total_points + ?, last_submission = CURRENT_TIMESTAMP
                WHERE team_id = ?
            ''', (points, team_id))
            
            conn.commit()
            conn.close()
            
            # 更新內存中的團隊分數
            if team_id in self.teams:
                self.teams[team_id]['total_points'] += points
            
        except Exception as e:
            logger.error(f"更新團隊分數錯誤: {e}")
    
    def _update_challenge_solve_status(self, challenge_id: str, team_id: str):
        """更新挑戰解決狀態"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE competition_challenges
                SET solve_count = solve_count + 1
                WHERE challenge_id = ?
            ''', (challenge_id,))
            
            conn.commit()
            conn.close()
            
            # 更新內存中的挑戰狀態
            if challenge_id in self.challenges:
                self.challenges[challenge_id]['solve_count'] += 1
                self.challenges[challenge_id]['solved_by'].append(team_id)
            
        except Exception as e:
            logger.error(f"更新挑戰解決狀態錯誤: {e}")
    
    def _update_leaderboard(self):
        """更新排行榜"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 獲取團隊排名
            cursor.execute('''
                SELECT team_id, total_points, last_submission
                FROM teams
                ORDER BY total_points DESC, last_submission ASC
            ''')
            
            teams = cursor.fetchall()
            
            # 更新排名
            for rank, (team_id, total_points, last_submission) in enumerate(teams, 1):
                cursor.execute('''
                    UPDATE teams
                    SET rank = ?
                    WHERE team_id = ?
                ''', (rank, team_id))
                
                # 更新內存中的排名
                if team_id in self.teams:
                    self.teams[team_id]['rank'] = rank
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"更新排行榜錯誤: {e}")
    
    def get_leaderboard(self, limit: int = 50) -> Dict[str, Any]:
        """獲取排行榜"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT team_id, team_name, total_points, rank, last_submission
                FROM teams
                ORDER BY total_points DESC, last_submission ASC
                LIMIT ?
            ''', (limit,))
            
            teams = cursor.fetchall()
            conn.close()
            
            leaderboard = []
            for team in teams:
                leaderboard.append({
                    'team_id': team[0],
                    'team_name': team[1],
                    'total_points': team[2],
                    'rank': team[3],
                    'last_submission': team[4]
                })
            
            return {
                'success': True,
                'leaderboard': leaderboard,
                'total_teams': len(leaderboard)
            }
            
        except Exception as e:
            logger.error(f"獲取排行榜錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_team_stats(self, team_id: str) -> Dict[str, Any]:
        """獲取團隊統計"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 獲取團隊基本信息
            cursor.execute('''
                SELECT team_name, total_points, rank, last_submission
                FROM teams
                WHERE team_id = ?
            ''', (team_id,))
            
            team_info = cursor.fetchone()
            if not team_info:
                return {'success': False, 'error': '團隊不存在'}
            
            # 獲取解決的挑戰
            cursor.execute('''
                SELECT challenge_id, points, timestamp
                FROM submissions
                WHERE team_id = ? AND correct = TRUE
                ORDER BY timestamp ASC
            ''', (team_id,))
            
            solved_challenges = cursor.fetchall()
            
            # 獲取提交統計
            cursor.execute('''
                SELECT COUNT(*) as total_submissions,
                       COUNT(CASE WHEN correct = TRUE THEN 1 END) as correct_submissions
                FROM submissions
                WHERE team_id = ?
            ''', (team_id,))
            
            submission_stats = cursor.fetchone()
            
            conn.close()
            
            return {
                'success': True,
                'team_stats': {
                    'team_name': team_info[0],
                    'total_points': team_info[1],
                    'rank': team_info[2],
                    'last_submission': team_info[3],
                    'solved_challenges': [
                        {
                            'challenge_id': challenge[0],
                            'points': challenge[1],
                            'solved_at': challenge[2]
                        }
                        for challenge in solved_challenges
                    ],
                    'total_submissions': submission_stats[0],
                    'correct_submissions': submission_stats[1],
                    'accuracy': submission_stats[1] / submission_stats[0] if submission_stats[0] > 0 else 0
                }
            }
            
        except Exception as e:
            logger.error(f"獲取團隊統計錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_challenge_stats(self, challenge_id: str) -> Dict[str, Any]:
        """獲取挑戰統計"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 獲取挑戰基本信息
            cursor.execute('''
                SELECT name, category, difficulty, points, solve_count
                FROM competition_challenges
                WHERE challenge_id = ?
            ''', (challenge_id,))
            
            challenge_info = cursor.fetchone()
            if not challenge_info:
                return {'success': False, 'error': '挑戰不存在'}
            
            # 獲取解決團隊
            cursor.execute('''
                SELECT team_id, timestamp
                FROM submissions
                WHERE challenge_id = ? AND correct = TRUE
                ORDER BY timestamp ASC
            ''', (challenge_id,))
            
            solved_teams = cursor.fetchall()
            
            conn.close()
            
            return {
                'success': True,
                'challenge_stats': {
                    'name': challenge_info[0],
                    'category': challenge_info[1],
                    'difficulty': challenge_info[2],
                    'points': challenge_info[3],
                    'solve_count': challenge_info[4],
                    'solved_teams': [
                        {
                            'team_id': team[0],
                            'solved_at': team[1]
                        }
                        for team in solved_teams
                    ]
                }
            }
            
        except Exception as e:
            logger.error(f"獲取挑戰統計錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def start_competition_monitoring(self) -> Dict[str, Any]:
        """啟動競賽監控"""
        try:
            if self.running:
                return {'success': False, 'error': '競賽監控已在運行中'}
            
            self.running = True
            
            # 啟動監控線程
            thread = threading.Thread(target=self._run_competition_monitoring, daemon=True)
            thread.start()
            self.competition_threads.append(thread)
            
            logger.info("CTF競賽監控已啟動")
            return {'success': True, 'message': 'CTF競賽監控已啟動'}
            
        except Exception as e:
            logger.error(f"啟動競賽監控錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _run_competition_monitoring(self):
        """運行競賽監控"""
        try:
            while self.running:
                try:
                    # 更新排行榜
                    self._update_leaderboard()
                    
                    # 檢查競賽狀態
                    self._check_competition_status()
                    
                    time.sleep(30)  # 每30秒更新一次
                    
                except Exception as e:
                    logger.error(f"競賽監控錯誤: {e}")
                    time.sleep(10)
                    
        except Exception as e:
            logger.error(f"運行競賽監控錯誤: {e}")
    
    def _check_competition_status(self):
        """檢查競賽狀態"""
        try:
            # 這裡可以添加競賽狀態檢查邏輯
            # 例如：檢查競賽是否結束、發送通知等
            pass
            
        except Exception as e:
            logger.error(f"檢查競賽狀態錯誤: {e}")
    
    def stop_competition_monitoring(self) -> Dict[str, Any]:
        """停止競賽監控"""
        try:
            self.running = False
            
            # 等待所有線程結束
            for thread in self.competition_threads:
                thread.join(timeout=5)
            
            self.competition_threads.clear()
            
            logger.info("CTF競賽監控已停止")
            return {'success': True, 'message': 'CTF競賽監控已停止'}
            
        except Exception as e:
            logger.error(f"停止競賽監控錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """獲取系統狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'teams_count': len(self.teams),
                'challenges_count': len(self.challenges),
                'competition_threads': len(self.competition_threads)
            }
        except Exception as e:
            logger.error(f"獲取系統狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """獲取綜合報告"""
        try:
            return {
                'success': True,
                'ctf_competition_manager': {
                    'teams': list(self.teams.keys()),
                    'challenges': list(self.challenges.keys()),
                    'scoring_systems': list(self.scoring_systems.keys()),
                    'competition_config': self.competition_config
                }
            }
        except Exception as e:
            logger.error(f"獲取綜合報告錯誤: {e}")
            return {'success': False, 'error': str(e)}


