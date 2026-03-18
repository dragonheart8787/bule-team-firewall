#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
攻擊圖譜與 ATT&CK 導出模組
彙整偵測/演練/CTI 資料，輸出攻擊路徑與 Navigator layer
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class RealAttackGraph:
    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self.techniques: List[str] = []

    def add_node(self, node_id: str, label: str, kind: str, meta: Dict[str, Any] = None):
        self.nodes.append({ 'id': node_id, 'label': label, 'kind': kind, 'meta': meta or {} })

    def add_edge(self, src: str, dst: str, label: str, meta: Dict[str, Any] = None):
        self.edges.append({ 'source': src, 'target': dst, 'label': label, 'meta': meta or {} })

    def add_technique(self, tid: str):
        if tid not in self.techniques:
            self.techniques.append(tid)

    def build_from_events(self, events: List[Dict[str, Any]]):
        # 簡化：從事件中抽取節點與關聯
        for idx, e in enumerate(events or []):
            nid = f"evt_{idx}"
            self.add_node(nid, e.get('type', 'event'), 'event', { 'time': e.get('timestamp') })
            if 'src_ip' in e:
                sip = e['src_ip']
                self.add_node(sip, sip, 'ip')
                self.add_edge(sip, nid, 'triggers')
            if 'dest_ip' in e:
                dip = e['dest_ip']
                self.add_node(dip, dip, 'ip')
                self.add_edge(nid, dip, 'targets')
            # 攻擊技術標記（示例）
            if e.get('type') == 'SUSPICIOUS_PROCESS':
                self.add_technique('T1059')
            if e.get('type') == 'CODE_INJECTION':
                self.add_technique('T1055')
            if e.get('type') == 'SUSPICIOUS_DNS':
                self.add_technique('T1071')

    def export_attack_navigator_layer(self) -> Dict[str, Any]:
        # 產生 ATT&CK Navigator v4 layer JSON
        layer = {
            "version": "4.3",
            "name": "Defense Coverage",
            "description": "Auto-generated coverage from events/simulation",
            "domain": "enterprise-attack",
            "techniques": [{ "techniqueID": t, "tactic": "", "score": 1 } for t in self.techniques],
            "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 1},
            "legendItems": [{"label": "covered", "color": "#ff6666"}],
            "metadata": [{"name": "generated", "value": datetime.now().isoformat()}]
        }
        return layer

    def get_graph(self) -> Dict[str, Any]:
        return { 'nodes': self.nodes, 'edges': self.edges, 'techniques': self.techniques }

    def get_comprehensive_report(self) -> Dict[str, Any]:
        return { 'success': True, 'attack_graph': self.get_graph(), 'navigator': self.export_attack_navigator_layer() }



