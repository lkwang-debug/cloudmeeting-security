#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""门禁契约测试：配置中的每个检查文件存在、证据 schema 一致。"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import yaml  # noqa: E402

CFG = os.path.join(ROOT, "configs", "release_gate.yaml")
EVID = os.path.join(ROOT, "reports", "final", "gate", "evidence")
REQUIRED_KEYS = {"check_id", "category", "status", "findings", "blocked_reason"}


def test_all_configured_checks_exist():
    cfg = yaml.safe_load(open(CFG, encoding="utf-8"))
    missing = []
    for cid, meta in (cfg.get("checks") or {}).items():
        p = os.path.join(ROOT, meta["cmd"])
        if not os.path.exists(p):
            missing.append((cid, meta["cmd"]))
    assert not missing, f"missing check scripts: {missing}"


def test_evidence_schema_for_all_checks():
    if not os.path.isdir(EVID):
        return
    files = [f for f in os.listdir(EVID) if f.endswith(".json")]
    assert files, "no gate evidence generated; run runner/release_gate.py first"
    for f in files:
        j = json.load(open(os.path.join(EVID, f), encoding="utf-8"))
        assert REQUIRED_KEYS.issubset(j.keys()), f"{f} 缺字段: {REQUIRED_KEYS - set(j)}"
        assert j["status"] in ("PASS", "FAIL", "BLOCKED", "ERROR"), f"{f} 非法状态 {j['status']}"
        for finding in j.get("findings") or []:
            assert {"id", "severity", "title"}.issubset(finding.keys()), f"{f} finding 缺字段"


def test_gate_matrix_has_categories_and_reports():
    m = yaml.safe_load(open(os.path.join(ROOT, "knowledge", "gate_matrix.yaml"), encoding="utf-8"))
    assert set(m.get("categories") or {}) >= {"application", "crypto", "component"}
    items = []
    for r in (m.get("reports") or {}).values():
        items += r.get("items") or []
    assert len(items) >= 20, f"客户报告映射过少: {len(items)}"
    assert all(i.get("check") for i in items), "存在未映射检查的报告项"
