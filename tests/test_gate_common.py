#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""门禁证据公共库单元测试。"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import checks.gate_common as gc  # noqa: E402


def test_finding_schema():
    f = gc.finding("ID-1", "high", "title", evidence="e", remediation="r")
    assert f["id"] == "ID-1"
    assert f["severity"] == "high"
    assert f["remediation"] == "r"


def test_emit_writes_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(gc, "EVIDENCE_DIR", str(tmp_path))
    payload = gc.emit("chk_x", "application", "PASS", [], summary="ok")
    p = tmp_path / "chk_x.json"
    assert p.exists()
    data = json.load(open(p, encoding="utf-8"))
    assert data["check_id"] == "chk_x"
    assert data["status"] == "PASS"
    assert payload["summary"] == "ok"
