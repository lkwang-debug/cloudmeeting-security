#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""HTTP 证据记录器测试（脱敏+落盘）。"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from checks import gate_common as gc  # noqa: E402


class _Resp:
    status_code = 200
    headers = {"Content-Type": "application/json"}
    text = '{"code":"0"}'
    elapsed = None


def test_http_record_and_mask(tmp_path, monkeypatch):
    monkeypatch.setattr(gc, "EVIDENCE_DIR", str(tmp_path))
    gc._record("POST", "https://example.test/api", {
        "headers": {"Authorization": "Bearer secret", "X-Test": "1"},
        "json": {"password": "p", "name": "n"},
    }, _Resp())
    files = list((tmp_path / "http").glob("**/req_*.json"))
    assert files, "evidence file not written"
    rec = json.load(open(files[0], encoding="utf-8"))
    assert rec["request"]["headers"]["Authorization"] == "***"
    assert rec["request"]["body"]["password"] == "***"
    assert rec["response"]["status"] == 200
