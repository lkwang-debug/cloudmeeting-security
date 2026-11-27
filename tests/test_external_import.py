#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""外部扫描器报告解析单元测试。"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from checks.import_external import parse_sarif, parse_generic  # noqa: E402


def test_parse_sarif(tmp_path):
    p = tmp_path / "x.sarif"
    p.write_text(json.dumps({"runs": [{"results": [
        {"ruleId": "XSS", "level": "error",
         "message": {"text": "reflected xss"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "https://t/a"}}}]}
    ]}]}), encoding="utf-8")
    out = parse_sarif(str(p))
    assert len(out) == 1
    assert out[0]["severity"] == "high"
    assert out[0]["id"].startswith("EXT-")


def test_parse_generic(tmp_path):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"findings": [
        {"id": "V1", "severity": "critical", "title": "RCE", "url": "https://t/x"}
    ]}), encoding="utf-8")
    out = parse_generic(str(p))
    assert out[0]["severity"] == "critical"
    assert out[0]["title"] == "RCE"
