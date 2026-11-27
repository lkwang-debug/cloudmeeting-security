#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""外部报告导入端到端测试（模拟客户 SARIF 样本）。"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests.test_gate_checks_fixtures import run_check  # noqa: E402

REPORT = os.path.join(ROOT, "fixtures", "scanner_reports", "sample_simulated.sarif")


def test_import_external_sarif(tmp_path):
    ev = run_check("checks/import_external.py", "http://127.0.0.1:1", tmp_path,
                   extra_env={"GATE_EXTERNAL_REPORT": REPORT})
    assert ev["status"] == "PASS"
    assert len(ev["findings"]) == 3
    assert all(f["confidence"] == "external" for f in ev["findings"])
