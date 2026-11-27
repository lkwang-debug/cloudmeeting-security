#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""门禁 truth set 评估单元测试。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from runner.build_gate_truth_set import evaluate  # noqa: E402


def test_evaluate_positive_and_negative():
    gate = {"checks": {"crypto_inventory": {"status": "PASS"},
                       "client_crypto": {"status": "PASS"},
                       "secret_scan": {"status": "PASS"},
                       "cve_gate": {"status": "PASS"},
                       "xss_full": {"status": "PASS"},
                       "upload_webshell": {"status": "PASS"},
                       "rce_probe": {"status": "PASS"},
                       "file_download": {"status": "PASS"},
                       "idor_matrix": {"status": "PASS"},
                       "login_policy": {"status": "PASS"},
                       "auth_token_checks": {"status": "PASS"},
                       "soap_checks": {"status": "PASS"},
                       "plaintext_http": {"status": "PASS"}}}
    matrix = {"reports": {"r": {"items": [
        {"id": "1", "check": "xss_full", "level": "auto"},
        {"id": "2", "check": "manual", "level": "manual"},
    ]}}}
    out = evaluate(gate, matrix)
    assert out["metrics"]["mapped"] == 1
    assert out["metrics"]["executed"] == 1
    assert out["metrics"]["report_items"] == 2
    assert out["metrics"]["negative_checks"] == len(
        ["xss_full", "upload_webshell", "rce_probe", "file_download", "idor_matrix",
         "login_policy", "auth_token_checks", "soap_checks", "plaintext_http"])
