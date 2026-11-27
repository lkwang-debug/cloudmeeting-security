#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""更多门禁检查正/负例：RCE/登录策略/IDOR/明文 HTTP。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests.mock_gate_server import MODE, start_server  # noqa: E402
from tests.test_gate_checks_fixtures import run_check, highs  # noqa: E402


def test_rce_time_blind(server=None):
    srv, base = start_server()
    try:
        MODE["value"] = "vuln"
        ev = run_check("checks/rce_probe.py", base, __import__("pathlib").Path(__import__("tempfile").mkdtemp()),
                       endpoints=[{"method": "POST", "path": "/login", "body_keys": ["password"]}])
        assert highs(ev), ev
        MODE["value"] = "fixed"
        ev = run_check("checks/rce_probe.py", base, __import__("pathlib").Path(__import__("tempfile").mkdtemp()),
                       endpoints=[{"method": "POST", "path": "/login", "body_keys": ["password"]}])
        assert not highs(ev)
    finally:
        srv.shutdown()


def test_login_policy(server=None):
    srv, base = start_server()
    try:
        MODE["value"] = "vuln"
        ev = run_check("checks/login_policy.py", base, __import__("pathlib").Path(__import__("tempfile").mkdtemp()))
        assert highs(ev), ev
        MODE["value"] = "fixed"
        ev = run_check("checks/login_policy.py", base, __import__("pathlib").Path(__import__("tempfile").mkdtemp()))
        assert not highs(ev)
    finally:
        srv.shutdown()


def test_idor_matrix(server=None):
    srv, base = start_server()
    try:
        MODE["value"] = "vuln"
        ev = run_check("checks/idor_matrix.py", base, __import__("pathlib").Path(__import__("tempfile").mkdtemp()))
        assert highs(ev), ev
        MODE["value"] = "fixed"
        ev = run_check("checks/idor_matrix.py", base, __import__("pathlib").Path(__import__("tempfile").mkdtemp()))
        assert not highs(ev)
    finally:
        srv.shutdown()


def test_plaintext_http(server=None):
    srv, base = start_server()
    try:
        MODE["value"] = "vuln"
        ev = run_check("checks/plaintext_http.py", base, __import__("pathlib").Path(__import__("tempfile").mkdtemp()),
                       extra_env={"GATE_HTTP_TARGETS": base + "/"})
        assert highs(ev), ev
        # 指向不可达端口，应无高危
        ev = run_check("checks/plaintext_http.py", base, __import__("pathlib").Path(__import__("tempfile").mkdtemp()),
                       extra_env={"GATE_HTTP_TARGETS": "http://127.0.0.1:1/"})
        assert not highs(ev)
    finally:
        srv.shutdown()
