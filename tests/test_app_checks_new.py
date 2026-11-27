#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""新增应用检查的正反例 fixture 测试（XSS crawl/上传内容/RCE 探测/登录限速）。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests.mock_gate_server import MODE, start_server  # noqa: E402
from tests.test_gate_checks_fixtures import run_check, highs  # noqa: E402


def test_xss_crawl_positive_negative():
    srv, base = start_server()
    try:
        MODE["value"] = "vuln"
        ev = run_check("checks/xss_crawl.py", base, __import__("pathlib").Path(__import__("tempfile").mkdtemp()),
                       all_eps=["/search"])
        assert highs(ev), ev
        MODE["value"] = "fixed"
        ev = run_check("checks/xss_crawl.py", base, __import__("pathlib").Path(__import__("tempfile").mkdtemp()),
                       all_eps=["/search"])
        assert not highs(ev)
    finally:
        srv.shutdown()


def test_upload_content_positive_negative():
    srv, base = start_server()
    try:
        MODE["value"] = "vuln"
        ev = run_check("checks/upload_content.py", base, __import__("pathlib").Path(__import__("tempfile").mkdtemp()))
        assert highs(ev), ev
        MODE["value"] = "fixed"
        ev = run_check("checks/upload_content.py", base, __import__("pathlib").Path(__import__("tempfile").mkdtemp()))
        assert not highs(ev)
    finally:
        srv.shutdown()


def test_rce_deserialization_executes():
    srv, base = start_server()
    try:
        MODE["value"] = "fixed"
        ev = run_check("checks/rce_deserialization.py", base, __import__("pathlib").Path(__import__("tempfile").mkdtemp()),
                       endpoints=[{"method": "POST", "path": "/login", "body_keys": ["password"]}])
        assert ev["status"] == "PASS"
    finally:
        srv.shutdown()


def test_login_rate_limit_not_configured(tmp_path, monkeypatch):
    # 该检查无配置时直接 PASS(info)，不发起登录
    ev = run_check("checks/login_rate_limit.py", "http://127.0.0.1:1", tmp_path,
                   extra_env={"GATE_LOGIN_TEST_USERS": "", "SEC_LOGIN_TEST_PASS": ""})
    assert ev["status"] == "PASS"
    assert any(f["id"] == "LOGIN-RATE-SKIP" for f in ev["findings"])
