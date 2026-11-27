#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""IDOR-H5 / 登录限速检查的单元测试（不访问真实环境）。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from checks import idor_h5, login_rate_limit  # noqa: E402


def _capture(monkeypatch, mod):
    box = {}

    def fake_emit(check_id, category, status, findings=None, summary="", blocked_reason=""):
        box.update({"id": check_id, "status": status, "findings": findings or [],
                    "summary": summary, "blocked": blocked_reason})

    monkeypatch.setattr(mod.gc, "emit", fake_emit)
    return box


def test_idor_h5_same_data(monkeypatch):
    box = _capture(monkeypatch, idor_h5)
    monkeypatch.setattr(idor_h5, "token", lambda u, p: "tok")
    monkeypatch.setattr(idor_h5, "call", lambda path, tok: {"http": 200, "code": 1, "len": 100, "items": 20})
    idor_h5.main()
    assert box["status"] == "PASS"
    assert len(box["findings"]) == 2
    assert all(f["severity"] == "medium" for f in box["findings"])


def test_idor_h5_denied(monkeypatch):
    box = _capture(monkeypatch, idor_h5)
    monkeypatch.setattr(idor_h5, "token", lambda u, p: "tok")
    monkeypatch.setattr(idor_h5, "call", lambda path, tok: {"http": 200, "code": 1003, "len": 50, "items": 0})
    idor_h5.main()
    assert box["findings"] == []


def test_login_no_rate_limit(monkeypatch):
    box = _capture(monkeypatch, login_rate_limit)
    monkeypatch.setenv("GATE_LOGIN_TEST_USERS", "test_user_a")
    monkeypatch.setenv("SEC_LOGIN_TEST_PASS", "<configure-locally>")
    seq = [{"http": 200, "token": False}] * 3 + [{"http": 200, "token": True}]
    monkeypatch.setattr(login_rate_limit, "login", lambda u, p: seq.pop(0))
    login_rate_limit.main()
    assert box["findings"] and box["findings"][0]["severity"] == "medium"


def test_login_skipped(monkeypatch):
    box = _capture(monkeypatch, login_rate_limit)
    monkeypatch.delenv("GATE_LOGIN_TEST_USERS", raising=False)
    monkeypatch.delenv("SEC_LOGIN_TEST_PASS", raising=False)
    login_rate_limit.main()
    assert box["findings"][0]["id"] == "LOGIN-RATE-SKIP"
