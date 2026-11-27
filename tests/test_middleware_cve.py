#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""中间件探测与 CVE 严重性单元测试（mock SSH/HTTP，不依赖目标网络）。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from checks import middleware_scan as mw  # noqa: E402
from checks import cve_gate  # noqa: E402


def test_redis_unauth(monkeypatch):
    monkeypatch.setattr(mw, "ssh_run", lambda cmd, timeout=30: "+PONG")
    findings = []
    out = mw.probe_redis(findings)
    assert out["unauth"] is True
    assert any(f["id"] == "MW-REDIS-UNAUTH" for f in findings)


def test_redis_auth(monkeypatch):
    monkeypatch.setattr(mw, "ssh_run", lambda cmd, timeout=30: "NOAUTH Authentication required")
    findings = []
    out = mw.probe_redis(findings)
    assert out["unauth"] is False
    assert not findings


def test_zk_unauth(monkeypatch):
    monkeypatch.setattr(mw, "ssh_run", lambda cmd, timeout=30: "imok")
    findings = []
    out = mw.probe_zk(findings)
    assert out["unauth"] is True
    assert findings


def test_zk_whitelist(monkeypatch):
    monkeypatch.setattr(mw, "ssh_run", lambda cmd, timeout=30:
                        "ruok is not executed because it is not in the whitelist")
    findings = []
    out = mw.probe_zk(findings)
    assert out["unauth"] is False
    assert not findings


def test_rabbit_unauth(monkeypatch):
    def fake(cmd, timeout=30):
        if "15672" in cmd:
            return "HTTP 200"
        return "rabbitmq listeners"
    monkeypatch.setattr(mw, "ssh_run", fake)
    findings = []
    out = mw.probe_rabbit(findings)
    assert out["unauth"] is True
    assert findings


def test_rabbit_auth(monkeypatch):
    def fake(cmd, timeout=30):
        if "15672" in cmd:
            return "ERR HTTP 401"
        return "listeners"
    monkeypatch.setattr(mw, "ssh_run", fake)
    findings = []
    out = mw.probe_rabbit(findings)
    assert out["unauth"] is False
    assert not findings


class R:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


def test_cve_severity_critical(monkeypatch):
    monkeypatch.setattr(cve_gate.requests, "get",
                        lambda *a, **k: R(200, {"severity": [{"score": "CVSS_V3:CRITICAL"}]}))
    assert cve_gate.severity_of("X") == "critical"


def test_cve_severity_high(monkeypatch):
    monkeypatch.setattr(cve_gate.requests, "get",
                        lambda *a, **k: R(200, {"database_specific": {"severity": "HIGH"}}))
    assert cve_gate.severity_of("X") == "high"


def test_cve_severity_unknown(monkeypatch):
    monkeypatch.setattr(cve_gate.requests, "get", lambda *a, **k: R(500, {}))
    assert cve_gate.severity_of("X") == "unknown"
