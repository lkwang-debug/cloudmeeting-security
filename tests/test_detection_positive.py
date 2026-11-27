#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""检测能力正向 mock 测试：IP 伪造、nginx 403 绕过。"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from checks import ip_spoof, nginx_bypass


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        path = self.path
        if "actuator" in path and ("%00" in path or "\x00" in path):
            body = json.dumps({"_links": {"self": "bypassed"}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif path.startswith("/actuator"):
            body = b"403 Forbidden"
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
        else:
            fake = self.headers.get("X-Forwarded-For", "")
            body = json.dumps({"client": fake or "127.0.0.1"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def mock():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d" % srv.server_port
    srv.shutdown()


def _capture(monkeypatch, mod):
    box = {"findings": [], "status": None}

    def emit(cid, cat, status, findings, **kw):
        box["status"] = status
        box["findings"] = findings

    monkeypatch.setattr(mod.gc, "emit", emit)
    return box


def test_ip_spoof_positive(mock, monkeypatch):
    monkeypatch.setattr(ip_spoof, "BASE", mock)
    monkeypatch.setattr(ip_spoof, "PATHS", ["/echo"])
    monkeypatch.setattr(ip_spoof.web_auth, "headers", lambda cfg: {})
    box = _capture(monkeypatch, ip_spoof)
    ip_spoof.main()
    assert "IP-SPOOF-REFLECTED" in [f["id"] for f in box["findings"]]


def test_nginx_bypass_positive(mock, monkeypatch):
    monkeypatch.setattr(nginx_bypass, "BASE", mock)
    monkeypatch.setattr(nginx_bypass, "PATHS", ["/actuator"])
    box = _capture(monkeypatch, nginx_bypass)
    nginx_bypass.main()
    assert "NGINX-403-BYPASS" in [f["id"] for f in box["findings"]]


class SoapHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        data = self.rfile.read(n)
        text = data.decode("utf-8", "replace")
        if "GetNodeInfo" in text:
            body = b"<nodeID>123</nodeID>"
            ct = "text/xml"
        elif "AllUser" in text:
            body = b'{"code":"0","msg":"SUCCESS"}'
            ct = "application/json"
        elif "login" in self.path:
            body = b'{"access_token":"mocktoken"}'
            ct = "application/json"
        else:
            body = b'{"code":"0"}'
            ct = "application/json"
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def soap_mock():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), SoapHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_port
    srv.shutdown()


def test_ssrf_oast_positive(mock, monkeypatch):
    from checks import ssrf_check

    class FakeOast:
        def status(self):
            return {"domain": "mock.oast"}

        def url(self, token, kind):
            return "http://mock.oast/" + token

        def wait_for(self, token, timeout=1):
            return [{"full-id": token, "protocol": "http"}]

    cfg = {"ssrf": {"enabled": True, "endpoints": [
        {"method": "GET", "path": "/ssrf", "param": "url", "param_in": "query"}],
        "cleanup": []}}
    monkeypatch.setattr(ssrf_check, "BASE", mock)
    monkeypatch.setattr(ssrf_check, "load_cfg", lambda: cfg)
    monkeypatch.setattr(ssrf_check, "oast_mod", lambda: FakeOast())
    monkeypatch.setattr(ssrf_check.web_auth, "headers", lambda root: {})
    box = _capture(monkeypatch, ssrf_check)
    ssrf_check.main()
    assert "SSRF-OAST" in [f["id"] for f in box["findings"]]


def test_rce_write_chain_positive(soap_mock, monkeypatch):
    from checks import rce_write_chain

    cfg = {"rce_write_chain": {
        "enabled": True, "require_env": "ALLOW_WRITE_CHAIN",
        "steps": {
            "get_node": {"method": "POST", "path": "/soap", "data": "<GetNodeInfo/>",
                         "node_regex": r"nodeID[^0-9]{0,20}(\d+)"},
            "add_admin": {"method": "POST", "path": "/soap", "template": "<AllUser>{node_id}</AllUser>"},
            "login": {"method": "POST", "path": "/login", "json": {"name": "{username}", "password": "{password}"}},
            "upload": {"method": "POST", "path": "/upload", "headers": {}},
        },
        "cleanup": [],
    }}
    monkeypatch.setattr(rce_write_chain, "BASE", soap_mock)
    monkeypatch.setattr(rce_write_chain, "load_cfg", lambda: cfg)
    monkeypatch.setenv("ALLOW_WRITE_CHAIN", "1")
    box = _capture(monkeypatch, rce_write_chain)
    rce_write_chain.main()
    ids = [f["id"] for f in box["findings"]]
    assert "RCE-CHAIN-ADD-ADMIN" in ids
