#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""门禁关键检查的正例/负例 fixture 测试（本地 mock 服务器）。"""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests.mock_gate_server import MODE, start_server  # noqa: E402

PY = sys.executable


@pytest.fixture(scope="session")
def server():
    srv, base = start_server()
    yield srv, base
    srv.shutdown()


def run_check(script, base, tmp_path, endpoints=None, all_eps=None, extra_env=None):
    ev = tmp_path / "ev"
    ev.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update({
        "GATE_BASE_URL": base,
        "GATE_EVIDENCE_DIR": str(ev),
        "GATE_TOKEN_ADMIN02": "admin-token",
        "GATE_TOKEN_USER_A": "user-token",
        "SEC_BACKEND_PASS": "x",
    })
    if endpoints is not None:
        p = tmp_path / "endpoints.json"
        p.write_text(json.dumps({"endpoints": endpoints}), encoding="utf-8")
        env["GATE_ENDPOINTS_FILE"] = str(p)
    if all_eps is not None:
        p = tmp_path / "all.json"
        p.write_text(json.dumps({"endpoints": all_eps}), encoding="utf-8")
        env["GATE_ALL_ENDPOINTS_FILE"] = str(p)
    if extra_env:
        env.update(extra_env)
    p = subprocess.run([PY, os.path.join(ROOT, script)], cwd=ROOT, env=env,
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    name = os.path.splitext(os.path.basename(script))[0] + ".json"
    path = os.path.join(str(ev), name)
    assert os.path.exists(path), f"{script} 未产出证据: {p.stdout[-300:]} {p.stderr[-300:]}"
    return json.load(open(path, encoding="utf-8"))


def highs(ev):
    return [f for f in ev.get("findings") or [] if f.get("severity") in ("critical", "high")]


def test_xss_reflection(server, tmp_path):
    srv, base = server
    MODE["value"] = "vuln"
    ev = run_check("checks/xss_full.py", base, tmp_path / "x1",
                   endpoints=[{"method": "GET", "path": "/search", "query_keys": ["q"]}])
    assert highs(ev), ev
    MODE["value"] = "fixed"
    ev = run_check("checks/xss_full.py", base, tmp_path / "x2",
                   endpoints=[{"method": "GET", "path": "/search", "query_keys": ["q"]}])
    assert not highs(ev)


def test_file_download(server, tmp_path):
    MODE["value"] = "vuln"
    srv, base = server
    ev = run_check("checks/file_download.py", base, tmp_path / "d1", all_eps=["/download"])
    assert highs(ev), ev
    MODE["value"] = "fixed"
    ev = run_check("checks/file_download.py", base, tmp_path / "d2", all_eps=["/download"])
    assert not highs(ev)


def test_auth_token_refresh(server, tmp_path):
    srv, base = server
    MODE["value"] = "vuln"
    ev = run_check("checks/auth_token_checks.py", base, tmp_path / "a1")
    assert highs(ev), ev
    MODE["value"] = "fixed"
    ev = run_check("checks/auth_token_checks.py", base, tmp_path / "a2")
    assert not highs(ev), ev


def test_upload_webshell(server, tmp_path):
    srv, base = server
    MODE["value"] = "vuln"
    ev = run_check("checks/upload_webshell.py", base, tmp_path / "u1")
    assert highs(ev), ev
    MODE["value"] = "fixed"
    ev = run_check("checks/upload_webshell.py", base, tmp_path / "u2")
    assert not highs(ev)


def test_soap_default_key(server, tmp_path):
    srv, base = server
    MODE["value"] = "vuln"
    ev = run_check("checks/soap_checks.py", base, tmp_path / "s1")
    assert highs(ev), ev
    MODE["value"] = "fixed"
    ev = run_check("checks/soap_checks.py", base, tmp_path / "s2")
    assert not highs(ev)


def test_secret_scan_fixture(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    (d / "app.js").write_text('const password = "SuperSecret123";', encoding="utf-8")
    MODE["value"] = "vuln"
    ev = run_check("checks/secret_scan.py", "http://127.0.0.1:1", tmp_path / "sec1",
                   extra_env={"GATE_SECRET_DIRS": str(d)})
    assert highs(ev), ev
    fixed = tmp_path / "clean"
    fixed.mkdir()
    (fixed / "app.js").write_text('const password = "";', encoding="utf-8")
    ev = run_check("checks/secret_scan.py", "http://127.0.0.1:1", tmp_path / "sec2",
                   extra_env={"GATE_SECRET_DIRS": str(fixed)})
    assert not highs(ev)


def test_client_crypto_fixture(tmp_path):
    d = tmp_path / "js"
    d.mkdir()
    (d / "app.js").write_text('var keyen="8f071f3441a847e88f071f3441a847e8";', encoding="utf-8")
    ev = run_check("checks/client_crypto.py", "http://127.0.0.1:1", tmp_path / "c1",
                   extra_env={"GATE_CHUNKS_DIR": str(d)})
    assert highs(ev), ev
    clean = tmp_path / "cleanjs"
    clean.mkdir()
    (clean / "app.js").write_text("var a=1;", encoding="utf-8")
    ev = run_check("checks/client_crypto.py", "http://127.0.0.1:1", tmp_path / "c2",
                   extra_env={"GATE_CHUNKS_DIR": str(clean)})
    assert not highs(ev)
