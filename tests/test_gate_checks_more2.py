#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""补充 fixture：SBOM/CVE/加密/SMS/XSS浏览器包装器 正反例。"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from checks import sbom_collect, cve_gate, crypto_inventory, sms_bomb, xss_browser  # noqa: E402
import checks.gate_common as gc  # noqa: E402


def evidence(tmp_path, cid):
    p = tmp_path / (cid + ".json")
    return json.load(open(p, encoding="utf-8"))


def test_sbom_collect_positive_and_negative(tmp_path, monkeypatch):
    monkeypatch.setattr(gc, "EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setattr(sbom_collect, "OUT", str(tmp_path / "sbom.json"))
    monkeypatch.setattr(sbom_collect, "maven_components", lambda: [])
    data = {
        "reports/p1/sbom_cyclonedx.json": {"components": [{"name": "a", "version": "1"}] * 60},
        "reports/final/container_sboms/containers_cyclonedx.json": {"components": [{"name": "b", "version": "2"}] * 60},
        "reports/final/java_sbom/java_dependencies.json": {"dependencies": [{"jar": "x.jar", "path": "/x"}]},
    }
    monkeypatch.setattr(sbom_collect, "load", lambda p: data.get(p, {}))
    sbom_collect.main()
    ev = evidence(tmp_path, "sbom_collect")
    assert not [f for f in ev["findings"] if f["severity"] == "high"]
    # 负例：空 SBOM 触发不完整提示
    monkeypatch.setattr(sbom_collect, "load", lambda p: {})
    sbom_collect.main()
    ev = evidence(tmp_path, "sbom_collect")
    assert any(f["id"] == "SBOM-INCOMPLETE" for f in ev["findings"])


def test_cve_gate_positive(tmp_path, monkeypatch):
    monkeypatch.setattr(gc, "EVIDENCE_DIR", str(tmp_path))
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({"components": [
        {"name": "pkg", "version": "1.0", "source": "container"}]}), encoding="utf-8")
    monkeypatch.setattr(cve_gate, "SBOM", str(sbom))

    class R:
        status_code = 200
        def json(self):
            return {"results": [{"vulns": [{"id": "CVE-1"}]}]}
        def raise_for_status(self):
            return None
    monkeypatch.setattr(cve_gate.requests, "post", lambda *a, **k: R())
    monkeypatch.setattr(cve_gate, "severity_of", lambda v: "high")
    cve_gate.main()
    ev = evidence(tmp_path, "cve_gate")
    assert any(f["severity"] == "high" for f in ev["findings"])


def test_crypto_js_des(tmp_path, monkeypatch):
    jsdir = tmp_path / "js"
    jsdir.mkdir()
    (jsdir / "a.js").write_text("CryptoJS.DES.encrypt; 3DES;", encoding="utf-8")
    monkeypatch.setenv("GATE_CHUNKS_DIR", str(jsdir))
    out = crypto_inventory.js_inventory()
    assert out["algorithms"]["DES"] >= 1


def test_sms_bomb_not_applicable(tmp_path, monkeypatch):
    monkeypatch.setattr(gc, "EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setattr(sms_bomb.gc, "all_endpoints", lambda: [])
    sms_bomb.main()
    ev = evidence(tmp_path, "sms_bomb")
    assert ev["status"] == "PASS"
    assert ev["findings"][0]["id"] == "SMS-NOT-APPLICABLE"


def test_xss_browser_escaped(tmp_path, monkeypatch):
    monkeypatch.setattr(gc, "EVIDENCE_DIR", str(tmp_path))
    res = tmp_path / "xss_room_ui.json"
    res.write_text(json.dumps({"checks": {"verdict": "ESCAPED"}}), encoding="utf-8")
    monkeypatch.setattr(xss_browser, "RESULT", str(res))
    monkeypatch.setattr(xss_browser.subprocess, "run", lambda *a, **k: type("P", (), {"returncode": 0})())
    xss_browser.main()
    ev = evidence(tmp_path, "xss_browser")
    assert ev["status"] == "PASS"


def test_xss_browser_possible_xss(tmp_path, monkeypatch):
    monkeypatch.setattr(gc, "EVIDENCE_DIR", str(tmp_path))
    res = tmp_path / "xss_room_ui.json"
    res.write_text(json.dumps({"checks": {"verdict": "POSSIBLE_XSS", "window_xss": 1}}), encoding="utf-8")
    monkeypatch.setattr(xss_browser, "RESULT", str(res))
    monkeypatch.setattr(xss_browser.subprocess, "run", lambda *a, **k: type("P", (), {"returncode": 0})())
    xss_browser.main()
    ev = evidence(tmp_path, "xss_browser")
    assert ev["status"] == "FAIL"
    assert any(f["severity"] == "high" for f in ev["findings"])
