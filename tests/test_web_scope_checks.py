#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Web 范围补充检查与报告模板的契约测试（不访问网络）。"""
import json
import os
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from checks import oauth_secret_check, csrf_check, ssrf_check, web_logic_check, rce_write_chain  # noqa: E402


def test_oauth_secret_detects_client_secret(tmp_path, monkeypatch):
    (tmp_path / "app.js").write_text(
        'var conf={client_secret:"abcdef123456",client_id:"cid-123456"};', encoding="utf-8")
    monkeypatch.setattr(oauth_secret_check, "CHUNKS", str(tmp_path))
    box = {}

    def fake_emit(check_id, category, status, findings=None, summary="", blocked_reason=""):
        box["findings"] = findings or []

    monkeypatch.setattr(oauth_secret_check.gc, "emit", fake_emit)
    oauth_secret_check.main()
    assert any(f["severity"] == "high" for f in box["findings"])


def test_web_checks_registered_and_nonweb_removed():
    cfg = yaml.safe_load(open(os.path.join(ROOT, "configs", "release_gate.yaml"), encoding="utf-8"))
    rel = cfg["profiles"]["release"]
    for cid in ("injection_extended", "csrf_check", "ssrf_check", "oauth_secret_check",
                "cookie_security", "web_logic_check", "asset_inventory"):
        assert cid in rel, cid
    for cid in ("ssh_algorithms", "host_baseline", "os_package_cve"):
        assert cid not in rel, cid


def test_report_template_has_reference_standard():
    p = os.path.join(ROOT, "runner", "build_assessment_report_internal.py")
    text = open(p, encoding="utf-8").read()
    for s in ("6. 参考标准", "6.1 单一系统漏洞风险等级评定标准",
              "6.2 单一Web漏洞风险等级评定标准", "6.3 单一资产风险等级评定标准"):
        assert s in text


def _capture(mod, monkeypatch):
    box = {}

    def fake_emit(check_id, category, status, findings=None, summary="", blocked_reason=""):
        box.update({"status": status, "findings": findings or [], "blocked": blocked_reason})

    monkeypatch.setattr(mod.gc, "emit", fake_emit)
    return box


def test_automation_checks_run_with_config(monkeypatch):
    for mod in (csrf_check, ssrf_check, web_logic_check, rce_write_chain):
        box = _capture(mod, monkeypatch)
        mod.main()
        assert box["status"] in ("PASS", "BLOCKED")


def test_web_automation_config_sections():
    import yaml
    cfg = yaml.safe_load(open(os.path.join(ROOT, "configs", "web_automation.yaml"), encoding="utf-8"))
    for key in ("csrf", "ssrf", "business_logic", "rce_write_chain"):
        assert key in cfg
