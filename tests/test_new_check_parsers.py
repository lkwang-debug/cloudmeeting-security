#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""新增检查的解析器单元测试（Trivy/Grype/AppScan）。"""
import json
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from checks import trivy_cve, grype_cve, import_appscan  # noqa: E402


def test_trivy_parse():
    data = {"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "p", "InstalledVersion": "1",
         "Severity": "HIGH", "FixedVersion": "2"}]}]}
    out = trivy_cve.parse(data)
    assert len(out) == 1 and out[0]["severity"] == "high"


def test_grype_parse():
    data = {"matches": [{"vulnerability": {"id": "GHSA-1", "severity": "High",
                                          "fix": {"versions": ["2"]}},
                         "artifact": {"name": "p", "version": "1"}}]}
    out = grype_cve.parse(data)
    assert len(out) == 1 and out[0]["id"].startswith("GRYPE-")


def test_appscan_parse(tmp_path):
    p = tmp_path / "x.scan"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("incrementalScanData.json", json.dumps({"TestedEntities": {
            "e1": {"VulnerableRuleIds": ["attXSS", "attXSS"]}}}))
        z.writestr("templateConfig.xml",
                   '<root><IssueType Name="attXSS" Severity="High"/></root>')
    z = zipfile.ZipFile(p)
    res = import_appscan.parse(z)
    assert res["entities"] == 1
    assert res["findings"][0]["rule"] == "attXSS"
    assert res["findings"][0]["severity"] == "high"
