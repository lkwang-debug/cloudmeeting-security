#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""客户扫描器对比逻辑单元测试。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from runner.scanner_compare import compare, map_check  # noqa: E402


def test_map_check():
    assert map_check("Reflected XSS") == "xss_full"
    assert map_check("任意文件下载") == "file_download"
    assert map_check("SQL Injection") == "injection_matrix"


def test_compare_coverage():
    gate = {"checks": {"xss_full": {}, "file_download": {}}}
    ext = [{"title": "XSS", "severity": "high"},
           {"title": "路径下载", "severity": "medium"},
           {"title": "SQLi", "severity": "high"}]
    res = compare(gate, ext)
    assert res["external_total"] == 3
    assert res["covered"] == 2
    assert res["uncovered"] == 1
    assert res["coverage_pct"] == 66.7
