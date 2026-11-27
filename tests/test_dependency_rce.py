#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""RCE 依赖联查单元测试。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from checks.dependency_rce import evaluate  # noqa: E402


def test_dependency_rules():
    comps = [
        {"name": "com.alibaba:fastjson", "version": "1.2.83"},
        {"name": "libfastjson", "version": "0.99.9-1.ky10"},
        {"name": "org.yaml:snakeyaml", "version": "1.29"},
        {"name": "log4j-core", "version": "2.14.1"},
        {"name": "log4j-core", "version": "2.17.1"},
    ]
    hits = evaluate(comps)
    names = {h["component"] for h in hits}
    assert "org.yaml:snakeyaml" in names
    assert "log4j-core" in names  # 2.14.1 vulnerable
    assert "libfastjson" not in names
    # 2.17.1 不应命中
    assert not any(h["component"] == "log4j-core" and h["version"] == "2.17.1" for h in hits)
