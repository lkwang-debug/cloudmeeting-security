#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""多发行版 OSV 生态映射测试。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from checks.os_mapping import ecosystem_for  # noqa: E402


def test_mappings():
    assert ecosystem_for("openEuler", "22.03")[0] == "openEuler"
    assert ecosystem_for("Kylin", "V10")[0] == "Red Hat:8"
    assert ecosystem_for("CentOS", "7.9")[0] == "Red Hat:7"
    assert ecosystem_for("CentOS", "8")[0] == "Red Hat:8"
    assert ecosystem_for("UOS", "20")[0] == "Debian:10"
    assert ecosystem_for("Debian", "11")[0] == "Debian:11"
    assert ecosystem_for("UnknownOS", "1")[0] is None


def test_confidence_levels():
    assert ecosystem_for("openEuler", "22.03")[1] == "high"
    assert ecosystem_for("Kylin", "V10")[1] == "medium"
    assert ecosystem_for("UOS", "20")[1] == "low"
