#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""应用层密码算法清单解析测试。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from checks.crypto_app import analyze  # noqa: E402


def test_analyze_counts():
    r = analyze('var k="8f07"; AES.encrypt(x); DES; RSA 1024; md5(x); SM4')
    assert r["aes"] >= 1 and r["des"] >= 1 and r["md5"] >= 1
    assert 1024 in r["rsa_sizes"]
    assert r["sm4"] >= 1


def test_analyze_empty():
    r = analyze("")
    assert r["aes"] == 0 and r["rsa_sizes"] == []
