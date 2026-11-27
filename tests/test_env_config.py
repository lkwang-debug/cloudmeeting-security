#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""统一环境配置测试。"""
import os

import pytest

from runner import env_config


def test_load_and_export(tmp_path, monkeypatch):
    p = tmp_path / "scan.yaml"
    p.write_text("""
env: {name: test, version: '1.0'}
web: {base_url: 'https://example.test:28443'}
accounts:
  admin: {username: admin, password: pass}
  idor_a: {username: a, password: p1, depart_id: 1}
  idor_b: {username: b, password: p2, depart_id: 2}
api: {openapi_key: k, openapi_secret: s}
scan: {allow_write_chain: false}
""", encoding="utf-8")
    monkeypatch.setenv("GATE_SCAN_CONFIG", str(p))
    cfg = env_config.load()
    assert cfg["env"]["name"] == "test"
    env_config.export_env(cfg)
    assert os.environ["GATE_BASE_URL"] == "https://example.test:28443"
    assert os.environ["SEC_OPEN_KEY"] == "k"
    assert os.environ["SEC_IDOR_A_USER"] == "a"


def test_missing_config(monkeypatch):
    monkeypatch.setenv("GATE_SCAN_CONFIG", "Z:/not-exists.yaml")
    with pytest.raises(FileNotFoundError):
        env_config.load()
