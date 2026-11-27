#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""P0 全量覆盖工具测试：库存过滤、IDOR token 前置、API 清单解析。"""
import importlib.util
import json
import os

from checks import idor_objects, inventory_common


def test_inventory_filters_write_endpoints(monkeypatch):
    data = [
        {"method": "POST", "path": "/api/v1/user/list", "body_keys": ["pageNumber"]},
        {"method": "POST", "path": "/api/v1/user/add", "body_keys": ["userName"]},
        {"method": "DELETE", "path": "/api/v1/user/del", "body_keys": ["userName"]},
        {"method": "GET", "path": "/api/v1/room/summary/1", "query_keys": []},
    ]
    monkeypatch.setattr(inventory_common, "load", lambda: data)
    eps = inventory_common.read_endpoints()
    paths = [e["path"] for e in eps]
    assert "/api/v1/user/list" in paths
    assert "/api/v1/user/add" not in paths
    assert "/api/v1/user/del" not in paths


def test_idor_objects_blocks_without_tokens(monkeypatch):
    monkeypatch.setenv("GATE_SCAN_CONFIG", "Z:/not-exists.yaml")
    monkeypatch.setattr(idor_objects, "load_cfg", lambda: {"idor_accounts": {}})
    box = {}
    monkeypatch.setattr(idor_objects.gc, "emit",
                        lambda cid, cat, status, findings, **kw: box.update(status=status, blocked=kw.get("blocked_reason")))
    idor_objects.main()
    assert box["status"] == "BLOCKED"


def test_api_inventory_parse_html(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location(
        "build_api_inventory", os.path.join(os.path.dirname(__file__), "..", "tools", "build_api_inventory.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    p = tmp_path / "api.html"
    p.write_text('<p><strong>Path：</strong> /api/v1/demo/list</p><p><strong>Method：</strong> POST</p>', encoding="utf-8")
    store = {}
    monkeypatch.setattr(mod, "API_HTML", str(p))
    mod.parse_html(store)
    assert ("POST", "/api/v1/demo/list") in store


def test_token_refresh_script_present():
    p = os.path.join(os.path.dirname(__file__), "..", "runner", "refresh_web_tokens.py")
    assert os.path.exists(p)
