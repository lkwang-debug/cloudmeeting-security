#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""C：AI 证据复核器（规则版，可替换为 LLM 判决）。
对关键证据文件检查：存在性、正例/负例、复现字段、清理状态；输出 review JSON + Markdown。
"""
import json
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "reports", "final")

CHECKS = [
    {
        "id": "F-01-role-cache",
        "files": ["reports/p3/role_cache_invalidation.json", "reports/final/regression_role_cache.json"],
        "require": ["role_change_test", "verdict", "clean_cache_test"],
        "controls": ["clean_cache_test", "role_change_test"],
        "expected": {"regression verdict": "FAIL_CACHE_INVALIDATION"},
    },
    {
        "id": "F-02-share-api",
        "files": ["reports/p2/share_api_disclosure.json"],
        "require": ["endpoint", "response_fields", "verdict"],
        "controls": ["auth"],
        "expected": {},
    },
    {
        "id": "F-04-client-creds",
        "files": ["reports/p2/client_capture_summary.json"],
        "require": ["http", "notes"],
        "controls": ["notes"],
        "expected": {},
    },
    {
        "id": "XSS-confirm",
        "files": ["reports/p3/xss_browser_admin02.json"],
        "require": ["body_has_name", "escaped_img", "oast_hits"],
        "controls": ["token_in_html", "raw_payload_in_html"],
        "expected": {"escaped_img": True, "oast_hits": 0},
    },
    {
        "id": "WS-auth",
        "files": ["reports/p2/ws_webproxy_auth.json"],
        "require": ["results"],
        "controls": ["results"],
        "expected": {},
    },
    {
        "id": "scenario-room-limit",
        "files": ["reports/final/scenarios/room_maxuser_boundary.json"],
        "require": ["steps", "verdict"],
        "controls": ["cleanup"],
        "expected": {"verdict": "PASS"},
    },
]


def load(path):
    p = os.path.join(ROOT, path)
    if not os.path.exists(p):
        return None, "missing"
    try:
        return json.load(open(p, encoding="utf-8-sig")), None
    except Exception as e:
        return None, "parse_error: " + str(e)[:80]


def main():
    review = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "items": [], "summary": {}}
    ok = 0
    for chk in CHECKS:
        item = {"id": chk["id"], "files": chk["files"], "status": "PASS", "reasons": []}
        loaded = {}
        for f in chk["files"]:
            data, err = load(f)
            loaded[f] = data
            if err:
                item["status"] = "FAIL"; item["reasons"].append(f"{f}: {err}")
        merged = {}
        for d in loaded.values():
            if isinstance(d, dict):
                merged.update(d)
        for key in chk["require"]:
            if key not in merged:
                item["status"] = "FAIL"; item["reasons"].append(f"missing field: {key}")
        for key in chk["controls"]:
            if key not in merged:
                item["reasons"].append(f"missing control/context: {key} (warn)")
        for k, v in chk["expected"].items():
            if k in merged and merged[k] != v:
                item["status"] = "FAIL"; item["reasons"].append(f"expected {k}={v}, got {merged[k]}")
        if item["status"] == "PASS":
            ok += 1
        review["items"].append(item)
    review["summary"] = {"total": len(CHECKS), "pass": ok, "fail": len(CHECKS) - ok}
    json.dump(review, open(os.path.join(OUT, "ai_evidence_review.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    lines = ["# AI 证据复核结果（规则版）", "",
             f"- 时间：{review['generated_at']}", f"- 通过 {ok}/{len(CHECKS)}", ""]
    for it in review["items"]:
        lines.append(f"## {it['id']} — {it['status']}")
        for r in it["reasons"]:
            lines.append(f"- {r}")
        lines.append("")
    open(os.path.join(OUT, "ai_evidence_review.md"), "w", encoding="utf-8").write("\n".join(lines))
    print(json.dumps(review["summary"], ensure_ascii=False), "->", os.path.join(OUT, "ai_evidence_review.json"))


if __name__ == "__main__":
    main()
