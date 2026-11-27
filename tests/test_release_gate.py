#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""门禁引擎单元测试：通过/失败/豁免/阻塞/缺失检查。"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from runner.release_gate import evaluate, match_exception  # noqa: E402


def cfg(required=("chk_a",), blocked=False, fail_sev=("critical", "high")):
    return {
        "checks": {"chk_a": {"category": "application"}},
        "categories": {"application": {"title": "应用安全", "required": list(required),
                                       "fail_severities": list(fail_sev),
                                       "blocked_is_failure": blocked}},
    }


def test_pass_when_no_findings():
    cats, overall, _ = evaluate(cfg(), {"chk_a": {"status": "PASS", "findings": []}}, [])
    assert cats["application"]["status"] == "PASS"
    assert overall == "PASS"


def test_fail_on_high_finding():
    res = {"chk_a": {"status": "PASS", "findings": [
        {"id": "X-1", "severity": "high", "title": "XSS"}]}}
    cats, overall, _ = evaluate(cfg(), res, [])
    assert cats["application"]["status"] == "FAIL"
    assert overall == "FAIL"
    assert cats["application"]["blocking_findings"]


def test_exception_allows_pass_with_exceptions():
    res = {"chk_a": {"status": "PASS", "findings": [
        {"id": "X-1", "severity": "high", "title": "XSS"}]}}
    exc = [{"id": "X-1", "reason": "accepted", "owner": "qa", "expires": "2099-01-01"}]
    cats, overall, excepted = evaluate(cfg(), res, exc)
    assert cats["application"]["status"] == "PASS_WITH_EXCEPTIONS"
    assert overall == "PASS_WITH_EXCEPTIONS"
    assert len(excepted) == 1


def test_missing_required_check_blocks():
    cats, overall, _ = evaluate(cfg(required=("chk_a", "chk_b"), blocked=True), {},
                                [])
    assert cats["application"]["status"] == "BLOCKED"
    assert overall == "BLOCKED"
    assert "chk_b" in cats["application"]["blocked_checks"]


def test_blocked_check_without_fail_flag_still_blocked():
    res = {"chk_a": {"status": "BLOCKED", "findings": []}}
    cats, overall, _ = evaluate(cfg(blocked=False), res, [])
    assert cats["application"]["status"] == "BLOCKED"
    assert overall == "BLOCKED"


def test_low_severity_is_not_blocking():
    res = {"chk_a": {"status": "PASS", "findings": [
        {"id": "M-1", "severity": "medium", "title": "info"}]}}
    cats, overall, _ = evaluate(cfg(), res, [])
    assert cats["application"]["status"] == "PASS_WITH_FINDINGS"
    assert overall == "PASS_WITH_FINDINGS"


def test_match_exception_by_check_or_id():
    assert match_exception({"id": "X-1", "title": "t"}, "chk", [{"id": "X-1"}, {"id": "chk"}])
    assert match_exception({"id": "A", "title": "B"}, "chk", [{"id": "chk:B"}])
    assert match_exception({"id": "A", "title": "B"}, "chk", [{"id": "other"}]) is None
