#!/usr/bin/env python3
"""
Test Suite for SAFE-T1603: System-Prompt Disclosure

This test suite validates:
1) Basic structure expectations for techniques/SAFE-T1603/detection-rule.yml
2) Example detection logic against techniques/SAFE-T1603/test-logs.json

Notes:
- The Sigma rule is example-only; this test mirrors the intent (session correlation and pattern matching).
- Uses Python stdlib unittest (repo-consistent).

Author: Vikranth Kumar Shivaa
Date: 2025-12-17
"""

import json
import re
import unittest
from pathlib import Path
from typing import Any, Dict, List


UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class SystemPromptDisclosureDetector:
    """
    Minimal detector that mirrors the intent of techniques/SAFE-T1603/detection-rule.yml.
    Correlates within a session by evaluating the event list in a test case.
    """

    REQUEST_PHRASES_USER = (
        "system prompt",
        "developer message",
        "developer instructions",
        "hidden instructions",
        "dump tools",
        "tool json",
        "tools json",
        "inputschema",
        "verbatim",
    )

    REQUEST_PHRASES_IN_CONTEXT = (
        "reveal your system prompt",
        "print your system prompt",
        "dump tools json",
        "inputschema",
    )

    DISCLOSURE_SYSTEM_PROMPT_MARKERS = (
        "begin system prompt",
        "end system prompt",
        "developer message:",
        "system message:",
    )

    def detect(self, events: List[Dict[str, Any]]) -> bool:
        request_seen = False
        system_prompt_dump_seen = False
        tool_json_dump_seen = False

        for ev in events:
            event_type = (ev.get("event_type") or "").lower()
            content = (ev.get("content") or "")
            content_l = str(content).lower()

            if event_type == "user_message":
                if any(p in content_l for p in self.REQUEST_PHRASES_USER):
                    request_seen = True

            if event_type == "context_ingest":
                if any(p in content_l for p in self.REQUEST_PHRASES_IN_CONTEXT):
                    request_seen = True

            if event_type == "assistant_message":
                if any(m in content_l for m in self.DISCLOSURE_SYSTEM_PROMPT_MARKERS):
                    system_prompt_dump_seen = True

                # Tool registry/tool schema disclosure (example): require both tools and schema markers
                if '"tools"' in content_l and '"inputschema"' in content_l:
                    tool_json_dump_seen = True

        return request_seen and (system_prompt_dump_seen or tool_json_dump_seen)


def _parse_top_level_yaml_keys(yaml_text: str) -> Dict[str, str]:
    """
    Very small YAML helper: extracts top-level scalar keys (no nesting).
    This avoids external dependencies (PyYAML) while still verifying rule metadata.
    """
    keys: Dict[str, str] = {}
    for line in yaml_text.splitlines():
        raw = line.rstrip("\n")
        if not raw or raw.lstrip().startswith("#"):
            continue
        if raw.startswith(" ") or raw.startswith("\t"):
            continue  # nested
        if ":" not in raw:
            continue
        k, v = raw.split(":", 1)
        keys[k.strip()] = v.strip().strip("'").strip('"')
    return keys


class TestSAFE_T1603(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).parent
        self.rule_path = base / "detection-rule.yml"
        self.logs_path = base / "test-logs.json"
        self.detector = SystemPromptDisclosureDetector()

        with open(self.logs_path, "r", encoding="utf-8") as f:
            self.test_cases = json.load(f)

    def test_rule_structure(self):
        text = self.rule_path.read_text(encoding="utf-8")
        keys = _parse_top_level_yaml_keys(text)

        for required in (
            "title",
            "id",
            "status",
            "description",
            "author",
            "date",
            "logsource",
            "detection",
            "level",
            "tags",
        ):
            self.assertIn(required, text, f"Expected '{required}' section/key to exist in detection-rule.yml")

        self.assertIn("SAFE-T1603", keys.get("title", ""), "title should reference SAFE-T1603")
        self.assertTrue(UUID_V4_RE.match(keys.get("id", "")), "id should be a UUIDv4")
        self.assertEqual(keys.get("status"), "experimental")
        self.assertEqual(keys.get("author"), "Vikranth Kumar Shivaa")
        self.assertEqual(keys.get("date"), "2025-12-17")
        self.assertIn("safe.t1603", text.lower(), "tags should include safe.t1603")

    def test_cases_match_expectations(self):
        for case in self.test_cases:
            detected = self.detector.detect(case["events"])
            self.assertEqual(
                detected,
                case["expected_detection"],
                f"Mismatch for test_case={case.get('test_case')}: expected {case['expected_detection']} got {detected}",
            )


if __name__ == "__main__":
    unittest.main()


