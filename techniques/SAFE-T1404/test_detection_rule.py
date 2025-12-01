#!/usr/bin/env python3
"""
Pytest tests for SAFE-T1404 (Response Tampering) detection rule

Mirrors the style of other technique tests in this repo.
"""

import json
from pathlib import Path
from typing import Dict, List

import pytest
import yaml


def load_detection_rule() -> Dict:
    rule_path = Path(__file__).parent / "detection-rule.yml"
    with rule_path.open("r") as f:
        return yaml.safe_load(f)


def extract_contains_terms(selection: Dict) -> Dict[str, List[str]]:
    terms: Dict[str, List[str]] = {}
    for key, value in selection.items():
        if "|contains" in key and isinstance(value, list):
            field = key.split("|", 1)[0]
            terms[field] = value
    return terms


def case_insensitive_contains(haystack: str, needles: List[str]) -> bool:
    hs = haystack.lower()
    return any(n.lower() in hs for n in needles)


def event_matches_selection(event: Dict, field_terms: Dict[str, List[str]]) -> bool:
    # AND across fields, OR within field term lists
    for field, terms in field_terms.items():
        value = str(event.get(field, ""))
        if not case_insensitive_contains(value, terms):
            return False
    return True


def load_test_events() -> List[Dict]:
    logs_path = Path(__file__).parent / "test-logs.json"
    events: List[Dict] = []
    with logs_path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


def expected_by_case() -> Dict[str, bool]:
    return {
        # Positives: suppression phrase + risky action
        "hide_delete_basic": True,
        "hide_disable_alerts": True,
        "omit_escalation": True,
        # Negatives and edge cases
        "benign_summary_delete": False,
        "benign_prompt_text": False,
        "no_action_type": False,
        "hide_phrase_without_risky_action": False,
        "risky_action_without_hide_phrase": False,
    }


def test_rule_structure():
    rule = load_detection_rule()
    assert "title" in rule
    assert "id" in rule
    assert "detection" in rule
    assert "logsource" in rule
    # Technique reference via description or tag
    assert (
        "SAFE-T1404" in rule.get("description", "")
        or "safe.t1404" in " ".join(rule.get("tags", []))
    )


def test_detection_logic():
    rule = load_detection_rule()
    detection = rule["detection"]
    assert "selection_keywords" in detection
    assert "condition" in detection
    field_terms = extract_contains_terms(detection["selection_keywords"])
    # Expect both fields used in the rule
    assert "prompt_text" in field_terms
    assert "action_type" in field_terms


def test_positive_cases():
    rule = load_detection_rule()
    field_terms = extract_contains_terms(rule["detection"]["selection_keywords"])
    events = load_test_events()
    expected = expected_by_case()

    positives = [e for e in events if expected.get(e.get("case"))]
    assert positives, "No positive test cases loaded"

    for ev in positives:
        assert event_matches_selection(ev, field_terms), f"Should detect: {ev['case']}"


def test_negative_cases():
    rule = load_detection_rule()
    field_terms = extract_contains_terms(rule["detection"]["selection_keywords"])
    events = load_test_events()
    expected = expected_by_case()

    negatives = [e for e in events if expected.get(e.get("case")) is False]
    assert negatives, "No negative test cases loaded"

    for ev in negatives:
        assert not event_matches_selection(ev, field_terms), f"Should not detect: {ev['case']}"


def test_false_positives_section():
    rule = load_detection_rule()
    assert "falsepositives" in rule
    fp = " ".join(rule["falsepositives"]).lower()
    assert "benign" in fp or "compliance" in fp or "redact" in fp


def test_tags_and_level():
    rule = load_detection_rule()
    assert "tags" in rule
    tags = set(rule["tags"])
    assert "attack.defense-evasion" in tags
    assert "attack.t1562" in tags
    assert "attack.t1564" in tags
    assert "safe.t1404" in tags
    assert rule.get("level") in ["low", "medium", "high", "critical"]
