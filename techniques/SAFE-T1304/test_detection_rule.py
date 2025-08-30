#!/usr/bin/env python3
"""
Test suite for SAFE-T1304 Credential Relay Chain detection rule.

This validates the Sigma-like rule semantics for:
  (A) Token surfaced in one tool  -> (B) Privileged use in another tool within 5 minutes
  (OR)
  (C) Token Exchange + Privileged action

It also checks rule structure and required tags.
"""

import yaml
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

# ----------------------------
# Helpers & Constants (mirrors the YAML semantics)
# ----------------------------

SURFACE_TOOLS = {
    "log_reader", "file_reader", "debug_dumper", "http_client", "browser",
    "code_search", "notes_reader", "clipboard_reader"
}

PRIVILEGED_TOOLS = {
    "cloud_admin", "config_admin", "data_exporter", "iam_admin",
    "payments_admin", "gh_admin", "k8s_admin", "vault_admin"
}

PRIVILEGED_ACTIONS = {
    "assume_role", "create_user", "create_*", "delete_*", "rotate_*",
    "update_policy", "grant_*", "export_*", "transfer_*",
    "add_deploy_key", "mint_token"
}

BENIGN_TOOLS = {"unit_test_runner", "docs_builder", "linter"}

MOCK_TOKEN_MARKERS = {"TEST_TOKEN", "FAKE_TOKEN", "DUMMY"}

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"

FIVE_MIN = timedelta(minutes=5)

TOKEN_SUBSTRINGS = [
    "access_token", "refresh_token", "Authorization:", "Set-Cookie",
    "subject_token", "id_token"
]

TOKEN_PATTERNS = [
    r"eyJ[^.]*\.[^.]*\.[^.]*",     # JWT-ish
    r"AKIA[A-Z0-9]{8,}",           # AWS Access Key ID (loose)
    r"ghp_[A-Za-z0-9]{20,}",       # GitHub PAT (loose)
    r"xox[abp]-[A-Za-z0-9-]{10,}", # Slack tokens (loose)
    r"ya29\.[A-Za-z0-9\-_\.]{10,}" # Google access tokens (loose)
]

def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

# ----------------------------
# Synthetic Test Data
# ----------------------------

POSITIVE_EVENTS: List[Dict[str, Any]] = [
    # A) Surface -> Use within 3 minutes (should alert)
    {
        "timestamp": "2025-08-30T10:00:00Z",
        "event_type": "tool_output",
        "tool_name": "log_reader",
        "session_id": "S1",
        "user": "ai_assistant",
        "output": "Found access_token=ya29.A0ARfoobar and some logs..."
    },
    {
        "timestamp": "2025-08-30T10:02:00Z",
        "event_type": "tool_invocation",
        "tool_name": "cloud_admin",
        "session_id": "S1",
        "user": "ai_assistant",
        "action": "create_user",
        "result": "success"
    },

    # B) JWT-like token surfaced -> privileged action different tool
    {
        "timestamp": "2025-08-30T11:00:00Z",
        "event_type": "tool_output",
        "tool_name": "file_reader",
        "session_id": "S2",
        "user": "ai_assistant",
        "output": "JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xx.yy"
    },
    {
        "timestamp": "2025-08-30T11:04:00Z",
        "event_type": "tool_invocation",
        "tool_name": "gh_admin",
        "session_id": "S2",
        "user": "ai_assistant",
        "action": "add_deploy_key",
        "result": "success"
    },

    # C) Token Exchange path
    {
        "timestamp": "2025-08-30T12:00:00Z",
        "event_type": "tool_invocation",
        "tool_name": "cloud_admin",
        "session_id": "S3",
        "user": "ai_assistant",
        "action": "update_policy",
        "result": "success",
        "request": {
            "params": {
                "grant_type": TOKEN_EXCHANGE_GRANT,
                "subject_token": "eyJ.some.subject.token"
            }
        }
    },
]

NEGATIVE_EVENTS: List[Dict[str, Any]] = [
    # Surface then privileged use after 10 minutes -> NO alert
    {
        "timestamp": "2025-08-30T13:00:00Z",
        "event_type": "tool_output",
        "tool_name": "log_reader",
        "session_id": "S4",
        "user": "ai_assistant",
        "output": "Set-Cookie: sessionid=abc; access_token=ya29.SLOW"
    },
    {
        "timestamp": "2025-08-30T13:11:00Z",
        "event_type": "tool_invocation",
        "tool_name": "cloud_admin",
        "session_id": "S4",
        "user": "ai_assistant",
        "action": "create_user",
        "result": "success"
    },

    # Surface with mock token markers -> filtered
    {
        "timestamp": "2025-08-30T14:00:00Z",
        "event_type": "tool_output",
        "tool_name": "log_reader",
        "session_id": "S5",
        "user": "ai_assistant",
        "output": "This is a TEST_TOKEN for demos"
    },
    {
        "timestamp": "2025-08-30T14:02:00Z",
        "event_type": "tool_invocation",
        "tool_name": "cloud_admin",
        "session_id": "S5",
        "user": "ai_assistant",
        "action": "create_user",
        "result": "success"
    },

    # Benign tool surfacing a token -> filtered
    {
        "timestamp": "2025-08-30T15:00:00Z",
        "event_type": "tool_output",
        "tool_name": "unit_test_runner",
        "session_id": "S6",
        "user": "ai_assistant",
        "output": "access_token=ya29.BENIGN"
    },
    {
        "timestamp": "2025-08-30T15:03:00Z",
        "event_type": "tool_invocation",
        "tool_name": "cloud_admin",
        "session_id": "S6",
        "user": "ai_assistant",
        "action": "create_user",
        "result": "success"
    },

    # Privileged action with no prior surface and no token-exchange
    {
        "timestamp": "2025-08-30T16:00:00Z",
        "event_type": "tool_invocation",
        "tool_name": "vault_admin",
        "session_id": "S7",
        "user": "ai_assistant",
        "action": "rotate_keys",
        "result": "success"
    },

    # Surface followed by non-privileged tool
    {
        "timestamp": "2025-08-30T17:00:00Z",
        "event_type": "tool_output",
        "tool_name": "file_reader",
        "session_id": "S8",
        "user": "ai_assistant",
        "output": "Authorization: Bearer eyJ.foo.bar"
    },
    {
        "timestamp": "2025-08-30T17:01:00Z",
        "event_type": "tool_invocation",
        "tool_name": "notes_reader",
        "session_id": "S8",
        "user": "ai_assistant",
        "action": "open_note",
        "result": "success"
    },
]

# ----------------------------
# Rule loading & structure checks
# ----------------------------

def load_rule(path: str = "detection-rule.yml") -> Dict[str, Any]:
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print("Error: detection-rule.yml not found")
        return {}
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
        return {}

def validate_rule_structure(rule: Dict[str, Any]) -> bool:
    required = ["title", "id", "status", "description", "tags", "logsource", "detection"]
    ok = True
    for k in required:
        if k not in rule:
            print(f"Missing required field: {k}")
            ok = False
    det = rule.get("detection", {})
    if "condition" not in det:
        print("Missing condition in detection section")
        ok = False
    return ok

def validate_tags(rule: Dict[str, Any]) -> bool:
    tags = set(rule.get("tags", []))
    required = {"attack.privilege_escalation", "safe-mcp", "safe-t1304"}
    missing = required - tags
    if missing:
        print(f"Missing required tags: {sorted(missing)}")
        return False
    return True

# ----------------------------
# Core detection emulation
# ----------------------------

def is_mock_token(text: str) -> bool:
    return any(marker in text.upper() for marker in MOCK_TOKEN_MARKERS)

def has_token_substrings(text: str) -> bool:
    return any(s in text for s in TOKEN_SUBSTRINGS)

def has_token_pattern(text: str) -> bool:
    return any(re.search(p, text) for p in TOKEN_PATTERNS)

def is_surface_event(e: Dict[str, Any]) -> bool:
    if e.get("event_type") != "tool_output":
        return False
    tool = e.get("tool_name", "")
    if tool in BENIGN_TOOLS:
        return False
    if tool not in SURFACE_TOOLS:
        return False
    output = e.get("output", "") or ""
    if not isinstance(output, str):
        return False
    if is_mock_token(output):
        return False
    return has_token_substrings(output) or has_token_pattern(output)

def action_matches(action: str, patterns: set) -> bool:
    for p in patterns:
        if p.endswith("*") and action.startswith(p[:-1]):
            return True
        if action == p:
            return True
    return False

def is_privileged_use_event(e: Dict[str, Any]) -> bool:
    if e.get("event_type") != "tool_invocation":
        return False
    if e.get("result") != "success":
        return False
    if e.get("tool_name") not in PRIVILEGED_TOOLS:
        return False
    return action_matches(e.get("action", "") or "", PRIVILEGED_ACTIONS)

def is_token_exchange_path(e: Dict[str, Any]) -> bool:
    if not is_privileged_use_event(e):
        return False
    req = e.get("request", {}).get("params", {})
    return req.get("grant_type") == TOKEN_EXCHANGE_GRANT and bool(req.get("subject_token"))

def correlate_surface_to_use(events: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    evs = sorted(events, key=lambda e: ts(e["timestamp"]))
    surfaces = [e for e in evs if is_surface_event(e)]
    uses = [e for e in evs if is_privileged_use_event(e)]
    pairs = []
    for s in surfaces:
        s_time = ts(s["timestamp"])
        sid, user = s.get("session_id"), s.get("user")
        for u in uses:
            u_time = ts(u["timestamp"])
            if not (s_time <= u_time <= s_time + FIVE_MIN):
                continue
            if sid and u.get("session_id") == sid:
                pairs.append((s, u))
            elif not sid and user and u.get("user") == user:
                pairs.append((s, u))
    return pairs

def detect_alerts(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts = []
    for s, u in correlate_surface_to_use(events):
        alerts.append({"path": "surface->use", "surface_event": s, "use_event": u})
    for e in events:
        if is_token_exchange_path(e):
            alerts.append({"path": "token-exchange", "event": e})
    return alerts

# ----------------------------
# Tests
# ----------------------------

def test_structure(rule: Dict[str, Any]) -> bool:
    return validate_rule_structure(rule)

def test_tags(rule: Dict[str, Any]) -> bool:
    return validate_tags(rule)

def test_positive_sequences() -> bool:
    alerts = detect_alerts(POSITIVE_EVENTS)
    by_path = {"surface->use": 0, "token-exchange": 0}
    for a in alerts:
        by_path[a["path"]] = by_path.get(a["path"], 0) + 1
    return by_path.get("surface->use", 0) == 2 and by_path.get("token-exchange", 0) == 1

def test_negative_sequences() -> bool:
    alerts = detect_alerts(NEGATIVE_EVENTS)
    return len(alerts) == 0

def run_all(rule: Dict[str, Any]) -> bool:
    tests = [
        ("Rule Structure", lambda: test_structure(rule)),
        ("Tags", lambda: test_tags(rule)),
        ("Positive Cases", test_positive_sequences),
        ("Negative Cases", test_negative_sequences),
    ]
    passed = sum(1 for name, fn in tests if fn())
    print(f"\n=== SUMMARY ===\nPassed {passed}/{len(tests)} tests")
    return passed == len(tests)

def main() -> int:
    print("SAFE-T1304 Detection Rule Test Suite")
    print("=" * 40)
    rule = load_rule()
    if not rule:
        return 1
    return 0 if run_all(rule) else 1

if __name__ == "__main__":
    raise SystemExit(main())
