import json
from collections import defaultdict


def detect_repeated_calls(logs, window_minutes=5, threshold=10):
    buckets = defaultdict(int)
    for entry in logs:
        key = (entry.get("session_id"), entry.get("tool_name"), entry.get("args_hash"))
        buckets[key] += 1
    flagged = []
    for (session_id, tool_name, args_hash), count in buckets.items():
        if count >= threshold:
            flagged.append({
                "session_id": session_id,
                "tool_name": tool_name,
                "args_hash": args_hash,
                "count": count,
            })
    return flagged


if __name__ == "__main__":
    with open("test-logs.json", "r", encoding="utf-8") as f:
        logs = json.load(f)
    findings = detect_repeated_calls(logs, threshold=3)
    assert findings, "Expected at least one flagged loop symptom"
    print("Findings:", findings)


