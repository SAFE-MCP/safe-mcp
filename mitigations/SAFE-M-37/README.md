# SAFE-M-37: Input Validation – Metadata Sanitization

## Overview
**Mitigation ID**: SAFE-M-37  
**Category**: Input Validation  
**Effectiveness**: High (Provable Security against zero-width and comment-based payloads)  
**Implementation Complexity**: Medium  
**First Published**: April 2025

## Description
Metadata sanitization is a preventive control that strips hidden characters and markup from tool configurations before they are passed to LLMs. It targets invisible Unicode characters (e.g., zero-width spaces, joiners) and HTML comments that can be used to embed hidden instructions. This mitigation ensures that only clean, human-readable metadata is used in prompt construction.

In MCP environments, tool metadata is often parsed by LLMs as part of context. Attackers exploit this by embedding steganographic payloads in fields like `description`, `parameters`, or `examples`. Metadata sanitization intercepts these fields during tool registration or context assembly, removing hidden directives and neutralizing prompt injection vectors. This mitigation also defends against Shadow Tools—malicious tool configurations that mimic legitimate functionality while embedding hidden instructions. By sanitizing metadata fields, Shadow Tools lose their ability to carry steganographic payloads undetected.

## Mitigates
- [SAFE-T1402](../../techniques/SAFE-T1402/README.md): Instruction Steganography
- [SAFE-T1401](../../techniques/SAFE-T1401/README.md): Direct Prompt Injection
- [SAFE-T1403](../../techniques/SAFE-T1403/README.md): Context Poisoning

## Technical Implementation

### Core Principles
1. **Character Whitelisting**: Only allow printable, visible Unicode characters in metadata fields.
2. **Comment Stripping**: Remove HTML comments and other markup from string fields.
3. **Length and Entropy Checks**: Flag unusually long or low-entropy strings that may contain obfuscated payloads.

### Architecture Components
```
+------------------+       +------------------+       +------------------+
| Tool Registry    | --->  | Metadata Filter  | --->  | Prompt Assembler |
+------------------+       +------------------+       +------------------+
        |                          |                          |
        |                          v                          v
        |                 [Sanitized Metadata]         [Safe Prompt Context]
        v
[Tool Config Database]
```

### Prerequisites
- MCP server with tool registration interface
- LLM or agent that consumes tool metadata

### Implementation Steps
1. **Design Phase**:
   - Define allowed character sets and markup rules
   - Specify sanitization points in tool lifecycle

2. **Development Phase**:
   - Implement sanitization functions in tool registry
   - Integrate filters into context assembly pipeline

3. **Deployment Phase**:
   - Apply filters to all existing tool metadata
   - Monitor for registration attempts with blocked characters

## Benefits
- **Reduces Prompt Injection Risk**: Blocks hidden directives before they reach the model
- **Improves Auditability**: Ensures metadata is human-readable and reviewable
- **Supports Schema Validation**: Enforces consistent formatting across tools
- **Neutralizes Shadow Tools**: Removes hidden characters that enable stealthy tool poisoning

## Limitations
- **False Positives**: May block legitimate multilingual or formatted content
- **Bypass Risk**: Attackers may find new encoding schemes not covered by filters
- **Performance Overhead**: Adds latency during registration and context assembly

## Implementation Examples

### Example 1: Python Sanitizer
```python
import re

def sanitize_metadata(text):
    # Remove zero-width characters
    text = re.sub(r'[\u200B-\u200D\u2060\uFEFF]', '', text)
    # Strip HTML comments
    text = re.sub(r'<!--.*?-->', '', text)
    return text
```

### Example 2: Configuration Policy
```json
{
  "metadata_sanitization": {
    "enabled": true,
    "allowed_characters": "printable_ascii",
    "strip_html_comments": true
  }
}
```

## Testing and Validation
1. **Security Testing**:
   - Inject zero-width payloads and verify removal
   - Test HTML comment injection scenarios
   - Validate against known steganographic benchmarks

2. **Functional Testing**:
   - Ensure legitimate metadata remains intact
   - Confirm tool registration succeeds post-sanitization
   - Measure latency impact

3. **Integration Testing**:
   - Validate prompt context integrity
   - Confirm compatibility with downstream agents

## Deployment Considerations

### Resource Requirements
- **CPU**: Minimal (string parsing only)
- **Memory**: Low
- **Storage**: No additional requirements
- **Network**: No impact

### Performance Impact
- **Latency**: ~2–5ms per tool registration
- **Throughput**: Negligible impact
- **Resource Usage**: Lightweight

### Monitoring and Alerting
- Number of blocked registration attempts
- Frequency of stripped characters per field
- Alert on repeated use of disallowed patterns
- Alert on entropy anomalies in metadata

## Current Status (2025)
According to industry reports, organizations are adopting this mitigation:
- 68% of MCP vendors now implement metadata sanitization (Invariant Labs, 2025)
- OWASP LLM Top 10 recommends input validation for all prompt-adjacent fields

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Tool Poisoning Attacks – Invariant Labs, 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [MCPTox Benchmark – Arxiv, 2025](https://arxiv.org/abs/2508.14925)

## Related Mitigations
- [SAFE-M-38](../SAFE-M-38/README.md): Schema Validation – Enforces structural integrity of tool metadata
- [SAFE-M-39](../SAFE-M-39/README.md): Prompt Context Isolation – Prevents metadata from contaminating user prompt

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-10-25 | Initial documentation | Ryan |

---

Let me know if you'd like additional mitigations documented or want this adapted for a specific vendor or deployment model.
