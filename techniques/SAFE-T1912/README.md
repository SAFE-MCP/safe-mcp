# SAFE-T1912: Stego Response Exfiltration

## Overview

Tactic: Exfiltration (ATK-TA0010)
Technique ID: SAFE-T1912
Severity: High
 # SAFE-T1912: Stego Response Exfiltration

## Overview

Tactic: Exfiltration (ATK-TA0010)
Technique ID: SAFE-T1912
Severity: High
First Observed: Not observed in production
Last Updated: 2025-11-26

## Description
Stego Response Exfiltration is a technique where attackers embed covert payloads inside AI-generated or MCP-generated responses. These payloads are commonly hidden in code blocks, JSON structures, logs, or markdown elements that users frequently copy or paste into external systems. The embedded content may consist of zero-width Unicode characters, encoded payloads, or structured steganographic data that allows attackers to exfiltrate information without detection.

From a technical perspective, the attack exploits the tendency of AI-generated structured outputs to appear trustworthy. MCP systems often generate code, configuration, or schema-based responses; attackers manipulate these formats to insert high‑entropy data or invisible characters that remain undetected by basic sanitation. When users transfer these outputs into IDEs, build systems, cloud consoles, or other environments, the payload propagates and is eventually decoded or executed by downstream processes.

Stego Response Exfiltration is a technique where attackers embed covert payloads inside AI-generated or MCP-generated responses. These payloads are commonly hidden in code blocks, JSON structures, logs, or markdown elements that users frequently copy or paste into external systems. The embedded content may consist of zero-width Unicode characters, encoded payloads, or structured steganographic data that allows attackers to exfiltrate information without detection.

From a technical perspective, the attack exploits the tendency of AI-generated structured outputs to appear trustworthy. MCP systems often generate code, configuration, or schema-based responses; attackers manipulate these formats to insert high‑entropy data or invisible characters that remain undetected by basic sanitation. When users transfer these outputs into IDEs, build systems, cloud consoles, or other environments, the payload propagates and is eventually decoded or executed by downstream processes.

## Attack Vectors

**Primary Vector:** Payload hidden inside AI-generated code blocks, JSON, or structured output.

**Secondary Vectors:**

- Zero-width character encoding (e.g., U+200B, U+200C).

- Hidden payloads inside comments, markdown, or unused configuration parameters.

## Technical Details

### Prerequisites

- Attacker can influence or modify the AI/MCP response (direct prompt injection, indirect poisoning).

- User transfers or copies the content into another system that processes structured text.

## Attack Flow

### Initial Stage – Prompt Influence
Attacker manipulates the AI system to output predictable structures (code/JSON).

### Payload Preparation
Covert data encoded using zero-width Unicode, base64, compressed blobs, or steganographic patterns.

### Embedding Stage
Hidden content inserted into comments, whitespace, unused config keys, or token patterns.

### Exploitation Stage
User copies the response into another system where the payload is parsed, executed, or decoded.

### Post-Exploitation
Payload exfiltrates confidential data back to an attacker-controlled channel or establishes persistence.

## Example Scenario
{
  "config": {
    "theme": "light",
    "user_settings": "ZW1iZGRlZF9leGZpbF9kYXRh" // Hidden exfil payload (Base64-encoded)
  }
}
{
  "config": {
    "theme": "light",
    "user_settings": "ZW1iZGRlZF9leGZpbF9kYXRh" // Hidden exfil payload (Base64-encoded)
  }
}

## Advanced Attack Techniques (2023–2024 Research)

According to research from LLM-Steganography (Zou et al., 2023) and StegLLM (Liu et al., 2024), attackers have developed sophisticated variations:

### Zero-Width Character Encoding
Payload encoded using invisible Unicode sequences, enabling stealthy transport (Zou et al., 2023).

### Token-Pattern Steganography
Natural-language responses where sentence structure or token selection encodes binary payloads (Liu et al., 2024).

## Impact Assessment

Confidentiality: High – Stealthy extraction of sensitive data through invisible or encoded payloads.

Integrity: Medium – Payload may alter configuration files or execution flows.

Availability: Low – Technique does not target system disruption.

Scope: Network-wide – Payload spreads via copy/paste into tools, repositories, or CI/CD pipelines.

## Current Status (2025)

Security researchers report that most AI systems do not sanitize zero-width Unicode or detect steganographic encoding in structured responses. Organizations have begun introducing:

- Zero-width Unicode filtering

- Entropy-based scanning of AI-generated outputs

- Strict schema validation to block unexpected fields

(Sources: OWASP Top 10 for LLM Applications, MCP Security Notes)

## Detection Methods
### Indicators of Compromise (IoCs)

- Presence of zero-width Unicode characters in configuration files.

- Unexpected base64, hex, or compressed blobs in simple AI-generated outputs.

- AI responses with abnormally large or nested code blocks unrelated to query intent.

### Detection Rules

Important: The following Sigma rule is an example only and not comprehensive.

title: Stego Payload Embedded in MCP Responses
id: 7b29c1c4-9730-4e13-9ef0-52e48cbb2c61
status: experimental
description: Detects suspicious zero-width characters or encoded blobs in MCP responses.
author: rajivsthh
date: 2025/11/26
references:
  - https://github.com/safe-mcp/techniques/SAFE-T1912
logsource:
  product: mcp
  service: response
detection:
  selection:
    response.text|re:
      - '\u200b'
      - '\u200c'
      - '^[A-Za-z0-9+/]{20,}={0,2}$'
  condition: selection
falsepositives:
  - Legitimate encoded configuration values
  - Tools that embed base64 for expected features
level: high
tags:
  - attack.exfiltration
  - attack.t1020
  - safe.t1912

### Behavioral Indicators

- Users copy unusually large portions of AI output into external systems.

- Presence of encoded or invisible content in repository commits.

- CI pipelines failing due to unexpected encoded fields.

## Mitigation Strategies
### Preventive Controls

- SAFE-M-003: Output Sanitization
  - Strip zero-width Unicode, validate character classes, and reject suspicious embedded content.

- SAFE-M-014: Model Response Validation
  - Enforce strict schemas; reject unknown fields or high-entropy values.

- SAFE-M-021: Content Security Filtering
  - Detect and block compressed blobs, base64 strings, or hidden comments in non-binary contexts.

### Detective Controls

- SAFE-M-009: Steganography Detection Layer
  - Scan for entropy anomalies, invisible Unicode, or structural steganography.

- SAFE-M-011: Logging & Telemetry Controls
  - Monitor MCP responses for patterns consistent with hidden payloads.

## Response Procedures
### Immediate Actions

- Halt execution of workflows using potentially contaminated AI responses.

- Sanitize all recent AI/MCP outputs.

- Block user operations involving suspicious data.

### Investigation Steps

- Inspect logs for encoded or invisible Unicode.

- Analyze recently copied files and repository commits.

- Review CI/CD pipeline artifacts for hidden data propagation.

### Remediation

- Patch sanitization and validation modules.

- Add regression tests for zero-width Unicode and high‑entropy blocks.

- Deploy stricter schema enforcement for all AI-generated content.

## Related Techniques

- SAFE-T1006: User Social Engineering Install — Similar reliance on user trust and manual copying.

- SAFE-T1704: Compromised-Server Pivot — May chain with exfiltrated data for lateral movement.

## References

- Model Context Protocol Specification

- OWASP Top 10 for LLM Applications

- LLM-Steganography - Zou et al., 2023

- StegLLM - Liu et al., 2024

## MITRE ATT&CK Mapping

- T1020 – Automated Exfiltration
- https://attack.mitre.org/techniques/T1020/

## Version History
| Version | Date | Changes | Author |
|--------:|------|---------|--------|
| 1.0     | 2025-11-26 | Initial documentation | rajivsthh |