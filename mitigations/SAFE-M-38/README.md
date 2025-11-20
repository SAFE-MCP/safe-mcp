# SAFE-M-38: Input Validation – Schema Validation

## Overview
**Mitigation ID**: SAFE-M-38  
**Category**: Input Validation  
**Effectiveness**: Medium-High (Blocks malformed and ambiguous metadata before prompt assembly)  
**Implementation Complexity**: Medium  
**First Published**: April 2025

## Description
Schema validation ensures that all tool metadata and configuration fields conform to a strict, predefined structure. This prevents attackers from injecting hidden instructions or malformed content into fields that are parsed by LLMs. By enforcing type constraints, length limits, and formatting rules, schema validation acts as a gatekeeper for MCP tool registration and prompt context assembly.

In MCP-based systems, tool metadata is often dynamically assembled into prompts. Without schema enforcement, fields like `description`, `parameters`, or `examples` can carry ambiguous or malicious content. Schema validation blocks these vectors by rejecting inputs that deviate from expected formats, contain disallowed characters, or exceed safe complexity thresholds. Schema validation is especially effective against Shadow Tools, which often exploit loosely typed or overly permissive metadata fields. By enforcing strict schemas, these tools are rejected before they can be registered or used.

## Mitigates
- [SAFE-T1402](../../techniques/SAFE-T1402/README.md): Instruction Steganography
- [SAFE-T1403](../../techniques/SAFE-T1403/README.md): Context Poisoning
- [SAFE-T1401](../../techniques/SAFE-T1401/README.md): Direct Prompt Injection

## Technical Implementation

### Core Principles
1. **Strict Typing**: Enforce data types for all fields (e.g., string, array, boolean).
2. **Length Constraints**: Limit field lengths to prevent hidden payloads or prompt overflow.
3. **Character Validation**: Disallow non-printable, zero-width, and markup characters.

### Architecture Components
```
+------------------+       +------------------+       +------------------+
| Tool Registry    | --->  | Schema Validator | --->  | Prompt Assembler |
+------------------+       +------------------+       +------------------+
        |                          |                          |
        |                          v                          v
        |                 [Validated Metadata]         [Safe Prompt Context]
        v
[Tool Config Database]
```

### Prerequisites
- Defined JSON schema for MCP tool metadata
- Validation engine integrated into registration and context flow

### Implementation Steps
1. **Design Phase**:
   - Define schema for each metadata field
   - Specify allowed character sets and formatting rules

2. **Development Phase**:
   - Implement schema validation using libraries (e.g., `jsonschema`, `pydantic`)
   - Integrate validation into tool registration and prompt assembly

3. **Deployment Phase**:
   - Apply schema checks to all incoming tool configs
   - Reject or quarantine non-compliant entries

## Benefits
- **Blocks Malformed Inputs**: Prevents ambiguous or dangerous metadata from reaching the model
- **Improves Consistency**: Enforces uniform formatting across tools and agents
- **Supports Downstream Security**: Enables layered defenses like sanitization and context isolation
- **Blocks Shadow Tool Registration**: Prevents structurally valid but semantically malicious tools from entering the system

## Limitations
- **Schema Drift**: Requires updates as tool formats evolve
- **False Negatives**: May miss payloads that conform structurally but are semantically malicious
- **Developer Burden**: Requires coordination across teams to maintain schema integrity

## Implementation Examples

### Example 1: Python Schema Validation
```python
from jsonschema import validate, ValidationError

tool_schema = {
  "type": "object",
  "properties": {
    "name": {"type": "string", "maxLength": 50},
    "description": {
      "type": "string",
      "pattern": "^[\\x20-\\x7E]+$"  # Printable ASCII only
    },
    "parameters": {"type": "object"}
  },
  "required": ["name", "description", "parameters"]
}

def validate_tool_config(config):
    try:
        validate(instance=config, schema=tool_schema)
        return True
    except ValidationError as e:
        return False
```

### Example 2: Configuration Policy
```json
{
  "schema_validation": {
    "enabled": true,
    "max_description_length": 100,
    "allowed_characters": "printable_ascii",
    "required_fields": ["name", "description", "parameters"]
  }
}
```

## Testing and Validation
1. **Security Testing**:
   - Submit malformed tool configs and verify rejection
   - Test payloads with zero-width and markup characters
   - Validate against known prompt injection benchmarks

2. **Functional Testing**:
   - Confirm valid tools pass schema checks
   - Ensure error handling for rejected entries
   - Measure latency impact

3. **Integration Testing**:
   - Validate prompt context integrity post-validation
   - Confirm compatibility with MCP agents and registries

## Deployment Considerations

### Resource Requirements
- **CPU**: Low (schema parsing only)
- **Memory**: Minimal
- **Storage**: No additional requirements
- **Network**: No impact

### Performance Impact
- **Latency**: ~1–3ms per validation
- **Throughput**: Negligible impact
- **Resource Usage**: Lightweight

### Monitoring and Alerting
- Number of rejected tool configs
- Frequency of schema violations per field
- Alert on repeated use of disallowed patterns
- Alert on schema drift or version mismatch

## Current Status (2025)
According to industry reports, organizations are adopting this mitigation:
- 54% of MCP vendors now enforce schema validation (MCPTox Benchmark, 2025)
- OWASP LLM Top 10 recommends schema enforcement for all prompt-adjacent metadata

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Tool Poisoning Attacks – Invariant Labs, 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [MCPTox Benchmark – Arxiv, 2025](https://arxiv.org/abs/2508.14925)

## Related Mitigations
- [SAFE-M-37](../SAFE-M-37/README.md): Metadata Sanitization – Removes hidden characters from validated fields
- [SAFE-M-39](../SAFE-M-39/README.md): Prompt Context Isolation – Prevents metadata from contaminating user prompt

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-10-25 | Initial documentation | Ryan Jennings |

