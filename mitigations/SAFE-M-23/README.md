# SAFE-M-23: Tool Output Truncation

## Overview
**Mitigation ID**: SAFE-M-23  
**Category**: Preventive Control  
**Effectiveness**: Medium  
**Implementation Complexity**: Low  
**First Published**: 2025-01-09

## Description
Tool Output Truncation limits the size of tool outputs before they reach the LLM to prevent overwhelming the context with potentially malicious content. This mitigation implements configurable limits on output length, with different thresholds based on tool privilege levels and data types. By constraining output size, it reduces the attack surface for prompt injection attempts that rely on large volumes of text to hide malicious instructions.

## Mitigates
- [SAFE-T1102](../../techniques/SAFE-T1102/README.md): Prompt Injection (Multiple Vectors)
- [SAFE-T1103](../../techniques/SAFE-T1103/README.md): Indirect Prompt Injection
- [SAFE-T1601](../../techniques/SAFE-T1601/README.md): Context Window Saturation

## Technical Implementation
[TO BE COMPLETED]

## References
[TO BE COMPLETED]

## Related Mitigations
- [SAFE-M-21](../SAFE-M-21/README.md): Output Context Isolation
- [SAFE-M-22](../SAFE-M-22/README.md): Semantic Output Validation

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 0.1 | 2025-01-09 | Initial documentation | Frederick Kautz |