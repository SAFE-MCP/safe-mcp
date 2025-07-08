# SAFE-M-7: Description Rendering Parity

## Overview
**Mitigation ID**: SAFE-M-7  
**Category**: UI Security  
**Effectiveness**: Medium-High  
**Implementation Complexity**: Low  
**First Published**: 2025-01-03

## Description
Description Rendering Parity ensures that what users see in the UI exactly matches what is sent to the LLM, preventing attacks that exploit differences between displayed and processed content.

## Mitigates
- [SAFE-T1001](../../techniques/SAFE-T1001/README.md): Tool Poisoning Attack (TPA)
- [SAFE-T1401](../../techniques/SAFE-T1401/README.md): Line Jumping
- [SAFE-T1402](../../techniques/SAFE-T1402/README.md): Instruction Steganography

## Technical Implementation
[TO BE COMPLETED]

## References
- [UI Security Best Practices](https://owasp.org/www-project-web-security-testing-guide/)

## Related Mitigations
- [SAFE-M-8](../SAFE-M-8/README.md): Visual Validation
- [SAFE-M-4](../SAFE-M-4/README.md): Unicode Sanitization and Filtering

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 0.1 | 2025-01-03 | Initial stub | Frederick Kautz |