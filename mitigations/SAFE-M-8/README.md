# SAFE-M-8: Visual Validation

## Overview
**Mitigation ID**: SAFE-M-8  
**Category**: UI Security  
**Effectiveness**: Medium  
**Implementation Complexity**: Medium  
**First Published**: 2025-01-03

## Description
Visual Validation compares the visual rendering of descriptions with actual content to detect invisible characters, using techniques like screenshot comparison or rendering analysis to identify discrepancies.

## Mitigates
- [SAFE-T1001](../../techniques/SAFE-T1001/README.md): Tool Poisoning Attack (TPA)
- [SAFE-T1402](../../techniques/SAFE-T1402/README.md): Instruction Steganography

## Technical Implementation
[TO BE COMPLETED]

## References
- [Promptfoo Research on Invisible Characters](https://www.promptfoo.dev/blog/invisible-unicode-threats/)
- [OWASP Web Security Testing Guide v4.2 - Testing for Clickjacking](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking)
- [GUI Testing Using Computer Vision - CHI 2010](https://dl.acm.org/doi/10.1145/1753326.1753555)
- [Percy Visual Testing Documentation](https://www.browserstack.com/docs/percy)
- [Applitools Visual AI Documentation](https://applitools.com/docs/)

## Related Mitigations
- [SAFE-M-7](../SAFE-M-7/README.md): Description Rendering Parity
- [SAFE-M-4](../SAFE-M-4/README.md): Unicode Sanitization and Filtering

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 0.1 | 2025-01-03 | Initial stub | Frederick Kautz |