# SAFE-T[XXXX]: [Technique Name]

## Overview
**Tactic**: [Tactic Name (ATK-TAXXXX)]  
**Technique ID**: SAFE-T[XXXX]  
**Severity**: [Critical/High/Medium/Low]  
**First Observed**: [Date/Not observed in production/Discovered by X]  
**Last Updated**: [Date]

## Description
[First paragraph: Brief description of what the technique is and how it works]

[Second paragraph: Technical details about how the attack exploits MCP or AI systems]

## Attack Vectors
- **Primary Vector**: [Main method of attack]
- **Secondary Vectors**: 
  - [Additional vector 1]
  - [Additional vector 2]

## Technical Details

### Prerequisites
- [Prerequisite 1]
- [Prerequisite 2]

### Attack Flow
1. **Initial Stage**: [Description]
2. **[Stage Name]**: [Description]
3. **[Stage Name]**: [Description]
4. **Exploitation Stage**: [Description]
5. **Post-Exploitation**: [Description]

### Example Scenario
```json
// Example configuration, payload, or code
{
  "example": "content"
}
```

### Advanced Attack Techniques (Year Research Published)
<!-- Include this section when there's relevant research on variations or advanced techniques -->

According to research from [Source 1](URL) and [Source 2](URL), attackers have developed sophisticated variations:

1. **Technique Variation 1**: Description with proper citation ([Author, Year](URL))
2. **Technique Variation 2**: Description with proper citation
<!-- Ensure all claims have supporting citations -->

## Impact Assessment
- **Confidentiality**: [High/Medium/Low] - [Brief explanation]
- **Integrity**: [High/Medium/Low] - [Brief explanation]
- **Availability**: [High/Medium/Low] - [Brief explanation]
- **Scope**: [Local/Adjacent/Network-wide] - [Brief explanation]

### Current Status (Year)
<!-- Include when documenting the current state of mitigations or patches -->
According to security researchers, organizations are beginning to implement mitigations:
- [Specific mitigation or patch with citation]
- [Another mitigation with citation]
<!-- Verify all claims against cited sources -->

## Detection Methods

### Indicators of Compromise (IoCs)
- [IoC 1]
- [IoC 2]
- [IoC 3]

### Detection Rules

**Important**: The following rule is written in Sigma format and contains example patterns only. Attackers continuously develop new injection techniques and obfuscation methods. Organizations should:
- Use AI-based anomaly detection to identify novel attack patterns
- Regularly update detection rules based on threat intelligence
- Implement multiple layers of detection beyond pattern matching
- Consider semantic analysis of [relevant data]

```yaml
# EXAMPLE SIGMA RULE - Not comprehensive
title: [Detection Rule Name]
id: [UUID - generate with uuidgen]
status: experimental
description: [Description]
author: [Author Name]
date: [Date]
references:
  - https://github.com/safe-mcp/techniques/SAFE-T[XXXX]
logsource:
  product: mcp
  service: [service name]
detection:
  selection:
    [field_name]:
      - '[pattern1]'
      - '[pattern2]'
  condition: selection
falsepositives:
  - [False positive scenario 1]
  - [False positive scenario 2]
level: [high/medium/low]
tags:
  - attack.[tactic]
  - attack.t[XXXX]
  - safe.t[XXXX]
```

### Behavioral Indicators
- [Behavioral indicator 1]
- [Behavioral indicator 2]

## Mitigation Strategies

### Preventive Controls
1. **[SAFE-M-X: Control Name](../../mitigations/SAFE-M-X/README.md)**: [Description of implementation]
2. **[SAFE-M-X: Control Name](../../mitigations/SAFE-M-X/README.md)**: [Description of implementation]
3. **[SAFE-M-X: Control Name](../../mitigations/SAFE-M-X/README.md)**: [Description of implementation]
   <!-- If citing research for a control, include inline citation like: According to [Research Name](URL), implementing X can provide Y benefit -->

### Detective Controls
1. **[SAFE-M-X: Control Name](../../mitigations/SAFE-M-X/README.md)**: [Description of implementation]
2. **[SAFE-M-X: Control Name](../../mitigations/SAFE-M-X/README.md)**: [Description of implementation]

### Response Procedures
1. **Immediate Actions**:
   - [Action 1]
   - [Action 2]
2. **Investigation Steps**:
   - [Step 1]
   - [Step 2]
3. **Remediation**:
   - [Remediation step 1]
   - [Remediation step 2]

## Related Techniques
- [SAFE-TXXXX](../SAFE-TXXXX/README.md): [Relationship description]
- [SAFE-TXXXX](../SAFE-TXXXX/README.md): [Relationship description]

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
<!-- Include all sources cited in the document body
     Prefer academic papers and neutral sources over vendor blogs
     Format academic papers as: [Title - Authors, Conference Year](URL) -->
- [Additional Reference 1]
- [Additional Reference 2]

## MITRE ATT&CK Mapping
- [TXXXX - Technique Name](https://attack.mitre.org/techniques/TXXXX/)
- [TXXXX - Technique Name](https://attack.mitre.org/techniques/TXXXX/) (if applicable)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | [Date] | Initial documentation | [Author] |