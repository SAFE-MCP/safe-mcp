# SAFE-MCP Contributor Guide

## Table of Contents
1. [Overview](#overview)
2. [Understanding SAFE-MCP and MITRE ATT&CK](#understanding-safe-mcp-and-mitre-attck)
3. [Types of Contributions](#types-of-contributions)
4. [Contributing Attack Techniques](#contributing-attack-techniques)
5. [Contributing Mitigations](#contributing-mitigations)
6. [Other Contribution Types](#other-contribution-types)
7. [Contribution Process](#contribution-process)
8. [Best Practices](#best-practices)
9. [Resources](#resources)

---

## Overview

SAFE-MCP (Security Analysis Framework for Evaluation of Model Context Protocol) is a comprehensive security framework that adapts the proven MITRE ATT&CK methodology specifically for MCP (Model Context Protocol) environments. The framework documents adversary tactics, techniques, and procedures (TTPs) that target MCP implementations and AI-powered applications.

This guide explains how developers can contribute to SAFE-MCP by documenting new attack techniques, proposing mitigations, improving detection rules, and enhancing documentation.

---

## Understanding SAFE-MCP and MITRE ATT&CK

### What is MITRE ATT&CK?

MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. It provides a common taxonomy for describing adversary behavior and helps organizations understand their security posture.

### How SAFE-MCP Adapts MITRE ATT&CK

SAFE-MCP follows the MITRE ATT&CK structure but focuses specifically on threats to the Model Context Protocol ecosystem:

- **14 Tactics**: From Reconnaissance to Impact, aligned with MITRE ATT&CK tactics
- **Techniques**: MCP-specific attack techniques (e.g., SAFE-T1001: Tool Poisoning Attack)
- **Mitigations**: Security controls to prevent or detect attacks (e.g., SAFE-M-1: Control/Data Flow Separation)
- **Detection Rules**: Sigma-format detection rules for security monitoring

### Key Principles

1. **MITRE ATT&CK Alignment**: Each SAFE-MCP technique maps to corresponding MITRE ATT&CK techniques where applicable
2. **MCP-Specific Focus**: Techniques target MCP implementations, AI agents, and LLM integrations
3. **Actionable Content**: Every technique includes detection methods and mitigation strategies
4. **Real-World Basis**: Techniques are based on observed attacks, research, or credible threat models

---

## Types of Contributions

Developers can contribute to SAFE-MCP in several ways:

1. **New Attack Techniques**: Document new MCP-specific attack techniques
2. **New Mitigations**: Propose security controls to prevent or detect attacks
3. **Detection Rules**: Create or improve Sigma detection rules
4. **Documentation Improvements**: Enhance existing technique or mitigation documentation
5. **Code Contributions**: Scripts, tools, or automation for the framework
6. **Bug Reports**: Report inaccuracies or issues in existing content
7. **Reviews**: Review and provide feedback on pull requests

---

## Contributing Attack Techniques

### What is an Attack Technique?

An attack technique describes a specific method adversaries use to achieve their objectives in MCP environments. Examples include:
- **SAFE-T1001**: Tool Poisoning Attack (TPA) - Embedding malicious instructions in tool descriptions
- **SAFE-T1102**: Prompt Injection - Manipulating AI behavior through various vectors
- **SAFE-T1201**: MCP Rug Pull Attack - Time-delayed malicious tool definition changes

### When to Contribute a New Technique

Contribute a new technique when you:
- Discover a new attack vector specific to MCP
- Identify a variation of an existing technique that warrants separate documentation
- Find research documenting MCP-specific threats
- Observe real-world attacks targeting MCP implementations

### Step-by-Step: Creating a New Attack Technique

#### Step 1: Identify the Tactic

Determine which of the 14 SAFE-MCP tactics your technique belongs to:

| Tactic ID | Tactic Name | Description |
|-----------|-------------|-------------|
| ATK-TA0043 | Reconnaissance | Gathering information to plan operations |
| ATK-TA0042 | Resource Development | Establishing resources to support operations |
| ATK-TA0001 | Initial Access | Getting into the MCP environment |
| ATK-TA0002 | Execution | Running malicious code via MCP |
| ATK-TA0003 | Persistence | Maintaining foothold in MCP |
| ATK-TA0004 | Privilege Escalation | Gaining higher-level permissions |
| ATK-TA0005 | Defense Evasion | Avoiding detection |
| ATK-TA0006 | Credential Access | Stealing account names and passwords |
| ATK-TA0007 | Discovery | Figuring out the MCP environment |
| ATK-TA0008 | Lateral Movement | Moving through the environment |
| ATK-TA0009 | Collection | Gathering data of interest |
| ATK-TA0011 | Command and Control | Communicating with compromised systems |
| ATK-TA0010 | Exfiltration | Stealing data |
| ATK-TA0040 | Impact | Manipulating, interrupting, or destroying systems |

#### Step 2: Get the Next Technique ID

Check the [README.md](README.md) to find the highest numbered technique. The next available ID will be SAFE-T[XXXX] where XXXX is the next sequential number.

#### Step 3: Create the Directory Structure

```bash
cd techniques/
mkdir SAFE-T[XXXX]
cd SAFE-T[XXXX]
```

#### Step 4: Create the README.md

Copy the template from `techniques/TEMPLATE.md` and fill in all required sections:

```bash
cp ../TEMPLATE.md README.md
```

#### Step 5: Fill in the Template

Use the checklist in `techniques/TEMPLATE-CHECKLIST.md` to ensure completeness:

**Required Sections:**

1. **Overview**
   - Tactic name and ID
   - Technique ID (SAFE-T[XXXX])
   - Severity (Critical/High/Medium/Low)
   - First Observed date
   - Last Updated date

2. **Description** (2-3 paragraphs)
   - What the technique is
   - How it works
   - Technical details about MCP exploitation

3. **Attack Vectors**
   - Primary vector
   - Secondary vectors

4. **Technical Details**
   - Prerequisites
   - Attack Flow (numbered stages)
   - Example Scenario (code/config)
   - Advanced Attack Techniques (if research exists)

5. **Impact Assessment**
   - Confidentiality (High/Medium/Low)
   - Integrity (High/Medium/Low)
   - Availability (High/Medium/Low)
   - Scope (Local/Adjacent/Network-wide)
   - Current Status (if patches/mitigations exist)

6. **Detection Methods**
   - Indicators of Compromise (IoCs) - at least 3
   - Sigma detection rule with limitations warning
   - Behavioral indicators

7. **Mitigation Strategies**
   - Preventive controls (reference SAFE-M-X)
   - Detective controls (reference SAFE-M-X)
   - Response procedures

8. **Related Techniques**
   - Links to other SAFE techniques

9. **References**
   - MCP specification
   - All cited sources (prefer academic papers)
   - Format: `[Title - Authors, Conference Year](URL)`

10. **MITRE ATT&CK Mapping**
    - Links to official MITRE techniques

11. **Version History**
    - Track all changes with dates and authors

#### Step 6: Create Detection Rule (Optional but Recommended)

Create a `detection-rule.yml` file in Sigma format:

```yaml
title: [Detection Rule Name]
id: [UUID - generate with uuidgen]
status: experimental
description: [Description]
author: [Your Name]
date: [YYYY-MM-DD]
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
  - [False positive scenario]
level: [high/medium/low]
tags:
  - attack.[tactic]
  - attack.t[XXXX]
  - safe.t[XXXX]
```

**Important**: Always include a warning that detection rules are examples only and attackers continuously develop new evasions.

#### Step 7: Add Test Files (Optional)

- `test-logs.json`: Sample log data for testing detection rules
- `test_detection_rule.py`: Python script to validate detection rules
- `validate.sh`: Shell script for validation

#### Step 8: Update Main README.md

Add your new technique to the TTP Reference Table in the main `README.md`:

```markdown
| ATK-TA0001 | Initial Access | [SAFE-T[XXXX]](techniques/SAFE-T[XXXX]/README.md) | [Technique Name] | [Brief description] |
```

#### Step 9: Follow Style Guidelines

- Use objective, technical language (avoid "sophisticated", "clever")
- Cite sources with inline links
- Include "Source:" in comments for detection patterns
- Use RFC 2360 principles for clarity
- Generate proper UUIDs for Sigma rules (`uuidgen`)
- Verify all claims against cited sources
- Prefer academic papers over vendor blogs

### Example: Complete Technique Contribution

See [SAFE-T1001: Tool Poisoning Attack](techniques/SAFE-T1001/README.md) for a comprehensive example of a well-documented technique.

---

## Contributing Mitigations

### What is a Mitigation?

A mitigation is a security control designed to prevent or detect attack techniques. Examples include:
- **SAFE-M-1**: Control/Data Flow Separation - Architectural defense
- **SAFE-M-2**: Cryptographic Integrity - Cryptographic control
- **SAFE-M-11**: Behavioral Monitoring - Detective control

### When to Contribute a New Mitigation

Contribute a new mitigation when you:
- Develop a new security control for MCP
- Identify an effective defense not yet documented
- Find research on mitigation strategies
- Propose improvements to existing mitigations

### Step-by-Step: Creating a New Mitigation

#### Step 1: Determine the Category

Choose the appropriate mitigation category:

- **Architectural Defense**: Fundamental design patterns
- **Cryptographic Control**: Security using cryptography
- **AI-Based Defense**: Controls leveraging AI/ML
- **Input Validation**: Sanitization and validation
- **Supply Chain Security**: Securing MCP software supply chain
- **UI Security**: Visual consistency and deception prevention
- **Isolation and Containment**: Sandboxing techniques
- **Detective Control**: Monitoring and detection
- **Preventive Control**: Preventing attacks before they occur
- **Architectural Control**: System design patterns
- **Risk Management**: Risk assessment controls
- **Data Security**: Data integrity and confidentiality
- **Human Factors**: Social engineering and user awareness

#### Step 2: Assess Effectiveness

Rate effectiveness based on prevention capability:

- **High**: Prevents 80%+ of targeted attacks, or provides provable security
- **Medium-High**: Prevents 60-80% of targeted attacks
- **Medium**: Prevents 40-60% of targeted attacks
- **Low**: Prevents <40% of targeted attacks

#### Step 3: Get the Next Mitigation ID

Check `MITIGATIONS.md` to find the highest numbered mitigation. The next available ID will be SAFE-M-[XXXX].

#### Step 4: Create the Directory Structure

```bash
cd mitigations/
mkdir SAFE-M-[XXXX]
cd SAFE-M-[XXXX]
```

#### Step 5: Create the README.md

Copy the template from `mitigations/TEMPLATE.md`:

```bash
cp ../TEMPLATE.md README.md
```

#### Step 6: Fill in the Template

Use the checklist in `mitigations/TEMPLATE-CHECKLIST.md`:

**Required Sections:**

1. **Overview**
   - Mitigation ID
   - Category
   - Effectiveness rating
   - Implementation Complexity (High/Medium/Low)
   - First Published date

2. **Description** (2 paragraphs)
   - What the mitigation is
   - How it protects against MCP attacks

3. **Mitigates**
   - Links to techniques this mitigation addresses (SAFE-T[XXXX])

4. **Technical Implementation**
   - Core Principles (3+ principles)
   - Architecture Components (diagram/description)
   - Prerequisites
   - Implementation Steps (Design/Development/Deployment)

5. **Benefits** (at least 3)
   - Description with metrics if available

6. **Limitations** (at least 3)
   - Description with impact assessment

7. **Implementation Examples**
   - Code example (vulnerable vs protected)
   - Configuration example (if applicable)

8. **Testing and Validation**
   - Security testing scenarios
   - Functional testing requirements
   - Integration testing considerations

9. **Deployment Considerations**
   - Resource requirements (CPU, Memory, Storage, Network)
   - Performance impact assessment
   - Monitoring and alerting guidance

10. **Current Status** (if industry data exists)
    - Adoption statistics or trends

11. **References**
    - MCP specification
    - All cited sources

12. **Related Mitigations**
    - Links to other SAFE mitigations

13. **Version History**
    - Track all changes

#### Step 7: Update MITIGATIONS.md

Add your new mitigation to the Mitigation Overview table:

```markdown
| [SAFE-M-[XXXX]](mitigations/SAFE-M-[XXXX]/README.md) | [Name] | [Category] | [Effectiveness] |
```

#### Step 8: Link from Techniques

Update any relevant technique documents to reference your new mitigation in their "Mitigation Strategies" sections.

### Example: Complete Mitigation Contribution

See [SAFE-M-1: Control/Data Flow Separation](mitigations/SAFE-M-1/README.md) for a comprehensive example.

---

## Other Contribution Types

### Detection Rules

Improve existing detection rules or create new ones:

1. Review existing `detection-rule.yml` files
2. Test rules with sample data
3. Improve patterns to reduce false positives
4. Add new detection methods

### Documentation Improvements

- Fix typos or inaccuracies
- Clarify technical explanations
- Add missing information
- Improve examples
- Update references

### Code Contributions

- Scripts for validation
- Testing tools
- Automation for framework maintenance
- Detection rule testers

### Bug Reports

Open an issue for:
- Inaccuracies in technique descriptions
- Missing information
- Broken links
- Incorrect MITRE ATT&CK mappings

---

## Contribution Process

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/safe-mcp.git
cd safe-mcp
git remote add upstream https://github.com/soltrinox/safe-mcp.git
```

### 2. Create a Branch

```bash
git checkout -b feature/SAFE-T-XXXX-description
# or
git checkout -b feature/SAFE-M-XXXX-description
```

### 3. Make Your Changes

- Follow the templates and checklists
- Ensure all required sections are complete
- Test any code or scripts you add
- Verify all links work

### 4. Sign Off Your Commits (DCO)

**CRITICAL**: All commits must be signed off using the Developer Certificate of Origin (DCO):

```bash
git commit -s -m "Add SAFE-T[XXXX]: Technique Name"
```

The `-s` flag adds:
```
Signed-off-by: Your Name <your.email@example.com>
```

If you already committed without sign-off:

```bash
git commit -s --amend --no-edit
```

### 5. Update Version History

Add yourself to the Version History table in your contribution:

```markdown
| Version | Date       | Changes                               | Author    |
| ------- | ---------- | ------------------------------------- | --------- |
| 1.0     | 2025-01-02 | Initial documentation                 | Your Name |
```

### 6. Test Your Changes

- Validate markdown syntax
- Check all links
- Test detection rules if applicable
- Review for completeness using checklists

### 7. Submit a Pull Request

1. Push your branch:
   ```bash
   git push origin feature/SAFE-T-XXXX-description
   ```

2. Open a PR on GitHub with:
   - Clear title describing your contribution
   - Description of what you added/changed
   - Checkboxes for the PR template
   - Reference to related issues (if any)

3. PR Template Checklist:
   - [ ] DCO sign-off included
   - [ ] Template checklist completed
   - [ ] All required sections present
   - [ ] References cited properly

### 8. Address Review Feedback

- Respond to comments professionally
- Make requested changes
- Update your branch with fixes
- Maintain DCO sign-off on all commits

---

## Best Practices

### Writing Style

1. **Be Objective**: Use technical, factual language
   - ❌ "Sophisticated attack technique"
   - ✅ "Attack technique that exploits X to achieve Y"

2. **Cite Sources**: Always cite research and claims
   - Format: `[Title - Authors, Year](URL)`
   - Prefer academic papers over vendor blogs

3. **Be Specific**: Provide concrete examples
   - Include code snippets
   - Show attack flows
   - Provide configuration examples

4. **Acknowledge Limitations**: Be honest about what detection/mitigation can and cannot do

### Technical Accuracy

1. **Verify Claims**: Check all technical claims against sources
2. **Test Examples**: Ensure code examples work
3. **Update Dates**: Keep "Last Updated" current
4. **Map Correctly**: Ensure MITRE ATT&CK mappings are accurate

### Completeness

1. **Use Checklists**: Follow TEMPLATE-CHECKLIST.md rigorously
2. **Fill All Sections**: Don't leave placeholders
3. **Cross-Reference**: Link to related techniques/mitigations
4. **Version History**: Document all significant changes

### Security Considerations

1. **Don't Provide Exploits**: Document techniques, don't provide working exploits
2. **Focus on Defense**: Emphasize detection and mitigation
3. **Responsible Disclosure**: If reporting real vulnerabilities, follow responsible disclosure

---

## Resources

### Documentation

- [SAFE-MCP README](README.md) - Framework overview
- [CONTRIBUTING.md](CONTRIBUTING.md) - General contribution guidelines
- [MITIGATIONS.md](MITIGATIONS.md) - Mitigation reference
- [Technique Template](techniques/TEMPLATE.md)
- [Mitigation Template](mitigations/TEMPLATE.md)
- [Technique Checklist](techniques/TEMPLATE-CHECKLIST.md)
- [Mitigation Checklist](mitigations/TEMPLATE-CHECKLIST.md)

### External References

- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Sigma Detection Rules](https://github.com/SigmaHQ/sigma)

### Community

- **Mailing List**: [openssf-sig-safe-mcp@lists.openssf.org](https://lists.openssf.org/g/openssf-sig-safe-mcp)
- **Slack**: OpenSSF #sig-safe-mcp
- **Meeting Time**: 1:00 PM PT (PST/PDT) Bi-Weekly

### Tools

- **UUID Generator**: `uuidgen` (for Sigma rule IDs)
- **Markdown Linters**: Check markdown syntax
- **Link Checkers**: Verify all links work

---

## Getting Help

If you have questions:

1. **Check Documentation**: Review templates and examples
2. **Open an Issue**: Ask questions in GitHub issues
3. **Join Meetings**: Attend SIG meetings (see Community above)
4. **Slack**: Ask in #sig-safe-mcp channel

---

## Summary

Contributing to SAFE-MCP helps secure the MCP ecosystem by:

1. **Documenting Threats**: Making attack techniques visible and understandable
2. **Providing Defenses**: Offering actionable mitigation strategies
3. **Enabling Detection**: Creating detection rules for security monitoring
4. **Building Knowledge**: Creating a comprehensive security knowledge base

Whether you're documenting a new attack technique, proposing a mitigation, or improving documentation, your contributions make MCP deployments more secure.

Thank you for contributing to SAFE-MCP!

