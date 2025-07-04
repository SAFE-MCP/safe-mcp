# SAFE Technique Documentation Checklist

## Required Sections
- [ ] **Overview** - Tactic, ID, Severity, First Observed, Last Updated
- [ ] **Description** - 2-3 paragraphs explaining the technique
- [ ] **Attack Vectors** - Primary and secondary vectors
- [ ] **Technical Details**
  - [ ] Prerequisites
  - [ ] Attack Flow (numbered stages)
  - [ ] Example Scenario (code/config)
  - [ ] Advanced Attack Techniques (if relevant research exists)
- [ ] **Impact Assessment** - CIA triad + Scope
  - [ ] Current Status (if patches/mitigations are deployed)
- [ ] **Detection Methods**
  - [ ] IoCs (at least 3)
  - [ ] Sigma rule with warning about limitations
  - [ ] Behavioral indicators
- [ ] **Mitigation Strategies**
  - [ ] Preventive controls (use SAFE-M-X format)
  - [ ] Detective controls (use SAFE-M-X format)
  - [ ] Response procedures
- [ ] **Related Techniques** - Link to other SAFE techniques
- [ ] **References** - Include MCP spec + all cited sources
- [ ] **MITRE ATT&CK Mapping** - Link to official techniques
- [ ] **Version History** - Track changes

## Style Guidelines
- Use objective, technical language (avoid "sophisticated", "clever", etc.)
- Cite sources for research findings with inline links
- Include "Source:" in comments for detection patterns
- Use RFC 2360 principles for clarity
- Generate proper UUIDs for Sigma rules (use `uuidgen`)
- Verify all claims against their cited sources
- Prefer academic papers and neutral sources over vendor promotional content
- Include all cited URLs in the References section
- Format academic citations as: [Title - Authors, Conference Year](URL)
- Use SAFE-M-X format for mitigation references

## Directory Structure
```
techniques/
└── SAFE-TXXXX/
    ├── README.md           # Main documentation
    ├── detection-rule.yml  # Standalone Sigma rule
    ├── test-logs.json      # Test data (optional)
    ├── test_detection_rule.py # Test script (optional)
    └── validate.sh         # Validation script (optional)
```

## Notes
- First Observed: Use "Not observed in production" if theoretical
- Severity: Critical for direct system compromise, High for data exposure, Medium for limited impact, Low for minimal risk
- Always include warning that detection rules are examples only
- Consider adding "Advanced Attack Techniques" section if new research emerges
- Add "Current Status" section if major platforms have patches