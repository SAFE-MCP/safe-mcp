# SAFE Mitigation Documentation Checklist

## Required Sections
- [ ] **Overview** - ID, Category, Effectiveness, Complexity, First Published
- [ ] **Description** - 2 paragraphs explaining the mitigation
- [ ] **Mitigates** - Links to techniques this mitigation addresses
- [ ] **Technical Implementation**
  - [ ] Core Principles (3+ principles)
  - [ ] Architecture Components (diagram/description)
  - [ ] Prerequisites
  - [ ] Implementation Steps (Design/Development/Deployment phases)
- [ ] **Benefits** - At least 3 benefits with descriptions
- [ ] **Limitations** - At least 3 limitations with impact assessment
- [ ] **Implementation Examples**
  - [ ] Code example showing vulnerable vs protected approach
  - [ ] Configuration example (if applicable)
- [ ] **Testing and Validation**
  - [ ] Security testing scenarios
  - [ ] Functional testing requirements
  - [ ] Integration testing considerations
- [ ] **Deployment Considerations**
  - [ ] Resource requirements
  - [ ] Performance impact assessment
  - [ ] Monitoring and alerting guidance
- [ ] **Current Status** (if relevant industry data exists)
- [ ] **References** - Include MCP spec + all cited sources
- [ ] **Related Mitigations** - Link to other SAFE mitigations
- [ ] **Version History** - Track changes

## Style Guidelines
- Use objective, technical language (avoid marketing terms)
- Cite sources for claims with inline links
- Include concrete metrics where available (e.g., "77% task completion rate")
- Use RFC 2360 principles for clarity
- Verify all claims against their cited sources
- Prefer academic papers and neutral sources over vendor promotional content
- Include all cited URLs in the References section
- Format academic citations as: [Title - Authors, Conference Year](URL)
- Use SAFE-M-X format for mitigation cross-references
- Use SAFE-T-X format for technique references

## Category Guidelines

### Effectiveness Ratings
- **High**: Prevents 80%+ of targeted attacks, or provides provable security
- **Medium-High**: Prevents 60-80% of targeted attacks
- **Medium**: Prevents 40-60% of targeted attacks
- **Low**: Prevents <40% of targeted attacks

### Implementation Complexity
- **High**: Requires significant architectural changes, specialized expertise
- **Medium**: Requires moderate development effort, some architectural changes
- **Low**: Can be implemented with minimal changes to existing systems

### Category Definitions
- **Architectural Defense**: Fundamental design patterns preventing attack classes
- **Cryptographic Control**: Security measures using cryptographic techniques
- **AI-Based Defense**: Controls leveraging AI/ML for detection and prevention
- **Input Validation**: Sanitization and validation of inputs before processing
- **Supply Chain Security**: Controls for securing the MCP software supply chain
- **UI Security**: Controls ensuring visual consistency and preventing deception
- **Isolation and Containment**: Sandboxing and isolation techniques
- **Detective Control**: Monitoring and detection capabilities
- **Preventive Control**: Controls that prevent attacks before they occur
- **Architectural Control**: System design patterns for security
- **Risk Management**: Risk assessment and management controls
- **Data Security**: Controls protecting data integrity and confidentiality
- **Human Factors**: Controls addressing social engineering and user awareness

## Directory Structure
```
mitigations/
└── SAFE-M-XXXX/
    ├── README.md           # Main documentation
    ├── implementation/     # Implementation examples (optional)
    ├── tests/             # Test cases (optional)
    └── validate.sh        # Validation script (optional)
```

## Notes
- First Published: Use date when mitigation was first documented
- Effectiveness: Include parenthetical context like "(Provable Security)" when applicable
- Always include performance impact assessment in Limitations
- Consider adding "Current Status" section if there's significant industry adoption data
- Link to actual SAFE-T techniques in the "Mitigates" section
- Cross-reference related mitigations in the same category or addressing similar threats