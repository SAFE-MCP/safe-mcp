# SAFE-M-11: Behavioral Monitoring

## Overview
**Mitigation ID**: SAFE-M-11  
**Category**: Detective Control  
**Effectiveness**: High  
**Implementation Complexity**: Medium-High  
**First Published**: 2025-01-03

## Description
Behavioral Monitoring tracks LLM behavior patterns to detect unexpected tool usage, suspicious sequences of operations, or deviations from normal behavior that may indicate compromise or attack. This includes monitoring for signs of prompt injection attacks such as sudden context switches, execution of unrelated commands, or acknowledgment of instructions not visible in the original user request.

## Mitigates
- [SAFE-T1001](../../techniques/SAFE-T1001/README.md): Tool Poisoning Attack (TPA)
- [SAFE-T1101](../../techniques/SAFE-T1101/README.md): Command Injection
- [SAFE-T1102](../../techniques/SAFE-T1102/README.md): Prompt Injection (Multiple Vectors)
- [SAFE-T1701](../../techniques/SAFE-T1701/README.md): Cross-Tool Contamination

## Technical Implementation
[TO BE COMPLETED]

## References
- [MITRE CAR - Cyber Analytics Repository](https://car.mitre.org/)
- [NISTIR 8219: Securing Manufacturing Industrial Control Systems: Behavioral Anomaly Detection](https://csrc.nist.gov/publications/detail/nistir/8219/final)
- [Anomaly Detection: A Survey - ACM Computing Surveys (2009)](https://dl.acm.org/doi/10.1145/1541880.1541882)
- [Large Language Models for Forecasting and Anomaly Detection: A Systematic Literature Review (2024)](https://arxiv.org/abs/2402.10350)
- [Finding Cyber Threats with ATT&CK-Based Analytics - MITRE](https://www.mitre.org/publications/technical-papers/finding-cyber-threats-with-attck-based-analytics)

## Related Mitigations
- [SAFE-M-10](../SAFE-M-10/README.md): Automated Scanning
- [SAFE-M-12](../SAFE-M-12/README.md): Audit Logging

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 0.1 | 2025-01-03 | Initial stub | Frederick Kautz |
| 0.2 | 2025-01-09 | Added explicit prompt injection monitoring | Frederick Kautz |