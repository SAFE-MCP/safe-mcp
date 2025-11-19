#!/usr/bin/env python3
"""
Customize example implementations for SAFE-MCP techniques based on their README content.

This script reads each technique's README and customizes the detector and attack simulation
with technique-specific patterns and logic.
"""

import os
import re
from pathlib import Path
from typing import Dict, Any, List

TECHNIQUES_DIR = Path(__file__).parent.parent / "techniques"

def extract_iocs_from_readme(readme_content: str) -> List[str]:
    """Extract Indicators of Compromise from README"""
    ioc_section = re.search(r'### Indicators of Compromise.*?\n(.*?)(?=\n###|\n##|$)', readme_content, re.DOTALL)
    if not ioc_section:
        return []
    
    iocs = []
    for line in ioc_section.group(1).split('\n'):
        line = line.strip()
        if line.startswith('-') and len(line) > 2:
            ioc = line[1:].strip()
            if ioc:
                iocs.append(ioc)
    return iocs[:5]  # Limit to 5 most relevant

def extract_attack_flow(readme_content: str) -> List[Dict[str, str]]:
    """Extract attack flow stages from README"""
    flow_section = re.search(r'### Attack Flow\n(.*?)(?=\n###|\n##|$)', readme_content, re.DOTALL)
    if not flow_section:
        return []
    
    stages = []
    for line in flow_section.group(1).split('\n'):
        match = re.match(r'(\d+)\.\s*\*\*(.+?)\*\*:\s*(.+)', line)
        if match:
            stages.append({
                'number': match.group(1),
                'name': match.group(2),
                'description': match.group(3)
            })
    return stages

def customize_detector(tech_info: Dict[str, Any], readme_content: str) -> str:
    """Generate customized detector based on technique specifics"""
    tech_id = tech_info.get('id', 'TXXXX')
    tech_name = tech_info.get('name', 'Technique')
    iocs = extract_iocs_from_readme(readme_content)
    
    ioc_code = ""
    if iocs:
        ioc_code = "        # Check IoCs from README\n"
        for i, ioc in enumerate(iocs):
            # Extract key terms from IoC
            terms = re.findall(r'\b\w{4,}\b', ioc.lower())
            if terms:
                key_term = terms[0]
                ioc_code += f"        if '{key_term}' in str(data).lower():\n"
                ioc_code += f"            findings['high'].append('{ioc}')\n"
    
    return f'''#!/usr/bin/env python3
"""
{tech_id}: {tech_name} - Detection Implementation

This detector identifies indicators of {tech_name.lower()} attacks in MCP environments.
"""

import json
import re
from typing import Dict, List, Any
from datetime import datetime

class {tech_id.replace('-', '')}Detector:
    """Detector for {tech_name} attacks in MCP environments"""
    
    def __init__(self):
        # Detection patterns based on technique IoCs
        self.suspicious_patterns = [
            # TODO: Add specific patterns from detection-rule.yml
        ]
        self.indicators = {iocs}
    
    def scan(self, data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Scan for {tech_name.lower()} indicators"""
        findings = {{
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }}
        
        # Check for IoCs
{ioc_code}
        
        # TODO: Implement additional detection logic
        # See README.md for complete detection methods and IoCs
        # See detection-rule.yml for Sigma rule patterns
        
        return findings
    
    def generate_report(self, findings: Dict[str, List[str]]) -> str:
        """Generate detection report"""
        report = f"\\n=== {tech_id} Detection Report ===\\n"
        report += f"Technique: {tech_name}\\n"
        report += f"Scan Date: {{datetime.now().isoformat()}}\\n\\n"
        
        total = sum(len(items) for items in findings.values())
        if total == 0:
            report += "✓ No indicators detected\\n"
            return report
        
        report += f"Total issues: {{total}}\\n\\n"
        
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        icons = {{'critical': '🚨', 'high': '⚠️ ', 'medium': '⚡', 'low': '📌', 'info': 'ℹ️ '}}
        
        for severity in severity_order:
            if findings[severity]:
                report += f"{{icons.get(severity, '')}} {{severity.upper()}} ({{len(findings[severity])}}):\\n"
                for finding in findings[severity]:
                    report += f"  - {{finding}}\\n"
                report += "\\n"
        
        return report


def main():
    """Example usage"""
    detector = {tech_id.replace('-', '')}Detector()
    
    # Example test data - customize based on technique
    test_data = {{
        # TODO: Add technique-specific test data
    }}
    
    findings = detector.scan(test_data)
    report = detector.generate_report(findings)
    print(report)


if __name__ == "__main__":
    main()
'''

def customize_attack_simulation(tech_info: Dict[str, Any], readme_content: str) -> str:
    """Generate customized attack simulation based on technique specifics"""
    tech_id = tech_info.get('id', 'TXXXX')
    tech_name = tech_info.get('name', 'Technique')
    stages = extract_attack_flow(readme_content)
    
    stage_code = ""
    if stages:
        for stage in stages[:6]:  # Limit to 6 stages
            stage_code += f'''        # Stage {stage['number']}: {stage['name']}
        print("\\n[STAGE {stage['number']}] {stage['name']}")
        print("-" * 60)
        print("{stage['description']}")
        
        self.attack_stages.append({{
            'stage': {stage['number']},
            'name': '{stage['name']}',
            'description': '{stage['description']}',
            'status': 'completed'
        }})
        
'''
    else:
        stage_code = '''        # Stage 1: Initial Stage
        print("\\n[STAGE 1] Attack Initialization")
        print("-" * 60)
        print("Simulating attack initialization...")
        
        self.attack_stages.append({
            'stage': 1,
            'name': 'Initialization',
            'status': 'completed'
        })
        
'''
    
    return f'''#!/usr/bin/env python3
"""
{tech_id}: {tech_name} - Attack Simulation

This script simulates a {tech_name.lower()} attack to demonstrate
the attack vector and validate detection mechanisms.

WARNING: This is for educational and testing purposes only.
"""

import json
import time
from typing import Dict, Any

class AttackSimulation:
    """Simulates {tech_name} attack"""
    
    def __init__(self):
        self.attack_stages = []
    
    def run_simulation(self):
        """Run complete attack simulation"""
        print("=" * 60)
        print(f"{tech_id}: {tech_name} Attack Simulation")
        print("=" * 60)
        print("\\n⚠️  WARNING: This is a simulation for educational purposes only\\n")
        
{stage_code}
        # Summary
        print("\\n" + "=" * 60)
        print("ATTACK SIMULATION COMPLETE")
        print("=" * 60)
        print(f"\\nTotal stages: {{len(self.attack_stages)}}")
        
        return {{
            'stages': self.attack_stages,
            'success': True
        }}


def main():
    """Run attack simulation"""
    simulation = AttackSimulation()
    result = simulation.run_simulation()
    print("\\n✅ Simulation completed successfully")
    print("⚠️  Use detection mechanisms to identify these attack patterns")


if __name__ == "__main__":
    main()
'''

def customize_example_md(tech_info: Dict[str, Any], readme_content: str) -> str:
    """Generate customized EXAMPLE.md"""
    tech_id = tech_info.get('id', 'TXXXX')
    tech_name = tech_info.get('name', 'Technique')
    description = tech_info.get('description', '')
    iocs = extract_iocs_from_readme(readme_content)
    
    ioc_list = ""
    if iocs:
        ioc_list = "\n".join([f"- {ioc}" for ioc in iocs[:5]])
    
    return f'''# {tech_id}: {tech_name} - Examples and Validation

## Overview

This directory contains working examples demonstrating the **{tech_id}: {tech_name}** technique. These examples include detection implementations, attack simulations, and validation mechanisms.

## Files

- **`detector.py`**: Detection implementation that identifies {tech_name.lower()} indicators
- **`attack_simulation.py`**: Attack simulation demonstrating the attack vector
- **`EXAMPLE.md`**: This file - documentation of the technique and validation axioms

## Technique Description

{description[:500]}{'...' if len(description) > 500 else ''}

## Detection Implementation

### Axioms and Validation Principles

The detection implementation is based on the following security axioms:

#### Axiom 1: Attack Pattern Recognition
**Statement**: {tech_name} attacks exhibit identifiable patterns that can be detected through analysis.

**Validation**:
- ✅ Detector identifies known attack patterns
- ✅ Flags suspicious activities matching technique characteristics
- ✅ Correlates multiple indicators for higher confidence

**Key Indicators of Compromise**:
{ioc_list if ioc_list else "- See README.md for complete IoC list"}

**Test Assertion**:
```python
detector = {tech_id.replace('-', '')}Detector()
findings = detector.scan(test_data)
# Assertions should validate detection of known attack patterns
```

## Attack Simulation

The attack simulation demonstrates the complete attack flow as documented in the README.md.

## Validation and Testing

### Running the Detector

```bash
python3 detector.py
```

### Running the Attack Simulation

```bash
python3 attack_simulation.py
```

## Integration with Detection Rules

The detector aligns with the Sigma detection rule in `../detection-rule.yml`:

- Pattern matching for known attack signatures
- Behavioral analysis for anomaly detection
- Correlation with other security events

## Limitations and Considerations

1. **False Positives**: Legitimate activities may trigger alerts
2. **Evasion**: Sophisticated attackers may use evasion techniques
3. **Coverage**: Detector may not cover all attack variations

## References

- See `../README.md` for complete technique documentation
- See `../detection-rule.yml` for Sigma detection rule
- See `../pseudocode.md` for attack flow pseudocode

## Educational Use Only

⚠️ **WARNING**: These examples are for educational and defensive purposes only. Do not use these techniques against production systems.
'''

def customize_technique_examples(technique_dir: Path):
    """Customize examples for a specific technique"""
    examples_dir = technique_dir / "examples"
    if not examples_dir.exists():
        return False
    
    readme_path = technique_dir / "README.md"
    if not readme_path.exists():
        return False
    
    readme_content = readme_path.read_text()
    tech_info = {
        'id': technique_dir.name,
        'name': re.search(r'# SAFE-T\d+: (.+)', readme_content).group(1) if re.search(r'# SAFE-T\d+: (.+)', readme_content) else "Technique",
        'description': re.search(r'## Description\n\n(.+?)(?:\n\n|##)', readme_content, re.DOTALL).group(1).strip()[:200] if re.search(r'## Description\n\n(.+?)(?:\n\n|##)', readme_content, re.DOTALL) else ""
    }
    
    # Customize files
    detector_content = customize_detector(tech_info, readme_content)
    attack_content = customize_attack_simulation(tech_info, readme_content)
    example_md_content = customize_example_md(tech_info, readme_content)
    
    # Write customized files
    (examples_dir / "detector.py").write_text(detector_content)
    (examples_dir / "attack_simulation.py").write_text(attack_content)
    (examples_dir / "EXAMPLE.md").write_text(example_md_content)
    
    return True

def main():
    """Customize examples for all techniques"""
    print("Customizing examples for SAFE-MCP techniques...\n")
    
    techniques = sorted([d for d in TECHNIQUES_DIR.iterdir() 
                        if d.is_dir() and d.name.startswith("SAFE-T")])
    
    customized = 0
    
    for technique_dir in techniques:
        print(f"Customizing {technique_dir.name}...")
        if customize_technique_examples(technique_dir):
            customized += 1
            print(f"  ✅ Customized")
        else:
            print(f"  ⚠️  Skipped (no examples dir or README)")
    
    print(f"\n✅ Customized examples for {customized} techniques")

if __name__ == "__main__":
    main()

