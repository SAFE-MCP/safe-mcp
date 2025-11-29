#!/usr/bin/env python3
"""
Generate examples structure for all SAFE techniques.

This script creates the examples folder structure with:
- detector.py (detection implementation)
- attack_simulation.py (attack simulation)
- EXAMPLE.md (documentation with validation axioms)

Usage:
    python generate_examples.py [technique_id]
    python generate_examples.py  # Process all techniques
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional


TECHNIQUES_DIR = Path(__file__).parent.parent / "techniques"


def read_technique_readme(technique_dir: Path) -> Optional[Dict[str, str]]:
    """Read and parse technique README"""
    readme_path = technique_dir / "README.md"
    if not readme_path.exists():
        return None
    
    content = readme_path.read_text()
    
    # Extract key information
    technique_id_match = re.search(r'SAFE-T(\d+)', content)
    technique_id = technique_id_match.group(0) if technique_id_match else None
    
    name_match = re.search(r'# SAFE-T\d+:\s*(.+?)(?:\n|##)', content)
    technique_name = name_match.group(1).strip() if name_match else "Unknown Technique"
    
    description_match = re.search(r'## Description\n\n(.+?)(?:\n##|\Z)', content, re.DOTALL)
    description = description_match.group(1).strip() if description_match else ""
    
    return {
        'id': technique_id,
        'name': technique_name,
        'description': description,
        'content': content
    }


def generate_detector_template(tech_info: Dict[str, str]) -> str:
    """Generate detector.py template"""
    return f'''#!/usr/bin/env python3
"""
{tech_info['id']}: {tech_info['name']} - Detection Implementation

This detector identifies indicators of {tech_info['name'].lower()} in MCP environments.
"""

import json
import re
from typing import Dict, List, Any
from datetime import datetime


class {tech_info['id'].replace('-', '')}Detector:
    """Detector for {tech_info['name']} attacks in MCP environments"""
    
    def __init__(self):
        # Detection patterns specific to {tech_info['name']}
        self.suspicious_patterns = [
            # Add technique-specific patterns here
        ]
    
    def scan_logs(self, log_file: str) -> Dict[str, Any]:
        """Scan log file for {tech_info['name'].lower()} indicators"""
        try:
            with open(log_file, 'r') as f:
                logs = json.load(f)
        except Exception as e:
            return {{'error': f"Failed to load log file: {{e}}"}}
        
        findings = {{
            'events_analyzed': len(logs),
            'findings': {{
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
            }},
            'summary': {{}}
        }}
        
        # TODO: Implement detection logic
        
        return findings
    
    def generate_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate human-readable report"""
        if 'error' in scan_results:
            return f"Error: {{scan_results['error']}}\\n"
        
        report = "\\n=== {tech_info['name']} Detection Report ===\\n\\n"
        report += f"Events Analyzed: {{scan_results['events_analyzed']}}\\n\\n"
        
        findings = scan_results['findings']
        severity_order = ['critical', 'high', 'medium', 'low']
        icons = {{
            'critical': '🚨',
            'high': '⚠️ ',
            'medium': '⚡',
            'low': '📌',
        }}
        
        for severity in severity_order:
            if findings[severity]:
                report += f"{{icons[severity]}} {{severity.upper()}} ({{len(findings[severity])}} findings)\\n"
                for finding in findings[severity][:10]:
                    report += f"  - {{finding}}\\n"
                report += "\\n"
        
        if all(not findings[s] for s in severity_order):
            report += "✓ No indicators detected\\n"
        
        return report


def main():
    """Main entry point"""
    import sys
    
    detector = {tech_info['id'].replace('-', '')}Detector()
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        results = detector.scan_logs(log_file)
        report = detector.generate_report(results)
        print(report)
    else:
        print("Usage: python detector.py <log_file.json>")


if __name__ == "__main__":
    main()
'''


def generate_attack_simulation_template(tech_info: Dict[str, str]) -> str:
    """Generate attack_simulation.py template"""
    return f'''#!/usr/bin/env python3
"""
{tech_info['id']}: {tech_info['name']} - Attack Simulation

This script simulates {tech_info['name'].lower()} attack scenarios to demonstrate
the technique and test detection capabilities.

WARNING: This is for educational and testing purposes only.
"""

import json
from typing import Dict, Any
from datetime import datetime


class {tech_info['id'].replace('-', '')}AttackSimulator:
    """Simulates {tech_info['name']} attack scenarios"""
    
    def __init__(self):
        self.attack_log = []
        self.stage = 0
    
    def log_event(self, event_type: str, data: Dict[str, Any]):
        """Log attack event"""
        event = {{
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'stage': self.stage,
            **data
        }}
        self.attack_log.append(event)
        return event
    
    def run_full_attack(self):
        """Run complete attack simulation"""
        print("=" * 60)
        print("{tech_info['name']} Attack Simulation")
        print("=" * 60)
        print()
        
        # TODO: Implement attack stages
        
        print()
        print("=" * 60)
        print("Attack simulation complete!")
        print("=" * 60)
        
        return self.attack_log
    
    def save_logs(self, filename: str = "{tech_info['id'].lower()}_attack_logs.json"):
        """Save attack logs to file"""
        with open(filename, 'w') as f:
            json.dump(self.attack_log, f, indent=2)
        print(f"\\nAttack logs saved to: {{filename}}")
        return filename


def main():
    """Main entry point"""
    simulator = {tech_info['id'].replace('-', '')}AttackSimulator()
    
    # Run full attack simulation
    logs = simulator.run_full_attack()
    
    # Save logs for detection testing
    log_file = simulator.save_logs()
    
    print(f"\\nTotal events generated: {{len(logs)}}")
    print(f"\\nYou can now test detection with:")
    print(f"  python detector.py {{log_file}}")


if __name__ == "__main__":
    main()
'''


def generate_example_md_template(tech_info: Dict[str, str]) -> str:
    """Generate EXAMPLE.md template"""
    return f'''# {tech_info['id']}: {tech_info['name']} - Example Implementation

## Overview

This directory contains working examples demonstrating **{tech_info['id']}: {tech_info['name']}** detection and attack simulation. These examples are designed for educational purposes and to validate detection capabilities.

## Technique Description

{tech_info['description'][:500]}...

## Files

- **`detector.py`**: Detection implementation that identifies {tech_info['name'].lower()} indicators
- **`attack_simulation.py`**: Attack simulation that generates realistic attack scenarios
- **`EXAMPLE.md`**: This file - documentation of the technique and validation axioms

## Detection Axioms

The detection implementation is based on the following axioms (fundamental truths about {tech_info['name'].lower()} attacks):

### Axiom 1: [Primary Detection Principle]
**Assertion**: [Fundamental truth about the attack]

**Validation**:
- [Validation criteria 1]
- [Validation criteria 2]

**Test Cases**:
- [Test case 1]
- [Test case 2]

## Validation Methodology

### Test 1: [Test Name]
```python
# TODO: Add test implementation
```

## Running the Examples

### 1. Run Attack Simulation
```bash
python3 attack_simulation.py
```

### 2. Test Detection
```bash
python3 detector.py attack_logs.json
```

## Educational Use Only

⚠️ **WARNING**: These examples are for educational and defensive testing purposes only. Do not use these techniques against production systems or real MCP deployments.

## References

- [{tech_info['id']} README](../README.md) - Complete technique documentation
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
'''


def create_examples_for_technique(technique_id: str):
    """Create examples folder structure for a technique"""
    technique_dir = TECHNIQUES_DIR / technique_id
    if not technique_dir.exists():
        print(f"Error: Technique directory not found: {technique_dir}")
        return False
    
    examples_dir = technique_dir / "examples"
    examples_dir.mkdir(exist_ok=True)
    
    # Read technique info
    tech_info = read_technique_readme(technique_dir)
    if not tech_info:
        print(f"Warning: Could not read README for {technique_id}")
        tech_info = {
            'id': technique_id,
            'name': technique_id.replace('SAFE-', '').replace('-', ' ').title(),
            'description': 'Technique description',
        }
    
    # Generate files
    detector_content = generate_detector_template(tech_info)
    attack_content = generate_attack_simulation_template(tech_info)
    example_md_content = generate_example_md_template(tech_info)
    
    # Write files
    (examples_dir / "detector.py").write_text(detector_content)
    (examples_dir / "attack_simulation.py").write_text(attack_content)
    (examples_dir / "EXAMPLE.md").write_text(example_md_content)
    
    # Make scripts executable
    os.chmod(examples_dir / "detector.py", 0o755)
    os.chmod(examples_dir / "attack_simulation.py", 0o755)
    
    print(f"✓ Created examples for {technique_id}")
    return True


def main():
    """Main entry point"""
    if len(sys.argv) > 1:
        # Process specific technique
        technique_id = sys.argv[1]
        if not technique_id.startswith('SAFE-T'):
            technique_id = f"SAFE-T{technique_id}"
        create_examples_for_technique(technique_id)
    else:
        # Process all techniques
        technique_dirs = sorted([d for d in TECHNIQUES_DIR.iterdir() 
                                if d.is_dir() and d.name.startswith('SAFE-T')])
        
        for technique_dir in technique_dirs:
            technique_id = technique_dir.name
            examples_dir = technique_dir / "examples"
            
            # Skip if examples already exist
            if examples_dir.exists() and any(examples_dir.iterdir()):
                print(f"⊘ Skipping {technique_id} (examples already exist)")
                continue
            
            create_examples_for_technique(technique_id)


if __name__ == "__main__":
    main()

