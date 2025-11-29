#!/usr/bin/env python3
"""
Generate examples from pseudocode and detection rules for all SAFE techniques.

This script:
1. Reads pseudocode.md and detection-rule.yml from each technique
2. Generates detector.py based on detection rules
3. Generates attack_simulation.py based on pseudocode
4. Creates EXAMPLE.md documentation
"""

import os
import re
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional


TECHNIQUES_DIR = Path(__file__).parent.parent / "techniques"


def read_technique_info(technique_dir: Path) -> Optional[Dict[str, Any]]:
    """Read technique information from README, pseudocode, and detection rule"""
    tech_info = {
        'id': technique_dir.name,
        'readme': None,
        'pseudocode': None,
        'detection_rule': None,
    }
    
    # Read README
    readme_path = technique_dir / "README.md"
    if readme_path.exists():
        tech_info['readme'] = readme_path.read_text()
        # Extract name and description
        name_match = re.search(r'# SAFE-T\d+:\s*(.+?)(?:\n|##)', tech_info['readme'])
        tech_info['name'] = name_match.group(1).strip() if name_match else "Unknown Technique"
        
        desc_match = re.search(r'## Description\n\n(.+?)(?:\n##|\Z)', tech_info['readme'], re.DOTALL)
        tech_info['description'] = desc_match.group(1).strip()[:500] if desc_match else ""
    else:
        tech_info['name'] = technique_dir.name.replace('SAFE-', '').replace('-', ' ').title()
        tech_info['description'] = ""
    
    # Read pseudocode
    pseudocode_path = technique_dir / "pseudocode.md"
    if pseudocode_path.exists():
        tech_info['pseudocode'] = pseudocode_path.read_text()
    
    # Read detection rule
    detection_rule_path = technique_dir / "detection-rule.yml"
    if detection_rule_path.exists():
        try:
            with open(detection_rule_path, 'r') as f:
                tech_info['detection_rule'] = yaml.safe_load(f)
        except Exception as e:
            print(f"  Warning: Could not parse detection-rule.yml: {e}")
    
    return tech_info


def extract_detection_patterns(detection_rule: Dict[str, Any]) -> List[str]:
    """Extract detection patterns from Sigma rule"""
    patterns = []
    
    if not detection_rule or 'detection' not in detection_rule:
        return patterns
    
    detection = detection_rule['detection']
    
    # Extract from selection
    if 'selection' in detection:
        selection = detection['selection']
        for key, value in selection.items():
            if isinstance(value, list):
                patterns.extend(value)
            elif isinstance(value, str):
                patterns.append(value)
            elif isinstance(value, dict) and 'contains' in value:
                if isinstance(value['contains'], list):
                    patterns.extend(value['contains'])
                else:
                    patterns.append(value['contains'])
    
    return patterns


def extract_attack_stages(pseudocode: str) -> List[Dict[str, str]]:
    """Extract attack stages from pseudocode"""
    stages = []
    
    if not pseudocode:
        return stages
    
    # Look for numbered stages or function definitions
    # Pattern 1: Numbered stages
    stage_pattern = r'(\d+)\.\s*([A-Z_]+):\s*(.+?)(?=\n\d+\.|\n```|\Z)'
    matches = re.finditer(stage_pattern, pseudocode, re.DOTALL | re.MULTILINE)
    for match in matches:
        desc = match.group(3).strip()
        # Clean up description - remove excessive whitespace, limit length
        desc = re.sub(r'\s+', ' ', desc)  # Replace multiple whitespace with single space
        desc = desc[:200]  # Limit length
        stages.append({
            'number': match.group(1),
            'name': match.group(2).replace('_', ' ').title(),
            'description': desc
        })
    
    # Pattern 2: Function definitions in pseudocode
    if not stages:
        func_pattern = r'def\s+(\w+)\([^)]*\):\s*"""(.*?)"""'
        matches = re.finditer(func_pattern, pseudocode, re.DOTALL)
        for i, match in enumerate(matches, 1):
            func_name = match.group(1)
            func_desc = match.group(2).strip() if match.group(2) else ""
            # Clean up description
            func_desc = re.sub(r'\s+', ' ', func_desc)  # Replace multiple whitespace with single space
            func_desc = func_desc[:200]  # Limit length
            if 'attack' in func_name.lower() or 'exploit' in func_name.lower() or 'inject' in func_name.lower():
                stages.append({
                    'number': str(i),
                    'name': func_name.replace('_', ' ').title(),
                    'description': func_desc
                })
    
    return stages[:6]  # Limit to 6 stages


def generate_detector(tech_info: Dict[str, Any]) -> str:
    """Generate detector.py from detection rule and pseudocode"""
    tech_id = tech_info['id']
    tech_name = tech_info['name']
    # Escape quotes in tech_name for use in f-strings
    tech_name_escaped = tech_name.replace('"', '\\"').replace("'", "\\'")
    detection_rule = tech_info.get('detection_rule')
    patterns = extract_detection_patterns(detection_rule) if detection_rule else []
    
    # Generate pattern matching code
    pattern_code = ""
    if patterns:
        pattern_code = "        # Detection patterns from detection-rule.yml\n"
        for pattern in patterns[:10]:  # Limit to 10 patterns
            # Convert Sigma wildcard to regex
            regex_pattern = pattern.replace('*', '.*')
            pattern_code += f"        if re.search(r'{re.escape(regex_pattern)}', str(data), re.IGNORECASE):\n"
            pattern_code += f"            findings['high'].append(f'Pattern matched: {pattern}')\n"
    else:
        pattern_code = "        # TODO: Add detection patterns from detection-rule.yml\n"
    
    class_name = tech_id.replace('-', '').replace('SAFE', '')
    
    return f'''#!/usr/bin/env python3
"""
{tech_id}: {tech_name} - Detection Implementation

This detector identifies indicators of {tech_name.lower()} attacks in MCP environments.
Generated from detection-rule.yml and pseudocode.md.
"""

import json
import re
from typing import Dict, List, Any
from datetime import datetime


class {class_name}Detector:
    """Detector for {tech_name} attacks in MCP environments"""
    
    def __init__(self):
        # Detection patterns from detection-rule.yml
        self.patterns = {patterns}
    
    def scan(self, data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Scan for {tech_name.lower()} indicators"""
        findings = {{
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }}
        
{pattern_code}
        
        # Additional detection logic based on technique specifics
        # See README.md and pseudocode.md for complete attack flow
        
        return findings
    
    def scan_logs(self, log_file: str) -> Dict[str, Any]:
        """Scan log file for {tech_name.lower()} indicators"""
        try:
            with open(log_file, 'r') as f:
                logs = json.load(f)
        except Exception as e:
            return {{'error': f"Failed to load log file: {{e}}"}}
        
        all_findings = {{
            'events_analyzed': 0,
            'findings': {{
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
            }},
            'summary': {{}}
        }}
        
        for event in logs:
            all_findings['events_analyzed'] += 1
            event_findings = self.scan(event)
            
            # Merge findings
            for severity in event_findings:
                if severity in all_findings['findings']:
                    all_findings['findings'][severity].extend(event_findings[severity])
        
        # Generate summary
        all_findings['summary'] = {{
            'critical': len(all_findings['findings']['critical']),
            'high': len(all_findings['findings']['high']),
            'medium': len(all_findings['findings']['medium']),
            'low': len(all_findings['findings']['low']),
        }}
        
        return all_findings
    
    def generate_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate human-readable report"""
        if 'error' in scan_results:
            return f"Error: {{scan_results['error']}}\\n"
        
        report = f"\\n=== {tech_id} Detection Report ===\\n\\n"
        report += f"Technique: {tech_name_escaped}\\n"
        report += f"Events Analyzed: {{scan_results.get('events_analyzed', 0)}}\\n\\n"
        
        if 'summary' in scan_results:
            summary = scan_results['summary']
            report += "Summary:\\n"
            report += f"  Critical: {{summary.get('critical', 0)}}\\n"
            report += f"  High: {{summary.get('high', 0)}}\\n"
            report += f"  Medium: {{summary.get('medium', 0)}}\\n"
            report += f"  Low: {{summary.get('low', 0)}}\\n\\n"
        
        findings = scan_results.get('findings', {{}})
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        icons = {{
            'critical': '🚨',
            'high': '⚠️ ',
            'medium': '⚡',
            'low': '📌',
            'info': 'ℹ️ '
        }}
        
        for severity in severity_order:
            if findings.get(severity):
                report += f"{{icons.get(severity, '')}} {{severity.upper()}} ({{len(findings[severity])}} findings)\\n"
                for finding in findings[severity][:10]:
                    report += f"  - {{finding}}\\n"
                if len(findings[severity]) > 10:
                    report += f"  ... and {{len(findings[severity]) - 10}} more\\n"
                report += "\\n"
        
        if all(not findings.get(s, []) for s in severity_order):
            report += "✓ No indicators detected\\n"
        
        return report


def main():
    """Main entry point"""
    import sys
    
    detector = {class_name}Detector()
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        results = detector.scan_logs(log_file)
        report = detector.generate_report(results)
        print(report)
    else:
        print(f"Usage: python {{sys.argv[0]}} <log_file.json>")
        print(f"\\n{tech_id}: {tech_name_escaped} Detector")
        print("See README.md and detection-rule.yml for more information.")


if __name__ == "__main__":
    main()
'''


def generate_attack_simulation(tech_info: Dict[str, Any]) -> str:
    """Generate attack_simulation.py from pseudocode"""
    tech_id = tech_info['id']
    tech_name = tech_info['name']
    # Escape quotes in tech_name for use in f-strings
    tech_name_escaped = tech_name.replace('"', '\\"').replace("'", "\\'")
    pseudocode = tech_info.get('pseudocode', '')
    stages = extract_attack_stages(pseudocode)
    
    # Generate stage code
    stage_code = ""
    if stages:
        for stage in stages:
            stage_num = stage['number']
            stage_name = stage['name']
            # Properly escape the description for Python strings
            stage_desc = stage['description']
            # Escape quotes and newlines
            stage_desc_escaped = stage_desc.replace('\\', '\\\\').replace("'", "\\'").replace('"', '\\"')
            # Replace newlines with \n
            stage_desc_escaped = stage_desc_escaped.replace('\n', '\\n')
            # For print statement, use repr to safely handle the string
            stage_desc_print = repr(stage_desc)
            
            stage_method_name = stage_name.lower().replace(' ', '_').replace('-', '_')
            # Clean method name to be valid Python identifier
            stage_method_name = re.sub(r'[^a-z0-9_]', '', stage_method_name)
            if not stage_method_name or stage_method_name[0].isdigit():
                stage_method_name = f"stage_{stage_method_name}"
            
            stage_code += f'''    def stage_{stage_num}_{stage_method_name}(self):
        """Stage {stage_num}: {stage_name}"""
        print("[Stage {stage_num}] {stage_name}")
        print("-" * 60)
        print({stage_desc_print})
        
        event_data = {{
            'stage': {stage_num},
            'name': {repr(stage_name)},
            'description': {repr(stage_desc)},
            'timestamp': datetime.now().isoformat(),
        }}
        
        event = self.log_event('stage_{stage_num}', event_data)
        print(f"  ✓ Stage {stage_num} completed")
        return event
    
'''
    else:
        # Default stages if none found
        stage_code = '''    def stage_1_preparation(self):
        """Stage 1: Attack Preparation"""
        print("[Stage 1] Attack Preparation")
        print("-" * 60)
        print("Preparing attack based on pseudocode...")
        
        event_data = {
            'stage': 1,
            'name': 'Preparation',
            'timestamp': datetime.now().isoformat(),
        }
        
        event = self.log_event('preparation', event_data)
        print("  ✓ Preparation completed")
        return event
    
    def stage_2_execution(self):
        """Stage 2: Attack Execution"""
        print("[Stage 2] Attack Execution")
        print("-" * 60)
        print("Executing attack...")
        
        event_data = {
            'stage': 2,
            'name': 'Execution',
            'timestamp': datetime.now().isoformat(),
        }
        
        event = self.log_event('execution', event_data)
        print("  ✓ Execution completed")
        return event
    
'''
    
    # Generate run_full_attack method
    run_code = "        self.stage = 1\n"
    if stages:
        for i, stage in enumerate(stages, 1):
            stage_name = stage['name']
            stage_method_name = stage_name.lower().replace(' ', '_').replace('-', '_')
            stage_method_name = re.sub(r'[^a-z0-9_]', '', stage_method_name)
            if not stage_method_name or stage_method_name[0].isdigit():
                stage_method_name = f"stage_{stage_method_name}"
            stage_method = f"stage_{stage['number']}_{stage_method_name}"
            run_code += f"        self.{stage_method}()\n"
            if i < len(stages):
                run_code += "        time.sleep(0.5)\n"
                run_code += f"        self.stage = {i + 1}\n"
    else:
        run_code += "        self.stage_1_preparation()\n"
        run_code += "        time.sleep(0.5)\n"
        run_code += "        self.stage = 2\n"
        run_code += "        self.stage_2_execution()\n"
    
    class_name = tech_id.replace('-', '').replace('SAFE', '')
    
    return f'''#!/usr/bin/env python3
"""
{tech_id}: {tech_name} - Attack Simulation

This script simulates {tech_name.lower()} attack scenarios based on pseudocode.md.
Generated from pseudocode.md.

WARNING: This is for educational and testing purposes only.
"""

import json
import time
from typing import Dict, Any
from datetime import datetime


class {class_name}AttackSimulator:
    """Simulates {tech_name} attack scenarios"""
    
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
    
{stage_code}
    def run_full_attack(self):
        """Run complete attack simulation"""
        print("=" * 60)
        print(f"{tech_name_escaped} Attack Simulation")
        print("=" * 60)
        print("\\n⚠️  WARNING: This is a simulation for educational purposes only\\n")
        
{run_code}
        print()
        print("=" * 60)
        print("Attack simulation complete!")
        print("=" * 60)
        
        return self.attack_log
    
    def save_logs(self, filename: str = "{tech_id.lower()}_attack_logs.json"):
        """Save attack logs to file"""
        with open(filename, 'w') as f:
            json.dump(self.attack_log, f, indent=2)
        print(f"\\nAttack logs saved to: {{filename}}")
        return filename


def main():
    """Main entry point"""
    simulator = {class_name}AttackSimulator()
    
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


def generate_example_md(tech_info: Dict[str, Any]) -> str:
    """Generate EXAMPLE.md documentation"""
    tech_id = tech_info['id']
    tech_name = tech_info['name']
    description = tech_info.get('description', '')
    has_pseudocode = tech_info.get('pseudocode') is not None
    has_detection_rule = tech_info.get('detection_rule') is not None
    
    return f'''# {tech_id}: {tech_name} - Example Implementation

## Overview

This directory contains working examples demonstrating **{tech_id}: {tech_name}** detection and attack simulation. These examples are generated from `pseudocode.md` and `detection-rule.yml`.

## Technique Description

{description[:500]}{'...' if len(description) > 500 else ''}

## Files

- **`detector.py`**: Detection implementation based on `detection-rule.yml`
- **`attack_simulation.py`**: Attack simulation based on `pseudocode.md`
- **`EXAMPLE.md`**: This file - documentation of the technique and validation

## Source Files

- **`../pseudocode.md`**: Attack flow pseudocode {'✓' if has_pseudocode else '✗'}
- **`../detection-rule.yml`**: Sigma detection rule {'✓' if has_detection_rule else '✗'}
- **`../README.md`**: Complete technique documentation

## Detection Implementation

The detector (`detector.py`) implements patterns from the Sigma detection rule to identify {tech_name.lower()} indicators in MCP environments.

### Key Features

- Pattern matching based on detection-rule.yml
- Log file analysis
- Report generation with severity levels

## Attack Simulation

The attack simulation (`attack_simulation.py`) demonstrates the attack flow as documented in `pseudocode.md`.

### Running the Simulation

```bash
python3 attack_simulation.py
```

This will generate attack logs that can be used to test the detector.

## Testing Detection

### 1. Generate Attack Logs

```bash
python3 attack_simulation.py
```

### 2. Test Detection

```bash
python3 detector.py {tech_id.lower()}_attack_logs.json
```

## Validation

These examples should be validated against:
- The pseudocode in `../pseudocode.md`
- The detection patterns in `../detection-rule.yml`
- The test cases in `../test_detection_rule.py` (if available)

## Limitations

1. **Coverage**: Examples may not cover all attack variations
2. **False Positives**: Legitimate activities may trigger alerts
3. **Evasion**: Sophisticated attackers may use evasion techniques

## References

- See `../README.md` for complete technique documentation
- See `../detection-rule.yml` for Sigma detection rule
- See `../pseudocode.md` for attack flow pseudocode
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)

## Educational Use Only

⚠️ **WARNING**: These examples are for educational and defensive purposes only. Do not use these techniques against production systems or real MCP deployments.
'''


def create_examples_for_technique(technique_dir: Path) -> bool:
    """Create examples for a specific technique"""
    tech_info = read_technique_info(technique_dir)
    
    if not tech_info:
        return False
    
    examples_dir = technique_dir / "examples"
    examples_dir.mkdir(exist_ok=True)
    
    # Generate files
    detector_content = generate_detector(tech_info)
    attack_content = generate_attack_simulation(tech_info)
    example_md_content = generate_example_md(tech_info)
    
    # Write files
    (examples_dir / "detector.py").write_text(detector_content)
    (examples_dir / "attack_simulation.py").write_text(attack_content)
    (examples_dir / "EXAMPLE.md").write_text(example_md_content)
    
    # Make scripts executable
    os.chmod(examples_dir / "detector.py", 0o755)
    os.chmod(examples_dir / "attack_simulation.py", 0o755)
    
    return True


def validate_examples(technique_dir: Path) -> Dict[str, Any]:
    """Validate examples for a technique"""
    results = {
        'technique': technique_dir.name,
        'valid': True,
        'errors': [],
        'warnings': []
    }
    
    examples_dir = technique_dir / "examples"
    
    if not examples_dir.exists():
        results['valid'] = False
        results['errors'].append("Examples directory does not exist")
        return results
    
    # Check required files
    required_files = ['detector.py', 'attack_simulation.py', 'EXAMPLE.md']
    for file in required_files:
        file_path = examples_dir / file
        if not file_path.exists():
            results['valid'] = False
            results['errors'].append(f"Missing file: {file}")
        else:
            # Check if file is not empty
            if file_path.stat().st_size == 0:
                results['warnings'].append(f"Empty file: {file}")
    
    # Try to import and validate Python syntax
    for py_file in ['detector.py', 'attack_simulation.py']:
        py_path = examples_dir / py_file
        if py_path.exists():
            try:
                with open(py_path, 'r') as f:
                    code = f.read()
                compile(code, str(py_path), 'exec')
            except SyntaxError as e:
                results['valid'] = False
                results['errors'].append(f"Syntax error in {py_file}: {e}")
            except Exception as e:
                results['warnings'].append(f"Could not validate {py_file}: {e}")
    
    return results


def main():
    """Main entry point"""
    if len(sys.argv) > 1:
        # Process specific technique
        technique_id = sys.argv[1]
        if not technique_id.startswith('SAFE-T'):
            technique_id = f"SAFE-T{technique_id}"
        
        technique_dir = TECHNIQUES_DIR / technique_id
        if not technique_dir.exists():
            print(f"Error: Technique directory not found: {technique_dir}")
            return 1
        
        print(f"Generating examples for {technique_id}...")
        if create_examples_for_technique(technique_dir):
            print(f"✓ Created examples for {technique_id}")
            
            # Validate
            results = validate_examples(technique_dir)
            if results['valid']:
                print(f"✓ Validation passed")
            else:
                print(f"✗ Validation failed:")
                for error in results['errors']:
                    print(f"  - {error}")
            if results['warnings']:
                for warning in results['warnings']:
                    print(f"  ⚠ {warning}")
        else:
            print(f"✗ Failed to create examples for {technique_id}")
            return 1
    else:
        # Process all techniques
        print("Generating examples for all SAFE techniques...\n")
        
        technique_dirs = sorted([d for d in TECHNIQUES_DIR.iterdir() 
                                if d.is_dir() and d.name.startswith("SAFE-T")])
        
        created = 0
        validated = 0
        failed = []
        
        for technique_dir in technique_dirs:
            technique_id = technique_dir.name
            print(f"Processing {technique_id}...", end=" ")
            
            if create_examples_for_technique(technique_dir):
                created += 1
                print("✓", end=" ")
                
                # Validate
                results = validate_examples(technique_dir)
                if results['valid']:
                    validated += 1
                    print("✓")
                else:
                    print("✗")
                    failed.append((technique_id, results))
            else:
                print("✗")
                failed.append((technique_id, {'errors': ['Failed to create examples']}))
        
        print(f"\n{'='*60}")
        print(f"Summary:")
        print(f"  Created: {created}/{len(technique_dirs)}")
        print(f"  Validated: {validated}/{len(technique_dirs)}")
        
        if failed:
            print(f"\nFailed techniques ({len(failed)}):")
            for tech_id, results in failed:
                print(f"  - {tech_id}")
                if 'errors' in results:
                    for error in results['errors']:
                        print(f"    ✗ {error}")
        
        return 0 if len(failed) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

