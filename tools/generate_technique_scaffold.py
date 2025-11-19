#!/usr/bin/env python3
"""
SAFE-MCP Technique Scaffolding Generator

This script generates missing files for SAFE-MCP techniques that have README.md
but are missing detection-rule.yml and other required files.

Based on CONTRIBUTOR_GUIDE.md requirements:
- detection-rule.yml (Sigma format)
- test-logs.json (optional but recommended)
- test_detection_rule.py (optional but recommended)
- pseudocode example file

Usage:
    python generate_technique_scaffold.py [--technique SAFE-TXXXX] [--all] [--dry-run]
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required. Install with: pip install pyyaml")
    sys.exit(1)

# Import validator
sys.path.insert(0, str(Path(__file__).parent))
try:
    from validate_detection_rules import DetectionRuleValidator
except ImportError:
    print("Warning: Could not import DetectionRuleValidator. Validation will be skipped.")
    DetectionRuleValidator = None

# Get repository root
REPO_ROOT = Path(__file__).parent.parent
TECHNIQUES_DIR = REPO_ROOT / "techniques"
TEMPLATE_DIR = TECHNIQUES_DIR


class TechniqueInfo:
    """Extracts and stores information from a technique README.md"""
    
    def __init__(self, technique_dir: Path):
        self.technique_dir = technique_dir
        self.technique_id = technique_dir.name
        self.readme_path = technique_dir / "README.md"
        self.readme_content = ""
        self.info = {}
        
    def load_readme(self) -> bool:
        """Load and parse README.md"""
        if not self.readme_path.exists():
            return False
        
        with open(self.readme_path, 'r', encoding='utf-8') as f:
            self.readme_content = f.read()
        
        self._extract_info()
        return True
    
    def _extract_info(self):
        """Extract technique information from README.md"""
        content = self.readme_content
        
        # Extract technique ID
        match = re.search(r'SAFE-T(\d+)', content)
        if match:
            self.info['technique_id'] = f"SAFE-T{match.group(1)}"
            self.info['technique_number'] = match.group(1)
        
        # Extract technique name
        name_match = re.search(r'#\s*SAFE-T\d+:\s*(.+?)(?:\n|$)', content)
        if name_match:
            self.info['technique_name'] = name_match.group(1).strip()
        else:
            # Try alternative pattern
            name_match = re.search(r'Technique Name[:\*]+\s*(.+?)(?:\n|$)', content, re.IGNORECASE)
            if name_match:
                self.info['technique_name'] = name_match.group(1).strip()
            else:
                self.info['technique_name'] = "Unknown Technique"
        
        # Extract tactic
        tactic_match = re.search(r'Tactic[:\*]+\s*(.+?)(?:\n|$)', content, re.IGNORECASE)
        if tactic_match:
            tactic = tactic_match.group(1).strip()
            # Extract tactic ID
            tactic_id_match = re.search(r'ATK-TA(\d+)', tactic)
            if tactic_id_match:
                self.info['tactic_id'] = f"ATK-TA{tactic_id_match.group(1)}"
                self.info['tactic_name'] = re.sub(r'\([^)]+\)', '', tactic).strip()
            else:
                self.info['tactic_name'] = tactic
        else:
            self.info['tactic_name'] = "Unknown"
            self.info['tactic_id'] = "ATK-TA0000"
        
        # Extract severity
        severity_match = re.search(r'Severity[:\*]+\s*(Critical|High|Medium|Low)', content, re.IGNORECASE)
        if severity_match:
            self.info['severity'] = severity_match.group(1).capitalize()
        else:
            self.info['severity'] = "Medium"
        
        # Extract description (first paragraph)
        desc_match = re.search(r'##\s*Description\s*\n\n(.+?)(?:\n\n|\n##)', content, re.DOTALL)
        if desc_match:
            desc = desc_match.group(1).strip()
            # Take first sentence or first 200 chars
            self.info['description'] = desc.split('.')[0] + '.' if '.' in desc else desc[:200]
        else:
            self.info['description'] = f"Detection rule for {self.info.get('technique_name', 'technique')}"
        
        # Extract MITRE ATT&CK mapping
        mitre_match = re.search(r'MITRE ATT&CK.*?T(\d+)', content, re.IGNORECASE | re.DOTALL)
        if mitre_match:
            self.info['mitre_technique'] = f"T{mitre_match.group(1)}"
        else:
            # Try alternative pattern
            mitre_match = re.search(r'T(\d{4})\s*[-–]\s*([^\n]+)', content)
            if mitre_match:
                self.info['mitre_technique'] = f"T{mitre_match.group(1)}"
        
        # Extract IoCs from Detection Methods section
        ioc_section = re.search(r'##\s*Detection.*?##', content, re.DOTALL | re.IGNORECASE)
        if ioc_section:
            ioc_text = ioc_section.group(0)
            # Look for bullet points or numbered lists
            iocs = re.findall(r'[-*•]\s*(.+?)(?:\n|$)', ioc_text)
            self.info['iocs'] = [ioc.strip() for ioc in iocs[:5]]  # Limit to 5
        else:
            self.info['iocs'] = []
        
        # Extract attack vectors
        vectors = []
        vector_section = re.search(r'##\s*Attack Vectors.*?##', content, re.DOTALL | re.IGNORECASE)
        if vector_section:
            vector_text = vector_section.group(0)
            primary_match = re.search(r'Primary Vector[:\*]+\s*(.+?)(?:\n|$)', vector_text, re.IGNORECASE)
            if primary_match:
                vectors.append(primary_match.group(1).strip())
            # Secondary vectors
            secondary_matches = re.findall(r'Secondary.*?[-*•]\s*(.+?)(?:\n|$)', vector_text, re.IGNORECASE | re.DOTALL)
            vectors.extend([m.strip() for m in secondary_matches[:3]])
        self.info['attack_vectors'] = vectors
        
        # Extract last updated date
        date_match = re.search(r'Last Updated[:\*]+\s*(\d{4}-\d{2}-\d{2})', content, re.IGNORECASE)
        if date_match:
            self.info['last_updated'] = date_match.group(1)
        else:
            self.info['last_updated'] = datetime.now().strftime("%Y-%m-%d")
        
        # Determine detection level from severity
        severity_to_level = {
            'Critical': 'high',
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low'
        }
        self.info['detection_level'] = severity_to_level.get(self.info['severity'], 'medium')
        
        # Extract tactic tag
        tactic_tag_map = {
            'reconnaissance': 'attack.reconnaissance',
            'resource_development': 'attack.resource_development',
            'initial_access': 'attack.initial_access',
            'execution': 'attack.execution',
            'persistence': 'attack.persistence',
            'privilege_escalation': 'attack.privilege_escalation',
            'defense_evasion': 'attack.defense_evasion',
            'credential_access': 'attack.credential_access',
            'discovery': 'attack.discovery',
            'lateral_movement': 'attack.lateral_movement',
            'collection': 'attack.collection',
            'command_and_control': 'attack.command_and_control',
            'exfiltration': 'attack.exfiltration',
            'impact': 'attack.impact'
        }
        tactic_lower = self.info['tactic_name'].lower().replace(' ', '_')
        self.info['tactic_tag'] = tactic_tag_map.get(tactic_lower, 'attack.unknown')


def generate_uuid() -> str:
    """Generate a UUID for detection rules"""
    return str(uuid.uuid4())


def generate_detection_rule(tech_info: TechniqueInfo) -> str:
    """Generate detection-rule.yml in Sigma format"""
    info = tech_info.info
    
    # Generate patterns based on technique characteristics
    patterns = []
    
    # Common patterns based on technique name and description
    desc_lower = info.get('description', '').lower()
    name_lower = info.get('technique_name', '').lower()
    
    # Tool call patterns
    if 'tool' in name_lower or 'invocation' in name_lower or 'call' in name_lower:
        patterns.extend([
            '*tools/call*',
            '*method*: *tools/call*',
            '*tool_name*',
        ])
    
    # Injection patterns
    if 'injection' in name_lower or 'inject' in desc_lower:
        patterns.extend([
            '*<!-- SYSTEM:*',
            '*<|system|>*',
            '*[INST]*',
            '*### Instruction:*',
        ])
    
    # Enumeration patterns
    if 'enumeration' in name_lower or 'enum' in desc_lower:
        patterns.extend([
            '*list_*',
            '*enumerate*',
            '*discover*',
            '*query*',
        ])
    
    # Data harvesting patterns
    if 'harvest' in name_lower or 'collection' in name_lower:
        patterns.extend([
            '*get_*',
            '*read_*',
            '*query_*',
            '*fetch_*',
        ])
    
    # Backchannel patterns
    if 'backchannel' in name_lower or 'base64' in desc_lower:
        patterns.extend([
            '*data:image/*',
            '*data:audio/*',
            '*;base64,*',
            '*```base64*',
        ])
    
    # Fake tool patterns
    if 'fake' in name_lower or 'spoof' in name_lower:
        patterns.extend([
            '*system_admin*',
            '*admin_tool*',
            '*bypass*',
            '*elevated*',
        ])
    
    # Default patterns if none found
    if not patterns:
        patterns = [
            '*suspicious*',
            '*malicious*',
            '*unauthorized*',
        ]
    
    # Build detection rule
    rule = {
        'title': f"{info.get('technique_name', 'Unknown')} Detection",
        'id': generate_uuid(),
        'status': 'experimental',
        'description': f"Detects potential {info.get('technique_name', 'attack')} attempts in MCP environments",
        'author': 'SAFE-MCP Team',
        'date': info.get('last_updated', datetime.now().strftime("%Y-%m-%d")),
        'references': [
            f"https://github.com/safe-mcp/techniques/{info.get('technique_id', 'SAFE-TXXXX')}"
        ],
        'logsource': {
            'product': 'mcp',
            'service': 'tool_invocation'
        },
        'detection': {
            'selection': {
                'tool_name|contains': patterns[:10]  # Limit to 10 patterns
            },
            'condition': 'selection'
        },
        'falsepositives': [
            'Legitimate operations that match detection patterns',
            'Authorized administrative activities',
            'Security testing and research activities'
        ],
        'level': info.get('detection_level', 'medium'),
        'tags': [
            info.get('tactic_tag', 'attack.unknown'),
            f"safe.t{info.get('technique_number', 'XXXX')}"
        ]
    }
    
    # Add MITRE tag if available
    if 'mitre_technique' in info:
        rule['tags'].append(f"attack.{info['mitre_technique'].lower()}")
    
    # Convert to YAML
    yaml_str = yaml.dump(rule, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    # Add header comment
    header = f"""# {info.get('technique_id', 'SAFE-TXXXX')}: {info.get('technique_name', 'Detection Rule')}
# This rule detects potential {info.get('technique_name', 'attack')} attempts
# Note: This is an example rule. Attackers continuously develop new techniques.

"""
    
    return header + yaml_str


def generate_test_logs(tech_info: TechniqueInfo) -> str:
    """Generate test-logs.json with sample test data"""
    info = tech_info.info
    patterns = []
    
    # Extract patterns from detection rule or use defaults
    desc_lower = info.get('description', '').lower()
    name_lower = info.get('technique_name', '').lower()
    
    # Generate test cases
    test_cases = []
    
    # Positive test cases (should be detected)
    positive_cases = [
        {"tool_name": "suspicious_tool", "tool_description": "Tool with suspicious pattern"},
        {"tool_name": "malicious_function", "tool_description": "Contains malicious content"},
    ]
    
    # Negative test cases (should not be detected)
    negative_cases = [
        {"tool_name": "legitimate_tool", "tool_description": "Normal tool for legitimate operations"},
        {"tool_name": "safe_function", "tool_description": "Standard functionality"},
    ]
    
    # Add technique-specific test cases
    if 'injection' in name_lower:
        positive_cases.append({
            "tool_name": "injection_test",
            "tool_description": "Tool with <!-- SYSTEM: malicious instruction --> hidden"
        })
    
    if 'enumeration' in name_lower:
        positive_cases.append({
            "tool_name": "enumeration_tool",
            "tool_description": "Tool that lists all available resources"
        })
    
    if 'harvest' in name_lower:
        positive_cases.append({
            "tool_name": "data_harvester",
            "tool_description": "Tool that fetches large amounts of data"
        })
    
    if 'backchannel' in name_lower:
        positive_cases.append({
            "tool_name": "backchannel_tool",
            "tool_description": "Tool with data:image/png;base64,iVBORw0KGgo embedded"
        })
    
    if 'fake' in name_lower or 'spoof' in name_lower:
        positive_cases.append({
            "tool_name": "fake_admin_tool",
            "tool_description": "System administration tool with bypass capabilities"
        })
    
    # Combine all test cases
    all_cases = positive_cases + negative_cases
    
    # Convert to JSON lines format
    json_lines = []
    for case in all_cases:
        json_lines.append(json.dumps(case))
    
    return '\n'.join(json_lines) + '\n'


def generate_test_script(tech_info: TechniqueInfo) -> str:
    """Generate test_detection_rule.py validation script"""
    info = tech_info.info
    technique_id = info.get('technique_id', 'SAFE-TXXXX')
    
    script = f'''#!/usr/bin/env python3
"""Test script for {technique_id} detection rule validation"""

import json
import re
import yaml
from pathlib import Path

def load_sigma_rule(rule_path):
    """Load and parse Sigma rule"""
    with open(rule_path, 'r') as f:
        return yaml.safe_load(f)

def convert_sigma_pattern_to_regex(pattern):
    """Convert Sigma wildcard pattern to regex"""
    # Handle unicode escape sequences
    if '\\\\u' in pattern:
        try:
            pattern = pattern.encode().decode('unicode-escape')
        except:
            pass
    
    # Escape special regex characters except *
    pattern = re.escape(pattern)
    # Replace escaped \\* with .*
    pattern = pattern.replace(r'\\*', '.*')
    return pattern

def test_detection_rule():
    """Test the detection rule against known samples"""
    # Load rule
    rule_path = Path(__file__).parent / 'detection-rule.yml'
    rule = load_sigma_rule(rule_path)
    
    # Extract patterns
    detection = rule.get('detection', {{}})
    selection = detection.get('selection', {{}})
    
    # Find the field with patterns
    patterns = []
    for key, value in selection.items():
        if isinstance(value, list):
            patterns = value
            break
        elif isinstance(value, dict) and 'contains' in key:
            patterns = list(value.values())[0] if value else []
            break
    
    if not patterns:
        print("Warning: No patterns found in detection rule")
        return False
    
    # Load test logs
    test_logs_path = Path(__file__).parent / 'test-logs.json'
    if not test_logs_path.exists():
        print("Warning: test-logs.json not found")
        return False
    
    results = {{}}
    
    with open(test_logs_path, 'r') as f:
        for line in f:
            if not line.strip():
                continue
            log = json.loads(line.strip())
            tool_name = log.get('tool_name', 'unknown')
            description = log.get('tool_description', '')
            
            # Check if any pattern matches
            detected = False
            matched_pattern = None
            
            for pattern in patterns:
                regex = convert_sigma_pattern_to_regex(pattern)
                if re.search(regex, description, re.IGNORECASE) or re.search(regex, tool_name, re.IGNORECASE):
                    detected = True
                    matched_pattern = pattern
                    break
            
            results[tool_name] = {{
                'detected': detected,
                'matched_pattern': matched_pattern,
                'description': description
            }}
    
    # Print results
    print(f"{technique_id} Detection Rule Test Results")
    print("=" * 50)
    
    total_tests = len(results)
    detected_count = sum(1 for r in results.values() if r['detected'])
    
    for tool_name, result in results.items():
        status = "✓" if result['detected'] else "✗"
        print(f"{{status}} {{tool_name}}: Detected={{result['detected']}}")
        if result['matched_pattern']:
            print(f"  Matched pattern: {{result['matched_pattern']}}")
    
    print("\\n" + "=" * 50)
    print(f"Test Summary: {{detected_count}}/{{total_tests}} tools detected")
    
    return True

if __name__ == "__main__":
    success = test_detection_rule()
    exit(0 if success else 1)
'''
    return script


def generate_pseudocode(tech_info: TechniqueInfo) -> str:
    """Generate pseudocode example showing attack flow"""
    info = tech_info.info
    technique_id = info.get('technique_id', 'SAFE-TXXXX')
    technique_name = info.get('technique_name', 'Attack Technique')
    
    pseudocode = f'''# {technique_id}: {technique_name} - Attack Pseudocode

## Overview
This file contains pseudocode examples demonstrating how {technique_name} attacks
are performed. These examples are for educational and defensive purposes only.

## Attack Flow Pseudocode

### High-Level Attack Flow

```
1. ATTACKER_PREPARATION:
   - Identify target MCP environment
   - Analyze available tools and capabilities
   - Craft malicious payload/instructions

2. INITIAL_ACCESS:
   - Gain access to MCP session
   - Identify vulnerable entry points
   - Establish communication channel

3. ATTACK_EXECUTION:
   - Inject malicious content/instructions
   - Trigger tool execution
   - Bypass security controls

4. POST_EXPLOITATION:
   - Achieve attack objectives
   - Maintain persistence (if applicable)
   - Exfiltrate data (if applicable)
```

### Detailed Pseudocode

```python
# Example attack pseudocode for {technique_name}

def perform_attack():
    """
    Pseudocode demonstrating {technique_name} attack flow
    """
    
    # Step 1: Preparation
    target_mcp_server = identify_target()
    available_tools = enumerate_tools(target_mcp_server)
    
    # Step 2: Craft malicious payload
    malicious_payload = craft_payload(
        technique="{technique_name}",
        target_tools=available_tools
    )
    
    # Step 3: Execute attack
    attack_session = establish_session(target_mcp_server)
    
    # Inject malicious content
    if attack_session.inject(malicious_payload):
        # Trigger tool execution
        result = attack_session.execute_tool(
            tool_name=select_target_tool(available_tools),
            arguments=malicious_payload
        )
        
        # Step 4: Process results
        if result.success:
            exfiltrate_data(result.data)
            maintain_persistence(attack_session)
        else:
            log_attack_failure(result.error)
    
    return attack_session

def craft_payload(technique, target_tools):
    """
    Generate attack payload based on technique
    """
    payload = {{
        "method": "tools/call",
        "params": {{
            "name": select_vulnerable_tool(target_tools),
            "arguments": generate_malicious_arguments(technique)
        }}
    }}
    
    return payload

def generate_malicious_arguments(technique):
    """
    Generate technique-specific malicious arguments
    """
    if technique == "{technique_name}":
        return {{
            # Technique-specific arguments
            "malicious_field": "malicious_value",
            "bypass_flag": True,
            "elevated_permissions": True
        }}
    
    return {{}}

# Detection evasion techniques
def evade_detection(payload):
    """
    Apply obfuscation to evade detection
    """
    # Obfuscate payload
    obfuscated = obfuscate_string(payload)
    
    # Use encoding
    encoded = base64_encode(obfuscated)
    
    # Add legitimate-looking wrapper
    wrapped = wrap_in_legitimate_context(encoded)
    
    return wrapped
```

## Defense Pseudocode

```python
# Example defense pseudocode

def detect_attack(session, tool_call):
    """
    Detect {technique_name} attack attempts
    """
    
    # Check for suspicious patterns
    if contains_suspicious_patterns(tool_call):
        log_security_event(
            event_type="{technique_id}",
            session=session,
            tool_call=tool_call
        )
        return True
    
    # Validate tool call
    if not validate_tool_call(tool_call):
        block_tool_call(tool_call)
        return True
    
    return False

def validate_tool_call(tool_call):
    """
    Validate tool call against security policies
    """
    # Check tool registration
    if not is_tool_registered(tool_call.name):
        return False
    
    # Validate arguments
    if not validate_arguments(tool_call.arguments):
        return False
    
    # Check rate limits
    if exceeds_rate_limit(tool_call):
        return False
    
    return True
```

## Notes

- This pseudocode is for educational purposes only
- Actual implementations may vary significantly
- Always implement proper security controls in production
- Regularly update detection rules based on new attack patterns

## References

- See README.md for complete technique documentation
- See detection-rule.yml for detection patterns
- See test-logs.json for test scenarios
'''
    return pseudocode


def has_only_readme(technique_dir: Path) -> bool:
    """Check if technique directory has only README.md file"""
    if not (technique_dir / "README.md").exists():
        return False
    
    # Get all files in directory (excluding hidden files and directories)
    files = [f for f in technique_dir.iterdir() if f.is_file() and not f.name.startswith('.')]
    
    # Check if only README.md exists
    return len(files) == 1 and files[0].name == "README.md"


def validate_existing_detection_rule(rule_path: Path) -> Tuple[bool, List[str], List[str]]:
    """Validate an existing detection rule YAML file.
    
    Returns:
        Tuple of (is_valid, errors, warnings)
    """
    if not DetectionRuleValidator:
        # If validator not available, assume valid
        return True, [], []
    
    if not rule_path.exists():
        return False, ["File does not exist"], []
    
    validator = DetectionRuleValidator(rule_path)
    is_valid, errors, warnings, _ = validator.validate()
    
    error_messages = [str(e) for e in errors]
    warning_messages = [str(w) for w in warnings]
    
    return is_valid, error_messages, warning_messages


def backup_detection_rule(rule_path: Path) -> Optional[Path]:
    """Create a backup of existing detection rule.
    
    Returns:
        Path to backup file, or None if backup failed
    """
    if not rule_path.exists():
        return None
    
    # Create backup filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = rule_path.parent / f"detection-rule.yml.backup_{timestamp}"
    
    try:
        shutil.copy2(rule_path, backup_path)
        return backup_path
    except Exception as e:
        print(f"  ⚠ Warning: Failed to create backup: {e}")
        return None


def needs_scaffolding(technique_dir: Path) -> Tuple[bool, List[str], bool]:
    """Check if technique needs scaffolding and what files are missing.
    
    Returns:
        Tuple of (needs_scaffolding, missing_files, has_detection_rule)
    """
    missing = []
    has_detection_rule = False
    
    # Check for README.md
    if not (technique_dir / "README.md").exists():
        return False, [], False  # Skip if no README.md
    
    # Check for detection-rule.yml
    detection_rule_path = technique_dir / "detection-rule.yml"
    if detection_rule_path.exists():
        has_detection_rule = True
    else:
        missing.append("detection-rule.yml")
    
    # Optional files (we'll generate them)
    if not (technique_dir / "test-logs.json").exists():
        missing.append("test-logs.json")
    
    if not (technique_dir / "test_detection_rule.py").exists():
        missing.append("test_detection_rule.py")
    
    if not (technique_dir / "pseudocode.md").exists():
        missing.append("pseudocode.md")
    
    return len(missing) > 0, missing, has_detection_rule


def main():
    parser = argparse.ArgumentParser(
        description="Generate scaffolding files for SAFE-MCP techniques",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate files for a specific technique
  python generate_technique_scaffold.py --technique SAFE-T1103
  
  # Generate files for all techniques missing detection rules
  python generate_technique_scaffold.py --all
  
  # Dry run to see what would be generated
  python generate_technique_scaffold.py --all --dry-run
        """
    )
    
    parser.add_argument(
        "--technique",
        type=str,
        help="Specific technique ID to scaffold (e.g., SAFE-T1103)"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Process all techniques that need scaffolding"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be generated without creating files"
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate generated detection rules after creation"
    )
    
    args = parser.parse_args()
    
    if not args.technique and not args.all:
        parser.print_help()
        sys.exit(1)
    
    # Find techniques to process
    techniques_to_process = []
    
    if args.technique:
        technique_dir = TECHNIQUES_DIR / args.technique
        if not technique_dir.exists():
            print(f"Error: Technique directory not found: {technique_dir}")
            sys.exit(1)
        techniques_to_process.append(technique_dir)
    elif args.all:
        # Find all technique directories
        for technique_dir in sorted(TECHNIQUES_DIR.glob("SAFE-T*")):
            if technique_dir.is_dir():
                # Include if it has only README.md or needs scaffolding
                if has_only_readme(technique_dir):
                    techniques_to_process.append(technique_dir)
                else:
                    needs, missing, has_rule = needs_scaffolding(technique_dir)
                    if needs:
                        techniques_to_process.append(technique_dir)
    
    if not techniques_to_process:
        print("No techniques found that need scaffolding.")
        sys.exit(0)
    
    print(f"Found {len(techniques_to_process)} technique(s) to process:")
    for tech_dir in techniques_to_process:
        if has_only_readme(tech_dir):
            print(f"  - {tech_dir.name}: has only README.md (will generate all files)")
        else:
            needs, missing, has_rule = needs_scaffolding(tech_dir)
            if has_rule:
                print(f"  - {tech_dir.name}: has detection-rule.yml (will validate and regenerate)")
            if missing:
                print(f"  - {tech_dir.name}: missing {', '.join(missing)}")
    
    if args.dry_run:
        print("\n[DRY RUN] Would generate files for the above techniques.")
        return
    
    # Process each technique
    generated_count = 0
    failed_count = 0
    
    for technique_dir in techniques_to_process:
        print(f"\n{'='*70}")
        print(f"Processing: {technique_dir.name}")
        print(f"{'='*70}")
        
        try:
            # Load technique info
            tech_info = TechniqueInfo(technique_dir)
            if not tech_info.load_readme():
                print(f"  ✗ Failed to load README.md")
                failed_count += 1
                continue
            
            print(f"  Technique: {tech_info.info.get('technique_name', 'Unknown')}")
            print(f"  Tactic: {tech_info.info.get('tactic_name', 'Unknown')}")
            
            # Check if folder has only README.md
            only_readme = has_only_readme(technique_dir)
            detection_rule_path = technique_dir / "detection-rule.yml"
            has_existing_rule = detection_rule_path.exists()
            
            # Handle existing detection rule
            if has_existing_rule:
                print(f"  ℹ Found existing detection-rule.yml")
                
                # Validate existing rule
                is_valid, errors, warnings = validate_existing_detection_rule(detection_rule_path)
                
                if is_valid:
                    print(f"  ✓ Existing detection rule is valid")
                    if warnings:
                        print(f"  ⚠ Warnings: {len(warnings)}")
                        for warning in warnings[:3]:  # Show first 3 warnings
                            print(f"    - {warning}")
                else:
                    print(f"  ✗ Existing detection rule has errors: {len(errors)}")
                    for error in errors[:3]:  # Show first 3 errors
                        print(f"    - {error}")
                    print(f"  ℹ Will regenerate detection rule")
                
                # Create backup of existing rule
                if not args.dry_run:
                    backup_path = backup_detection_rule(detection_rule_path)
                    if backup_path:
                        print(f"  ✓ Created backup: {backup_path.name}")
            
            # Generate files
            files_generated = []
            needs, missing, _ = needs_scaffolding(technique_dir)
            
            # Generate detection-rule.yml (always regenerate if it exists, or create if missing)
            if "detection-rule.yml" in missing or has_existing_rule:
                rule_content = generate_detection_rule(tech_info)
                if not args.dry_run:
                    with open(detection_rule_path, 'w', encoding='utf-8') as f:
                        f.write(rule_content)
                files_generated.append("detection-rule.yml")
                if has_existing_rule:
                    print(f"  ✓ Regenerated detection-rule.yml")
                else:
                    print(f"  ✓ Generated detection-rule.yml")
            
            # Generate test-logs.json
            if "test-logs.json" in missing:
                test_logs_content = generate_test_logs(tech_info)
                test_logs_path = technique_dir / "test-logs.json"
                if not args.dry_run:
                    with open(test_logs_path, 'w', encoding='utf-8') as f:
                        f.write(test_logs_content)
                files_generated.append("test-logs.json")
                print(f"  ✓ Generated test-logs.json")
            
            # Generate test_detection_rule.py
            if "test_detection_rule.py" in missing:
                test_script_content = generate_test_script(tech_info)
                test_script_path = technique_dir / "test_detection_rule.py"
                if not args.dry_run:
                    with open(test_script_path, 'w', encoding='utf-8') as f:
                        f.write(test_script_content)
                    # Make executable
                    test_script_path.chmod(0o755)
                files_generated.append("test_detection_rule.py")
                print(f"  ✓ Generated test_detection_rule.py")
            
            # Generate pseudocode.md
            if "pseudocode.md" in missing:
                pseudocode_content = generate_pseudocode(tech_info)
                pseudocode_path = technique_dir / "pseudocode.md"
                if not args.dry_run:
                    with open(pseudocode_path, 'w', encoding='utf-8') as f:
                        f.write(pseudocode_content)
                files_generated.append("pseudocode.md")
                print(f"  ✓ Generated pseudocode.md")
            
            if files_generated:
                generated_count += 1
                print(f"  ✓ Successfully generated {len(files_generated)} file(s)")
            else:
                print(f"  ⚠ No files needed generation")
        
        except Exception as e:
            print(f"  ✗ Error processing {technique_dir.name}: {e}")
            import traceback
            traceback.print_exc()
            failed_count += 1
    
    # Summary
    print(f"\n{'='*70}")
    print("Summary")
    print(f"{'='*70}")
    print(f"Techniques processed: {len(techniques_to_process)}")
    print(f"Successfully generated: {generated_count}")
    print(f"Failed: {failed_count}")
    
    # Validate if requested
    if args.validate and generated_count > 0:
        print(f"\n{'='*70}")
        print("Validating generated detection rules...")
        print(f"{'='*70}")
        
        # Run validation script
        validator_path = REPO_ROOT / "tools" / "validate_detection_rules.py"
        if validator_path.exists():
            for technique_dir in techniques_to_process:
                rule_path = technique_dir / "detection-rule.yml"
                if rule_path.exists():
                    print(f"\nValidating {technique_dir.name}...")
                    result = subprocess.run(
                        [sys.executable, str(validator_path), str(rule_path)],
                        capture_output=True,
                        text=True
                    )
                    print(result.stdout)
                    if result.stderr:
                        print(result.stderr, file=sys.stderr)
        else:
            print("Warning: Validation script not found")


if __name__ == "__main__":
    main()

