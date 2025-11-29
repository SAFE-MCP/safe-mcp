#!/usr/bin/env python3
"""
SAFE-MCP Technique Generator

This script generates a new SAFE-MCP technique directory structure with
all required files based on the template.

Usage:
    python generate_technique.py SAFE-T[XXXX] "Technique Name" --tactic ATK-TA0001
"""

import argparse
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path

# Get the repository root (parent of tools directory)
REPO_ROOT = Path(__file__).parent.parent
TECHNIQUES_DIR = REPO_ROOT / "techniques"
TEMPLATE_DIR = TECHNIQUES_DIR / "TEMPLATE.md"


def generate_uuid():
    """Generate a UUID for detection rules."""
    return str(uuid.uuid4())


def get_next_technique_id():
    """Find the next available technique ID by scanning existing directories."""
    existing_ids = []
    if TECHNIQUES_DIR.exists():
        for item in TECHNIQUES_DIR.iterdir():
            if item.is_dir() and item.name.startswith("SAFE-T"):
                try:
                    # Extract number from SAFE-TXXXX
                    num = int(item.name.replace("SAFE-T", ""))
                    existing_ids.append(num)
                except ValueError:
                    continue
    
    if existing_ids:
        next_id = max(existing_ids) + 1
    else:
        next_id = 1001  # Start from 1001 if no techniques exist
    
    return f"SAFE-T{next_id}"


def create_technique_directory(technique_id, technique_name, tactic_id, tactic_name, author):
    """Create a new technique directory with all required files."""
    
    technique_dir = TECHNIQUES_DIR / technique_id
    
    if technique_dir.exists():
        print(f"Error: Directory {technique_dir} already exists!")
        return False
    
    # Create directory
    technique_dir.mkdir(parents=True, exist_ok=True)
    print(f"Created directory: {technique_dir}")
    
    # Read template
    if not TEMPLATE_DIR.exists():
        print(f"Error: Template not found at {TEMPLATE_DIR}")
        return False
    
    with open(TEMPLATE_DIR, 'r') as f:
        template = f.read()
    
    # Replace template placeholders
    today = datetime.now().strftime("%Y-%m-%d")
    replacements = {
        "SAFE-T[XXXX]": technique_id,
        "[Technique Name]": technique_name,
        "[Tactic Name (ATK-TAXXXX)]": f"{tactic_name} ({tactic_id})",
        "[Tactic ID]": tactic_id,
        "[Date]": today,
        "[Author]": author,
        "[YYYY-MM-DD]": today,
    }
    
    content = template
    for placeholder, value in replacements.items():
        content = content.replace(placeholder, value)
    
    # Write README.md
    readme_path = technique_dir / "README.md"
    with open(readme_path, 'w') as f:
        f.write(content)
    print(f"Created: {readme_path}")
    
    # Create detection-rule.yml
    detection_rule_id = generate_uuid()
    detection_rule = f"""title: MCP {technique_name} Detection
id: {detection_rule_id}
status: experimental
description: Detects potential {technique_name.lower()} attempts in MCP environments
author: {author}
date: {today}
references:
  - https://github.com/safe-mcp/techniques/{technique_id}
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
level: high
tags:
  - attack.[tactic]
  - attack.t[XXXX]
  - safe.{technique_id.lower()}
"""
    
    detection_rule_path = technique_dir / "detection-rule.yml"
    with open(detection_rule_path, 'w') as f:
        f.write(detection_rule)
    print(f"Created: {detection_rule_path}")
    
    # Create empty test files (optional)
    test_logs_path = technique_dir / "test-logs.json"
    test_logs_path.write_text("[]\n")
    print(f"Created: {test_logs_path}")
    
    print(f"\n✓ Successfully created technique {technique_id}: {technique_name}")
    print(f"\nNext steps:")
    print(f"1. Edit {readme_path} and fill in all required sections")
    print(f"2. Update {detection_rule_path} with specific detection patterns")
    print(f"3. Review the checklist: {TECHNIQUES_DIR}/TEMPLATE-CHECKLIST.md")
    print(f"4. Update README.md in repository root to add this technique to the TTP table")
    
    return True


def get_tactic_info(tactic_id):
    """Map tactic ID to tactic name."""
    tactics = {
        "ATK-TA0043": "Reconnaissance",
        "ATK-TA0042": "Resource Development",
        "ATK-TA0001": "Initial Access",
        "ATK-TA0002": "Execution",
        "ATK-TA0003": "Persistence",
        "ATK-TA0004": "Privilege Escalation",
        "ATK-TA0005": "Defense Evasion",
        "ATK-TA0006": "Credential Access",
        "ATK-TA0007": "Discovery",
        "ATK-TA0008": "Lateral Movement",
        "ATK-TA0009": "Collection",
        "ATK-TA0011": "Command and Control",
        "ATK-TA0010": "Exfiltration",
        "ATK-TA0040": "Impact",
    }
    return tactics.get(tactic_id, "Unknown Tactic")


def main():
    parser = argparse.ArgumentParser(
        description="Generate a new SAFE-MCP technique directory structure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate with auto-detected next ID
  python generate_technique.py --name "Tool Poisoning Attack" --tactic ATK-TA0001 --author "Your Name"
  
  # Generate with specific ID
  python generate_technique.py SAFE-T1001 --name "Tool Poisoning Attack" --tactic ATK-TA0001 --author "Your Name"
        """
    )
    
    parser.add_argument(
        "technique_id",
        nargs="?",
        help="Technique ID (e.g., SAFE-T1001). If not provided, will auto-detect next available ID."
    )
    parser.add_argument(
        "--name",
        required=True,
        help="Technique name (e.g., 'Tool Poisoning Attack')"
    )
    parser.add_argument(
        "--tactic",
        required=True,
        help="Tactic ID (e.g., ATK-TA0001)"
    )
    parser.add_argument(
        "--author",
        default="SAFE-MCP Team",
        help="Author name (default: SAFE-MCP Team)"
    )
    
    args = parser.parse_args()
    
    # Validate tactic ID
    tactic_name = get_tactic_info(args.tactic)
    if tactic_name == "Unknown Tactic":
        print(f"Warning: Unknown tactic ID: {args.tactic}")
        print("Valid tactic IDs: ATK-TA0043, ATK-TA0042, ATK-TA0001-ATK-TA0011, ATK-TA0040")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(1)
        tactic_name = args.tactic
    
    # Determine technique ID
    if args.technique_id:
        technique_id = args.technique_id.upper()
        if not technique_id.startswith("SAFE-T"):
            technique_id = f"SAFE-T{technique_id.replace('SAFE-T', '').replace('T', '')}"
    else:
        technique_id = get_next_technique_id()
        print(f"Auto-detected next technique ID: {technique_id}")
    
    # Validate technique ID format
    if not technique_id.startswith("SAFE-T"):
        print(f"Error: Invalid technique ID format: {technique_id}")
        print("Expected format: SAFE-T[XXXX] where XXXX is a number")
        sys.exit(1)
    
    # Create the technique
    success = create_technique_directory(
        technique_id,
        args.name,
        args.tactic,
        tactic_name,
        args.author
    )
    
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()

