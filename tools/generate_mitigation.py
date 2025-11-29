#!/usr/bin/env python3
"""
SAFE-MCP Mitigation Generator

This script generates a new SAFE-MCP mitigation directory structure with
all required files based on the template.

Usage:
    python generate_mitigation.py SAFE-M-[XXXX] "Mitigation Name" --category "Preventive Control"
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

# Get the repository root (parent of tools directory)
REPO_ROOT = Path(__file__).parent.parent
MITIGATIONS_DIR = REPO_ROOT / "mitigations"
TEMPLATE_DIR = MITIGATIONS_DIR / "TEMPLATE.md"


def get_next_mitigation_id():
    """Find the next available mitigation ID by scanning existing directories."""
    existing_ids = []
    if MITIGATIONS_DIR.exists():
        for item in MITIGATIONS_DIR.iterdir():
            if item.is_dir() and item.name.startswith("SAFE-M-"):
                try:
                    # Extract number from SAFE-M-XXXX
                    num = int(item.name.replace("SAFE-M-", ""))
                    existing_ids.append(num)
                except ValueError:
                    continue
    
    if existing_ids:
        next_id = max(existing_ids) + 1
    else:
        next_id = 1  # Start from 1 if no mitigations exist
    
    return f"SAFE-M-{next_id}"


def validate_category(category):
    """Validate mitigation category."""
    valid_categories = [
        "Architectural Defense",
        "Cryptographic Control",
        "AI-Based Defense",
        "Input Validation",
        "Supply Chain Security",
        "UI Security",
        "Isolation and Containment",
        "Detective Control",
        "Preventive Control",
        "Architectural Control",
        "Risk Management",
        "Data Security",
        "Human Factors",
    ]
    return category in valid_categories


def validate_effectiveness(effectiveness):
    """Validate effectiveness rating."""
    valid_ratings = ["High", "Medium-High", "Medium", "Low"]
    return effectiveness in valid_ratings


def validate_complexity(complexity):
    """Validate implementation complexity."""
    valid_complexities = ["High", "Medium", "Low"]
    return complexity in valid_complexities


def create_mitigation_directory(mitigation_id, mitigation_name, category, effectiveness, complexity, author):
    """Create a new mitigation directory with all required files."""
    
    mitigation_dir = MITIGATIONS_DIR / mitigation_id
    
    if mitigation_dir.exists():
        print(f"Error: Directory {mitigation_dir} already exists!")
        return False
    
    # Validate inputs
    if not validate_category(category):
        print(f"Error: Invalid category: {category}")
        print(f"Valid categories: {', '.join(['Architectural Defense', 'Cryptographic Control', 'AI-Based Defense', 'Input Validation', 'Supply Chain Security', 'UI Security', 'Isolation and Containment', 'Detective Control', 'Preventive Control', 'Architectural Control', 'Risk Management', 'Data Security', 'Human Factors'])}")
        return False
    
    if not validate_effectiveness(effectiveness):
        print(f"Error: Invalid effectiveness: {effectiveness}")
        print(f"Valid ratings: High, Medium-High, Medium, Low")
        return False
    
    if not validate_complexity(complexity):
        print(f"Error: Invalid complexity: {complexity}")
        print(f"Valid complexities: High, Medium, Low")
        return False
    
    # Create directory
    mitigation_dir.mkdir(parents=True, exist_ok=True)
    print(f"Created directory: {mitigation_dir}")
    
    # Read template
    if not TEMPLATE_DIR.exists():
        print(f"Error: Template not found at {TEMPLATE_DIR}")
        return False
    
    with open(TEMPLATE_DIR, 'r') as f:
        template = f.read()
    
    # Replace template placeholders
    today = datetime.now().strftime("%Y-%m-%d")
    replacements = {
        "SAFE-M-[XXXX]": mitigation_id,
        "[Mitigation Name]": mitigation_name,
        "[Category]": category,
        "[Effectiveness]": effectiveness,
        "[Implementation Complexity]": complexity,
        "[Date]": today,
        "[Author]": author,
        "[YYYY-MM-DD]": today,
    }
    
    content = template
    for placeholder, value in replacements.items():
        content = content.replace(placeholder, value)
    
    # Write README.md
    readme_path = mitigation_dir / "README.md"
    with open(readme_path, 'w') as f:
        f.write(content)
    print(f"Created: {readme_path}")
    
    print(f"\n✓ Successfully created mitigation {mitigation_id}: {mitigation_name}")
    print(f"\nNext steps:")
    print(f"1. Edit {readme_path} and fill in all required sections")
    print(f"2. Add techniques this mitigation addresses in the 'Mitigates' section")
    print(f"3. Review the checklist: {MITIGATIONS_DIR}/TEMPLATE-CHECKLIST.md")
    print(f"4. Update MITIGATIONS.md in repository root to add this mitigation to the table")
    print(f"5. Update relevant technique READMEs to reference this mitigation")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Generate a new SAFE-MCP mitigation directory structure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate with auto-detected next ID
  python generate_mitigation.py --name "Control/Data Flow Separation" --category "Architectural Defense" --effectiveness "High" --complexity "High" --author "Your Name"
  
  # Generate with specific ID
  python generate_mitigation.py SAFE-M-1 --name "Control/Data Flow Separation" --category "Architectural Defense" --effectiveness "High" --complexity "High" --author "Your Name"
        """
    )
    
    parser.add_argument(
        "mitigation_id",
        nargs="?",
        help="Mitigation ID (e.g., SAFE-M-1). If not provided, will auto-detect next available ID."
    )
    parser.add_argument(
        "--name",
        required=True,
        help="Mitigation name (e.g., 'Control/Data Flow Separation')"
    )
    parser.add_argument(
        "--category",
        required=True,
        help="Mitigation category (e.g., 'Preventive Control')"
    )
    parser.add_argument(
        "--effectiveness",
        required=True,
        choices=["High", "Medium-High", "Medium", "Low"],
        help="Effectiveness rating"
    )
    parser.add_argument(
        "--complexity",
        required=True,
        choices=["High", "Medium", "Low"],
        help="Implementation complexity"
    )
    parser.add_argument(
        "--author",
        default="SAFE-MCP Team",
        help="Author name (default: SAFE-MCP Team)"
    )
    
    args = parser.parse_args()
    
    # Determine mitigation ID
    if args.mitigation_id:
        mitigation_id = args.mitigation_id.upper()
        if not mitigation_id.startswith("SAFE-M-"):
            mitigation_id = f"SAFE-M-{mitigation_id.replace('SAFE-M-', '').replace('M-', '')}"
    else:
        mitigation_id = get_next_mitigation_id()
        print(f"Auto-detected next mitigation ID: {mitigation_id}")
    
    # Validate mitigation ID format
    if not mitigation_id.startswith("SAFE-M-"):
        print(f"Error: Invalid mitigation ID format: {mitigation_id}")
        print("Expected format: SAFE-M-[XXXX] where XXXX is a number")
        sys.exit(1)
    
    # Create the mitigation
    success = create_mitigation_directory(
        mitigation_id,
        args.name,
        args.category,
        args.effectiveness,
        args.complexity,
        args.author
    )
    
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()

