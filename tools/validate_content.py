#!/usr/bin/env python3
"""
SAFE-MCP Content Validator
Wrapper around validate_detection_rules.py with additional content validation
"""

import os
import sys
import subprocess
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Get repository root
REPO_ROOT = Path(__file__).parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
VALIDATOR_SCRIPT = TOOLS_DIR / "validate_detection_rules.py"

console = Console() if RICH_AVAILABLE else None


def run_detection_rule_validation():
    """Run the detection rule validator."""
    if not VALIDATOR_SCRIPT.exists():
        if RICH_AVAILABLE:
            console.print(f"[red]Error: Validator script not found: {VALIDATOR_SCRIPT}[/red]")
        else:
            print(f"Error: Validator script not found: {VALIDATOR_SCRIPT}")
        return 1
    
    if RICH_AVAILABLE:
        console.print("[bold cyan]Validating detection rules...[/bold cyan]\n")
    
    # Run the validator with --all flag
    try:
        result = subprocess.run(
            [sys.executable, str(VALIDATOR_SCRIPT), "--all"],
            cwd=str(REPO_ROOT),
            capture_output=False
        )
        return result.returncode
    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"[red]Error running validator: {e}[/red]")
        else:
            print(f"Error running validator: {e}")
        return 1


def check_readme_completeness():
    """Check if README files exist for all techniques and mitigations."""
    techniques_dir = REPO_ROOT / "techniques"
    mitigations_dir = REPO_ROOT / "mitigations"
    
    missing_readmes = []
    
    if RICH_AVAILABLE:
        console.print("\n[bold cyan]Checking README completeness...[/bold cyan]\n")
    else:
        print("\nChecking README completeness...\n")
    
    # Check techniques
    if techniques_dir.exists():
        for tech_dir in techniques_dir.iterdir():
            if tech_dir.is_dir() and tech_dir.name.startswith("SAFE-T"):
                readme = tech_dir / "README.md"
                if not readme.exists():
                    missing_readmes.append(("technique", tech_dir.name))
    
    # Check mitigations
    if mitigations_dir.exists():
        for mit_dir in mitigations_dir.iterdir():
            if mit_dir.is_dir() and mit_dir.name.startswith("SAFE-M-"):
                readme = mit_dir / "README.md"
                if not readme.exists():
                    missing_readmes.append(("mitigation", mit_dir.name))
    
    if missing_readmes:
        if RICH_AVAILABLE:
            console.print("[yellow]Missing README files:[/yellow]")
            for item_type, item_id in missing_readmes:
                console.print(f"  - {item_type}: {item_id}")
        else:
            print("Missing README files:")
            for item_type, item_id in missing_readmes:
                print(f"  - {item_type}: {item_id}")
        return len(missing_readmes)
    else:
        if RICH_AVAILABLE:
            console.print("[green]✓ All items have README files[/green]")
        else:
            print("✓ All items have README files")
        return 0


def main():
    """Main function."""
    if RICH_AVAILABLE:
        console.print("[bold cyan]SAFE-MCP Content Validator[/bold cyan]\n")
    else:
        print("SAFE-MCP Content Validator\n")
    
    errors = 0
    
    # Run detection rule validation
    result = run_detection_rule_validation()
    if result != 0:
        errors += 1
    
    # Check README completeness
    missing_count = check_readme_completeness()
    if missing_count > 0:
        errors += 1
    
    # Summary
    if RICH_AVAILABLE:
        console.print("\n" + "=" * 60)
        if errors == 0:
            console.print("[bold green]✓ All validations passed[/bold green]")
        else:
            console.print(f"[bold red]✗ Validation found {errors} issue(s)[/bold red]")
    else:
        print("\n" + "=" * 60)
        if errors == 0:
            print("✓ All validations passed")
        else:
            print(f"✗ Validation found {errors} issue(s)")
    
    if RICH_AVAILABLE:
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()
    else:
        input("\nPress Enter to continue...")
    
    return errors


if __name__ == "__main__":
    sys.exit(main())

