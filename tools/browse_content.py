#!/usr/bin/env python3
"""
SAFE-MCP Content Browser
Interactive browser for viewing techniques and mitigations
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple

try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, IntPrompt
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Get repository root
REPO_ROOT = Path(__file__).parent.parent
TECHNIQUES_DIR = REPO_ROOT / "techniques"
MITIGATIONS_DIR = REPO_ROOT / "mitigations"

console = Console() if RICH_AVAILABLE else None


def get_techniques() -> List[Path]:
    """Get all technique directories."""
    if not TECHNIQUES_DIR.exists():
        return []
    return sorted([d for d in TECHNIQUES_DIR.iterdir() if d.is_dir() and d.name.startswith("SAFE-T")])


def get_mitigations() -> List[Path]:
    """Get all mitigation directories."""
    if not MITIGATIONS_DIR.exists():
        return []
    return sorted([d for d in MITIGATIONS_DIR.iterdir() if d.is_dir() and d.name.startswith("SAFE-M-")])


def extract_technique_info(readme_path: Path) -> dict:
    """Extract key information from technique README."""
    info = {
        "id": readme_path.parent.name,
        "name": "",
        "tactic": "",
        "severity": "",
        "description": ""
    }
    
    if not readme_path.exists():
        return info
    
    content = readme_path.read_text(encoding='utf-8', errors='ignore')
    
    # Extract name from first line
    first_line = content.split('\n')[0]
    if ':' in first_line:
        info["name"] = first_line.split(':', 1)[1].strip()
    
    # Extract tactic
    tactic_match = re.search(r'\*\*Tactic\*\*:\s*(.+)', content)
    if tactic_match:
        info["tactic"] = tactic_match.group(1).strip()
    
    # Extract severity
    severity_match = re.search(r'\*\*Severity\*\*:\s*(.+)', content)
    if severity_match:
        info["severity"] = severity_match.group(1).strip()
    
    # Extract description (first paragraph after Description header)
    desc_match = re.search(r'## Description\s*\n(.+?)(?:\n##|\n\n\n|$)', content, re.DOTALL)
    if desc_match:
        info["description"] = desc_match.group(1).strip()[:200] + "..."
    
    return info


def extract_mitigation_info(readme_path: Path) -> dict:
    """Extract key information from mitigation README."""
    info = {
        "id": readme_path.parent.name,
        "name": "",
        "category": "",
        "effectiveness": "",
        "description": ""
    }
    
    if not readme_path.exists():
        return info
    
    content = readme_path.read_text(encoding='utf-8', errors='ignore')
    
    # Extract name from first line
    first_line = content.split('\n')[0]
    if ':' in first_line:
        info["name"] = first_line.split(':', 1)[1].strip()
    
    # Extract category
    category_match = re.search(r'\*\*Category\*\*:\s*(.+)', content)
    if category_match:
        info["category"] = category_match.group(1).strip()
    
    # Extract effectiveness
    eff_match = re.search(r'\*\*Effectiveness\*\*:\s*(.+)', content)
    if eff_match:
        info["effectiveness"] = eff_match.group(1).strip()
    
    # Extract description
    desc_match = re.search(r'## Description\s*\n(.+?)(?:\n##|\n\n\n|$)', content, re.DOTALL)
    if desc_match:
        info["description"] = desc_match.group(1).strip()[:200] + "..."
    
    return info


def display_technique_list(techniques: List[Path]):
    """Display list of techniques."""
    if RICH_AVAILABLE:
        table = Table(title="SAFE-MCP Techniques", show_header=True, header_style="bold cyan")
        table.add_column("ID", style="cyan", width=12)
        table.add_column("Name", style="white", width=40)
        table.add_column("Tactic", style="yellow", width=25)
        table.add_column("Severity", style="red", width=10)
        
        for tech_dir in techniques:
            readme = tech_dir / "README.md"
            info = extract_technique_info(readme)
            table.add_row(
                info["id"],
                info["name"][:38],
                info["tactic"][:23],
                info["severity"]
            )
        
        console.print(table)
    else:
        print("\nSAFE-MCP Techniques")
        print("=" * 80)
        print(f"{'ID':<12} {'Name':<40} {'Tactic':<25} {'Severity':<10}")
        print("-" * 80)
        for tech_dir in techniques:
            readme = tech_dir / "README.md"
            info = extract_technique_info(readme)
            print(f"{info['id']:<12} {info['name'][:38]:<40} {info['tactic'][:23]:<25} {info['severity']:<10}")


def display_mitigation_list(mitigations: List[Path]):
    """Display list of mitigations."""
    if RICH_AVAILABLE:
        table = Table(title="SAFE-MCP Mitigations", show_header=True, header_style="bold cyan")
        table.add_column("ID", style="cyan", width=12)
        table.add_column("Name", style="white", width=40)
        table.add_column("Category", style="yellow", width=25)
        table.add_column("Effectiveness", style="green", width=15)
        
        for mit_dir in mitigations:
            readme = mit_dir / "README.md"
            info = extract_mitigation_info(readme)
            table.add_row(
                info["id"],
                info["name"][:38],
                info["category"][:23],
                info["effectiveness"]
            )
        
        console.print(table)
    else:
        print("\nSAFE-MCP Mitigations")
        print("=" * 80)
        print(f"{'ID':<12} {'Name':<40} {'Category':<25} {'Effectiveness':<15}")
        print("-" * 80)
        for mit_dir in mitigations:
            readme = mit_dir / "README.md"
            info = extract_mitigation_info(readme)
            print(f"{info['id']:<12} {info['name'][:38]:<40} {info['category'][:23]:<25} {info['effectiveness']:<15}")


def view_readme(readme_path: Path):
    """View README content."""
    if not readme_path.exists():
        if RICH_AVAILABLE:
            console.print(f"[red]Error:[/red] File not found: {readme_path}")
        else:
            print(f"Error: File not found: {readme_path}")
        return
    
    content = readme_path.read_text(encoding='utf-8', errors='ignore')
    
    if RICH_AVAILABLE:
        console.print(Panel(Markdown(content), title=str(readme_path.name), border_style="cyan"))
    else:
        print("\n" + "=" * 80)
        print(readme_path.name)
        print("=" * 80)
        print(content)
        print("=" * 80)


def browse_techniques():
    """Browse techniques interactively."""
    techniques = get_techniques()
    if not techniques:
        if RICH_AVAILABLE:
            console.print("[yellow]No techniques found[/yellow]")
        else:
            print("No techniques found")
        return
    
    while True:
        display_technique_list(techniques)
        
        if RICH_AVAILABLE:
            choice = Prompt.ask(
                "\nEnter technique ID to view, 'b' to go back, or 'q' to quit",
                default="b"
            )
        else:
            choice = input("\nEnter technique ID to view, 'b' to go back, or 'q' to quit [b]: ").strip() or "b"
        
        if choice.lower() == 'q':
            return
        elif choice.lower() == 'b':
            break
        
        # Find matching technique
        selected = None
        for tech_dir in techniques:
            if tech_dir.name.upper() == choice.upper() or tech_dir.name.upper().startswith(choice.upper()):
                selected = tech_dir
                break
        
        if selected:
            readme = selected / "README.md"
            view_readme(readme)
            if RICH_AVAILABLE:
                Prompt.ask("\nPress Enter to continue", default="")
            else:
                input("\nPress Enter to continue")
        else:
            if RICH_AVAILABLE:
                console.print(f"[red]Technique not found: {choice}[/red]")
            else:
                print(f"Technique not found: {choice}")


def browse_mitigations():
    """Browse mitigations interactively."""
    mitigations = get_mitigations()
    if not mitigations:
        if RICH_AVAILABLE:
            console.print("[yellow]No mitigations found[/yellow]")
        else:
            print("No mitigations found")
        return
    
    while True:
        display_mitigation_list(mitigations)
        
        if RICH_AVAILABLE:
            choice = Prompt.ask(
                "\nEnter mitigation ID to view, 'b' to go back, or 'q' to quit",
                default="b"
            )
        else:
            choice = input("\nEnter mitigation ID to view, 'b' to go back, or 'q' to quit [b]: ").strip() or "b"
        
        if choice.lower() == 'q':
            return
        elif choice.lower() == 'b':
            break
        
        # Find matching mitigation
        selected = None
        for mit_dir in mitigations:
            if mit_dir.name.upper() == choice.upper() or mit_dir.name.upper().startswith(choice.upper()):
                selected = mit_dir
                break
        
        if selected:
            readme = selected / "README.md"
            view_readme(readme)
            if RICH_AVAILABLE:
                Prompt.ask("\nPress Enter to continue", default="")
            else:
                input("\nPress Enter to continue")
        else:
            if RICH_AVAILABLE:
                console.print(f"[red]Mitigation not found: {choice}[/red]")
            else:
                print(f"Mitigation not found: {choice}")


def main():
    """Main menu."""
    while True:
        if RICH_AVAILABLE:
            console.print("\n[bold cyan]SAFE-MCP Content Browser[/bold cyan]")
            console.print("1. Browse Techniques")
            console.print("2. Browse Mitigations")
            console.print("3. Quit")
            choice = Prompt.ask("\nSelect an option", choices=["1", "2", "3"], default="3")
        else:
            print("\nSAFE-MCP Content Browser")
            print("1. Browse Techniques")
            print("2. Browse Mitigations")
            print("3. Quit")
            choice = input("\nSelect an option [3]: ").strip() or "3"
        
        if choice == "1":
            browse_techniques()
        elif choice == "2":
            browse_mitigations()
        elif choice == "3":
            break


if __name__ == "__main__":
    main()

