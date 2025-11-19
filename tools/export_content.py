#!/usr/bin/env python3
"""
SAFE-MCP Export Tool
Export techniques/mitigations to various formats (JSON, CSV, Markdown)
"""

import json
import csv
import os
import re
import sys
from pathlib import Path
from typing import List, Dict

try:
    from rich.console import Console
    from rich.prompt import Prompt, Confirm
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


def extract_technique_data(readme_path: Path) -> Dict:
    """Extract data from technique README."""
    data = {
        "id": readme_path.parent.name,
        "name": "",
        "tactic": "",
        "severity": "",
        "description": ""
    }
    
    if not readme_path.exists():
        return data
    
    content = readme_path.read_text(encoding='utf-8', errors='ignore')
    
    # Extract name
    first_line = content.split('\n')[0]
    if ':' in first_line:
        data["name"] = first_line.split(':', 1)[1].strip()
    
    # Extract tactic
    tactic_match = re.search(r'\*\*Tactic\*\*:\s*(.+)', content)
    if tactic_match:
        data["tactic"] = tactic_match.group(1).strip()
    
    # Extract severity
    severity_match = re.search(r'\*\*Severity\*\*:\s*(.+)', content)
    if severity_match:
        data["severity"] = severity_match.group(1).strip()
    
    # Extract description
    desc_match = re.search(r'## Description\s*\n(.+?)(?:\n##|\n\n\n|$)', content, re.DOTALL)
    if desc_match:
        data["description"] = desc_match.group(1).strip()
    
    return data


def extract_mitigation_data(readme_path: Path) -> Dict:
    """Extract data from mitigation README."""
    data = {
        "id": readme_path.parent.name,
        "name": "",
        "category": "",
        "effectiveness": "",
        "description": ""
    }
    
    if not readme_path.exists():
        return data
    
    content = readme_path.read_text(encoding='utf-8', errors='ignore')
    
    # Extract name
    first_line = content.split('\n')[0]
    if ':' in first_line:
        data["name"] = first_line.split(':', 1)[1].strip()
    
    # Extract category
    category_match = re.search(r'\*\*Category\*\*:\s*(.+)', content)
    if category_match:
        data["category"] = category_match.group(1).strip()
    
    # Extract effectiveness
    eff_match = re.search(r'\*\*Effectiveness\*\*:\s*(.+)', content)
    if eff_match:
        data["effectiveness"] = eff_match.group(1).strip()
    
    # Extract description
    desc_match = re.search(r'## Description\s*\n(.+?)(?:\n##|\n\n\n|$)', content, re.DOTALL)
    if desc_match:
        data["description"] = desc_match.group(1).strip()
    
    return data


def export_json(output_path: Path, item_type: str):
    """Export to JSON format."""
    data = {"type": item_type, "items": []}
    
    if item_type == "techniques":
        techniques = get_techniques()
        for tech_dir in techniques:
            readme = tech_dir / "README.md"
            data["items"].append(extract_technique_data(readme))
    elif item_type == "mitigations":
        mitigations = get_mitigations()
        for mit_dir in mitigations:
            readme = mit_dir / "README.md"
            data["items"].append(extract_mitigation_data(readme))
    elif item_type == "all":
        techniques = get_techniques()
        mitigations = get_mitigations()
        data["techniques"] = [extract_technique_data(tech_dir / "README.md") for tech_dir in techniques]
        data["mitigations"] = [extract_mitigation_data(mit_dir / "README.md") for mit_dir in mitigations]
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    if RICH_AVAILABLE:
        console.print(f"[green]✓ Exported to {output_path}[/green]")
    else:
        print(f"✓ Exported to {output_path}")


def export_csv(output_path: Path, item_type: str):
    """Export to CSV format."""
    items = []
    
    if item_type == "techniques":
        techniques = get_techniques()
        for tech_dir in techniques:
            readme = tech_dir / "README.md"
            items.append(extract_technique_data(readme))
        fieldnames = ["id", "name", "tactic", "severity", "description"]
    elif item_type == "mitigations":
        mitigations = get_mitigations()
        for mit_dir in mitigations:
            readme = mit_dir / "README.md"
            items.append(extract_mitigation_data(readme))
        fieldnames = ["id", "name", "category", "effectiveness", "description"]
    else:
        if RICH_AVAILABLE:
            console.print("[red]CSV export only supports 'techniques' or 'mitigations'[/red]")
        else:
            print("CSV export only supports 'techniques' or 'mitigations'")
        return
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(items)
    
    if RICH_AVAILABLE:
        console.print(f"[green]✓ Exported to {output_path}[/green]")
    else:
        print(f"✓ Exported to {output_path}")


def export_markdown(output_path: Path, item_type: str):
    """Export to Markdown format."""
    lines = [f"# SAFE-MCP {item_type.title()} Export\n"]
    
    if item_type == "techniques":
        techniques = get_techniques()
        for tech_dir in techniques:
            readme = tech_dir / "README.md"
            if readme.exists():
                lines.append(f"\n## {readme.parent.name}\n")
                lines.append(readme.read_text(encoding='utf-8', errors='ignore'))
                lines.append("\n---\n")
    elif item_type == "mitigations":
        mitigations = get_mitigations()
        for mit_dir in mitigations:
            readme = mit_dir / "README.md"
            if readme.exists():
                lines.append(f"\n## {readme.parent.name}\n")
                lines.append(readme.read_text(encoding='utf-8', errors='ignore'))
                lines.append("\n---\n")
    elif item_type == "all":
        lines.append("\n# Techniques\n")
        techniques = get_techniques()
        for tech_dir in techniques:
            readme = tech_dir / "README.md"
            if readme.exists():
                lines.append(f"\n## {readme.parent.name}\n")
                lines.append(readme.read_text(encoding='utf-8', errors='ignore'))
                lines.append("\n---\n")
        
        lines.append("\n# Mitigations\n")
        mitigations = get_mitigations()
        for mit_dir in mitigations:
            readme = mit_dir / "README.md"
            if readme.exists():
                lines.append(f"\n## {readme.parent.name}\n")
                lines.append(readme.read_text(encoding='utf-8', errors='ignore'))
                lines.append("\n---\n")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    
    if RICH_AVAILABLE:
        console.print(f"[green]✓ Exported to {output_path}[/green]")
    else:
        print(f"✓ Exported to {output_path}")


def main():
    """Main function."""
    if RICH_AVAILABLE:
        console.print("[bold cyan]SAFE-MCP Export Tool[/bold cyan]\n")
    else:
        print("SAFE-MCP Export Tool\n")
    
    # Get export type
    if RICH_AVAILABLE:
        item_type = Prompt.ask(
            "Export",
            choices=["techniques", "mitigations", "all"],
            default="all"
        )
        format_type = Prompt.ask(
            "Format",
            choices=["json", "csv", "markdown"],
            default="json"
        )
        output_file = Prompt.ask("Output file path")
    else:
        item_type = input("Export [techniques/mitigations/all] [all]: ").strip() or "all"
        format_type = input("Format [json/csv/markdown] [json]: ").strip() or "json"
        output_file = input("Output file path: ").strip()
    
    if not output_file:
        if RICH_AVAILABLE:
            console.print("[red]Output file path is required[/red]")
        else:
            print("Output file path is required")
        return
    
    output_path = Path(output_file)
    
    # Confirm overwrite
    if output_path.exists():
        if RICH_AVAILABLE:
            if not Confirm.ask(f"File {output_path} exists. Overwrite?"):
                return
        else:
            response = input(f"File {output_path} exists. Overwrite? [y/N]: ").strip().lower()
            if response != 'y':
                return
    
    # Export
    if format_type == "json":
        export_json(output_path, item_type)
    elif format_type == "csv":
        export_csv(output_path, item_type)
    elif format_type == "markdown":
        export_markdown(output_path, item_type)
    
    if RICH_AVAILABLE:
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()
    else:
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()

