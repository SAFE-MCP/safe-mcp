#!/usr/bin/env python3
"""
SAFE-MCP Quick Reference Tool
Display quick reference cards for techniques and mitigations
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Get repository root
REPO_ROOT = Path(__file__).parent.parent
TECHNIQUES_DIR = REPO_ROOT / "techniques"
MITIGATIONS_DIR = REPO_ROOT / "mitigations"

console = Console() if RICH_AVAILABLE else None


def find_item(item_id: str) -> Optional[Path]:
    """Find a technique or mitigation by ID."""
    # Try technique first
    tech_path = TECHNIQUES_DIR / item_id / "README.md"
    if tech_path.exists():
        return tech_path
    
    # Try mitigation
    mit_path = MITIGATIONS_DIR / item_id / "README.md"
    if mit_path.exists():
        return mit_path
    
    return None


def extract_quick_info(readme_path: Path) -> Dict:
    """Extract quick reference information."""
    info = {
        "id": readme_path.parent.name,
        "name": "",
        "type": "technique" if "techniques" in str(readme_path) else "mitigation",
        "fields": {}
    }
    
    if not readme_path.exists():
        return info
    
    content = readme_path.read_text(encoding='utf-8', errors='ignore')
    
    # Extract name from first line
    first_line = content.split('\n')[0]
    if ':' in first_line:
        info["name"] = first_line.split(':', 1)[1].strip()
    
    # Extract all key-value pairs from Overview section
    overview_match = re.search(r'## Overview\s*\n(.*?)(?:\n##|\Z)', content, re.DOTALL)
    if overview_match:
        overview_text = overview_match.group(1)
        for match in re.finditer(r'\*\*([^*]+)\*\*:\s*(.+)', overview_text):
            field = match.group(1).strip()
            value = match.group(2).strip()
            info["fields"][field] = value
    
    # Extract description (first paragraph)
    desc_match = re.search(r'## Description\s*\n(.+?)(?:\n\n|\n##|$)', content, re.DOTALL)
    if desc_match:
        desc = desc_match.group(1).strip()
        # Take first sentence or first 200 chars
        if '.' in desc:
            info["description"] = desc.split('.')[0] + '.'
        else:
            info["description"] = desc[:200] + "..."
    
    return info


def display_quick_ref(info: Dict):
    """Display quick reference card."""
    if RICH_AVAILABLE:
        type_color = "blue" if info["type"] == "technique" else "green"
        type_label = "TECHNIQUE" if info["type"] == "technique" else "MITIGATION"
        
        # Build content
        content_lines = [f"[bold]{info['name']}[/bold]\n"]
        content_lines.append(f"[{type_color}]{type_label}[/{type_color}] - {info['id']}\n")
        
        # Add fields
        for field, value in info["fields"].items():
            content_lines.append(f"\n[bold yellow]{field}:[/bold yellow] {value}")
        
        # Add description
        if "description" in info:
            content_lines.append(f"\n[bold cyan]Description:[/bold cyan]")
            content_lines.append(info["description"])
        
        content = "\n".join(content_lines)
        
        panel = Panel(
            content,
            title=f"[bold]{info['id']}[/bold]",
            border_style=type_color,
            width=80
        )
        console.print(panel)
    else:
        type_label = "TECHNIQUE" if info["type"] == "technique" else "MITIGATION"
        print("\n" + "=" * 80)
        print(f"{type_label}: {info['id']}")
        print("=" * 80)
        print(f"Name: {info['name']}")
        print()
        for field, value in info["fields"].items():
            print(f"{field}: {value}")
        if "description" in info:
            print()
            print("Description:")
            print(info["description"])
        print("=" * 80)


def list_all_items():
    """List all available items."""
    techniques = []
    mitigations = []
    
    if TECHNIQUES_DIR.exists():
        for tech_dir in TECHNIQUES_DIR.iterdir():
            if tech_dir.is_dir() and tech_dir.name.startswith("SAFE-T"):
                readme = tech_dir / "README.md"
                if readme.exists():
                    info = extract_quick_info(readme)
                    techniques.append((info["id"], info["name"]))
    
    if MITIGATIONS_DIR.exists():
        for mit_dir in MITIGATIONS_DIR.iterdir():
            if mit_dir.is_dir() and mit_dir.name.startswith("SAFE-M-"):
                readme = mit_dir / "README.md"
                if readme.exists():
                    info = extract_quick_info(readme)
                    mitigations.append((info["id"], info["name"]))
    
    if RICH_AVAILABLE:
        if techniques:
            table = Table(title="Techniques", show_header=True, header_style="bold blue")
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="white")
            for item_id, name in techniques[:20]:  # Show first 20
                table.add_row(item_id, name[:60])
            if len(techniques) > 20:
                table.add_row("...", f"... and {len(techniques) - 20} more")
            console.print(table)
        
        if mitigations:
            table = Table(title="Mitigations", show_header=True, header_style="bold green")
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="white")
            for item_id, name in mitigations[:20]:  # Show first 20
                table.add_row(item_id, name[:60])
            if len(mitigations) > 20:
                table.add_row("...", f"... and {len(mitigations) - 20} more")
            console.print(table)
    else:
        if techniques:
            print("\nTechniques:")
            print("-" * 80)
            for item_id, name in techniques[:20]:
                print(f"  {item_id:<15} {name[:60]}")
            if len(techniques) > 20:
                print(f"  ... and {len(techniques) - 20} more")
        
        if mitigations:
            print("\nMitigations:")
            print("-" * 80)
            for item_id, name in mitigations[:20]:
                print(f"  {item_id:<15} {name[:60]}")
            if len(mitigations) > 20:
                print(f"  ... and {len(mitigations) - 20} more")


def main():
    """Main function."""
    if RICH_AVAILABLE:
        console.print("[bold cyan]SAFE-MCP Quick Reference[/bold cyan]\n")
    else:
        print("SAFE-MCP Quick Reference\n")
    
    while True:
        if RICH_AVAILABLE:
            choice = Prompt.ask(
                "Options",
                choices=["view", "list", "quit"],
                default="view"
            )
        else:
            choice = input("Options [view/list/quit] [view]: ").strip().lower() or "view"
        
        if choice == "quit":
            break
        elif choice == "list":
            list_all_items()
            print()
        elif choice == "view":
            if RICH_AVAILABLE:
                item_id = Prompt.ask("Enter item ID (technique or mitigation)")
            else:
                item_id = input("Enter item ID (technique or mitigation): ").strip()
            
            item_path = find_item(item_id)
            if not item_path:
                if RICH_AVAILABLE:
                    console.print(f"[red]Item not found: {item_id}[/red]")
                else:
                    print(f"Item not found: {item_id}")
            else:
                info = extract_quick_info(item_path)
                display_quick_ref(info)
                print()
        
        if RICH_AVAILABLE:
            console.print()


if __name__ == "__main__":
    main()

