#!/usr/bin/env python3
"""
SAFE-MCP Comparison Tool
Compare two techniques or mitigations side-by-side
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
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


def extract_metadata(readme_path: Path) -> Dict:
    """Extract metadata from README."""
    metadata = {
        "id": readme_path.parent.name,
        "name": "",
        "type": "technique" if "techniques" in str(readme_path) else "mitigation",
        "fields": {}
    }
    
    if not readme_path.exists():
        return metadata
    
    content = readme_path.read_text(encoding='utf-8', errors='ignore')
    
    # Extract name from first line
    first_line = content.split('\n')[0]
    if ':' in first_line:
        metadata["name"] = first_line.split(':', 1)[1].strip()
    
    # Extract all key-value pairs from Overview section
    overview_match = re.search(r'## Overview\s*\n(.*?)(?:\n##|\Z)', content, re.DOTALL)
    if overview_match:
        overview_text = overview_match.group(1)
        # Match **Field**: Value patterns
        for match in re.finditer(r'\*\*([^*]+)\*\*:\s*(.+)', overview_text):
            field = match.group(1).strip()
            value = match.group(2).strip()
            metadata["fields"][field] = value
    
    # Extract description
    desc_match = re.search(r'## Description\s*\n(.+?)(?:\n##|\n\n\n|$)', content, re.DOTALL)
    if desc_match:
        metadata["description"] = desc_match.group(1).strip()[:500]
    
    return metadata


def compare_metadata(meta1: Dict, meta2: Dict):
    """Compare two metadata dictionaries."""
    if RICH_AVAILABLE:
        table = Table(title="Comparison", show_header=True, header_style="bold cyan")
        table.add_column("Field", style="yellow", width=20)
        table.add_column(f"{meta1['id']}", style="blue", width=30)
        table.add_column(f"{meta2['id']}", style="green", width=30)
        
        # Compare common fields
        all_fields = set(meta1["fields"].keys()) | set(meta2["fields"].keys())
        
        for field in sorted(all_fields):
            val1 = meta1["fields"].get(field, "N/A")
            val2 = meta2["fields"].get(field, "N/A")
            
            # Highlight differences
            if val1 != val2:
                style1 = "bold red"
                style2 = "bold red"
            else:
                style1 = "white"
                style2 = "white"
            
            table.add_row(field, Text(str(val1), style=style1), Text(str(val2), style=style2))
        
        console.print(table)
    else:
        print("\nComparison")
        print("=" * 80)
        print(f"{'Field':<20} {meta1['id']:<30} {meta2['id']:<30}")
        print("-" * 80)
        
        all_fields = set(meta1["fields"].keys()) | set(meta2["fields"].keys())
        for field in sorted(all_fields):
            val1 = meta1["fields"].get(field, "N/A")
            val2 = meta2["fields"].get(field, "N/A")
            marker = " *" if val1 != val2 else ""
            print(f"{field:<20} {str(val1)[:28]:<30} {str(val2)[:28]:<30}{marker}")
        
        print("\n* = Different values")


def main():
    """Main function."""
    if RICH_AVAILABLE:
        console.print("[bold cyan]SAFE-MCP Comparison Tool[/bold cyan]\n")
    else:
        print("SAFE-MCP Comparison Tool\n")
    
    # Get first item
    if RICH_AVAILABLE:
        item1_id = Prompt.ask("Enter first item ID (technique or mitigation)")
    else:
        item1_id = input("Enter first item ID (technique or mitigation): ").strip()
    
    item1_path = find_item(item1_id)
    if not item1_path:
        if RICH_AVAILABLE:
            console.print(f"[red]Item not found: {item1_id}[/red]")
        else:
            print(f"Item not found: {item1_id}")
        return
    
    # Get second item
    if RICH_AVAILABLE:
        item2_id = Prompt.ask("Enter second item ID (technique or mitigation)")
    else:
        item2_id = input("Enter second item ID (technique or mitigation): ").strip()
    
    item2_path = find_item(item2_id)
    if not item2_path:
        if RICH_AVAILABLE:
            console.print(f"[red]Item not found: {item2_id}[/red]")
        else:
            print(f"Item not found: {item2_id}")
        return
    
    # Extract metadata
    meta1 = extract_metadata(item1_path)
    meta2 = extract_metadata(item2_path)
    
    # Display comparison
    compare_metadata(meta1, meta2)
    
    if RICH_AVAILABLE:
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()
    else:
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()

