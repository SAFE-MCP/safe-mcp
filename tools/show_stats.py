#!/usr/bin/env python3
"""
SAFE-MCP Statistics Dashboard
Display summary statistics and coverage analysis
"""

import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import track
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


def extract_technique_stats(readme_path: Path) -> Dict:
    """Extract statistics from technique README."""
    stats = {
        "tactic": "Unknown",
        "severity": "Unknown",
        "has_detection_rule": False,
        "has_test": False
    }
    
    if not readme_path.exists():
        return stats
    
    content = readme_path.read_text(encoding='utf-8', errors='ignore')
    
    # Extract tactic
    tactic_match = re.search(r'\*\*Tactic\*\*:\s*(.+)', content)
    if tactic_match:
        stats["tactic"] = tactic_match.group(1).strip()
    
    # Extract severity
    severity_match = re.search(r'\*\*Severity\*\*:\s*(.+)', content)
    if severity_match:
        stats["severity"] = severity_match.group(1).strip()
    
    # Check for detection rule
    detection_rule = readme_path.parent / "detection-rule.yml"
    stats["has_detection_rule"] = detection_rule.exists()
    
    # Check for test file
    test_file = readme_path.parent / "test_detection_rule.py"
    stats["has_test"] = test_file.exists()
    
    return stats


def extract_mitigation_stats(readme_path: Path) -> Dict:
    """Extract statistics from mitigation README."""
    stats = {
        "category": "Unknown",
        "effectiveness": "Unknown"
    }
    
    if not readme_path.exists():
        return stats
    
    content = readme_path.read_text(encoding='utf-8', errors='ignore')
    
    # Extract category
    category_match = re.search(r'\*\*Category\*\*:\s*(.+)', content)
    if category_match:
        stats["category"] = category_match.group(1).strip()
    
    # Extract effectiveness
    eff_match = re.search(r'\*\*Effectiveness\*\*:\s*(.+)', content)
    if eff_match:
        eff_text = eff_match.group(1).strip()
        # Extract just the rating (e.g., "High" from "High (Provable Security)")
        stats["effectiveness"] = eff_text.split()[0] if eff_text else "Unknown"
    
    return stats


def collect_statistics():
    """Collect all statistics."""
    techniques = get_techniques()
    mitigations = get_mitigations()
    
    # Technique statistics
    tactic_counts = defaultdict(int)
    severity_counts = defaultdict(int)
    detection_rule_count = 0
    test_count = 0
    
    for tech_dir in techniques:
        readme = tech_dir / "README.md"
        stats = extract_technique_stats(readme)
        tactic_counts[stats["tactic"]] += 1
        severity_counts[stats["severity"]] += 1
        if stats["has_detection_rule"]:
            detection_rule_count += 1
        if stats["has_test"]:
            test_count += 1
    
    # Mitigation statistics
    category_counts = defaultdict(int)
    effectiveness_counts = defaultdict(int)
    
    for mit_dir in mitigations:
        readme = mit_dir / "README.md"
        stats = extract_mitigation_stats(readme)
        category_counts[stats["category"]] += 1
        effectiveness_counts[stats["effectiveness"]] += 1
    
    return {
        "total_techniques": len(techniques),
        "total_mitigations": len(mitigations),
        "tactic_counts": dict(tactic_counts),
        "severity_counts": dict(severity_counts),
        "detection_rule_count": detection_rule_count,
        "test_count": test_count,
        "category_counts": dict(category_counts),
        "effectiveness_counts": dict(effectiveness_counts)
    }


def display_summary(stats: Dict):
    """Display summary statistics."""
    if RICH_AVAILABLE:
        table = Table(title="Summary Statistics", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="white")
        table.add_column("Value", style="green", justify="right")
        
        table.add_row("Total Techniques", str(stats["total_techniques"]))
        table.add_row("Total Mitigations", str(stats["total_mitigations"]))
        table.add_row("Techniques with Detection Rules", str(stats["detection_rule_count"]))
        table.add_row("Techniques with Tests", str(stats["test_count"]))
        
        console.print(table)
    else:
        print("\nSummary Statistics")
        print("=" * 50)
        print(f"Total Techniques:           {stats['total_techniques']}")
        print(f"Total Mitigations:          {stats['total_mitigations']}")
        print(f"Techniques with Detection Rules: {stats['detection_rule_count']}")
        print(f"Techniques with Tests:      {stats['test_count']}")
        print("=" * 50)


def display_tactic_distribution(stats: Dict):
    """Display tactic distribution."""
    if RICH_AVAILABLE:
        table = Table(title="Technique Distribution by Tactic", show_header=True, header_style="bold cyan")
        table.add_column("Tactic", style="yellow")
        table.add_column("Count", style="green", justify="right")
        table.add_column("Percentage", style="cyan", justify="right")
        
        total = stats["total_techniques"]
        for tactic, count in sorted(stats["tactic_counts"].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            table.add_row(tactic, str(count), f"{percentage:.1f}%")
        
        console.print(table)
    else:
        print("\nTechnique Distribution by Tactic")
        print("=" * 60)
        print(f"{'Tactic':<40} {'Count':<10} {'Percentage':<10}")
        print("-" * 60)
        total = stats["total_techniques"]
        for tactic, count in sorted(stats["tactic_counts"].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            print(f"{tactic:<40} {count:<10} {percentage:>6.1f}%")


def display_severity_distribution(stats: Dict):
    """Display severity distribution."""
    if RICH_AVAILABLE:
        table = Table(title="Technique Distribution by Severity", show_header=True, header_style="bold cyan")
        table.add_column("Severity", style="red")
        table.add_column("Count", style="green", justify="right")
        table.add_column("Percentage", style="cyan", justify="right")
        
        total = stats["total_techniques"]
        severity_order = ["Critical", "High", "Medium", "Low", "Unknown"]
        for severity in severity_order:
            if severity in stats["severity_counts"]:
                count = stats["severity_counts"][severity]
                percentage = (count / total * 100) if total > 0 else 0
                table.add_row(severity, str(count), f"{percentage:.1f}%")
        
        console.print(table)
    else:
        print("\nTechnique Distribution by Severity")
        print("=" * 50)
        print(f"{'Severity':<20} {'Count':<10} {'Percentage':<10}")
        print("-" * 50)
        total = stats["total_techniques"]
        severity_order = ["Critical", "High", "Medium", "Low", "Unknown"]
        for severity in severity_order:
            if severity in stats["severity_counts"]:
                count = stats["severity_counts"][severity]
                percentage = (count / total * 100) if total > 0 else 0
                print(f"{severity:<20} {count:<10} {percentage:>6.1f}%")


def display_category_distribution(stats: Dict):
    """Display mitigation category distribution."""
    if RICH_AVAILABLE:
        table = Table(title="Mitigation Distribution by Category", show_header=True, header_style="bold cyan")
        table.add_column("Category", style="yellow")
        table.add_column("Count", style="green", justify="right")
        table.add_column("Percentage", style="cyan", justify="right")
        
        total = stats["total_mitigations"]
        for category, count in sorted(stats["category_counts"].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            table.add_row(category, str(count), f"{percentage:.1f}%")
        
        console.print(table)
    else:
        print("\nMitigation Distribution by Category")
        print("=" * 60)
        print(f"{'Category':<40} {'Count':<10} {'Percentage':<10}")
        print("-" * 60)
        total = stats["total_mitigations"]
        for category, count in sorted(stats["category_counts"].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            print(f"{category:<40} {count:<10} {percentage:>6.1f}%")


def display_effectiveness_distribution(stats: Dict):
    """Display effectiveness distribution."""
    if RICH_AVAILABLE:
        table = Table(title="Mitigation Distribution by Effectiveness", show_header=True, header_style="bold cyan")
        table.add_column("Effectiveness", style="green")
        table.add_column("Count", style="green", justify="right")
        table.add_column("Percentage", style="cyan", justify="right")
        
        total = stats["total_mitigations"]
        eff_order = ["High", "Medium-High", "Medium", "Low", "Unknown"]
        for eff in eff_order:
            if eff in stats["effectiveness_counts"]:
                count = stats["effectiveness_counts"][eff]
                percentage = (count / total * 100) if total > 0 else 0
                table.add_row(eff, str(count), f"{percentage:.1f}%")
        
        console.print(table)
    else:
        print("\nMitigation Distribution by Effectiveness")
        print("=" * 50)
        print(f"{'Effectiveness':<20} {'Count':<10} {'Percentage':<10}")
        print("-" * 50)
        total = stats["total_mitigations"]
        eff_order = ["High", "Medium-High", "Medium", "Low", "Unknown"]
        for eff in eff_order:
            if eff in stats["effectiveness_counts"]:
                count = stats["effectiveness_counts"][eff]
                percentage = (count / total * 100) if total > 0 else 0
                print(f"{eff:<20} {count:<10} {percentage:>6.1f}%")


def main():
    """Main function."""
    if RICH_AVAILABLE:
        console.print("[bold cyan]Collecting statistics...[/bold cyan]")
    else:
        print("Collecting statistics...")
    
    stats = collect_statistics()
    
    if RICH_AVAILABLE:
        console.print("\n")
    
    display_summary(stats)
    print()
    display_tactic_distribution(stats)
    print()
    display_severity_distribution(stats)
    print()
    display_category_distribution(stats)
    print()
    display_effectiveness_distribution(stats)
    
    if RICH_AVAILABLE:
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()
    else:
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()

