#!/usr/bin/env python3
"""
SAFE-MCP Content Search Tool
Full-text search across all techniques and mitigations
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Tuple, Dict

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


def get_all_readmes() -> List[Tuple[Path, str]]:
    """Get all README files with their type."""
    readmes = []
    
    # Get technique READMEs
    if TECHNIQUES_DIR.exists():
        for tech_dir in TECHNIQUES_DIR.iterdir():
            if tech_dir.is_dir() and tech_dir.name.startswith("SAFE-T"):
                readme = tech_dir / "README.md"
                if readme.exists():
                    readmes.append((readme, "technique"))
    
    # Get mitigation READMEs
    if MITIGATIONS_DIR.exists():
        for mit_dir in MITIGATIONS_DIR.iterdir():
            if mit_dir.is_dir() and mit_dir.name.startswith("SAFE-M-"):
                readme = mit_dir / "README.md"
                if readme.exists():
                    readmes.append((readme, "mitigation"))
    
    return readmes


def search_in_file(file_path: Path, query: str, case_sensitive: bool = False) -> List[Tuple[int, str]]:
    """Search for query in file and return matching lines with line numbers."""
    matches = []
    
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        lines = content.split('\n')
        
        flags = 0 if case_sensitive else re.IGNORECASE
        pattern = re.compile(re.escape(query), flags)
        
        for line_num, line in enumerate(lines, 1):
            if pattern.search(line):
                matches.append((line_num, line.strip()))
    
    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"[red]Error reading {file_path}: {e}[/red]")
        else:
            print(f"Error reading {file_path}: {e}")
    
    return matches


def extract_id_from_path(path: Path) -> str:
    """Extract ID from file path."""
    return path.parent.name


def extract_title_from_readme(path: Path) -> str:
    """Extract title from README."""
    try:
        first_line = path.read_text(encoding='utf-8', errors='ignore').split('\n')[0]
        if ':' in first_line:
            return first_line.split(':', 1)[1].strip()
        return first_line.strip()
    except:
        return path.name


def highlight_match(text: str, query: str, case_sensitive: bool = False) -> str:
    """Highlight matches in text."""
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = re.compile(re.escape(query), flags)
    
    if RICH_AVAILABLE:
        # Use rich Text for highlighting
        result = Text()
        last_end = 0
        for match in pattern.finditer(text):
            result.append(text[last_end:match.start()])
            result.append(text[match.start():match.end()], style="bold yellow on red")
            last_end = match.end()
        result.append(text[last_end:])
        return result
    else:
        # Simple highlighting with markers
        return pattern.sub(f"**{query}**", text)


def search_content(query: str, case_sensitive: bool = False, file_type: str = "all") -> List[Dict]:
    """Search across all content."""
    results = []
    readmes = get_all_readmes()
    
    for readme_path, readme_type in readmes:
        # Filter by type if specified
        if file_type != "all" and readme_type != file_type:
            continue
        
        matches = search_in_file(readme_path, query, case_sensitive)
        if matches:
            results.append({
                "path": readme_path,
                "type": readme_type,
                "id": extract_id_from_path(readme_path),
                "title": extract_title_from_readme(readme_path),
                "matches": matches
            })
    
    return results


def display_results(results: List[Dict], query: str, case_sensitive: bool = False):
    """Display search results."""
    if not results:
        if RICH_AVAILABLE:
            console.print(f"[yellow]No results found for '{query}'[/yellow]")
        else:
            print(f"No results found for '{query}'")
        return
    
    if RICH_AVAILABLE:
        console.print(f"\n[bold cyan]Found {len(results)} result(s) for '{query}'[/bold cyan]\n")
        
        for i, result in enumerate(results, 1):
            type_color = "blue" if result["type"] == "technique" else "green"
            console.print(f"[{type_color}][{result['type'].upper()}][/{type_color}] [bold]{result['id']}[/bold] - {result['title']}")
            console.print(f"  [dim]{result['path']}[/dim]")
            
            # Show first few matches
            for line_num, line in result['matches'][:3]:
                highlighted = highlight_match(line, query, case_sensitive)
                console.print(f"  [dim]Line {line_num}:[/dim] {highlighted}")
            
            if len(result['matches']) > 3:
                console.print(f"  [dim]... and {len(result['matches']) - 3} more match(es)[/dim]")
            console.print()
    else:
        print(f"\nFound {len(results)} result(s) for '{query}'\n")
        
        for i, result in enumerate(results, 1):
            print(f"[{result['type'].upper()}] {result['id']} - {result['title']}")
            print(f"  {result['path']}")
            
            # Show first few matches
            for line_num, line in result['matches'][:3]:
                highlighted = highlight_match(line, query, case_sensitive)
                print(f"  Line {line_num}: {highlighted}")
            
            if len(result['matches']) > 3:
                print(f"  ... and {len(result['matches']) - 3} more match(es)")
            print()


def main():
    """Main function."""
    if RICH_AVAILABLE:
        console.print("[bold cyan]SAFE-MCP Content Search[/bold cyan]\n")
    else:
        print("SAFE-MCP Content Search\n")
    
    while True:
        if RICH_AVAILABLE:
            query = Prompt.ask("Enter search query (or 'q' to quit)")
        else:
            query = input("Enter search query (or 'q' to quit): ").strip()
        
        if query.lower() == 'q':
            break
        
        if not query:
            continue
        
        # Ask for options
        if RICH_AVAILABLE:
            case_sensitive = Prompt.ask("Case sensitive?", choices=["y", "n"], default="n") == "y"
            file_type = Prompt.ask("Search in", choices=["all", "technique", "mitigation"], default="all")
        else:
            case_choice = input("Case sensitive? [n]: ").strip().lower() or "n"
            case_sensitive = case_choice == "y"
            file_type = input("Search in [all/technique/mitigation]: ").strip().lower() or "all"
        
        results = search_content(query, case_sensitive, file_type)
        display_results(results, query, case_sensitive)
        
        if RICH_AVAILABLE:
            console.print()


if __name__ == "__main__":
    main()

