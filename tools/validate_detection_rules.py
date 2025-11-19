#!/usr/bin/env python3
"""
SAFE-MCP Detection Rule Validator

This script validates SAFE-MCP detection rule YAML files against
the framework's requirements and produces a detailed report.

Usage:
    python validate_detection_rules.py [path_to_rule.yml]
    python validate_detection_rules.py --all  # Validate all rules
    python validate_detection_rules.py --directory techniques/SAFE-T1001
"""

import argparse
import json
import re
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


# Get the repository root
REPO_ROOT = Path(__file__).parent.parent


class ValidationError:
    """Represents a validation error."""
    def __init__(self, field: str, message: str, severity: str = "error"):
        self.field = field
        self.message = message
        self.severity = severity  # error, warning, info
    
    def __str__(self):
        return f"[{self.severity.upper()}] {self.field}: {self.message}"


class DetectionRuleValidator:
    """Validates SAFE-MCP detection rule YAML files."""
    
    # Required fields
    REQUIRED_FIELDS = [
        "title",
        "id",
        "status",
        "description",
        "author",
        "date",
        "logsource",
        "detection",
        "level",
        "tags",
    ]
    
    # Optional but recommended fields
    RECOMMENDED_FIELDS = [
        "references",
    ]
    
    # Valid status values
    VALID_STATUS = ["experimental", "test", "stable", "deprecated"]
    
    # Valid level values
    VALID_LEVELS = ["low", "medium", "high", "critical"]
    
    # UUID regex pattern
    UUID_PATTERN = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    
    # Descriptive ID pattern (e.g., safe-t1105-path-traversal)
    DESCRIPTIVE_ID_PATTERN = re.compile(r'^[a-z0-9][a-z0-9-]*[a-z0-9]$', re.IGNORECASE)
    
    # Date format patterns (YYYY-MM-DD or YYYY/MM/DD)
    DATE_PATTERN_ISO = re.compile(r'^\d{4}-\d{2}-\d{2}$')
    DATE_PATTERN_SLASH = re.compile(r'^\d{4}/\d{2}/\d{2}$')
    
    def __init__(self, rule_path: Path):
        self.rule_path = rule_path
        self.errors: List[ValidationError] = []
        self.warnings: List[ValidationError] = []
        self.info: List[ValidationError] = []
        self.rule_data: Optional[Dict] = None
    
    def validate(self) -> Tuple[bool, List[ValidationError], List[ValidationError], List[ValidationError]]:
        """Validate the detection rule and return results."""
        # Load YAML file
        try:
            with open(self.rule_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Strip markdown code blocks if present
                # Handle cases where YAML is wrapped in markdown
                if '```' in content:
                    # Extract YAML from markdown code block
                    lines = content.split('\n')
                    yaml_lines = []
                    in_code_block = False
                    code_block_lang = None
                    for line in lines:
                        stripped_line = line.strip()
                        if stripped_line.startswith('```'):
                            if not in_code_block:
                                # Opening code block - extract language if present
                                code_block_lang = stripped_line[3:].strip()
                                in_code_block = True
                            else:
                                # Closing code block
                                in_code_block = False
                            continue
                        if in_code_block:
                            yaml_lines.append(line)
                    if yaml_lines:
                        content = '\n'.join(yaml_lines)
                
                # Also handle YAML frontmatter separator (but only if it's at the very start)
                # Don't remove --- if it's part of the actual YAML content
                content_stripped = content.strip()
                if content_stripped.startswith('---\n') or content_stripped == '---':
                    # Remove leading --- and any following blank lines
                    content = re.sub(r'^---\s*\n+', '', content, flags=re.MULTILINE)
                
                self.rule_data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            self.errors.append(ValidationError(
                "yaml_parse",
                f"Failed to parse YAML: {str(e)}"
            ))
            return False, self.errors, self.warnings, self.info
        except FileNotFoundError:
            self.errors.append(ValidationError(
                "file_not_found",
                f"File not found: {self.rule_path}"
            ))
            return False, self.errors, self.warnings, self.info
        
        if not self.rule_data:
            self.errors.append(ValidationError(
                "empty_file",
                "YAML file is empty or contains no data"
            ))
            return False, self.errors, self.warnings, self.info
        
        # Validate required fields
        self._validate_required_fields()
        
        # Validate field formats
        self._validate_field_formats()
        
        # Validate structure
        self._validate_structure()
        
        # Validate content
        self._validate_content()
        
        # Determine overall validity
        is_valid = len(self.errors) == 0
        
        return is_valid, self.errors, self.warnings, self.info
    
    def _validate_required_fields(self):
        """Check that all required fields are present."""
        for field in self.REQUIRED_FIELDS:
            if field not in self.rule_data:
                self.errors.append(ValidationError(
                    field,
                    f"Required field '{field}' is missing"
                ))
        
        # Check recommended fields
        for field in self.RECOMMENDED_FIELDS:
            if field not in self.rule_data:
                self.warnings.append(ValidationError(
                    field,
                    f"Recommended field '{field}' is missing",
                    "warning"
                ))
    
    def _validate_field_formats(self):
        """Validate the format of specific fields."""
        # Validate ID (UUID or descriptive format)
        if "id" in self.rule_data:
            id_value = str(self.rule_data["id"])
            is_uuid = self.UUID_PATTERN.match(id_value)
            is_descriptive = self.DESCRIPTIVE_ID_PATTERN.match(id_value)
            
            if not is_uuid and not is_descriptive:
                self.errors.append(ValidationError(
                    "id",
                    f"ID must be a valid UUID or descriptive format (e.g., safe-t1105-path-traversal), got: {id_value}"
                ))
        
        # Validate date format (accept both YYYY-MM-DD and YYYY/MM/DD)
        if "date" in self.rule_data:
            date_value = str(self.rule_data["date"])
            is_iso = self.DATE_PATTERN_ISO.match(date_value)
            is_slash = self.DATE_PATTERN_SLASH.match(date_value)
            
            if not is_iso and not is_slash:
                self.errors.append(ValidationError(
                    "date",
                    f"Date must be in YYYY-MM-DD or YYYY/MM/DD format, got: {date_value}"
                ))
            else:
                # Validate date is valid
                try:
                    if is_iso:
                        datetime.strptime(date_value, "%Y-%m-%d")
                    elif is_slash:
                        datetime.strptime(date_value, "%Y/%m/%d")
                except ValueError:
                    self.errors.append(ValidationError(
                        "date",
                        f"Invalid date: {date_value}"
                    ))
                else:
                    # Warn if using slash format (prefer ISO format)
                    if is_slash:
                        self.warnings.append(ValidationError(
                            "date",
                            f"Date uses YYYY/MM/DD format, consider using YYYY-MM-DD (ISO format) for consistency",
                            "warning"
                        ))
        
        # Validate status
        if "status" in self.rule_data:
            status = str(self.rule_data["status"]).lower()
            if status not in self.VALID_STATUS:
                self.errors.append(ValidationError(
                    "status",
                    f"Status must be one of {self.VALID_STATUS}, got: {status}"
                ))
        
        # Validate level
        if "level" in self.rule_data:
            level = str(self.rule_data["level"]).lower()
            if level not in self.VALID_LEVELS:
                self.errors.append(ValidationError(
                    "level",
                    f"Level must be one of {self.VALID_LEVELS}, got: {level}"
                ))
        
        # Validate references (should be a list)
        if "references" in self.rule_data:
            if not isinstance(self.rule_data["references"], list):
                self.errors.append(ValidationError(
                    "references",
                    "References must be a list"
                ))
            elif len(self.rule_data["references"]) == 0:
                self.warnings.append(ValidationError(
                    "references",
                    "References list is empty (should include at least the technique URL)",
                    "warning"
                ))
            else:
                # Check if technique reference is present
                technique_ref = None
                for ref in self.rule_data["references"]:
                    if "github.com/safe-mcp/techniques/" in str(ref):
                        technique_ref = ref
                        break
                
                if not technique_ref:
                    self.warnings.append(ValidationError(
                        "references",
                        "References should include a link to the technique (github.com/safe-mcp/techniques/SAFE-TXXXX)",
                        "warning"
                    ))
        
        # Validate tags (should be a list)
        if "tags" in self.rule_data:
            if not isinstance(self.rule_data["tags"], list):
                self.errors.append(ValidationError(
                    "tags",
                    "Tags must be a list"
                ))
            elif len(self.rule_data["tags"]) == 0:
                self.warnings.append(ValidationError(
                    "tags",
                    "Tags list is empty",
                    "warning"
                ))
            else:
                # Check for required tags
                tag_values = [str(tag).lower() for tag in self.rule_data["tags"]]
                has_attack_tag = any("attack." in tag for tag in tag_values)
                has_safe_tag = any("safe.t" in tag for tag in tag_values)
                
                if not has_attack_tag:
                    self.warnings.append(ValidationError(
                        "tags",
                        "Tags should include at least one 'attack.*' tag",
                        "warning"
                    ))
                
                if not has_safe_tag:
                    self.warnings.append(ValidationError(
                        "tags",
                        "Tags should include a 'safe.tXXXX' tag matching the technique",
                        "warning"
                    ))
    
    def _validate_structure(self):
        """Validate the structure of complex fields."""
        # Validate logsource
        if "logsource" in self.rule_data:
            logsource = self.rule_data["logsource"]
            if not isinstance(logsource, dict):
                self.errors.append(ValidationError(
                    "logsource",
                    "Logsource must be a dictionary/object"
                ))
            else:
                # Check for product field (recommended)
                if "product" not in logsource:
                    self.warnings.append(ValidationError(
                        "logsource.product",
                        "Logsource should include a 'product' field (e.g., 'mcp')",
                        "warning"
                    ))
        
        # Validate detection
        if "detection" in self.rule_data:
            detection = self.rule_data["detection"]
            if not isinstance(detection, dict):
                self.errors.append(ValidationError(
                    "detection",
                    "Detection must be a dictionary/object"
                ))
            else:
                # Check for condition
                if "condition" not in detection:
                    self.errors.append(ValidationError(
                        "detection.condition",
                        "Detection must include a 'condition' field"
                    ))
                else:
                    # Validate condition syntax
                    condition = str(detection["condition"])
                    # Check if condition references selections that exist
                    if "selection" in condition or "selection_" in condition:
                        # Extract selection names from condition
                        # Handle both simple names and names with modifiers (e.g., selection_1, selection_token_reuse)
                        selection_refs = re.findall(r'\b(selection[\w_]*)\b', condition)
                        for ref in set(selection_refs):  # Use set to avoid duplicate warnings
                            # Skip if it's part of a larger word or if it's just "selection" as a word
                            if ref == "selection" and "selection_" not in condition:
                                continue
                            if ref not in detection:
                                self.warnings.append(ValidationError(
                                    f"detection.condition",
                                    f"Condition references '{ref}' but it's not defined in detection",
                                    "warning"
                                ))
        
        # Validate falsepositives (optional but recommended)
        if "falsepositives" not in self.rule_data:
            self.info.append(ValidationError(
                "falsepositives",
                "Consider adding a 'falsepositives' field to document known false positive scenarios",
                "info"
            ))
        elif isinstance(self.rule_data["falsepositives"], list):
            if len(self.rule_data["falsepositives"]) == 0:
                self.info.append(ValidationError(
                    "falsepositives",
                    "False positives list is empty",
                    "info"
                ))
    
    def _validate_content(self):
        """Validate content quality and completeness."""
        # Check title length
        if "title" in self.rule_data:
            title = str(self.rule_data["title"])
            if len(title) < 10:
                self.warnings.append(ValidationError(
                    "title",
                    "Title seems too short (should be descriptive)",
                    "warning"
                ))
        
        # Check description length
        if "description" in self.rule_data:
            description = str(self.rule_data["description"])
            if len(description) < 50:
                self.warnings.append(ValidationError(
                    "description",
                    "Description seems too short (should be at least 50 characters)",
                    "warning"
                ))
        
        # Check if detection has actual patterns
        if "detection" in self.rule_data and isinstance(self.rule_data["detection"], dict):
            detection = self.rule_data["detection"]
            has_selections = any(
                key.startswith("selection") for key in detection.keys()
            )
            if not has_selections:
                self.warnings.append(ValidationError(
                    "detection",
                    "Detection should include at least one selection with patterns",
                    "warning"
                ))
    
    def generate_report(self) -> str:
        """Generate a formatted validation report."""
        is_valid, errors, warnings, info = self.validate()
        
        report_lines = [
            f"{'='*70}",
            f"Validation Report: {self.rule_path.name}",
            f"{'='*70}",
            f"",
            f"Status: {'✓ VALID' if is_valid else '✗ INVALID'}",
            f"",
        ]
        
        if errors:
            report_lines.extend([
                f"Errors ({len(errors)}):",
                "-" * 70,
            ])
            for error in errors:
                report_lines.append(f"  {error}")
            report_lines.append("")
        
        if warnings:
            report_lines.extend([
                f"Warnings ({len(warnings)}):",
                "-" * 70,
            ])
            for warning in warnings:
                report_lines.append(f"  {warning}")
            report_lines.append("")
        
        if info:
            report_lines.extend([
                f"Info ({len(info)}):",
                "-" * 70,
            ])
            for info_item in info:
                report_lines.append(f"  {info_item}")
            report_lines.append("")
        
        if is_valid and not warnings and not info:
            report_lines.append("✓ All checks passed!")
        
        report_lines.append("")
        report_lines.append("=" * 70)
        
        return "\n".join(report_lines)


def find_all_detection_rules(directory: Path) -> List[Path]:
    """Find all detection-rule.yml files in a directory."""
    rules = []
    if directory.is_file() and directory.name == "detection-rule.yml":
        return [directory]
    
    for path in directory.rglob("detection-rule.yml"):
        rules.append(path)
    
    return sorted(rules)


def main():
    parser = argparse.ArgumentParser(
        description="Validate SAFE-MCP detection rule YAML files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate a specific rule
  python validate_detection_rules.py techniques/SAFE-T1001/detection-rule.yml
  
  # Validate all rules in a directory
  python validate_detection_rules.py --directory techniques/
  
  # Validate all rules in repository
  python validate_detection_rules.py --all
  
  # Generate JSON report
  python validate_detection_rules.py --all --json report.json
        """
    )
    
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        help="Path to detection rule YAML file or directory"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Validate all detection rules in the repository"
    )
    parser.add_argument(
        "--directory",
        type=Path,
        help="Validate all rules in the specified directory"
    )
    parser.add_argument(
        "--json",
        type=Path,
        help="Output results as JSON to the specified file"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only show errors and warnings, suppress info messages"
    )
    
    args = parser.parse_args()
    
    # Determine which rules to validate
    rules_to_validate = []
    
    if args.all:
        rules_to_validate = find_all_detection_rules(REPO_ROOT)
    elif args.directory:
        rules_to_validate = find_all_detection_rules(args.directory)
    elif args.path:
        if args.path.is_file():
            rules_to_validate = [args.path]
        elif args.path.is_dir():
            rules_to_validate = find_all_detection_rules(args.path)
        else:
            print(f"Error: Path not found: {args.path}")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)
    
    if not rules_to_validate:
        print("No detection rules found to validate.")
        sys.exit(1)
    
    # Validate all rules
    results = []
    total_errors = 0
    total_warnings = 0
    
    for rule_path in rules_to_validate:
        validator = DetectionRuleValidator(rule_path)
        is_valid, errors, warnings, info = validator.validate()
        
        total_errors += len(errors)
        total_warnings += len(warnings)
        
        # Get relative path, handling cases where rule_path might not be under REPO_ROOT
        try:
            file_path = str(rule_path.relative_to(REPO_ROOT))
        except ValueError:
            # Path is not under REPO_ROOT, use absolute path or just filename
            file_path = str(rule_path)
        
        result = {
            "file": file_path,
            "valid": is_valid,
            "errors": [{"field": e.field, "message": e.message} for e in errors],
            "warnings": [{"field": w.field, "message": w.message} for w in warnings],
            "info": [{"field": i.field, "message": i.message} for i in info] if not args.quiet else [],
        }
        results.append(result)
        
        # Print report
        report = validator.generate_report()
        if not args.quiet or errors or warnings:
            print(report)
            print()
    
    # Summary
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    print(f"Total rules validated: {len(rules_to_validate)}")
    print(f"Valid rules: {sum(1 for r in results if r['valid'])}")
    print(f"Invalid rules: {sum(1 for r in results if not r['valid'])}")
    print(f"Total errors: {total_errors}")
    print(f"Total warnings: {total_warnings}")
    print("=" * 70)
    
    # Output JSON if requested
    if args.json:
        json_output = {
            "summary": {
                "total_rules": len(rules_to_validate),
                "valid_rules": sum(1 for r in results if r['valid']),
                "invalid_rules": sum(1 for r in results if not r['valid']),
                "total_errors": total_errors,
                "total_warnings": total_warnings,
            },
            "results": results,
        }
        with open(args.json, 'w') as f:
            json.dump(json_output, f, indent=2)
        print(f"\nJSON report written to: {args.json}")
    
    # Exit with error code if any validation failed
    if total_errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

