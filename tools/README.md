# SAFE-MCP Tools

This directory contains utility scripts for working with SAFE-MCP techniques and mitigations.

## Tools

### 1. `generate_technique.py`

Generates a new SAFE-MCP technique directory structure with all required files based on the template.

**Usage:**

```bash
# Generate with auto-detected next ID
python generate_technique.py --name "Tool Poisoning Attack" --tactic ATK-TA0001 --author "Your Name"

# Generate with specific ID
python generate_technique.py SAFE-T1001 --name "Tool Poisoning Attack" --tactic ATK-TA0001 --author "Your Name"
```

**Options:**
- `technique_id` (optional): Technique ID (e.g., SAFE-T1001). If not provided, will auto-detect next available ID.
- `--name` (required): Technique name (e.g., "Tool Poisoning Attack")
- `--tactic` (required): Tactic ID (e.g., ATK-TA0001)
- `--author` (optional): Author name (default: "SAFE-MCP Team")

**What it creates:**
- `techniques/SAFE-T[XXXX]/README.md` - Main documentation file (from template)
- `techniques/SAFE-T[XXXX]/detection-rule.yml` - Detection rule template
- `techniques/SAFE-T[XXXX]/test-logs.json` - Empty test logs file

**Example:**

```bash
python generate_technique.py --name "Server Impersonation" --tactic ATK-TA0001 --author "John Doe"
# Creates: techniques/SAFE-T1002/ with all required files
```

---

### 2. `generate_mitigation.py`

Generates a new SAFE-MCP mitigation directory structure with all required files based on the template.

**Usage:**

```bash
# Generate with auto-detected next ID
python generate_mitigation.py --name "Control/Data Flow Separation" --category "Architectural Defense" --effectiveness "High" --complexity "High" --author "Your Name"

# Generate with specific ID
python generate_mitigation.py SAFE-M-1 --name "Control/Data Flow Separation" --category "Architectural Defense" --effectiveness "High" --complexity "High" --author "Your Name"
```

**Options:**
- `mitigation_id` (optional): Mitigation ID (e.g., SAFE-M-1). If not provided, will auto-detect next available ID.
- `--name` (required): Mitigation name
- `--category` (required): Mitigation category (see valid categories below)
- `--effectiveness` (required): Effectiveness rating (High, Medium-High, Medium, Low)
- `--complexity` (required): Implementation complexity (High, Medium, Low)
- `--author` (optional): Author name (default: "SAFE-MCP Team")

**Valid Categories:**
- Architectural Defense
- Cryptographic Control
- AI-Based Defense
- Input Validation
- Supply Chain Security
- UI Security
- Isolation and Containment
- Detective Control
- Preventive Control
- Architectural Control
- Risk Management
- Data Security
- Human Factors

**What it creates:**
- `mitigations/SAFE-M-[XXXX]/README.md` - Main documentation file (from template)

**Example:**

```bash
python generate_mitigation.py --name "Tool Registry Verification" --category "Supply Chain Security" --effectiveness "High" --complexity "Medium" --author "Jane Smith"
# Creates: mitigations/SAFE-M-6/ with README.md
```

---

### 3. `validate_detection_rules.py`

Validates SAFE-MCP detection rule YAML files against the framework's requirements and produces a detailed report.

**Prerequisites:**

```bash
pip install pyyaml
```

**Usage:**

```bash
# Validate a specific rule
python validate_detection_rules.py techniques/SAFE-T1001/detection-rule.yml

# Validate all rules in a directory
python validate_detection_rules.py --directory techniques/

# Validate all rules in repository
python validate_detection_rules.py --all

# Generate JSON report
python validate_detection_rules.py --all --json report.json

# Quiet mode (only errors and warnings)
python validate_detection_rules.py --all --quiet
```

**Options:**
- `path` (optional): Path to detection rule YAML file or directory
- `--all`: Validate all detection rules in the repository
- `--directory PATH`: Validate all rules in the specified directory
- `--json PATH`: Output results as JSON to the specified file
- `--quiet`: Only show errors and warnings, suppress info messages

**What it validates:**

1. **Required Fields:**
   - title, id, status, description, author, date
   - references, logsource, detection, level, tags

2. **Field Formats:**
   - ID must be a valid UUID
   - Date must be in YYYY-MM-DD format
   - Status must be one of: experimental, test, stable, deprecated
   - Level must be one of: low, medium, high, critical

3. **Structure:**
   - logsource must be a dictionary
   - detection must be a dictionary with a condition
   - references must be a list
   - tags must be a list

4. **Content Quality:**
   - References should include technique URL
   - Tags should include attack.* and safe.tXXXX tags
   - Detection should have selection patterns
   - Description should be descriptive (>= 50 chars)

**Example Output:**

```
======================================================================
Validation Report: detection-rule.yml
======================================================================

Status: ✓ VALID

Warnings (2):
----------------------------------------------------------------------
  [WARNING] references: References should include a link to the technique (github.com/safe-mcp/techniques/SAFE-TXXXX)
  [WARNING] tags: Tags should include a 'safe.tXXXX' tag matching the technique

Info (1):
----------------------------------------------------------------------
  [INFO] falsepositives: Consider adding a 'falsepositives' field to document known false positive scenarios

======================================================================
Summary
======================================================================
Total rules validated: 35
Valid rules: 33
Invalid rules: 2
Total errors: 5
Total warnings: 12
======================================================================
```

**Exit Codes:**
- `0`: All validations passed (may have warnings/info)
- `1`: One or more validation errors found

---

## Interactive Menu System

The SAFE-MCP Interactive Menu System provides a user-friendly, cross-platform interface for navigating and using all SAFE-MCP tools.

### Quick Start

```bash
# From the repository root
./tools/safe-mcp-menu.sh

# Or from anywhere
cd /path/to/safe-mcp
bash tools/safe-mcp-menu.sh
```

### Features

- **Cross-Platform**: Works on macOS, Linux, and Windows (Cygwin)
- **Interactive Navigation**: Easy-to-use menu interface
- **Color-Coded Output**: Enhanced readability with terminal colors
- **Integrated Tools**: Access all SAFE-MCP tools from one place

### Menu Options

1. **Browse Techniques & Mitigations** - Navigate and view content
2. **View Statistics Dashboard** - See summary statistics and distributions
3. **Search Content** - Full-text search across all content
4. **Quick Reference** - Display quick reference cards
5. **Compare Items** - Compare techniques or mitigations side-by-side
6. **Validate Content** - Validate detection rules and content
7. **Test Detection Rules** - Run tests on detection rules
8. **Export Content** - Export to JSON, CSV, or Markdown
9. **Generate New Technique** - Create new technique structure
10. **Generate New Mitigation** - Create new mitigation structure
11. **Scaffold Missing Technique Files** - Generate missing files (detection-rule.yml, tests, pseudocode) for existing techniques
12. **Test Scaffold Generator** - Test and validate the scaffolding generator against CONTRIBUTOR_GUIDE.md requirements

---

## Interactive Tools

### 4. `browse_content.py`

Interactive browser for viewing techniques and mitigations with formatted output.

**Usage:**

```bash
# Run directly
python tools/browse_content.py

# Or through menu
./tools/safe-mcp-menu.sh  # Select option 1
```

**Features:**
- Browse all techniques with key information (ID, name, tactic, severity)
- Browse all mitigations with key information (ID, name, category, effectiveness)
- View full README content for any item
- Navigate between items easily

**Output:**
- Rich formatted tables (if `rich` library is installed)
- Plain text tables (fallback)
- Full markdown rendering of README files

---

### 5. `show_stats.py`

Statistics dashboard showing summary statistics, distributions, and coverage analysis.

**Usage:**

```bash
# Run directly
python tools/show_stats.py

# Or through menu
./tools/safe-mcp-menu.sh  # Select option 2
```

**Features:**
- Summary statistics (total techniques, mitigations, etc.)
- Technique distribution by tactic
- Technique distribution by severity
- Mitigation distribution by category
- Mitigation distribution by effectiveness
- Detection rule and test coverage

**Output:**
- Formatted tables with percentages
- ASCII charts and distributions
- Coverage metrics

---

### 6. `search_content.py`

Full-text search tool across all techniques and mitigations.

**Usage:**

```bash
# Run directly
python tools/search_content.py

# Or through menu
./tools/safe-mcp-menu.sh  # Select option 3
```

**Features:**
- Full-text search across all README files
- Case-sensitive or case-insensitive search
- Filter by type (techniques, mitigations, or all)
- Highlighted search results with line numbers
- Shows context around matches

**Example:**

```
Enter search query: prompt injection
Case sensitive? [n]: n
Search in [all/technique/mitigation]: all

Found 5 result(s) for 'prompt injection'
...
```

---

### 7. `quick_ref.py`

Display quick reference cards for techniques and mitigations.

**Usage:**

```bash
# Run directly
python tools/quick_ref.py

# Or through menu
./tools/safe-mcp-menu.sh  # Select option 4
```

**Features:**
- View quick reference cards by ID
- List all available techniques and mitigations
- Extract key metadata (tactic, severity, category, effectiveness)
- Compact, readable format

**Example:**

```
Enter item ID: SAFE-T1001
[TECHNIQUE] SAFE-T1001 - Tool Poisoning Attack (TPA)
Tactic: Initial Access (ATK-TA0001)
Severity: Critical
...
```

---

### 8. `compare_items.py`

Compare two techniques or mitigations side-by-side.

**Usage:**

```bash
# Run directly
python tools/compare_items.py

# Or through menu
./tools/safe-mcp-menu.sh  # Select option 5
```

**Features:**
- Compare any two techniques or mitigations
- Side-by-side comparison of metadata
- Highlights differences
- Works across types (can compare technique to mitigation)

**Example:**

```
Enter first item ID: SAFE-T1001
Enter second item ID: SAFE-T1002

Comparison:
Field              SAFE-T1001              SAFE-T1002
Tactic             Initial Access          Initial Access
Severity           Critical                High *
...
* = Different values
```

---

### 9. `validate_content.py`

Comprehensive content validation wrapper.

**Usage:**

```bash
# Run directly
python tools/validate_content.py

# Or through menu
./tools/safe-mcp-menu.sh  # Select option 6
```

**Features:**
- Validates all detection rules (uses `validate_detection_rules.py`)
- Checks README completeness
- Verifies all techniques and mitigations have README files
- Generates summary report

**Output:**
- Validation results for detection rules
- List of missing README files
- Summary of issues found

---

### 10. `run_tests.sh`

Test runner that executes all `test_detection_rule.py` scripts and aggregates results.

**Usage:**

```bash
# Run directly
bash tools/run_tests.sh

# Or through menu
./tools/safe-mcp-menu.sh  # Select option 7
```

**Features:**
- Finds all test files in technique directories
- Runs each test script
- Aggregates results
- Shows passed/failed tests
- Displays error output for failed tests

**Output:**

```
SAFE-MCP Detection Rule Test Runner

Found 15 test file(s)

Running tests for SAFE-T1001...
✓ SAFE-T1001: All tests passed

Test Summary:
Total test files:  15
Passed:            14
Failed:            1
```

---

### 11. `export_content.py`

Export techniques and mitigations to various formats.

**Usage:**

```bash
# Run directly
python tools/export_content.py

# Or through menu
./tools/safe-mcp-menu.sh  # Select option 8
```

**Features:**
- Export to JSON format
- Export to CSV format
- Export to Markdown format
- Filter by type (techniques, mitigations, or all)
- Preserves metadata and structure

**Formats:**

- **JSON**: Structured data with all metadata
- **CSV**: Tabular format for spreadsheet analysis
- **Markdown**: Full README content concatenated

**Example:**

```bash
Export [techniques/mitigations/all] [all]: all
Format [json/csv/markdown] [json]: json
Output file path: safe-mcp-export.json
✓ Exported to safe-mcp-export.json
```

---

### 12. `generate_technique_scaffold.py`

Generate missing files for existing SAFE-MCP techniques that have README.md but are missing detection rules, test files, or pseudocode examples.

**Usage:**

```bash
# Generate for a specific technique
python tools/generate_technique_scaffold.py --technique SAFE-T1103

# Generate for all techniques missing detection rules
python tools/generate_technique_scaffold.py --all

# Dry run to see what would be generated
python tools/generate_technique_scaffold.py --all --dry-run

# Generate and validate
python tools/generate_technique_scaffold.py --all --validate

# Or through menu
./tools/safe-mcp-menu.sh  # Select option 11
```

**Features:**
- Automatically extracts technique information from README.md
- Generates Sigma-format detection rules with appropriate patterns
- Creates test data files (test-logs.json)
- Generates test validation scripts (test_detection_rule.py)
- Creates pseudocode examples showing attack flows
- Validates generated detection rules automatically
- Supports dry-run mode to preview changes

**Generated Files:**
- `detection-rule.yml` - Sigma-format detection rule
- `test-logs.json` - Sample test data for validation
- `test_detection_rule.py` - Python script to test detection rules
- `pseudocode.md` - Attack flow pseudocode examples

**Example:**

```bash
$ python tools/generate_technique_scaffold.py --technique SAFE-T1103

Found 1 technique(s) needing scaffolding:
  - SAFE-T1103: missing detection-rule.yml, test-logs.json, test_detection_rule.py, pseudocode.md

======================================================================
Processing: SAFE-T1103
======================================================================
  Technique: Fake Tool Invocation (Function Spoofing)
  Tactic: Execution
  ✓ Generated detection-rule.yml
  ✓ Generated test-logs.json
  ✓ Generated test_detection_rule.py
  ✓ Generated pseudocode.md
  ✓ Successfully generated 4 file(s)

======================================================================
Summary
======================================================================
Techniques processed: 1
Successfully generated: 1
Failed: 0
```

**Menu Integration:**

The scaffolding tool is integrated into the interactive menu system with a dedicated submenu:

1. **Scaffold specific technique** - Generate files for one technique
2. **Scaffold all techniques missing files** - Batch process all techniques
3. **Dry run** - Preview what would be generated without creating files
4. **Scaffold and validate** - Generate files and validate detection rules

---

### 13. `test_scaffold_generator.sh`

Test script that validates the technique scaffolding generator by copying a technique, running the generator, validating the output against CONTRIBUTOR_GUIDE.md requirements, and cleaning up.

**Usage:**

```bash
# Test with default technique (SAFE-T1103)
bash tools/test_scaffold_generator.sh

# Test with a specific technique
bash tools/test_scaffold_generator.sh SAFE-T1602
```

**Features:**
- Copies a technique to a temporary test directory
- Removes existing generated files to test fresh generation
- Runs the scaffold generator
- Validates all generated files against CONTRIBUTOR_GUIDE.md requirements
- Checks detection rule structure (UUID, date format, required fields, etc.)
- Validates test logs JSONL format
- Validates test script structure
- Validates pseudocode content
- Runs the detection rule validator
- Generates a comprehensive test report
- Automatically cleans up test files

**Test Coverage:**
- Required files existence (README.md, detection-rule.yml)
- Recommended files existence (test-logs.json, test_detection_rule.py, pseudocode.md)
- Detection rule structure validation (all required fields, UUID format, date format, etc.)
- Test logs JSONL format validation
- Test script structure validation
- Pseudocode content validation
- Integration with detection rule validator

**Example Output:**

```bash
$ bash tools/test_scaffold_generator.sh SAFE-T1103

╔══════════════════════════════════════════════════════════════╗
║     Technique Scaffolding Generator Test Suite              ║
╚══════════════════════════════════════════════════════════════╝

Testing technique: SAFE-T1103

Step 1: Copying Technique to Test Directory
✓ Copied technique to test directory

Step 2: Running Scaffold Generator
✓ Scaffold generator completed

Step 3: Validating Generated Files
✓ All required files exist
✓ Detection rule structure is valid
✓ Test logs are valid JSONL
✓ Test script is properly structured
✓ Pseudocode includes required sections

Step 4: Running Detection Rule Validator
✓ Detection rule validation passed

Test Report
Summary
✓ Passed: 38
✗ Failed: 0
⚠ Warnings: 0

✓ All critical tests passed!
The scaffolding generator correctly structured the technique
according to CONTRIBUTOR_GUIDE.md requirements.
```

**Exit Codes:**
- `0`: All tests passed
- `1`: One or more tests failed

---

## Platform Support

### macOS

Fully supported. All tools work natively.

```bash
./tools/safe-mcp-menu.sh
```

### Linux

Fully supported. All tools work natively.

```bash
bash tools/safe-mcp-menu.sh
```

### Windows (Cygwin)

Fully supported when using Cygwin bash emulator.

**Requirements:**
- Cygwin installed with bash
- Python 3.7+ installed and in PATH
- Git for Windows (optional, for repository access)

```bash
# In Cygwin terminal
bash tools/safe-mcp-menu.sh
```

**Note:** The tools automatically detect Windows/Cygwin and adjust paths accordingly.

---

## Installation

### Requirements

**Required:**
- Python 3.7 or higher
- Bash 4.0+ (for menu system)
- PyYAML (for validation)

**Optional (Recommended):**
- `rich` library for enhanced terminal formatting

**Install dependencies:**

```bash
# Install all dependencies (including optional)
pip install -r requirements.txt

# Or install required only
pip install pyyaml

# Install optional formatting library
pip install rich
```

**System Requirements:**
- macOS: Native support
- Linux: Native support
- Windows: Cygwin bash emulator required

### Making Scripts Executable

The scripts are already executable, but if needed:

```bash
# Make all scripts executable
chmod +x tools/*.py tools/*.sh tools/lib/*.sh

# Or make menu executable
chmod +x tools/safe-mcp-menu.sh
```

---

## Workflow Examples

### Creating a New Technique

1. Generate the technique structure:
   ```bash
   python tools/generate_technique.py --name "My New Attack" --tactic ATK-TA0002 --author "Your Name"
   ```

2. Edit the generated files:
   - Fill in `techniques/SAFE-T[XXXX]/README.md`
   - Update `techniques/SAFE-T[XXXX]/detection-rule.yml` with specific patterns

3. Validate the detection rule:
   ```bash
   python tools/validate_detection_rules.py techniques/SAFE-T[XXXX]/detection-rule.yml
   ```

4. Update the main README.md to add the technique to the TTP table

### Creating a New Mitigation

1. Generate the mitigation structure:
   ```bash
   python tools/generate_mitigation.py --name "My New Mitigation" --category "Preventive Control" --effectiveness "High" --complexity "Medium" --author "Your Name"
   ```

2. Edit the generated file:
   - Fill in `mitigations/SAFE-M-[XXXX]/README.md`
   - Add techniques this mitigation addresses

3. Update MITIGATIONS.md to add the mitigation to the table

4. Update relevant technique READMEs to reference this mitigation

### Validating All Rules

Before submitting a PR, validate all detection rules:

```bash
python tools/validate_detection_rules.py --all
```

Generate a JSON report for CI/CD:

```bash
python tools/validate_detection_rules.py --all --json validation-report.json
```

---

## Integration with CI/CD

You can integrate the validator into your CI/CD pipeline:

```yaml
# Example GitHub Actions workflow
- name: Validate Detection Rules
  run: |
    pip install pyyaml
    python tools/validate_detection_rules.py --all --json validation-report.json
    if [ $? -ne 0 ]; then
      echo "Validation failed!"
      exit 1
    fi
```

---

## Troubleshooting

### "PyYAML is required" Error

Install PyYAML:
```bash
pip install pyyaml
```

### "Template not found" Error

Make sure you're running the script from the repository root, or that the templates exist:
- `techniques/TEMPLATE.md`
- `mitigations/TEMPLATE.md`

### UUID Generation

The validator checks that IDs are valid UUIDs. To generate a UUID:

```bash
# Linux/macOS
uuidgen

# Python
python -c "import uuid; print(uuid.uuid4())"
```

---

## Contributing

When adding new tools:

1. Follow Python best practices (PEP 8)
2. Add docstrings to functions
3. Include usage examples in the script's help text
4. Update this README with tool documentation
5. Test with existing techniques/mitigations

---

## License

These tools are part of the SAFE-MCP project and are licensed under the same terms as the repository.

