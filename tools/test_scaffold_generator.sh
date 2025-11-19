#!/bin/bash
# Test script for technique scaffolding generator
# Copies a technique, tests scaffolding, validates against requirements, and cleans up

# Get script directory and source utilities
TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$TOOLS_DIR/.." && pwd)"
source "$TOOLS_DIR/lib/platform_detect.sh"
source "$TOOLS_DIR/lib/colors.sh"
source "$TOOLS_DIR/lib/utils.sh"

# Test configuration
TEST_TECHNIQUE="${1:-SAFE-T1103}"  # Default to SAFE-T1103 if not provided
TEST_DIR="$REPO_ROOT/.test_scaffold_$$"
ORIGINAL_DIR="$REPO_ROOT/techniques/$TEST_TECHNIQUE"
SCAFFOLD_SCRIPT="$TOOLS_DIR/generate_technique_scaffold.py"
VALIDATOR_SCRIPT="$TOOLS_DIR/validate_detection_rules.py"

# Report tracking
PASSED=0
FAILED=0
WARNINGS=0
ISSUES=()

# Cleanup function
cleanup() {
    if [[ -d "$TEST_DIR" ]]; then
        rm -rf "$TEST_DIR"
    fi
    # Also clean up any temporary technique directory in the actual techniques folder
    if [[ -n "$TEST_TECHNIQUE" ]] && [[ -d "$REPO_ROOT/techniques/.test_$TEST_TECHNIQUE" ]]; then
        rm -rf "$REPO_ROOT/techniques/.test_$TEST_TECHNIQUE"
    fi
}

# Trap to ensure cleanup on exit
trap cleanup EXIT INT TERM

# Print test result
print_test_result() {
    local status="$1"
    local message="$2"
    
    if [[ "$status" == "PASS" ]]; then
        print_success "$message"
        ((PASSED++))
    elif [[ "$status" == "FAIL" ]]; then
        print_error "$message"
        ((FAILED++))
        ISSUES+=("$message")
    elif [[ "$status" == "WARN" ]]; then
        print_warning "$message"
        ((WARNINGS++))
        ISSUES+=("$message")
    fi
}

# Check if file exists
check_file_exists() {
    local file="$1"
    local description="$2"
    
    if [[ -f "$file" ]]; then
        print_test_result "PASS" "$description exists"
        return 0
    else
        print_test_result "FAIL" "$description missing: $file"
        return 1
    fi
}

# Check file content
check_file_content() {
    local file="$1"
    local pattern="$2"
    local description="$3"
    
    if [[ -f "$file" ]] && grep -q "$pattern" "$file" 2>/dev/null; then
        print_test_result "PASS" "$description contains expected content"
        return 0
    else
        print_test_result "FAIL" "$description missing expected content: $pattern"
        return 1
    fi
}

# Get YAML value (using yq or python fallback)
get_yaml_value() {
    local file="$1"
    local path="$2"
    
    if command -v yq >/dev/null 2>&1; then
        yq eval "$path" "$file" 2>/dev/null
    else
        # Fallback to Python
        python3 -c "import yaml, sys; data=yaml.safe_load(open('$file')); path='$path'.split('.'); obj=data; [obj:=obj.get(p) for p in path if obj]; print(obj if obj else '')" 2>/dev/null
    fi
}

# Check if YAML field exists
yaml_field_exists() {
    local file="$1"
    local path="$2"
    
    if command -v yq >/dev/null 2>&1; then
        yq eval "$path" "$file" >/dev/null 2>&1
    else
        # Fallback to Python
        python3 -c "import yaml, sys; data=yaml.safe_load(open('$file')); path='$path'.split('.'); obj=data; [obj:=obj.get(p) for p in path if obj]; sys.exit(0 if obj else 1)" 2>/dev/null
    fi
}

# Get YAML array values
get_yaml_array() {
    local file="$1"
    local path="$2"
    
    if command -v yq >/dev/null 2>&1; then
        yq eval "$path[]" "$file" 2>/dev/null
    else
        # Fallback to Python
        python3 -c "import yaml, sys; data=yaml.safe_load(open('$file')); path='$path'.split('.'); obj=data; [obj:=obj.get(p) for p in path if obj]; [print(item) for item in (obj if isinstance(obj, list) else [])]" 2>/dev/null
    fi
}

# Validate detection rule structure
validate_detection_rule() {
    local rule_file="$1"
    local technique_id="$2"
    
    echo ""
    print_subheader "Validating Detection Rule Structure"
    print_separator "─" 60
    
    # Check required fields
    local required_fields=("title" "id" "status" "description" "author" "date" "references" "logsource" "detection" "level" "tags")
    
    for field in "${required_fields[@]}"; do
        if yaml_field_exists "$rule_file" ".$field"; then
            print_test_result "PASS" "Detection rule has required field: $field"
        else
            print_test_result "FAIL" "Detection rule missing required field: $field"
        fi
    done
    
    # Check UUID format
    local id=$(get_yaml_value "$rule_file" ".id")
    if [[ "$id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        print_test_result "PASS" "Detection rule ID is valid UUID"
    else
        print_test_result "FAIL" "Detection rule ID is not a valid UUID: $id"
    fi
    
    # Check date format
    local date=$(get_yaml_value "$rule_file" ".date")
    if [[ "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        print_test_result "PASS" "Detection rule date is valid format (YYYY-MM-DD)"
    else
        print_test_result "FAIL" "Detection rule date is not valid format: $date"
    fi
    
    # Check status
    local status=$(get_yaml_value "$rule_file" ".status")
    if [[ "$status" =~ ^(experimental|test|stable|deprecated)$ ]]; then
        print_test_result "PASS" "Detection rule status is valid: $status"
    else
        print_test_result "FAIL" "Detection rule status is invalid: $status"
    fi
    
    # Check level
    local level=$(get_yaml_value "$rule_file" ".level")
    if [[ "$level" =~ ^(low|medium|high|critical)$ ]]; then
        print_test_result "PASS" "Detection rule level is valid: $level"
    else
        print_test_result "FAIL" "Detection rule level is invalid: $level"
    fi
    
    # Check references include technique URL
    if get_yaml_array "$rule_file" ".references" | grep -q "github.com/safe-mcp/techniques/$technique_id"; then
        print_test_result "PASS" "Detection rule references include technique URL"
    else
        print_test_result "WARN" "Detection rule references may not include technique URL"
    fi
    
    # Check tags include safe.tXXXX
    if get_yaml_array "$rule_file" ".tags" | grep -qi "safe.t"; then
        print_test_result "PASS" "Detection rule tags include safe.tXXXX tag"
    else
        print_test_result "FAIL" "Detection rule tags missing safe.tXXXX tag"
    fi
    
    # Check logsource
    local product=$(get_yaml_value "$rule_file" ".logsource.product")
    if [[ "$product" == "mcp" ]]; then
        print_test_result "PASS" "Detection rule logsource.product is 'mcp'"
    else
        print_test_result "WARN" "Detection rule logsource.product is not 'mcp': $product"
    fi
    
    # Check detection has selection
    if yaml_field_exists "$rule_file" ".detection.selection"; then
        print_test_result "PASS" "Detection rule has selection patterns"
    else
        print_test_result "FAIL" "Detection rule missing selection patterns"
    fi
    
    # Check condition
    if yaml_field_exists "$rule_file" ".detection.condition"; then
        print_test_result "PASS" "Detection rule has condition"
    else
        print_test_result "FAIL" "Detection rule missing condition"
    fi
}

# Validate test logs JSON
validate_test_logs() {
    local test_logs_file="$1"
    
    echo ""
    print_subheader "Validating Test Logs"
    print_separator "─" 60
    
    if [[ ! -f "$test_logs_file" ]]; then
        print_test_result "FAIL" "test-logs.json file missing"
        return 1
    fi
    
    # Check if has entries (JSONL format - one JSON object per line)
    local line_count=$(wc -l < "$test_logs_file" 2>/dev/null | tr -d ' ')
    if [[ $line_count -gt 0 ]]; then
        print_test_result "PASS" "test-logs.json has entries ($line_count lines)"
    else
        print_test_result "WARN" "test-logs.json appears empty"
        return 1
    fi
    
    # Validate each line is valid JSON (JSONL format)
    local valid_lines=0
    local total_lines=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        ((total_lines++))
        if echo "$line" | python3 -c "import sys, json; json.load(sys.stdin)" >/dev/null 2>&1; then
            ((valid_lines++))
        fi
    done < "$test_logs_file"
    
    if [[ $valid_lines -eq $total_lines ]] && [[ $total_lines -gt 0 ]]; then
        print_test_result "PASS" "test-logs.json is valid JSONL format ($valid_lines/$total_lines lines valid)"
    else
        print_test_result "FAIL" "test-logs.json contains invalid JSON ($valid_lines/$total_lines lines valid)"
        return 1
    fi
    
    # Check if entries have expected fields
    local first_line=$(head -n 1 "$test_logs_file" 2>/dev/null)
    if [[ -n "$first_line" ]] && echo "$first_line" | python3 -c "import sys, json; obj=json.load(sys.stdin); assert 'tool_name' in obj or 'tool_description' in obj" 2>/dev/null; then
        print_test_result "PASS" "test-logs.json entries have expected fields"
    else
        print_test_result "WARN" "test-logs.json entries may be missing expected fields"
    fi
}

# Validate test script
validate_test_script() {
    local test_script_file="$1"
    local technique_id="$2"
    
    echo ""
    print_subheader "Validating Test Script"
    print_separator "─" 60
    
    if [[ ! -f "$test_script_file" ]]; then
        print_test_result "FAIL" "test_detection_rule.py file missing"
        return 1
    fi
    
    # Check if executable
    if [[ -x "$test_script_file" ]]; then
        print_test_result "PASS" "test_detection_rule.py is executable"
    else
        print_test_result "WARN" "test_detection_rule.py is not executable"
    fi
    
    # Check if has shebang
    if head -n 1 "$test_script_file" | grep -q "^#!/usr/bin/env python"; then
        print_test_result "PASS" "test_detection_rule.py has correct shebang"
    else
        print_test_result "WARN" "test_detection_rule.py may be missing shebang"
    fi
    
    # Check if imports required modules
    if grep -q "import.*yaml" "$test_script_file" && grep -q "import.*json" "$test_script_file"; then
        print_test_result "PASS" "test_detection_rule.py imports required modules"
    else
        print_test_result "WARN" "test_detection_rule.py may be missing required imports"
    fi
    
    # Check if references technique ID
    if grep -qi "$technique_id" "$test_script_file"; then
        print_test_result "PASS" "test_detection_rule.py references technique ID"
    else
        print_test_result "WARN" "test_detection_rule.py may not reference technique ID"
    fi
}

# Validate pseudocode
validate_pseudocode() {
    local pseudocode_file="$1"
    local technique_id="$2"
    local technique_name="$3"
    
    echo ""
    print_subheader "Validating Pseudocode"
    print_separator "─" 60
    
    if [[ ! -f "$pseudocode_file" ]]; then
        print_test_result "FAIL" "pseudocode.md file missing"
        return 1
    fi
    
    # Check if has technique ID in title
    if grep -q "$technique_id" "$pseudocode_file"; then
        print_test_result "PASS" "pseudocode.md includes technique ID"
    else
        print_test_result "WARN" "pseudocode.md may not include technique ID"
    fi
    
    # Check if has attack flow section
    if grep -qi "attack flow\|attack flow" "$pseudocode_file"; then
        print_test_result "PASS" "pseudocode.md includes attack flow section"
    else
        print_test_result "WARN" "pseudocode.md may be missing attack flow section"
    fi
    
    # Check if has code examples
    if grep -q '```' "$pseudocode_file"; then
        print_test_result "PASS" "pseudocode.md includes code examples"
    else
        print_test_result "WARN" "pseudocode.md may be missing code examples"
    fi
    
    # Check if has defense section
    if grep -qi "defense\|mitigation" "$pseudocode_file"; then
        print_test_result "PASS" "pseudocode.md includes defense/mitigation section"
    else
        print_test_result "WARN" "pseudocode.md may be missing defense section"
    fi
}

# Check CONTRIBUTOR_GUIDE requirements
check_contributor_guide_requirements() {
    local technique_dir="$1"
    local technique_id="$2"
    
    echo ""
    print_subheader "Checking CONTRIBUTOR_GUIDE.md Requirements"
    print_separator "─" 60
    
    # Required files per CONTRIBUTOR_GUIDE
    local required_files=(
        "README.md:Main documentation"
        "detection-rule.yml:Sigma detection rule"
    )
    
    # Optional but recommended files
    local recommended_files=(
        "test-logs.json:Test data"
        "test_detection_rule.py:Test validation script"
    )
    
    echo ""
    print_info "Required Files:"
    for file_desc in "${required_files[@]}"; do
        local file="${file_desc%%:*}"
        local desc="${file_desc##*:}"
        check_file_exists "$technique_dir/$file" "$desc"
    done
    
    echo ""
    print_info "Recommended Files:"
    for file_desc in "${recommended_files[@]}"; do
        local file="${file_desc%%:*}"
        local desc="${file_desc##*:}"
        if check_file_exists "$technique_dir/$file" "$desc"; then
            print_test_result "PASS" "$desc exists (recommended)"
        else
            print_test_result "WARN" "$desc missing (recommended but not required)"
        fi
    done
    
    # Check detection rule format requirements
    if [[ -f "$technique_dir/detection-rule.yml" ]]; then
        validate_detection_rule "$technique_dir/detection-rule.yml" "$technique_id"
    fi
    
    # Validate other files
    if [[ -f "$technique_dir/test-logs.json" ]]; then
        validate_test_logs "$technique_dir/test-logs.json"
    fi
    
    if [[ -f "$technique_dir/test_detection_rule.py" ]]; then
        validate_test_script "$technique_dir/test_detection_rule.py" "$technique_id"
    fi
    
    if [[ -f "$technique_dir/pseudocode.md" ]]; then
        local technique_name=$(grep -m 1 "^# SAFE-T" "$technique_dir/README.md" 2>/dev/null | sed 's/^# SAFE-T[0-9]*: //' || echo "Unknown")
        validate_pseudocode "$technique_dir/pseudocode.md" "$technique_id" "$technique_name"
    fi
}

# Run validation using the validator script
run_validator() {
    local rule_file="$1"
    
    echo ""
    print_subheader "Running Detection Rule Validator"
    print_separator "─" 60
    
    if [[ ! -f "$VALIDATOR_SCRIPT" ]]; then
        print_test_result "WARN" "Validator script not found: $VALIDATOR_SCRIPT"
        return 1
    fi
    
    local python_cmd=$(get_python_cmd)
    if [[ -z "$python_cmd" ]]; then
        print_test_result "WARN" "Python not found, skipping validator"
        return 1
    fi
    
    echo ""
    if "$python_cmd" "$VALIDATOR_SCRIPT" "$rule_file" 2>&1 | tee /tmp/validator_output_$$.txt; then
        # Check if validation passed
        if grep -q "✓ VALID\|Status:.*VALID" /tmp/validator_output_$$.txt 2>/dev/null; then
            print_test_result "PASS" "Detection rule validation passed"
        else
            print_test_result "FAIL" "Detection rule validation failed or produced warnings"
        fi
    else
        print_test_result "FAIL" "Detection rule validator encountered errors"
    fi
    
    rm -f /tmp/validator_output_$$.txt
}

# Main test function
main() {
    clear_screen
    print_header "╔══════════════════════════════════════════════════════════════╗"
    print_header "║     Technique Scaffolding Generator Test Suite              ║"
    print_header "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    print_info "Testing technique: $TEST_TECHNIQUE"
    print_info "Test directory: $TEST_DIR"
    echo ""
    
    # Check if original technique exists
    if [[ ! -d "$ORIGINAL_DIR" ]]; then
        print_error "Original technique directory not found: $ORIGINAL_DIR"
        exit 1
    fi
    
    if [[ ! -f "$ORIGINAL_DIR/README.md" ]]; then
        print_error "Original technique README.md not found"
        exit 1
    fi
    
    # Check if scaffold script exists
    if [[ ! -f "$SCAFFOLD_SCRIPT" ]]; then
        print_error "Scaffold script not found: $SCAFFOLD_SCRIPT"
        exit 1
    fi
    
    # Step 1: Copy technique to test directory
    echo ""
    print_subheader "Step 1: Copying Technique to Test Directory"
    print_separator "─" 60
    
    mkdir -p "$TEST_DIR/techniques"
    cp -r "$ORIGINAL_DIR" "$TEST_DIR/techniques/"
    
    local test_technique_dir="$TEST_DIR/techniques/$TEST_TECHNIQUE"
    
    # Remove existing generated files if they exist
    rm -f "$test_technique_dir/detection-rule.yml"
    rm -f "$test_technique_dir/test-logs.json"
    rm -f "$test_technique_dir/test_detection_rule.py"
    rm -f "$test_technique_dir/pseudocode.md"
    
    print_success "Copied technique to test directory"
    print_info "Removed existing generated files (if any)"
    
    # Step 2: Run scaffold generator
    echo ""
    print_subheader "Step 2: Running Scaffold Generator"
    print_separator "─" 60
    
    local python_cmd=$(get_python_cmd)
    if [[ -z "$python_cmd" ]]; then
        print_error "Python not found"
        exit 1
    fi
    
    # Temporarily move the test technique to the actual techniques directory
    # so the scaffold generator can find it
    local temp_technique_dir="$REPO_ROOT/techniques/.test_$TEST_TECHNIQUE"
    if [[ -d "$temp_technique_dir" ]]; then
        rm -rf "$temp_technique_dir"
    fi
    mv "$test_technique_dir" "$temp_technique_dir"
    
    echo ""
    print_info "Running: $python_cmd $SCAFFOLD_SCRIPT --technique .test_$TEST_TECHNIQUE"
    echo ""
    
    if "$python_cmd" "$SCAFFOLD_SCRIPT" --technique ".test_$TEST_TECHNIQUE" 2>&1; then
        print_success "Scaffold generator completed"
        # Move back to test directory
        mv "$temp_technique_dir" "$test_technique_dir"
    else
        print_error "Scaffold generator failed"
        # Move back to test directory even on failure
        mv "$temp_technique_dir" "$test_technique_dir" 2>/dev/null || true
        exit 1
    fi
    
    # Step 3: Validate generated files
    echo ""
    print_subheader "Step 3: Validating Generated Files"
    print_separator "─" 60
    
    check_contributor_guide_requirements "$test_technique_dir" "$TEST_TECHNIQUE"
    
    # Step 4: Run validator script
    if [[ -f "$test_technique_dir/detection-rule.yml" ]]; then
        run_validator "$test_technique_dir/detection-rule.yml"
    fi
    
    # Step 5: Generate report
    echo ""
    echo ""
    print_header "╔══════════════════════════════════════════════════════════════╗"
    print_header "║                    Test Report                               ║"
    print_header "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    print_separator "─" 60
    print_subheader "Summary"
    print_separator "─" 60
    echo ""
    print_success "Passed: $PASSED"
    print_error "Failed: $FAILED"
    print_warning "Warnings: $WARNINGS"
    echo ""
    
    if [[ $FAILED -gt 0 ]]; then
        print_separator "─" 60
        print_subheader "Issues Found"
        print_separator "─" 60
        for issue in "${ISSUES[@]}"; do
            echo "  • $issue"
        done
        echo ""
    fi
    
    # Overall result
    print_separator "─" 60
    if [[ $FAILED -eq 0 ]]; then
        print_success "✓ All critical tests passed!"
        if [[ $WARNINGS -gt 0 ]]; then
            print_warning "⚠ Some warnings were found (non-critical)"
        fi
        echo ""
        print_info "The scaffolding generator correctly structured the technique"
        print_info "according to CONTRIBUTOR_GUIDE.md requirements."
        exit_code=0
    else
        print_error "✗ Some tests failed"
        echo ""
        print_error "The scaffolding generator did not meet all requirements."
        print_error "Please review the issues above."
        exit_code=1
    fi
    print_separator "─" 60
    echo ""
    
    # Cleanup
    print_info "Cleaning up test directory..."
    cleanup
    
    exit $exit_code
}

# Run main function
main "$@"

