#!/bin/bash
# SAFE-MCP Test Runner
# Runs all test_detection_rule.py scripts and aggregates results

# Source utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/platform_detect.sh"
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/utils.sh"

# Get repository root
REPO_ROOT=$(get_repo_root)
TECHNIQUES_DIR=$(get_techniques_dir)
PYTHON_CMD=$(get_python_cmd)

if [[ -z "$PYTHON_CMD" ]]; then
    print_error "Python is not installed or not in PATH"
    exit 1
fi

if ! check_python_version; then
    print_error "Python 3.7 or higher is required"
    exit 1
fi

print_header "SAFE-MCP Detection Rule Test Runner"
echo ""

# Find all test files
test_files=$(find "$TECHNIQUES_DIR" -name "test_detection_rule.py" -type f | sort)

if [[ -z "$test_files" ]]; then
    print_warning "No test files found"
    exit 0
fi

# Counters
total_tests=0
passed_tests=0
failed_tests=0
test_count=$(echo "$test_files" | wc -l | tr -d ' ')

print_info "Found $test_count test file(s)"
echo ""

# Run each test
failed_list=()
passed_list=()

while IFS= read -r test_file; do
    technique_dir=$(dirname "$test_file")
    technique_id=$(basename "$technique_dir")
    
    print_info "Running tests for $technique_id..."
    
    # Change to technique directory
    cd "$technique_dir" || continue
    
    # Run test
    if "$PYTHON_CMD" "test_detection_rule.py" > /tmp/test_output_$$.txt 2>&1; then
        print_success "$technique_id: All tests passed"
        passed_list+=("$technique_id")
        passed_tests=$((passed_tests + 1))
    else
        print_error "$technique_id: Tests failed"
        failed_list+=("$technique_id")
        failed_tests=$((failed_tests + 1))
        
        # Show error output
        if [[ -f /tmp/test_output_$$.txt ]]; then
            echo "  Error output:"
            sed 's/^/    /' /tmp/test_output_$$.txt
        fi
    fi
    
    total_tests=$((total_tests + 1))
    echo ""
    
    # Cleanup
    rm -f /tmp/test_output_$$.txt
    
done <<< "$test_files"

# Return to original directory
cd "$REPO_ROOT" || true

# Print summary
print_separator "=" 60
print_header "Test Summary"
print_separator "=" 60
echo ""
echo "Total test files:  $test_count"
echo "Passed:            $passed_tests"
echo "Failed:            $failed_tests"
echo ""

if [[ ${#failed_list[@]} -gt 0 ]]; then
    print_error "Failed tests:"
    for failed in "${failed_list[@]}"; do
        echo "  - $failed"
    done
    echo ""
fi

if [[ ${#passed_list[@]} -gt 0 ]]; then
    print_success "Passed tests:"
    for passed in "${passed_list[@]}"; do
        echo "  - $passed"
    done
    echo ""
fi

# Exit with appropriate code
if [[ $failed_tests -gt 0 ]]; then
    exit 1
else
    exit 0
fi

