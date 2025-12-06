#!/bin/bash
# SAFE-MCP Interactive Menu System
# Master menu for navigating and using SAFE-MCP tools

# Get script directory and source utilities
TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TOOLS_DIR/lib/platform_detect.sh"
source "$TOOLS_DIR/lib/colors.sh"
source "$TOOLS_DIR/lib/utils.sh"

# Menu version
MENU_VERSION="1.0.0"

# Main menu function
show_main_menu() {
    clear_screen
    print_header "╔══════════════════════════════════════════════════════════════╗"
    print_header "║           SAFE-MCP Interactive Tools Suite                  ║"
    print_header "║              Version $MENU_VERSION                              ║"
    print_header "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    print_info "Platform: $(get_os_name)"
    local python_ver=$(check_python)
    if [[ -n "$python_ver" ]]; then
        print_info "Python: $python_ver"
    else
        print_warning "Python not found - some features may be unavailable"
    fi
    echo ""
    print_separator "─" 60
    echo ""
    echo -e "  ${COLOR_BOLD}1)${COLOR_RESET} Browse Techniques & Mitigations"
    echo -e "  ${COLOR_BOLD}2)${COLOR_RESET} View Statistics Dashboard"
    echo -e "  ${COLOR_BOLD}3)${COLOR_RESET} Search Content"
    echo -e "  ${COLOR_BOLD}4)${COLOR_RESET} Quick Reference"
    echo -e "  ${COLOR_BOLD}5)${COLOR_RESET} Compare Items"
    echo -e "  ${COLOR_BOLD}6)${COLOR_RESET} Validate Content"
    echo -e "  ${COLOR_BOLD}7)${COLOR_RESET} Test Detection Rules"
    echo -e "  ${COLOR_BOLD}8)${COLOR_RESET} Export Content"
    echo -e "  ${COLOR_BOLD}9)${COLOR_RESET} Generate New Technique"
    echo -e "  ${COLOR_BOLD}10)${COLOR_RESET} Generate New Mitigation"
    echo -e "  ${COLOR_BOLD}11)${COLOR_RESET} Scaffold Missing Technique Files"
    echo -e "  ${COLOR_BOLD}12)${COLOR_RESET} Test Scaffold Generator"
    echo -e "  ${COLOR_BOLD}13)${COLOR_RESET} Generate Examples from Sources"
    echo ""
    print_separator "─" 60
    echo ""
    echo -e "  ${COLOR_BOLD}h)${COLOR_RESET} Help"
    echo -e "  ${COLOR_BOLD}q)${COLOR_RESET} Quit"
    echo ""
}

# Handle menu selection
handle_menu_choice() {
    local choice="$1"
    
    case "$choice" in
        1)
            run_python_script "browse_content.py"
            press_enter_to_continue
            ;;
        2)
            run_python_script "show_stats.py"
            press_enter_to_continue
            ;;
        3)
            run_python_script "search_content.py"
            press_enter_to_continue
            ;;
        4)
            run_python_script "quick_ref.py"
            press_enter_to_continue
            ;;
        5)
            run_python_script "compare_items.py"
            press_enter_to_continue
            ;;
        6)
            run_python_script "validate_content.py"
            press_enter_to_continue
            ;;
        7)
            bash "$(get_tools_dir)/run_tests.sh"
            press_enter_to_continue
            ;;
        8)
            run_python_script "export_content.py"
            press_enter_to_continue
            ;;
        9)
            local python_cmd=$(get_python_cmd)
            if [[ -n "$python_cmd" ]]; then
                echo ""
                print_info "Generating new technique..."
                echo ""
                print_info "You will be prompted for required information."
                echo ""
                "$python_cmd" "$(get_tools_dir)/generate_technique.py" --interactive 2>/dev/null || {
                    # If --interactive flag doesn't exist, prompt for required fields
                    local name=$(ask_input "Enter technique name")
                    local tactic=$(ask_input "Enter tactic ID (e.g., ATK-TA0001)")
                    local author=$(ask_input "Enter author name" "SAFE-MCP Team")
                    "$python_cmd" "$(get_tools_dir)/generate_technique.py" --name "$name" --tactic "$tactic" --author "$author"
                }
            else
                print_error "Python is required for this feature"
            fi
            press_enter_to_continue
            ;;
        10)
            local python_cmd=$(get_python_cmd)
            if [[ -n "$python_cmd" ]]; then
                echo ""
                print_info "Generating new mitigation..."
                echo ""
                print_info "You will be prompted for required information."
                echo ""
                "$python_cmd" "$(get_tools_dir)/generate_mitigation.py" --interactive 2>/dev/null || {
                    # If --interactive flag doesn't exist, prompt for required fields
                    local name=$(ask_input "Enter mitigation name")
                    local category=$(ask_input "Enter category (e.g., Preventive Control)")
                    local effectiveness=$(ask_input "Enter effectiveness (High/Medium-High/Medium/Low)" "High")
                    local complexity=$(ask_input "Enter complexity (High/Medium/Low)" "Medium")
                    local author=$(ask_input "Enter author name" "SAFE-MCP Team")
                    "$python_cmd" "$(get_tools_dir)/generate_mitigation.py" --name "$name" --category "$category" --effectiveness "$effectiveness" --complexity "$complexity" --author "$author"
                }
            else
                print_error "Python is required for this feature"
            fi
            press_enter_to_continue
            ;;
        11)
            show_scaffold_menu
            ;;
        12)
            show_test_scaffold_menu
            ;;
        13)
            show_generate_examples_menu
            ;;
        h|H|help|Help)
            show_help
            press_enter_to_continue
            ;;
        q|Q|quit|Quit|exit|Exit)
            print_success "Thank you for using SAFE-MCP Tools!"
            exit 0
            ;;
        *)
            print_error "Invalid choice: $choice"
            sleep 1
            ;;
    esac
}

# Show scaffold menu
show_scaffold_menu() {
    local python_cmd=$(get_python_cmd)
    if [[ -z "$python_cmd" ]]; then
        print_error "Python is required for this feature"
        press_enter_to_continue
        return
    fi
    
    while true; do
        clear_screen
        print_header "╔══════════════════════════════════════════════════════════════╗"
        print_header "║        Scaffold Missing Technique Files                    ║"
        print_header "╚══════════════════════════════════════════════════════════════╝"
        echo ""
        print_info "Generate missing files for techniques (detection-rule.yml, test files, pseudocode)"
        echo ""
        print_separator "─" 60
        echo ""
        echo -e "  ${COLOR_BOLD}1)${COLOR_RESET} Scaffold specific technique"
        echo -e "  ${COLOR_BOLD}2)${COLOR_RESET} Scaffold all techniques missing files"
        echo -e "  ${COLOR_BOLD}3)${COLOR_RESET} Dry run (show what would be generated)"
        echo -e "  ${COLOR_BOLD}4)${COLOR_RESET} Scaffold and validate"
        echo ""
        print_separator "─" 60
        echo ""
        echo -e "  ${COLOR_BOLD}b)${COLOR_RESET} Back to main menu"
        echo ""
        echo -ne "${COLOR_CYAN}Select an option:${COLOR_RESET} "
        read -r choice
        choice=$(trim "$choice")
        
        case "$choice" in
            1)
                echo ""
                local technique=$(ask_input "Enter technique ID (e.g., SAFE-T1103)")
                if [[ -n "$technique" ]]; then
                    echo ""
                    print_info "Scaffolding files for $technique..."
                    echo ""
                    "$python_cmd" "$(get_tools_dir)/generate_technique_scaffold.py" --technique "$technique" 2>&1
                    echo ""
                    if ask_yes_no "Validate generated detection rule?" "y"; then
                        echo ""
                        "$python_cmd" "$(get_tools_dir)/validate_detection_rules.py" "$(get_repo_root)/techniques/$technique/detection-rule.yml" 2>&1 || true
                    fi
                fi
                press_enter_to_continue
                ;;
            2)
                echo ""
                print_warning "This will generate files for ALL techniques missing detection-rule.yml"
                if ask_yes_no "Continue?" "n"; then
                    echo ""
                    print_info "Scaffolding files for all techniques..."
                    echo ""
                    "$python_cmd" "$(get_tools_dir)/generate_technique_scaffold.py" --all 2>&1
                    echo ""
                    if ask_yes_no "Validate all generated detection rules?" "y"; then
                        echo ""
                        "$python_cmd" "$(get_tools_dir)/validate_detection_rules.py" --directory "$(get_repo_root)/techniques" 2>&1 || true
                    fi
                fi
                press_enter_to_continue
                ;;
            3)
                echo ""
                print_info "Dry run - showing what would be generated..."
                echo ""
                "$python_cmd" "$(get_tools_dir)/generate_technique_scaffold.py" --all --dry-run 2>&1
                press_enter_to_continue
                ;;
            4)
                echo ""
                print_warning "This will generate files for ALL techniques missing detection-rule.yml and validate them"
                if ask_yes_no "Continue?" "n"; then
                    echo ""
                    print_info "Scaffolding and validating files..."
                    echo ""
                    "$python_cmd" "$(get_tools_dir)/generate_technique_scaffold.py" --all --validate 2>&1
                fi
                press_enter_to_continue
                ;;
            b|B|back|Back)
                return
                ;;
            *)
                print_error "Invalid choice: $choice"
                sleep 1
                ;;
        esac
    done
}

# Show generate examples menu
show_generate_examples_menu() {
    local python_cmd=$(get_python_cmd)
    if [[ -z "$python_cmd" ]]; then
        print_error "Python is required for this feature"
        press_enter_to_continue
        return
    fi
    
    while true; do
        clear_screen
        print_header "╔══════════════════════════════════════════════════════════════╗"
        print_header "║        Generate Examples from Sources                       ║"
        print_header "╚══════════════════════════════════════════════════════════════╝"
        echo ""
        print_info "Generate detector.py and attack_simulation.py from pseudocode.md and detection-rule.yml"
        echo ""
        print_separator "─" 60
        echo ""
        echo -e "  ${COLOR_BOLD}1)${COLOR_RESET} Generate examples for specific technique"
        echo -e "  ${COLOR_BOLD}2)${COLOR_RESET} Generate examples for all techniques"
        echo ""
        print_separator "─" 60
        echo ""
        echo -e "  ${COLOR_BOLD}b)${COLOR_RESET} Back to main menu"
        echo ""
        echo -ne "${COLOR_CYAN}Select an option:${COLOR_RESET} "
        read -r choice
        choice=$(trim "$choice")
        
        case "$choice" in
            1)
                echo ""
                local technique=$(ask_input "Enter technique ID (e.g., SAFE-T1001)")
                if [[ -n "$technique" ]]; then
                    echo ""
                    print_info "Generating examples for $technique..."
                    echo ""
                    "$python_cmd" "$(get_tools_dir)/generate_examples_from_sources.py" "$technique" 2>&1
                    echo ""
                    if ask_yes_no "View generated files?" "n"; then
                        local examples_dir="$(get_repo_root)/techniques/$technique/examples"
                        if [[ -d "$examples_dir" ]]; then
                            echo ""
                            print_info "Generated files in $examples_dir:"
                            ls -lh "$examples_dir" 2>/dev/null || true
                        fi
                    fi
                else
                    print_warning "No technique ID provided"
                fi
                press_enter_to_continue
                ;;
            2)
                echo ""
                print_warning "This will generate examples for ALL techniques"
                if ask_yes_no "Continue?" "n"; then
                    echo ""
                    print_info "Generating examples for all techniques..."
                    echo ""
                    "$python_cmd" "$(get_tools_dir)/generate_examples_from_sources.py" 2>&1
                fi
                press_enter_to_continue
                ;;
            b|B|back|Back)
                return
                ;;
            *)
                print_error "Invalid choice: $choice"
                sleep 1
                ;;
        esac
    done
}

# Show test scaffold menu
show_test_scaffold_menu() {
    local test_script="$TOOLS_DIR/test_scaffold_generator.sh"
    
    if [[ ! -f "$test_script" ]]; then
        print_error "Test scaffold script not found: $test_script"
        press_enter_to_continue
        return
    fi
    
    while true; do
        clear_screen
        print_header "╔══════════════════════════════════════════════════════════════╗"
        print_header "║        Test Scaffold Generator                              ║"
        print_header "╚══════════════════════════════════════════════════════════════╝"
        echo ""
        print_info "Test the technique scaffolding generator by validating generated files"
        print_info "against CONTRIBUTOR_GUIDE.md requirements"
        echo ""
        print_separator "─" 60
        echo ""
        echo -e "  ${COLOR_BOLD}1)${COLOR_RESET} Test with default technique (SAFE-T1103)"
        echo -e "  ${COLOR_BOLD}2)${COLOR_RESET} Test with specific technique"
        echo ""
        print_separator "─" 60
        echo ""
        echo -e "  ${COLOR_BOLD}b)${COLOR_RESET} Back to main menu"
        echo ""
        echo -ne "${COLOR_CYAN}Select an option:${COLOR_RESET} "
        read -r choice
        choice=$(trim "$choice")
        
        case "$choice" in
            1)
                echo ""
                print_info "Running test with default technique (SAFE-T1103)..."
                echo ""
                bash "$test_script" SAFE-T1103
                press_enter_to_continue
                ;;
            2)
                echo ""
                local technique=$(ask_input "Enter technique ID (e.g., SAFE-T1602)")
                if [[ -n "$technique" ]]; then
                    echo ""
                    print_info "Running test with technique: $technique"
                    echo ""
                    bash "$test_script" "$technique"
                else
                    print_warning "No technique ID provided"
                fi
                press_enter_to_continue
                ;;
            b|B|back|Back)
                return
                ;;
            *)
                print_error "Invalid choice: $choice"
                sleep 1
                ;;
        esac
    done
}

# Show help information
show_help() {
    clear_screen
    print_header "SAFE-MCP Tools Help"
    echo ""
    print_subheader "Available Tools:"
    echo ""
    echo "  1. Browse Techniques & Mitigations"
    echo "     Navigate and view SAFE-MCP techniques and mitigations"
    echo ""
    echo "  2. View Statistics Dashboard"
    echo "     Display summary statistics and coverage analysis"
    echo ""
    echo "  3. Search Content"
    echo "     Full-text search across all techniques and mitigations"
    echo ""
    echo "  4. Quick Reference"
    echo "     Display quick reference cards for techniques/mitigations"
    echo ""
    echo "  5. Compare Items"
    echo "     Compare two techniques or mitigations side-by-side"
    echo ""
    echo "  6. Validate Content"
    echo "     Validate detection rules and content completeness"
    echo ""
    echo "  7. Test Detection Rules"
    echo "     Run tests on detection rules against test logs"
    echo ""
    echo "  8. Export Content"
    echo "     Export techniques/mitigations to various formats"
    echo ""
    echo "  9. Generate New Technique"
    echo "     Create a new SAFE-MCP technique structure"
    echo ""
    echo "  10. Generate New Mitigation"
    echo "      Create a new SAFE-MCP mitigation structure"
    echo ""
    echo "  11. Scaffold Missing Technique Files"
    echo "      Generate missing files (detection-rule.yml, tests, pseudocode) for existing techniques"
    echo ""
    echo "  12. Test Scaffold Generator"
    echo "      Test and validate the scaffolding generator against CONTRIBUTOR_GUIDE.md requirements"
    echo ""
    echo "  13. Generate Examples from Sources"
    echo "      Generate detector.py and attack_simulation.py examples from pseudocode.md and detection-rule.yml"
    echo ""
    print_separator "─" 60
    echo ""
    print_subheader "Navigation:"
    echo "  - Enter a number to select a menu option"
    echo "  - Press 'h' for help"
    echo "  - Press 'q' to quit"
    echo ""
    print_subheader "Platform Support:"
    echo "  - macOS"
    echo "  - Linux"
    echo "  - Windows (Cygwin)"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    local errors=0
    
    # Check Python
    if [[ -z "$(get_python_cmd)" ]]; then
        print_error "Python is not installed or not in PATH"
        errors=$((errors + 1))
    elif ! check_python_version; then
        print_error "Python 3.7 or higher is required"
        errors=$((errors + 1))
    fi
    
    # Check repository structure
    if [[ ! -d "$(get_techniques_dir)" ]]; then
        print_error "Techniques directory not found"
        errors=$((errors + 1))
    fi
    
    if [[ ! -d "$(get_mitigations_dir)" ]]; then
        print_error "Mitigations directory not found"
        errors=$((errors + 1))
    fi
    
    if [[ $errors -gt 0 ]]; then
        echo ""
        print_warning "Some prerequisites are missing. Some features may not work."
        echo ""
        if ! ask_yes_no "Continue anyway?" "y"; then
            exit 1
        fi
    fi
}

# Main loop
main() {
    # Check if running from correct directory
    cd "$(get_repo_root)" || {
        print_error "Failed to change to repository root"
        exit 1
    }
    
    # Check prerequisites
    check_prerequisites
    
    # Main menu loop
    while true; do
        show_main_menu
        echo -ne "${COLOR_CYAN}Select an option:${COLOR_RESET} "
        read -r choice
        choice=$(trim "$choice")
        handle_menu_choice "$choice"
    done
}

# Run main function
main "$@"

