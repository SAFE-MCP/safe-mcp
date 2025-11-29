#!/bin/bash
# Common utility functions for SAFE-MCP tools

# Source platform detection and colors (only if not already sourced)
# Get the directory where this script is located
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Only source if functions don't already exist
if ! declare -f detect_os >/dev/null 2>&1; then
    source "$LIB_DIR/platform_detect.sh"
fi

if ! declare -f print_success >/dev/null 2>&1; then
    source "$LIB_DIR/colors.sh"
fi

# Print a section separator
print_separator() {
    local char="${1:-=}"
    local width="${2:-80}"
    printf "%${width}s\n" | tr " " "$char"
}

# Print a centered title
print_centered_title() {
    local title="$1"
    local width="${2:-80}"
    local padding=$(( (width - ${#title} - 2) / 2 ))
    printf "%${padding}s %s %${padding}s\n" "" "$title" "" | head -c $width
}

# Print a box around text
print_box() {
    local text="$1"
    local width="${2:-80}"
    local border=$(printf "%${width}s" | tr " " "=")
    
    echo "$border"
    echo "$text" | fold -w $((width - 4)) | while IFS= read -r line; do
        printf "| %-${width}s |\n" "$line"
    done
    echo "$border"
}

# Ask for user input with prompt
ask_input() {
    local prompt="$1"
    local default="${2:-}"
    local result
    
    if [[ -n "$default" ]]; then
        echo -ne "${COLOR_CYAN}$prompt${COLOR_RESET} [${COLOR_DIM}$default${COLOR_RESET}]: " >&2
        read -r result
        result="${result:-$default}"
    else
        echo -ne "${COLOR_CYAN}$prompt${COLOR_RESET}: " >&2
        read -r result
    fi
    echo "$result"
}

# Ask yes/no question
ask_yes_no() {
    local prompt="$1"
    local default="${2:-y}"
    local response
    
    if [[ "$default" == "y" ]]; then
        echo -ne "${COLOR_CYAN}$prompt${COLOR_RESET} [Y/n]: " >&2
        read -r response
        response="${response:-y}"
    else
        echo -ne "${COLOR_CYAN}$prompt${COLOR_RESET} [y/N]: " >&2
        read -r response
        response="${response:-n}"
    fi
    
    [[ "$response" =~ ^[Yy]$ ]]
}

# Wait for user to press Enter
press_enter_to_continue() {
    echo -ne "${COLOR_DIM}Press Enter to continue...${COLOR_RESET}"
    read -r
}

# Clear screen (cross-platform)
clear_screen() {
    if command_exists clear; then
        clear
    elif is_windows; then
        # Windows/Cygwin
        printf "\033[2J\033[H"
    else
        printf "\033[2J\033[H"
    fi
}

# Find all technique directories
find_techniques() {
    local techniques_dir=$(get_techniques_dir)
    if [[ -d "$techniques_dir" ]]; then
        find "$techniques_dir" -maxdepth 1 -type d -name "SAFE-T*" | sort
    fi
}

# Find all mitigation directories
find_mitigations() {
    local mitigations_dir=$(get_mitigations_dir)
    if [[ -d "$mitigations_dir" ]]; then
        find "$mitigations_dir" -maxdepth 1 -type d -name "SAFE-M-*" | sort
    fi
}

# Extract technique ID from path
extract_technique_id() {
    local path="$1"
    basename "$path" | grep -oE "SAFE-T[0-9]+"
}

# Extract mitigation ID from path
extract_mitigation_id() {
    local path="$1"
    basename "$path" | grep -oE "SAFE-M-[0-9]+"
}

# Get technique README path
get_technique_readme() {
    local technique_id="$1"
    local techniques_dir=$(get_techniques_dir)
    echo "$techniques_dir/$technique_id/README.md"
}

# Get mitigation README path
get_mitigation_readme() {
    local mitigation_id="$1"
    local mitigations_dir=$(get_mitigations_dir)
    echo "$mitigations_dir/$mitigation_id/README.md"
}

# Check if file exists and is readable
file_exists() {
    [[ -f "$1" ]] && [[ -r "$1" ]]
}

# Run Python script with error handling
run_python_script() {
    local script="$1"
    shift
    local python_cmd=$(get_python_cmd)
    
    if [[ -z "$python_cmd" ]]; then
        print_error "Python is not installed or not in PATH"
        return 1
    fi
    
    if ! check_python_version; then
        print_error "Python 3.7 or higher is required"
        return 1
    fi
    
    local script_path="$(get_tools_dir)/$script"
    if [[ ! -f "$script_path" ]]; then
        print_error "Script not found: $script_path"
        return 1
    fi
    
    "$python_cmd" "$script_path" "$@"
}

# Format file size
format_size() {
    local size="$1"
    if [[ $size -lt 1024 ]]; then
        echo "${size}B"
    elif [[ $size -lt 1048576 ]]; then
        echo "$((size / 1024))KB"
    else
        echo "$((size / 1048576))MB"
    fi
}

# Count lines in file
count_lines() {
    local file="$1"
    if file_exists "$file"; then
        if command_exists wc; then
            wc -l < "$file" | tr -d ' '
        else
            # Fallback for systems without wc
            awk 'END {print NR}' "$file" 2>/dev/null || echo "0"
        fi
    else
        echo "0"
    fi
}

# Check if a string contains a substring (case-insensitive)
contains_ignore_case() {
    local haystack="$1"
    local needle="$2"
    [[ "${haystack,,}" == *"${needle,,}"* ]]
}

# Trim whitespace from string
trim() {
    local str="$1"
    # Remove leading whitespace
    str="${str#"${str%%[![:space:]]*}"}"
    # Remove trailing whitespace
    str="${str%"${str##*[![:space:]]}"}"
    echo "$str"
}

