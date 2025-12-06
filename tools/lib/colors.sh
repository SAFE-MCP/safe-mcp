#!/bin/bash
# Color definitions for terminal output
# Automatically disables colors if terminal doesn't support them

# Source platform detection
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/platform_detect.sh"

# Check if colors should be enabled
if supports_colors; then
    # ANSI color codes
    COLOR_RESET='\033[0m'
    COLOR_BOLD='\033[1m'
    COLOR_DIM='\033[2m'
    COLOR_UNDERLINE='\033[4m'
    
    # Foreground colors
    COLOR_BLACK='\033[30m'
    COLOR_RED='\033[31m'
    COLOR_GREEN='\033[32m'
    COLOR_YELLOW='\033[33m'
    COLOR_BLUE='\033[34m'
    COLOR_MAGENTA='\033[35m'
    COLOR_CYAN='\033[36m'
    COLOR_WHITE='\033[37m'
    
    # Bright foreground colors
    COLOR_BRIGHT_BLACK='\033[90m'
    COLOR_BRIGHT_RED='\033[91m'
    COLOR_BRIGHT_GREEN='\033[92m'
    COLOR_BRIGHT_YELLOW='\033[93m'
    COLOR_BRIGHT_BLUE='\033[94m'
    COLOR_BRIGHT_MAGENTA='\033[95m'
    COLOR_BRIGHT_CYAN='\033[96m'
    COLOR_BRIGHT_WHITE='\033[97m'
    
    # Background colors
    COLOR_BG_BLACK='\033[40m'
    COLOR_BG_RED='\033[41m'
    COLOR_BG_GREEN='\033[42m'
    COLOR_BG_YELLOW='\033[43m'
    COLOR_BG_BLUE='\033[44m'
    COLOR_BG_MAGENTA='\033[45m'
    COLOR_BG_CYAN='\033[46m'
    COLOR_BG_WHITE='\033[47m'
else
    # No colors - empty strings
    COLOR_RESET=''
    COLOR_BOLD=''
    COLOR_DIM=''
    COLOR_UNDERLINE=''
    COLOR_BLACK=''
    COLOR_RED=''
    COLOR_GREEN=''
    COLOR_YELLOW=''
    COLOR_BLUE=''
    COLOR_MAGENTA=''
    COLOR_CYAN=''
    COLOR_WHITE=''
    COLOR_BRIGHT_BLACK=''
    COLOR_BRIGHT_RED=''
    COLOR_BRIGHT_GREEN=''
    COLOR_BRIGHT_YELLOW=''
    COLOR_BRIGHT_BLUE=''
    COLOR_BRIGHT_MAGENTA=''
    COLOR_BRIGHT_CYAN=''
    COLOR_BRIGHT_WHITE=''
    COLOR_BG_BLACK=''
    COLOR_BG_RED=''
    COLOR_BG_GREEN=''
    COLOR_BG_YELLOW=''
    COLOR_BG_BLUE=''
    COLOR_BG_MAGENTA=''
    COLOR_BG_CYAN=''
    COLOR_BG_WHITE=''
fi

# Semantic color functions
print_success() {
    echo -e "${COLOR_GREEN}✓${COLOR_RESET} $1"
}

print_error() {
    echo -e "${COLOR_RED}✗${COLOR_RESET} $1" >&2
}

print_warning() {
    echo -e "${COLOR_YELLOW}⚠${COLOR_RESET} $1"
}

print_info() {
    echo -e "${COLOR_CYAN}ℹ${COLOR_RESET} $1"
}

print_header() {
    echo -e "${COLOR_BOLD}${COLOR_CYAN}$1${COLOR_RESET}"
}

print_subheader() {
    echo -e "${COLOR_BOLD}$1${COLOR_RESET}"
}

print_highlight() {
    echo -e "${COLOR_BRIGHT_YELLOW}$1${COLOR_RESET}"
}

