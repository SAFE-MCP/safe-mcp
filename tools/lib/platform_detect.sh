#!/bin/bash
# Platform detection utilities for cross-platform compatibility
# Supports: macOS, Linux, Windows (Cygwin)

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "linux-musl"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ -n "$WINDIR" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Get OS name for display
get_os_name() {
    case "$(detect_os)" in
        macos) echo "macOS" ;;
        linux) echo "Linux" ;;
        windows) echo "Windows (Cygwin)" ;;
        *) echo "Unknown" ;;
    esac
}

# Check if running in Cygwin
is_cygwin() {
    [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]]
}

# Check if running on Windows (native or Cygwin)
is_windows() {
    [[ "$(detect_os)" == "windows" ]] || [[ -n "$WINDIR" ]]
}

# Normalize path for current platform
normalize_path() {
    local path="$1"
    if is_windows; then
        # Convert Unix-style path to Windows if needed
        if command -v cygpath >/dev/null 2>&1; then
            cygpath -w "$path" 2>/dev/null || echo "$path"
        else
            echo "$path" | sed 's/\//\\/g'
        fi
    else
        echo "$path"
    fi
}

# Get path separator
get_path_separator() {
    if is_windows; then
        echo "\\"
    else
        echo "/"
    fi
}

# Check if Python is available
check_python() {
    if command -v python3 >/dev/null 2>&1; then
        python3 --version 2>&1 | head -n1
    elif command -v python >/dev/null 2>&1; then
        python --version 2>&1 | head -n1
    else
        echo ""
    fi
}

# Get Python command
get_python_cmd() {
    if command -v python3 >/dev/null 2>&1; then
        echo "python3"
    elif command -v python >/dev/null 2>&1; then
        echo "python"
    else
        echo ""
    fi
}

# Check Python version (returns 0 if >= 3.7, 1 otherwise)
check_python_version() {
    local python_cmd=$(get_python_cmd)
    if [[ -z "$python_cmd" ]]; then
        return 1
    fi
    
    local version=$($python_cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
    if [[ -z "$version" ]]; then
        return 1
    fi
    
    # Compare version (3.7 or higher)
    local major=$(echo "$version" | cut -d. -f1)
    local minor=$(echo "$version" | cut -d. -f2)
    
    if [[ $major -gt 3 ]] || [[ $major -eq 3 && $minor -ge 7 ]]; then
        return 0
    else
        return 1
    fi
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check terminal color support
supports_colors() {
    if [[ -t 1 ]]; then
        # Check if terminal supports colors
        case "$TERM" in
            xterm-color|*-256color|screen|screen-256color|tmux|tmux-256color)
                return 0
                ;;
            *)
                # Check for COLORTERM
                if [[ -n "$COLORTERM" ]]; then
                    return 0
                fi
                return 1
                ;;
        esac
    else
        return 1
    fi
}

# Get repository root directory
get_repo_root() {
    # Get the directory where this script is located (lib/)
    local lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    # Go up two levels: lib/ -> tools/ -> repo root
    local repo_root="$(cd "$lib_dir/../.." && pwd)"
    echo "$repo_root"
}

# Get tools directory
get_tools_dir() {
    echo "$(get_repo_root)/tools"
}

# Get techniques directory
get_techniques_dir() {
    echo "$(get_repo_root)/techniques"
}

# Get mitigations directory
get_mitigations_dir() {
    echo "$(get_repo_root)/mitigations"
}

