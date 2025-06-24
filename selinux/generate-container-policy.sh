#!/bin/bash
# SELinux Policy Generation Script for Scale Printer MQTT Daemons
# This script helps generate custom SELinux policies for the container services

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="${SCRIPT_DIR}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_selinux() {
    if ! command -v getenforce >/dev/null 2>&1; then
        log_error "SELinux tools not found. Please install policycoreutils-python-utils"
        exit 1
    fi

    if [ "$(getenforce)" = "Disabled" ]; then
        log_warn "SELinux is disabled. These policies will have no effect."
        return 1
    fi

    log_info "SELinux is $(getenforce)"
    return 0
}

generate_container_policy() {
    local service_name="$1"
    local policy_file="${POLICY_DIR}/${service_name}.te"

    log_info "Generating SELinux policy for ${service_name}..."

    cat > "${policy_file}" << EOF
policy_module(${service_name//-/_}, 1.0.0)

require {
    type container_runtime_t;
    type container_t;
    type container_device_t;
    type devtty_t;
    type sysctl_net_t;
    type proc_net_t;
    type container_file_t;
    class chr_file { read write open ioctl };
    class file { read write open };
    class dir search;
    class sock_file write;
}

# Allow container to access serial devices
allow container_t container_device_t:chr_file { read write open ioctl };

# Allow container to access tty devices
allow container_t devtty_t:chr_file { read write open ioctl };

# Allow network access for MQTT
allow container_t sysctl_net_t:file read;
allow container_t proc_net_t:file read;

# Allow container runtime to manage container files
allow container_runtime_t container_file_t:file { read write open };
EOF

    log_info "Generated policy file: ${policy_file}"
}

compile_and_install_policy() {
    local service_name="$1"
    local policy_file="${POLICY_DIR}/${service_name}.te"
    local policy_pp="${POLICY_DIR}/${service_name}.pp"

    if [ ! -f "${policy_file}" ]; then
        log_error "Policy file ${policy_file} not found"
        return 1
    fi

    log_info "Compiling SELinux policy for ${service_name}..."

    if ! checkmodule -M -m -o "${policy_file%.*}.mod" "${policy_file}"; then
        log_error "Failed to compile policy module"
        return 1
    fi

    if ! semodule_package -o "${policy_pp}" -m "${policy_file%.*}.mod"; then
        log_error "Failed to package policy module"
        return 1
    fi

    log_info "Installing SELinux policy for ${service_name}..."
    if ! semodule -i "${policy_pp}"; then
        log_error "Failed to install policy module"
        return 1
    fi

    log_info "SELinux policy for ${service_name} installed successfully"

    # Clean up temporary files
    rm -f "${policy_file%.*}.mod" "${policy_pp}"
}

set_file_contexts() {
    log_info "Setting file contexts for device files..."

    # Set context for device symlinks
    if ! semanage fcontext -a -t container_device_t "/dev/ttyUSB_SCALE" 2>/dev/null; then
        log_warn "File context for /dev/ttyUSB_SCALE already exists or failed to set"
    fi

    if ! semanage fcontext -a -t container_device_t "/dev/ttyUSB_PRINTER" 2>/dev/null; then
        log_warn "File context for /dev/ttyUSB_PRINTER already exists or failed to set"
    fi

    # Restore contexts
    if [ -e "/dev/ttyUSB_SCALE" ]; then
        restorecon -v /dev/ttyUSB_SCALE
    fi

    if [ -e "/dev/ttyUSB_PRINTER" ]; then
        restorecon -v /dev/ttyUSB_PRINTER
    fi
}

enable_container_selinux_booleans() {
    log_info "Enabling necessary SELinux booleans for containers..."

    # Allow containers to use host devices
    setsebool -P container_use_cephfs on 2>/dev/null || true
    setsebool -P virt_use_serial on 2>/dev/null || true

    log_info "SELinux booleans configured"
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] [COMMAND]

Commands:
    generate     Generate SELinux policy files
    install      Compile and install SELinux policies
    contexts     Set file contexts for device files
    booleans     Enable necessary SELinux booleans
    all          Run all commands (default)
    clean        Remove generated policy files

Options:
    -h, --help   Show this help message

Examples:
    $0                    # Run all setup steps
    $0 generate           # Only generate policy files
    $0 install            # Only install policies
    $0 clean              # Clean up generated files
EOF
}

clean_policies() {
    log_info "Cleaning up generated policy files..."
    rm -f "${POLICY_DIR}"/*.te "${POLICY_DIR}"/*.mod "${POLICY_DIR}"/*.pp
    log_info "Cleanup completed"
}

main() {
    local command="${1:-all}"

    case "$command" in
        -h|--help)
            show_usage
            exit 0
            ;;
        generate)
            check_selinux || true
            generate_container_policy "scale-daemon"
            generate_container_policy "printer-daemon"
            ;;
        install)
            check_selinux
            compile_and_install_policy "scale-daemon"
            compile_and_install_policy "printer-daemon"
            ;;
        contexts)
            check_selinux
            set_file_contexts
            ;;
        booleans)
            check_selinux
            enable_container_selinux_booleans
            ;;
        all)
            check_selinux || true
            generate_container_policy "scale-daemon"
            generate_container_policy "printer-daemon"
            if check_selinux; then
                compile_and_install_policy "scale-daemon"
                compile_and_install_policy "printer-daemon"
                set_file_contexts
                enable_container_selinux_booleans
            fi
            ;;
        clean)
            clean_policies
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Check if running as root for operations that require it
if [[ "$1" =~ ^(install|contexts|booleans|all)$ ]] && [ "$EUID" -ne 0 ]; then
    log_error "This operation requires root privileges. Please run with sudo."
    exit 1
fi

main "$@"
