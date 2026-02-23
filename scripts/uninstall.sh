#!/bin/bash
#
# Kubelet-Proxy Uninstallation Script
#
# This script removes kubelet-proxy from a Kubernetes worker node VM
# and restores the original kubelet configuration.
#
# Usage:
#   sudo ./uninstall.sh [OPTIONS]
#
# Options:
#   --skip-kubelet-restart    Don't restart kubelet after uninstallation
#   --help                    Show this help message
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Configuration
PROXY_CERT_DIR="/etc/kubelet-proxy"
PROXY_BIN_PATH="/usr/local/bin/kubelet-proxy"
PROXY_KUBECONFIG="/etc/kubernetes/kubelet-via-proxy.conf"
KUBELET_DROPIN_DIR="/etc/systemd/system/kubelet.service.d"
KUBELET_DROPIN_FILE="$KUBELET_DROPIN_DIR/20-kubelet-proxy.conf"

SKIP_KUBELET_RESTART=false

usage() {
    head -20 "$0" | grep -E "^#" | sed 's/^# \?//'
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-kubelet-restart)
                SKIP_KUBELET_RESTART=true
                shift
                ;;
            --help|-h)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done
}

check_prerequisites() {
    log_step "Checking prerequisites..."

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi

    log_info "Prerequisites check passed"
}

uninstall() {
    log_step "Uninstalling kubelet-proxy..."

    # Stop and disable kubelet-proxy
    if systemctl is-active --quiet kubelet-proxy 2>/dev/null; then
        log_info "Stopping kubelet-proxy service..."
        systemctl stop kubelet-proxy
    fi

    if systemctl is-enabled --quiet kubelet-proxy 2>/dev/null; then
        log_info "Disabling kubelet-proxy service..."
        systemctl disable kubelet-proxy
    fi

    # Remove kubelet drop-in
    if [[ -f "$KUBELET_DROPIN_FILE" ]]; then
        log_info "Removing kubelet drop-in: $KUBELET_DROPIN_FILE"
        rm -f "$KUBELET_DROPIN_FILE"
    fi

    # Reload systemd and restart kubelet
    systemctl daemon-reload

    if [[ "$SKIP_KUBELET_RESTART" == "false" ]]; then
        if systemctl list-unit-files kubelet.service &>/dev/null && systemctl cat kubelet.service &>/dev/null; then
            log_info "Restarting kubelet with original configuration..."
            systemctl restart kubelet

            sleep 3

            if systemctl is-active --quiet kubelet; then
                log_info "kubelet is running with original configuration"
            else
                log_warn "kubelet may have issues after restart"
                systemctl status kubelet --no-pager || true
            fi
        else
            log_warn "kubelet.service not found, skipping kubelet restart"
        fi
    else
        log_warn "Skipping kubelet restart (--skip-kubelet-restart specified)"
        log_warn "You must manually restart kubelet:"
        log_warn "  sudo systemctl daemon-reload && sudo systemctl restart kubelet"
    fi

    # Remove files
    if [[ -f "$PROXY_BIN_PATH" ]]; then
        log_info "Removing binary: $PROXY_BIN_PATH"
        rm -f "$PROXY_BIN_PATH"
    fi

    if [[ -f /etc/systemd/system/kubelet-proxy.service ]]; then
        log_info "Removing service file: /etc/systemd/system/kubelet-proxy.service"
        rm -f /etc/systemd/system/kubelet-proxy.service
    fi

    if [[ -f "$PROXY_KUBECONFIG" ]]; then
        log_info "Removing proxy kubeconfig: $PROXY_KUBECONFIG"
        rm -f "$PROXY_KUBECONFIG"
    fi

    if [[ -d "$PROXY_CERT_DIR" ]]; then
        log_info "Removing certificate directory: $PROXY_CERT_DIR"
        rm -rf "$PROXY_CERT_DIR"
    fi

    # Final systemd reload
    systemctl daemon-reload

    log_info "kubelet-proxy uninstalled successfully"
}

print_success() {
    echo ""
    log_info "=========================================="
    log_info "  kubelet-proxy uninstalled successfully!"
    log_info "=========================================="
    echo ""
    echo "The following have been removed:"
    echo "  - kubelet-proxy binary"
    echo "  - kubelet-proxy systemd service"
    echo "  - TLS certificates"
    echo "  - Proxy kubeconfig"
    echo "  - Kubelet drop-in configuration"
    echo ""
    if [[ "$SKIP_KUBELET_RESTART" == "false" ]]; then
        echo "kubelet has been restarted with original configuration."
    else
        echo "Remember to restart kubelet manually:"
        echo "  sudo systemctl restart kubelet"
    fi
    echo ""
}

main() {
    parse_args "$@"

    echo ""
    log_info "=========================================="
    log_info "  kubelet-proxy Uninstallation Script"
    log_info "=========================================="
    echo ""

    check_prerequisites
    uninstall
    print_success
}

main "$@"
