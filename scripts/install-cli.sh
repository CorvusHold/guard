#!/bin/bash

# Guard CLI Installation Script
# This script downloads and installs the Guard CLI tool

set -e

# Configuration
REPO="corvushold/guard"
BINARY_NAME="guard-cli"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="$HOME/.guard-cli"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect OS and architecture
detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    case $os in
        linux*)
            OS="linux"
            ;;
        darwin*)
            OS="darwin"
            ;;
        *)
            log_error "Unsupported operating system: $os"
            exit 1
            ;;
    esac
    
    case $arch in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
    
    PLATFORM="${OS}-${ARCH}"
    log_info "Detected platform: $PLATFORM"
}

# Get latest release version
get_latest_version() {
    log_info "Fetching latest release information..."
    
    if command -v curl >/dev/null 2>&1; then
        VERSION=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    elif command -v wget >/dev/null 2>&1; then
        VERSION=$(wget -qO- "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        log_error "Neither curl nor wget is available. Please install one of them."
        exit 1
    fi
    
    if [ -z "$VERSION" ]; then
        log_error "Failed to get latest version"
        exit 1
    fi
    
    log_info "Latest version: $VERSION"
}

# Download binary
download_binary() {
    local download_url="https://github.com/$REPO/releases/download/$VERSION/${BINARY_NAME}-${PLATFORM}"
    local temp_file="/tmp/${BINARY_NAME}-${PLATFORM}"
    
    log_info "Downloading $BINARY_NAME from $download_url"
    
    if command -v curl >/dev/null 2>&1; then
        curl -L "$download_url" -o "$temp_file"
    elif command -v wget >/dev/null 2>&1; then
        wget "$download_url" -O "$temp_file"
    else
        log_error "Neither curl nor wget is available"
        exit 1
    fi
    
    if [ ! -f "$temp_file" ]; then
        log_error "Failed to download binary"
        exit 1
    fi
    
    # Make executable
    chmod +x "$temp_file"
    
    log_success "Binary downloaded successfully"
    echo "$temp_file"
}

# Install binary
install_binary() {
    local temp_file="$1"
    local install_path="$INSTALL_DIR/$BINARY_NAME"
    
    log_info "Installing $BINARY_NAME to $install_path"
    
    # Check if we need sudo
    if [ -w "$INSTALL_DIR" ]; then
        mv "$temp_file" "$install_path"
    else
        log_info "Installing to system directory requires sudo privileges"
        sudo mv "$temp_file" "$install_path"
    fi
    
    log_success "$BINARY_NAME installed successfully"
}

# Verify installation
verify_installation() {
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        local version_output=$($BINARY_NAME --version 2>/dev/null || echo "unknown")
        log_success "$BINARY_NAME is installed and available in PATH"
        log_info "Version: $version_output"
        return 0
    else
        log_warning "$BINARY_NAME is not in PATH. You may need to add $INSTALL_DIR to your PATH"
        return 1
    fi
}

# Setup configuration
setup_config() {
    log_info "Setting up configuration..."
    
    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
        log_info "Created configuration directory: $CONFIG_DIR"
    fi
    
    # Check if config already exists
    if [ -f "$HOME/.guard-cli.yaml" ]; then
        log_info "Configuration file already exists at $HOME/.guard-cli.yaml"
        read -p "Do you want to reconfigure? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    # Interactive configuration
    echo
    log_info "Let's configure Guard CLI..."
    
    read -p "Guard API URL [http://localhost:8080]: " api_url
    api_url=${api_url:-http://localhost:8080}
    
    read -p "API Token (optional): " api_token
    
    read -p "Default Tenant ID (optional): " tenant_id
    
    # Create config file
    cat > "$HOME/.guard-cli.yaml" << EOF
api_url: "$api_url"
api_token: "$api_token"
tenant_id: "$tenant_id"
EOF
    
    log_success "Configuration saved to $HOME/.guard-cli.yaml"
}

# Test installation
test_installation() {
    log_info "Testing installation..."
    
    if $BINARY_NAME health >/dev/null 2>&1; then
        log_success "Guard CLI is working correctly!"
    else
        log_warning "Guard CLI installed but health check failed. This might be normal if the API is not running."
    fi
}

# Cleanup
cleanup() {
    log_info "Cleaning up temporary files..."
    rm -f "/tmp/${BINARY_NAME}-${PLATFORM}"
}

# Show usage information
show_usage() {
    echo "Guard CLI Installation Script"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -v, --version       Install specific version"
    echo "  -d, --dir           Installation directory (default: $INSTALL_DIR)"
    echo "  --no-config         Skip configuration setup"
    echo "  --no-test           Skip installation test"
    echo
    echo "Examples:"
    echo "  $0                  Install latest version with interactive setup"
    echo "  $0 -v v1.2.3        Install specific version"
    echo "  $0 -d ~/bin         Install to custom directory"
    echo "  $0 --no-config      Install without configuration setup"
}

# Main installation function
main() {
    local skip_config=false
    local skip_test=false
    local custom_version=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--version)
                custom_version="$2"
                shift 2
                ;;
            -d|--dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --no-config)
                skip_config=true
                shift
                ;;
            --no-test)
                skip_test=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    echo "Guard CLI Installation Script"
    echo "============================="
    echo
    
    # Detect platform
    detect_platform
    
    # Get version
    if [ -n "$custom_version" ]; then
        VERSION="$custom_version"
        log_info "Installing version: $VERSION"
    else
        get_latest_version
    fi
    
    # Download and install
    temp_file=$(download_binary)
    install_binary "$temp_file"
    
    # Verify installation
    if verify_installation; then
        # Setup configuration
        if [ "$skip_config" = false ]; then
            setup_config
        fi
        
        # Test installation
        if [ "$skip_test" = false ]; then
            test_installation
        fi
        
        echo
        log_success "Guard CLI installation completed!"
        echo
        echo "Next steps:"
        echo "1. Run 'guard-cli config init' to configure the CLI"
        echo "2. Run 'guard-cli health' to test connectivity"
        echo "3. Run 'guard-cli --help' to see available commands"
        echo
    else
        log_error "Installation verification failed"
        exit 1
    fi
    
    # Cleanup
    cleanup
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

# Run main function
main "$@"
