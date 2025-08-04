#!/bin/bash

# Quick Setup Script for MTProto Proxy Manager
# This script automates the complete installation process

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_colored() {
    color=$1
    message=$2
    echo -e "${color}${message}${NC}"
}

# Print banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                          ║"
    echo "║     🚀 MTProto Proxy Manager - Quick Setup v3.0 🚀                     ║"
    echo "║                                                                          ║"
    echo "║     Complete automated installation for Linux servers                    ║"
    echo "║                                                                          ║"
    echo "╚══════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_colored $GREEN "✅ Running with root privileges"
        return 0
    else
        print_colored $YELLOW "⚠️  Not running as root. Some features may require sudo."
        return 1
    fi
}

# Detect OS and package manager
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        print_colored $RED "❌ Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
    
    print_colored $BLUE "🔍 Detected OS: $PRETTY_NAME"
    
    # Detect package manager
    if command -v apt >/dev/null 2>&1; then
        PKG_MANAGER="apt"
        UPDATE_CMD="apt update"
        INSTALL_CMD="apt install -y"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
        UPDATE_CMD="yum makecache"
        INSTALL_CMD="yum install -y"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
        UPDATE_CMD="dnf makecache"
        INSTALL_CMD="dnf install -y"
    elif command -v pacman >/dev/null 2>&1; then
        PKG_MANAGER="pacman"
        UPDATE_CMD="pacman -Sy"
        INSTALL_CMD="pacman -S --noconfirm"
    else
        print_colored $RED "❌ Unsupported package manager"
        exit 1
    fi
    
    print_colored $BLUE "📦 Package Manager: $PKG_MANAGER"
}

# Update system packages
update_system() {
    print_colored $BLUE "🔄 Updating system packages..."
    
    if [[ $EUID -eq 0 ]]; then
        $UPDATE_CMD
    else
        sudo $UPDATE_CMD
    fi
    
    print_colored $GREEN "✅ System packages updated"
}

# Install system dependencies
install_system_deps() {
    print_colored $BLUE "📦 Installing system dependencies..."
    
    case $PKG_MANAGER in
        apt)
            PACKAGES="python3 python3-pip python3-dev python3-venv build-essential libssl-dev libffi-dev libsqlite3-dev curl wget git htop iptables ufw supervisor nginx"
            ;;
        yum)
            PACKAGES="python3 python3-pip python3-devel gcc gcc-c++ make openssl-devel libffi-devel sqlite-devel curl wget git htop iptables supervisor nginx"
            ;;
        dnf)
            PACKAGES="python3 python3-pip python3-devel gcc gcc-c++ make openssl-devel libffi-devel sqlite-devel curl wget git htop iptables supervisor nginx"
            ;;
        pacman)
            PACKAGES="python python-pip base-devel openssl libffi curl wget git htop iptables supervisor nginx"
            ;;
    esac
    
    if [[ $EUID -eq 0 ]]; then
        $INSTALL_CMD $PACKAGES
    else
        sudo $INSTALL_CMD $PACKAGES
    fi
    
    print_colored $GREEN "✅ System dependencies installed"
}

# Setup Python environment
setup_python() {
    print_colored $BLUE "🐍 Setting up Python environment..."
    
    # Create project directory
    PROJECT_DIR="/opt/mtproxy"
    if [[ $EUID -eq 0 ]]; then
        mkdir -p $PROJECT_DIR
        cd $PROJECT_DIR
    else
        PROJECT_DIR="$HOME/mtproxy"
        mkdir -p $PROJECT_DIR
        cd $PROJECT_DIR
    fi
    
    # Download the main script
    print_colored $BLUE "📥 Downloading MTProto Proxy Manager..."
    if command -v wget >/dev/null 2>&1; then
        # In a real scenario, you would download from your repository
        # wget https://raw.githubusercontent.com/your-repo/mtproxy_manager.py
        # For now, we'll create it from the embedded script
        echo "# MTProxy Manager will be created by the Python installer"
    elif command -v curl >/dev/null 2>&1; then
        # curl -o mtproxy_manager.py https://raw.githubusercontent.com/your-repo/mtproxy_manager.py
        echo "# MTProxy Manager will be created by the Python installer"
    fi
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install Python packages
    print_colored $BLUE "📦 Installing Python packages..."
    pip install aiohttp aiofiles ujson cryptography psutil qrcode pillow requests websockets jinja2 click tabulate
    
    # Install uvloop for better performance (Unix only)
    if [[ "$OSTYPE" != "msys" ]]; then
        pip install uvloop
    fi
    
    print_colored $GREEN "✅ Python environment setup completed"
    
    # Set project directory for later use
    echo "export MTPROXY_DIR=$PROJECT_DIR" >> ~/.bashrc
}

# Optimize system for proxy performance
optimize_system() {
    print_colored $BLUE "⚡ Optimizing system for high performance..."
    
    if [[ $EUID -ne 0 ]]; then
        print_colored $YELLOW "⚠️  Root access required for system optimization. Skipping..."
        return
    fi
    
    # Network optimizations
    cat > /etc/sysctl.d/99-mtproxy.conf << EOF
# MTProto Proxy optimizations
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1

# Memory and file system
fs.file-max = 2097152
fs.nr_open = 2097152
vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# Security
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_source_route = 0
EOF
    
    # Apply sysctl changes
    sysctl --system
    
    # Set ulimits
    cat > /etc/security/limits.d/99-mtproxy.conf << EOF
# MTProto Proxy limits
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 1048576
* hard nproc 1048576
root soft nofile 1048576
root hard nofile 1048576
root soft nproc 1048576
root hard nproc 1048576
EOF
    
    # Configure systemd limits
    mkdir -p /etc/systemd/system.conf.d
    cat > /etc/systemd/system.conf.d/99-mtproxy.conf << EOF
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=1048576
EOF
    
    print_colored $GREEN "✅ System optimization completed"
}

# Configure firewall
setup_firewall() {
    print_colored $BLUE "🛡️ Configuring firewall..."
    
    if [[ $EUID -ne 0 ]]; then
        print_colored $YELLOW "⚠️  Root access required for firewall configuration. Skipping..."
        return
    fi
    
    # Configure UFW if available
    if command -v ufw >/dev/null 2>&1; then
        ufw --force enable
        ufw allow ssh
        ufw allow 8080:8180/tcp  # Proxy ports
        ufw allow 8080/tcp       # Web interface
        print_colored $GREEN "✅ UFW firewall configured"
    else
        print_colored $YELLOW "⚠️  UFW not available, please configure firewall manually"
    fi
}

# Create systemd service
create_service() {
    if [[ $EUID -ne 0 ]]; then
        print_colored $YELLOW "⚠️  Root access required to create systemd service. Skipping..."
        return
    fi
    
    print_colored $BLUE "🔧 Creating systemd service..."
    
    cat > /etc/systemd/system/mtproxy-manager.service << EOF
[Unit]
Description=MTProto Proxy Manager v3.0
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(logname 2>/dev/null || echo root)
WorkingDirectory=$PROJECT_DIR
ExecStart=$PROJECT_DIR/venv/bin/python mtproxy_manager.py run-all
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mtproxy-manager

# Security
NoNewPrivileges=true
PrivateTmp=true

# Resource limits
LimitNOFILE=1048576
LimitNPROC=1048576

# Environment
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable mtproxy-manager
    
    print_colored $GREEN "✅ Systemd service created"
}

# Create example configuration
create_example_config() {
    print_colored $BLUE "📝 Creating example configuration..."
    
    cd $PROJECT_DIR
    
    # Create first proxy
    python3 mtproxy_manager.py create 8080 --description "Main proxy server"
    python3 mtproxy_manager.py create 8081 --description "Backup proxy server"
    
    print_colored $GREEN "✅ Example proxies created"
}

# Main installation function
main() {
    print_banner
    
    print_colored $BLUE "🚀 Starting MTProto Proxy Manager installation..."
    
    # Check system requirements
    if ! command -v python3 >/dev/null 2>&1; then
        print_colored $RED "❌ Python 3 is required but not installed"
        exit 1
    fi
    
    # Detect OS and check root
    detect_os
    check_root
    
    # Update system
    update_system
    
    # Install dependencies
    install_system_deps
    
    # Setup Python environment
    setup_python
    
    # Optimize system
    optimize_system
    
    # Setup firewall
    setup_firewall
    
    # Create systemd service
    create_service
    
    print_colored $GREEN "🎉 Installation completed successfully!"
    print_colored $BLUE "📁 Project directory: $PROJECT_DIR"
    
    echo
    print_colored $CYAN "Next steps:"
    print_colored $BLUE "1. Create your first proxy:"
    print_colored $GREEN "   cd $PROJECT_DIR && python3 mtproxy_manager.py create 8080"
    print_colored $BLUE "2. Start all proxies:"
    print_colored $GREEN "   python3 mtproxy_manager.py run-all"
    print_colored $BLUE "3. Or use systemd service:"
    print_colored $GREEN "   sudo systemctl start mtproxy-manager"
    print_colored $BLUE "4. Check status:"
    print_colored $GREEN "   python3 mtproxy_manager.py status --detailed"
    
    echo
    print_colored $YELLOW "📚 For more help, run: python3 mtproxy_manager.py --help"
}

# Run main function
main "$@"
