#!/usr/bin/env python3
"""
🛠️ Advanced System Installer & Dependency Manager
=================================================
Comprehensive installation and setup system for MTProto Proxy Manager
"""

import asyncio
import os
import subprocess
import platform
import shutil
import urllib.request
import urllib.error
import tarfile
import zipfile
import tempfile
import logging
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from datetime import datetime
import json
import secrets
import socket
class SystemDetector:
    """Advanced system detection and compatibility checking"""
    
    @staticmethod
    def detect_os() -> Dict[str, str]:
        """Detect operating system details"""
        os_info = {
            'system': platform.system().lower(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'architecture': platform.architecture()[0]
        }
        
        # Linux distribution detection
        if os_info['system'] == 'linux':
            os_info.update(SystemDetector._detect_linux_distro())
        
        return os_info
    
    @staticmethod
    def _detect_linux_distro() -> Dict[str, str]:
        """Detect Linux distribution details"""
        distro_info = {}
        
        # Try /etc/os-release first
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        distro_info[key.lower()] = value.strip('"')
        
        # Try other methods if os-release is not available
        distro_files = {
            '/etc/redhat-release': 'redhat',
            '/etc/debian_version': 'debian',
            '/etc/centos-release': 'centos',
            '/etc/fedora-release': 'fedora'
        }
        
        for file_path, distro_type in distro_files.items():
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    distro_info['name'] = f.read().strip()
                    distro_info['id'] = distro_type
                break
        
        return distro_info
    
    @staticmethod
    def detect_package_manager() -> Optional[str]:
        """Detect available package manager"""
        package_managers = {
            'apt': ['/usr/bin/apt', '/usr/bin/apt-get'],
            'yum': ['/usr/bin/yum', '/bin/yum'],
            'dnf': ['/usr/bin/dnf', '/bin/dnf'],
            'pacman': ['/usr/bin/pacman'],
            'apk': ['/sbin/apk'],
            'zypper': ['/usr/bin/zypper'],
            'portage': ['/usr/bin/emerge'],
            'homebrew': ['/usr/local/bin/brew', '/opt/homebrew/bin/brew']
        }
        
        for manager, paths in package_managers.items():
            for path in paths:
                if os.path.exists(path) and os.access(path, os.X_OK):
                    return manager
        
        return None
    
    @staticmethod
    def check_system_requirements() -> Dict[str, Any]:
        """Check system requirements and compatibility"""
        requirements = {
            'python_version': {
                'required': '3.7.0',
                'current': platform.python_version(),
                'satisfied': False
            },
            'memory': {
                'required_mb': 512,
                'current_mb': 0,
                'satisfied': False
            },
            'disk_space': {
                'required_mb': 1024,
                'current_mb': 0,
                'satisfied': False
            },
            'network': {
                'required': True,
                'satisfied': False
            },
            'permissions': {
                'root_required': False,
                'has_root': os.geteuid() == 0 if hasattr(os, 'geteuid') else False
            }
        }
        
        # Check Python version
        try:
            current_version = tuple(map(int, platform.python_version().split('.')))
            required_version = tuple(map(int, requirements['python_version']['required'].split('.')))
            requirements['python_version']['satisfied'] = current_version >= required_version
        except:
            requirements['python_version']['satisfied'] = False
        
        # Check memory
        try:
            import psutil
            memory = psutil.virtual_memory()
            requirements['memory']['current_mb'] = memory.total // (1024 * 1024)
            requirements['memory']['satisfied'] = requirements['memory']['current_mb'] >= requirements['memory']['required_mb']
        except ImportError:
            # Fallback method for systems without psutil
            try:
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemTotal:'):
                            memory_kb = int(line.split()[1])
                            requirements['memory']['current_mb'] = memory_kb // 1024
                            requirements['memory']['satisfied'] = requirements['memory']['current_mb'] >= requirements['memory']['required_mb']
                            break
            except:
                pass
        
        # Check disk space
        try:
            import shutil
            total, used, free = shutil.disk_usage('/')
            requirements['disk_space']['current_mb'] = free // (1024 * 1024)
            requirements['disk_space']['satisfied'] = requirements['disk_space']['current_mb'] >= requirements['disk_space']['required_mb']
        except:
            pass
        
        # Check network connectivity
        try:
            response = urllib.request.urlopen('https://www.google.com', timeout=5)
            requirements['network']['satisfied'] = response.getcode() == 200
        except:
            requirements['network']['satisfied'] = False
        
        return requirements

class DependencyManager:
    """Advanced dependency management and installation"""
    
    def __init__(self):
        self.os_info = SystemDetector.detect_os()
        self.package_manager = SystemDetector.detect_package_manager()
        self.logger = logging.getLogger('dependency-manager')
        # System performance validation
        self.performance_checks = {
            'tcp_bbr_available': self._check_tcp_bbr(),
            'huge_pages_enabled': self._check_huge_pages(),
            'numa_topology': self._get_numa_topology(),
            'disk_scheduler': self._get_disk_scheduler(),
            'network_interfaces': self._get_network_interfaces()
        }
        
        # Security validation
        self.security_checks = {
            'selinux_status': self._check_selinux(),
            'apparmor_status': self._check_apparmor(),
            'firewall_status': self._check_firewall_status(),
            'kernel_version': self._get_kernel_version()
        }
    
    def _check_tcp_bbr(self) -> bool:
        """Check if TCP BBR congestion control is available"""
        try:
            with open('/proc/sys/net/ipv4/tcp_available_congestion_control', 'r') as f:
                available = f.read().strip()
                return 'bbr' in available
        except:
            return False
    
    def _check_huge_pages(self) -> Dict[str, Any]:
        """Check huge pages configuration"""
        try:
            with open('/proc/meminfo', 'r') as f:
                content = f.read()
                
            huge_pages_info = {}
            for line in content.split('\n'):
                if 'HugePages' in line or 'Hugepagesize' in line:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        huge_pages_info[key] = value
            
            return huge_pages_info
        except:
            return {}
    
    def _get_numa_topology(self) -> Dict[str, Any]:
        """Get NUMA topology information"""
        numa_info = {'available': False, 'nodes': 0}
        
        try:
            if os.path.exists('/sys/devices/system/node'):
                nodes = list(Path('/sys/devices/system/node').glob('node*'))
                numa_info['available'] = len(nodes) > 1
                numa_info['nodes'] = len(nodes)
                
                # Get CPU-to-node mapping
                cpu_mapping = {}
                for node_dir in nodes:
                    node_id = node_dir.name.replace('node', '')
                    cpulist_file = node_dir / 'cpulist'
                    if cpulist_file.exists():
                        with open(cpulist_file, 'r') as f:
                            cpus = f.read().strip()
                            cpu_mapping[node_id] = cpus
                
                numa_info['cpu_mapping'] = cpu_mapping
        except:
            pass
        
        return numa_info
    
    def _get_disk_scheduler(self) -> Dict[str, str]:
        """Get I/O scheduler for each disk"""
        schedulers = {}
        
        try:
            for device in Path('/sys/block').glob('sd*'):
                scheduler_file = device / 'queue/scheduler'
                if scheduler_file.exists():
                    with open(scheduler_file, 'r') as f:
                        content = f.read().strip()
                        # Extract current scheduler (between brackets)
                        import re
                        match = re.search(r'\[([^\]]+)\]', content)
                        if match:
                            schedulers[device.name] = match.group(1)
        except:
            pass
        
        return schedulers
    
    def _get_network_interfaces(self) -> List[Dict[str, Any]]:
        """Get network interface information"""
        interfaces = []
        
        try:
            import socket
            import fcntl
            import struct
            
            # Get all network interfaces
            with open('/proc/net/dev', 'r') as f:
                lines = f.readlines()[2:]  # Skip header lines
            
            for line in lines:
                parts = line.split(':')
                if len(parts) >= 2:
                    interface_name = parts[0].strip()
                    if interface_name == 'lo':  # Skip loopback
                        continue
                    
                    # Get interface details
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        
                        # Get IP address
                        try:
                            ip_addr = socket.inet_ntoa(fcntl.ioctl(
                                s.fileno(),
                                0x8915,  # SIOCGIFADDR
                                struct.pack('256s', interface_name[:15].encode())
                            )[20:24])
                        except:
                            ip_addr = 'N/A'
                        
                        # Get MAC address
                        try:
                            mac_addr = ':'.join(['%02x' % b for b in fcntl.ioctl(
                                s.fileno(),
                                0x8927,  # SIOCGIFHWADDR
                                struct.pack('256s', interface_name[:15].encode())
                            )[18:24]])
                        except:
                            mac_addr = 'N/A'
                        
                        s.close()
                        
                        interfaces.append({
                            'name': interface_name,
                            'ip_address': ip_addr,
                            'mac_address': mac_addr
                        })
                        
                    except:
                        continue
        except:
            pass
        
        return interfaces
    
    def _check_selinux(self) -> str:
        """Check SELinux status"""
        try:
            result = subprocess.run(['getenforce'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip().lower()
        except:
            pass
        return 'not_available'
    
    def _check_apparmor(self) -> str:
        """Check AppArmor status"""
        try:
            result = subprocess.run(['aa-status'], capture_output=True, text=True)
            if result.returncode == 0:
                return 'enabled'
            else:
                return 'disabled'
        except:
            return 'not_available'
    
    def _check_firewall_status(self) -> Dict[str, Any]:
        """Check firewall status"""
        firewall_info = {}
        
        # Check UFW
        try:
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
            if result.returncode == 0:
                firewall_info['ufw'] = 'active' if 'Status: active' in result.stdout else 'inactive'
        except:
            firewall_info['ufw'] = 'not_available'
        
        # Check iptables
        try:
            result = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
            firewall_info['iptables'] = 'available' if result.returncode == 0 else 'not_available'
        except:
            firewall_info['iptables'] = 'not_available'
        
        # Check firewalld
        try:
            result = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True)
            firewall_info['firewalld'] = 'running' if result.returncode == 0 else 'not_running'
        except:
            firewall_info['firewalld'] = 'not_available'
        
        return firewall_info
    
    def _get_kernel_version(self) -> str:
        """Get kernel version"""
        try:
            with open('/proc/version', 'r') as f:
                return f.read().strip()
        except:
            return platform.release()

class SystemInstaller:
    """Complete system installer orchestrator"""
    
    def __init__(self):
        self.detector = SystemDetector()
        self.dependency_manager = DependencyManager()
        self.logger = logging.getLogger('system-installer')
        
        # Installation phases
        self.phases = [
            ('validation', self._validate_system),
            ('dependencies', self._install_dependencies),
            ('optimization', self._optimize_system),
            ('security', self._configure_security),
            ('services', self._setup_services),
            ('validation_final', self._final_validation)
        ]
    
    async def install(self, auto: bool = True, docker: bool = False, 
                     firewall: bool = True, optimize: bool = True, 
                     cluster: bool = False) -> bool:
        """Execute complete installation process"""
        
        print_colored("🚀 Starting MTProto Proxy Manager Installation", Colors.OKCYAN, bold=True)
        print_colored("="*70, Colors.OKCYAN)
        
        installation_config = {
            'auto': auto,
            'docker': docker,
            'firewall': firewall,
            'optimize': optimize,
            'cluster': cluster
        }
        
        self.logger.info(f"Starting installation with config: {installation_config}")
        
        # Execute installation phases
        for phase_name, phase_func in self.phases:
            try:
                print_colored(f"\n📋 Phase: {phase_name.title()}", Colors.OKBLUE, bold=True)
                
                success = await phase_func(installation_config)
                
                if success:
                    print_colored(f"✅ {phase_name.title()} completed successfully", Colors.OKGREEN)
                else:
                    print_colored(f"❌ {phase_name.title()} failed", Colors.FAIL)
                    if not auto:
                        user_input = input("Continue anyway? (y/N): ").lower()
                        if user_input != 'y':
                            return False
                    else:
                        self.logger.error(f"Installation failed at phase: {phase_name}")
                        return False
                        
            except Exception as e:
                print_colored(f"❌ Error in {phase_name}: {e}", Colors.FAIL)
                self.logger.error(f"Phase {phase_name} failed with error: {e}")
                if not auto:
                    user_input = input("Continue anyway? (y/N): ").lower()
                    if user_input != 'y':
                        return False
                else:
                    return False
        
        # Installation summary
        self._print_installation_summary()
        
        print_colored("\n🎉 Installation completed successfully!", Colors.OKGREEN, bold=True)
        print_colored("="*70, Colors.OKCYAN)
        
        return True
    
    async def _validate_system(self, config: Dict[str, Any]) -> bool:
        """Validate system requirements"""
        print_colored("🔍 Checking system requirements...", Colors.OKBLUE)
        
        # Get system information
        os_info = self.detector.detect_os()
        requirements = self.detector.check_system_requirements()
        
        print_colored(f"Operating System: {os_info.get('name', 'Unknown')}", Colors.OKBLUE)
        print_colored(f"Architecture: {os_info.get('machine', 'Unknown')}", Colors.OKBLUE)
        print_colored(f"Python Version: {requirements['python_version']['current']}", Colors.OKBLUE)
        
        # Check requirements
        failed_requirements = []
        
        for req_name, req_data in requirements.items():
            if isinstance(req_data, dict) and 'satisfied' in req_data:
                if not req_data['satisfied']:
                    failed_requirements.append(req_name)
                    print_colored(f"❌ {req_name}: {req_data}", Colors.FAIL)
                else:
                    print_colored(f"✅ {req_name}: OK", Colors.OKGREEN)
        
        if failed_requirements:
            print_colored(f"⚠️ Failed requirements: {', '.join(failed_requirements)}", Colors.WARNING)
            if not config['auto']:
                user_input = input("Continue despite failed requirements? (y/N): ").lower()
                return user_input == 'y'
            return False
        
        return True
    
    async def _install_dependencies(self, config: Dict[str, Any]) -> bool:
        """Install system and Python dependencies"""
        print_colored("📦 Installing dependencies...", Colors.OKBLUE)
        
        try:
            # Install system packages
            if not self.dependency_manager.install_system_packages():
                return False
            
            # Setup Python environment
            if not self.dependency_manager.setup_python_environment():
                return False
            
            # Install Docker if requested
            if config['docker']:
                await self._install_docker()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Dependency installation failed: {e}")
            return False
    
    async def _optimize_system(self, config: Dict[str, Any]) -> bool:
        """Optimize system for high performance"""
        if not config['optimize']:
            print_colored("⏩ Skipping system optimization", Colors.WARNING)
            return True
        
        print_colored("⚡ Optimizing system performance...", Colors.OKBLUE)
        
        try:
            return self.dependency_manager.optimize_system()
        except Exception as e:
            self.logger.error(f"System optimization failed: {e}")
            return False
    
    async def _configure_security(self, config: Dict[str, Any]) -> bool:
        """Configure security settings"""
        print_colored("🛡️ Configuring security...", Colors.OKBLUE)
        
        try:
            if config['firewall']:
                return self.dependency_manager.setup_firewall()
            return True
        except Exception as e:
            self.logger.error(f"Security configuration failed: {e}")
            return False
    
    async def _setup_services(self, config: Dict[str, Any]) -> bool:
        """Setup system services"""
        print_colored("🔧 Setting up services...", Colors.OKBLUE)
        
        try:
            # Create systemd service
            await self._create_systemd_service()
            
            # Setup log rotation
            await self._setup_log_rotation()
            
            # Setup monitoring
            await self._setup_monitoring()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Service setup failed: {e}")
            return False
    
    async def _final_validation(self, config: Dict[str, Any]) -> bool:
        """Final validation of installation"""
        print_colored("✅ Performing final validation...", Colors.OKBLUE)
        
        try:
            # Test Python environment
            venv_python = Path.home() / 'mtproxy' / 'venv' / 'bin' / 'python'
            if venv_python.exists():
                result = subprocess.run([str(venv_python), '-c', 'import aiohttp; print("OK")'], 
                                      capture_output=True, text=True)
                if result.returncode != 0:
                    print_colored("❌ Python environment validation failed", Colors.FAIL)
                    return False
            
            # Check required directories
            required_dirs = ['logs', 'data', 'config', 'cache', 'backups']
            for dir_name in required_dirs:
                dir_path = Path.cwd() / dir_name
                if not dir_path.exists():
                    dir_path.mkdir(parents=True)
            
            print_colored("✅ All validations passed", Colors.OKGREEN)
            return True
            
        except Exception as e:
            self.logger.error(f"Final validation failed: {e}")
            return False
    
    async def _install_docker(self):
        """Install Docker"""
        print_colored("🐳 Installing Docker...", Colors.OKBLUE)
        
        try:
            # Detect OS and install Docker accordingly
            os_info = self.detector.detect_os()
            
            if os_info.get('id') in ['ubuntu', 'debian']:
                commands = [
                    ['apt', 'update'],
                    ['apt', 'install', '-y', 'apt-transport-https', 'ca-certificates', 'curl', 'gnupg', 'lsb-release'],
                    ['curl', '-fsSL', 'https://download.docker.com/linux/ubuntu/gpg', '|', 'gpg', '--dearmor', '-o', '/usr/share/keyrings/docker-archive-keyring.gpg'],
                    ['apt', 'update'],
                    ['apt', 'install', '-y', 'docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-compose-plugin']
                ]
            elif os_info.get('id') in ['centos', 'rhel', 'fedora']:
                commands = [
                    ['yum', 'install', '-y', 'yum-utils'],
                    ['yum-config-manager', '--add-repo', 'https://download.docker.com/linux/centos/docker-ce.repo'],
                    ['yum', 'install', '-y', 'docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-compose-plugin']
                ]
            else:
                print_colored("⚠️ Docker installation not supported for this OS", Colors.WARNING)
                return
            
            for cmd in commands:
                if '|' in cmd:
                    # Handle pipe commands
                    subprocess.run(' '.join(cmd), shell=True, check=True)
                else:
                    subprocess.run(cmd, check=True)
            
            # Start and enable Docker
            subprocess.run(['systemctl', 'start', 'docker'], check=True)
            subprocess.run(['systemctl', 'enable', 'docker'], check=True)
            
            print_colored("✅ Docker installed successfully", Colors.OKGREEN)
            
        except Exception as e:
            print_colored(f"❌ Docker installation failed: {e}", Colors.FAIL)
    
    async def _create_systemd_service(self):
        """Create systemd service file"""
        service_content = f"""[Unit]
Description=MTProto Proxy Manager v4.0
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={os.getenv('SUDO_USER', os.getenv('USER', 'root'))}
Group={os.getenv('SUDO_USER', os.getenv('USER', 'root'))}
WorkingDirectory={os.getcwd()}
ExecStart={Path.home() / 'mtproxy' / 'venv' / 'bin' / 'python'} main.py run-all
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mtproxy-manager

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={os.getcwd()}

# Resource limits
LimitNOFILE=1048576
LimitNPROC=1048576

# Environment
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH={os.getcwd()}

[Install]
WantedBy=multi-user.target
"""
        
        try:
            with open('/etc/systemd/system/mtproxy-manager.service', 'w') as f:
                f.write(service_content)
            
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            subprocess.run(['systemctl', 'enable', 'mtproxy-manager'], check=True)
            
            print_colored("✅ Systemd service created", Colors.OKGREEN)
            
        except Exception as e:
            print_colored(f"⚠️ Failed to create systemd service: {e}", Colors.WARNING)
    
    async def _setup_log_rotation(self):
        """Setup log rotation"""
        logrotate_config = f"""{os.getcwd()}/logs/*.log {{
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    create 644 {os.getenv('USER', 'root')} {os.getenv('USER', 'root')}
}}
"""
        
        try:
            with open('/etc/logrotate.d/mtproxy-manager', 'w') as f:
                f.write(logrotate_config)
            
            print_colored("✅ Log rotation configured", Colors.OKGREEN)
            
        except Exception as e:
            print_colored(f"⚠️ Failed to setup log rotation: {e}", Colors.WARNING)
    
    async def _setup_monitoring(self):
        """Setup basic monitoring"""
        try:
            # Create monitoring script
            monitor_script = f"""#!/bin/bash
# MTProxy Manager monitoring script

LOG_FILE="/var/log/mtproxy-monitor.log"
SERVICE_NAME="mtproxy-manager"

echo "$(date): Checking $SERVICE_NAME" >> $LOG_FILE

if ! systemctl is-active --quiet $SERVICE_NAME; then
    echo "$(date): $SERVICE_NAME is not running, attempting restart" >> $LOG_FILE
    systemctl restart $SERVICE_NAME
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo "$(date): $SERVICE_NAME restarted successfully" >> $LOG_FILE
    else
        echo "$(date): Failed to restart $SERVICE_NAME" >> $LOG_FILE
    fi
else
    echo "$(date): $SERVICE_NAME is running normally" >> $LOG_FILE
fi
"""
            
            monitor_path = Path('/usr/local/bin/mtproxy-monitor.sh')
            with open(monitor_path, 'w') as f:
                f.write(monitor_script)
            
            monitor_path.chmod(0o755)
            
            # Add to crontab (check every 5 minutes)
            cron_entry = "*/5 * * * * /usr/local/bin/mtproxy-monitor.sh\n"
            
            # Add to root crontab
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            current_cron = result.stdout if result.returncode == 0 else ""
            
            if 'mtproxy-monitor.sh' not in current_cron:
                new_cron = current_cron + cron_entry
                subprocess.run(['crontab', '-'], input=new_cron, text=True)
            
            print_colored("✅ Monitoring setup completed", Colors.OKGREEN)
            
        except Exception as e:
            print_colored(f"⚠️ Failed to setup monitoring: {e}", Colors.WARNING)
    
    def _print_installation_summary(self):
        """Print installation summary"""
        print_colored("\n📋 Installation Summary", Colors.OKCYAN, bold=True)
        print_colored("="*50, Colors.OKCYAN)
        
        # System info
        os_info = self.detector.detect_os()
        print_colored(f"📍 Installation Location: {os.getcwd()}", Colors.OKBLUE)
        print_colored(f"🖥️  Operating System: {os_info.get('name', 'Unknown')}", Colors.OKBLUE)
        print_colored(f"🏗️  Architecture: {os_info.get('machine', 'Unknown')}", Colors.OKBLUE)
        
        # Services
        print_colored(f"🔧 Systemd Service: mtproxy-manager.service", Colors.OKBLUE)
        print_colored(f"📁 Project Directory: {Path.home() / 'mtproxy'}", Colors.OKBLUE)
        print_colored(f"📊 Logs Directory: {os.getcwd()}/logs", Colors.OKBLUE)
        
        # Next steps
        print_colored("\n🚀 Next Steps:", Colors.OKGREEN, bold=True)
        print_colored("1. Create your first proxy:", Colors.OKGREEN)
        print_colored(f"   {Path.home() / 'mtproxy' / 'venv' / 'bin' / 'python'} main.py create 8080", Colors.OKBLUE)
        print_colored("2. Start all proxies:", Colors.OKGREEN)
        print_colored(f"   {Path.home() / 'mtproxy' / 'venv' / 'bin' / 'python'} main.py run-all", Colors.OKBLUE)
        print_colored("3. Or use systemd service:", Colors.OKGREEN)
        print_colored("   sudo systemctl start mtproxy-manager", Colors.OKBLUE)
        print_colored("4. Check status:", Colors.OKGREEN)
        print_colored(f"   {Path.home() / 'mtproxy' / 'venv' / 'bin' / 'python'} main.py status --detailed", Colors.OKBLUE)
        print_colored("5. Access web interface:", Colors.OKGREEN)
        print_colored("   http://your-server-ip:8080", Colors.OKBLUE)

def print_colored(text: str, color: str = "", bold: bool = False):
    """Print colored text (simplified version for installer)"""
    colors = {
        "Colors.HEADER": '\033[95m',
        "Colors.OKBLUE": '\033[94m', 
        "Colors.OKCYAN": '\033[96m',
        "Colors.OKGREEN": '\033[92m',
        "Colors.WARNING": '\033[93m',
        "Colors.FAIL": '\033[91m',
        "Colors.ENDC": '\033[0m',
        "Colors.BOLD": '\033[1m'
    }
    
    prefix = '\033[1m' if bold else ""
    color_code = colors.get(color, "")
    print(f"{prefix}{color_code}{text}\033[0m")

# Main installer entry point
async def main():
    """Main installer function"""
    
    print_colored("""
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║     🛠️ MTProto Proxy Manager v4.0 - System Installer 🛠️                ║
║                                                                          ║
║     Complete automated installation for Linux servers                    ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
    """, "Colors.OKCYAN", bold=True)
    
    parser = argparse.ArgumentParser(description='MTProto Proxy Manager Installer')
    parser.add_argument('--auto', action='store_true', help='Automatic installation')
    parser.add_argument('--docker', action='store_true', help='Install Docker')
    parser.add_argument('--no-firewall', action='store_true', help='Skip firewall configuration')
    parser.add_argument('--no-optimize', action='store_true', help='Skip system optimization')
    parser.add_argument('--cluster', action='store_true', help='Setup for cluster mode')
    
    args = parser.parse_args()
    
    installer = SystemInstaller()
    
    success = await installer.install(
        auto=args.auto,
        docker=args.docker,
        firewall=not args.no_firewall,
        optimize=not args.no_optimize,
        cluster=args.cluster
    )
    
    if success:
        print_colored("\n🎉 Installation completed successfully!", "Colors.OKGREEN", bold=True)
        print_colored("You can now start using MTProto Proxy Manager!", "Colors.OKGREEN")
    else:
        print_colored("\n❌ Installation failed!", "Colors.FAIL", bold=True)
        print_colored("Please check the logs and try again.", "Colors.FAIL")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
