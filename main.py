#!/usr/bin/env python3
"""
🚀 Advanced MTProto Proxy Manager v4.0
=====================================
Enterprise-grade Multi-Proxy Management System

Author: MTProxy Development Team
Version: 4.0.0
License: MIT
Repository: https://github.com/mtproxy/manager
"""

import asyncio
import sys
import os
import argparse
import signal
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import json

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

# Import project modules
try:
    from proxy_core import ProxyManager, ProxyServer, ProxyConfig
    from database_manager import DatabaseManager, StatsCollector
    from web_interface import WebInterface, APIManager
    from config_manager import ConfigManager, SystemOptimizer
    from installer import SystemInstaller, DependencyManager
except ImportError as e:
    print(f"❌ Failed to import modules: {e}")
    print("Please ensure all files are in the same directory")
    sys.exit(1)

# Version and metadata
__version__ = "4.0.0"
__author__ = "MTProxy Development Team"
__license__ = "MIT"

class Colors:
    """ANSI color codes for beautiful terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'

def print_colored(text: str, color: str = Colors.ENDC, bold: bool = False):
    """Print colored text with optional bold formatting"""
    prefix = Colors.BOLD if bold else ""
    print(f"{prefix}{color}{text}{Colors.ENDC}")

def print_banner():
    """Display application banner with version information"""
    banner = f"""
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║     🚀 Advanced MTProto Proxy Manager v{__version__:<8} 🚀                     ║
║                                                                          ║
║     ⚡ Enterprise Multi-Proxy Management                                 ║
║     🛡️  Advanced Security & Performance                                  ║
║     📊 Real-time Analytics & Monitoring                                  ║
║     🌐 Modern Web Interface & API                                        ║
║     🐳 Docker & Kubernetes Ready                                         ║
║     💰 Sponsored Channels Integration                                    ║
║                                                                          ║
║     Built for Scale, Performance & Reliability                           ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
    """
    print_colored(banner, Colors.OKCYAN, bold=True)

class MTProxyApplication:
    """Main application class orchestrating all components"""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.db_manager = DatabaseManager()
        self.proxy_manager = ProxyManager(self.db_manager, self.config_manager)
        self.web_interface = WebInterface(self.proxy_manager, self.db_manager)
        self.stats_collector = StatsCollector(self.db_manager)
        
        # Application state
        self.running = False
        self.tasks = []
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Setup signal handlers
        self._setup_signal_handlers()
    
    def _setup_logging(self):
        """Setup comprehensive logging system"""
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # Create logger
        logger = logging.getLogger('mtproxy-app')
        logger.setLevel(logging.INFO)
        
        # File handler with rotation
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_dir / 'application.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        logger.addHandler(file_handler)
        
        # Console handler for important messages
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(logging.Formatter(
            '%(levelname)s: %(message)s'
        ))
        logger.addHandler(console_handler)
        
        return logger
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            print_colored(f"\n🛑 Received signal {signum}. Shutting down gracefully...", Colors.WARNING)
            asyncio.create_task(self.shutdown())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def startup(self):
        """Application startup sequence"""
        self.logger.info("Starting MTProto Proxy Manager v4.0")
        
        try:
            # Initialize database
            await self.db_manager.initialize()
            
            # Load configuration
            await self.config_manager.load_config()
            
            # Initialize proxy manager
            await self.proxy_manager.initialize()
            
            # Start stats collection
            self.tasks.append(asyncio.create_task(self.stats_collector.start_collection()))
            
            self.running = True
            self.logger.info("Application startup completed successfully")
            
        except Exception as e:
            self.logger.error(f"Startup failed: {e}")
            raise
    
    async def shutdown(self):
        """Graceful application shutdown"""
        if not self.running:
            return
        
        self.running = False
        self.logger.info("Starting graceful shutdown...")
        
        try:
            # Stop all proxies
            await self.proxy_manager.stop_all_proxies()
            
            # Cancel all tasks
            for task in self.tasks:
                if not task.done():
                    task.cancel()
            
            # Wait for tasks to complete
            if self.tasks:
                await asyncio.gather(*self.tasks, return_exceptions=True)
            
            # Close database connections
            await self.db_manager.close()
            
            print_colored("✅ Shutdown completed successfully", Colors.OKGREEN)
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")
        
        finally:
            # Force exit if needed
            loop = asyncio.get_event_loop()
            loop.stop()

def create_argument_parser():
    """Create comprehensive argument parser"""
    parser = argparse.ArgumentParser(
        description='Advanced MTProto Proxy Manager v4.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🚀 Examples:
  %(prog)s install                    # Install and setup system
  %(prog)s create 8080                # Create proxy on port 8080
  %(prog)s create-bulk 10             # Create 10 proxies starting from port 8080
  %(prog)s start proxy_001            # Start specific proxy
  %(prog)s run-all                    # Start all proxies with monitoring
  %(prog)s web --port 8000            # Start web interface on port 8000
  %(prog)s status --detailed --json   # Show detailed status in JSON format
  %(prog)s monitor --interval 30      # Start monitoring with 30s interval
  %(prog)s optimize --level advanced  # Advanced system optimization
  %(prog)s backup --encrypt           # Create encrypted backup
  %(prog)s cluster add-node           # Add node to cluster

📚 Documentation: https://github.com/mtproxy/manager/wiki
🐛 Issues: https://github.com/mtproxy/manager/issues
        """
    )
    
    # Global options
    parser.add_argument('--version', action='version', version=f'MTProxy Manager v{__version__}')
    parser.add_argument('--config', '-c', help='Custom config file path')
    parser.add_argument('--verbose', '-v', action='count', default=0, help='Increase verbosity')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress output')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Set logging level')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Install command
    install_parser = subparsers.add_parser('install', help='Install and setup system')
    install_parser.add_argument('--auto', action='store_true', help='Automatic installation')
    install_parser.add_argument('--docker', action='store_true', help='Include Docker setup')
    install_parser.add_argument('--firewall', action='store_true', help='Configure firewall')
    install_parser.add_argument('--optimize', action='store_true', help='Optimize system')
    install_parser.add_argument('--cluster', action='store_true', help='Setup for cluster mode')
    
    # Proxy creation commands
    create_parser = subparsers.add_parser('create', help='Create new proxy')
    create_parser.add_argument('port', type=int, help='Proxy port (1024-65535)')
    create_parser.add_argument('--secret', help='Custom secret (hex, 32 chars)')
    create_parser.add_argument('--ad-tag', help='Sponsored channel ad tag')
    create_parser.add_argument('--max-connections', type=int, default=1000)
    create_parser.add_argument('--bandwidth-limit', type=int, default=0, help='KB/s, 0=unlimited')
    create_parser.add_argument('--geo-restrictions', nargs='+', help='Country codes to block')
    create_parser.add_argument('--ssl', action='store_true', help='Enable SSL/TLS')
    create_parser.add_argument('--protocol', choices=['mtproto', 'http', 'socks5'], default='mtproto')
    create_parser.add_argument('--name', help='Proxy display name')
    create_parser.add_argument('--description', help='Proxy description')
    create_parser.add_argument('--tags', nargs='+', help='Proxy tags for organization')
    
    # Bulk creation
    bulk_parser = subparsers.add_parser('create-bulk', help='Create multiple proxies')
    bulk_parser.add_argument('count', type=int, help='Number of proxies to create')
    bulk_parser.add_argument('--start-port', type=int, default=8080)
    bulk_parser.add_argument('--port-range', help='Port range (e.g., 8080-8180)')
    bulk_parser.add_argument('--template', help='Proxy template name')
    bulk_parser.add_argument('--distributed', action='store_true', help='Distribute across available nodes')
    
    # Management commands
    list_parser = subparsers.add_parser('list', help='List proxies')
    list_parser.add_argument('--filter', help='Filter by status, tag, or name')
    list_parser.add_argument('--sort', choices=['name', 'port', 'status', 'connections', 'traffic'], default='name')
    list_parser.add_argument('--format', choices=['table', 'json', 'yaml', 'csv'], default='table')
    list_parser.add_argument('--export', help='Export to file')
    
    status_parser = subparsers.add_parser('status', help='Show proxy status')
    status_parser.add_argument('proxy_id', nargs='?', help='Specific proxy ID')
    status_parser.add_argument('--detailed', action='store_true')
    status_parser.add_argument('--json', action='store_true')
    status_parser.add_argument('--watch', action='store_true', help='Watch mode (auto-refresh)')
    status_parser.add_argument('--metrics', action='store_true', help='Include performance metrics')
    
    # Control commands
    start_parser = subparsers.add_parser('start', help='Start proxy')
    start_parser.add_argument('proxy_id', help='Proxy ID or "all"')
    start_parser.add_argument('--force', action='store_true')
    start_parser.add_argument('--wait', type=int, default=5, help='Wait seconds for startup')
    
    stop_parser = subparsers.add_parser('stop', help='Stop proxy')
    stop_parser.add_argument('proxy_id', help='Proxy ID or "all"')
    stop_parser.add_argument('--graceful', action='store_true', help='Graceful shutdown')
    stop_parser.add_argument('--timeout', type=int, default=30)
    
    restart_parser = subparsers.add_parser('restart', help='Restart proxy')
    restart_parser.add_argument('proxy_id', help='Proxy ID or "all"')
    restart_parser.add_argument('--rolling', action='store_true', help='Rolling restart')
    
    delete_parser = subparsers.add_parser('delete', help='Delete proxy')
    delete_parser.add_argument('proxy_id', help='Proxy ID')
    delete_parser.add_argument('--force', action='store_true')
    delete_parser.add_argument('--backup', action='store_true', help='Backup before delete')
    
    # Advanced operations
    run_parser = subparsers.add_parser('run-all', help='Start all proxies with monitoring')
    run_parser.add_argument('--web-port', type=int, default=8080)
    run_parser.add_argument('--monitor-interval', type=int, default=60)
    run_parser.add_argument('--auto-restart', action='store_true')
    run_parser.add_argument('--load-balance', action='store_true')
    
    web_parser = subparsers.add_parser('web', help='Start web interface')
    web_parser.add_argument('--host', default='0.0.0.0')
    web_parser.add_argument('--port', type=int, default=8080)
    web_parser.add_argument('--ssl-cert', help='SSL certificate file')
    web_parser.add_argument('--ssl-key', help='SSL private key file')
    web_parser.add_argument('--auth', action='store_true', help='Enable authentication')
    
    monitor_parser = subparsers.add_parser('monitor', help='Start monitoring mode')
    monitor_parser.add_argument('--interval', type=int, default=30)
    monitor_parser.add_argument('--alerts', action='store_true')
    monitor_parser.add_argument('--webhook', help='Webhook URL for alerts')
    
    # Configuration commands
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_subparsers = config_parser.add_subparsers(dest='config_action')
    
    config_subparsers.add_parser('show', help='Show current configuration')
    config_set_parser = config_subparsers.add_parser('set', help='Set configuration value')
    config_set_parser.add_argument('key', help='Configuration key')
    config_set_parser.add_argument('value', help='Configuration value')
    
    # Utility commands
    optimize_parser = subparsers.add_parser('optimize', help='Optimize system')
    optimize_parser.add_argument('--level', choices=['basic', 'advanced', 'extreme'], default='basic')
    optimize_parser.add_argument('--apply', action='store_true', help='Apply optimizations')
    
    backup_parser = subparsers.add_parser('backup', help='Backup configuration and data')
    backup_parser.add_argument('--output', help='Backup file path')
    backup_parser.add_argument('--encrypt', action='store_true')
    backup_parser.add_argument('--compress', action='store_true')
    backup_parser.add_argument('--include-logs', action='store_true')
    
    restore_parser = subparsers.add_parser('restore', help='Restore from backup')
    restore_parser.add_argument('backup_file', help='Backup file to restore')
    restore_parser.add_argument('--decrypt-key', help='Decryption key for encrypted backups')
    
    # Analytics and reporting
    stats_parser = subparsers.add_parser('stats', help='Show statistics')
    stats_parser.add_argument('--period', choices=['hour', 'day', 'week', 'month'], default='day')
    stats_parser.add_argument('--proxy-id', help='Statistics for specific proxy')
    stats_parser.add_argument('--export', help='Export statistics to file')
    stats_parser.add_argument('--chart', action='store_true', help='Generate charts')
    
    # Advanced features
    cluster_parser = subparsers.add_parser('cluster', help='Cluster management')
    cluster_subparsers = cluster_parser.add_subparsers(dest='cluster_action')
    
    cluster_subparsers.add_parser('init', help='Initialize cluster')
    cluster_add_parser = cluster_subparsers.add_parser('add-node', help='Add cluster node')
    cluster_add_parser.add_argument('node_address', help='Node IP address')
    cluster_subparsers.add_parser('remove-node', help='Remove cluster node')
    cluster_subparsers.add_parser('status', help='Cluster status')
    
    # Security commands
    security_parser = subparsers.add_parser('security', help='Security management')
    security_subparsers = security_parser.add_subparsers(dest='security_action')
    
    security_subparsers.add_parser('scan', help='Security scan')
    security_subparsers.add_parser('update-blocklist', help='Update IP blocklist')
    security_audit_parser = security_subparsers.add_parser('audit', help='Security audit')
    security_audit_parser.add_argument('--report', help='Generate audit report')
    
    return parser

async def execute_command(app: MTProxyApplication, args):
    """Execute the specified command"""
    
    if args.command == 'install':
        installer = SystemInstaller()
        await installer.install(
            auto=args.auto,
            docker=args.docker,
            firewall=args.firewall,
            optimize=args.optimize,
            cluster=args.cluster
        )
    
    elif args.command == 'create':
        proxy_id = await app.proxy_manager.create_proxy(
            port=args.port,
            secret=args.secret,
            ad_tag=args.ad_tag,
            max_connections=args.max_connections,
            bandwidth_limit=args.bandwidth_limit,
            geo_restrictions=args.geo_restrictions or [],
            ssl_enabled=args.ssl,
            protocol=args.protocol,
            name=args.name,
            description=args.description,
            tags=args.tags or []
        )
        print_colored(f"✅ Created proxy: {proxy_id}", Colors.OKGREEN)
    
    elif args.command == 'create-bulk':
        proxy_ids = await app.proxy_manager.create_bulk_proxies(
            count=args.count,
            start_port=args.start_port,
            port_range=args.port_range,
            template=args.template,
            distributed=args.distributed
        )
        print_colored(f"✅ Created {len(proxy_ids)} proxies", Colors.OKGREEN)
    
    elif args.command == 'list':
        await app.proxy_manager.list_proxies(
            filter_criteria=args.filter,
            sort_by=args.sort,
            format=args.format,
            export_file=args.export
        )
    
    elif args.command == 'status':
        await app.proxy_manager.show_status(
            proxy_id=args.proxy_id,
            detailed=args.detailed,
            json_format=args.json,
            watch=args.watch,
            include_metrics=args.metrics
        )
    
    elif args.command == 'start':
        await app.proxy_manager.start_proxy(
            args.proxy_id,
            force=args.force,
            wait_time=args.wait
        )
    
    elif args.command == 'stop':
        await app.proxy_manager.stop_proxy(
            args.proxy_id,
            graceful=args.graceful,
            timeout=args.timeout
        )
    
    elif args.command == 'restart':
        await app.proxy_manager.restart_proxy(
            args.proxy_id,
            rolling=args.rolling
        )
    
    elif args.command == 'delete':
        await app.proxy_manager.delete_proxy(
            args.proxy_id,
            force=args.force,
            backup=args.backup
        )
    
    elif args.command == 'run-all':
        await app.proxy_manager.run_all(
            web_port=args.web_port,
            monitor_interval=args.monitor_interval,
            auto_restart=args.auto_restart,
            load_balance=args.load_balance
        )
    
    elif args.command == 'web':
        await app.web_interface.start_server(
            host=args.host,
            port=args.port,
            ssl_cert=args.ssl_cert,
            ssl_key=args.ssl_key,
            auth_enabled=args.auth
        )
    
    elif args.command == 'monitor':
        await app.proxy_manager.start_monitoring(
            interval=args.interval,
            alerts=args.alerts,
            webhook=args.webhook
        )
    
    elif args.command == 'config':
        if args.config_action == 'show':
            app.config_manager.show_config()
        elif args.config_action == 'set':
            app.config_manager.set_config(args.key, args.value)
    
    elif args.command == 'optimize':
        optimizer = SystemOptimizer()
        await optimizer.optimize_system(
            level=args.level,
            apply=args.apply
        )
    
    elif args.command == 'backup':
        await app.proxy_manager.create_backup(
            output_file=args.output,
            encrypt=args.encrypt,
            compress=args.compress,
            include_logs=args.include_logs
        )
    
    elif args.command == 'restore':
        await app.proxy_manager.restore_backup(
            args.backup_file,
            decrypt_key=args.decrypt_key
        )
    
    elif args.command == 'stats':
        await app.stats_collector.show_statistics(
            period=args.period,
            proxy_id=args.proxy_id,
            export_file=args.export,
            generate_chart=args.chart
        )
    
    elif args.command == 'cluster':
        cluster_manager = app.proxy_manager.cluster_manager
        if args.cluster_action == 'init':
            await cluster_manager.initialize_cluster()
        elif args.cluster_action == 'add-node':
            await cluster_manager.add_node(args.node_address)
        elif args.cluster_action == 'status':
            await cluster_manager.show_cluster_status()
    
    elif args.command == 'security':
        security_manager = app.proxy_manager.security_manager
        if args.security_action == 'scan':
            await security_manager.security_scan()
        elif args.security_action == 'update-blocklist':
            await security_manager.update_blocklist()
        elif args.security_action == 'audit':
            await security_manager.security_audit(args.report)

async def main():
    """Main application entry point"""
    
    # Parse command line arguments
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Handle no command case
    if not args.command:
        print_banner()
        parser.print_help()
        return
    
    # Show banner for interactive commands
    if args.command not in ['status', 'list'] or args.verbose > 0:
        print_banner()
    
    # Setup logging level
    if args.verbose >= 2:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbose == 1:
        logging.basicConfig(level=logging.INFO)
    elif args.quiet:
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=getattr(logging, args.log_level))
    
    # Initialize application
    try:
        app = MTProxyApplication()
        
        # Set custom config path if provided
        if args.config:
            app.config_manager.config_path = Path(args.config)
        
        # Special handling for install command (may not have dependencies)
        if args.command == 'install':
            await execute_command(app, args)
            return
        
        # Start application
        await app.startup()
        
        # Execute command
        await execute_command(app, args)
        
    except KeyboardInterrupt:
        print_colored("\n⚠️ Operation cancelled by user", Colors.WARNING)
    except Exception as e:
        print_colored(f"❌ Error: {e}", Colors.FAIL)
        if args.verbose >= 1:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        # Cleanup
        if 'app' in locals():
            await app.shutdown()

if __name__ == "__main__":
    try:
        # Use uvloop for better performance if available
        try:
            import uvloop
            uvloop.install()
        except ImportError:
            pass
        
        # Run main application
        asyncio.run(main())
        
    except KeyboardInterrupt:
        print_colored("\n🛑 Application interrupted", Colors.WARNING)
    except Exception as e:
        print_colored(f"❌ Critical error: {e}", Colors.FAIL)
        sys.exit(1)
