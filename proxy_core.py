#!/usr/bin/env python3
"""
🔥 Advanced Proxy Core System
=============================
High-performance proxy server implementation with enterprise features
"""

import asyncio
import socket
import struct
import hashlib
import secrets
import time
import ssl
import json
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
import logging
from enum import Enum
import ipaddress
import geoip2.database
import geoip2.errors

try:
    import aiohttp
    import aiofiles
    import cryptography
    from cryptography.fernet import Fernet
    import psutil
    import ujson
except ImportError as e:
    print(f"Missing dependencies: {e}")
    print("Run: pip install aiohttp aiofiles cryptography psutil ujson geoip2")

class ProxyProtocol(Enum):
    """Supported proxy protocols"""
    MTPROTO = "mtproto"
    HTTP = "http" 
    SOCKS5 = "socks5"
    SHADOWSOCKS = "shadowsocks"

class ProxyStatus(Enum):
    """Proxy server status states"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"
    MAINTENANCE = "maintenance"

class ConnectionState(Enum):
    """Client connection states"""
    CONNECTING = "connecting"
    HANDSHAKING = "handshaking"
    CONNECTED = "connected"
    FORWARDING = "forwarding"
    DISCONNECTING = "disconnecting"

@dataclass
class GeoLocation:
    """Geographic location information"""
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = ""
    isp: str = ""

@dataclass
class ConnectionInfo:
    """Client connection information"""
    client_id: str
    ip_address: str
    port: int
    user_agent: str = ""
    geo_location: GeoLocation = field(default_factory=GeoLocation)
    connected_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    bytes_sent: int = 0
    bytes_received: int = 0
    state: ConnectionState = ConnectionState.CONNECTING
    protocol_version: str = ""
    encryption_enabled: bool = False

@dataclass
class ProxyStats:
    """Comprehensive proxy statistics"""
    # Connection statistics
    active_connections: int = 0
    total_connections: int = 0
    peak_connections: int = 0
    failed_connections: int = 0
    rejected_connections: int = 0
    
    # Traffic statistics
    bytes_sent: int = 0
    bytes_received: int = 0
    total_traffic: int = 0
    
    # Performance metrics
    avg_response_time: float = 0.0
    min_response_time: float = float('inf')
    max_response_time: float = 0.0
    uptime_seconds: int = 0
    
    # Revenue tracking
    revenue: float = 0.0
    ad_impressions: int = 0
    ad_clicks: int = 0
    
    # Error tracking
    errors: int = 0
    timeouts: int = 0
    protocol_errors: int = 0
    
    # Security metrics
    blocked_ips: List[str] = field(default_factory=list)
    suspicious_activity: int = 0
    
    # Geographic distribution
    countries: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary"""
        return asdict(self)

@dataclass
class ProxyConfig:
    """Comprehensive proxy configuration"""
    # Basic configuration
    proxy_id: str
    name: str = ""
    description: str = ""
    port: int = 8080
    protocol: ProxyProtocol = ProxyProtocol.MTPROTO
    
    # Security configuration
    secret: str = ""
    encryption_key: str = ""
    ssl_enabled: bool = False
    ssl_cert_path: str = ""
    ssl_key_path: str = ""
    
    # Performance configuration
    max_connections: int = 1000
    connection_timeout: int = 30
    read_timeout: int = 60
    write_timeout: int = 60
    buffer_size: int = 65536
    
    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_period: int = 60
    bandwidth_limit: int = 0  # KB/s, 0 = unlimited
    
    # Geographic restrictions
    geo_restrictions: List[str] = field(default_factory=list)
    allowed_countries: List[str] = field(default_factory=list)
    blocked_countries: List[str] = field(default_factory=list)
    
    # Sponsored content
    ad_tag: str = ""
    sponsored_enabled: bool = False
    revenue_share: float = 0.5
    
    # Monitoring and logging
    logging_enabled: bool = True
    metrics_enabled: bool = True
    debug_mode: bool = False
    
    # Advanced features
    load_balancing: bool = False
    failover_enabled: bool = True
    auto_restart: bool = True
    health_check_interval: int = 60
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    created_by: str = "system"
    
    # Statistics
    stats: ProxyStats = field(default_factory=ProxyStats)
    
    def validate(self) -> bool:
        """Validate proxy configuration"""
        if not (1024 <= self.port <= 65535):
            return False
        if not self.proxy_id or len(self.proxy_id) < 3:
            return False
        if self.protocol == ProxyProtocol.MTPROTO and len(self.secret) != 32:
            return False
        if self.max_connections < 1 or self.max_connections > 10000:
            return False
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        data = asdict(self)
        # Convert enums to strings
        data['protocol'] = self.protocol.value
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProxyConfig':
        """Create config from dictionary"""
        # Handle enum conversion
        if 'protocol' in data:
            data['protocol'] = ProxyProtocol(data['protocol'])
        
        # Handle datetime conversion
        if 'created_at' in data and isinstance(data['created_at'], str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if 'updated_at' in data and isinstance(data['updated_at'], str):
            data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        
        # Handle stats
        if 'stats' in data and isinstance(data['stats'], dict):
            data['stats'] = ProxyStats(**data['stats'])
        
        return cls(**data)

class SecurityManager:
    """Advanced security management system"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.rate_limits = {}
        self.failed_attempts = {}
        self.whitelist = set()
        self.geo_db = None
        
        # Load GeoIP database if available
        self._load_geoip_database()
        
        # Security settings
        self.max_requests_per_minute = 60
        self.max_failed_attempts = 5
        self.ban_duration = 3600
        self.suspicious_threshold = 10
    
    def _load_geoip_database(self):
        """Load GeoIP database for geographic filtering"""
        try:
            # Try to load GeoLite2 database
            db_paths = [
                '/usr/share/GeoIP/GeoLite2-City.mmdb',
                '/var/lib/GeoIP/GeoLite2-City.mmdb',
                'data/GeoLite2-City.mmdb'
            ]
            
            for db_path in db_paths:
                if Path(db_path).exists():
                    self.geo_db = geoip2.database.Reader(db_path)
                    break
        except Exception:
            pass
    
    def get_geo_location(self, ip_address: str) -> GeoLocation:
        """Get geographic location for IP address"""
        geo = GeoLocation()
        
        if not self.geo_db:
            return geo
        
        try:
            response = self.geo_db.city(ip_address)
            geo.country = response.country.name or ""
            geo.country_code = response.country.iso_code or ""
            geo.region = response.subdivisions.most_specific.name or ""
            geo.city = response.city.name or ""
            geo.latitude = float(response.location.latitude or 0)
            geo.longitude = float(response.location.longitude or 0)
            geo.timezone = response.location.time_zone or ""
            
            if hasattr(response, 'traits') and hasattr(response.traits, 'isp'):
                geo.isp = response.traits.isp or ""
                
        except Exception:
            pass
        
        return geo
    
    def validate_ip(self, ip_address: str, config: ProxyConfig) -> Tuple[bool, str]:
        """Validate IP address against security rules"""
        
        # Check whitelist first
        if ip_address in self.whitelist:
            return True, "whitelisted"
        
        # Check blacklist
        if ip_address in self.blocked_ips:
            return False, "blocked"
        
        # Check geographic restrictions
        if config.geo_restrictions or config.blocked_countries:
            geo = self.get_geo_location(ip_address)
            
            if config.blocked_countries and geo.country_code in config.blocked_countries:
                return False, "geo_blocked"
            
            if config.allowed_countries and geo.country_code not in config.allowed_countries:
                return False, "geo_restricted"
        
        # Check rate limiting
        if config.rate_limit_enabled:
            if not self._check_rate_limit(ip_address, config):
                return False, "rate_limited"
        
        # Check for suspicious activity
        if self._is_suspicious_ip(ip_address):
            return False, "suspicious"
        
        return True, "allowed"
    
    def _check_rate_limit(self, ip_address: str, config: ProxyConfig) -> bool:
        """Check rate limiting for IP address"""
        now = time.time()
        window_start = now - config.rate_limit_period
        
        if ip_address not in self.rate_limits:
            self.rate_limits[ip_address] = []
        
        # Remove old requests
        self.rate_limits[ip_address] = [
            req_time for req_time in self.rate_limits[ip_address]
            if req_time > window_start
        ]
        
        # Check if limit exceeded
        if len(self.rate_limits[ip_address]) >= config.rate_limit_requests:
            return False
        
        # Add current request
        self.rate_limits[ip_address].append(now)
        return True
    
    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """Check if IP shows suspicious activity"""
        if ip_address in self.failed_attempts:
            return len(self.failed_attempts[ip_address]) >= self.suspicious_threshold
        return False
    
    def record_failed_attempt(self, ip_address: str):
        """Record failed authentication attempt"""
        now = time.time()
        
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = []
        
        self.failed_attempts[ip_address].append(now)
        
        # Remove old attempts
        cutoff = now - 600  # 10 minutes
        self.failed_attempts[ip_address] = [
            attempt for attempt in self.failed_attempts[ip_address]
            if attempt > cutoff
        ]
        
        # Block IP if too many failures
        if len(self.failed_attempts[ip_address]) >= self.max_failed_attempts:
            self.blocked_ips.add(ip_address)
    
    def generate_secret(self, length: int = 16) -> str:
        """Generate cryptographically secure secret"""
        return secrets.token_hex(length)

class ProxyServer:
    """High-performance proxy server implementation"""
    
    def __init__(self, config: ProxyConfig, security_manager: SecurityManager):
        self.config = config
        self.security = security_manager
        self.status = ProxyStatus.STOPPED
        self.server = None
        self.connections: Dict[str, ConnectionInfo] = {}
        self.middle_proxies: List[Tuple[str, int]] = []
        self.current_proxy_index = 0
        
        # Performance monitoring
        self.response_times = []
        self.last_health_check = time.time()
        
        # Tasks
        self.monitoring_task = None
        self.cleanup_task = None
        self.health_check_task = None
        
        # Setup logging
        self.logger = self._setup_logger()
        
        # Load balancing
        self.upstream_servers = []
        self.load_balancer_index = 0
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logger for this proxy server"""
        logger = logging.getLogger(f'proxy-{self.config.proxy_id}')
        logger.setLevel(logging.DEBUG if self.config.debug_mode else logging.INFO)
        
        # Create logs directory
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # File handler
        handler = logging.FileHandler(log_dir / f'{self.config.proxy_id}.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    async def start(self) -> bool:
        """Start the proxy server"""
        if self.status != ProxyStatus.STOPPED:
            self.logger.warning(f"Cannot start proxy in {self.status.value} state")
            return False
        
        try:
            self.status = ProxyStatus.STARTING
            self.logger.info(f"Starting proxy server on port {self.config.port}")
            
            # Fetch middleware configuration
            await self._fetch_middleware_config()
            
            # Setup SSL context if enabled
            ssl_context = None
            if self.config.ssl_enabled:
                ssl_context = self._create_ssl_context()
            
            # Create and start server
            self.server = await asyncio.start_server(
                self._handle_client,
                '0.0.0.0',
                self.config.port,
                ssl=ssl_context,
                reuse_address=True,
                reuse_port=True,
                backlog=1024
            )
            
            # Start background tasks
            self.monitoring_task = asyncio.create_task(self._monitoring_loop())
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())
            self.health_check_task = asyncio.create_task(self._health_check_loop())
            
            self.status = ProxyStatus.RUNNING
            self.config.stats.uptime_seconds = 0
            
            self.logger.info(f"Proxy server started successfully on port {self.config.port}")
            return True
            
        except Exception as e:
            self.status = ProxyStatus.ERROR
            self.logger.error(f"Failed to start proxy server: {e}")
            return False
    
    async def stop(self, graceful: bool = True, timeout: int = 30) -> bool:
        """Stop the proxy server"""
        if self.status == ProxyStatus.STOPPED:
            return True
        
        try:
            self.status = ProxyStatus.STOPPING
            self.logger.info("Stopping proxy server...")
            
            # Cancel background tasks
            for task in [self.monitoring_task, self.cleanup_task, self.health_check_task]:
                if task and not task.done():
                    task.cancel()
            
            # Close server
            if self.server:
                self.server.close()
                
                if graceful:
                    # Wait for existing connections to finish
                    try:
                        await asyncio.wait_for(self.server.wait_closed(), timeout=timeout)
                    except asyncio.TimeoutError:
                        self.logger.warning("Graceful shutdown timeout, forcing close")
                else:
                    await self.server.wait_closed()
            
            # Close all connections
            for connection in list(self.connections.values()):
                connection.state = ConnectionState.DISCONNECTING
            
            self.connections.clear()
            self.status = ProxyStatus.STOPPED
            
            self.logger.info("Proxy server stopped successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping proxy server: {e}")
            self.status = ProxyStatus.ERROR
            return False
    
    async def restart(self, graceful: bool = True) -> bool:
        """Restart the proxy server"""
        self.logger.info("Restarting proxy server...")
        
        if await self.stop(graceful):
            await asyncio.sleep(1)  # Brief pause
            return await self.start()
        
        return False
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for HTTPS proxy"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        if self.config.ssl_cert_path and self.config.ssl_key_path:
            context.load_cert_chain(self.config.ssl_cert_path, self.config.ssl_key_path)
        else:
            # Generate self-signed certificate
            self._generate_self_signed_cert()
            context.load_cert_chain('cert.pem', 'key.pem')
        
        return context
    
    def _generate_self_signed_cert(self):
        """Generate self-signed SSL certificate"""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MTProxy"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write certificate and key to files
        with open('cert.pem', 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open('key.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
    
    async def _fetch_middleware_config(self):
        """Fetch middleware proxy configuration"""
        cache_file = Path(f'cache/middleware_{self.config.proxy_id}.json')
        cache_file.parent.mkdir(exist_ok=True)
        
        # Try cache first
        if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < 3600:
            try:
                async with aiofiles.open(cache_file, 'r') as f:
                    data = json.loads(await f.read())
                    self.middle_proxies = [(p['ip'], p['port']) for p in data['proxies']]
                    return
            except Exception:
                pass
        
        # Fetch from Telegram
        sources = [
            'https://core.telegram.org/getProxyConfig',
            'https://telegram.org/getProxyConfig'
        ]
        
        for source in sources:
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(10)) as session:
                    async with session.get(source) as response:
                        if response.status == 200:
                            config_text = await response.text()
                            self.middle_proxies = self._parse_proxy_config(config_text)
                            
                            # Cache the result
                            cache_data = {
                                'proxies': [{'ip': ip, 'port': port} for ip, port in self.middle_proxies],
                                'fetched_at': datetime.now().isoformat()
                            }
                            async with aiofiles.open(cache_file, 'w') as f:
                                await f.write(json.dumps(cache_data))
                            
                            self.logger.info(f"Loaded {len(self.middle_proxies)} middleware proxies")
                            return
                            
            except Exception as e:
                self.logger.debug(f"Failed to fetch config from {source}: {e}")
        
        # Fallback to default Telegram servers
        self.middle_proxies = [
            ('149.154.167.51', 443),
            ('149.154.175.53', 443),
            ('149.154.175.100', 443),
            ('149.154.167.91', 443),
            ('149.154.171.5', 443)
        ]
        self.logger.warning("Using fallback middleware proxies")
    
    def _parse_proxy_config(self, config_text: str) -> List[Tuple[str, int]]:
        """Parse middleware proxy configuration"""
        proxies = []
        
        for line in config_text.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 2:
                    try:
                        ip = parts[0].strip()
                        port = int(parts[1].strip())
                        
                        # Validate IP and port
                        socket.inet_aton(ip)
                        if 1 <= port <= 65535:
                            proxies.append((ip, port))
                            
                    except (ValueError, socket.error):
                        continue
        
        return proxies
    
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connection"""
        client_addr = writer.get_extra_info('peername')
        client_ip = client_addr[0] if client_addr else 'unknown'
        client_id = f"{client_ip}:{client_addr[1] if client_addr else 0}:{time.time()}"
        
        start_time = time.time()
        connection_info = None
        
        try:
            # Security validation
            is_valid, reason = self.security.validate_ip(client_ip, self.config)
            if not is_valid:
                self.logger.warning(f"Rejected connection from {client_ip}: {reason}")
                self.config.stats.rejected_connections += 1
                return
            
            # Connection limit check
            if len(self.connections) >= self.config.max_connections:
                self.logger.warning(f"Connection limit reached, rejecting {client_ip}")
                self.config.stats.rejected_connections += 1
                return
            
            # Create connection info
            geo_location = self.security.get_geo_location(client_ip)
            connection_info = ConnectionInfo(
                client_id=client_id,
                ip_address=client_ip,
                port=client_addr[1] if client_addr else 0,
                geo_location=geo_location,
                state=ConnectionState.CONNECTING
            )
            
            self.connections[client_id] = connection_info
            self.config.stats.active_connections += 1
            self.config.stats.total_connections += 1
            
            # Update peak connections
            if self.config.stats.active_connections > self.config.stats.peak_connections:
                self.config.stats.peak_connections = self.config.stats.active_connections
            
            # Update country statistics
            if geo_location.country_code:
                country = geo_location.country_code
                self.config.stats.countries[country] = self.config.stats.countries.get(country, 0) + 1
            
            self.logger.info(f"New connection from {client_ip} ({geo_location.country})")
            
            # Protocol-specific handling
            if self.config.protocol == ProxyProtocol.MTPROTO:
                await self._handle_mtproto_connection(reader, writer, connection_info)
            elif self.config.protocol == ProxyProtocol.HTTP:
                await self._handle_http_connection(reader, writer, connection_info)
            elif self.config.protocol == ProxyProtocol.SOCKS5:
                await self._handle_socks5_connection(reader, writer, connection_info)
            else:
                raise ValueError(f"Unsupported protocol: {self.config.protocol}")
            
        except Exception as e:
            self.logger.error(f"Error handling client {client_ip}: {e}")
            self.config.stats.errors += 1
            
            if connection_info:
                connection_info.state = ConnectionState.DISCONNECTING
            
            # Record failed attempt for security
            if "authentication" in str(e).lower() or "handshake" in str(e).lower():
                self.security.record_failed_attempt(client_ip)
        
        finally:
            # Cleanup
            if client_id in self.connections:
                # Calculate response time
                response_time = time.time() - start_time
                self.response_times.append(response_time)
                
                # Keep only last 1000 response times
                if len(self.response_times) > 1000:
                    self.response_times.pop(0)
                
                # Update average response time
                if self.response_times:
                    self.config.stats.avg_response_time = sum(self.response_times) / len(self.response_times)
                    self.config.stats.min_response_time = min(self.response_times)
                    self.config.stats.max_response_time = max(self.response_times)
                
                # Update connection count
                self.config.stats.active_connections -= 1
                del self.connections[client_id]
            
            # Close connection
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def _handle_mtproto_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                                       connection_info: ConnectionInfo):
        """Handle MTProto proxy connection"""
        connection_info.state = ConnectionState.HANDSHAKING
        
        # Read initial handshake
        try:
            handshake_data = await asyncio.wait_for(
                reader.read(64), 
                timeout=self.config.connection_timeout
            )
        except asyncio.TimeoutError:
            raise Exception("Handshake timeout")
        
        if len(handshake_data) < 64:
            raise Exception("Invalid handshake size")
        
        # Validate MTProto handshake
        if not self._validate_mtproto_handshake(handshake_data):
            raise Exception("Invalid MTProto handshake")
        
        connection_info.state = ConnectionState.CONNECTED
        
        # Connect to Telegram backend
        backend_reader, backend_writer = await self._connect_to_backend()
        
        # Forward initial handshake
        backend_writer.write(handshake_data)
        await backend_writer.drain()
        
        connection_info.state = ConnectionState.FORWARDING
        
        # Start bidirectional data forwarding
        await self._forward_data(reader, writer, backend_reader, backend_writer, connection_info)
    
    def _validate_mtproto_handshake(self, data: bytes) -> bool:
        """Validate MTProto handshake"""
        if len(data) != 64:
            return False
        
        try:
            # Extract and validate secret
            secret_bytes = bytes.fromhex(self.config.secret)
            
            # Basic MTProto validation
            # In a real implementation, this would include proper cryptographic validation
            return len(secret_bytes) == 16
            
        except Exception:
            return False
    
    async def _handle_http_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                    connection_info: ConnectionInfo):
        """Handle HTTP proxy connection"""
        connection_info.state = ConnectionState.HANDSHAKING
        
        # Read HTTP request
        request_line = await reader.readline()
        if not request_line:
            raise Exception("Empty HTTP request")
        
        request_str = request_line.decode('utf-8', errors='ignore').strip()
        self.logger.debug(f"HTTP request: {request_str}")
        
        connection_info.state = ConnectionState.CONNECTED
        
        # Parse HTTP CONNECT method
        if request_str.startswith('CONNECT'):
            await self._handle_http_connect(reader, writer, request_str, connection_info)
        else:
            await self._handle_http_request(reader, writer, request_str, connection_info)
    
    async def _handle_http_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                 request: str, connection_info: ConnectionInfo):
        """Handle HTTP CONNECT method"""
        try:
            # Parse CONNECT request
            parts = request.split()
            if len(parts) < 2:
                raise Exception("Invalid CONNECT request")
            
            target = parts[1]
            host, port = target.split(':')
            port = int(port)
            
            # Connect to target
            target_reader, target_writer = await asyncio.open_connection(host, port)
            
            # Send 200 Connection established
            response = b"HTTP/1.1 200 Connection established\r\n\r\n"
            writer.write(response)
            await writer.drain()
            
            connection_info.state = ConnectionState.FORWARDING
            
            # Forward data
            await self._forward_data(reader, writer, target_reader, target_writer, connection_info)
            
        except Exception as e:
            # Send error response
            error_response = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
            writer.write(error_response)
            await writer.drain()
            raise e
    
    async def _handle_socks5_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                      connection_info: ConnectionInfo):
        """Handle SOCKS5 proxy connection"""
        connection_info.state = ConnectionState.HANDSHAKING
        
        # SOCKS5 initial handshake
        initial_data = await reader.read(3)
        if len(initial_data) < 3 or initial_data[0] != 0x05:
            raise Exception("Invalid SOCKS5 handshake")
        
        # Send no authentication required
        writer.write(b'\x05\x00')
        await writer.drain()
        
        # Read connection request
        request_data = await reader.read(10)  # Minimum size
        if len(request_data) < 10 or request_data[0] != 0x05:
            raise Exception("Invalid SOCKS5 request")
        
        connection_info.state = ConnectionState.CONNECTED
        
        # Parse target address
        cmd = request_data[1]
        atyp = request_data[3]
        
        if cmd != 0x01:  # Only CONNECT supported
            writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')  # Command not supported
            await writer.drain()
            raise Exception("Unsupported SOCKS5 command")
        
        # Extract target address and port
        if atyp == 0x01:  # IPv4
            target_ip = socket.inet_ntoa(request_data[4:8])
            target_port = struct.unpack('>H', request_data[8:10])[0]
        elif atyp == 0x03:  # Domain name
            domain_len = request_data[4]
            target_ip = request_data[5:5+domain_len].decode()
            target_port = struct.unpack('>H', request_data[5+domain_len:7+domain_len])[0]
        else:
            writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')  # Address type not supported
            await writer.drain()
            raise Exception("Unsupported SOCKS5 address type")
        
        try:
            # Connect to target
            target_reader, target_writer = await asyncio.open_connection(target_ip, target_port)
            
            # Send success response
            writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            
            connection_info.state = ConnectionState.FORWARDING
            
            # Forward data
            await self._forward_data(reader, writer, target_reader, target_writer, connection_info)
            
        except Exception:
            # Send connection refused
            writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            raise Exception("Failed to connect to target")
    
    async def _connect_to_backend(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to backend server with load balancing"""
        if not self.middle_proxies:
            raise Exception("No backend servers available")
        
        # Try multiple backend servers
        attempts = min(len(self.middle_proxies), 3)
        
        for _ in range(attempts):
            proxy_ip, proxy_port = self.middle_proxies[self.current_proxy_index]
            self.current_proxy_index = (self.current_proxy_index + 1) % len(self.middle_proxies)
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(proxy_ip, proxy_port),
                    timeout=10
                )
                return reader, writer
                
            except Exception as e:
                self.logger.debug(f"Failed to connect to {proxy_ip}:{proxy_port} - {e}")
                continue
        
        # Fallback to direct connection
        return await asyncio.open_connection('149.154.167.51', 443)
    
    async def _forward_data(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                          backend_reader: asyncio.StreamReader, backend_writer: asyncio.StreamWriter,
                          connection_info: ConnectionInfo):
        """Forward data between client and backend"""
        
        async def forward_stream(reader, writer, direction):
            try:
                while True:
                    # Apply bandwidth limiting if configured
                    if self.config.bandwidth_limit > 0:
                        chunk_size = min(self.config.buffer_size, self.config.bandwidth_limit * 1024)
                    else:
                        chunk_size = self.config.buffer_size
                    
                    data = await asyncio.wait_for(
                        reader.read(chunk_size),
                        timeout=self.config.read_timeout
                    )
                    
                    if not data:
                        break
                    
                    # Update statistics
                    if direction == 'upstream':
                        connection_info.bytes_sent += len(data)
                        self.config.stats.bytes_sent += len(data)
                    else:
                        connection_info.bytes_received += len(data)
                        self.config.stats.bytes_received += len(data)
                    
                    connection_info.last_activity = datetime.now()
                    
                    # Process sponsored content
                    if self.config.sponsored_enabled and direction == 'downstream':
                        await self._process_sponsored_content(data)
                    
                    # Write data
                    writer.write(data)
                    await asyncio.wait_for(
                        writer.drain(),
                        timeout=self.config.write_timeout
                    )
                    
                    # Bandwidth limiting delay
                    if self.config.bandwidth_limit > 0:
                        delay = len(data) / (self.config.bandwidth_limit * 1024)
                        if delay > 0.001:  # Only delay if significant
                            await asyncio.sleep(delay)
                    
            except Exception as e:
                self.logger.debug(f"Forward stream error ({direction}): {e}")
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass
        
        # Start bidirectional forwarding
        await asyncio.gather(
            forward_stream(client_reader, backend_writer, 'upstream'),
            forward_stream(backend_reader, client_writer, 'downstream'),
            return_exceptions=True
        )
    
    async def _process_sponsored_content(self, data: bytes):
        """Process sponsored content for revenue tracking"""
        if not self.config.ad_tag:
            return
        
        try:
            # Look for sponsored content markers
            data_lower = data.lower()
            
            sponsored_markers = [
                b'sponsored',
                b'advertisement',
                b'promotion',
                self.config.ad_tag.encode().lower()
            ]
            
            for marker in sponsored_markers:
                if marker in data_lower:
                    # Update statistics
                    self.config.stats.ad_impressions += 1
                    
                    # Calculate revenue (example logic)
                    impression_value = 0.001  # $0.001 per impression
                    click_value = 0.01  # $0.01 per click
                    
                    if b'click' in data_lower or b'tap' in data_lower:
                        self.config.stats.ad_clicks += 1
                        revenue = click_value
                    else:
                        revenue = impression_value
                    
                    # Apply revenue share
                    revenue *= self.config.revenue_share
                    self.config.stats.revenue += revenue
                    
                    self.logger.debug(f"Sponsored content processed: +${revenue:.4f}")
                    break
                    
        except Exception as e:
            self.logger.debug(f"Error processing sponsored content: {e}")
    
    async def _monitoring_loop(self):
        """Background monitoring task"""
        while self.status == ProxyStatus.RUNNING:
            try:
                await asyncio.sleep(60)  # Monitor every minute
                
                # Update uptime
                self.config.stats.uptime_seconds += 60
                
                # Log statistics
                self.logger.info(
                    f"Stats - Active: {self.config.stats.active_connections}, "
                    f"Total: {self.config.stats.total_connections}, "
                    f"Revenue: ${self.config.stats.revenue:.4f}, "
                    f"Traffic: {self.config.stats.bytes_sent + self.config.stats.bytes_received} bytes"
                )
                
                # Update total traffic
                self.config.stats.total_traffic = self.config.stats.bytes_sent + self.config.stats.bytes_received
                
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
    
    async def _cleanup_loop(self):
        """Background cleanup task"""
        while self.status == ProxyStatus.RUNNING:
            try:
                await asyncio.sleep(300)  # Cleanup every 5 minutes
                
                current_time = datetime.now()
                stale_connections = []
                
                # Find stale connections
                for client_id, conn_info in self.connections.items():
                    inactive_time = (current_time - conn_info.last_activity).total_seconds()
                    if inactive_time > 1800:  # 30 minutes inactive
                        stale_connections.append(client_id)
                
                # Remove stale connections
                for client_id in stale_connections:
                    if client_id in self.connections:
                        del self.connections[client_id]
                        self.config.stats.active_connections -= 1
                
                if stale_connections:
                    self.logger.info(f"Cleaned up {len(stale_connections)} stale connections")
                
                # Cleanup old response times
                if len(self.response_times) > 1000:
                    self.response_times = self.response_times[-1000:]
                
            except Exception as e:
                self.logger.error(f"Cleanup loop error: {e}")
    
    async def _health_check_loop(self):
        """Background health check task"""
        while self.status == ProxyStatus.RUNNING:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                
                # Perform health checks
                health_status = await self._perform_health_check()
                
                if not health_status and self.config.auto_restart:
                    self.logger.warning("Health check failed, attempting restart...")
                    await self.restart()
                
                self.last_health_check = time.time()
                
            except Exception as e:
                self.logger.error(f"Health check loop error: {e}")
    
    async def _perform_health_check(self) -> bool:
        """Perform comprehensive health check"""
        try:
            # Check if server is still accepting connections
            if not self.server or self.server.is_serving() is False:
                return False
            
            # Check if we can connect to backend
            if self.config.protocol == ProxyProtocol.MTPROTO:
                try:
                    reader, writer = await asyncio.wait_for(
                        self._connect_to_backend(),
                        timeout=5
                    )
                    writer.close()
                    await writer.wait_closed()
                except:
                    return False
            
            # Check system resources
            if hasattr(psutil, 'virtual_memory'):
                memory = psutil.virtual_memory()
                if memory.percent > 90:  # High memory usage
                    self.logger.warning(f"High memory usage: {memory.percent}%")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Health check error: {e}")
            return False
    
    def get_status_info(self) -> Dict[str, Any]:
        """Get comprehensive status information"""
        return {
            'proxy_id': self.config.proxy_id,
            'name': self.config.name,
            'status': self.status.value,
            'port': self.config.port,
            'protocol': self.config.protocol.value,
            'connections': {
                'active': self.config.stats.active_connections,
                'total': self.config.stats.total_connections,
                'peak': self.config.stats.peak_connections,
                'failed': self.config.stats.failed_connections,
                'rejected': self.config.stats.rejected_connections
            },
            'traffic': {
                'bytes_sent': self.config.stats.bytes_sent,
                'bytes_received': self.config.stats.bytes_received,
                'total': self.config.stats.total_traffic
            },
            'performance': {
                'avg_response_time': self.config.stats.avg_response_time,
                'min_response_time': self.config.stats.min_response_time,
                'max_response_time': self.config.stats.max_response_time,
                'uptime_seconds': self.config.stats.uptime_seconds
            },
            'revenue': {
                'total': self.config.stats.revenue,
                'impressions': self.config.stats.ad_impressions,
                'clicks': self.config.stats.ad_clicks
            },
            'security': {
                'blocked_ips': len(self.config.stats.blocked_ips),
                'errors': self.config.stats.errors,
                'suspicious_activity': self.config.stats.suspicious_activity
            },
            'geography': self.config.stats.countries,
            'last_health_check': self.last_health_check,
            'created_at': self.config.created_at.isoformat(),
            'updated_at': self.config.updated_at.isoformat()
        }

class ProxyManager:
    """Advanced proxy management system"""
    
    def __init__(self, db_manager, config_manager):
        self.db_manager = db_manager
        self.config_manager = config_manager
        self.proxies: Dict[str, ProxyConfig] = {}
        self.servers: Dict[str, ProxyServer] = {}
        self.security_manager = SecurityManager()
        
        # Management features
        self.cluster_manager = None  # Will be implemented
        self.load_balancer = None    # Will be implemented
        
        # Setup logging
        self.logger = logging.getLogger('proxy-manager')
    
    async def initialize(self):
        """Initialize proxy manager"""
        # Load existing proxies from database
        self.proxies = await self.db_manager.load_all_proxies()
        self.logger.info(f"Loaded {len(self.proxies)} proxies from database")
    
    async def create_proxy(self, **kwargs) -> str:
        """Create a new proxy with advanced configuration"""
        # Generate unique proxy ID
        proxy_id = f"proxy_{int(time.time())}_{secrets.token_hex(4)}"
        
        # Create configuration
        config = ProxyConfig(
            proxy_id=proxy_id,
            **kwargs
        )
        
        # Generate secret if not provided
        if not config.secret and config.protocol == ProxyProtocol.MTPROTO:
            config.secret = self.security_manager.generate_secret()
        
        # Validate configuration
        if not config.validate():
            raise ValueError("Invalid proxy configuration")
        
        # Check port availability
        if self._is_port_in_use(config.port):
            raise ValueError(f"Port {config.port} is already in use")
        
        # Save to database and memory
        await self.db_manager.save_proxy(config)
        self.proxies[proxy_id] = config
        
        self.logger.info(f"Created proxy {proxy_id} on port {config.port}")
        return proxy_id
    
    async def create_bulk_proxies(self, count: int, start_port: int = 8080, **kwargs) -> List[str]:
        """Create multiple proxies at once"""
        created_proxies = []
        current_port = start_port
        
        for i in range(count):
            # Find next available port
            while self._is_port_in_use(current_port):
                current_port += 1
                if current_port > 65535:
                    raise ValueError("No available ports")
            
            try:
                proxy_id = await self.create_proxy(
                    port=current_port,
                    name=f"Bulk Proxy {i+1}",
                    **kwargs
                )
                created_proxies.append(proxy_id)
                current_port += 1
                
            except Exception as e:
                self.logger.error(f"Failed to create proxy on port {current_port}: {e}")
                current_port += 1
        
        return created_proxies
    
    def _is_port_in_use(self, port: int) -> bool:
        """Check if port is in use"""
        # Check existing proxies
        for proxy in self.proxies.values():
            if proxy.port == port:
                return True
        
        # Check system
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result == 0
        except:
            return False
    
    async def start_proxy(self, proxy_id: str, **kwargs) -> bool:
        """Start a specific proxy"""
        if proxy_id not in self.proxies:
            raise ValueError(f"Proxy {proxy_id} not found")
        
        if proxy_id in self.servers:
            if self.servers[proxy_id].status == ProxyStatus.RUNNING:
                self.logger.warning(f"Proxy {proxy_id} is already running")
                return True
        
        # Create and start server
        config = self.proxies[proxy_id]
        server = ProxyServer(config, self.security_manager)
        
        success = await server.start()
        if success:
            self.servers[proxy_id] = server
            await self.db_manager.update_proxy_status(proxy_id, ProxyStatus.RUNNING)
        
        return success
    
    async def stop_proxy(self, proxy_id: str, **kwargs) -> bool:
        """Stop a specific proxy"""
        if proxy_id not in self.servers:
            self.logger.warning(f"Proxy {proxy_id} is not running")
            return True
        
        server = self.servers[proxy_id]
        success = await server.stop(**kwargs)
        
        if success:
            del self.servers[proxy_id]
            await self.db_manager.update_proxy_status(proxy_id, ProxyStatus.STOPPED)
        
        return success
    
    async def restart_proxy(self, proxy_id: str, **kwargs) -> bool:
        """Restart a specific proxy"""
        if proxy_id in self.servers:
            return await self.servers[proxy_id].restart(**kwargs)
        else:
            return await self.start_proxy(proxy_id)
    
    async def delete_proxy(self, proxy_id: str, **kwargs) -> bool:
        """Delete a proxy"""
        if proxy_id not in self.proxies:
            raise ValueError(f"Proxy {proxy_id} not found")
        
        # Stop if running
        if proxy_id in self.servers:
            await self.stop_proxy(proxy_id)
        
        # Create backup if requested
        if kwargs.get('backup', False):
            await self._backup_proxy(proxy_id)
        
        # Remove from database and memory
        await self.db_manager.delete_proxy(proxy_id)
        del self.proxies[proxy_id]
        
        self.logger.info(f"Deleted proxy {proxy_id}")
        return True
    
    async def start_all_proxies(self) -> Dict[str, bool]:
        """Start all configured proxies"""
        results = {}
        
        for proxy_id in self.proxies:
            try:
                results[proxy_id] = await self.start_proxy(proxy_id)
            except Exception as e:
                self.logger.error(f"Failed to start proxy {proxy_id}: {e}")
                results[proxy_id] = False
        
        return results
    
    async def stop_all_proxies(self) -> Dict[str, bool]:
        """Stop all running proxies"""
        results = {}
        
        for proxy_id in list(self.servers.keys()):
            try:
                results[proxy_id] = await self.stop_proxy(proxy_id)
            except Exception as e:
                self.logger.error(f"Failed to stop proxy {proxy_id}: {e}")
                results[proxy_id] = False
        
        return results
    
    async def list_proxies(self, **kwargs):
        """List proxies with filtering and formatting"""
        # Implementation would include filtering, sorting, and formatting
        proxies_info = []
        
        for proxy_id, config in self.proxies.items():
            server = self.servers.get(proxy_id)
            status_info = server.get_status_info() if server else {
                'proxy_id': proxy_id,
                'status': ProxyStatus.STOPPED.value,
                'connections': {'active': 0}
            }
            proxies_info.append(status_info)
        
        # Apply filters and sorting here
        # Format output according to requested format
        
        return proxies_info
    
    async def show_status(self, **kwargs):
        """Show detailed proxy status"""
        # Implementation would show formatted status information
        pass
    
    async def _backup_proxy(self, proxy_id: str):
        """Create backup of proxy configuration"""
        if proxy_id not in self.proxies:
            return
        
        backup_dir = Path('backups')
        backup_dir.mkdir(exist_ok=True)
        
        backup_data = {
            'proxy_id': proxy_id,
            'config': self.proxies[proxy_id].to_dict(),
            'backup_time': datetime.now().isoformat()
        }
        
        backup_file = backup_dir / f'{proxy_id}_{int(time.time())}.json'
        
        async with aiofiles.open(backup_file, 'w') as f:
            await f.write(json.dumps(backup_data, indent=2))
        
        self.logger.info(f"Created backup for proxy {proxy_id}: {backup_file}")
