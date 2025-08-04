#!/usr/bin/env python3
"""
🌐 Advanced Web Interface & API System
=====================================
Modern web interface with REST API and WebSocket support
"""

import asyncio
import json
import time
import logging
import secrets
import hashlib
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime, timedelta
import mimetypes
import base64

try:
    import aiohttp
    from aiohttp import web, WSMsgType
    import aiofiles
    import jinja2
    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False
    print("Web dependencies not available. Install: pip install aiohttp aiofiles jinja2")

from proxy_core import ProxyStatus, ProxyProtocol

class AuthenticationManager:
    """Advanced authentication and session management"""
    
    def __init__(self):
        self.sessions = {}
        self.api_keys = {}
        self.failed_attempts = {}
        self.session_timeout = 3600  # 1 hour
        self.max_failed_attempts = 5
        self.lockout_duration = 900  # 15 minutes
        
        # Default admin credentials (should be changed)
        self.admin_username = "admin"
        self.admin_password_hash = self._hash_password("mtproxy_admin_2024")
    
    def _hash_password(self, password: str) -> str:
        """Hash password with salt"""
        salt = secrets.token_hex(32)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{pwd_hash.hex()}"
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            salt, pwd_hash = password_hash.split(':')
            return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() == pwd_hash
        except:
            return False
    
    def authenticate_user(self, username: str, password: str, ip_address: str) -> Optional[str]:
        """Authenticate user and return session token"""
        # Check for lockout
        if self._is_ip_locked(ip_address):
            return None
        
        # Verify credentials
        if username == self.admin_username and self._verify_password(password, self.admin_password_hash):
            # Create session
            session_token = secrets.token_urlsafe(32)
            self.sessions[session_token] = {
                'username': username,
                'ip_address': ip_address,
                'created_at': time.time(),
                'last_activity': time.time(),
                'permissions': ['admin']
            }
            
            # Clear failed attempts
            if ip_address in self.failed_attempts:
                del self.failed_attempts[ip_address]
            
            return session_token
        else:
            # Record failed attempt
            self._record_failed_attempt(ip_address)
            return None
    
    def validate_session(self, session_token: str, ip_address: str) -> bool:
        """Validate session token"""
        if not session_token or session_token not in self.sessions:
            return False
        
        session = self.sessions[session_token]
        
        # Check IP address
        if session['ip_address'] != ip_address:
            return False
        
        # Check timeout
        if time.time() - session['last_activity'] > self.session_timeout:
            del self.sessions[session_token]
            return False
        
        # Update last activity
        session['last_activity'] = time.time()
        return True
    
    def generate_api_key(self, name: str, permissions: List[str]) -> str:
        """Generate API key with permissions"""
        api_key = f"mtproxy_{secrets.token_urlsafe(32)}"
        self.api_keys[api_key] = {
            'name': name,
            'permissions': permissions,
            'created_at': time.time(),
            'last_used': None,
            'usage_count': 0
        }
        return api_key
    
    def validate_api_key(self, api_key: str) -> bool:
        """Validate API key"""
        if api_key in self.api_keys:
            self.api_keys[api_key]['last_used'] = time.time()
            self.api_keys[api_key]['usage_count'] += 1
            return True
        return False
    
    def _record_failed_attempt(self, ip_address: str):
        """Record failed authentication attempt"""
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = []
        
        self.failed_attempts[ip_address].append(time.time())
        
        # Clean old attempts
        cutoff = time.time() - self.lockout_duration
        self.failed_attempts[ip_address] = [
            attempt for attempt in self.failed_attempts[ip_address]
            if attempt > cutoff
        ]
    
    def _is_ip_locked(self, ip_address: str) -> bool:
        """Check if IP is locked due to failed attempts"""
        if ip_address not in self.failed_attempts:
            return False
        
        recent_attempts = len([
            attempt for attempt in self.failed_attempts[ip_address]
            if time.time() - attempt < self.lockout_duration
        ])
        
        return recent_attempts >= self.max_failed_attempts

class WebSocketManager:
    """WebSocket connection management for real-time updates"""
    
    def __init__(self):
        self.connections = {}
        self.logger = logging.getLogger('websocket-manager')
    
    async def add_connection(self, ws, connection_id: str):
        """Add WebSocket connection"""
        self.connections[connection_id] = {
            'websocket': ws,
            'connected_at': time.time(),
            'last_ping': time.time()
        }
        self.logger.info(f"WebSocket connection added: {connection_id}")
    
    async def remove_connection(self, connection_id: str):
        """Remove WebSocket connection"""
        if connection_id in self.connections:
            del self.connections[connection_id]
            self.logger.info(f"WebSocket connection removed: {connection_id}")
    
    async def broadcast_message(self, message: Dict[str, Any]):
        """Broadcast message to all connections"""
        if not self.connections:
            return
        
        message_json = json.dumps(message)
        disconnected = []
        
        for connection_id, conn_data in self.connections.items():
            try:
                await conn_data['websocket'].send_str(message_json)
            except Exception as e:
                self.logger.debug(f"Failed to send to {connection_id}: {e}")
                disconnected.append(connection_id)
        
        # Remove disconnected connections
        for connection_id in disconnected:
            await self.remove_connection(connection_id)
    
    async def send_to_connection(self, connection_id: str, message: Dict[str, Any]):
        """Send message to specific connection"""
        if connection_id not in self.connections:
            return False
        
        try:
            message_json = json.dumps(message)
            await self.connections[connection_id]['websocket'].send_str(message_json)
            return True
        except Exception as e:
            self.logger.debug(f"Failed to send to {connection_id}: {e}")
            await self.remove_connection(connection_id)
            return False

class WebInterface:
    """Advanced web interface with modern features"""
    
    def __init__(self, proxy_manager, db_manager):
        self.proxy_manager = proxy_manager
        self.db_manager = db_manager
        self.auth_manager = AuthenticationManager()
        self.ws_manager = WebSocketManager()
        
        # Setup logging
        self.logger = logging.getLogger('web-interface')
        
        # Template engine
        self.jinja_env = None
        self._setup_templates()
        
        # Web app
        self.app = None
        self.server = None
        
        # Configuration
        self.host = '0.0.0.0'
        self.port = 8080
        self.ssl_enabled = False
        self.auth_enabled = True
    
    def _setup_templates(self):
        """Setup Jinja2 template engine"""
        if not WEB_AVAILABLE:
            return
        
        template_dir = Path('templates')
        if not template_dir.exists():
            template_dir.mkdir()
            self._create_default_templates()
        
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
    
    def _create_default_templates(self):
        """Create default HTML templates"""
        # Main dashboard template
        dashboard_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MTProto Proxy Manager v4.0</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #fff;
            min-height: 100vh;
        }
        
        .header {
            background: rgba(0,0,0,0.2);
            padding: 20px;
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 5px;
            background: linear-gradient(45deg, #fff, #64b5f6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: 15px;
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-value {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
            color: #64b5f6;
        }
        
        .stat-label {
            font-size: 1.1em;
            opacity: 0.8;
        }
        
        .proxy-section {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        
        .section-header {
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 25px;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .section-title {
            font-size: 2em;
            margin-bottom: 10px;
        }
        
        .btn-group {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s ease;
            background: linear-gradient(45deg, #64b5f6, #42a5f5);
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(100,181,246,0.4);
        }
        
        .btn-success { background: linear-gradient(45deg, #4caf50, #66bb6a); }
        .btn-danger { background: linear-gradient(45deg, #f44336, #ef5350); }
        .btn-warning { background: linear-gradient(45deg, #ff9800, #ffb74d); }
        
        .proxy-grid {
            display: grid;
            gap: 15px;
        }
        
        .proxy-item {
            background: rgba(255,255,255,0.08);
            border-radius: 10px;
            padding: 20px;
            border: 1px solid rgba(255,255,255,0.1);
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 20px;
            align-items: center;
        }
        
        .proxy-info h3 {
            margin-bottom: 8px;
            font-size: 1.3em;
        }
        
        .proxy-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-top: 10px;
        }
        
        .detail-item {
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        .detail-label {
            font-weight: bold;
            margin-bottom: 2px;
        }
        
        .status-running { color: #4caf50; }
        .status-stopped { color: #f44336; }
        .status-starting { color: #ff9800; }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            backdrop-filter: blur(5px);
        }
        
        .modal-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            padding: 40px;
            border-radius: 15px;
            width: 90%;
            max-width: 600px;
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
        }
        
        .form-control {
            width: 100%;
            padding: 12px;
            border: 1px solid rgba(255,255,255,0.3);
            border-radius: 8px;
            background: rgba(255,255,255,0.1);
            color: white;
            font-size: 1em;
        }
        
        .form-control::placeholder {
            color: rgba(255,255,255,0.7);
        }
        
        .form-control:focus {
            outline: none;
            border-color: #64b5f6;
            background: rgba(255,255,255,0.15);
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .section-header {
                flex-direction: column;
                align-items: stretch;
            }
            
            .proxy-item {
                grid-template-columns: 1fr;
            }
            
            .proxy-details {
                grid-template-columns: 1fr 1fr;
            }
        }
        
        .loading {
            opacity: 0.5;
            pointer-events: none;
        }
        
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 25px;
            border-radius: 8px;
            color: white;
            font-weight: bold;
            z-index: 2000;
            transition: all 0.3s ease;
        }
        
        .notification.success { background: #4caf50; }
        .notification.error { background: #f44336; }
        .notification.warning { background: #ff9800; }
        
        .chart-container {
            background: rgba(255,255,255,0.05);
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
            height: 300px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>🚀 MTProto Proxy Manager v4.0</h1>
            <p>Enterprise-grade proxy management system</p>
        </div>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="total-proxies">0</div>
                <div class="stat-label">Total Proxies</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="running-proxies">0</div>
                <div class="stat-label">Running Proxies</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="total-connections">0</div>
                <div class="stat-label">Active Connections</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="total-revenue">$0.00</div>
                <div class="stat-label">Total Revenue</div>
            </div>
        </div>
        
        <div class="proxy-section">
            <div class="section-header">
                <div>
                    <h2 class="section-title">Proxy Management</h2>
                    <p>Manage your MTProto proxy servers</p>
                </div>
                <div class="btn-group">
                    <button class="btn" onclick="showCreateModal()">
                        ➕ Add Proxy
                    </button>
                    <button class="btn btn-success" onclick="startAllProxies()">
                        ▶️ Start All
                    </button>
                    <button class="btn btn-danger" onclick="stopAllProxies()">
                        ⏹️ Stop All
                    </button>
                    <button class="btn btn-warning" onclick="refreshData()">
                        🔄 Refresh
                    </button>
                </div>
            </div>
            
            <div class="proxy-grid" id="proxy-container">
                <!-- Proxies will be loaded here -->
            </div>
        </div>
        
        <div class="chart-container" id="chart-container" style="display: none;">
            <canvas id="trafficChart"></canvas>
        </div>
    </div>
    
    <!-- Create Proxy Modal -->
    <div id="createModal" class="modal">
        <div class="modal-content">
            <h3 style="margin-bottom: 30px;">Create New Proxy</h3>
            <form id="createForm">
                <div class="form-group">
                    <label class="form-label">Proxy Name:</label>
                    <input type="text" class="form-control" id="proxyName" placeholder="Enter proxy name">
                </div>
                
                <div class="form-group">
                    <label class="form-label">Port:</label>
                    <input type="number" class="form-control" id="port" min="1024" max="65535" required placeholder="8080">
                </div>
                
                <div class="form-group">
                    <label class="form-label">Protocol:</label>
                    <select class="form-control" id="protocol">
                        <option value="mtproto">MTProto</option>
                        <option value="http">HTTP</option>
                        <option value="socks5">SOCKS5</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Secret (optional):</label>
                    <input type="text" class="form-control" id="secret" placeholder="Auto-generated if empty">
                </div>
                
                <div class="form-group">
                    <label class="form-label">Ad Tag (optional):</label>
                    <input type="text" class="form-control" id="adTag" placeholder="For sponsored channels">
                </div>
                
                <div class="form-group">
                    <label class="form-label">Max Connections:</label>
                    <input type="number" class="form-control" id="maxConnections" value="1000" min="1" max="10000">
                </div>
                
                <div class="form-group">
                    <div class="checkbox-group">
                        <input type="checkbox" id="sslEnabled">
                        <label for="sslEnabled">Enable SSL/TLS</label>
                    </div>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Description:</label>
                    <textarea class="form-control" id="description" rows="3" placeholder="Optional description"></textarea>
                </div>
                
                <div class="btn-group" style="margin-top: 30px;">
                    <button type="submit" class="btn btn-success">Create Proxy</button>
                    <button type="button" class="btn btn-danger" onclick="hideCreateModal()">Cancel</button>
                </div>
            </form>
        </div>
    </div>
    
    <script>
        let ws = null;
        let reconnectInterval = null;
        
        // Initialize WebSocket connection
        function initWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws`;
            
            ws = new WebSocket(wsUrl);
            
            ws.onopen = function() {
                console.log('WebSocket connected');
                if (reconnectInterval) {
                    clearInterval(reconnectInterval);
                    reconnectInterval = null;
                }
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                handleWebSocketMessage(data);
            };
            
            ws.onclose = function() {
                console.log('WebSocket disconnected');
                if (!reconnectInterval) {
                    reconnectInterval = setInterval(initWebSocket, 5000);
                }
            };
            
            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
            };
        }
        
        function handleWebSocketMessage(data) {
            if (data.type === 'stats_update') {
                updateStats(data.data);
            } else if (data.type === 'proxy_status_change') {
                loadProxies();
            }
        }
        
        // Load initial data
        document.addEventListener('DOMContentLoaded', function() {
            loadStats();
            loadProxies();
            initWebSocket();
            
            // Auto-refresh every 30 seconds
            setInterval(refreshData, 30000);
        });
        
        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                const stats = await response.json();
                updateStats(stats);
            } catch (error) {
                console.error('Error loading stats:', error);
                showNotification('Failed to load statistics', 'error');
            }
        }
        
        function updateStats(stats) {
            document.getElementById('total-proxies').textContent = stats.total_proxies || 0;
            document.getElementById('running-proxies').textContent = stats.running_proxies || 0;
            document.getElementById('total-connections').textContent = stats.total_connections || 0;
            document.getElementById('total-revenue').textContent = `$${(stats.total_revenue || 0).toFixed(2)}`;
        }
        
        async function loadProxies() {
            try {
                const response = await fetch('/api/proxies');
                const proxies = await response.json();
                displayProxies(proxies);
            } catch (error) {
                console.error('Error loading proxies:', error);
                showNotification('Failed to load proxies', 'error');
            }
        }
        
        function displayProxies(proxies) {
            const container = document.getElementById('proxy-container');
            
            if (proxies.length === 0) {
                container.innerHTML = '<p style="text-align: center; opacity: 0.7; padding: 40px;">No proxies configured. Click "Add Proxy" to create your first proxy.</p>';
                return;
            }
            
            container.innerHTML = '';
            
            proxies.forEach(proxy => {
                const proxyElement = createProxyElement(proxy);
                container.appendChild(proxyElement);
            });
        }
        
        function createProxyElement(proxy) {
            const div = document.createElement('div');
            div.className = 'proxy-item';
            
            const statusClass = `status-${proxy.status}`;
            const statusIcon = proxy.status === 'running' ? '🟢' : proxy.status === 'starting' ? '🟡' : '🔴';
            
            div.innerHTML = `
                <div class="proxy-info">
                    <h3>${proxy.name || proxy.proxy_id}</h3>
                    <p>Status: ${statusIcon} <span class="${statusClass}">${proxy.status.toUpperCase()}</span></p>
                    
                    <div class="proxy-details">
                        <div class="detail-item">
                            <div class="detail-label">Port</div>
                            <div>${proxy.port}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Protocol</div>
                            <div>${proxy.protocol.toUpperCase()}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Connections</div>
                            <div>${proxy.connections?.active || 0}/${proxy.max_connections}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Traffic</div>
                            <div>${formatBytes((proxy.traffic?.bytes_sent || 0) + (proxy.traffic?.bytes_received || 0))}</div>
                        </div>
                        ${proxy.revenue?.total > 0 ? `
                        <div class="detail-item">
                            <div class="detail-label">Revenue</div>
                            <div>$${proxy.revenue.total.toFixed(2)}</div>
                        </div>
                        ` : ''}
                    </div>
                </div>
                
                <div class="btn-group">
                    ${proxy.status === 'running' ? 
                        `<button class="btn btn-warning" onclick="stopProxy('${proxy.proxy_id}')">⏹️ Stop</button>` :
                        `<button class="btn btn-success" onclick="startProxy('${proxy.proxy_id}')">▶️ Start</button>`
                    }
                    <button class="btn btn-warning" onclick="restartProxy('${proxy.proxy_id}')">🔄 Restart</button>
                    <button class="btn btn-danger" onclick="deleteProxy('${proxy.proxy_id}')">🗑️ Delete</button>
                </div>
            `;
            
            return div;
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function showCreateModal() {
            document.getElementById('createModal').style.display = 'block';
        }
        
        function hideCreateModal() {
            document.getElementById('createModal').style.display = 'none';
            document.getElementById('createForm').reset();
        }
        
        // Form submission
        document.getElementById('createForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = {
                name: document.getElementById('proxyName').value,
                port: parseInt(document.getElementById('port').value),
                protocol: document.getElementById('protocol').value,
                secret: document.getElementById('secret').value || undefined,
                ad_tag: document.getElementById('adTag').value || undefined,
                max_connections: parseInt(document.getElementById('maxConnections').value),
                ssl_enabled: document.getElementById('sslEnabled').checked,
                description: document.getElementById('description').value || undefined
            };
            
            try {
                const response = await fetch('/api/proxies', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(formData)
                });
                
                if (response.ok) {
                    const result = await response.json();
                    showNotification(`Proxy ${result.proxy_id} created successfully!`, 'success');
                    hideCreateModal();
                    refreshData();
                } else {
                    const error = await response.json();
                    showNotification(error.error || 'Failed to create proxy', 'error');
                }
            } catch (error) {
                showNotification('Network error occurred', 'error');
            }
        });
        
        async function startProxy(proxyId) {
            try {
                const response = await fetch(`/api/proxies/${proxyId}/start`, { method: 'POST' });
                if (response.ok) {
                    showNotification(`Starting proxy ${proxyId}...`, 'success');
                    setTimeout(loadProxies, 2000);
                } else {
                    const error = await response.json();
                    showNotification(error.error || 'Failed to start proxy', 'error');
                }
            } catch (error) {
                showNotification('Network error occurred', 'error');
            }
        }
        
        async function stopProxy(proxyId) {
            try {
                const response = await fetch(`/api/proxies/${proxyId}/stop`, { method: 'POST' });
                if (response.ok) {
                    showNotification(`Stopping proxy ${proxyId}...`, 'warning');
                    setTimeout(loadProxies, 1000);
                } else {
                    const error = await response.json();
                    showNotification(error.error || 'Failed to stop proxy', 'error');
                }
            } catch (error) {
                showNotification('Network error occurred', 'error');
            }
        }
        
        async function restartProxy(proxyId) {
            try {
                const response = await fetch(`/api/proxies/${proxyId}/restart`, { method: 'POST' });
                if (response.ok) {
                    showNotification(`Restarting proxy ${proxyId}...`, 'warning');
                    setTimeout(loadProxies, 3000);
                } else {
                    const error = await response.json();
                    showNotification(error.error || 'Failed to restart proxy', 'error');
                }
            } catch (error) {
                showNotification('Network error occurred', 'error');
            }
        }
        
        async function deleteProxy(proxyId) {
            if (!confirm(`Are you sure you want to delete proxy ${proxyId}? This action cannot be undone.`)) {
                return;
            }
            
            try {
                const response = await fetch(`/api/proxies/${proxyId}`, { method: 'DELETE' });
                if (response.ok) {
                    showNotification(`Proxy ${proxyId} deleted successfully!`, 'success');
                    refreshData();
                } else {
                    const error = await response.json();
                    showNotification(error.error || 'Failed to delete proxy', 'error');
                }
            } catch (error) {
                showNotification('Network error occurred', 'error');
            }
        }
        
        async function startAllProxies() {
            try {
                const response = await fetch('/api/proxies/start-all', { method: 'POST' });
                if (response.ok) {
                    showNotification('Starting all proxies...', 'success');
                    setTimeout(refreshData, 3000);
                } else {
                    showNotification('Failed to start all proxies', 'error');
                }
            } catch (error) {
                showNotification('Network error occurred', 'error');
            }
        }
        
        async function stopAllProxies() {
            if (!confirm('Are you sure you want to stop all running proxies?')) {
                return;
            }
            
            try {
                const response = await fetch('/api/proxies/stop-all', { method: 'POST' });
                if (response.ok) {
                    showNotification('Stopping all proxies...', 'warning');
                    setTimeout(refreshData, 2000);
                } else {
                    showNotification('Failed to stop all proxies', 'error');
                }
            } catch (error) {
                showNotification('Network error occurred', 'error');
            }
        }
        
        function refreshData() {
            loadStats();
            loadProxies();
        }
        
        function showNotification(message, type = 'success') {
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.textContent = message;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.style.opacity = '0';
                setTimeout(() => {
                    document.body.removeChild(notification);
                }, 300);
            }, 3000);
        }
        
        // Close modal when clicking outside
        document.getElementById('createModal').addEventListener('click', function(e) {
            if (e.target === this) {
                hideCreateModal();
            }
        });
    </script>
</body>
</html>
        """
        
        # Save template
        template_dir = Path('templates')
        template_dir.mkdir(exist_ok=True)
        
        with open(template_dir / 'dashboard.html', 'w', encoding='utf-8') as f:
            f.write(dashboard_html)
    
    def create_app(self) -> web.Application:
        """Create and configure web application"""
        if not WEB_AVAILABLE:
            raise RuntimeError("Web dependencies not available")
        
        # Create application with middleware
        app = web.Application(middlewares=[
            self._cors_middleware,
            self._auth_middleware if self.auth_enabled else None,
            self._error_middleware
        ])
        
        # Static files
        static_dir = Path('static')
        static_dir.mkdir(exist_ok=True)
        app.router.add_static('/static', static_dir)
        
        # Web routes
        app.router.add_get('/', self._dashboard_handler)
        app.router.add_get('/login', self._login_handler)
        app.router.add_post('/login', self._login_post_handler)
        app.router.add_get('/logout', self._logout_handler)
        
        # WebSocket
        app.router.add_get('/ws', self._websocket_handler)
        
        # API routes
        app.router.add_get('/api/stats', self._api_stats)
        app.router.add_get('/api/proxies', self._api_get_proxies)
        app.router.add_post('/api/proxies', self._api_create_proxy)
        app.router.add_delete('/api/proxies/{proxy_id}', self._api_delete_proxy)
        app.router.add_post('/api/proxies/{proxy_id}/start', self._api_start_proxy)
        app.router.add_post('/api/proxies/{proxy_id}/stop', self._api_stop_proxy)
        app.router.add_post('/api/proxies/{proxy_id}/restart', self._api_restart_proxy)
        app.router.add_post('/api/proxies/start-all', self._api_start_all_proxies)
        app.router.add_post('/api/proxies/stop-all', self._api_stop_all_proxies)
        
        # Advanced API routes
        app.router.add_get('/api/proxies/{proxy_id}/stats', self._api_proxy_stats)
        app.router.add_get('/api/system/health', self._api_system_health)
        app.router.add_get('/api/system/metrics', self._api_system_metrics)
        
        self.app = app
        return app
    
    async def start_server(self, **kwargs):
        """Start web server"""
        if not WEB_AVAILABLE:
            raise RuntimeError("Web dependencies not available")
        
        # Update configuration
        self.host = kwargs.get('host', self.host)
        self.port = kwargs.get('port', self.port)
        self.ssl_enabled = bool(kwargs.get('ssl_cert') and kwargs.get('ssl_key'))
        self.auth_enabled = kwargs.get('auth_enabled', self.auth_enabled)
        
        # Create application
        app = self.create_app()
        
        # Setup SSL
        ssl_context = None
        if self.ssl_enabled:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(kwargs['ssl_cert'], kwargs['ssl_key'])
        
        # Start server
        self.logger.info(f"Starting web server on {self.host}:{self.port}")
        
        runner = web.AppRunner(app)
        await runner.setup()
        
        site = web.TCPSite(runner, self.host, self.port, ssl_context=ssl_context)
        await site.start()
        
        protocol = 'https' if self.ssl_enabled else 'http'
        self.logger.info(f"Web server started: {protocol}://{self.host}:{self.port}")
        
        # Keep server running
        try:
            while True:
                await asyncio.sleep(3600)
        except KeyboardInterrupt:
            pass
        finally:
            await runner.cleanup()
    
    # Middleware
    @web.middleware
    async def _cors_middleware(self, request, handler):
        """CORS middleware"""
        response = await handler(request)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response
    
    @web.middleware
    async def _auth_middleware(self, request, handler):
        """Authentication middleware"""
        # Skip auth for public endpoints
        if request.path in ['/login', '/static', '/favicon.ico'] or request.path.startswith('/static/'):
            return await handler(request)
        
        # Check session or API key
        auth_header = request.headers.get('Authorization', '')
        session_token = request.cookies.get('session_token', '')
        client_ip = request.remote
        
        # API key authentication
        if auth_header.startswith('Bearer '):
            api_key = auth_header[7:]
            if self.auth_manager.validate_api_key(api_key):
                return await handler(request)
        
        # Session authentication
        if session_token and self.auth_manager.validate_session(session_token, client_ip):
            return await handler(request)
        
        # Redirect to login for web interface
        if request.path.startswith('/api/'):
            return web.json_response({'error': 'Authentication required'}, status=401)
        else:
            return web.HTTPFound('/login')
    
    @web.middleware
    async def _error_middleware(self, request, handler):
        """Error handling middleware"""
        try:
            return await handler(request)
        except Exception as e:
            self.logger.error(f"Request error: {e}")
            
            if request.path.startswith('/api/'):
                return web.json_response({
                    'error': str(e),
                    'type': type(e).__name__
                }, status=500)
            else:
                return web.Response(text='Internal Server Error', status=500)
    
    # Web handlers
    async def _dashboard_handler(self, request):
        """Main dashboard handler"""
        template = self.jinja_env.get_template('dashboard.html')
        html = template.render(title="MTProto Proxy Manager")
        return web.Response(text=html, content_type='text/html')
    
    async def _login_handler(self, request):
        """Login page handler"""
        login_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Login - MTProxy Manager</title>
    <style>
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); margin: 0; padding: 0; height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-container { background: rgba(255,255,255,0.1); padding: 40px; border-radius: 15px; backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.2); }
        .login-form { width: 300px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; color: white; margin-bottom: 5px; font-weight: bold; }
        input { width: 100%; padding: 12px; border: 1px solid rgba(255,255,255,0.3); border-radius: 5px; background: rgba(255,255,255,0.1); color: white; }
        input::placeholder { color: rgba(255,255,255,0.7); }
        button { width: 100%; padding: 12px; background: #64b5f6; color: white; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; }
        button:hover { background: #42a5f5; }
        .title { text-align: center; color: white; margin-bottom: 30px; }
        .error { color: #f44336; text-align: center; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2 class="title">🚀 MTProxy Manager</h2>
        <form class="login-form" method="POST">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" required placeholder="Enter username">
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required placeholder="Enter password">
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
        """
        return web.Response(text=login_html, content_type='text/html')
    
    async def _login_post_handler(self, request):
        """Login form submission handler"""
        data = await request.post()
        username = data.get('username', '')
        password = data.get('password', '')
        client_ip = request.remote
        
        session_token = self.auth_manager.authenticate_user(username, password, client_ip)
        
        if session_token:
            response = web.HTTPFound('/')
            response.set_cookie('session_token', session_token, httponly=True, secure=self.ssl_enabled)
            return response
        else:
            return web.Response(text='Login failed', status=401)
    
    async def _logout_handler(self, request):
        """Logout handler"""
        response = web.HTTPFound('/login')
        response.del_cookie('session_token')
        return response
    
    async def _websocket_handler(self, request):
        """WebSocket handler for real-time updates"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        connection_id = secrets.token_urlsafe(16)
        await self.ws_manager.add_connection(ws, connection_id)
        
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        await self._handle_websocket_message(connection_id, data)
                    except json.JSONDecodeError:
                        pass
                elif msg.type == WSMsgType.ERROR:
                    self.logger.error(f'WebSocket error: {ws.exception()}')
                    break
        except Exception as e:
            self.logger.error(f'WebSocket connection error: {e}')
        finally:
            await self.ws_manager.remove_connection(connection_id)
        
        return ws
    
    async def _handle_websocket_message(self, connection_id: str, data: Dict[str, Any]):
        """Handle incoming WebSocket message"""
        message_type = data.get('type')
        
        if message_type == 'ping':
            await self.ws_manager.send_to_connection(connection_id, {'type': 'pong'})
        elif message_type == 'subscribe':
            # Handle subscription to specific data streams
            pass
    
    # API handlers
    async def _api_stats(self, request):
        """API endpoint for general statistics"""
        stats = {
            'total_proxies': len(self.proxy_manager.proxies),
            'running_proxies': len(self.proxy_manager.servers),
            'total_connections': sum(
                server.config.stats.active_connections 
                for server in self.proxy_manager.servers.values()
            ),
            'total_revenue': sum(
                proxy.stats.revenue 
                for proxy in self.proxy_manager.proxies.values()
            ),
            'total_traffic': sum(
                proxy.stats.bytes_sent + proxy.stats.bytes_received
                for proxy in self.proxy_manager.proxies.values()
            ),
            'timestamp': time.time()
        }
        
        return web.json_response(stats)
    
    async def _api_get_proxies(self, request):
        """API endpoint to get all proxies"""
        proxies_data = []
        
        for proxy_id, config in self.proxy_manager.proxies.items():
            server = self.proxy_manager.servers.get(proxy_id)
            
            proxy_info = {
                'proxy_id': proxy_id,
                'name': config.name,
                'description': config.description,
                'port': config.port,
                'protocol': config.protocol.value,
                'status': server.status.value if server else 'stopped',
                'max_connections': config.max_connections,
                'ssl_enabled': config.ssl_enabled,
                'ad_tag': config.ad_tag,
                'created_at': config.created_at.isoformat(),
                'connections': {
                    'active': config.stats.active_connections,
                    'total': config.stats.total_connections,
                    'peak': config.stats.peak_connections
                },
                'traffic': {
                    'bytes_sent': config.stats.bytes_sent,
                    'bytes_received': config.stats.bytes_received,
                    'total': config.stats.total_traffic
                },
                'revenue': {
                    'total': config.stats.revenue,
                    'impressions': config.stats.ad_impressions,
                    'clicks': config.stats.ad_clicks
                },
                'performance': {
                    'avg_response_time': config.stats.avg_response_time,
                    'uptime_seconds': config.stats.uptime_seconds,
                    'errors': config.stats.errors
                }
            }
            
            proxies_data.append(proxy_info)
        
        return web.json_response(proxies_data)
    
    async def _api_create_proxy(self, request):
        """API endpoint to create new proxy"""
        try:
            data = await request.json()
            
            proxy_id = await self.proxy_manager.create_proxy(**data)
            
            # Broadcast update via WebSocket
            await self.ws_manager.broadcast_message({
                'type': 'proxy_created',
                'data': {'proxy_id': proxy_id}
            })
            
            return web.json_response({
                'success': True,
                'proxy_id': proxy_id,
                'message': f'Proxy {proxy_id} created successfully'
            })
            
        except Exception as e:
            return web.json_response({'error': str(e)}, status=400)
    
    async def _api_delete_proxy(self, request):
        """API endpoint to delete proxy"""
        proxy_id = request.match_info['proxy_id']
        
        try:
            await self.proxy_manager.delete_proxy(proxy_id)
            
            # Broadcast update via WebSocket
            await self.ws_manager.broadcast_message({
                'type': 'proxy_deleted',
                'data': {'proxy_id': proxy_id}
            })
            
            return web.json_response({
                'success': True,
                'message': f'Proxy {proxy_id} deleted successfully'
            })
            
        except Exception as e:
            return web.json_response({'error': str(e)}, status=400)
    
    async def _api_start_proxy(self, request):
        """API endpoint to start proxy"""
        proxy_id = request.match_info['proxy_id']
        
        try:
            success = await self.proxy_manager.start_proxy(proxy_id)
            
            if success:
                await self.ws_manager.broadcast_message({
                    'type': 'proxy_status_change',
                    'data': {'proxy_id': proxy_id, 'status': 'starting'}
                })
                
                return web.json_response({
                    'success': True,
                    'message': f'Proxy {proxy_id} started successfully'
                })
            else:
                return web.json_response({'error': 'Failed to start proxy'}, status=500)
                
        except Exception as e:
            return web.json_response({'error': str(e)}, status=400)
    
    async def _api_stop_proxy(self, request):
        """API endpoint to stop proxy"""
        proxy_id = request.match_info['proxy_id']
        
        try:
            success = await self.proxy_manager.stop_proxy(proxy_id)
            
            if success:
                await self.ws_manager.broadcast_message({
                    'type': 'proxy_status_change',
                    'data': {'proxy_id': proxy_id, 'status': 'stopped'}
                })
                
                return web.json_response({
                    'success': True,
                    'message': f'Proxy {proxy_id} stopped successfully'
                })
            else:
                return web.json_response({'error': 'Failed to stop proxy'}, status=500)
                
        except Exception as e:
            return web.json_response({'error': str(e)}, status=400)
    
    async def _api_restart_proxy(self, request):
        """API endpoint to restart proxy"""
        proxy_id = request.match_info['proxy_id']
        
        try:
            success = await self.proxy_manager.restart_proxy(proxy_id)
            
            if success:
                await self.ws_manager.broadcast_message({
                    'type': 'proxy_status_change',
                    'data': {'proxy_id': proxy_id, 'status': 'restarting'}
                })
                
                return web.json_response({
                    'success': True,
                    'message': f'Proxy {proxy_id} restarted successfully'
                })
            else:
                return web.json_response({'error': 'Failed to restart proxy'}, status=500)
                
        except Exception as e:
            return web.json_response({'error': str(e)}, status=400)
    
    async def _api_start_all_proxies(self, request):
        """API endpoint to start all proxies"""
        try:
            results = await self.proxy_manager.start_all_proxies()
            success_count = sum(1 for success in results.values() if success)
            
            await self.ws_manager.broadcast_message({
                'type': 'bulk_operation',
                'data': {'operation': 'start_all', 'success_count': success_count}
            })
            
            return web.json_response({
                'success': True,
                'message': f'Started {success_count}/{len(results)} proxies',
                'results': results
            })
            
        except Exception as e:
            return web.json_response({'error': str(e)}, status=500)
    
    async def _api_stop_all_proxies(self, request):
        """API endpoint to stop all proxies"""
        try:
            results = await self.proxy_manager.stop_all_proxies()
            success_count = sum(1 for success in results.values() if success)
            
            await self.ws_manager.broadcast_message({
                'type': 'bulk_operation',
                'data': {'operation': 'stop_all', 'success_count': success_count}
            })
            
            return web.json_response({
                'success': True,
                'message': f'Stopped {success_count}/{len(results)} proxies',
                'results': results
            })
            
        except Exception as e:
            return web.json_response({'error': str(e)}, status=500)
    
    async def _api_proxy_stats(self, request):
        """API endpoint for detailed proxy statistics"""
        proxy_id = request.match_info['proxy_id']
        
        if proxy_id not in self.proxy_manager.proxies:
            return web.json_response({'error': 'Proxy not found'}, status=404)
        
        config = self.proxy_manager.proxies[proxy_id]
        server = self.proxy_manager.servers.get(proxy_id)
        
        stats = {
            'proxy_id': proxy_id,
            'status': server.status.value if server else 'stopped',
            'stats': config.stats.to_dict(),
            'connections': list(server.connections.values()) if server else [],
            'performance_history': []  # Would be populated from database
        }
        
        return web.json_response(stats)
    
    async def _api_system_health(self, request):
        """API endpoint for system health check"""
        health_data = {
            'status': 'healthy',
            'timestamp': time.time(),
            'uptime': time.time() - getattr(self, 'start_time', time.time()),
            'proxies': {
                'total': len(self.proxy_manager.proxies),
                'running': len(self.proxy_manager.servers),
                'healthy': 0  # Would perform actual health checks
            },
            'system': {}
        }
        
        # Add system metrics if available
        try:
            if hasattr(psutil, 'cpu_percent'):
                health_data['system'].update({
                    'cpu_percent': psutil.cpu_percent(),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_percent': psutil.disk_usage('/').percent
                })
        except:
            pass
        
        return web.json_response(health_data)
    
    async def _api_system_metrics(self, request):
        """API endpoint for detailed system metrics"""
        # This would return comprehensive system metrics
        # Implementation would depend on monitoring requirements
        metrics = {
            'timestamp': time.time(),
            'performance': await self.db_manager.get_performance_stats(),
            'proxies': {},
            'system': {}
        }
        
        return web.json_response(metrics)
