#!/usr/bin/env python3
"""
🗄️ Advanced Database Management System
====================================== 
High-performance database layer with advanced features
"""

import asyncio
import sqlite3
import json
import time
import logging
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import asdict
import threading
from contextlib import asynccontextmanager
import hashlib
import secrets

try:
    import aiosqlite
    import psutil
    AIOSQLITE_AVAILABLE = True
except ImportError:
    AIOSQLITE_AVAILABLE = False
    print("aiosqlite not available, using synchronous SQLite")

from proxy_core import ProxyConfig, ProxyStats, ProxyStatus

class DatabaseManager:
    """Advanced database management with connection pooling and optimization"""
    
    def __init__(self, db_path: str = "data/mtproxy.db", pool_size: int = 10):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.pool_size = pool_size
        self.connections = []
        self.lock = threading.Lock()
        
        # Setup logging
        self.logger = logging.getLogger('database-manager')
        
        # Performance monitoring
        self.query_times = []
        self.query_count = 0
        
        # Database configuration
        self.pragma_settings = {
            'journal_mode': 'WAL',
            'synchronous': 'NORMAL',
            'cache_size': -64000,  # 64MB cache
            'temp_store': 'MEMORY',
            'mmap_size': 268435456,  # 256MB memory map
            'optimize': True
        }
    
    async def initialize(self):
        """Initialize database with optimized settings"""
        self.logger.info("Initializing database...")
        
        # Create database file if it doesn't exist
        if not self.db_path.exists():
            await self._create_database()
        
        # Apply optimizations
        await self._apply_optimizations()
        
        # Initialize connection pool
        await self._initialize_connection_pool()
        
        # Create indices
        await self._create_indices()
        
        # Perform maintenance
        await self._maintenance_tasks()
        
        self.logger.info("Database initialization completed")
    
    async def _create_database(self):
        """Create database schema"""
        schema_sql = """
        -- Main proxy configurations table
        CREATE TABLE IF NOT EXISTS proxies (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            config TEXT NOT NULL,
            status TEXT DEFAULT 'stopped',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT DEFAULT 'system',
            tags TEXT DEFAULT '[]',
            metadata TEXT DEFAULT '{}'
        );
        
        -- Detailed proxy statistics
        CREATE TABLE IF NOT EXISTS proxy_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proxy_id TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            active_connections INTEGER DEFAULT 0,
            total_connections INTEGER DEFAULT 0,
            bytes_sent INTEGER DEFAULT 0,
            bytes_received INTEGER DEFAULT 0,
            revenue REAL DEFAULT 0.0,
            ad_impressions INTEGER DEFAULT 0,
            ad_clicks INTEGER DEFAULT 0,
            errors INTEGER DEFAULT 0,
            avg_response_time REAL DEFAULT 0.0,
            uptime_seconds INTEGER DEFAULT 0,
            peak_connections INTEGER DEFAULT 0,
            countries TEXT DEFAULT '{}',
            FOREIGN KEY (proxy_id) REFERENCES proxies (id) ON DELETE CASCADE
        );
        
        -- Connection logs for detailed tracking
        CREATE TABLE IF NOT EXISTS connection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proxy_id TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            client_port INTEGER,
            country_code TEXT,
            connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            disconnected_at TIMESTAMP,
            bytes_sent INTEGER DEFAULT 0,
            bytes_received INTEGER DEFAULT 0,
            duration_seconds INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            user_agent TEXT,
            protocol_version TEXT,
            FOREIGN KEY (proxy_id) REFERENCES proxies (id) ON DELETE CASCADE
        );
        
        -- System events and audit log
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proxy_id TEXT,
            event_type TEXT NOT NULL,
            event_level TEXT DEFAULT 'INFO',
            message TEXT NOT NULL,
            details TEXT DEFAULT '{}',
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source TEXT DEFAULT 'system',
            FOREIGN KEY (proxy_id) REFERENCES proxies (id) ON DELETE SET NULL
        );
        
        -- System configuration and settings
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            description TEXT,
            category TEXT DEFAULT 'general',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT DEFAULT 'system'
        );
        
        -- Security and blocked IPs
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proxy_id TEXT,
            ip_address TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT DEFAULT 'medium',
            details TEXT DEFAULT '{}',
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (proxy_id) REFERENCES proxies (id) ON DELETE SET NULL
        );
        
        -- Performance metrics
        CREATE TABLE IF NOT EXISTS performance_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proxy_id TEXT,
            metric_name TEXT NOT NULL,
            metric_value REAL NOT NULL,
            metric_unit TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            tags TEXT DEFAULT '{}',
            FOREIGN KEY (proxy_id) REFERENCES proxies (id) ON DELETE CASCADE
        );
        
        -- Revenue tracking
        CREATE TABLE IF NOT EXISTS revenue_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proxy_id TEXT NOT NULL,
            event_type TEXT NOT NULL, -- 'impression', 'click', 'conversion'
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'USD',
            ad_tag TEXT,
            client_ip TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT DEFAULT '{}',
            FOREIGN KEY (proxy_id) REFERENCES proxies (id) ON DELETE CASCADE
        );
        
        -- Backup and maintenance logs
        CREATE TABLE IF NOT EXISTS maintenance_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operation TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            duration_seconds INTEGER
        );
        """
        
        if AIOSQLITE_AVAILABLE:
            async with aiosqlite.connect(self.db_path) as db:
                await db.executescript(schema_sql)
                await db.commit()
        else:
            with sqlite3.connect(self.db_path) as db:
                db.executescript(schema_sql)
                db.commit()
    
    async def _apply_optimizations(self):
        """Apply database optimizations"""
        pragma_commands = []
        for setting, value in self.pragma_settings.items():
            if setting == 'optimize':
                continue
            pragma_commands.append(f"PRAGMA {setting} = {value};")
        
        if AIOSQLITE_AVAILABLE:
            async with aiosqlite.connect(self.db_path) as db:
                for command in pragma_commands:
                    await db.execute(command)
                await db.commit()
        else:
            with sqlite3.connect(self.db_path) as db:
                for command in pragma_commands:
                    db.execute(command)
                db.commit()
    
    async def _initialize_connection_pool(self):
        """Initialize connection pool for better performance"""
        if AIOSQLITE_AVAILABLE:
            for _ in range(self.pool_size):
                conn = await aiosqlite.connect(self.db_path)
                # Apply pragmas to each connection
                for setting, value in self.pragma_settings.items():
                    if setting != 'optimize':
                        await conn.execute(f"PRAGMA {setting} = {value}")
                self.connections.append(conn)
    
    @asynccontextmanager
    async def get_connection(self):
        """Get database connection from pool"""
        if AIOSQLITE_AVAILABLE and self.connections:
            with self.lock:
                if self.connections:
                    conn = self.connections.pop()
                else:
                    conn = await aiosqlite.connect(self.db_path)
            
            try:
                yield conn
            finally:
                with self.lock:
                    if len(self.connections) < self.pool_size:
                        self.connections.append(conn)
                    else:
                        await conn.close()
        else:
            # Fallback to synchronous connection
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()
    
    async def _create_indices(self):
        """Create database indices for better performance"""
        indices = [
            "CREATE INDEX IF NOT EXISTS idx_proxy_stats_proxy_id ON proxy_stats(proxy_id)",
            "CREATE INDEX IF NOT EXISTS idx_proxy_stats_timestamp ON proxy_stats(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_connection_logs_proxy_id ON connection_logs(proxy_id)",
            "CREATE INDEX IF NOT EXISTS idx_connection_logs_timestamp ON connection_logs(connected_at)",
            "CREATE INDEX IF NOT EXISTS idx_connection_logs_ip ON connection_logs(client_ip)",
            "CREATE INDEX IF NOT EXISTS idx_events_proxy_id ON events(proxy_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)",
            "CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_performance_metrics_proxy_id ON performance_metrics(proxy_id)",
            "CREATE INDEX IF NOT EXISTS idx_performance_metrics_timestamp ON performance_metrics(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_revenue_events_proxy_id ON revenue_events(proxy_id)",
            "CREATE INDEX IF NOT EXISTS idx_revenue_events_timestamp ON revenue_events(timestamp)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_system_settings_key ON system_settings(key)"
        ]
        
        if AIOSQLITE_AVAILABLE:
            async with self.get_connection() as db:
                for index_sql in indices:
                    await db.execute(index_sql)
                await db.commit()
        else:
            async with self.get_connection() as db:
                for index_sql in indices:
                    db.execute(index_sql)
                db.commit()
    
    async def _maintenance_tasks(self):
        """Perform database maintenance tasks"""
        maintenance_tasks = [
            "PRAGMA optimize",
            "PRAGMA analysis_limit=400",
            "PRAGMA optimize"
        ]
        
        if AIOSQLITE_AVAILABLE:
            async with self.get_connection() as db:
                for task in maintenance_tasks:
                    await db.execute(task)
        else:
            async with self.get_connection() as db:
                for task in maintenance_tasks:
                    db.execute(task)
    
    async def save_proxy(self, config: ProxyConfig):
        """Save proxy configuration to database"""
        start_time = time.time()
        
        try:
            config_json = json.dumps(config.to_dict())
            tags_json = json.dumps(config.tags)
            
            if AIOSQLITE_AVAILABLE:
                async with self.get_connection() as db:
                    await db.execute("""
                        INSERT OR REPLACE INTO proxies 
                        (id, name, description, config, status, updated_at, tags)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
                    """, (config.proxy_id, config.name, config.description, 
                         config_json, config.stats.status if hasattr(config.stats, 'status') else 'stopped', tags_json))
                    await db.commit()
            else:
                async with self.get_connection() as db:
                    db.execute("""
                        INSERT OR REPLACE INTO proxies 
                        (id, name, description, config, status, updated_at, tags)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
                    """, (config.proxy_id, config.name, config.description, 
                         config_json, 'stopped', tags_json))
                    db.commit()
            
            # Record performance
            query_time = time.time() - start_time
            self._record_query_performance('save_proxy', query_time)
            
            self.logger.debug(f"Saved proxy {config.proxy_id} in {query_time:.3f}s")
            
        except Exception as e:
            self.logger.error(f"Failed to save proxy {config.proxy_id}: {e}")
            raise
    
    async def load_proxy(self, proxy_id: str) -> Optional[ProxyConfig]:
        """Load proxy configuration from database"""
        start_time = time.time()
        
        try:
            if AIOSQLITE_AVAILABLE:
                async with self.get_connection() as db:
                    async with db.execute("""
                        SELECT config FROM proxies WHERE id = ?
                    """, (proxy_id,)) as cursor:
                        row = await cursor.fetchone()
            else:
                async with self.get_connection() as db:
                    cursor = db.execute("""
                        SELECT config FROM proxies WHERE id = ?
                    """, (proxy_id,))
                    row = cursor.fetchone()
            
            if row:
                config_data = json.loads(row[0] if AIOSQLITE_AVAILABLE else row['config'])
                config = ProxyConfig.from_dict(config_data)
                
                query_time = time.time() - start_time
                self._record_query_performance('load_proxy', query_time)
                
                return config
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to load proxy {proxy_id}: {e}")
            return None
    
    async def load_all_proxies(self) -> Dict[str, ProxyConfig]:
        """Load all proxy configurations from database"""
        start_time = time.time()
        proxies = {}
        
        try:
            if AIOSQLITE_AVAILABLE:
                async with self.get_connection() as db:
                    async with db.execute("SELECT id, config FROM proxies") as cursor:
                        async for row in cursor:
                            try:
                                config_data = json.loads(row[1])
                                config = ProxyConfig.from_dict(config_data)
                                proxies[row[0]] = config
                            except Exception as e:
                                self.logger.warning(f"Failed to load proxy {row[0]}: {e}")
            else:
                async with self.get_connection() as db:
                    cursor = db.execute("SELECT id, config FROM proxies")
                    for row in cursor:
                        try:
                            config_data = json.loads(row['config'])
                            config = ProxyConfig.from_dict(config_data)
                            proxies[row['id']] = config
                        except Exception as e:
                            self.logger.warning(f"Failed to load proxy {row['id']}: {e}")
            
            query_time = time.time() - start_time
            self._record_query_performance('load_all_proxies', query_time)
            
            self.logger.info(f"Loaded {len(proxies)} proxies in {query_time:.3f}s")
            return proxies
            
        except Exception as e:
            self.logger.error(f"Failed to load proxies: {e}")
            return {}
    
    async def delete_proxy(self, proxy_id: str):
        """Delete proxy and all related data"""
        start_time = time.time()
        
        try:
            if AIOSQLITE_AVAILABLE:
                async with self.get_connection() as db:
                    # Delete will cascade to related tables
                    await db.execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
                    await db.commit()
            else:
                async with self.get_connection() as db:
                    db.execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
                    db.commit()
            
            query_time = time.time() - start_time
            self._record_query_performance('delete_proxy', query_time)
            
            self.logger.info(f"Deleted proxy {proxy_id} in {query_time:.3f}s")
            
        except Exception as e:
            self.logger.error(f"Failed to delete proxy {proxy_id}: {e}")
            raise
    
    async def record_stats(self, proxy_id: str, stats: ProxyStats):
        """Record proxy statistics"""
        try:
            countries_json = json.dumps(stats.countries)
            
            if AIOSQLITE_AVAILABLE:
                async with self.get_connection() as db:
                    await db.execute("""
                        INSERT INTO proxy_stats 
                        (proxy_id, active_connections, total_connections, bytes_sent, bytes_received,
                         revenue, ad_impressions, ad_clicks, errors, avg_response_time, 
                         uptime_seconds, peak_connections, countries)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (proxy_id, stats.active_connections, stats.total_connections,
                         stats.bytes_sent, stats.bytes_received, stats.revenue,
                         stats.ad_impressions, stats.ad_clicks, stats.errors,
                         stats.avg_response_time, stats.uptime_seconds,
                         stats.peak_connections, countries_json))
                    await db.commit()
            else:
                async with self.get_connection() as db:
                    db.execute("""
                        INSERT INTO proxy_stats 
                        (proxy_id, active_connections, total_connections, bytes_sent, bytes_received,
                         revenue, ad_impressions, ad_clicks, errors, avg_response_time, 
                         uptime_seconds, peak_connections, countries)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (proxy_id, stats.active_connections, stats.total_connections,
                         stats.bytes_sent, stats.bytes_received, stats.revenue,
                         stats.ad_impressions, stats.ad_clicks, stats.errors,
                         stats.avg_response_time, stats.uptime_seconds,
                         stats.peak_connections, countries_json))
                    db.commit()
                    
        except Exception as e:
            self.logger.error(f"Failed to record stats for proxy {proxy_id}: {e}")
    
    async def log_event(self, proxy_id: Optional[str], event_type: str, message: str, 
                       level: str = 'INFO', details: Dict = None):
        """Log system event"""
        try:
            details_json = json.dumps(details or {})
            
            if AIOSQLITE_AVAILABLE:
                async with self.get_connection() as db:
                    await db.execute("""
                        INSERT INTO events (proxy_id, event_type, event_level, message, details)
                        VALUES (?, ?, ?, ?, ?)
                    """, (proxy_id, event_type, level, message, details_json))
                    await db.commit()
            else:
                async with self.get_connection() as db:
                    db.execute("""
                        INSERT INTO events (proxy_id, event_type, event_level, message, details)
                        VALUES (?, ?, ?, ?, ?)
                    """, (proxy_id, event_type, level, message, details_json))
                    db.commit()
                    
        except Exception as e:
            self.logger.error(f"Failed to log event: {e}")
    
    async def update_proxy_status(self, proxy_id: str, status: ProxyStatus):
        """Update proxy status"""
        try:
            if AIOSQLITE_AVAILABLE:
                async with self.get_connection() as db:
                    await db.execute("""
                        UPDATE proxies SET status = ?, updated_at = CURRENT_TIMESTAMP 
                        WHERE id = ?
                    """, (status.value, proxy_id))
                    await db.commit()
            else:
                async with self.get_connection() as db:
                    db.execute("""
                        UPDATE proxies SET status = ?, updated_at = CURRENT_TIMESTAMP 
                        WHERE id = ?
                    """, (status.value, proxy_id))
                    db.commit()
                    
        except Exception as e:
            self.logger.error(f"Failed to update status for proxy {proxy_id}: {e}")
    
    def _record_query_performance(self, query_type: str, execution_time: float):
        """Record query performance for monitoring"""
        self.query_times.append({
            'query_type': query_type,
            'execution_time': execution_time,
            'timestamp': time.time()
        })
        
        # Keep only last 1000 queries
        if len(self.query_times) > 1000:
            self.query_times.pop(0)
        
        self.query_count += 1
    
    async def get_performance_stats(self) -> Dict[str, Any]:
        """Get database performance statistics"""
        if not self.query_times:
            return {}
        
        avg_time = sum(q['execution_time'] for q in self.query_times) / len(self.query_times)
        max_time = max(q['execution_time'] for q in self.query_times)
        min_time = min(q['execution_time'] for q in self.query_times)
        
        return {
            'total_queries': self.query_count,
            'avg_query_time': avg_time,
            'max_query_time': max_time,
            'min_query_time': min_time,
            'recent_queries': len(self.query_times)
        }
    
    async def close(self):
        """Close all database connections"""
        if AIOSQLITE_AVAILABLE:
            with self.lock:
                for conn in self.connections:
                    await conn.close()
                self.connections.clear()
        
        self.logger.info("Database connections closed")

class StatsCollector:
    """Advanced statistics collection and analysis"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.logger = logging.getLogger('stats-collector')
        self.collection_interval = 60  # seconds
        self.collection_task = None
        self.running = False
    
    async def start_collection(self):
        """Start automatic statistics collection"""
        if self.running:
            return
        
        self.running = True
        self.collection_task = asyncio.create_task(self._collection_loop())
        self.logger.info("Statistics collection started")
    
    async def stop_collection(self):
        """Stop statistics collection"""
        self.running = False
        
        if self.collection_task and not self.collection_task.done():
            self.collection_task.cancel()
            try:
                await self.collection_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Statistics collection stopped")
    
    async def _collection_loop(self):
        """Main statistics collection loop"""
        while self.running:
            try:
                await asyncio.sleep(self.collection_interval)
                
                # Collect system metrics
                await self._collect_system_metrics()
                
                # Collect database metrics
                await self._collect_database_metrics()
                
                # Perform cleanup
                await self._cleanup_old_data()
                
            except Exception as e:
                self.logger.error(f"Statistics collection error: {e}")
    
    async def _collect_system_metrics(self):
        """Collect system performance metrics"""
        try:
            if hasattr(psutil, 'cpu_percent'):
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                await self._record_metric('system', 'cpu_usage_percent', cpu_percent)
                await self._record_metric('system', 'memory_usage_percent', memory.percent)
                await self._record_metric('system', 'disk_usage_percent', disk.percent)
                
        except Exception as e:
            self.logger.debug(f"Failed to collect system metrics: {e}")
    
    async def _collect_database_metrics(self):
        """Collect database performance metrics"""
        try:
            perf_stats = await self.db_manager.get_performance_stats()
            
            for metric, value in perf_stats.items():
                await self._record_metric('database', metric, value)
                
        except Exception as e:
            self.logger.debug(f"Failed to collect database metrics: {e}")
    
    async def _record_metric(self, category: str, metric_name: str, value: float):
        """Record a performance metric"""
        try:
            if AIOSQLITE_AVAILABLE:
                async with self.db_manager.get_connection() as db:
                    await db.execute("""
                        INSERT INTO performance_metrics (proxy_id, metric_name, metric_value, tags)
                        VALUES (?, ?, ?, ?)
                    """, (None, metric_name, value, json.dumps({'category': category})))
                    await db.commit()
            else:
                async with self.db_manager.get_connection() as db:
                    db.execute("""
                        INSERT INTO performance_metrics (proxy_id, metric_name, metric_value, tags)
                        VALUES (?, ?, ?, ?)
                    """, (None, metric_name, value, json.dumps({'category': category})))
                    db.commit()
                    
        except Exception as e:
            self.logger.debug(f"Failed to record metric {metric_name}: {e}")
    
    async def _cleanup_old_data(self):
        """Clean up old data to prevent database bloat"""
        try:
            # Remove data older than 30 days
            cutoff_date = datetime.now() - timedelta(days=30)
            cutoff_timestamp = cutoff_date.isoformat()
            
            cleanup_queries = [
                f"DELETE FROM proxy_stats WHERE timestamp < '{cutoff_timestamp}'",
                f"DELETE FROM connection_logs WHERE connected_at < '{cutoff_timestamp}'",
                f"DELETE FROM performance_metrics WHERE timestamp < '{cutoff_timestamp}'",
                f"DELETE FROM events WHERE timestamp < '{cutoff_timestamp}' AND event_level = 'DEBUG'"
            ]
            
            if AIOSQLITE_AVAILABLE:
                async with self.db_manager.get_connection() as db:
                    for query in cleanup_queries:
                        await db.execute(query)
                    await db.commit()
            else:
                async with self.db_manager.get_connection() as db:
                    for query in cleanup_queries:
                        db.execute(query)
                    db.commit()
            
            self.logger.debug("Completed data cleanup")
            
        except Exception as e:
            self.logger.error(f"Data cleanup failed: {e}")
