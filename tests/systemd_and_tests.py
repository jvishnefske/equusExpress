# ============================================================================
# Systemd Service File: /etc/systemd/system/pubsub-daemon.service
# ============================================================================

"""
[Unit]
Description=PubSub Bridge Daemon
After=network.target
Wants=network.target

[Service]
Type=simple
User=pubsub
Group=pubsub
WorkingDirectory=/opt/pubsub-daemon
ExecStart=/usr/bin/python3 /opt/pubsub-daemon/daemon.py --config /etc/pubsub-daemon/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/pubsub-daemon /var/lib/pubsub-daemon /var/log/pubsub-daemon
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pubsub-daemon

[Install]
WantedBy=multi-user.target
"""

# ============================================================================
# Unit Tests
# ============================================================================

import asyncio
import unittest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import pytest
from pathlib import Path
import tempfile
import json
import logging

# Import the classes we want to test
from pubsub_daemon_core import (
    PubSubDaemon, FileConfigStore, MessageBridge, RouteRule, 
    Plugin, PubSubPlugin, AuthPlugin, AuthzPlugin,
    PluginMetadata, Message, QoS
)
from pubsub_auth_interfaces import PubSubClient, AuthProvider, AuthorizationProvider


class MockConfigStore:
    """Mock configuration store for testing"""
    
    def __init__(self):
        self.data = {}
    
    async def get(self, key: str, default=None):
        return self.data.get(key, default)
    
    async def set(self, key: str, value):
        self.data[key] = value
    
    async def delete(self, key: str):
        if key in self.data:
            del self.data[key]
            return True
        return False
    
    async def get_all(self, prefix: str = ""):
        if not prefix:
            return self.data.copy()
        return {k: v for k, v in self.data.items() if k.startswith(prefix)}
    
    async def exists(self, key: str):
        return key in self.data
    
    async def load(self):
        pass


class MockPubSubClient(PubSubClient):
    """Mock PubSub client for testing"""
    
    def __init__(self):
        self.connected = False
        self.published_messages = []
        self.subscriptions = {}
        
    async def connect(self):
        self.connected = True
    
    async def disconnect(self):
        self.connected = False
    
    async def publish(self, channel: str, payload, qos=QoS.AT_MOST_ONCE, headers=None, reply_to=None):
        self.published_messages.append({
            'channel': channel,
            'payload': payload,
            'qos': qos,
            'headers': headers,
            'reply_to': reply_to
        })
        return f"msg_{len(self.published_messages)}"
    
    async def subscribe(self, channel: str, callback):
        self.subscriptions[channel] = callback
    
    async def unsubscribe(self, channel: str):
        if channel in self.subscriptions:
            del self.subscriptions[channel]
    
    async def subscribe_stream(self, channel: str):
        # Mock implementation
        yield Message(channel, "test_payload")
    
    async def request(self, channel: str, payload, timeout=5.0, qos=QoS.AT_LEAST_ONCE):
        return Message(channel, f"response_to_{payload}")
    
    async def reply(self, original_message: Message, response_payload):
        pass
    
    def is_connected(self):
        return self.connected
    
    async def get_channels(self):
        return list(self.subscriptions.keys())
    
    # Helper method for testing
    async def simulate_message(self, channel: str, payload):
        """Simulate receiving a message"""
        if channel in self.subscriptions:
            message = Message(channel, payload)
            await self.subscriptions[channel](message)


class MockPubSubPlugin(PubSubPlugin):
    """Mock PubSub plugin for testing"""
    
    def __init__(self, name: str, config_store, logger):
        super().__init__(config_store, logger)
        self.name = name
        self.client = MockPubSubClient()
        self.initialized = False
    
    def get_metadata(self):
        return PluginMetadata(
            name=self.name,
            version="1.0.0",
            description=f"Mock {self.name} plugin",
            plugin_type="pubsub"
        )
    
    async def initialize(self):
        self.initialized = True
    
    async def shutdown(self):
        self.initialized = False
    
    def get_client(self):
        return self.client


class TestFileConfigStore(unittest.TestCase):
    """Test FileConfigStore"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = Path(self.temp_dir) / "test_config.json"
        self.store = FileConfigStore(self.config_file)
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)
    
    async def test_set_and_get(self):
        """Test setting and getting configuration values"""
        await self.store.set("test.key", "test_value")
        value = await self.store.get("test.key")
        self.assertEqual(value, "test_value")
    
    async def test_nested_keys(self):
        """Test nested configuration keys"""
        await self.store.set("level1.level2.key", "nested_value")
        value = await self.store.get("level1.level2.key")
        self.assertEqual(value, "nested_value")
    
    async def test_default_value(self):
        """Test default value when key doesn't exist"""
        value = await self.store.get("nonexistent.key", "default")
        self.assertEqual(value, "default")
    
    async def test_delete(self):
        """Test deleting configuration keys"""
        await self.store.set("delete.me", "value")
        result = await self.store.delete("delete.me")
        self.assertTrue(result)
        
        value = await self.store.get("delete.me")
        self.assertIsNone(value)
    
    async def test_persistence(self):
        """Test configuration persistence"""
        await self.store.set("persistent.key", "persistent_value")
        
        # Create new store instance
        new_store = FileConfigStore(self.config_file)
        await new_store.load()
        
        value = await new_store.get("persistent.key")
        self.assertEqual(value, "persistent_value")


class TestMessageBridge(unittest.TestCase):
    """Test MessageBridge"""
    
    def setUp(self):
        self.logger = logging.getLogger("test")
        self.bridge = MessageBridge(self.logger)
    
    def test_add_route(self):
        """Test adding routing rules"""
        rule = RouteRule("source", "ch1", "target", "ch2")
        self.bridge.add_route(rule)
        
        self.assertEqual(len(self.bridge.routes), 1)
        self.assertEqual(self.bridge.routes[0].source_plugin, "source")
    
    def test_remove_route(self):
        """Test removing routing rules"""
        rule = RouteRule("source", "ch1", "target", "ch2")
        self.bridge.add_route(rule)
        
        result = self.bridge.remove_route("source", "ch1", "target", "ch2")
        self.assertTrue(result)
        self.assertEqual(len(self.bridge.routes), 0)
    
    async def test_route_message(self):
        """Test message routing"""
        # Create mock plugins
        config_store = MockConfigStore()
        logger = logging.getLogger("test")
        
        source_plugin = MockPubSubPlugin("source", config_store, logger)
        target_plugin = MockPubSubPlugin("target", config_store, logger)
        
        plugins = {
            "source": source_plugin,
            "target": target_plugin
        }
        
        # Add routing rule
        rule = RouteRule("source", "input", "target", "output")
        self.bridge.add_route(rule)
        
        # Create test message
        message = Message("input", "test_payload")
        
        # Route the message
        await self.bridge.route_message("source", message, plugins)
        
        # Check that message was published to target
        target_client = target_plugin.get_client()
        self.assertEqual(len(target_client.published_messages), 1)
        self.assertEqual(target_client.published_messages[0]["channel"], "output")
        self.assertEqual(target_client.published_messages[0]["payload"], "test_payload")


class TestPubSubDaemon(unittest.TestCase):
    """Test PubSubDaemon"""
    
    def setUp(self):
        self.config_store = MockConfigStore()
        self.logger = logging.getLogger("test")
        self.daemon = PubSubDaemon(self.config_store, self.logger)
    
    def test_register_plugin(self):
        """Test plugin registration"""
        plugin = MockPubSubPlugin("test_plugin", self.config_store, self.logger)
        self.daemon.register_plugin(plugin)
        
        self.assertIn("test_plugin", self.daemon.plugins)
        self.assertIn("test_plugin", self.daemon.pubsub_plugins)
    
    async def test_initialize_plugins(self):
        """Test plugin initialization"""
        plugin = MockPubSubPlugin("test_plugin", self.config_store, self.logger)
        self.daemon.register_plugin(plugin)
        
        await self.daemon.initialize_plugins()
        
        self.assertTrue(plugin.initialized)
    
    def test_add_remove_route(self):
        """Test adding and removing routes"""
        self.daemon.add_route("source", "ch1", "target", "ch2")
        self.assertEqual(len(self.daemon.message_bridge.routes), 1)
        
        result = self.daemon.remove_route("source", "ch1", "target", "ch2")
        self.assertTrue(result)
        self.assertEqual(len(self.daemon.message_bridge.routes), 0)
    
    def test_get_plugin(self):
        """Test getting plugins by name"""
        plugin = MockP