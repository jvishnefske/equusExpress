#!/usr/bin/env python3
"""
PubSub Bridge Daemon Core System

A systemd-supervised daemon that bridges between different pubsub plugin modules
with configuration persistence and full unit testability.
"""

import asyncio
import logging
import signal
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Callable, Union
from pathlib import Path
import json
import yaml
from datetime import datetime
import traceback

# Import the interfaces from the previous artifact
from pubsub_auth_interfaces import (
    PubSubClient, Message, QoS, AuthProvider, AuthorizationProvider,
    AuthCredentials, AuthContext, AuthResponse, AuthResult
)


# ============================================================================
# Configuration and Storage Interfaces
# ============================================================================

class ConfigStore(ABC):
    """Abstract interface for configuration persistence"""
    
    @abstractmethod
    async def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        pass
    
    @abstractmethod
    async def set(self, key: str, value: Any) -> None:
        """Set configuration value"""
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete configuration key"""
        pass
    
    @abstractmethod
    async def get_all(self, prefix: str = "") -> Dict[str, Any]:
        """Get all configuration with optional prefix filter"""
        pass
    
    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if configuration key exists"""
        pass


class FileConfigStore(ConfigStore):
    """File-based configuration storage"""
    
    def __init__(self, config_file: Path):
        self.config_file = config_file
        self._config: Dict[str, Any] = {}
        self._lock = asyncio.Lock()
    
    async def load(self) -> None:
        """Load configuration from file"""
        async with self._lock:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    if self.config_file.suffix == '.json':
                        self._config = json.load(f)
                    elif self.config_file.suffix in ['.yml', '.yaml']:
                        self._config = yaml.safe_load(f)
                    else:
                        raise ValueError(f"Unsupported config file format: {self.config_file.suffix}")
            else:
                self._config = {}
    
    async def save(self) -> None:
        """Save configuration to file"""
        async with self._lock:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w') as f:
                if self.config_file.suffix == '.json':
                    json.dump(self._config, f, indent=2)
                elif self.config_file.suffix in ['.yml', '.yaml']:
                    yaml.dump(self._config, f, default_flow_style=False)
    
    async def get(self, key: str, default: Any = None) -> Any:
        async with self._lock:
            keys = key.split('.')
            value = self._config
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            return value
    
    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            keys = key.split('.')
            config = self._config
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            config[keys[-1]] = value
            await self.save()
    
    async def delete(self, key: str) -> bool:
        async with self._lock:
            keys = key.split('.')
            config = self._config
            for k in keys[:-1]:
                if k not in config:
                    return False
                config = config[k]
            if keys[-1] in config:
                del config[keys[-1]]
                await self.save()
                return True
            return False
    
    async def get_all(self, prefix: str = "") -> Dict[str, Any]:
        async with self._lock:
            if not prefix:
                return self._config.copy()
            
            keys = prefix.split('.')
            value = self._config
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return {}
            return value if isinstance(value, dict) else {}
    
    async def exists(self, key: str) -> bool:
        return await self.get(key) is not None


# ============================================================================
# Plugin System
# ============================================================================

@dataclass
class PluginMetadata:
    """Metadata for a plugin"""
    name: str
    version: str
    description: str
    plugin_type: str  # 'pubsub', 'auth', 'authz'
    dependencies: List[str] = field(default_factory=list)
    config_schema: Optional[Dict[str, Any]] = None


class Plugin(ABC):
    """Base class for all plugins"""
    
    def __init__(self, config_store: ConfigStore, logger: logging.Logger):
        self.config_store = config_store
        self.logger = logger
        self._config_prefix = f"plugins.{self.get_metadata().name}"
    
    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        pass
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the plugin"""
        pass
    
    @abstractmethod
    async def shutdown(self) -> None:
        """Shutdown the plugin"""
        pass
    
    async def get_config(self, key: str, default: Any = None) -> Any:
        """Get plugin-specific configuration"""
        return await self.config_store.get(f"{self._config_prefix}.{key}", default)
    
    async def set_config(self, key: str, value: Any) -> None:
        """Set plugin-specific configuration"""
        await self.config_store.set(f"{self._config_prefix}.{key}", value)
    
    async def get_all_config(self) -> Dict[str, Any]:
        """Get all plugin configuration"""
        return await self.config_store.get_all(self._config_prefix)


class PubSubPlugin(Plugin):
    """Base class for PubSub plugins"""
    
    @abstractmethod
    def get_client(self) -> PubSubClient:
        """Return the PubSub client instance"""
        pass


class AuthPlugin(Plugin):
    """Base class for Authentication plugins"""
    
    @abstractmethod
    def get_provider(self) -> AuthProvider:
        """Return the Auth provider instance"""
        pass


class AuthzPlugin(Plugin):
    """Base class for Authorization plugins"""
    
    @abstractmethod
    def get_provider(self) -> AuthorizationProvider:
        """Return the Authorization provider instance"""
        pass


# ============================================================================
# Message Routing and Bridge
# ============================================================================

@dataclass
class RouteRule:
    """Routing rule for message bridging"""
    source_plugin: str
    source_channel: str
    target_plugin: str
    target_channel: str
    transform: Optional[Callable[[Message], Message]] = None
    condition: Optional[Callable[[Message], bool]] = None


class MessageBridge:
    """Handles message routing between plugins"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.routes: List[RouteRule] = []
        self.subscriptions: Dict[str, Set[str]] = {}  # plugin_name -> set of channels
    
    def add_route(self, rule: RouteRule) -> None:
        """Add a routing rule"""
        self.routes.append(rule)
        self.logger.info(f"Added route: {rule.source_plugin}:{rule.source_channel} -> {rule.target_plugin}:{rule.target_channel}")
    
    def remove_route(self, source_plugin: str, source_channel: str, target_plugin: str, target_channel: str) -> bool:
        """Remove a routing rule"""
        for i, rule in enumerate(self.routes):
            if (rule.source_plugin == source_plugin and 
                rule.source_channel == source_channel and
                rule.target_plugin == target_plugin and 
                rule.target_channel == target_channel):
                del self.routes[i]
                self.logger.info(f"Removed route: {source_plugin}:{source_channel} -> {target_plugin}:{target_channel}")
                return True
        return False
    
    async def route_message(self, source_plugin: str, message: Message, plugins: Dict[str, PubSubPlugin]) -> None:
        """Route a message according to routing rules"""
        for rule in self.routes:
            if rule.source_plugin == source_plugin and rule.source_channel == message.channel:
                # Apply condition filter if present
                if rule.condition and not rule.condition(message):
                    continue
                
                # Apply transformation if present
                routed_message = rule.transform(message) if rule.transform else message
                routed_message.channel = rule.target_channel
                
                # Send to target plugin
                if rule.target_plugin in plugins:
                    try:
                        target_client = plugins[rule.target_plugin].get_client()
                        await target_client.publish(
                            routed_message.channel,
                            routed_message.payload,
                            headers=routed_message.headers
                        )
                        self.logger.debug(f"Routed message from {source_plugin}:{message.channel} to {rule.target_plugin}:{rule.target_channel}")
                    except Exception as e:
                        self.logger.error(f"Failed to route message: {e}")
                else:
                    self.logger.warning(f"Target plugin {rule.target_plugin} not found")


# ============================================================================
# Core Daemon
# ============================================================================

class PubSubDaemon:
    """Core PubSub bridge daemon"""
    
    def __init__(
        self,
        config_store: ConfigStore,
        logger: Optional[logging.Logger] = None,
        plugin_dir: Optional[Path] = None
    ):
        self.config_store = config_store
        self.logger = logger or self._setup_logger()
        self.plugin_dir = plugin_dir or Path("/etc/pubsub-daemon/plugins")
        
        self.plugins: Dict[str, Plugin] = {}
        self.pubsub_plugins: Dict[str, PubSubPlugin] = {}
        self.auth_plugins: Dict[str, AuthPlugin] = {}
        self.authz_plugins: Dict[str, AuthzPlugin] = {}
        
        self.message_bridge = MessageBridge(self.logger)
        self.running = False
        self.tasks: List[asyncio.Task] = []
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _setup_logger(self) -> logging.Logger:
        """Setup default logger"""
        logger = logging.getLogger("pubsub_daemon")
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def _signal_handler(self, signum: int, frame) -> None:
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        asyncio.create_task(self.shutdown())
    
    async def load_config(self) -> None:
        """Load daemon configuration"""
        if hasattr(self.config_store, 'load'):
            await self.config_store.load()
        
        # Load routing rules
        routes_config = await self.config_store.get("routing.rules", [])
        for route_config in routes_config:
            rule = RouteRule(
                source_plugin=route_config["source_plugin"],
                source_channel=route_config["source_channel"],
                target_plugin=route_config["target_plugin"],
                target_channel=route_config["target_channel"]
            )
            self.message_bridge.add_route(rule)
    
    def register_plugin(self, plugin: Plugin) -> None:
        """Register a plugin with the daemon"""
        metadata = plugin.get_metadata()
        self.plugins[metadata.name] = plugin
        
        # Register in type-specific collections
        if isinstance(plugin, PubSubPlugin):
            self.pubsub_plugins[metadata.name] = plugin
        elif isinstance(plugin, AuthPlugin):
            self.auth_plugins[metadata.name] = plugin
        elif isinstance(plugin, AuthzPlugin):
            self.authz_plugins[metadata.name] = plugin
        
        self.logger.info(f"Registered plugin: {metadata.name} ({metadata.plugin_type})")
    
    async def initialize_plugins(self) -> None:
        """Initialize all registered plugins"""
        for name, plugin in self.plugins.items():
            try:
                await plugin.initialize()
                self.logger.info(f"Initialized plugin: {name}")
            except Exception as e:
                self.logger.error(f"Failed to initialize plugin {name}: {e}")
                raise
    
    async def setup_subscriptions(self) -> None:
        """Setup message subscriptions and routing"""
        for plugin_name, plugin in self.pubsub_plugins.items():
            client = plugin.get_client()
            
            # Subscribe to channels that have routing rules
            channels_to_subscribe = set()
            for rule in self.message_bridge.routes:
                if rule.source_plugin == plugin_name:
                    channels_to_subscribe.add(rule.source_channel)
            
            # Setup subscriptions
            for channel in channels_to_subscribe:
                await client.subscribe(
                    channel,
                    lambda msg, plugin=plugin_name: self._handle_message(plugin, msg)
                )
                self.logger.info(f"Subscribed {plugin_name} to channel: {channel}")
    
    async def _handle_message(self, source_plugin: str, message: Message) -> None:
        """Handle incoming messages and route them"""
        try:
            await self.message_bridge.route_message(source_plugin, message, self.pubsub_plugins)
        except Exception as e:
            self.logger.error(f"Error handling message from {source_plugin}: {e}")
            self.logger.debug(traceback.format_exc())
    
    async def start(self) -> None:
        """Start the daemon"""
        self.logger.info("Starting PubSub Bridge Daemon...")
        
        try:
            # Load configuration
            await self.load_config()
            
            # Initialize plugins
            await self.initialize_plugins()
            
            # Connect PubSub clients
            for name, plugin in self.pubsub_plugins.items():
                client = plugin.get_client()
                await client.connect()
                self.logger.info(f"Connected PubSub client: {name}")
            
            # Setup subscriptions and routing
            await self.setup_subscriptions()
            
            self.running = True
            self.logger.info("PubSub Bridge Daemon started successfully")
            
            # Keep the daemon running
            while self.running:
                await asyncio.sleep(1)
                
        except Exception as e:
            self.logger.error(f"Failed to start daemon: {e}")
            self.logger.debug(traceback.format_exc())
            await self.shutdown()
            raise
    
    async def shutdown(self) -> None:
        """Shutdown the daemon"""
        if not self.running:
            return
            
        self.logger.info("Shutting down PubSub Bridge Daemon...")
        self.running = False
        
        # Cancel all tasks
        for task in self.tasks:
            task.cancel()
        
        # Disconnect PubSub clients
        for name, plugin in self.pubsub_plugins.items():
            try:
                client = plugin.get_client()
                await client.disconnect()
                self.logger.info(f"Disconnected PubSub client: {name}")
            except Exception as e:
                self.logger.error(f"Error disconnecting {name}: {e}")
        
        # Shutdown plugins
        for name, plugin in self.plugins.items():
            try:
                await plugin.shutdown()
                self.logger.info(f"Shutdown plugin: {name}")
            except Exception as e:
                self.logger.error(f"Error shutting down plugin {name}: {e}")
        
        self.logger.info("PubSub Bridge Daemon shutdown complete")
    
    def add_route(self, source_plugin: str, source_channel: str, target_plugin: str, target_channel: str) -> None:
        """Add a routing rule"""
        rule = RouteRule(source_plugin, source_channel, target_plugin, target_channel)
        self.message_bridge.add_route(rule)
    
    def remove_route(self, source_plugin: str, source_channel: str, target_plugin: str, target_channel: str) -> bool:
        """Remove a routing rule"""
        return self.message_bridge.remove_route(source_plugin, source_channel, target_plugin, target_channel)
    
    def get_plugin(self, name: str) -> Optional[Plugin]:
        """Get a plugin by name"""
        return self.plugins.get(name)
    
    def get_pubsub_plugin(self, name: str) -> Optional[PubSubPlugin]:
        """Get a PubSub plugin by name"""
        return self.pubsub_plugins.get(name)
    
    def get_auth_plugin(self, name: str) -> Optional[AuthPlugin]:
        """Get an Auth plugin by name"""
        return self.auth_plugins.get(name)
    
    def get_authz_plugin(self, name: str) -> Optional[AuthzPlugin]:
        """Get an Authz plugin by name"""
        return self.authz_plugins.get(name)


# ============================================================================
# Main Entry Point
# ============================================================================

async def main():
    """Main entry point for the daemon"""
    import argparse
    
    parser = argparse.ArgumentParser(description="PubSub Bridge Daemon")
    parser.add_argument("--config", "-c", type=Path, 
                       default=Path("/etc/pubsub-daemon/config.yaml"),
                       help="Configuration file path")
    parser.add_argument("--plugin-dir", "-p", type=Path,
                       default=Path("/etc/pubsub-daemon/plugins"),
                       help="Plugin directory path")
    parser.add_argument("--log-level", "-l", default="INFO",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       help="Log level")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create config store
    config_store = FileConfigStore(args.config)
    
    # Create daemon
    daemon = PubSubDaemon(
        config_store=config_store,
        plugin_dir=args.plugin_dir
    )
    
    # Start daemon
    await daemon.start()


if __name__ == "__main__":
    asyncio.run(main())
