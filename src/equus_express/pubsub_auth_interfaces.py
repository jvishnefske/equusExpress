from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional, Union, AsyncIterator
from dataclasses import dataclass
from enum import Enum
import asyncio


# ============================================================================
# Publish-Subscribe Interface
# ============================================================================

@dataclass
class Message:
    """Container for pub/sub messages with metadata"""
    channel: str
    payload: Any  # Any serializable Python object
    timestamp: Optional[float] = None
    message_id: Optional[str] = None
    headers: Optional[Dict[str, Any]] = None
    reply_to: Optional[str] = None


class QoS(Enum):
    """Quality of Service levels"""
    AT_MOST_ONCE = 0    # Fire and forget
    AT_LEAST_ONCE = 1   # Acknowledged delivery
    EXACTLY_ONCE = 2    # Guaranteed single delivery


class PubSubClient(ABC):
    """Abstract base class for publish-subscribe clients"""
    
    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the pub/sub system"""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the pub/sub system"""
        pass
    
    @abstractmethod
    async def publish(
        self, 
        channel: str, 
        payload: Any, 
        qos: QoS = QoS.AT_MOST_ONCE,
        headers: Optional[Dict[str, Any]] = None,
        reply_to: Optional[str] = None
    ) -> Optional[str]:
        """
        Publish a message to a channel
        
        Args:
            channel: Channel name to publish to
            payload: Any serializable Python object
            qos: Quality of service level
            headers: Optional message headers
            reply_to: Optional reply channel for request/response pattern
            
        Returns:
            Message ID if supported by the implementation
        """
        pass
    
    @abstractmethod
    async def subscribe(
        self, 
        channel: str, 
        callback: Callable[[Message], Union[None, asyncio.Task]]
    ) -> None:
        """
        Subscribe to a channel with a callback function
        
        Args:
            channel: Channel name to subscribe to
            callback: Async function to handle received messages
        """
        pass
    
    @abstractmethod
    async def unsubscribe(self, channel: str) -> None:
        """Unsubscribe from a channel"""
        pass
    
    @abstractmethod
    async def subscribe_stream(self, channel: str) -> AsyncIterator[Message]:
        """
        Subscribe to a channel and return an async iterator of messages
        
        Args:
            channel: Channel name to subscribe to
            
        Yields:
            Message objects as they arrive
        """
        pass
    
    @abstractmethod
    async def request(
        self, 
        channel: str, 
        payload: Any, 
        timeout: float = 5.0,
        qos: QoS = QoS.AT_LEAST_ONCE
    ) -> Message:
        """
        Send a request and wait for a response (request/response pattern)
        
        Args:
            channel: Channel to send request to
            payload: Request payload
            timeout: Maximum time to wait for response
            qos: Quality of service level
            
        Returns:
            Response message
            
        Raises:
            TimeoutError: If no response received within timeout
        """
        pass
    
    @abstractmethod
    async def reply(self, original_message: Message, response_payload: Any) -> None:
        """
        Reply to a message (for request/response pattern)
        
        Args:
            original_message: The original message to reply to
            response_payload: The response data
        """
        pass
    
    @abstractmethod
    def is_connected(self) -> bool:
        """Check if client is connected"""
        pass
    
    @abstractmethod
    async def get_channels(self) -> List[str]:
        """Get list of available channels (if supported)"""
        pass


# ============================================================================
# Authentication/Authorization Interface
# ============================================================================

@dataclass
class AuthContext:
    """Authentication context containing user/client information"""
    user_id: str
    roles: List[str]
    permissions: List[str]
    metadata: Dict[str, Any]
    expires_at: Optional[float] = None
    issued_at: Optional[float] = None


@dataclass
class AuthCredentials:
    """Generic credentials container"""
    credential_type: str  # 'jwt', 'public_key', 'api_key', etc.
    credential_data: Dict[str, Any]  # Flexible data structure


class AuthResult(Enum):
    """Authentication/authorization result"""
    SUCCESS = "success"
    FAILED = "failed"
    EXPIRED = "expired"
    INSUFFICIENT_PERMISSIONS = "insufficient_permissions"


@dataclass
class AuthResponse:
    """Response from authentication/authorization operations"""
    result: AuthResult
    context: Optional[AuthContext] = None
    error_message: Optional[str] = None
    token: Optional[str] = None  # For token-based systems


class AuthProvider(ABC):
    """Abstract base class for authentication providers"""
    
    @abstractmethod
    async def authenticate(self, credentials: AuthCredentials) -> AuthResponse:
        """
        Authenticate using provided credentials
        
        Args:
            credentials: Authentication credentials
            
        Returns:
            AuthResponse with result and context
        """
        pass
    
    @abstractmethod
    async def validate_token(self, token: str) -> AuthResponse:
        """
        Validate an authentication token
        
        Args:
            token: Token to validate (JWT, session token, etc.)
            
        Returns:
            AuthResponse with validation result
        """
        pass
    
    @abstractmethod
    async def refresh_token(self, token: str) -> AuthResponse:
        """
        Refresh an authentication token
        
        Args:
            token: Current token to refresh
            
        Returns:
            AuthResponse with new token
        """
        pass
    
    @abstractmethod
    async def revoke_token(self, token: str) -> bool:
        """
        Revoke/invalidate a token
        
        Args:
            token: Token to revoke
            
        Returns:
            True if successfully revoked
        """
        pass


class AuthorizationProvider(ABC):
    """Abstract base class for authorization providers"""
    
    @abstractmethod
    async def authorize(
        self, 
        context: AuthContext, 
        resource: str, 
        action: str
    ) -> AuthResult:
        """
        Check if user is authorized to perform an action on a resource
        
        Args:
            context: Authentication context
            resource: Resource being accessed (e.g., channel name, endpoint)
            action: Action being performed (e.g., 'read', 'write', 'subscribe')
            
        Returns:
            Authorization result
        """
        pass
    
    @abstractmethod
    async def get_permissions(self, context: AuthContext) -> List[str]:
        """
        Get all permissions for the authenticated user
        
        Args:
            context: Authentication context
            
        Returns:
            List of permission strings
        """
        pass
    
    @abstractmethod
    async def has_permission(
        self, 
        context: AuthContext, 
        permission: str
    ) -> bool:
        """
        Check if user has a specific permission
        
        Args:
            context: Authentication context
            permission: Permission to check
            
        Returns:
            True if user has permission
        """
        pass
    
    @abstractmethod
    async def get_user_roles(self, context: AuthContext) -> List[str]:
        """
        Get roles for the authenticated user
        
        Args:
            context: Authentication context
            
        Returns:
            List of role names
        """
        pass


class SecurePubSubClient(PubSubClient):
    """Extended pub/sub client with authentication/authorization"""
    
    def __init__(
        self, 
        auth_provider: AuthProvider,
        authz_provider: AuthorizationProvider
    ):
        self.auth_provider = auth_provider
        self.authz_provider = authz_provider
        self.auth_context: Optional[AuthContext] = None
    
    @abstractmethod
    async def authenticate(self, credentials: AuthCredentials) -> AuthResponse:
        """Authenticate with the pub/sub system"""
        pass
    
    async def _check_authorization(self, resource: str, action: str) -> None:
        """Helper method to check authorization before operations"""
        if not self.auth_context:
            raise PermissionError("Not authenticated")
        
        result = await self.authz_provider.authorize(
            self.auth_context, resource, action
        )
        
        if result != AuthResult.SUCCESS:
            raise PermissionError(f"Authorization failed: {result.value}")


# ============================================================================
# Usage Examples (as comments for reference)
# ============================================================================

"""
Example usage patterns:

# NATS Implementation
class NATSClient(PubSubClient):
    async def connect(self):
        # Connect to NATS server
        pass
    
    async def publish(self, channel, payload, qos=QoS.AT_MOST_ONCE, **kwargs):
        # Serialize payload and publish to NATS
        pass

# MQTT Implementation  
class MQTTClient(PubSubClient):
    async def connect(self):
        # Connect to MQTT broker
        pass
    
    async def publish(self, channel, payload, qos=QoS.AT_MOST_ONCE, **kwargs):
        # Serialize payload and publish to MQTT
        pass

# I2C Hardware Implementation
class I2CClient(PubSubClient):
    async def connect(self):
        # Initialize I2C interface
        pass
    
    async def publish(self, channel, payload, qos=QoS.AT_MOST_ONCE, **kwargs):
        # Send data to I2C device
        pass

# JWT Authentication Provider
class JWTAuthProvider(AuthProvider):
    async def authenticate(self, credentials):
        # Validate JWT token
        pass
    
    async def validate_token(self, token):
        # Decode and validate JWT
        pass

# Public Key Authentication Provider
class PublicKeyAuthProvider(AuthProvider):
    async def authenticate(self, credentials):
        # Verify signature with public key
        pass
    
    async def validate_token(self, token):
        # Validate signed token
        pass

# Role-based Authorization Provider
class RBACAuthorizationProvider(AuthorizationProvider):
    async def authorize(self, context, resource, action):
        # Check roles and permissions
        pass
"""