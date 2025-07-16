#!/usr/bin/env python3
"""
Secure API Client with mTLS Authentication
Uses provisioned certificates to authenticate with the secure server
"""

import httpx
import ssl
import json
import logging
import os
import time
from datetime import datetime, timezone
import socket
import asyncio # Added for async operations
import uuid # Added for UUID parsing

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# NATS imports
import nats
from nats.errors import ConnectionClosedError, TimeoutError, NoServersError
from nats.nkeys import KeyPair, InvalidNKey

# SMBus imports
try:
    import smbus2
except ImportError:
    smbus2 = None
    logger.warning(
        "smbus2 not found. SMBus communication will be unavailable."
    )

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import psutil if available (optional dependency for telemetry)
try:
    import psutil
except ImportError:
    psutil = None
    logger.warning(
        "psutil not found. Some telemetry data might be unavailable."
    )


class PsutilNotInstalled(NotImplementedError):
    def __init__(self, message="psutil library is not available."):
        super().__init__(message)

class SMBusNotAvailable(NotImplementedError):
    def __init__(self, message="smbus2 library is not available or bus not initialized."):
        super().__init__(message)

# Define default key storage directory
DEFAULT_KEY_DIR = os.path.expanduser("~/.equus_express/keys")


class SecureAPIClient:
    def __init__(
        self,
        base_url: str,
        device_id: str = None,
        key_dir: str = DEFAULT_KEY_DIR,
    ):
        """
        Initialize the secure API client with public key management.

        Args:
            base_url: Base URL of the API server (e.g., HTTP for Traefik proxy)
            device_id: Device identifier
            key_dir: Directory to store generated private/public keys
        """
        self.base_url = base_url.rstrip("/")
        self.device_id = device_id or socket.gethostname()
        self.key_dir = key_dir
        self._private_key_path = os.path.join(self.key_dir, "device.pem")
        self._public_key_path = os.path.join(self.key_dir, "device.pub")
        self.private_key = None
        self.public_key_pem = None

        try:
            self._load_or_generate_keys()
        except (OSError, ValueError, TypeError) as e:
            logger.error(f"Error during key loading or generation: {e}")
            raise RuntimeError(f"Failed to initialize client keys: {e}") from e

        # Create httpx client
        self.client = httpx.Client(
            base_url=self.base_url,
            verify=True,
            headers={  # Set default headers, including device ID for identification
                "User-Agent": f"SecureClient/{self.device_id}",
                "Content-Type": "application/json",
                "X-Device-Id": self.device_id,  # Temporarily pass device_id in header for simplified auth
            },
        )

        logger.info(f"Initialized client for device: {self.device_id}")

    def _load_or_generate_keys(self):
        """Load existing keys or generate new RSA key pair."""
        os.makedirs(self.key_dir, exist_ok=True)  # Ensure directory exists

        if os.path.exists(self._private_key_path) and os.path.exists(
            self._public_key_path
        ):
            with open(self._private_key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            with open(self._public_key_path, "rb") as f:
                self.public_key_pem = (
                    f.read().decode("utf-8").strip()
                )  # Strip newline here
            logger.info("Existing device keys loaded.")
        else:
            logger.info("Generating new device keys...")
            self.private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            # Serialize private key
            pem_private_key = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            # Serialize public key
            pem_public_key = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
                encryption_algorithm=serialization.NoEncryption(),
            )
            self.public_key_pem = pem_public_key.decode(
                "utf-8"
            ).strip()  # Strip newline here

            with open(self._private_key_path, "wb") as f:
                f.write(pem_private_key)
            with open(self._public_key_path, "wb") as f:
                f.write(pem_public_key)
            logger.info(
                f"New device keys generated and saved to {self.key_dir}"
            )

    def _make_request(self, method: str, endpoint: str, **kwargs):
        """Make a request with error handling and logging"""
        url = f"{self.base_url}{endpoint}"

        try:
            logger.debug(f"Making {method} request to {url}")
            response = self.client.request(
                method, url, **kwargs
            )  # Changed self.session to self.client

            # Log response status
            logger.debug(f"Response status: {response.status_code}")

            # Raise for HTTP errors
            response.raise_for_status()

            # Try to parse JSON response
            try:
                return response.json()
            except json.JSONDecodeError:
                # This branch is taken if response is 2xx but not valid JSON
                logger.debug(f"Non-JSON response received from {url}")
                return response.text

        except httpx.ConnectError as e:
            logger.error(f"Connection error: {e}")
            raise ConnectionError(f"Failed to connect to server: {e}") from e
        except httpx.HTTPStatusError as e:
            logger.error(
                f"HTTP error: {e.response.status_code} - {e.response.text}"
            )
            if e.response.status_code == 401:
                raise PermissionError(
                    "Authentication failed - invalid client certificate"
                ) from e
            elif e.response.status_code == 403:
                raise PermissionError(
                    "Access denied - insufficient permissions"
                ) from e
            else:
                raise  # Re-raise original httpx.HTTPStatusError
        except httpx.RequestError as e:
            logger.error(f"Request failed: {e}")
            raise ConnectionError(f"Request to server failed: {e}") from e

    def get(self, endpoint: str, **kwargs):
        """Make a GET request"""
        return self._make_request("GET", endpoint, **kwargs)

    def post(self, endpoint: str, data=None, json=None, **kwargs):
        """Make a POST request"""
        return self._make_request(
            "POST", endpoint, data=data, json=json, **kwargs
        )

    def put(self, endpoint: str, data=None, json=None, **kwargs):
        """Make a PUT request"""
        return self._make_request(
            "PUT", endpoint, data=data, json=json, **kwargs
        )

    def delete(self, endpoint: str, **kwargs):
        """Make a DELETE request"""
        return self._make_request("DELETE", endpoint, **kwargs)

    def register_device(self):
        """Register the device's public key with the server."""
        if not self.public_key_pem:
            # Uncovered: Client does not have a public key for registration
            raise RuntimeError("Public key not available for registration.")

        logger.info(
            f"Attempting to register device '{self.device_id}' with server..."
        )
        registration_payload = {
            "device_id": self.device_id,
            "public_key": self.public_key_pem,
        }
        try:
            response = self.post("/api/register", json=registration_payload)
            logger.info(f"Device registration response: {response}")
            return response
        except (httpx.RequestError, ConnectionError, PermissionError) as e:
            # Uncovered: Network/server issue during registration
            logger.error(
                f"Failed to register device due to network/server issue: {e}"
            )
            raise  # Re-raise the specific exception

    def health_check(self):
        """Check server health"""
        return self.get("/health")

    def get_device_info(self):
        """Get device information from server"""
        return self.get("/api/device/info")

    def send_telemetry(self, data: dict):
        """Send telemetry data to server"""
        telemetry_payload = {
            "device_id": self.device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        return self.post("/api/telemetry", json=telemetry_payload)

    def get_configuration(self):
        """Get device configuration from server"""
        return self.get(f"/api/device/{self.device_id}/config")

    def update_status(self, status: str, details: dict = None):
        """Update device status"""
        status_payload = {
            "device_id": self.device_id,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details or {},
        }
        return self.post("/api/device/status", json=status_payload)

    def test_connection(self):
        """Test the secure connection and certificate authentication"""
        try:
            logger.info("Testing connection and registration...")

            # Test basic connectivity
            response = self.health_check()
            logger.info(f"Health check response: {response}")

            # Attempt to register device (or re-register if already done)
            registration_response = self.register_device()
            logger.info(
                f"Device registration/update response: {registration_response}"
            )

            # Test an endpoint that relies on registered device_id (e.g., get_device_info)
            # The server now relies on X-Device-Id header for initial simplified auth.
            try:
                device_info = self.get_device_info()
                logger.info(f"Device info: {device_info}")
            except (
                httpx.RequestError,
                ConnectionError,
                PermissionError,
            ) as e:  # Catch specific exceptions here
                # Uncovered: Device info endpoint failed (warning but continue)
                logger.warning(
                    f"Device info endpoint failed (this might be expected if server requires stronger auth post-registration): {e}"
                )
                # This is a warning, so we continue and still return True if other steps succeeded.

            logger.info(
                "✅ Connection test and initial registration step completed!"
            )
            return True

        except (
            httpx.RequestError,
            ConnectionError,
            PermissionError,
            RuntimeError,
        ) as e:
            logger.error(f"❌ Connection test or registration failed: {e}")
            return False


class NATSClient:
    def __init__(
        self,
        nats_url: str,
        device_id: str,
        key_dir: str = DEFAULT_KEY_DIR,
    ):
        self.nats_url = nats_url
        self.device_id = device_id
        self.key_dir = key_dir
        self._nkey_seed_path = os.path.join(self.key_dir, "device.nk")
        self._nkey_public_path = os.path.join(self.key_dir, "device.pub.nk")
        self.nkey_pair = None
        self.nc = None  # NATS connection object

        try:
            self._load_or_generate_nkeys()
        except (OSError, ValueError, InvalidNKey) as e:
            logger.error(f"Error during NATS nkey loading or generation: {e}")
            raise RuntimeError(f"Failed to initialize NATS nkeys: {e}") from e

    def _load_or_generate_nkeys(self):
        """Load existing NATS nkeys or generate new ones."""
        os.makedirs(self.key_dir, exist_ok=True)

        if os.path.exists(self._nkey_seed_path) and os.path.exists(
            self._nkey_public_path
        ):
            with open(self._nkey_seed_path, "rb") as f:
                seed = f.read()
            self.nkey_pair = KeyPair.from_seed(seed)
            logger.info("Existing NATS nkeys loaded.")
        else:
            logger.info("Generating new NATS nkeys...")
            self.nkey_pair = KeyPair.new()
            seed = self.nkey_pair.seed
            public_key = self.nkey_pair.public_key

            with open(self._nkey_seed_path, "wb") as f:
                f.write(seed)
            with open(self._nkey_public_path, "wb") as f:
                f.write(public_key)
            logger.info(
                f"New NATS nkeys generated and saved to {self.key_dir}"
            )

    async def connect(self):
        """Connect to NATS server."""
        if self.nc and self.nc.is_connected:
            logger.info("NATS client already connected.")
            return

        try:
            logger.info(f"Connecting to NATS server at {self.nats_url}...")
            self.nc = await nats.connect(
                self.nats_url,
                nkeys_seed=self.nkey_pair.seed,
                user_jwt_cb=self._user_jwt_callback,
                signature_cb=self._signature_callback,
                name=self.device_id, # Set client name for easier identification
                error_cb=self._nats_error_cb,
                reconnected_cb=self._nats_reconnected_cb,
                disconnected_cb=self._nats_disconnected_cb,
                closed_cb=self._nats_closed_cb,
            )
            logger.info(f"Connected to NATS server: {self.nc.connected_url.netloc}")
        except NoServersError as e:
            logger.error(f"NATS connection failed: No servers available at {self.nats_url}. Error: {e}")
            raise ConnectionError(f"NATS connection failed: {e}") from e
        except ConnectionClosedError as e:
            logger.error(f"NATS connection closed unexpectedly: {e}")
            raise ConnectionError(f"NATS connection closed: {e}") from e
        except TimeoutError as e:
            logger.error(f"NATS connection timed out: {e}")
            raise ConnectionError(f"NATS connection timed out: {e}") from e
        except Exception as e:
            logger.error(f"An unexpected error occurred during NATS connection: {e}")
            raise ConnectionError(f"NATS connection failed: {e}") from e

    async def disconnect(self):
        """Disconnect from NATS server."""
        if self.nc and self.nc.is_connected:
            logger.info("Disconnecting from NATS server...")
            await self.nc.close()
            logger.info("Disconnected from NATS server.")
        else:
            logger.info("NATS client not connected.")

    async def publish(self, subject: str, payload: bytes):
        """Publish a message to a NATS subject."""
        if not self.nc or not self.nc.is_connected:
            logger.warning(f"NATS client not connected, cannot publish to {subject}.")
            return
        try:
            await self.nc.publish(subject, payload)
            logger.debug(f"Published to {subject}: {payload[:50]}...")
        except Exception as e:
            logger.error(f"Failed to publish to {subject}: {e}")
            raise

    async def subscribe(self, subject: str, cb):
        """Subscribe to a NATS subject."""
        if not self.nc or not self.nc.is_connected:
            logger.warning(f"NATS client not connected, cannot subscribe to {subject}.")
            return None
        try:
            sub = await self.nc.subscribe(subject, cb=cb)
            logger.info(f"Subscribed to {subject}")
            return sub
        except Exception as e:
            logger.error(f"Failed to subscribe to {subject}: {e}")
            raise

    def _user_jwt_callback(self):
        """Callback to provide user JWT for NATS authentication."""
        return self.nkey_pair.public_key.decode()

    def _signature_callback(self, nonce):
        """Callback to sign the nonce for NATS authentication."""
        return self.nkey_pair.sign(nonce)

    async def _nats_error_cb(self, e):
        logger.error(f"NATS error: {e}")

    async def _nats_reconnected_cb(self):
        logger.info(f"NATS reconnected to {self.nc.connected_url.netloc}")

    async def _nats_disconnected_cb(self):
        logger.warning("NATS disconnected!")

    async def _nats_closed_cb(self):
        logger.info("NATS connection closed.")


class DeviceAgent:
    """High-level device agent that handles ongoing operations"""

    def __init__(
        self,
        client: SecureAPIClient,
        nats_client: NATSClient,
        smbus_address: int = None,
        smbus_bus_num: int = 1,
    ):
        self.client = client # For REST API communication
        self.nats_client = nats_client # For NATS real-time communication
        self.running = False
        self.telemetry_task = None
        self.command_listener_task = None

        self.smbus_address = smbus_address
        self.smbus_bus_num = smbus_bus_num
        self.smbus = None

        if smbus2 and self.smbus_address is not None:
            try:
                self.smbus = smbus2.SMBus(self.smbus_bus_num)
                logger.info(f"SMBus initialized on bus {self.smbus_bus_num} with address {hex(self.smbus_address)}")
            except Exception as e:
                logger.error(f"Failed to initialize SMBus on bus {self.smbus_bus_num}: {e}")
                self.smbus = None # Ensure it's None if initialization fails
        elif self.smbus_address is None:
            logger.info("SMBus address not provided, SMBus functionality will be disabled.")
        else:
            logger.warning("smbus2 library not available, SMBus functionality will be disabled.")


    async def start(self):
        """Start the device agent"""
        logger.info("Starting device agent...")

        # Perform connection test and registration with REST API
        if not self.client.test_connection():
            logger.error("Failed initial REST API connection and registration.")
            self.running = False
            return False

        # Connect to NATS
        try:
            await self.nats_client.connect()
        except ConnectionError as e:
            logger.error(f"Failed to connect to NATS: {e}")
            self.running = False
            return False

        self.running = True

        # Start NATS command listener
        self.command_listener_task = asyncio.create_task(self._command_listener())

        # Send initial status after successful connection/registration
        try:
            # Use NATS for status updates as per design doc implies real-time state
            status_payload = {
                "device_id": self.client.device_id,
                "status": "online",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": {
                    "startup_time": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0",
                },
            }
            await self.nats_client.publish("device.status", json.dumps(status_payload).encode())
            logger.info("Published initial 'online' status via NATS.")
        except Exception as e:
            logger.warning(f"Failed to send initial 'online' status via NATS: {e}")

        return True

    async def stop(self):
        """Stop the device agent"""
        logger.info("Stopping device agent...")
        self.running = False

        # Cancel running tasks
        if self.telemetry_task:
            self.telemetry_task.cancel()
            try:
                await self.telemetry_task
            except asyncio.CancelledError:
                logger.debug("Telemetry task cancelled.")
        if self.command_listener_task:
            self.command_listener_task.cancel()
            try:
                await self.command_listener_task
            except asyncio.CancelledError:
                logger.debug("Command listener task cancelled.")

        # Send offline status via NATS
        try:
            status_payload = {
                "device_id": self.client.device_id,
                "status": "offline",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": {"shutdown_time": datetime.now(timezone.utc).isoformat()},
            }
            await self.nats_client.publish("device.status", json.dumps(status_payload).encode())
            logger.info("Published 'offline' status via NATS.")
        except Exception as e:
            logger.warning(f"Failed to send offline status via NATS: {e}")

        # Disconnect from NATS
        await self.nats_client.disconnect()

        # Close SMBus if open
        if self.smbus:
            try:
                self.smbus.close()
                logger.info("SMBus closed.")
            except Exception as e:
                logger.warning(f"Error closing SMBus: {e}")


    async def run_telemetry_loop(self, interval: int = 60):
        """Run continuous telemetry reporting"""
        logger.info(f"Starting telemetry loop (interval: {interval}s)")

        while self.running:
            try:
                # Collect telemetry data
                telemetry_data = self._collect_telemetry()

                # Send to server via NATS
                telemetry_payload = {
                    "device_id": self.client.device_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": telemetry_data,
                }
                await self.nats_client.publish("pvs/update", json.dumps(telemetry_payload).encode())
                logger.debug("Telemetry published via NATS.")

                # Wait for next interval
                await asyncio.sleep(interval)

            except asyncio.CancelledError:
                logger.info("Telemetry loop cancelled.")
                break
            except (
                ConnectionError,
                json.JSONDecodeError,
                TypeError,
            ) as e:
                logger.error(
                    f"Telemetry loop communication or data error: {e}"
                )
                await asyncio.sleep(interval)  # Wait before retrying
            except Exception as e:
                logger.exception(
                    f"An unexpected error occurred in telemetry loop: {e}"
                )
                await asyncio.sleep(interval)

    async def _command_listener(self):
        """Listen for commands on NATS and process them."""
        logger.info("Starting NATS command listener...")
        try:
            # Subscribe to a specific command topic for this device
            # Example: "command.execute.device_id" or a general "command.execute"
            # For now, let's use a general topic as per DESIGN.md
            await self.nats_client.subscribe(
                "command/execute", cb=self._handle_command_message
            )
            # Keep the listener alive
            while self.running:
                await asyncio.sleep(1) # Keep the task alive
        except asyncio.CancelledError:
            logger.info("NATS command listener cancelled.")
        except Exception as e:
            logger.error(f"Error in NATS command listener: {e}")

    async def _handle_command_message(self, msg):
        """Callback for NATS command messages."""
        subject = msg.subject
        reply = msg.reply
        data = msg.data.decode()

        logger.info(f"Received NATS message on '{subject}': {data}")

        try:
            command = json.loads(data)
            cmd_type = command.get("cmd")
            params = command.get("params", {})

            response_data = await self._handle_command(cmd_type, params)
            if reply:
                await self.nats_client.publish(reply, json.dumps(response_data).encode())

        except json.JSONDecodeError:
            logger.error(f"Invalid JSON received on '{subject}': {data}")
            if reply:
                await self.nats_client.publish(reply, json.dumps({"status": "error", "message": "Invalid JSON"}).encode())
        except Exception as e:
            logger.exception(f"Error processing command on '{subject}': {e}")
            if reply:
                await self.nats_client.publish(reply, json.dumps({"status": "error", "message": str(e)}).encode())

    async def _handle_command(self, cmd_type: str, params: dict) -> dict:
        """Process a specific command, potentially interacting with SMBus."""
        logger.info(f"Processing command: {cmd_type} with params: {params}")
        response = {"status": "success", "command": cmd_type, "params": params}

        if cmd_type == "SMBUS_WRITE_BLOCK":
            address = params.get("address", self.smbus_address)
            command_code = params.get("command_code")
            data = params.get("data")
            if address is None:
                response = {"status": "error", "message": "SMBus address not specified for command."}
            elif command_code is None or data is None:
                response = {"status": "error", "message": "Missing command_code or data for SMBUS_WRITE_BLOCK."}
            else:
                try:
                    # SMBus operations are blocking, run in a thread pool
                    await asyncio.to_thread(self._smbus_write_block_data, address, command_code, data)
                    response["message"] = f"SMBus block write to address {hex(address)}, command {hex(command_code)} successful."
                except SMBusNotAvailable as e:
                    response = {"status": "error", "message": str(e)}
                except Exception as e:
                    logger.error(f"SMBus write block failed: {e}")
                    response = {"status": "error", "message": f"SMBus write block failed: {e}"}
        elif cmd_type == "SMBUS_READ_BLOCK":
            address = params.get("address", self.smbus_address)
            command_code = params.get("command_code")
            length = params.get("length")
            if address is None:
                response = {"status": "error", "message": "SMBus address not specified for command."}
            elif command_code is None or length is None:
                response = {"status": "error", "message": "Missing command_code or length for SMBUS_READ_BLOCK."}
            else:
                try:
                    # SMBus operations are blocking, run in a thread pool
                    read_data = await asyncio.to_thread(self._smbus_read_block_data, address, command_code, length)
                    response["data"] = list(read_data) # Convert bytearray to list for JSON serialization
                    response["message"] = f"SMBus block read from address {hex(address)}, command {hex(command_code)} successful."
                except SMBusNotAvailable as e:
                    response = {"status": "error", "message": str(e)}
                except Exception as e:
                    logger.error(f"SMBus read block failed: {e}")
                    response = {"status": "error", "message": f"SMBus read block failed: {e}"}
        else:
            response = {"status": "error", "message": f"Unknown command type: {cmd_type}"}

        return response

    def _smbus_write_block_data(self, address: int, command_code: int, data: list):
        """Write a block of data to an SMBus device."""
        if not self.smbus:
            raise SMBusNotAvailable()
        if address != self.smbus_address:
            logger.warning(f"SMBus write requested for address {hex(address)} but agent is configured for {hex(self.smbus_address)}. Using requested address.")
        try:
            self.smbus.write_i2c_block_data(address, command_code, data)
            logger.info(f"SMBus write_i2c_block_data: addr={hex(address)}, cmd={hex(command_code)}, data={data}")
        except OSError as e:
            logger.error(f"SMBus write_i2c_block_data OSError: {e}")
            raise IOError(f"SMBus write error: {e}") from e
        except Exception as e:
            logger.error(f"SMBus write_i2c_block_data unexpected error: {e}")
            raise

    def _smbus_read_block_data(self, address: int, command_code: int, length: int) -> bytearray:
        """Read a block of data from an SMBus device."""
        if not self.smbus:
            raise SMBusNotAvailable()
        if address != self.smbus_address:
            logger.warning(f"SMBus read requested for address {hex(address)} but agent is configured for {hex(self.smbus_address)}. Using requested address.")
        try:
            # read_i2c_block_data returns a list of integers
            data = self.smbus.read_i2c_block_data(address, command_code, length)
            logger.info(f"SMBus read_i2c_block_data: addr={hex(address)}, cmd={hex(command_code)}, length={length}, data={data}")
            return bytearray(data)
        except OSError as e:
            logger.error(f"SMBus read_i2c_block_data OSError: {e}")
            raise IOError(f"SMBus read error: {e}") from e
        except Exception as e:
            logger.error(f"SMBus read_i2c_block_data unexpected error: {e}")
            raise

    def _collect_telemetry(self) -> dict:
        """Collect telemetry data from the device"""
        telemetry = {
            "system": {},
            "network": {},
            "application": {"status": "running", "last_error": None},
        }
        errors = []

        # Example telemetry data collection
        try:
            telemetry["system"]["uptime"] = self._get_uptime()
        except Exception as e:
            errors.append(f"uptime: {e}")
            telemetry["system"]["uptime"] = "error"

        try:
            telemetry["system"]["cpu_usage"] = self._get_cpu_usage()
        except Exception as e:
            errors.append(f"cpu_usage: {e}")
            telemetry["system"]["cpu_usage"] = "error"

        try:
            telemetry["system"]["memory_usage"] = self._get_memory_usage()
        except Exception as e:
            errors.append(f"memory_usage: {e}")
            telemetry["system"]["memory_usage"] = {"error": str(e)}

        try:
            telemetry["system"]["disk_usage"] = self._get_disk_usage()
        except Exception as e:
            errors.append(f"disk_usage: {e}")
            telemetry["system"]["disk_usage"] = {"error": str(e)}

        try:
            telemetry["system"]["temperature"] = self._get_temperature()
        except Exception as e:
            errors.append(f"temperature: {e}")
            telemetry["system"]["temperature"] = "error"

        try:
            telemetry["network"]["ip_address"] = self._get_ip_address()
        except Exception as e:
            errors.append(f"ip_address: {e}")
            telemetry["network"]["ip_address"] = "error"

        telemetry["network"]["connection_quality"] = "good"  # Simplified

        if errors:
            telemetry["application"]["last_error"] = "; ".join(errors)
            logger.warning(
                f"Partial telemetry collection errors: {telemetry['application']['last_error']}"
            )

        return telemetry

    def _get_uptime(self) -> float:
        """Get system uptime"""
        try:
            with open("/proc/uptime", "r") as f:
                return float(f.readline().split()[0])
        except OSError as e:
            logger.warning(f"Failed to get uptime: {e}")
            raise  # Re-raise for _collect_telemetry to catch and report

    def _get_cpu_usage(self) -> float:
        """Get CPU usage percentage"""
        if psutil:
            try:
                return psutil.cpu_percent(interval=1)
            except psutil.Error as e:
                logger.warning(f"psutil CPU usage error: {e}")
                raise  # Re-raise for _collect_telemetry to catch and report
        else:
            logger.debug("psutil not available for CPU usage.")
            raise PsutilNotInstalled("psutil library is not available.")

    def _get_memory_usage(self) -> dict:
        """Get memory usage information"""
        if psutil:
            try:
                mem = psutil.virtual_memory()
                return {
                    "total": mem.total,
                    "available": mem.available,
                    "percent": mem.percent,
                }
            except psutil.Error as e:
                logger.warning(f"psutil memory usage error: {e}")
                raise
        else:
            logger.debug("psutil not available for memory usage.")
            raise PsutilNotInstalled("psutil library is not available.")

    def _get_disk_usage(self) -> dict:
        """Get disk usage information"""
        if psutil:
            try:
                disk = psutil.disk_usage("/")
                return {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "percent": (disk.used / disk.total) * 100,
                }
            except psutil.Error as e:
                logger.warning(f"psutil disk usage error: {e}")
                raise
        else:
            logger.debug("psutil not available for disk usage.")
            raise PsutilNotInstalled("psutil library is not available.")

    def _get_temperature(self) -> float:
        """Get CPU temperature (Raspberry Pi specific)"""
        try:
            with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
                temp = float(f.read().strip()) / 1000.0
                return temp
        except OSError as e:
            logger.warning(f"Failed to get temperature: {e}")
            raise

    def _get_ip_address(self) -> str:
        """Get device IP address (prefer non-loopback IPv4, fallback to hostname resolution)"""
        try:
            # gethostname() retrieves the local host's name
            # gethostbyname() resolves a host name to an IPv4 address
            ip = socket.gethostbyname(socket.gethostname())
            logger.debug(f"Resolved IP via gethostbyname(gethostname()): {ip}")
            return ip
        except (
            socket.gaierror
        ) as e:  # Address information error (e.g., hostname not found)
            logger.warning(
                f"Failed to get IP address via hostname resolution: {e}"
            )
            raise  # Re-raise for _collect_telemetry to catch and report
        except OSError as e:  # General OS error during hostname resolution
            # Uncovered: OS error during IP address retrieval from hostname
            logger.warning(
                f"OS error during IP address retrieval from hostname: {e}"
            )
            raise  # Re-raise for _collect_telemetry to catch and report


async def main():
    """Main function for running the secure client"""
    import sys

    if len(sys.argv) < 3:
        print(
            "Usage: python3 edge_device_controller.py <secure_server_url> <nats_url> [device_id] [smbus_address] [smbus_bus_num]"
        )
        print("Example: python3 edge_device_controller.py http://secure-server:8000 nats://localhost:4222 my_device_01 0x50 1")
        sys.exit(1)

    server_url = sys.argv[1]
    nats_url = sys.argv[2]
    device_id = sys.argv[3] if len(sys.argv) > 3 else None
    smbus_address = None
    smbus_bus_num = 1 # Default SMBus bus number

    if len(sys.argv) > 4:
        try:
            # Attempt to parse as int (decimal or hex)
            smbus_address = int(sys.argv[4], 0)
        except ValueError:
            logger.warning(f"Invalid SMBus address provided: {sys.argv[4]}. Attempting to derive from device_id.")
            smbus_address = None # Reset if invalid

    if len(sys.argv) > 5:
        try:
            smbus_bus_num = int(sys.argv[5])
        except ValueError:
            logger.warning(f"Invalid SMBus bus number provided: {sys.argv[5]}. Using default bus 1.")
            smbus_bus_num = 1

    # If device_id is a UUID and smbus_address was not provided or invalid, try to derive it
    if smbus_address is None and device_id:
        try:
            device_uuid = uuid.UUID(device_id)
            # Use the last byte of the UUID as a 7-bit SMBus address
            smbus_address = device_uuid.bytes[-1] & 0x7F
            logger.info(f"Derived SMBus address from device_id: {hex(smbus_address)}")
        except ValueError:
            logger.warning(f"Device ID '{device_id}' is not a valid UUID, cannot derive SMBus address.")
            smbus_address = None # Ensure it's None if derivation fails

    try:
        # Create REST API client
        client = SecureAPIClient(base_url=server_url, device_id=device_id)
        # Ensure device_id is set from SecureAPIClient if it was None initially
        device_id = client.device_id

        # Create NATS client
        nats_client = NATSClient(nats_url=nats_url, device_id=device_id)

        # Create device agent
        agent = DeviceAgent(
            client=client,
            nats_client=nats_client,
            smbus_address=smbus_address,
            smbus_bus_num=smbus_bus_num
        )

        # Start agent
        if await agent.start():
            logger.info("Device agent started successfully")

            # Run telemetry loop concurrently
            agent.telemetry_task = asyncio.create_task(agent.run_telemetry_loop(interval=30))

            # Keep main running until interrupted
            while agent.running:
                await asyncio.sleep(1)

        else:
            logger.error("Failed to start device agent")
            sys.exit(1)

    except (RuntimeError, ConnectionError, PermissionError) as e:
        logger.error(f"A critical client error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(
            f"An unexpected error occurred in the main client process: {e}"
        )
        sys.exit(1)
    finally:
        # Ensure agent stops cleanly on exit
        if 'agent' in locals() and agent.running:
            await agent.stop()
        elif 'nats_client' in locals() and nats_client.nc and nats_client.nc.is_connected:
            # If agent didn't start, but NATS client did, ensure it closes
            await nats_client.disconnect()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Client stopped by user.")
    except Exception as e:
        logger.critical(f"Unhandled exception in main asyncio run: {e}")
        sys.exit(1)
