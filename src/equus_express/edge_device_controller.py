import os
import logging
import asyncio
import platform
import socket
import uuid
import json
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Union, Tuple
import httpx
from nats.aio.client import Client as NATS
from nats.errors import ConnectionClosedError, NoServersError, TimeoutError
from nkeys import KeyPair
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import sys

logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError:
    psutil = None
    logger.warning("psutil library not found. System telemetry (CPU, memory, disk) will be unavailable.")

try:
    import smbus2
except ImportError:
    smbus2 = None
    logger.warning("smbus2 library not found. SMBus communication will be unavailable.")


class PsutilNotInstalled(NotImplementedError):
    def __init__(self, message="psutil library is not available."):
        self.message = message
        super().__init__(self.message)


class SMBusNotAvailable(NotImplementedError):
    def __init__(self, message="smbus2 library is not available or bus not initialized."):
        self.message = message
        super().__init__(self.message)


DEFAULT_KEY_DIR = os.path.expanduser("~/.equus_express/keys")


class SecureAPIClient:
    def __init__(
        self,
        base_url: str,
        device_id: str = None,
        key_dir: str = DEFAULT_KEY_DIR,
        timeout: int = 30,
    ):
        self.base_url = base_url
        self.key_dir = key_dir
        os.makedirs(self.key_dir, exist_ok=True)
        self.private_key_path = os.path.join(self.key_dir, "device_private_key.pem")
        self.public_key_path = os.path.join(self.key_dir, "device_public_key.pem")
        self.device_id_path = os.path.join(self.key_dir, "device_id.txt")
        self.client = httpx.AsyncClient(timeout=timeout)
        self.device_id = device_id if device_id else self._load_or_generate_device_id()
        self.private_key, self.public_key_pem = self._load_or_generate_keys()
        logger.info(f"SecureAPIClient initialized for device ID: {self.device_id}")

    def _load_or_generate_device_id(self) -> str:
        if os.path.exists(self.device_id_path):
            with open(self.device_id_path, "r") as f:
                device_id = f.read().strip()
            logger.debug(f"Loaded existing device ID: {device_id}")
            return device_id
        else:
            new_device_id = str(uuid.uuid4())
            with open(self.device_id_path, "w") as f:
                f.write(new_device_id)
            logger.info(f"Generated new device ID: {new_device_id}")
            return new_device_id

    def _load_or_generate_keys(self) -> Tuple[ed25519.Ed25519PrivateKey, str]:
        private_key = None
        public_key_pem = None

        os.makedirs(self.key_dir, exist_ok=True) # Ensure key directory exists before checking files
        if os.path.exists(self.private_key_path) and os.path.exists(self.public_key_path):
            try:
                with open(self.private_key_path, "rb") as f:
                    private_key = serialization.load_pem_private_key(
                        f.read(), password=None, backend=default_backend()
                    )
                # For Ed25519, we load the private key and derive the public key,
                # then load public key if it's stored in OpenSSH format for convenience
                public_key_pem = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.OpenSSH,
                    format=serialization.PublicFormat.OpenSSH,
                ).decode('utf-8').strip()
                logger.debug("Loaded existing Ed25519 keys.")
            except Exception as e:
                logger.error(f"Error loading keys: {e}. Generating new ones.")
                private_key, public_key_pem = self._generate_and_save_keys()
        else:
            logger.info("Keys not found. Generating new Ed25519 keys.")
            private_key, public_key_pem = self._generate_and_save_keys()

        return private_key, public_key_pem

    def _generate_and_save_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend() # Still generating RSA here!
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Ed25519 generation and saving:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key_openssh = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )

        with open(self.private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(self.public_key_path, "wb") as f:
            f.write(public_key_openssh)

        logger.info(f"Generated and saved new Ed25519 keys in {self.key_dir}")
        return private_key, public_key_openssh.decode('utf-8').strip()

        return private_key, public_pem.decode("utf-8")

    def _sign_request(self, data: Union[str, bytes]) -> str:
        if self.private_key is None:
            raise RuntimeError("Private key not loaded for signing.")

        message = data.encode("utf-8") if isinstance(data, str) else data

        # Ed25519 signing does not use padding or hashing parameters like RSA
        signature = self.private_key.sign(message)
        return signature.hex() # Return hex representation of the signature

    async def _make_request(self, method: str, endpoint: str, **kwargs):
        url = f"{self.base_url}{endpoint}"
        headers = kwargs.pop("headers", {})
        headers["X-Device-ID"] = self.device_id

        # Prepare data for signing
        data_to_sign = ""
        if "json" in kwargs and kwargs["json"] is not None:
            data_to_sign = json.dumps(kwargs["json"], sort_keys=True, separators=(",", ":"))
        elif "data" in kwargs and kwargs["data"] is not None:
            data_to_sign = kwargs["data"]
            if isinstance(data_to_sign, bytes):
                data_to_sign = data_to_sign.decode('utf-8') # Ensure string for signing

        headers["X-Signature"] = self._sign_request(data_to_sign)
        kwargs["headers"] = headers

        try:
            response = await self.client.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error for {method} {url}: {e.response.status_code} - {e.response.text}")
            raise
        except httpx.RequestError as e:
            logger.error(f"Network error for {method} {url}: {e}")
            raise
        except Exception as e:
            logger.error(f"An unexpected error occurred during request to {url}: {e}")
            raise

    async def get(self, endpoint: str, **kwargs):
        return await self._make_request("GET", endpoint, **kwargs)

    async def post(self, endpoint: str, data=None, json=None, **kwargs):
        return await self._make_request("POST", endpoint, data=data, json=json, **kwargs)

    async def put(self, endpoint: str, data=None, json=None, **kwargs):
        return await self._make_request("PUT", endpoint, data=data, json=json, **kwargs)

    async def delete(self, endpoint: str, **kwargs):
        return await self._make_request("DELETE", endpoint, **kwargs)

    async def register_device(self):
        logger.info(f"Attempting to register device {self.device_id} with API server.")
        payload = {
            "device_id": self.device_id,
            "public_key_pem": self.public_key_pem,
            "ip_address": self._get_ip_address(),
        }
        try:
            response = await self.post("/api/register", json=payload)
            logger.info(f"Device {self.device_id} registration successful: {response.json()}")
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 409:
                logger.warning(f"Device {self.device_id} already registered or conflict: {e.response.text}")
                return {"message": "Device already registered or conflict", "status": "warning"}
            else:
                logger.error(f"Failed to register device {self.device_id}: {e}")
                raise
        except Exception as e:
            logger.error(f"An error occurred during device registration: {e}")
            raise

    async def health_check(self):
        logger.debug("Performing API health check.")
        try:
            response = await self.get("/health")
            logger.debug(f"API health check successful: {response.json()}")
            return response.json()
        except Exception as e:
            logger.error(f"API health check failed: {e}")
            raise

    async def get_device_info(self):
        logger.debug(f"Fetching info for device {self.device_id}.")
        try:
            response = await self.get("/api/device/info")
            logger.debug(f"Device info received: {response.json()}")
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get device info: {e}")
            raise

    # Removed send_telemetry - now handled by NATS in DeviceAgent
    # async def send_telemetry(self, data: dict):
    #     logger.debug(f"Sending telemetry for device {self.device_id}.")
    #     payload = {
    #         "device_id": self.device_id,
    #         "timestamp": datetime.now(timezone.utc).isoformat(),
    #         "data": data,
    #     }
    #     try:
    #         response = await self.post("/api/telemetry", json=payload)
    #         logger.debug(f"Telemetry sent successfully: {response.json()}")
    #         return response.json()
    #     except Exception as e:
    #         logger.error(f"Failed to send telemetry: {e}")
    #         raise

    async def get_configuration(self):
        logger.debug(f"Fetching configuration for device {self.device_id}.")
        try:
            response = await self.get(f"/api/device/{self.device_id}/config")
            logger.debug(f"Configuration received: {response.json()}")
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get configuration: {e}")
            raise

    # Removed update_status - now handled by NATS in DeviceAgent
    # async def update_status(self, status: str, details: dict = None):
    #     logger.debug(f"Updating status for device {self.device_id} to {status}.")
    #     payload = {
    #         "device_id": self.device_id,
    #         "timestamp": datetime.now(timezone.utc).isoformat(),
    #         "status": status,
    #         "details": details if details is not None else {},
    #     }
    #     try:
    #         response = await self.post("/api/device/status", json=payload)
    #         logger.debug(f"Status updated successfully: {response.json()}")
    #         return response.json()
    #     except Exception as e:
    #         logger.error(f"Failed to update status: {e}")
    #         raise

    async def test_connection(self) -> bool:
        """Tests connectivity to the API server and device registration status."""
        try:
            logger.info("Testing connection to API server...")
            await self.health_check()
            logger.info("API server health check successful.")

            device_info = await self.get_device_info()
            if device_info and device_info.get("device_id") == self.device_id:
                logger.info(f"Device {self.device_id} is registered and recognized by the API server.")
                return True
            else:
                logger.warning(f"Device {self.device_id} not recognized by API server. Attempting to register...")
                await self.register_device()
                # After registration, try to get info again to confirm
                device_info_after_reg = await self.get_device_info()
                if device_info_after_reg and device_info_after_reg.get("device_id") == self.device_id:
                    logger.info(f"Device {self.device_id} successfully registered and recognized.")
                    return True
                else:
                    logger.error(f"Device {self.device_id} registration failed or not recognized after registration.")
                    return False
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False

    def _get_ip_address(self) -> str:
        """Attempts to get the local IP address."""
        try:
            # Create a socket to connect to an external host (doesn't actually send data)
            # This is a common trick to get the local IP address that would be used for outgoing connections
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Google's public DNS server
            ip_address = s.getsockname()[0] 
            s.close()
            return ip_address
        except Exception as e:
            logger.warning(f"Could not determine IP address: {e}. Returning 'unknown'.")
            return "unknown"


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
        self.nkeys_seed_path = os.path.join(self.key_dir, "nats_nkey_seed.txt")
        self.nkeys_public_path = os.path.join(self.key_dir, "nats_nkey_public.txt")
        self.nkey_pair = self._load_or_generate_nkeys()
        self.nc = NATS()
        logger.info(f"NATSClient initialized for device ID: {self.device_id}")

    def _load_or_generate_nkeys(self) -> KeyPair:
        if os.path.exists(self.nkeys_seed_path) and os.path.exists(self.nkeys_public_path):
            try:
                with open(self.nkeys_seed_path, "r") as f:
                    seed = f.read().strip()
                nkey_pair = KeyPair.from_seed(seed.encode())
                logger.debug("Loaded existing NATS NKey pair.")
                return nkey_pair
            except Exception as e:
                logger.error(f"Error loading NATS NKeys: {e}. Generating new ones.")
                return self._generate_and_save_nkeys()
        else:
            logger.info("NATS NKeys not found. Generating new NKey pair.")
            return self._generate_and_save_nkeys()

    def _generate_and_save_nkeys(self) -> KeyPair:
        nkey_pair = KeyPair.new()
        seed = nkey_pair.seed
        public_key = nkey_pair.public_key

        try:
            with open(self.nkeys_seed_path, "wb") as f:
                f.write(seed)
            with open(self.nkeys_public_path, "wb") as f:
                f.write(public_key)
            logger.info("Generated and saved new NATS NKey pair.")
        except OSError as e:
            logger.critical(f"Failed to save NATS NKeys to {self.key_dir}: {e}")
            raise

        return nkey_pair

    async def connect(self):
        logger.info(f"Connecting to NATS server at {self.nats_url}...")
        try:
            await self.nc.connect(
                servers=[self.nats_url],
                nkeys_seed=self.nkey_pair.seed,
                user_jwt_cb=self._user_jwt_callback,
                signature_cb=self._signature_callback,
                error_cb=self._nats_error_cb,
                reconnected_cb=self._nats_reconnected_cb,
                disconnected_cb=self._nats_disconnected_cb,
                closed_cb=self._nats_closed_cb,
                name=f"equus-express-device-{self.device_id}",
            )
            logger.info("Successfully connected to NATS.")
        except NoServersError as e:
            logger.critical(f"NATS connection failed: No servers available at {self.nats_url}. {e}")
            raise
        except TimeoutError as e:
            logger.critical(f"NATS connection timed out: {e}")
            raise
        except ConnectionClosedError as e:
            logger.critical(f"NATS connection closed unexpectedly: {e}")
            raise
        except Exception as e:
            logger.critical(f"An unexpected error occurred during NATS connection: {e}")
            raise

    async def disconnect(self):
        if self.nc.is_connected:
            logger.info("Disconnecting from NATS...")
            await self.nc.close()
            logger.info("Disconnected from NATS.")

    async def publish(self, subject: str, payload: bytes):
        if not self.nc.is_connected:
            logger.warning(f"Not connected to NATS. Cannot publish to {subject}.")
            return
        try:
            await self.nc.publish(subject, payload)
            logger.debug(f"Published to {subject}")
        except Exception as e:
            logger.error(f"Failed to publish to {subject}: {e}")

    async def subscribe(self, subject: str, cb):
        if not self.nc.is_connected:
            logger.warning(f"Not connected to NATS. Cannot subscribe to {subject}.")
            return
        try:
            await self.nc.subscribe(subject, cb=cb)
            logger.info(f"Subscribed to {subject}")
        except Exception as e:
            logger.error(f"Failed to subscribe to {subject}: {e}")

    def _user_jwt_callback(self):
        # This callback is used to provide the user JWT if required by the NATS server.
        # For NKey authentication, the server might issue a challenge.
        # For now, we return None as the NKey seed is provided directly.
        return None

    def _signature_callback(self, nonce):
        # This callback is used to sign the nonce provided by the NATS server
        # during NKey authentication.
        return self.nkey_pair.sign(nonce)

    async def _nats_error_cb(self, e):
        logger.error(f"NATS client error: {e}")

    async def _nats_reconnected_cb(self):
        logger.info("NATS client reconnected.")

    async def _nats_disconnected_cb(self):
        logger.warning("NATS client disconnected.")

    async def _nats_closed_cb(self):
        logger.info("NATS client connection closed.")


class DeviceAgent:
    """High-level device agent that handles ongoing operations"""

    def __init__(
        self,
        client: SecureAPIClient,
        nats_client: NATSClient,
        smbus_address: int = None,
        smbus_bus_num: int = 1,
    ):
        self.client = client
        self.nats_client = nats_client
        self.smbus_address = smbus_address
        self.smbus_bus_num = smbus_bus_num # Keep track of bus number
        self.smbus = None
        self._running = False
        self._telemetry_task = None
        self._command_listener_task = None

        if self.smbus_address is not None:
            if smbus2:
                try: # Ensure smbus is assigned to self.smbus
                    self.smbus = smbus2.SMBus(self.smbus_bus_num)
                    logger.info(f"SMBus initialized on bus {self.smbus_bus_num} for address {hex(self.smbus_address)}")
                except Exception as e:
                    logger.error(f"Failed to initialize SMBus on bus {self.smbus_bus_num}: {e}")
                    self.smbus = None
            else:
                logger.warning("smbus2 not installed, SMBus communication will not be available.")

    async def start(self):
        logger.info("Starting Device Agent...")
        self._running = True

        try:
            # 1. Test API connection and register/verify device (HTTP)
            if not await self.client.test_connection():
                logger.critical("Failed to establish connection with API server or register device. Exiting.")
                self._running = False # Set to false to prevent further loop attempts
                return

            # 2. Connect to NATS
            await self.nats_client.connect()

            # 3. Update device status to 'online' via NATS
            await self._publish_status("online", {"ip_address": self._get_ip_address()})

            # 4. Start telemetry loop
            self._telemetry_task = asyncio.create_task(self.run_telemetry_loop())

            # 5. Start command listener
            command_subject = f"commands.{self.client.device_id}"
            self._command_listener_task = asyncio.create_task(
                self.nats_client.subscribe(command_subject, self._handle_command_message)
            )

            logger.info("Device Agent started successfully.")
        except Exception as e:
            logger.critical(f"Failed to start Device Agent: {e}")
            self._running = False # Set to false if startup fails at any point
            # Attempt to update status to 'error' via NATS if possible
            try:
                await self._publish_status("error", {"message": f"Startup failed: {e}"})
            except Exception as status_e:
                logger.error(f"Failed to publish status 'error' during startup failure: {status_e}")

    async def stop(self):
        logger.info("Stopping Device Agent...")
        self._running = False

        if self._telemetry_task:
            self._telemetry_task.cancel()
            try: # await the task to ensure it's fully cancelled and exceptions are handled
                await self._telemetry_task 
            except asyncio.CancelledError: 
                logger.debug("Telemetry loop cancelled.")

        if self._command_listener_task: 
            self._command_listener_task.cancel()
            try:
                await self._command_listener_task
            except asyncio.CancelledError:
                logger.debug("Command listener cancelled.")

        # Update device status to 'offline' via NATS
        try:
            await self._publish_status("offline")
        except Exception as e:
            logger.error(f"Failed to publish status 'offline' during shutdown: {e}")

        await self.nats_client.disconnect() # Disconnect NATS *after* sending final status

        if self.smbus:
            try:
                self.smbus.close()
                logger.info("SMBus closed.")
            except Exception as e:
                logger.error(f"Error closing SMBus: {e}")

        logger.info("Device Agent stopped.")

    async def run_telemetry_loop(self, interval: int = 1): # Reduced interval for faster testing/demonstration
        """Collects and sends telemetry data at specified intervals via NATS."""
        logger.info(f"Starting telemetry loop with interval: {interval} seconds.")
        while self._running:
            try:
                telemetry_data = await asyncio.to_thread(self._collect_telemetry) # Offload sync function to a thread pool
                # Publish to NATS telemetry subject
                await self.nats_client.publish(f"telemetry.{self.client.device_id}", json.dumps(telemetry_data).encode())
                logger.debug(f"Telemetry published to NATS for {self.client.device_id}.")
            except PsutilNotInstalled as e:
                logger.warning(f"Telemetry collection skipped due to missing dependency: {e}")
                await self._publish_status("warning", {"message": f"Telemetry dependency missing: {e}"})
            except (httpx.RequestError, ConnectionError, TimeoutError) as e:
                logger.error(f"Network error during telemetry send: {e}")
                await self._publish_status("warning", {"message": f"Telemetry network error: {e}"})
            except Exception as e:
                logger.error(f"Unexpected error during telemetry loop: {e}")
                await self._publish_status("error", {"message": f"Unexpected telemetry error: {e}"})
            await asyncio.sleep(interval)
        logger.info("Telemetry loop stopped.")

    async def _publish_status(self, status: str, details: dict = None):
        """Publishes device status to NATS."""
        logger.debug(f"Publishing status for device {self.client.device_id} to {status}.")
        payload = {
            "device_id": self.client.device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "details": details if details is not None else {},
        }

        # Ensure payload is JSON string before encoding
        json_payload = json.dumps(payload).encode('utf-8')
        await self.nats_client.publish(f"status.{self.client.device_id}", json_payload) # Use dedicated status subject
        logger.debug(f"Status '{status}' published to NATS for {self.client.device_id}.")

    async def _command_listener(self):
        """Listens for commands from the NATS server."""
        # This method is now largely handled by the NATSClient's subscribe method
        # and the _handle_command_message callback.
        # This placeholder remains for conceptual clarity if direct polling were needed.
        pass

    async def _handle_command_message(self, msg):
        """Callback for NATS messages, handles incoming commands."""
        subject = msg.subject
        reply = msg.reply
        data = msg.data.decode()
        logger.info(f"Received command on '{subject}': {data}")

        response_payload = {}
        try: # Top-level try-except for message handling
            command_data = json.loads(data)
            cmd_type = command_data.get("type")
            params = command_data.get("params", {})

            if cmd_type is None:
                raise ValueError("'type' field is missing from command.")

            response_payload = await self._handle_command(cmd_type, params)
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON command received: {data}")
            response_payload = {"status": "error", "message": "Invalid JSON command format."}
        except ValueError as e:
            logger.error(f"Command validation error: {e}")
            response_payload = {"status": "error", "message": str(e)}
        except Exception as e:
            logger.error(f"Error processing command: {e}")
            response_payload = {"status": "error", "message": f"Unexpected error during command execution: {e}"}
        finally:
            if reply: # Always reply if a reply subject is provided
                await self.nats_client.publish(reply, json.dumps(response_payload).encode())

    async def _handle_command(self, cmd_type: str, params: dict) -> dict:
        """Executes a specific command based on its type and parameters."""
        logger.info(f"Executing command: {cmd_type} with params: {params}")
        response = {"status": "success", "message": f"Command '{cmd_type}' executed."}

        if cmd_type == "get_device_info":
            response["data"] = await self.client.get_device_info() # Still uses HTTP client
        elif cmd_type == "get_config": # Consistent with actual server API endpoint
            response["data"] = await self.client.get_configuration() # Still uses HTTP client
        elif cmd_type == "get_telemetry":
            response["data"] = await asyncio.to_thread(self._collect_telemetry) # Offload sync function to a thread pool
        elif cmd_type == "update_config":
            new_interval = params.get("telemetry_interval")
            if isinstance(new_interval, int) and new_interval > 0:
                self.telemetry_interval = new_interval
                response["message"] = f"Telemetry interval updated to {new_interval}s (requires restart to apply)."
            else:
                raise ValueError("Invalid 'telemetry_interval' parameter. Must be a positive integer.")
        elif cmd_type == "smbus_write":
            address = params.get("address", self.smbus_address)
            command_code = params.get("command_code")
            data = params.get("data")
            if command_code is not None and data is not None:
                # Execute synchronous SMBus operation in a thread pool
                await asyncio.to_thread(self._smbus_write_block_data, address, command_code, data)
                response["message"] = f"SMBus write to {hex(address)} command {hex(command_code)} successful."
            else:
                raise ValueError("Missing 'command_code' or 'data' for smbus_write command.")
        elif cmd_type == "smbus_read":
            address = params.get("address", self.smbus_address)
            command_code = params.get("command_code")
            length = params.get("length")
            if command_code is not None and length is not None:
                # Execute synchronous SMBus operation in a thread pool
                read_data = await asyncio.to_thread(self._smbus_read_block_data, address, command_code, length)
                response["data"] = list(read_data)  # Convert bytearray to list for JSON serialization
                response["message"] = f"SMBus read from {hex(address)} command {hex(command_code)} successful."
            else:
                raise ValueError("Missing 'command_code' or 'length' for smbus_read command.")
        elif cmd_type == "reboot":
            logger.warning("Reboot command received. Initiating system reboot...")
            response["message"] = "Device is rebooting."
            # In a real system, you'd execute a system reboot command here
            # For simulation, we just log and potentially exit
            asyncio.create_task(self.stop()) # Stop gracefully
            # os.system("sudo reboot") # Uncomment for actual reboot
        else:
            response = {"status": "error", "message": f"Unknown command type: {cmd_type}"}

        return response

    def _smbus_write_block_data(self, address: int, command_code: int, data: list):
        if self.smbus is None: # Check if smbus is initialized
            raise SMBusNotAvailable()
        if not isinstance(data, list) or not all(isinstance(x, int) and 0 <= x <= 255 for x in data):
            raise ValueError("Data must be a list of integers between 0 and 255.")
        logger.info(f"SMBus writing block data to address {hex(address)}, command {hex(command_code)}, data: {data}")
        self.smbus.write_i2c_block_data(address, command_code, data)

    def _smbus_read_block_data(self, address: int, command_code: int, length: int) -> bytearray:
        if self.smbus is None: # Check if smbus is initialized
            raise SMBusNotAvailable()
        if not isinstance(length, int) or length <= 0:
            raise ValueError("Length must be a positive integer.")
        logger.info(f"SMBus reading {length} bytes from address {hex(address)}, command {hex(command_code)}")
        # read_i2c_block_data returns a list, convert to bytearray if needed
        read_data = self.smbus.read_i2c_block_data(address, command_code, length)
        return bytearray(read_data)

    def _collect_telemetry(self) -> dict:
        """
        Collects various system telemetry data.
        This method is designed to be synchronous and can be offloaded to a thread pool.
        """
        telemetry = {
            "timestamp": datetime.now(timezone.utc).isoformat(), # ISO format for external use
            "device_id": self.client.device_id,
            "system_info": { # Group platform specific info
                "platform": platform.system(),
                "node_name": platform.node(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "python_version": platform.python_version(),
            },
            "network_info": { # Network details
                "ip_address": self.client._get_ip_address(), # Use client's IP discovery
            },
            "system_metrics": {}, # Metrics will be populated here
        }

        try:
            if psutil is None:
                raise PsutilNotInstalled()

            telemetry["system_metrics"]["uptime_seconds"] = self._get_uptime()
            telemetry["system_metrics"]["cpu_usage_percent"] = self._get_cpu_usage()
            mem_info = self._get_memory_usage()
            telemetry["system_metrics"]["memory_total_mb"] = mem_info.get("total_mb")
            telemetry["system_metrics"]["memory_available_mb"] = mem_info.get("available_mb")
            telemetry["system_metrics"]["memory_used_percent"] = mem_info.get("percent")
            disk_info = self._get_disk_usage()
            telemetry["system_metrics"]["disk_total_gb"] = disk_info.get("total_gb")
            telemetry["system_metrics"]["disk_used_gb"] = disk_info.get("used_gb")
            telemetry["system_metrics"]["disk_free_gb"] = disk_info.get("free_gb")
            telemetry["system_metrics"]["disk_used_percent"] = disk_info.get("percent")
            telemetry["system_metrics"]["temperature_celsius"] = self._get_temperature()
        except PsutilNotInstalled:
            logger.warning("psutil not installed, system metrics will be unavailable.")
            # Populate with default/empty values if psutil is not available
            telemetry["system_metrics"] = {
                "uptime_seconds": 0.0,
                "cpu_usage_percent": 0.0,
                "memory_total_mb": 0.0,
                "memory_available_mb": 0.0,
                "memory_used_percent": 0.0,
                "disk_total_gb": 0.0,
                "disk_used_gb": 0.0,
                "disk_free_gb": 0.0,
                "disk_used_percent": 0.0,
                "temperature_celsius": 0.0,
            }
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
        return telemetry

    def _get_uptime(self) -> float:
        """Returns system uptime in seconds."""
        if psutil:
            return psutil.boot_time()
        else:
            # Fallback for non-psutil systems (less accurate)
            return time.time() - os.stat("/proc/1").st_ctime if os.path.exists("/proc/1") else 0.0 # This is a Linux-specific fallback

    def _get_cpu_usage(self) -> float:
        """Returns current CPU usage percentage."""
        if psutil:
            return psutil.cpu_percent(interval=None)
        else:
            raise PsutilNotInstalled()

    def _get_memory_usage(self) -> dict:
        """Returns memory usage statistics."""
        if psutil:
            mem = psutil.virtual_memory()
            return {
                "total_mb": round(mem.total / (1024 * 1024), 2), # Use MB as per test expectation
                "available_mb": round(mem.available / (1024 * 1024), 2), # Use MB
                "percent": mem.percent,
                "used_mb": round(mem.used / (1024 * 1024), 2), # Use MB
                "free_mb": round(mem.free / (1024 * 1024), 2), # Use MB
            }
        else:
            raise PsutilNotInstalled()

    def _get_disk_usage(self) -> dict:
        """Returns disk usage statistics for the root partition."""
        if psutil:
            disk = psutil.disk_usage("/")
            return { # Use GB as per test expectation
                "total_gb": round(disk.total / (1024 * 1024 * 1024), 2), 
                "used_gb": round(disk.used / (1024 * 1024 * 1024), 2), 
                "free_gb": round(disk.free / (1024 * 1024 * 1024), 2), 
                "percent": disk.percent,
            }
        else:
            raise PsutilNotInstalled()

    def _get_temperature(self) -> float:
        """Returns CPU temperature in Celsius if available."""
        if psutil and hasattr(psutil, "sensors_temperatures"):
            temps = psutil.sensors_temperatures()
            if "coretemp" in temps and temps["coretemp"]:
                return temps["coretemp"][0].current
            elif "cpu_thermal" in temps and temps["cpu_thermal"]: # For Raspberry Pi
                return temps["cpu_thermal"][0].current
            elif "cpu-thermal" in temps and temps["cpu-thermal"]: # For some Linux systems
                return temps["cpu-thermal"][0].current
        return 0.0  # Default if not found or psutil not available

    def _get_ip_address(self) -> str:
        """Attempts to get the local IP address."""
        try:
            if psutil:
                # Get all network interfaces
                addrs = psutil.net_if_addrs()
                for interface_name, interface_addresses in addrs.items():
                    for address in interface_addresses:
                        if address.family == socket.AF_INET and not address.address.startswith("127."):
                            return address.address
            # Fallback if psutil is not available or doesn't find a non-loopback IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Google's public DNS server
            ip_address = s.getsockname()[0]
            s.close()
            return ip_address
        except Exception as e:
            logger.warning(f"Could not determine IP address: {e}. Returning 'unknown'.")
            return "unknown"


async def main():
    logging.basicConfig(level=logging.INFO) # Set default logging level
    logger.setLevel(logging.INFO) # Set logger for this module

    # Configuration from environment variables or defaults
    API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
    NATS_URL = os.getenv("NATS_URL", "nats://localhost:4222")
    DEVICE_ID = os.getenv("DEVICE_ID") # Optional, will be generated if not provided
    KEY_DIR = os.getenv("KEY_DIR", DEFAULT_KEY_DIR)
    SMBUS_ADDRESS = os.getenv("SMBUS_ADDRESS")
    SMBUS_BUS_NUM = os.getenv("SMBUS_BUS_NUM", "1")

    if SMBUS_ADDRESS:
        try:
            SMBUS_ADDRESS = int(SMBUS_ADDRESS, 0) # Auto-detect base (0x, 0b, 0o, or decimal)
        except ValueError:
            logger.error(f"Invalid SMBUS_ADDRESS: {SMBUS_ADDRESS}. Must be an integer (e.g., 0x48).")
            SMBUS_ADDRESS = None
    
    try:
        SMBUS_BUS_NUM = int(SMBUS_BUS_NUM)
    except ValueError:
        logger.error(f"Invalid SMBUS_BUS_NUM: {SMBUS_BUS_NUM}. Must be an integer.")
        SMBUS_BUS_NUM = 1 # Default to bus 1 if invalid

    logger.info(f"Starting Equus Express Edge Device Controller...")
    logger.info(f"API Base URL: {API_BASE_URL}")
    logger.info(f"NATS URL: {NATS_URL}")
    logger.info(f"Key Directory: {KEY_DIR}")
    if SMBUS_ADDRESS:
        logger.info(f"SMBus Address: {hex(SMBUS_ADDRESS)} on Bus: {SMBUS_BUS_NUM}")
    else:
        logger.info("SMBus not configured.")

    client = None
    nats_client = None
    agent = None

    try:
        client = SecureAPIClient(
            base_url=API_BASE_URL,
            device_id=DEVICE_ID,
            key_dir=KEY_DIR,
        )
        nats_client = NATSClient(
            nats_url=NATS_URL,
            device_id=client.device_id, # Ensure NATS client uses the same device ID
            key_dir=KEY_DIR,
        )
        agent = DeviceAgent(
            client=client,
            nats_client=nats_client,
            smbus_address=SMBUS_ADDRESS,
            smbus_bus_num=SMBUS_BUS_NUM,
        )

        await agent.start()

        # Keep the main task running until interrupted
        while agent._running:
            await asyncio.sleep(1)

    except Exception as e:
        logger.critical(f"A critical error occurred in main: {e}", exc_info=True)
    finally:
        if agent:
            logger.info("Shutting down agent...")
            await agent.stop()
        elif nats_client: # If agent didn't start, ensure NATS is closed
            await nats_client.disconnect()
        logger.info("Equus Express Edge Device Controller stopped.")


if __name__ == "__main__":
    # Configure logging for the entire application
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    asyncio.run(main())
