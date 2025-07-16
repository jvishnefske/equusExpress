import logging
import os
import asyncio
import json
import time
import platform
import socket
import fcntl
import struct
from typing import Optional, Dict, Any
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from nats.aio.client import Client as NATS
from nats.nkeys import KeyPair, InvalidNKey # Reverted import back to nats.nkeys

logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError:
    psutil = None
    logger.warning("psutil library not found. System telemetry functions will be limited.")

try:
    import smbus2
except ImportError:
    smbus2 = None
    logger.warning("smbus2 library not found. SMBus communication will be disabled.")


class PsutilNotInstalled(NotImplementedError):
    def __init__(self, message="psutil library is not available."):
        super().__init__(message)


class SMBusNotAvailable(NotImplementedError):
    def __init__(self, message="smbus2 library is not available or bus not initialized."):
        super().__init__(message)


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
        self.public_key_path = os.path.join(self.key_dir, "device_public_key.pub")
        self.device_id_path = os.path.join(self.key_dir, "device_id.txt")
        self.device_id = device_id
        self.private_key = None
        self.public_key = None
        self.client = httpx.Client(timeout=timeout)
        self._load_or_generate_keys()

    def _load_or_generate_keys(self):
        """Loads existing keys or generates new ones if they don't exist."""
        if os.path.exists(self.private_key_path) and os.path.exists(self.public_key_path):
            logger.info("Loading existing device keys.")
            with open(self.private_key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            with open(self.public_key_path, "rb") as f:
                self.public_key = serialization.load_ssh_public_key(f.read(), backend=default_backend())
            if os.path.exists(self.device_id_path):
                with open(self.device_id_path, "r") as f:
                    self.device_id = f.read().strip()
            else:
                logger.warning("Device ID file not found, but keys exist. Device ID might be missing.")
        else:
            logger.info("Generating new device keys.")
            self.private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()

            with open(self.private_key_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(self.public_key_path, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.OpenSSH,
                    format=serialization.PublicFormat.OpenSSH
                ))
            if not self.device_id:
                # Generate a simple hash of the public key as a default device ID
                hasher = Hash(SHA256(), backend=default_backend())
                hasher.update(self.public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ))
                self.device_id = hasher.finalize().hex()[:32] # Use first 32 chars for a shorter ID
                logger.info(f"Generated device ID: {self.device_id}")
            with open(self.device_id_path, "w") as f:
                self.device_id = f.write(self.device_id)

    def _sign_request(self, method: str, endpoint: str, body: Optional[bytes] = None) -> str:
        """Signs the request with the device's private key."""
        message = f"{method.upper()} {endpoint}"
        if body:
            message += f"\n{body.decode('utf-8')}" # Assuming body is UTF-8 for signing
        signature = self.private_key.sign(message.encode('utf-8'))
        return signature.hex()

    def _make_request(self, method: str, endpoint: str, **kwargs):
        """Makes a signed HTTP request to the API server."""
        url = f"{self.base_url}{endpoint}"
        headers = kwargs.pop("headers", {})
        json_data = kwargs.get("json")
        data = kwargs.get("data")

        body_to_sign = None
        if json_data is not None:
            body_to_sign = json.dumps(json_data, separators=(',', ':')).encode('utf-8')
            headers["Content-Type"] = "application/json"
        elif data is not None:
            if isinstance(data, dict):
                body_to_sign = json.dumps(data, separators=(',', ':')).encode('utf-8')
                headers["Content-Type"] = "application/json"
            elif isinstance(data, bytes):
                body_to_sign = data
            else:
                body_to_sign = str(data).encode('utf-8')

        signature = self._sign_request(method, endpoint, body_to_sign)
        headers["X-Device-ID"] = self.device_id
        headers["X-Signature"] = signature

        try:
            response = self.client.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error for {method} {endpoint}: {e.response.status_code} - {e.response.text}")
            raise
        except httpx.RequestError as e:
            logger.error(f"Request error for {method} {endpoint}: {e}")
            raise

    def get(self, endpoint: str, **kwargs):
        return self._make_request("GET", endpoint, **kwargs)

    def post(self, endpoint: str, data=None, json=None, **kwargs):
        return self._make_request("POST", endpoint, data=data, json=json, **kwargs)

    def put(self, endpoint: str, data=None, json=None, **kwargs):
        return self._make_request("PUT", endpoint, data=data, json=json, **kwargs)

    def delete(self, endpoint: str, **kwargs):
        return self._make_request("DELETE", endpoint, **kwargs)

    def register_device(self):
        """Registers the device's public key with the API server."""
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
        payload = {
            "device_id": self.device_id,
            "public_key": public_key_pem,
            "ip_address": self._get_ip_address() # Include IP address during registration
        }
        logger.info(f"Attempting to register device {self.device_id}...")
        try:
            response = self.post("/api/register", json=payload)
            logger.info(f"Device registration successful: {response.json()}")
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 409: # Conflict, device already registered
                logger.info(f"Device {self.device_id} already registered. Updating info.")
                # If already registered, we can try to update its info (e.g., IP address)
                # The /api/register endpoint should handle updates if device_id exists
                return {"message": "Device already registered, info updated."}
            else:
                logger.error(f"Device registration failed: {e.response.status_code} - {e.response.text}")
                raise
        except httpx.RequestError as e:
            logger.error(f"Network error during device registration: {e}")
            raise

    def health_check(self):
        """Performs a health check against the API server."""
        logger.debug("Performing API health check...")
        try:
            response = self.get("/health")
            logger.debug(f"API health check successful: {response.json()}")
            return response.json()
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            logger.error(f"API health check failed: {e}")
            raise

    def get_device_info(self):
        """Retrieves device information from the API server."""
        logger.debug(f"Getting info for device {self.device_id}...")
        try:
            response = self.get("/api/device/info")
            logger.debug(f"Device info received: {response.json()}")
            return response.json()
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            logger.error(f"Failed to get device info: {e}")
            raise

    def send_telemetry(self, data: dict):
        """Sends telemetry data to the API server."""
        payload = {
            "device_id": self.device_id,
            "timestamp": int(time.time()),
            "data": data
        }
        logger.debug(f"Sending telemetry for {self.device_id}: {payload}")
        try:
            response = self.post("/api/telemetry", json=payload)
            logger.debug(f"Telemetry sent successfully: {response.json()}")
            return response.json()
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            logger.error(f"Failed to send telemetry: {e}")
            raise

    def get_configuration(self):
        """Retrieves device configuration from the API server."""
        logger.debug(f"Getting configuration for device {self.device_id}...")
        try:
            response = self.get(f"/api/device/{self.device_id}/config")
            logger.debug(f"Configuration received: {response.json()}")
            return response.json()
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            logger.error(f"Failed to get configuration: {e}")
            raise

    def update_status(self, status: str, details: dict = None):
        """Updates the device's status on the API server."""
        payload = {
            "device_id": self.device_id,
            "timestamp": int(time.time()),
            "status": status,
            "details": details if details is not None else {}
        }
        logger.debug(f"Updating status for {self.device_id}: {status}")
        try:
            response = self.post("/api/device/status", json=payload)
            logger.debug(f"Status updated successfully: {response.json()}")
            return response.json()
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            logger.error(f"Failed to update status: {e}")
            raise

    def test_connection(self):
        """Tests the full connection flow: health check, get info, send telemetry."""
        logger.info(f"Testing connection for device {self.device_id}...")
        try:
            self.health_check()
            logger.info("API health check successful.")

            self.get_device_info()
            logger.info("Device info retrieval successful.")

            # Send a dummy telemetry to confirm data path
            self.send_telemetry({"test_metric": 1, "timestamp": int(time.time())})
            logger.info("Dummy telemetry sent successfully.")

            logger.info(f"Connection test for device {self.device_id} completed successfully.")
            return True
        except Exception as e:
            logger.error(f"Connection test for device {self.device_id} failed: {e}")
            return False

    def _get_ip_address(self):
        """Attempts to get the local IP address."""
        try:
            # This method attempts to connect to an external host (Google's DNS)
            # to determine the local IP address used for outbound connections.
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            s.close()
            return ip_address
        except Exception:
            # Fallback for non-Linux systems or if the above fails
            try:
                # Try to get IP from a common interface name (e.g., eth0, wlan0)
                # This is less reliable as interface names vary
                if_names = ["eth0", "wlan0", "en0", "lo0"] # Common interface names
                for ifname in if_names:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        ip_address = socket.inet_ntoa(fcntl.ioctl(
                            s.fileno(),
                            0x8915,  # SIOCGIFADDR
                            struct.pack('256s', ifname[:15].encode())
                        )[20:24])
                        s.close()
                        return ip_address
                    except OSError:
                        continue # Try next interface
                return "127.0.0.1" # Default to localhost if no other IP found
            except Exception:
                return "127.0.0.1" # Fallback if all else fails


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
        self.nc = NATS()
        self.nkey_pair = None
        self._load_or_generate_nkeys()

    def _load_or_generate_nkeys(self):
        """Loads existing NATS NKey pair or generates a new one."""
        nkey_seed_path = os.path.join(self.key_dir, "nats_nkey.seed")
        if os.path.exists(nkey_seed_path):
            logger.info("Loading existing NATS NKey.")
            with open(nkey_seed_path, "rb") as f:
                seed = f.read()
            try:
                self.nkey_pair = KeyPair.from_seed(seed)
            except InvalidNKey:
                logger.error("Invalid NKey seed found. Generating new NKey.")
                self.nkey_pair = KeyPair.new()
                with open(nkey_seed_path, "wb") as f:
                    f.write(self.nkey_pair.seed)
        else:
            logger.info("Generating new NATS NKey.")
            self.nkey_pair = KeyPair.new()
            with open(nkey_seed_path, "wb") as f:
                f.write(self.nkey_pair.seed)

    async def connect(self):
        """Connects to the NATS server with NKey authentication."""
        logger.info(f"Connecting to NATS server at {self.nats_url} with device ID {self.device_id}...")
        try:
            await self.nc.connect(
                servers=[self.nats_url],
                nkeys_pair=self.nkey_pair,
                user_jwt_cb=self._user_jwt_callback,
                signature_cb=self._signature_callback,
                error_cb=self._nats_error_cb,
                reconnected_cb=self._nats_reconnected_cb,
                disconnected_cb=self._nats_disconnected_cb,
                closed_cb=self._nats_closed_cb,
                name=f"device-agent-{self.device_id}"
            )
            logger.info(f"Successfully connected to NATS server.")
        except Exception as e:
            logger.error(f"Failed to connect to NATS server: {e}")
            raise

    async def disconnect(self):
        """Disconnects from the NATS server."""
        if self.nc.is_connected:
            logger.info("Disconnecting from NATS server.")
            await self.nc.close()
            logger.info("Disconnected from NATS server.")

    async def publish(self, subject: str, payload: bytes):
        """Publishes a message to a NATS subject."""
        if not self.nc.is_connected:
            logger.warning("NATS client not connected. Cannot publish message.")
            return
        try:
            await self.nc.publish(subject, payload)
            logger.debug(f"Published to '{subject}': {payload[:50]}...")
        except Exception as e:
            logger.error(f"Failed to publish to '{subject}': {e}")

    async def subscribe(self, subject: str, cb):
        """Subscribes to a NATS subject."""
        if not self.nc.is_connected:
            logger.warning("NATS client not connected. Cannot subscribe.")
            return None
        try:
            sid = await self.nc.subscribe(subject, cb=cb)
            logger.info(f"Subscribed to '{subject}' with SID {sid}")
            return sid
        except Exception as e:
            logger.error(f"Failed to subscribe to '{subject}': {e}")
            return None

    def _user_jwt_callback(self):
        """Callback to provide the user JWT for NATS authentication."""
        # In a real-world scenario, this JWT would be obtained from a NATS Account Server
        # or a secure provisioning service. For this example, we're relying on NKey auth
        # which implicitly handles the user identity based on the NKey.
        # If a JWT is required by the server, it would be returned here.
        # For now, return None or an empty string if not explicitly used.
        logger.debug("NATS user JWT callback invoked.")
        return None

    def _signature_callback(self, nonce):
        """Callback to sign the nonce for NATS authentication."""
        logger.debug("NATS signature callback invoked.")
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
        self.smbus_bus_num = smbus_bus_num
        self.smbus_bus = None
        self._telemetry_task = None
        self._command_listener_task = None

        if self.smbus_address is not None:
            if smbus2:
                try:
                    self.smbus_bus = smbus2.SMBus(self.smbus_bus_num)
                    logger.info(f"SMBus initialized on bus {self.smbus_bus_num} for address {hex(self.smbus_address)}")
                except Exception as e:
                    logger.error(f"Failed to initialize SMBus on bus {self.smbus_bus_num}: {e}")
                    self.smbus_bus = None
            else:
                logger.warning("smbus2 not installed, SMBus communication disabled.")

    async def start(self):
        """Starts the device agent, connecting to API and NATS, and starting loops."""
        logger.info("Starting Device Agent...")
        try:
            # 1. Register/Update device with API server
            self.client.register_device()
            logger.info("Device registered/updated with API server.")

            # 2. Connect to NATS
            await self.nats_client.connect()
            logger.info("Connected to NATS server.")

            # 3. Start telemetry loop
            self._telemetry_task = asyncio.create_task(self.run_telemetry_loop())
            logger.info("Telemetry loop started.")

            # 4. Start command listener
            command_subject = f"commands.{self.client.device_id}"
            self._command_listener_task = asyncio.create_task(
                self.nats_client.subscribe(command_subject, self._handle_command_message)
            )
            logger.info(f"Subscribed to NATS command subject: {command_subject}")

            logger.info("Device Agent started successfully.")
            await self.client.update_status("online", {"message": "Device agent started."})

        except Exception as e:
            logger.critical(f"Failed to start Device Agent: {e}")
            await self.client.update_status("error", {"message": f"Failed to start: {e}"})
            # Attempt to stop gracefully if start fails
            await self.stop()
            raise

    async def stop(self):
        """Stops the device agent, disconnecting from NATS and cancelling tasks."""
        logger.info("Stopping Device Agent...")
        if self._telemetry_task:
            self._telemetry_task.cancel()
            try:
                await self._telemetry_task
            except asyncio.CancelledError:
                logger.info("Telemetry loop cancelled.")
        if self._command_listener_task:
            self._command_listener_task.cancel()
            try:
                await self._command_listener_task
            except asyncio.CancelledError:
                logger.info("Command listener cancelled.")

        await self.nats_client.disconnect()
        logger.info("NATS client disconnected.")

        if self.smbus_bus:
            try:
                self.smbus_bus.close()
                logger.info("SMBus closed.")
            except Exception as e:
                logger.error(f"Error closing SMBus: {e}")

        await self.client.update_status("offline", {"message": "Device agent stopped."})
        logger.info("Device Agent stopped.")

    async def run_telemetry_loop(self, interval: int = 60):
        """Collects and sends telemetry data periodically."""
        while True:
            try:
                telemetry_data = self._collect_telemetry()
                await asyncio.sleep(0.1) # Yield control briefly
                self.client.send_telemetry(telemetry_data)
            except PsutilNotInstalled as e:
                logger.warning(f"Telemetry collection skipped: {e}")
            except Exception as e:
                logger.error(f"Error collecting or sending telemetry: {e}")
                await self.client.update_status("warning", {"message": f"Telemetry error: {e}"})
            await asyncio.sleep(interval)

    async def _command_listener(self):
        """Listens for commands from the NATS server."""
        # This method is now integrated into start() via self.nats_client.subscribe
        # and the callback _handle_command_message.
        pass

    async def _handle_command_message(self, msg):
        """Callback to handle incoming NATS command messages."""
        subject = msg.subject
        reply = msg.reply
        data = msg.data.decode()

        logger.info(f"Received command on '{subject}': {data}")

        try:
            command = json.loads(data)
            cmd_type = command.get("type")
            params = command.get("params", {})

            if not cmd_type:
                raise ValueError("Command message missing 'type' field.")

            result = await self._handle_command(cmd_type, params)
            response_payload = {"status": "success", "result": result}
            logger.info(f"Command '{cmd_type}' executed successfully. Result: {result}")
        except json.JSONDecodeError:
            response_payload = {"status": "error", "message": "Invalid JSON command format."}
            logger.error(f"Invalid JSON command received: {data}")
        except ValueError as e:
            response_payload = {"status": "error", "message": str(e)}
            logger.error(f"Command validation error: {e}")
        except Exception as e:
            response_payload = {"status": "error", "message": f"Error executing command: {e}"}
            logger.error(f"Unexpected error during command execution: {e}", exc_info=True)

        if reply:
            await self.nats_client.publish(reply, json.dumps(response_payload).encode())
            logger.debug(f"Published command response to '{reply}': {response_payload}")

    async def _handle_command(self, cmd_type: str, params: dict) -> dict:
        """Executes a specific command based on its type."""
        if cmd_type == "get_telemetry":
            return self._collect_telemetry()
        elif cmd_type == "update_config":
            # Example: update configuration (in a real app, this would persist config)
            new_interval = params.get("telemetry_interval")
            if new_interval and isinstance(new_interval, int) and new_interval > 0:
                # This would require re-scheduling the telemetry task,
                # or passing the interval dynamically. For simplicity,
                # we'll just log it here.
                logger.info(f"Received request to update telemetry interval to {new_interval}s.")
                # In a real system, you'd update a persistent config and potentially restart the loop
                return {"message": f"Telemetry interval updated to {new_interval}s (requires restart to apply)."}
            else:
                raise ValueError("Invalid 'telemetry_interval' parameter.")
        elif cmd_type == "smbus_write":
            address = params.get("address", self.smbus_address)
            command_code = params.get("command_code")
            data = params.get("data")
            if address is None or command_code is None or data is None:
                raise ValueError("Missing 'address', 'command_code', or 'data' for smbus_write.")
            if not isinstance(data, list) or not all(isinstance(x, int) for x in data):
                raise ValueError("'data' must be a list of integers for smbus_write.")
            self._smbus_write_block_data(address, command_code, data)
            return {"message": "SMBus write successful."}
        elif cmd_type == "smbus_read":
            address = params.get("address", self.smbus_address)
            command_code = params.get("command_code")
            length = params.get("length")
            if address is None or command_code is None or length is None:
                raise ValueError("Missing 'address', 'command_code', or 'length' for smbus_read.")
            if not isinstance(length, int) or length <= 0:
                raise ValueError("'length' must be a positive integer for smbus_read.")
            read_data = self._smbus_read_block_data(address, command_code, length)
            return {"data": list(read_data)}
        else:
            raise ValueError(f"Unknown command type: {cmd_type}")

    def _smbus_write_block_data(self, address: int, command_code: int, data: list):
        """Writes a block of data to an SMBus device."""
        if not self.smbus_bus:
            raise SMBusNotAvailable()
        try:
            self.smbus_bus.write_i2c_block_data(address, command_code, data)
            logger.info(f"SMBus write: address={hex(address)}, cmd={hex(command_code)}, data={data}")
        except Exception as e:
            logger.error(f"SMBus write failed: {e}")
            raise

    def _smbus_read_block_data(self, address: int, command_code: int, length: int) -> bytearray:
        """Reads a block of data from an SMBus device."""
        if not self.smbus_bus:
            raise SMBusNotAvailable()
        try:
            # read_i2c_block_data returns a list of integers
            read_list = self.smbus_bus.read_i2c_block_data(address, command_code, length)
            read_data = bytearray(read_list)
            logger.info(f"SMBus read: address={hex(address)}, cmd={hex(command_code)}, length={length}, data={list(read_data)}")
            return read_data
        except Exception as e:
            logger.error(f"SMBus read failed: {e}")
            raise

    def _collect_telemetry(self) -> dict:
        """Collects various system telemetry data."""
        telemetry = {
            "timestamp": int(time.time()),
            "device_id": self.client.device_id,
            "system_info": {
                "platform": platform.system(),
                "release": platform.release(),
                "architecture": platform.machine(),
                "python_version": platform.python_version(),
            },
            "network_info": {
                "ip_address": self.client._get_ip_address()
            }
        }

        if psutil:
            telemetry["system_metrics"] = {
                "uptime_seconds": self._get_uptime(),
                "cpu_usage_percent": self._get_cpu_usage(),
                "memory_usage": self._get_memory_usage(),
                "disk_usage": self._get_disk_usage(),
                "temperature_celsius": self._get_temperature(),
            }
        else:
            raise PsutilNotInstalled()

        return telemetry

    def _get_uptime(self) -> float:
        """Returns system uptime in seconds."""
        return psutil.boot_time()

    def _get_cpu_usage(self) -> float:
        """Returns CPU usage percentage."""
        return psutil.cpu_percent(interval=None) # Non-blocking call

    def _get_memory_usage(self) -> dict:
        """Returns memory usage statistics."""
        mem = psutil.virtual_memory()
        return {
            "total_gb": round(mem.total / (1024**3), 2),
            "available_gb": round(mem.available / (1024**3), 2),
            "percent": mem.percent,
            "used_gb": round(mem.used / (1024**3), 2),
            "free_gb": round(mem.free / (1024**3), 2),
        }

    def _get_disk_usage(self) -> dict:
        """Returns disk usage statistics for the root partition."""
        disk = psutil.disk_usage('/')
        return {
            "total_gb": round(disk.total / (1024**3), 2),
            "used_gb": round(disk.used / (1024**3), 2),
            "free_gb": round(disk.free / (1024**3), 2),
            "percent": disk.percent,
        }

    def _get_temperature(self) -> float:
        """Returns system temperature in Celsius if available."""
        if hasattr(psutil, "sensors_temperatures"):
            temps = psutil.sensors_temperatures()
            if "coretemp" in temps and temps["coretemp"]:
                return temps["coretemp"][0].current
            elif "cpu_thermal" in temps and temps["cpu_thermal"]: # Raspberry Pi
                return temps["cpu_thermal"][0].current
        return 0.0 # Default if not found or not supported

    def _get_ip_address(self) -> str:
        """Returns the primary IP address of the device."""
        return self.client._get_ip_address()


async def main():
    # Configuration
    API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
    NATS_URL = os.getenv("NATS_URL", "nats://localhost:4222")
    DEVICE_ID = os.getenv("DEVICE_ID") # Optional: if not set, client will generate one
    KEY_DIR = os.getenv("KEY_DIR", DEFAULT_KEY_DIR)
    SMBUS_ADDRESS = os.getenv("SMBUS_ADDRESS")
    SMBUS_BUS_NUM = os.getenv("SMBUS_BUS_NUM", "1")

    if SMBUS_ADDRESS:
        try:
            SMBUS_ADDRESS = int(SMBUS_ADDRESS, 16) if SMBUS_ADDRESS.startswith("0x") else int(SMBUS_ADDRESS)
        except ValueError:
            logger.error(f"Invalid SMBUS_ADDRESS: {SMBUS_ADDRESS}. Must be an integer or hex string.")
            SMBUS_ADDRESS = None
    
    try:
        SMBUS_BUS_NUM = int(SMBUS_BUS_NUM)
    except ValueError:
        logger.error(f"Invalid SMBUS_BUS_NUM: {SMBUS_BUS_NUM}. Must be an integer.")
        SMBUS_BUS_NUM = 1 # Default to bus 1

    # Initialize clients
    api_client = SecureAPIClient(
        base_url=API_BASE_URL,
        device_id=DEVICE_ID,
        key_dir=KEY_DIR
    )
    nats_client = NATSClient(
        nats_url=NATS_URL,
        device_id=api_client.device_id, # Use the ID generated/loaded by API client
        key_dir=KEY_DIR
    )

    # Initialize and start agent
    agent = DeviceAgent(
        client=api_client,
        nats_client=nats_client,
        smbus_address=SMBUS_ADDRESS,
        smbus_bus_num=SMBUS_BUS_NUM
    )

    try:
        await agent.start()
        # Keep the agent running until interrupted
        while True:
            await asyncio.sleep(3600) # Sleep for a long time, agent tasks run in background
    except asyncio.CancelledError:
        logger.info("Agent main loop cancelled.")
    except Exception as e:
        logger.critical(f"Agent encountered a critical error: {e}", exc_info=True)
    finally:
        await agent.stop()
        logger.info("Agent stopped gracefully.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    asyncio.run(main())
