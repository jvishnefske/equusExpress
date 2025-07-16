import os
import time
import httpx
import logging
import json
import asyncio
import platform
import socket
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.backends import default_backend

# Conditional import for psutil and smbus2
try:
    import psutil
except ImportError:
    psutil = None
    logging.warning("psutil not installed, system metrics will be unavailable.")

try:
    import smbus2
except ImportError:
    smbus2 = None
    logging.warning("smbus2 not installed, SMBus communication will be disabled.")


logger = logging.getLogger(__name__)


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
        self.timeout = timeout
        self.client = httpx.Client(base_url=base_url, timeout=timeout)
        self.private_key = None
        self.public_key = None
        self.device_id = device_id # Will be set by _load_or_generate_keys if not provided

        try:
            os.makedirs(self.key_dir, exist_ok=True)
            self._load_or_generate_keys()
        except Exception as e:
            logger.error(f"Failed to initialize client keys: {e}")
            raise RuntimeError(f"Failed to initialize client keys: {e}")

    def _load_or_generate_keys(self):
        """Loads existing Ed25519 keys or generates new ones."""
        private_key_path = os.path.join(self.key_dir, "device_private_key.pem")
        public_key_path = os.path.join(self.key_dir, "device_public_key.pub")
        device_id_path = os.path.join(self.key_dir, "device_id.txt")

        if (
            os.path.exists(private_key_path)
            and os.path.exists(public_key_path)
            and os.path.exists(device_id_path)
        ):
            with open(private_key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            with open(public_key_path, "rb") as f:
                self.public_key = serialization.load_ssh_public_key(f.read())
            with open(device_id_path, "r") as f:
                self.device_id = f.read().strip()
            logger.info(f"Loaded existing keys and device ID: {self.device_id}")
        else:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()

            # Generate device_id from public key hash if not provided
            if not self.device_id:
                public_key_bytes = self.public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                hasher = Hash(SHA256(), backend=default_backend())
                hasher.update(public_key_bytes)
                self.device_id = hasher.finalize().hex()
                logger.info(f"Generated device ID from public key hash: {self.device_id}")

            with open(private_key_path, "wb") as f:
                f.write(
                    self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
            with open(public_key_path, "wb") as f:
                f.write(
                    self.public_key.public_bytes(
                        encoding=serialization.Encoding.OpenSSH,
                        format=serialization.PublicFormat.OpenSSH,
                    )
                )
            with open(device_id_path, "w") as f:
                f.write(self.device_id)
            logger.info("Generated new Ed25519 keys and saved.")

    def _sign_request(self, method: str, endpoint: str, body: Optional[bytes] = None) -> str:
        """Signs the request with the device's private key."""
        if not self.private_key:
            raise RuntimeError("Private key not loaded for signing.")

        # Canonical representation of the request for signing
        # This should match the server's expected signing format
        message = f"{method.upper()} {endpoint}"
        if body:
            message += f" {body.decode('utf-8')}" # Assuming body is JSON and can be decoded
        
        signed_data = message.encode("utf-8")
        signature = self.private_key.sign(signed_data)
        return signature.hex()

    def _make_request(self, method: str, endpoint: str, **kwargs):
        """Makes an HTTP request with authentication headers."""
        headers = kwargs.pop("headers", {})
        
        # Add device ID and signature to headers
        headers["X-Device-ID"] = self.device_id
        
        # Prepare body for signing if present
        body_to_sign = None
        if "json" in kwargs and kwargs["json"] is not None:
            body_to_sign = json.dumps(kwargs["json"]).encode('utf-8')
        elif "data" in kwargs and kwargs["data"] is not None:
            body_to_sign = kwargs["data"] # Assuming data is already bytes or can be encoded

        headers["X-Signature"] = self._sign_request(method, endpoint, body_to_sign)

        try:
            response = self.client.request(method, endpoint, headers=headers, **kwargs)
            response.raise_for_status()  # Raise an exception for 4xx or 5xx status codes
            return response
        except httpx.RequestError as e:
            logger.error(f"Request failed for {method} {endpoint}: {e}")
            raise
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error for {method} {endpoint}: {e.response.status_code} - {e.response.text}")
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
        if self.public_key is None:
            raise RuntimeError("Public key not available for registration.")
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
        
        ip_address = self._get_ip_address()

        logger.info(f"Registering device {self.device_id} with public key...")
        return self.post(
            "/api/register",
            json={
                "device_id": self.device_id,
                "public_key": public_key_pem,
                "ip_address": ip_address
            },
        )

    def health_check(self):
        """Performs a health check against the API server."""
        logger.info("Performing API health check...")
        return self.get("/health")

    def get_device_info(self):
        """Retrieves device information from the API server."""
        logger.info(f"Getting info for device {self.device_id}...")
        return self.get(f"/api/device/info") # Device ID is sent in header

    def send_telemetry(self, data: dict):
        """Sends telemetry data to the API server."""
        logger.info(f"Sending telemetry for device {self.device_id}...")
        return self.post(
            "/api/telemetry",
            json={
                "device_id": self.device_id,
                "timestamp": int(time.time()),
                "data": data,
            },
        )

    def get_configuration(self):
        """Retrieves device configuration from the API server."""
        logger.info(f"Getting configuration for device {self.device_id}...")
        return self.get(f"/api/device/{self.device_id}/config")

    def update_status(self, status: str, details: dict = None):
        """Updates the device's status on the API server."""
        logger.info(f"Updating status for device {self.device_id} to {status}...")
        return self.post(
            "/api/device/status",
            json={
                "device_id": self.device_id,
                "status": status,
                "timestamp": int(time.time()),
                "details": details,
            },
        )

    def test_connection(self) -> bool:
        """Tests connectivity and registration with the API server."""
        logger.info(f"Running connection test for device {self.device_id}...")
        try:
            # 1. Health check
            self.health_check()
            logger.info("API health check successful.")

            # 2. Register/Update device
            self.register_device()
            logger.info("Device registration/update successful.")

            # 3. Get device info
            self.get_device_info()
            logger.info("Device info retrieval successful.")

            # 4. Send dummy telemetry
            self.send_telemetry({"test": "connection"})
            logger.info("Dummy telemetry sent successfully.")

            logger.info("Connection test completed successfully.")
            return True
        except Exception as e:
            logger.error(f"Connection test for device {self.device_id} failed: {e}")
            return False

    def _get_ip_address(self) -> str:
        """Attempts to get the local IP address."""
        try:
            # Create a socket to connect to an external host (doesn't actually send data)
            # This forces the OS to determine the most suitable local IP for outbound connections
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Google's public DNS server
            ip_address = s.getsockname()[0]
            s.close()
            return ip_address
        except Exception:
            # Fallback for environments where the above might fail (e.g., no network, restricted outbound)
            try:
                # Try getting hostname IP
                ip_address = socket.gethostbyname(socket.gethostname())
                if ip_address == "127.0.0.1":
                    # If it's localhost, try to find a non-loopback interface
                    # This part is more complex and platform-dependent,
                    # often requiring libraries like netifaces or parsing ifconfig/ip output.
                    # For simplicity, we'll just return 127.0.0.1 if other methods fail.
                    pass
                return ip_address
            except Exception:
                return "127.0.0.1" # Default to localhost if all else fails


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
        self.nc = None  # NATS.py client instance
        self.nkeys = None  # NATS.py NKeyPair instance
        self._load_or_generate_nkeys()

    def _load_or_generate_nkeys(self):
        """Loads existing NATS NKeys or generates new ones."""
        # This is a placeholder. NATS.py nkeys handling is more involved.
        # For a real implementation, you'd use nkeys.from_seed, nkeys.create_user_nkey, etc.
        # and securely store/load the seed.
        # For now, we'll mock a simple NKeyPair or assume it's handled externally.
        logger.warning("NATS NKey generation/loading is a placeholder and needs proper implementation.")
        pass # No actual NKey logic here yet

    async def connect(self):
        """Connects to the NATS server."""
        # This is a placeholder. Actual NATS.py connection logic would go here.
        # e.g., self.nc = await nats.connect(self.nats_url, ...)
        logger.info(f"Connecting to NATS server at {self.nats_url}...")
        # Simulate connection
        await asyncio.sleep(0.1) # Simulate async operation
        self.nc = True # Mock connected state
        logger.info("NATS client connected (mock).")

    async def disconnect(self):
        """Disconnects from the NATS server."""
        if self.nc:
            logger.info("Disconnecting from NATS server...")
            # Simulate disconnection
            await asyncio.sleep(0.1) # Simulate async operation
            self.nc = None # Mock disconnected state
            logger.info("NATS client disconnected (mock).")

    async def publish(self, subject: str, payload: bytes):
        """Publishes a message to a NATS subject."""
        if not self.nc:
            logger.warning(f"Attempted to publish to {subject} but NATS client is not connected.")
            return
        logger.info(f"Publishing to NATS subject '{subject}': {payload[:50]}...")
        # Simulate publish
        await asyncio.sleep(0.05) # Simulate async operation

    async def subscribe(self, subject: str, cb):
        """Subscribes to a NATS subject."""
        if not self.nc:
            logger.warning(f"Attempted to subscribe to {subject} but NATS client is not connected.")
            return
        logger.info(f"Subscribing to NATS subject '{subject}'...")
        # Simulate subscription
        await asyncio.sleep(0.05) # Simulate async operation
        return f"sub_{subject}" # Return a mock subscription ID

    def _user_jwt_callback(self):
        # Placeholder for NATS user JWT callback
        return "mock_user_jwt"

    def _signature_callback(self, nonce):
        # Placeholder for NATS signature callback
        return b"mock_signature_bytes"

    async def _nats_error_cb(self, e):
        logger.error(f"NATS error: {e}")

    async def _nats_reconnected_cb(self):
        logger.info("NATS reconnected.")

    async def _nats_disconnected_cb(self):
        logger.warning("NATS disconnected.")

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
                    logger.info(f"SMBus initialized on bus {self.smbus_bus_num}.")
                except Exception as e:
                    logger.error(f"Failed to initialize SMBus on bus {self.smbus_bus_num}: {e}")
                    self.smbus_bus = None
            else:
                logger.warning("smbus2 not installed, SMBus communication disabled.")
                self.smbus_bus = None

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
            raise # Re-raise the exception to indicate critical failure

    async def stop(self):
        """Stops the device agent, disconnecting from NATS and cancelling tasks."""
        logger.info("Stopping Device Agent...")
        if self._telemetry_task:
            self._telemetry_task.cancel()
            try:
                await self._telemetry_task
            except asyncio.CancelledError:
                logger.info("Telemetry task cancelled.")
        if self._command_listener_task:
            self._command_listener_task.cancel()
            try:
                await self._command_listener_task
            except asyncio.CancelledError:
                logger.info("Command listener task cancelled.")

        await self.nats_client.disconnect()
        await self.client.update_status("offline", {"message": "Device agent stopped."})
        logger.info("Device Agent stopped.")

    async def run_telemetry_loop(self, interval: int = 60):
        """Collects and sends telemetry data periodically."""
        while True:
            try:
                telemetry_data = self._collect_telemetry()
                await asyncio.sleep(0.1) # Yield control briefly
                await self.client.send_telemetry(telemetry_data)
                logger.info(f"Telemetry sent. Next in {interval} seconds.")
            except PsutilNotInstalled as e:
                logger.warning(f"Telemetry collection skipped: {e}")
                await self.client.update_status("warning", {"message": f"Telemetry skipped: {e}"})
            except Exception as e:
                logger.error(f"Error collecting or sending telemetry: {e}")
                await self.client.update_status("warning", {"message": f"Telemetry error: {e}"})
            finally:
                await asyncio.sleep(interval)

    async def _command_listener(self):
        """Listens for incoming commands from NATS."""
        # This method would typically be where the NATS subscription callback is set up
        # and the loop that keeps the subscription active.
        # For now, the subscription is set up in `start`.
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
            # Corrected syntax: exc_info is a parameter for logger.error, not a dictionary key.
            # The exception details will be logged separately.
            response_payload = {"status": "error", "message": f"Error executing command: {e}"}
            logger.error(f"Unexpected error during command execution: {e}", exc_info=True)

        if reply:
            await self.nats_client.publish(reply, json.dumps(response_payload).encode())

    async def _handle_command(self, cmd_type: str, params: dict) -> dict:
        """Executes a received command based on its type."""
        if cmd_type == "get_telemetry":
            return self._collect_telemetry()
        elif cmd_type == "update_config":
            # Example: update telemetry interval
            new_interval = params.get("telemetry_interval")
            if isinstance(new_interval, int) and new_interval > 0:
                # In a real scenario, you'd update a persistent config and potentially restart loops
                # For this example, we'll just acknowledge.
                return {"message": f"Telemetry interval updated to {new_interval}s (requires restart to apply)."}
            else:
                raise ValueError("Invalid 'telemetry_interval' parameter. Must be a positive integer.")
        elif cmd_type == "smbus_write":
            address = params.get("address")
            command_code = params.get("command_code")
            data = params.get("data")
            if not all(isinstance(x, int) for x in [address, command_code]) or not isinstance(data, list):
                raise ValueError("Invalid parameters for smbus_write. Requires 'address' (int), 'command_code' (int), 'data' (list of int).")
            self._smbus_write_block_data(address, command_code, data)
            return {"message": "SMBus write successful."}
        elif cmd_type == "smbus_read":
            address = params.get("address")
            command_code = params.get("command_code")
            length = params.get("length")
            if not all(isinstance(x, int) for x in [address, command_code, length]) or length <= 0:
                raise ValueError("Invalid parameters for smbus_read. Requires 'address' (int), 'command_code' (int), 'length' (positive int).")
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
            logger.info(f"SMBus write: address=0x{address:02x}, command=0x{command_code:02x}, data={data}")
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
            logger.info(f"SMBus read: address=0x{address:02x}, command=0x{command_code:02x}, length={length}, data={read_data.hex()}")
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
                "ip_address": "0.0.0.0" # Default value
            },
            "system_metrics": { # Default values if psutil is not available or errors occur
                "uptime_seconds": 0.0,
                "cpu_usage_percent": 0.0,
                "memory_usage": {},
                "disk_usage": {},
                "temperature_celsius": 0.0,
            }
        }

        try:
            telemetry["network_info"]["ip_address"] = self.client._get_ip_address()
        except Exception as e:
            logger.error(f"Error collecting ip_address: {e}")
            telemetry["network_info"]["ip_address"] = "0.0.0.0" # Fallback

        if psutil:
            try:
                telemetry["system_metrics"]["uptime_seconds"] = self._get_uptime()
            except Exception as e:
                logger.error(f"Error collecting uptime_seconds: {e}")
                telemetry["system_metrics"]["uptime_seconds"] = 0.0

            try:
                telemetry["system_metrics"]["cpu_usage_percent"] = self._get_cpu_usage()
            except Exception as e:
                logger.error(f"Error collecting cpu_usage_percent: {e}")
                telemetry["system_metrics"]["cpu_usage_percent"] = 0.0

            try:
                telemetry["system_metrics"]["memory_usage"] = self._get_memory_usage()
            except Exception as e:
                logger.error(f"Error collecting memory_usage: {e}")
                telemetry["system_metrics"]["memory_usage"] = {}

            try:
                telemetry["system_metrics"]["disk_usage"] = self._get_disk_usage()
            except Exception as e:
                logger.error(f"Error collecting disk_usage: {e}")
                telemetry["system_metrics"]["disk_usage"] = {}

            try:
                telemetry["system_metrics"]["temperature_celsius"] = self._get_temperature()
            except Exception as e:
                logger.error(f"Error collecting temperature_celsius: {e}")
                telemetry["system_metrics"]["temperature_celsius"] = 0.0
        else:
            logger.warning("psutil not installed, system metrics will be unavailable.")
            # Default values already set above, no need to re-assign
            # raise PsutilNotInstalled() # Removed, now logs and returns defaults

        return telemetry

    def _get_uptime(self) -> float:
        """Returns system uptime in seconds."""
        return time.time() - psutil.boot_time()

    def _get_cpu_usage(self) -> float:
        """Returns current CPU usage percentage."""
        return psutil.cpu_percent(interval=None)  # Non-blocking call

    def _get_memory_usage(self) -> dict:
        """Returns memory usage statistics."""
        virtual_mem = psutil.virtual_memory()
        return {
            "total_gb": round(virtual_mem.total / (1024**3), 2),
            "available_gb": round(virtual_mem.available / (1024**3), 2),
            "percent": virtual_mem.percent,
            "used_gb": round(virtual_mem.used / (1024**3), 2),
            "free_gb": round(virtual_mem.free / (1024**3), 2),
        }

    def _get_disk_usage(self) -> dict:
        """Returns disk usage statistics for the root partition."""
        disk_use = psutil.disk_usage('/')
        return {
            "total_gb": round(disk_use.total / (1024**3), 2),
            "used_gb": round(disk_use.used / (1024**3), 2),
            "free_gb": round(disk_use.free / (1024**3), 2),
            "percent": disk_use.percent,
        }

    def _get_temperature(self) -> float:
        """Returns CPU temperature in Celsius if available."""
        if hasattr(psutil, 'sensors_temperatures'):
            temps = psutil.sensors_temperatures()
            if "coretemp" in temps and temps["coretemp"]:
                return temps["coretemp"][0].current
            elif "cpu_thermal" in temps and temps["cpu_thermal"]:
                return temps["cpu_thermal"][0].current
        return 0.0 # Default if no temperature sensor data

    def _get_ip_address(self) -> str:
        """Retrieves the device's IP address using the client's method."""
        return self.client._get_ip_address()


async def main():
    # Configuration
    API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
    NATS_URL = os.getenv("NATS_URL", "nats://localhost:4222")
    DEVICE_ID = os.getenv("DEVICE_ID")  # Optional: if not set, client will generate one
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
        SMBUS_BUS_NUM = 1  # Default to bus 1

    # Initialize clients
    api_client = SecureAPIClient(
        base_url=API_BASE_URL,
        device_id=DEVICE_ID,
        key_dir=KEY_DIR
    )
    nats_client = NATSClient(
        nats_url=NATS_URL,
        device_id=api_client.device_id,  # Use the ID generated/loaded by API client
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
            await asyncio.sleep(3600)  # Sleep for a long time, agent tasks run in background
    except asyncio.CancelledError:
        logger.info("Agent main loop cancelled.")
    except Exception as e:
        logger.critical(f"Agent encountered a critical error: {e}", exc_info=True)
    finally:
        await agent.stop()

if __name__ == "__main__":
    # For local development, you might run this directly.
    # In production, consider using a process manager (e.g., systemd, Docker)
    # to run the main function.
    asyncio.run(main())
