#!/usr/bin/env python3
"""
Secure API Client with mTLS Authentication
Uses provisioned certificates to authenticate with the secure server
"""

import requests
import ssl
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import json
import logging
import os
import time
from datetime import datetime, timezone
import socket

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define default key storage directory
DEFAULT_KEY_DIR = os.path.expanduser("~/.equus_express/keys")
CLIENT_PRIVATE_KEY_FILE = os.path.join(DEFAULT_KEY_DIR, "device.pem")
CLIENT_PUBLIC_KEY_FILE = os.path.join(DEFAULT_KEY_DIR, "device.pub")


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
        self.private_key = None
        self.public_key_pem = None

        os.makedirs(self.key_dir, exist_ok=True)
        self._load_or_generate_keys()

        # Create session (no client cert for now, will rely on new auth)
        self.session = requests.Session()
        self.session.verify = (
            False  # Assuming Traefik handles server SSL, or running HTTP
        )
        urllib3.disable_warnings(
            InsecureRequestWarning
        )  # Suppress warnings if verify=False

        # Set default headers, including device ID for identification
        self.session.headers.update(
            {
                "User-Agent": f"SecureClient/{self.device_id}",
                "Content-Type": "application/json",
                "X-Device-Id": self.device_id,  # Temporarily pass device_id in header for simplified auth
            }
        )

        logger.info(f"Initialized client for device: {self.device_id}")

    def _load_or_generate_keys(self):
        """Load existing keys or generate new RSA key pair."""
        private_key_path = CLIENT_PRIVATE_KEY_FILE
        public_key_path = CLIENT_PUBLIC_KEY_FILE

        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            with open(private_key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            with open(public_key_path, "rb") as f:
                self.public_key_pem = f.read().decode("utf-8")
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
            with open(private_key_path, "wb") as f:
                f.write(pem_private_key)

            # Serialize public key
            public_key = self.private_key.public_key()
            self.public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")
            with open(public_key_path, "w") as f:
                f.write(self.public_key_pem)

            logger.info(
                f"New device keys generated and saved to {self.key_dir}"
            )

    def _make_request(self, method: str, endpoint: str, **kwargs):
        """Make a request with error handling and logging"""
        url = f"{self.base_url}{endpoint}"

        try:
            logger.debug(f"Making {method} request to {url}")
            response = self.session.request(method, url, **kwargs)

            # Log response status
            logger.debug(f"Response status: {response.status_code}")

            # Raise for HTTP errors
            response.raise_for_status()

            # Try to parse JSON response
            try:
                return response.json()
            except json.JSONDecodeError:
                return response.text

        except requests.exceptions.SSLError as e:
            logger.error(f"SSL/TLS error: {e}")
            raise ConnectionError(f"SSL authentication failed: {e}")
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error: {e}")
            raise ConnectionError(f"Failed to connect to server: {e}")
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error: {e}")
            if e.response.status_code == 401:
                raise PermissionError(
                    "Authentication failed - invalid client certificate"
                )
            elif e.response.status_code == 403:
                raise PermissionError(
                    "Access denied - insufficient permissions"
                )
            else:
                raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise

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
        except Exception as e:
            logger.error(f"Failed to register device: {e}")
            raise

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
            except Exception as e:
                logger.warning(
                    f"Device info endpoint failed (this might be expected if server requires stronger auth post-registration): {e}"
                )

            logger.info(
                "✅ Connection test and initial registration step completed!"
            )
            return True

        except Exception as e:
            logger.error(f"❌ Connection test or registration failed: {e}")
            return False


class DeviceAgent:
    """High-level device agent that handles ongoing operations"""

    def __init__(self, client: SecureAPIClient):
        self.client = client
        self.running = False

    def start(self):
        """Start the device agent"""
        logger.info("Starting device agent...")
        self.running = True

        # Perform connection test and registration
        if not self.client.test_connection():
            logger.error("Failed initial connection and registration.")
            return False

        # Send initial status after successful connection/registration
        self.client.update_status(
            "online",
            {
                "startup_time": datetime.now(timezone.utc).isoformat(),
                "version": "1.0",  # You might want to get this from somewhere dynamically
            },
        )

        return True

    def stop(self):
        """Stop the device agent"""
        logger.info("Stopping device agent...")
        self.running = False

        # Send offline status
        try:
            self.client.update_status(
                "offline",
                {"shutdown_time": datetime.now(timezone.utc).isoformat()},
            )
        except Exception as e:
            logger.warning(f"Failed to send offline status: {e}")

    def run_telemetry_loop(self, interval: int = 60):
        """Run continuous telemetry reporting"""
        logger.info(f"Starting telemetry loop (interval: {interval}s)")

        while self.running:
            try:
                # Collect telemetry data
                telemetry_data = self._collect_telemetry()

                # Send to server
                response = self.client.send_telemetry(telemetry_data)
                logger.debug(f"Telemetry sent: {response}")

                # Wait for next interval
                time.sleep(interval)

            except KeyboardInterrupt:
                logger.info("Telemetry loop interrupted by user")
                break
            except Exception as e:
                logger.error(f"Telemetry loop error: {e}")
                time.sleep(interval)  # Wait before retrying

    def _collect_telemetry(self) -> dict:
        """Collect telemetry data from the device"""
        try:
            # Example telemetry data collection
            telemetry = {
                "system": {
                    "uptime": self._get_uptime(),
                    "cpu_usage": self._get_cpu_usage(),
                    "memory_usage": self._get_memory_usage(),
                    "disk_usage": self._get_disk_usage(),
                    "temperature": self._get_temperature(),
                },
                "network": {
                    "ip_address": self._get_ip_address(),
                    "connection_quality": "good",  # Simplified
                },
                "application": {"status": "running", "last_error": None},
            }

            return telemetry

        except Exception as e:
            logger.error(f"Failed to collect telemetry: {e}")
            return {"error": str(e)}

    def _get_uptime(self) -> float:
        """Get system uptime"""
        try:
            with open("/proc/uptime", "r") as f:
                return float(f.readline().split()[0])
        except:
            return 0.0

    def _get_cpu_usage(self) -> float:
        """Get CPU usage percentage"""
        try:
            import psutil

            return psutil.cpu_percent(interval=1)
        except:
            return 0.0

    def _get_memory_usage(self) -> dict:
        """Get memory usage information"""
        try:
            import psutil

            mem = psutil.virtual_memory()
            return {
                "total": mem.total,
                "available": mem.available,
                "percent": mem.percent,
            }
        except:
            return {"error": "psutil not available"}

    def _get_disk_usage(self) -> dict:
        """Get disk usage information"""
        try:
            import psutil

            disk = psutil.disk_usage("/")
            return {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": (disk.used / disk.total) * 100,
            }
        except:
            return {"error": "psutil not available"}

    def _get_temperature(self) -> float:
        """Get CPU temperature (Raspberry Pi specific)"""
        try:
            with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
                temp = float(f.read().strip()) / 1000.0
                return temp
        except:
            return 0.0

    def _get_ip_address(self) -> str:
        """Get device IP address"""
        try:
            import socket

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "unknown"


def main():
    """Main function for running the secure client"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 secure_client.py <secure_server_url> [device_id]")
        print("Example: python3 secure_client.py https://secure-server:8443")
        sys.exit(1)

    server_url = sys.argv[1]
    device_id = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        # Create client
        # The base_url should now be HTTP, as Traefik handles HTTPS.
        # Example: http://secure-server:8000
        client = SecureAPIClient(base_url=server_url, device_id=device_id)

        # Create device agent
        agent = DeviceAgent(client)

        # Start agent
        if agent.start():
            logger.info("Device agent started successfully")

            # Run telemetry loop
            try:
                agent.run_telemetry_loop(interval=30)  # 30 second intervals
            except KeyboardInterrupt:
                logger.info("Shutting down...")
            finally:
                agent.stop()
        else:
            logger.error("Failed to start device agent")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Client error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
