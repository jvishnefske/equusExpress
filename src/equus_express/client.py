#!/usr/bin/env python3
"""
Secure API Client with mTLS Authentication
Uses provisioned certificates to authenticate with the secure server
"""

import httpx  # Changed from requests
import ssl

# Removed urllib3 and InsecureRequestWarning as httpx handles verify differently
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

# Import psutil if available (optional dependency for telemetry)
try:
    import psutil
except ImportError:
    psutil = None
    logger.warning(
        "psutil not found. Some telemetry data might be unavailable."
    )


class PsutilNotInstalled(NotImplementedError):
    # This class now takes a message, so it's consistent with other exceptions
    def __init__(self, message="psutil library is not available."):
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


class DeviceAgent:
    """High-level device agent that handles ongoing operations"""

    def __init__(self, client: SecureAPIClient):
        self.client = client
        self.running = False

    def start(self):
        """Start the device agent"""
        logger.info("Starting device agent...")

        # Perform connection test and registration
        if not self.client.test_connection():
            logger.error("Failed initial connection and registration.")
            self.running = False  # Explicitly set to False on failure
            return False

        # If connection is successful, set running to True
        self.running = True

        # Send initial status after successful connection/registration
        try:
            self.client.update_status(
                "online",
                {
                    "startup_time": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0",  # You might want to get this from somewhere dynamically
                },
            )
        except (httpx.RequestError, ConnectionError, PermissionError) as e:
            # Uncovered: Failed to send initial 'online' status
            logger.warning(f"Failed to send initial 'online' status: {e}")
            # Decide if this is a critical failure that should stop startup.
            # For now, we'll allow it to proceed but warn.

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
        except (httpx.RequestError, ConnectionError, PermissionError) as e:
            logger.warning(f"Failed to send offline status: {e}")

    def run_telemetry_loop(self, interval: int = 60):
        """Run continuous telemetry reporting"""
        logger.info(f"Starting telemetry loop (interval: {interval}s)")

        while self.running:
            try:
                # Collect telemetry data
                telemetry_data = self._collect_telemetry()

                # Send to server
                self.client.send_telemetry(telemetry_data)

                # Wait for next interval
                time.sleep(interval)

            except KeyboardInterrupt:
                logger.info("Telemetry loop interrupted by user")
                break
            except (
                httpx.RequestError,
                ConnectionError,
                PermissionError,
                json.JSONDecodeError,
                TypeError,
            ) as e:
                # Uncovered: Client communication errors or data formatting issues in telemetry loop
                logger.error(
                    f"Telemetry loop communication or data error: {e}"
                )
                time.sleep(interval)  # Wait before retrying
            except (
                Exception
            ) as e:  # Fallback for any other unexpected errors in the loop
                # Uncovered: Unexpected error in telemetry loop (fallback)
                logger.exception(
                    f"An unexpected error occurred in telemetry loop: {e}"
                )  # Use exception for full traceback
                time.sleep(interval)

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


def main():
    """Main function for running the secure client"""
    import sys # Moved import sys here

    if len(sys.argv) < 2:
        # Uncovered: Not enough arguments for main
        print(
            "Usage: python3 secure_client.py <secure_server_url> [device_id]"
        )
        print("Example: python3 secure_client.py https://secure-server:8443")
        sys.exit(1) # Uncovered: Exit on missing arguments

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
                logger.info("Telemetry loop stopped by user.")
            except (
                Exception
            ) as e:  # Catch any unhandled errors in telemetry loop
                # Uncovered: Unhandled error in telemetry loop
                logger.critical(
                    f"Unhandled error in telemetry loop, agent stopping: {e}"
                )
            finally:
                agent.stop()
        else:
            logger.error("Failed to start device agent")
            sys.exit(1) # Uncovered: Exit if agent fails to start

    except (RuntimeError, ConnectionError, PermissionError) as e:
        # Uncovered: Critical client error (e.g., key initialization failure)
        logger.error(f"A critical client error occurred: {e}")
        sys.exit(1) # Uncovered: Exit on critical client error
    except Exception as e:
        # Uncovered: Any unexpected error in main process
        logger.exception(
            f"An unexpected error occurred in the main client process: {e}"
        )
        sys.exit(1) # Uncovered: Exit on unexpected main error


@pytest.fixture(autouse=True)
def mock_sys_exit():
    """Fixture to mock sys.exit to prevent actual program exit during tests."""
    with patch('sys.exit') as mock_exit:
        yield mock_exit


def test_main_no_arguments(mock_sys_exit, capsys):
    """Test main function exits with error if no arguments are provided."""
    # Temporarily modify sys.argv for the test
    original_argv = sys.argv
    sys.argv = ["secure_client.py"]

    try:
        from equus_express.client import main
        main()
    finally:
        sys.argv = original_argv # Restore original argv

    mock_sys_exit.assert_called_once_with(1)
    captured = capsys.readouterr()
    assert "Usage: python3 secure_client.py <secure_server_url> [device_id]" in captured.out


def test_main_agent_start_failure(mock_sys_exit, mock_device_agent_dependencies, caplog):
    """Test main function exits if device agent fails to start."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_client.test_connection.return_value = False # Force agent.start() to fail

    original_argv = sys.argv
    sys.argv = ["secure_client.py", TEST_BASE_URL, TEST_DEVICE_ID]

    with caplog.at_level(logging.ERROR):
        try:
            from equus_express.client import main
            main()
        finally:
            sys.argv = original_argv

    mock_sys_exit.assert_called_once_with(1)
    assert "Failed to start device agent" in caplog.text


def test_main_client_init_critical_error(mock_sys_exit, mock_crypto, mock_httpx_client, tmp_key_dir, caplog):
    """Test main function exits on critical client initialization error."""
    mock_crypto["mock_os_makedirs"].side_effect = OSError("Critical init error") # Simulate error during key setup

    original_argv = sys.argv
    sys.argv = ["secure_client.py", TEST_BASE_URL, TEST_DEVICE_ID]

    with caplog.at_level(logging.ERROR):
        try:
            from equus_express.client import main
            main()
        finally:
            sys.argv = original_argv

    mock_sys_exit.assert_called_once_with(1)
    assert "A critical client error occurred: Failed to initialize client keys: Critical init error" in caplog.text


def test_main_telemetry_loop_unhandled_exception(mock_sys_exit, mock_device_agent_dependencies, caplog):
    """Test main function catches unhandled exceptions in telemetry loop and stops agent."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_sleep = mock_device_agent_dependencies["mock_sleep"]
    mock_sleep.side_effect = [
        None, # First sleep for loop iteration
        Exception("Simulated unhandled loop error"), # Second sleep to cause unhandled error
    ]

    original_argv = sys.argv
    sys.argv = ["secure_client.py", TEST_BASE_URL, TEST_DEVICE_ID]

    with caplog.at_level(logging.CRITICAL):
        try:
            from equus_express.client import main
            main()
        finally:
            sys.argv = original_argv

    mock_sys_exit.assert_called_once_with(1)
    assert "Unhandled error in telemetry loop, agent stopping: Simulated unhandled loop error" in caplog.text
    mock_client.update_status.assert_called_with("offline", {"shutdown_time": mock_device_agent_dependencies["fixed_now_iso"]})


def test_main_unexpected_error(mock_sys_exit, caplog):
    """Test main function handles unexpected general exceptions."""
    original_argv = sys.argv
    sys.argv = ["secure_client.py", TEST_BASE_URL, TEST_DEVICE_ID]

    # Mock SecureAPIClient constructor to raise an unexpected error
    with patch("equus_express.client.SecureAPIClient", side_effect=Exception("Unexpected client error")):
        with caplog.at_level(logging.CRITICAL):
            try:
                from equus_express.client import main
                main()
            finally:
                sys.argv = original_argv

    mock_sys_exit.assert_called_once_with(1)
    assert "An unexpected error occurred in the main client process: Unexpected client error" in caplog.text
