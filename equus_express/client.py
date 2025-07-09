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
from datetime import datetime
import socket

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecureAPIClient:
    def __init__(self,
                 secure_base_url: str,
                 client_cert_file: str = "/etc/ssl/certs/device.crt",
                 client_key_file: str = "/etc/ssl/private/device.key",
                 ca_cert_file: str = "/etc/ssl/certs/ca.crt",
                 device_id: str = None):
        """
        Initialize the secure API client with mTLS authentication

        Args:
            secure_base_url: Base URL of the secure API server (HTTPS)
            client_cert_file: Path to client certificate file
            client_key_file: Path to client private key file
            ca_cert_file: Path to CA certificate file
            device_id: Device identifier for logging
        """
        self.base_url = secure_base_url.rstrip('/')
        self.client_cert_file = client_cert_file
        self.client_key_file = client_key_file
        self.ca_cert_file = ca_cert_file
        self.device_id = device_id or socket.gethostname()

        # Validate certificate files exist
        self._validate_certificates()

        # Create session with certificate authentication
        self.session = requests.Session()

        # Configure client certificate
        self.session.cert = (client_cert_file, client_key_file)

        # Configure server certificate verification
        if os.path.exists(ca_cert_file):
            self.session.verify = ca_cert_file
        else:
            logger.warning("CA certificate not found, disabling SSL verification")
            self.session.verify = False
            urllib3.disable_warnings(InsecureRequestWarning)

        # Set default headers
        self.session.headers.update({
            'User-Agent': f'SecureClient/{self.device_id}',
            'Content-Type': 'application/json'
        })

        logger.info(f"Initialized secure client for device: {self.device_id}")

    def _validate_certificates(self):
        """Validate that required certificate files exist"""
        required_files = [self.client_cert_file, self.client_key_file]

        for file_path in required_files:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"Required certificate file not found: {file_path}")

        logger.info("Certificate files validated")

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
                raise PermissionError("Authentication failed - invalid client certificate")
            elif e.response.status_code == 403:
                raise PermissionError("Access denied - insufficient permissions")
            else:
                raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise

    def get(self, endpoint: str, **kwargs):
        """Make a GET request"""
        return self._make_request('GET', endpoint, **kwargs)

    def post(self, endpoint: str, data=None, json=None, **kwargs):
        """Make a POST request"""
        return self._make_request('POST', endpoint, data=data, json=json, **kwargs)

    def put(self, endpoint: str, data=None, json=None, **kwargs):
        """Make a PUT request"""
        return self._make_request('PUT', endpoint, data=data, json=json, **kwargs)

    def delete(self, endpoint: str, **kwargs):
        """Make a DELETE request"""
        return self._make_request('DELETE', endpoint, **kwargs)

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
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
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
            "timestamp": datetime.utcnow().isoformat(),
            "details": details or {}
        }
        return self.post("/api/device/status", json=status_payload)

    def test_connection(self):
        """Test the secure connection and certificate authentication"""
        try:
            logger.info("Testing secure connection...")

            # Test basic connectivity
            response = self.health_check()
            logger.info(f"Health check response: {response}")

            # Test authenticated endpoint
            try:
                device_info = self.get_device_info()
                logger.info(f"Device info: {device_info}")
            except Exception as e:
                logger.warning(f"Device info endpoint failed: {e}")

            # Test certificate info endpoint
            try:
                cert_info = self.get("/api/auth/cert-info")
                logger.info(f"Certificate info: {cert_info}")
            except Exception as e:
                logger.warning(f"Certificate info endpoint failed: {e}")

            logger.info("✅ Secure connection test successful!")
            return True

        except Exception as e:
            logger.error(f"❌ Secure connection test failed: {e}")
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

        # Initial connection test
        if not self.client.test_connection():
            logger.error("Failed to establish secure connection")
            return False

        # Send initial status
        self.client.update_status("online", {
            "startup_time": datetime.utcnow().isoformat(),
            "version": "1.0"
        })

        return True

    def stop(self):
        """Stop the device agent"""
        logger.info("Stopping device agent...")
        self.running = False

        # Send offline status
        try:
            self.client.update_status("offline", {
                "shutdown_time": datetime.utcnow().isoformat()
            })
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
                    "temperature": self._get_temperature()
                },
                "network": {
                    "ip_address": self._get_ip_address(),
                    "connection_quality": "good"  # Simplified
                },
                "application": {
                    "status": "running",
                    "last_error": None
                }
            }

            return telemetry

        except Exception as e:
            logger.error(f"Failed to collect telemetry: {e}")
            return {"error": str(e)}

    def _get_uptime(self) -> float:
        """Get system uptime"""
        try:
            with open('/proc/uptime', 'r') as f:
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
                "percent": mem.percent
            }
        except:
            return {"error": "psutil not available"}

    def _get_disk_usage(self) -> dict:
        """Get disk usage information"""
        try:
            import psutil
            disk = psutil.disk_usage('/')
            return {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": (disk.used / disk.total) * 100
            }
        except:
            return {"error": "psutil not available"}

    def _get_temperature(self) -> float:
        """Get CPU temperature (Raspberry Pi specific)"""
        try:
            with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
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
        # Create secure client
        client = SecureAPIClient(server_url, device_id=device_id)

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