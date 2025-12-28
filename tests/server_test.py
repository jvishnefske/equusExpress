import os
import sqlite3
import pytest
from fastapi.testclient import TestClient
from equus_express.server import app, init_secure_db, lifespan # Import lifespan
import tempfile
from fastapi import FastAPI # Import FastAPI to create new app instances
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock # Added MagicMock import

# Initialize the TestClient
client = TestClient(app)

# Define a test device ID and public key
TEST_DEVICE_ID = "test_device_001"
TEST_PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD3g+3Y6J/K..."


@pytest.fixture(autouse=True)
def setup_teardown_db():
    """
    Fixture to set up and tear down the database for each test.
    Ensures a clean database state for every test.
    """
    # Define a temporary database file for testing
    test_db_path = "test_secure_devices.db"
    os.environ["SQLITE_DB_PATH"] = (
        test_db_path  # Use an env var if server used it, or pass directly
    )

    # Ensure the app uses the test database path during startup for the fixture scope
    # This might require modifying app initialization if not already flexible.
    # For now, we'll delete and re-create.
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    # Re-initialize the database
    init_secure_db()

    # Yield control to the test function
    yield

    # Teardown: Close connection and remove the test database file
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
    # Clean up the environment variable too, if set
    if "SQLITE_DB_PATH" in os.environ:
        del os.environ["SQLITE_DB_PATH"]


# Fixture to mock sqlite3.connect for error scenarios
@pytest.fixture
def mock_db_error():
    """Fixture to mock sqlite3.connect to raise an error."""
    with patch("equus_express.server.sqlite3.connect") as mock_connect:
        mock_connect.side_effect = sqlite3.Error("Mock DB Error")
        yield mock_connect


def get_db_connection():
    """Helper to get a database connection for assertions."""
    # Ensure this connects to the same test DB as the server
    db_path = os.getenv("SQLITE_DB_PATH", "test_secure_devices.db")
    return sqlite3.connect(db_path)


def test_health_check():
    """Test the /health endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert "timestamp" in response.json()


def test_register_device():
    """Test device registration."""
    response = client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "Device registered successfully." in response.json()["message"]

    # Verify device in DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT device_id, public_key FROM devices WHERE device_id = ?",
        (TEST_DEVICE_ID,),
    )
    device = cursor.fetchone()
    conn.close()

    assert device is not None
    assert device[0] == TEST_DEVICE_ID
    assert device[1] == TEST_PUBLIC_KEY


def test_send_telemetry():
    """Test sending telemetry data."""
    # First, register the device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    telemetry_data = {
        "device_id": TEST_DEVICE_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {"temp": 25.5, "humidity": 60},
    }
    response = client.post(
        "/api/telemetry",
        json=telemetry_data,
        headers={
            "X-Device-Id": TEST_DEVICE_ID
        },  # Pass device_id in header for authentication
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"

    # Verify telemetry in DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT device_id, data FROM telemetry WHERE device_id = ?",
        (TEST_DEVICE_ID,),
    )
    telemetry_record = cursor.fetchone()
    conn.close()

    assert telemetry_record is not None
    assert telemetry_record[0] == TEST_DEVICE_ID
    assert "temp" in telemetry_record[1]  # Check if data is stored as JSON string


def test_get_authenticated_device_id_missing_header():
    """Test get_authenticated_device_id when X-Device-Id header is missing."""
    # Attempt to access an authenticated endpoint without the header
    response = client.get("/api/device/info")
    assert response.status_code == 401
    assert "Authentication required" in response.json()["detail"]


def test_register_device_missing_fields():
    """Test device registration with missing device_id or public_key."""
    response = client.post("/api/register", json={"public_key": TEST_PUBLIC_KEY})
    assert response.status_code == 422 # Pydantic validation error
    assert "missing" in response.json()["detail"][0]["type"]

    response = client.post("/api/register", json={"device_id": TEST_DEVICE_ID})
    assert response.status_code == 422 # Pydantic validation error
    assert "missing" in response.json()["detail"][0]["type"]


def test_receive_telemetry_device_id_mismatch():
    """Test receiving telemetry with device ID mismatch between payload and header."""
    # First, register a device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    telemetry_data = {
        "device_id": "mismatched_device_id",  # Mismatched ID
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {"temp": 25.5},
    }
    response = client.post(
        "/api/telemetry",
        json=telemetry_data,
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.status_code == 403
    assert "Device ID in payload does not match authenticated device." in response.json()["detail"]


def test_update_device_status_device_id_mismatch():
    """Test updating device status with device ID mismatch between payload and header."""
    # First, register a device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    status_data = {
        "device_id": "mismatched_device_id",  # Mismatched ID
        "status": "active",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    response = client.post(
        "/api/device/status",
        json=status_data,
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.status_code == 403
    assert "Device ID in payload does not match authenticated device." in response.json()["detail"]


def test_get_device_config_device_id_mismatch():
    """Test getting device config with device ID mismatch between path and header."""
    # First, register a device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    mismatched_device_id = "another_device"
    response = client.get(
        f"/api/device/{mismatched_device_id}/config",
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.status_code == 403
    assert "Access denied: Device ID mismatch." in response.json()["detail"]


def test_list_devices_empty():
    """Test listing devices when no devices are registered."""
    response = client.get("/api/admin/devices")
    assert response.status_code == 200
    assert response.json()["devices"] == []


def test_get_device_telemetry_no_telemetry():
    """Test getting telemetry for a device that exists but has no telemetry."""
    # Register a device first
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    response = client.get(f"/api/admin/telemetry/{TEST_DEVICE_ID}")
    assert response.status_code == 200
    assert response.json()["device_id"] == TEST_DEVICE_ID
    assert response.json()["telemetry"] == []


def test_get_device_telemetry_device_not_found():
    """Test getting telemetry for a device that does not exist."""
    non_existent_device_id = "non_existent_device"
    response = client.get(f"/api/admin/telemetry/{non_existent_device_id}")
    assert response.status_code == 200  # Server returns 200 with empty list for non-existent device
    assert response.json()["device_id"] == non_existent_device_id
    assert response.json()["telemetry"] == []


def test_update_device_status():
    """Test updating device status."""
    # First, register the device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    status_data = {
        "device_id": TEST_DEVICE_ID,
        "status": "active",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {"battery": "80%"},
    }
    response = client.post(
        "/api/device/status",
        json=status_data,
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"

    # Verify status in DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT status FROM devices WHERE device_id = ?", (TEST_DEVICE_ID,)
    )
    device_status = cursor.fetchone()
    conn.close()

    assert device_status is not None
    assert device_status[0] == "active"


def test_get_device_info():
    """Test getting device information."""
    # First, register the device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    response = client.get(
        "/api/device/info",
        headers={
            "X-Device-Id": TEST_DEVICE_ID
        },  # Pass device_id in header for authentication
    )
    assert response.status_code == 200
    assert response.json()["device_id"] == TEST_DEVICE_ID
    assert "status" in response.json()


def test_get_device_info_not_found():
    """Test getting device info for a device that does not exist."""
    response = client.get(
        "/api/device/info",
        headers={"X-Device-Id": "non_existent_device"},
    )
    assert response.status_code == 200 # Current implementation returns 200 with error dict
    assert response.json() == {"error": "Device not found"}


def test_get_device_config():
    """Test getting device configuration."""
    # First, register the device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    response = client.get(
        f"/api/device/{TEST_DEVICE_ID}/config",
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.status_code == 200
    assert response.json()["device_id"] == TEST_DEVICE_ID
    assert "config" in response.json()
    assert (
        response.json()["config"]["telemetry_interval"] == 60
    )  # Default config


def test_list_devices():
    """Test listing all devices (admin endpoint)."""
    # Register a device first
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    response = client.get("/api/admin/devices")
    assert response.status_code == 200
    assert isinstance(response.json()["devices"], list)
    assert any(
        d["device_id"] == TEST_DEVICE_ID for d in response.json()["devices"]
    )


def test_get_device_telemetry():
    """Test getting telemetry for a specific device (admin endpoint)."""
    # Register device and send telemetry
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )
    telemetry_data = {
        "device_id": TEST_DEVICE_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {"temp": 25.5, "humidity": 60},
    }
    client.post(
        "/api/telemetry",
        json=telemetry_data,
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )

    response = client.get(f"/api/admin/telemetry/{TEST_DEVICE_ID}")
    assert response.status_code == 200
    assert response.json()["device_id"] == TEST_DEVICE_ID
    assert isinstance(response.json()["telemetry"], list)
    assert len(response.json()["telemetry"]) > 0
    assert "data" in response.json()["telemetry"][0]
    assert response.json()["telemetry"][0]["data"]["temp"] == pytest.approx(25.5)


def test_init_secure_db_error(mock_db_error):
    """Test init_secure_db handles database errors."""
    # Ensure a clean slate before attempting to init with error
    test_db_path = os.getenv("SQLITE_DB_PATH", "test_secure_devices.db")
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    with pytest.raises(sqlite3.Error, match="Mock DB Error"):
        init_secure_db()
    mock_db_error.assert_called_once() # Verify connect was attempted


def test_register_device_db_error(mock_db_error):
    """Test device registration endpoint handles database errors."""
    response = client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )
    assert response.status_code == 500
    assert "Database error during registration" in response.json()["detail"]


def test_register_device_unexpected_error():
    """Test device registration endpoint handles unexpected errors."""
    # Mock register_or_update_device to raise a non-sqlite3 error
    with patch('equus_express.server.register_or_update_device', side_effect=ValueError("Simulated unexpected error")):
        response = client.post(
            "/api/register",
            json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
        )
    assert response.status_code == 500
    assert "Failed to register device: Simulated unexpected error" in response.json()["detail"]


def test_get_device_info_db_error(mock_db_error):
    """Test get device info endpoint handles database errors."""
    response = client.get(
        "/api/device/info", headers={"X-Device-Id": TEST_DEVICE_ID}
    )
    assert response.status_code == 500
    assert "Failed to retrieve device info" in response.json()["detail"]


def test_receive_telemetry_db_error(mock_db_error):
    """Test receive telemetry endpoint handles database errors."""
    telemetry_data = {
        "device_id": TEST_DEVICE_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {"temp": 25.5, "humidity": 60},
    }
    response = client.post(
        "/api/telemetry",
        json=telemetry_data,
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.status_code == 500
    assert "Failed to store telemetry" in response.json()["detail"]


def test_receive_telemetry_unexpected_error():
    """Test receive telemetry endpoint handles unexpected errors."""
    # Mock sqlite3.connect within the endpoint to raise a non-sqlite3 error
    with patch('equus_express.server.sqlite3.connect', side_effect=ValueError("Unexpected telemetry DB error")):
        telemetry_data = {
            "device_id": TEST_DEVICE_ID,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"temp": 25.5, "humidity": 60},
        }
        response = client.post(
            "/api/telemetry",
            json=telemetry_data,
            headers={"X-Device-Id": TEST_DEVICE_ID},
        )
    assert response.status_code == 500
    assert "Failed to store telemetry" in response.json()["detail"]


def test_update_device_status_db_error(mock_db_error):
    """Test update device status endpoint handles database errors."""
    status_data = {
        "device_id": TEST_DEVICE_ID,
        "status": "active",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {"battery": "80%"},
    }
    response = client.post(
        "/api/device/status",
        json=status_data,
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.status_code == 500
    assert "Failed to update status" in response.json()["detail"]


def test_update_device_status_unexpected_error():
    """Test update device status endpoint handles unexpected errors."""
    with patch('equus_express.server.sqlite3.connect', side_effect=ValueError("Unexpected status DB error")):
        status_data = {
            "device_id": TEST_DEVICE_ID,
            "status": "active",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": {"battery": "80%"},
        }
        response = client.post(
            "/api/device/status",
            json=status_data,
            headers={"X-Device-Id": TEST_DEVICE_ID},
        )
    assert response.status_code == 500
    assert "Failed to update status" in response.json()["detail"]


def test_get_device_config_db_error(mock_db_error):
    """Test get device config endpoint handles database errors."""
    response = client.get(
        f"/api/device/{TEST_DEVICE_ID}/config",
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.status_code == 500
    assert "Failed to retrieve configuration" in response.json()["detail"]


def test_get_device_config_unexpected_error():
    """Test get device config endpoint handles unexpected errors."""
    with patch('equus_express.server.sqlite3.connect', side_effect=ValueError("Unexpected config DB error")):
        response = client.get(
            f"/api/device/{TEST_DEVICE_ID}/config",
            headers={"X-Device-Id": TEST_DEVICE_ID},
        )
    assert response.status_code == 500
    assert "Failed to retrieve configuration" in response.json()["detail"]


def test_list_devices_db_error(mock_db_error):
    """Test list devices endpoint handles database errors."""
    response = client.get("/api/admin/devices")
    assert response.status_code == 500
    assert "Failed to list devices" in response.json()["detail"]


def test_list_devices_unexpected_error():
    """Test list devices endpoint handles unexpected errors."""
    with patch('equus_express.server.sqlite3.connect', side_effect=ValueError("Unexpected list devices DB error")):
        response = client.get("/api/admin/devices")
    assert response.status_code == 500
    assert "Failed to list devices" in response.json()["detail"]


def test_get_device_telemetry_db_error(mock_db_error):
    """Test get device telemetry endpoint handles database errors."""
    response = client.get(f"/api/admin/telemetry/{TEST_DEVICE_ID}")
    assert response.status_code == 500
    assert "Failed to retrieve telemetry" in response.json()["detail"]


def test_get_device_telemetry_unexpected_error():
    """Test get device telemetry endpoint handles unexpected errors."""
    with patch('equus_express.server.sqlite3.connect', side_effect=ValueError("Unexpected telemetry DB error")):
        response = client.get(f"/api/admin/telemetry/{TEST_DEVICE_ID}")
    assert response.status_code == 500
    assert "Failed to retrieve telemetry" in response.json()["detail"]


def test_favicon_not_found():
    """Test favicon endpoint when file is not found."""
    with patch("equus_express.server.pkg_resources.files") as mock_files:
        mock_files.return_value.joinpath.return_value.is_dir.return_value = False
        mock_files.return_value.joinpath.return_value.__enter__.side_effect = FileNotFoundError("Favicon missing")
        response = client.get("/favicon.ico")
        assert response.status_code == 404
        assert "Favicon not found" in response.json()["detail"]


def test_lifespan_static_file_setup_error():
    """Test lifespan context manager handles errors during static file setup."""
    # Create a new FastAPI app instance specifically for this test
    # This ensures a fresh lifespan context is triggered with the TestClient.
    temp_app = FastAPI(lifespan=lifespan)

    # Mock tempfile.TemporaryDirectory to raise an error
    with patch("equus_express.server.tempfile.TemporaryDirectory", side_effect=OSError("Temp dir error")):
        with pytest.raises(RuntimeError, match="Failed to initialize static file serving"):
            # Use TestClient as a context manager to ensure lifespan startup is fully executed and errors propagated
            with TestClient(temp_app) as client:
                # No actual requests needed, just the startup part is tested
                pass


# Tests for Device Configuration Update endpoints

def test_update_device_config():
    """Test updating device configuration by the device itself."""
    # First, register the device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    # Update config
    new_config = {
        "telemetry_interval": 30,
        "log_level": "DEBUG",
        "features": {
            "telemetry_enabled": True,
            "remote_control": True,
            "auto_update": False,
        },
    }
    response = client.put(
        f"/api/device/{TEST_DEVICE_ID}/config",
        json={"config": new_config},
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert response.json()["config"] == new_config

    # Verify config is stored by fetching it
    response = client.get(
        f"/api/device/{TEST_DEVICE_ID}/config",
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.status_code == 200
    assert response.json()["config"] == new_config


def test_update_device_config_twice():
    """Test updating device configuration multiple times."""
    # Register the device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    # First update
    config_v1 = {"telemetry_interval": 30}
    response = client.put(
        f"/api/device/{TEST_DEVICE_ID}/config",
        json={"config": config_v1},
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.status_code == 200

    # Second update
    config_v2 = {"telemetry_interval": 120, "log_level": "ERROR"}
    response = client.put(
        f"/api/device/{TEST_DEVICE_ID}/config",
        json={"config": config_v2},
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.status_code == 200
    assert response.json()["config"] == config_v2

    # Verify latest config is stored
    response = client.get(
        f"/api/device/{TEST_DEVICE_ID}/config",
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.json()["config"] == config_v2


def test_update_device_config_device_id_mismatch():
    """Test updating config with device ID mismatch between path and header."""
    # Register the device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    mismatched_device_id = "another_device"
    response = client.put(
        f"/api/device/{mismatched_device_id}/config",
        json={"config": {"telemetry_interval": 30}},
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.status_code == 403
    assert "Access denied: Device ID mismatch." in response.json()["detail"]


def test_update_device_config_no_auth():
    """Test updating config without authentication."""
    response = client.put(
        f"/api/device/{TEST_DEVICE_ID}/config",
        json={"config": {"telemetry_interval": 30}},
    )
    assert response.status_code == 401
    assert "Authentication required" in response.json()["detail"]


def test_update_device_config_db_error(mock_db_error):
    """Test update device config endpoint handles database errors."""
    response = client.put(
        f"/api/device/{TEST_DEVICE_ID}/config",
        json={"config": {"telemetry_interval": 30}},
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.status_code == 500
    assert "Failed to update configuration" in response.json()["detail"]


# Admin device config endpoints tests

def test_admin_update_device_config():
    """Test admin updating device configuration."""
    # Register the device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    # Admin updates config
    new_config = {
        "telemetry_interval": 15,
        "log_level": "WARNING",
        "features": {"telemetry_enabled": False},
    }
    response = client.put(
        f"/api/admin/device/{TEST_DEVICE_ID}/config",
        json={"config": new_config},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert response.json()["message"] == "Configuration updated by admin"
    assert response.json()["config"] == new_config


def test_admin_update_device_config_device_not_found():
    """Test admin updating config for non-existent device."""
    response = client.put(
        "/api/admin/device/non_existent_device/config",
        json={"config": {"telemetry_interval": 30}},
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]


def test_admin_update_device_config_twice():
    """Test admin updating device configuration multiple times."""
    # Register the device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    # First admin update
    config_v1 = {"telemetry_interval": 15}
    response = client.put(
        f"/api/admin/device/{TEST_DEVICE_ID}/config",
        json={"config": config_v1},
    )
    assert response.status_code == 200

    # Second admin update
    config_v2 = {"telemetry_interval": 300, "log_level": "CRITICAL"}
    response = client.put(
        f"/api/admin/device/{TEST_DEVICE_ID}/config",
        json={"config": config_v2},
    )
    assert response.status_code == 200
    assert response.json()["config"] == config_v2


def test_admin_update_device_config_db_error(mock_db_error):
    """Test admin update config endpoint handles database errors."""
    response = client.put(
        f"/api/admin/device/{TEST_DEVICE_ID}/config",
        json={"config": {"telemetry_interval": 30}},
    )
    assert response.status_code == 500
    assert "Failed to update configuration" in response.json()["detail"]


def test_admin_get_device_config():
    """Test admin getting device configuration."""
    # Register the device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    # Get config (should return defaults since no config set yet)
    response = client.get(f"/api/admin/device/{TEST_DEVICE_ID}/config")
    assert response.status_code == 200
    assert response.json()["device_id"] == TEST_DEVICE_ID
    assert response.json()["config"]["telemetry_interval"] == 60  # Default
    assert response.json()["updated_at"] is None  # No custom config yet


def test_admin_get_device_config_after_update():
    """Test admin getting device configuration after it was updated."""
    # Register the device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    # Set config via admin endpoint
    new_config = {"telemetry_interval": 45, "custom_field": "test_value"}
    client.put(
        f"/api/admin/device/{TEST_DEVICE_ID}/config",
        json={"config": new_config},
    )

    # Get config
    response = client.get(f"/api/admin/device/{TEST_DEVICE_ID}/config")
    assert response.status_code == 200
    assert response.json()["config"] == new_config
    assert response.json()["updated_at"] is not None


def test_admin_get_device_config_device_not_found():
    """Test admin getting config for non-existent device."""
    response = client.get("/api/admin/device/non_existent_device/config")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]


def test_admin_get_device_config_db_error(mock_db_error):
    """Test admin get config endpoint handles database errors."""
    response = client.get(f"/api/admin/device/{TEST_DEVICE_ID}/config")
    assert response.status_code == 500
    assert "Failed to retrieve configuration" in response.json()["detail"]


def test_config_persistence_between_device_and_admin():
    """Test that config updates from device are visible to admin and vice versa."""
    # Register the device
    client.post(
        "/api/register",
        json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY},
    )

    # Device sets config
    device_config = {"telemetry_interval": 25, "source": "device"}
    client.put(
        f"/api/device/{TEST_DEVICE_ID}/config",
        json={"config": device_config},
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )

    # Admin should see it
    response = client.get(f"/api/admin/device/{TEST_DEVICE_ID}/config")
    assert response.json()["config"] == device_config

    # Admin updates config
    admin_config = {"telemetry_interval": 100, "source": "admin"}
    client.put(
        f"/api/admin/device/{TEST_DEVICE_ID}/config",
        json={"config": admin_config},
    )

    # Device should see the admin's config
    response = client.get(
        f"/api/device/{TEST_DEVICE_ID}/config",
        headers={"X-Device-Id": TEST_DEVICE_ID},
    )
    assert response.json()["config"] == admin_config
