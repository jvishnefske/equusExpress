import os
import sqlite3
import pytest
from fastapi.testclient import TestClient
from equus_express.system_api import app, init_secure_db, lifespan, init_api_server_identity # Import init_api_server_identity directly
from equus_express.system_api import PROJECT_ROOT_DIR
from fastapi import FastAPI
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock, AsyncMock # Added AsyncMock import
from unittest.mock import mock_open
from cryptography.hazmat.primitives.asymmetric import rsa
import shutil
import pathlib

# Define a test device ID and public key
TEST_DEVICE_ID = "test_device_001"
TEST_PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD3g+3Y6J/K..."

# Constants for API server identity tests
MOCK_API_SERVER_ID = "00000000-0000-4000-8000-000000000001"
MOCK_API_PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----MOCK_API_PUBLIC_KEY-----END PUBLIC KEY-----"


# Initialize the TestClient AFTER defining PROJECT_ROOT_DIR and other module-level constants
# This global client will be used for tests that interact with the full FastAPI app lifecycle.
# For tests that specifically mock init_api_server_identity, we'll create a new app instance or call the function directly.
client = TestClient(app)

# Helper function for patching pathlib.Path.exists
def _mock_path_exists_side_effect_factory(initial_values):
    iterator = iter(initial_values)
    def mock_method(*args, **kwargs):
        try: return next(iterator)
        except StopIteration: return True
    return mock_method

# Removed @pytest.fixture(autouse=True) patch_pathlib_exists_global

@pytest.fixture(autouse=True)
def setup_teardown_db():
    """
    Fixture to set up and tear down the database for each test.
    Ensures a clean database state for every test.
    """
    test_db_path = "test_secure_devices.db"
    os.environ["SQLITE_DB_PATH"] = test_db_path
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    init_secure_db()

    yield

    conn = sqlite3.connect(test_db_path)
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS devices")
    cursor.execute("DROP TABLE IF EXISTS telemetry")
    cursor.execute("DROP TABLE IF EXISTS device_status")
    cursor.execute("DROP TABLE IF EXISTS device_config")
    cursor.execute("DROP TABLE IF EXISTS api_provision_requests")
    conn.commit()
    conn.close()
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
    if "SQLITE_DB_PATH" in os.environ:
        del os.environ["SQLITE_DB_PATH"]


@pytest.fixture
def mock_api_identity_generation(tmp_path):
    """Mocks UUID and crypto functions for API server identity generation."""
    temp_api_keys_dir = tmp_path / "test_api_keys_gen"
    # No need for shutil.rmtree here, tmp_path handles cleanup.
    # We will mock exists to ensure it appears not to exist initially.

    mock_app = MagicMock() # Mock the app object passed to init_api_server_identity
    mock_app.state = MagicMock() # Mock app.state

    mock_uuid = MagicMock()
    mock_uuid.uuid4.return_value = MOCK_API_SERVER_ID

    mock_private_key = MagicMock()
    mock_private_key.private_bytes.return_value = (
        b"-----BEGIN PRIVATE KEY-----MOCK_API_PRIVATE_KEY-----END PRIVATE KEY-----"
    )
    mock_private_key.public_key.return_value.public_bytes.return_value = MOCK_API_PUBLIC_KEY_PEM.encode("utf-8")

    # Mock Path.exists for the specific paths within temp_api_keys_dir
    # This needs to be done carefully to avoid interfering with other Path.exists calls.
    # We'll patch pathlib.Path.exists for the specific paths.
    mock_server_id_path = temp_api_keys_dir / "api_server_id.txt"
    mock_private_key_path = temp_api_keys_dir / "api_server_key.pem"

    # Configure mock_open for writing
    m_open = mock_open()

    with (
        patch("equus_express.system_api.uuid", mock_uuid),
        patch("equus_express.system_api.serialization") as mock_serialization,
        patch("equus_express.system_api.default_backend"),
        patch("builtins.open", m_open),
        patch("equus_express.system_api.rsa.generate_private_key", return_value=mock_private_key),
        # Patch pathlib.Path.exists to control behavior for the specific files
        patch.object(pathlib.Path, 'exists', side_effect=lambda p: False if p in [mock_server_id_path, mock_private_key_path] else True),
        patch.object(pathlib.Path, 'mkdir'), # Mock mkdir to prevent actual directory creation
    ):
        # Configure mock_serialization for PEM encoding/decryption
        mock_serialization.Encoding.PEM = MagicMock()
        mock_serialization.PrivateFormat.PKCS8 = MagicMock()
        mock_serialization.NoEncryption.return_value = MagicMock()
        mock_serialization.PublicFormat.SubjectPublicKeyInfo = MagicMock()
        mock_serialization.load_pem_private_key.return_value = mock_private_key

        # Call the function directly with the mocked app and temp_api_keys_dir
        init_api_server_identity(mock_app, key_dir=temp_api_keys_dir)

        yield {
            "mock_app": mock_app,
            "mock_uuid": mock_uuid,
            "mock_generate_private_key": rsa.generate_private_key,
            "mock_private_key": mock_private_key,
            "mock_file_open": m_open,
            "temp_api_keys_dir": temp_api_keys_dir,
            "mock_server_id_path": mock_server_id_path,
            "mock_private_key_path": mock_private_key_path,
        }


@pytest.fixture
def mock_api_identity_loading(tmp_path):
    """Mocks UUID and crypto functions for API server identity loading."""
    temp_api_keys_dir = tmp_path / "test_api_keys_load"

    mock_app = MagicMock() # Mock the app object passed to init_api_server_identity
    mock_app.state = MagicMock() # Mock app.state

    mock_uuid = MagicMock()
    mock_uuid.uuid4.return_value = MOCK_API_SERVER_ID

    mock_private_key = MagicMock()
    mock_private_key.private_bytes.return_value = (
        b"-----BEGIN PRIVATE KEY-----MOCK_API_PRIVATE_KEY-----END PRIVATE KEY-----"
    )
    mock_private_key.public_key.return_value.public_bytes.return_value = MOCK_API_PUBLIC_KEY_PEM.encode("utf-8")

    mock_server_id_path = temp_api_keys_dir / "api_server_id.txt"
    mock_private_key_path = temp_api_keys_dir / "api_server_key.pem"

    # Simulate files existing for loading scenario
    m_open = mock_open()
    m_open.return_value.__enter__.return_value.read.side_effect = [
        MOCK_API_SERVER_ID, # Content for api_server_id.txt
        b"-----BEGIN PRIVATE KEY-----MOCK_PRIVATE_KEY_LOADED-----END PRIVATE KEY-----", # Content for api_server_key.pem
    ]

    with (
        patch("equus_express.system_api.uuid", mock_uuid),
        patch("equus_express.system_api.rsa.generate_private_key"), # Should not be called
        patch("equus_express.system_api.serialization") as mock_serialization,
        patch("builtins.open", m_open),
        # Patch pathlib.Path.exists to control behavior for the specific files
        patch.object(pathlib.Path, 'exists', side_effect=lambda p: True if p in [mock_server_id_path, mock_private_key_path] else False),
        patch.object(pathlib.Path, 'mkdir'), # Mock mkdir to prevent actual directory creation
    ):
        # Configure mock_serialization for PEM encoding/decryption
        mock_serialization.Encoding.PEM = MagicMock()
        mock_serialization.PrivateFormat.PKCS8 = MagicMock()
        mock_serialization.NoEncryption.return_value = MagicMock()
        mock_serialization.PublicFormat.SubjectPublicKeyInfo = MagicMock()
        mock_serialization.load_pem_private_key.return_value = mock_private_key

        # Call the function directly with the mocked app and temp_api_keys_dir
        init_api_server_identity(mock_app, key_dir=temp_api_keys_dir)

        yield {
            "mock_app": mock_app,
            "mock_uuid": mock_uuid,
            "mock_generate_private_key": rsa.generate_private_key,
            "mock_private_key": mock_private_key,
            "mock_file_open": m_open,
            "mock_serialization": mock_serialization,
            "temp_api_keys_dir": temp_api_keys_dir,
            "mock_server_id_path": mock_server_id_path,
            "mock_private_key_path": mock_private_key_path,
        }


def test_api_server_identity_generated_on_startup(setup_teardown_db, mock_api_identity_generation):
    """Test that API server identity (GUID and keys) is generated on startup if not present."""
    mock_data = mock_api_identity_generation

    # Assert generation occurred
    mock_data["mock_generate_private_key"].assert_called_once()
    mock_data["mock_uuid"].uuid4.assert_called_once()

    # Assert files were written
    mock_data["mock_file_open"].assert_any_call(str(mock_data["mock_server_id_path"]), "w")
    mock_data["mock_file_open"].assert_any_call(str(mock_data["mock_private_key_path"]), "wb")

    # Assert that app.state was populated
    assert mock_data["mock_app"].state.api_server_id == MOCK_API_SERVER_ID
    assert mock_data["mock_app"].state.api_private_key is not None
    assert mock_data["mock_app"].state.api_public_key_pem == MOCK_API_PUBLIC_KEY_PEM


def test_api_server_identity_loaded_on_startup(setup_teardown_db, mock_api_identity_loading):
    """Test that API server identity (GUID and keys) is loaded on startup if present."""
    mock_data = mock_api_identity_loading

    # Assert loading occurred, not generation
    mock_data["mock_generate_private_key"].assert_not_called()
    mock_data["mock_serialization"].load_pem_private_key.assert_called_once()
    mock_data["mock_private_key"].public_key().public_bytes.assert_called_once() # Public key derived from loaded private key

    assert mock_data["mock_app"].state.api_server_id == MOCK_API_SERVER_ID
    assert mock_data["mock_app"].state.api_private_key is not None
    assert mock_data["mock_app"].state.api_public_key_pem == MOCK_API_PUBLIC_KEY_PEM


# Fixture to mock sqlite3.connect for error scenarios
@pytest.fixture
def mock_db_error():
    """Fixture to mock sqlite3.connect to raise an error."""
    with patch("equus_express.system_api.sqlite3.connect") as mock_connect:
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
    # First, register the device
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
    with patch('equus_express.system_api.register_or_update_device', side_effect=ValueError("Simulated unexpected error")):
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
    # Mock sqlite3.connect within the endpoint to raise a non-system_api error
    with patch('equus_express.system_api.sqlite3.connect', side_effect=ValueError("Unexpected telemetry DB error")):
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
    with patch('equus_express.system_api.sqlite3.connect', side_effect=ValueError("Unexpected status DB error")):
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
    with patch('equus_express.system_api.sqlite3.connect', side_effect=ValueError("Unexpected config DB error")):
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
    with patch('equus_express.system_api.sqlite3.connect', side_effect=ValueError("Unexpected list devices DB error")):
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
    with patch('equus_express.system_api.sqlite3.connect', side_effect=ValueError("Unexpected telemetry DB error")):
        response = client.get(f"/api/admin/telemetry/{TEST_DEVICE_ID}")
    assert response.status_code == 500
    assert "Failed to retrieve telemetry" in response.json()["detail"]


def test_api_provision_request_success():
    """Test the /api/provision/request endpoint successfully submits a request."""
    request_data = {
        "requesting_api_id": "api-server-123",
        "public_key": "ssh-rsa API_PUBLIC_KEY_123...",
        "contact_email": "admin@example.com",
        "notes": "Request for edge API",
    }
    response = client.post("/api/provision/request", json=request_data)

    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "Provisioning request submitted. Awaiting administrator approval." in response.json()["message"]

    # Verify data in api_provision_requests table
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT requesting_api_id, public_key, contact_email, notes, status, ip_address FROM api_provision_requests WHERE requesting_api_id = ?", ("api-server-123",))
    record = cursor.fetchone()
    conn.close()

    assert record is not None
    assert record[0] == "api-server-123"
    assert record[1] == "ssh-rsa API_PUBLIC_KEY_123..."
    assert record[2] == "admin@example.com"
    assert record[3] == "Request for edge API"
    assert record[4] == "pending"
    assert record[5] is not None # ip_address should be captured


def test_api_provision_request_missing_fields():
    """Test /api/provision/request with missing required fields."""
    response = client.post("/api/provision/request", json={"public_key": "abc"})
    assert response.status_code == 422
    assert "requesting_api_id" in response.json()["detail"][0]["loc"]

    response = client.post("/api/provision/request", json={"requesting_api_id": "abc"})
    assert response.status_code == 422
    assert "public_key" in response.json()["detail"][0]["loc"]


def test_api_provision_request_db_error(mock_db_error):
    """Test /api/provision/request handles database errors."""
    request_data = {
        "requesting_api_id": "api-server-123",
        "public_key": "ssh-rsa API_PUBLIC_KEY_123..."
    }
    response = client.post("/api/provision/request", json=request_data)
    assert response.status_code == 500
    assert "Failed to submit provisioning request" in response.json()["detail"]


def test_favicon_not_found():
    """Test favicon endpoint when file is not found."""
    with patch("equus_express.system_api.pkg_resources.files") as mock_files:
        # Mock the behavior of files().joinpath().as_file() to raise FileNotFoundError
        mock_resource = MagicMock()
        mock_resource.is_dir.return_value = False # Ensure it's not treated as a directory
        mock_files.return_value.joinpath.return_value = mock_resource

        # Patch as_file to raise FileNotFoundError when entered
        with patch("equus_express.system_api.pkg_resources.as_file", side_effect=FileNotFoundError("Favicon missing")):
            response = client.get("/favicon.ico")
            assert response.status_code == 404
            assert "Favicon not found" in response.json()["detail"]


def test_lifespan_static_file_setup_error():
    """Test lifespan context manager handles errors during static file setup."""
    # Create a new FastAPI app instance specifically for this test
    # This ensures a fresh lifespan context is triggered with the TestClient.
    temp_app = FastAPI(lifespan=lifespan)

    # Mock tempfile.TemporaryDirectory to raise an error
    with patch("equus_express.system_api.tempfile.TemporaryDirectory", side_effect=OSError("Temp dir error")):
        with pytest.raises(RuntimeError, match="Failed to initialize static file serving"):
            # Use TestClient as a context manager to ensure lifespan startup is fully executed and errors propagated
            with TestClient(temp_app) as client:
                # No actual requests needed, just the startup part is tested
                pass

