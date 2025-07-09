import os
import sqlite3
import pytest
from fastapi.testclient import TestClient
from equus_express.server import app, init_secure_db
from datetime import datetime

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
    os.environ["SQLITE_DB_PATH"] = test_db_path # Use an env var if server used it, or pass directly

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
    cursor.execute("SELECT device_id, public_key FROM devices WHERE device_id = ?", (TEST_DEVICE_ID,))
    device = cursor.fetchone()
    conn.close()

    assert device is not None
    assert device[0] == TEST_DEVICE_ID
    assert device[1] == TEST_PUBLIC_KEY


def test_send_telemetry():
    """Test sending telemetry data."""
    # First, register the device
    client.post("/api/register", json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY})

    telemetry_data = {
        "device_id": TEST_DEVICE_ID,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {"temp": 25.5, "humidity": 60},
    }
    response = client.post(
        "/api/telemetry",
        json=telemetry_data,
        headers={"X-Device-Id": TEST_DEVICE_ID} # Pass device_id in header for authentication
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"

    # Verify telemetry in DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT device_id, data FROM telemetry WHERE device_id = ?", (TEST_DEVICE_ID,))
    telemetry_record = cursor.fetchone()
    conn.close()

    assert telemetry_record is not None
    assert telemetry_record[0] == TEST_DEVICE_ID
    assert "temp" in telemetry_record[1] # Check if data is stored as JSON string


def test_update_device_status():
    """Test updating device status."""
    # First, register the device
    client.post("/api/register", json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY})

    status_data = {
        "device_id": TEST_DEVICE_ID,
        "status": "active",
        "timestamp": datetime.utcnow().isoformat(),
        "details": {"battery": "80%"}
    }
    response = client.post(
        "/api/device/status",
        json=status_data,
        headers={"X-Device-Id": TEST_DEVICE_ID}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"

    # Verify status in DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM devices WHERE device_id = ?", (TEST_DEVICE_ID,))
    device_status = cursor.fetchone()
    conn.close()

    assert device_status is not None
    assert device_status[0] == "active"


def test_get_device_info():
    """Test getting device information."""
    # First, register the device
    client.post("/api/register", json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY})

    response = client.get(
        "/api/device/info",
        headers={"X-Device-Id": TEST_DEVICE_ID} # Pass device_id in header for authentication
    )
    assert response.status_code == 200
    assert response.json()["device_id"] == TEST_DEVICE_ID
    assert "status" in response.json()


def test_get_device_config():
    """Test getting device configuration."""
    # First, register the device
    client.post("/api/register", json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY})

    response = client.get(
        f"/api/device/{TEST_DEVICE_ID}/config",
        headers={"X-Device-Id": TEST_DEVICE_ID}
    )
    assert response.status_code == 200
    assert response.json()["device_id"] == TEST_DEVICE_ID
    assert "config" in response.json()
    assert response.json()["config"]["telemetry_interval"] == 60 # Default config


def test_list_devices():
    """Test listing all devices (admin endpoint)."""
    # Register a device first
    client.post("/api/register", json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY})

    response = client.get("/api/admin/devices")
    assert response.status_code == 200
    assert isinstance(response.json()["devices"], list)
    assert any(d["device_id"] == TEST_DEVICE_ID for d in response.json()["devices"])


def test_get_device_telemetry():
    """Test getting telemetry for a specific device (admin endpoint)."""
    # Register device and send telemetry
    client.post("/api/register", json={"device_id": TEST_DEVICE_ID, "public_key": TEST_PUBLIC_KEY})
    telemetry_data = {
        "device_id": TEST_DEVICE_ID,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {"temp": 25.5, "humidity": 60},
    }
    client.post("/api/telemetry", json=telemetry_data, headers={"X-Device-Id": TEST_DEVICE_ID})

    response = client.get(f"/api/admin/telemetry/{TEST_DEVICE_ID}")
    assert response.status_code == 200
    assert response.json()["device_id"] == TEST_DEVICE_ID
    assert isinstance(response.json()["telemetry"], list)
    assert len(response.json()["telemetry"]) > 0
    assert "data" in response.json()["telemetry"][0]
    assert response.json()["telemetry"][0]["data"]["temp"] == 25.5
