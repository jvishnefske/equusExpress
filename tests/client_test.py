import pytest
import os
import shutil
import json
from unittest.mock import patch, MagicMock, mock_open
from datetime import datetime, timezone # Import datetime and timezone
import time
import httpx # Changed from requests

# Import the classes to be tested
from equus_express.client import SecureAPIClient, DeviceAgent

# Constants for testing
TEST_BASE_URL = "http://mock-server"
TEST_DEVICE_ID = "test_client_device"
MOCK_PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsdfadsfadsfasdfasdf\n-----END PUBLIC KEY-----\n"


@pytest.fixture
def tmp_key_dir(tmp_path):
    """Fixture to create a temporary directory for client keys and clean up after."""
    key_dir = tmp_path / "test_keys"
    key_dir.mkdir()
    yield str(key_dir)
    # No need for explicit cleanup, tmp_path fixture handles it.


@pytest.fixture
def mock_crypto():
    """Fixture to mock cryptography functions for key generation/loading."""
    with (
        patch(
            "equus_express.client.rsa.generate_private_key"
        ) as mock_generate_private_key,
        patch(
            "equus_express.client.serialization"
        ) as mock_serialization, # Patch the entire serialization module
        patch(
            "equus_express.client.default_backend"
        ) as mock_default_backend,
    ):
        # Configure mock_serialization to behave like the actual module
        # Provide mock objects for its attributes/enums
        mock_serialization.Encoding.PEM = MagicMock(name="Encoding.PEM_mock")
        mock_serialization.NoEncryption.return_value = MagicMock(name="NoEncryption_mock") # Return a mock instance
        mock_serialization.PrivateFormat.PKCS8 = MagicMock(name="PrivateFormat.PKCS8_mock")
        mock_serialization.PublicFormat.SubjectPublicKeyInfo = MagicMock(name="PublicFormat.SubjectPublicKeyInfo_mock")

        # Mock a private key object and its public_key method
        mock_private_key = MagicMock()
        mock_public_key = MagicMock()
        mock_private_key.public_key.return_value = mock_public_key
        mock_public_key.public_bytes.return_value = MOCK_PUBLIC_KEY_PEM.encode(
            "utf-8"
        )
        mock_private_key.private_bytes.return_value = (
            b"-----BEGIN PRIVATE KEY-----MOCK-----END PRIVATE KEY-----"
        )

        mock_generate_private_key.return_value = mock_private_key
        mock_serialization.load_pem_private_key.return_value = mock_private_key # Connect to mock_serialization

        yield {
            "mock_generate_private_key": mock_generate_private_key,
            "mock_serialization": mock_serialization, # Yield the patched serialization module
            "mock_private_key": mock_private_key,
            "mock_public_key": mock_public_key,
        }


@pytest.fixture
def mock_httpx_client():
    """Fixture to mock httpx.Client."""
    with patch("equus_express.client.httpx.Client") as MockClient: # Removed src.
        mock_client_instance = MockClient.return_value
        # Default mock response for success
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "message": "Mocked response",
        }
        mock_response.raise_for_status.return_value = (
            None  # No HTTP errors by default
        )
        mock_client_instance.request.return_value = mock_response
        yield mock_client_instance


@pytest.fixture
def secure_client_no_keys_exist(
    tmp_key_dir, mock_crypto, mock_httpx_client
):
    """SecureAPIClient instance where no keys exist initially."""
    with (
        patch(
            "equus_express.client.os.path.exists",
            side_effect=[False, False],
        ),
        patch("equus_express.client.os.makedirs"),
    ):
        client = SecureAPIClient(
            base_url=TEST_BASE_URL,
            device_id=TEST_DEVICE_ID,
            key_dir=tmp_key_dir,
        )
        yield client


@pytest.fixture
def secure_client_keys_exist(tmp_key_dir, mock_crypto, mock_httpx_client):
    """SecureAPIClient instance where keys already exist."""
    # Simulate files existing
    with open(os.path.join(tmp_key_dir, "device.pem"), "wb") as f:
        f.write(b"dummy private key")
    with open(os.path.join(tmp_key_dir, "device.pub"), "wb") as f:
        f.write(b"dummy public key")

    with patch(
        "equus_express.client.os.path.exists", side_effect=[True, True]
    ):  # First call for private, second for public
        client = SecureAPIClient(
            base_url=TEST_BASE_URL,
            device_id=TEST_DEVICE_ID,
            key_dir=tmp_key_dir,
        )
        yield client


@pytest.fixture
def mock_device_agent_dependencies():
    """Mocks system calls for DeviceAgent's telemetry collection."""
    # Define a fixed datetime for consistent assertions
    fixed_now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    with (
        patch("equus_express.client.SecureAPIClient") as MockClient,
        patch("equus_express.client.os.path.exists", return_value=True),
        patch(
            "equus_express.client.socket.gethostname",
            return_value=TEST_DEVICE_ID,
        ),
        patch("equus_express.client.time.sleep") as mock_sleep,
        patch("equus_express.client.datetime") as mock_datetime, # Patch datetime
        patch(
            "equus_express.client.SecureAPIClient.send_telemetry",
            return_value={"status": "success"},
        ),
        patch(
            "equus_express.client.SecureAPIClient.update_status",
            return_value={"status": "success"},
        ),
        patch(
            "equus_express.client.SecureAPIClient.test_connection",
            return_value=True,
        ),
        patch(
            "equus_express.client.SecureAPIClient.get_device_info",
            return_value={"device_id": TEST_DEVICE_ID},
        ),
        patch(
            "equus_express.client.SecureAPIClient.register_device",
            return_value={"status": "success"},
        ),
    ):
        # Configure mock_datetime
        mock_datetime.now.return_value = fixed_now
        mock_datetime.timezone = timezone # Ensure timezone.utc is accessible on the mock

        mock_client_instance = MockClient.return_value
        # Configure the mock client methods that DeviceAgent calls
        mock_client_instance.send_telemetry.return_value = {"status": "success"}
        mock_client_instance.update_status.return_value = {"status": "success"}
        mock_client_instance.test_connection.return_value = True

        # Mock internal telemetry collection methods
        with (
            patch(
                "equus_express.client.DeviceAgent._get_uptime",
                return_value=100.0,
            ),
            patch(
                "equus_express.client.DeviceAgent._get_cpu_usage",
                return_value=25.0,
            ),
            patch(
                "equus_express.client.DeviceAgent._get_memory_usage",
                return_value={"total": 1000, "percent": 50},
            ),
            patch(
                "equus_express.client.DeviceAgent._get_disk_usage",
                return_value={"total": 1000, "percent": 70},
            ),
            patch(
                "equus_express.client.DeviceAgent._get_temperature",
                return_value=45.0,
            ),
            patch(
                "equus_express.client.DeviceAgent._get_ip_address",
                return_value="192.168.1.100",
            ),
        ):

            yield {
                "MockClient": MockClient,
                "mock_client_instance": mock_client_instance,
                "mock_sleep": mock_sleep,
                "fixed_now_iso": fixed_now.isoformat(), # Provide the fixed isoformat string for assertions
            }


# --- SecureAPIClient Tests ---


def test_secure_client_initialization_generates_keys(
    secure_client_no_keys_exist, mock_crypto, mock_httpx_client
):
    """Test that SecureAPIClient generates keys if they don't exist."""
    client = secure_client_no_keys_exist
    assert client.private_key is not None
    assert client.public_key_pem == MOCK_PUBLIC_KEY_PEM.strip()
    mock_crypto["mock_generate_private_key"].assert_called_once()
    mock_crypto["mock_serialization"].load_pem_private_key.assert_not_called() # Updated mock assertion


def test_secure_client_initialization_loads_keys(
    secure_client_keys_exist, mock_crypto, mock_httpx_client
):
    """Test that SecureAPIClient loads keys if they exist."""
    client = secure_client_keys_exist
    assert client.private_key is not None
    # For loaded keys, the public_key_pem would be derived from the loaded private key's public part
    # Mock crypto ensures a consistent public key PEM is returned when .public_bytes is called.
    assert client.public_key_pem == MOCK_PUBLIC_KEY_PEM.strip()
    mock_crypto["mock_generate_private_key"].assert_not_called()
    mock_crypto["mock_serialization"].load_pem_private_key.assert_called_once() # Updated mock assertion


def test_secure_client_make_request_success(
    mock_httpx_client, secure_client_keys_exist # Changed fixture name
):
    """Test _make_request for a successful response."""
    response_data = {"key": "value"}
    mock_httpx_client.request.return_value.json.return_value = response_data # Changed mock_requests_session to mock_httpx_client
    mock_httpx_client.request.return_value.status_code = 200 # Changed mock_requests_session to mock_httpx_client

    client = secure_client_keys_exist
    result = client.get("/test")

    mock_httpx_client.request.assert_called_with( # Changed mock_requests_session to mock_httpx_client
        "GET", f"{TEST_BASE_URL}/test"
    )
    assert result == response_data


def test_secure_client_make_request_http_error(
    mock_httpx_client, secure_client_keys_exist # Changed fixture name
):
    """Test _make_request handles HTTP errors."""
    mock_httpx_client.request.return_value.status_code = 404 # Changed mock_requests_session to mock_httpx_client
    mock_httpx_client.request.return_value.raise_for_status.side_effect = ( # Changed mock_requests_session to mock_httpx_client
        httpx.HTTPStatusError("Not Found", request=httpx.Request("GET", "http://test.com"), response=httpx.Response(404)) # Changed exception type and added required args
    )

    client = secure_client_keys_exist
    with pytest.raises(httpx.HTTPStatusError): # Changed exception type
        client.get("/nonexistent")


def test_secure_client_register_device(
    mock_httpx_client, secure_client_keys_exist # Changed fixture name
):
    """Test register_device sends correct payload."""
    client = secure_client_keys_exist
    client.register_device()
    mock_httpx_client.request.assert_called_with( # Changed mock_requests_session to mock_httpx_client
        "POST",
        f"{TEST_BASE_URL}/api/register",
        json={
            "device_id": TEST_DEVICE_ID,
            "public_key": MOCK_PUBLIC_KEY_PEM.strip(),
        },
    )


def test_secure_client_health_check(
    mock_httpx_client, secure_client_keys_exist # Changed fixture name
):
    """Test health_check calls the correct endpoint."""
    client = secure_client_keys_exist
    client.health_check()
    mock_httpx_client.request.assert_called_with( # Changed mock_requests_session to mock_httpx_client
        "GET", f"{TEST_BASE_URL}/health"
    )


def test_secure_client_send_telemetry(
    mock_httpx_client, secure_client_keys_exist # Changed fixture name
):
    """Test send_telemetry sends correct payload."""
    client = secure_client_keys_exist
    test_data = {"temp": 25, "hum": 70}
    with patch("equus_express.client.datetime") as mock_dt: # Removed src.
        mock_dt.now.return_value = datetime(
            2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc
        )
        mock_dt.timezone = timezone  # Attach timezone for `timezone.utc` access
        client.send_telemetry(test_data)
    mock_httpx_client.request.assert_called_with(
        "POST",
        f"{TEST_BASE_URL}/api/telemetry",
        json={
            "device_id": TEST_DEVICE_ID,
            "timestamp": "2025-01-01T12:00:00+00:00",
            "data": test_data,
        },
    )


def test_secure_client_get_configuration(
    mock_httpx_client, secure_client_keys_exist # Changed fixture name
):
    """Test get_configuration calls the correct endpoint."""
    client = secure_client_keys_exist
    client.get_configuration()
    mock_httpx_client.request.assert_called_with( # Changed mock_requests_session to mock_httpx_client
        "GET", f"{TEST_BASE_URL}/api/device/{TEST_DEVICE_ID}/config"
    )


def test_secure_client_update_status(
    mock_httpx_client, secure_client_keys_exist # Changed fixture name
):
    """Test update_status sends correct payload."""
    client = secure_client_keys_exist
    test_status = "idle"
    test_details = {"battery": "90%"}
    with patch("equus_express.client.datetime") as mock_dt: # Removed src.
        mock_dt.now.return_value = datetime(
            2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc
        )
        mock_dt.timezone = timezone  # Attach timezone for `timezone.utc` access
        client.update_status(test_status, test_details)
    mock_httpx_client.request.assert_called_with(
        "POST",
        f"{TEST_BASE_URL}/api/device/status",
        json={
            "device_id": TEST_DEVICE_ID,
            "status": test_status,
            "timestamp": "2025-01-01T12:00:00+00:00",
            "details": test_details,
        },
    )


def test_secure_client_test_connection_success(
    mock_httpx_client, secure_client_keys_exist, mock_device_agent_dependencies # Added mock_device_agent_dependencies to ensure datetime is mocked
):
    """Test test_connection success path."""
    client = secure_client_keys_exist
    # Ensure nested calls return success
    mock_httpx_client.request.return_value.json.side_effect = [
        {"status": "healthy"},  # For health_check
        {"status": "success", "message": "registered"},  # For register_device
        {"device_id": TEST_DEVICE_ID},  # For get_device_info
    ]
    assert client.test_connection() is True


def test_secure_client_test_connection_failure(
    mock_httpx_client, secure_client_keys_exist, mock_device_agent_dependencies # Added mock_device_agent_dependencies to ensure datetime is mocked
):
    """Test test_connection failure path."""
    client = secure_client_keys_exist
    mock_httpx_client.request.return_value.json.side_effect = Exception(
        "Connection failed"
    )
    assert client.test_connection() is False


# --- DeviceAgent Tests ---


def test_device_agent_start_success(mock_device_agent_dependencies):
    """Test DeviceAgent starts successfully."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    fixed_now_iso = mock_device_agent_dependencies["fixed_now_iso"] # Get the fixed timestamp
    agent = DeviceAgent(mock_client)
    assert agent.start() is True
    mock_client.test_connection.assert_called_once()
    mock_client.update_status.assert_called_with(
        "online",
        {
            "startup_time": fixed_now_iso, # Use the fixed timestamp for assertion
            "version": "1.0",
        },
    )
    assert agent.running is True


def test_device_agent_start_failure(mock_device_agent_dependencies):
    """Test DeviceAgent handles connection failure on start."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_client.test_connection.return_value = False
    agent = DeviceAgent(mock_client)
    assert agent.start() is False
    assert agent.running is False # This assertion was failing because agent.start() sets it to True initially. It should remain False if start() fails.


def test_device_agent_stop(mock_device_agent_dependencies):
    """Test DeviceAgent stops correctly and sends offline status."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    fixed_now_iso = mock_device_agent_dependencies["fixed_now_iso"] # Get the fixed timestamp
    agent = DeviceAgent(mock_client)
    agent.running = True  # Manually set to running for stop test
    agent.stop()
    assert agent.running is False
    mock_client.update_status.assert_called_with(
        "offline", {"shutdown_time": fixed_now_iso} # Use the fixed timestamp for assertion
    )


def test_device_agent_run_telemetry_loop(mock_device_agent_dependencies):
    """Test telemetry loop sends data at intervals."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_sleep = mock_device_agent_dependencies["mock_sleep"]
    agent = DeviceAgent(mock_client)

    agent.running = True
    # Run loop briefly for 2 iterations
    mock_sleep.side_effect = [None, None, KeyboardInterrupt]

    # Mock _collect_telemetry for predictable data
    with patch(
        "equus_express.client.DeviceAgent._collect_telemetry",
        return_value={"mock_data": 123},
    ):
        # The loop handles KeyboardInterrupt internally, so we don't expect it to be re-raised.
        # The side_effect of mock_sleep will cause the loop to terminate.
        agent.run_telemetry_loop(interval=1)

    assert mock_client.send_telemetry.call_count == 2
    mock_sleep.assert_any_call(1)  # Ensure sleep was called with interval
    assert agent.running is True # The loop exits, but the 'running' flag is not changed by the loop itself.


def test_device_agent_collect_telemetry(mock_device_agent_dependencies):
    """Test _collect_telemetry aggregates data from helper methods."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client)

    telemetry = agent._collect_telemetry()

    assert "system" in telemetry
    assert "network" in telemetry
    assert "application" in telemetry
    assert telemetry["system"]["uptime"] == 100.0
    assert telemetry["system"]["cpu_usage"] == 25.0
    assert telemetry["system"]["memory_usage"]["percent"] == 50
    assert telemetry["system"]["disk_usage"]["percent"] == 70
    assert telemetry["system"]["temperature"] == 45.0
    assert telemetry["network"]["ip_address"] == "192.168.1.100"


def test_device_agent_collect_telemetry_error_handling(
    mock_device_agent_dependencies,
):
    """Test _collect_telemetry handles errors in helper methods."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client)

    # Make _get_uptime raise an error
    with patch(
        "equus_express.client.DeviceAgent._get_uptime", # Removed src.
        side_effect=Exception("Uptime error"),
    ):
        telemetry = agent._collect_telemetry()
        assert (
            "error" in telemetry
        )  # The _collect_telemetry catches and returns error string
        assert "Uptime error" in telemetry["error"]
