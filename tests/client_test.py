import pytest
from unittest.mock import patch, MagicMock, mock_open
from datetime import datetime, timezone
import httpx
# Import the classes to be tested
from equus_express.client import SecureAPIClient, DeviceAgent, PsutilNotInstalled # Added PsutilNotInstalled
import os
import socket
# Removed psutil import as it's not required for unit tests;
# its behavior is mocked or tested when it's None in client.py


# Constants for testing
TEST_BASE_URL = "https://mock-server"
TEST_DEVICE_ID = "test_client_device"
MOCK_PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsdfadsfadsfasdfasdf\n-----END PUBLIC KEY-----\n"
MOCK_PRIVATE_KEY_PEM = (
    b"-----BEGIN PRIVATE KEY-----MOCK_PRIVATE_KEY-----END PRIVATE KEY-----"
)
# Generate a random IP address in a private range (e.g., 192.168.X.Y) using cryptographically strong randomness
# os.urandom(1) generates 1 random byte (0-255)
MOCK_IP_ADDRESS = f"192.168.{int.from_bytes(os.urandom(1), 'big')}.{int.from_bytes(os.urandom(1), 'big') % 254 + 1}"


@pytest.fixture
def tmp_key_dir(tmp_path):
    """Fixture to create a temporary directory for client keys and clean up after."""
    key_dir = tmp_path / "test_keys"
    # No need to create directory, client.py's os.makedirs will be mocked
    yield str(key_dir)


@pytest.fixture
def mock_crypto():
    """Fixture to mock cryptography functions and file I/O for key generation/loading."""
    m_open = mock_open()

    # Configure mock_private_key and mock_public_key objects
    mock_private_key = MagicMock()
    mock_public_key = MagicMock()
    mock_private_key.public_key.return_value = mock_public_key
    mock_public_key.public_bytes.return_value = MOCK_PUBLIC_KEY_PEM.encode(
        "utf-8"
    )
    mock_private_key.private_bytes.return_value = MOCK_PRIVATE_KEY_PEM

    # Configure mock_open for reading (for secure_client_keys_exist scenario)
    # The read content depends on the order of reads. The client reads private then public.
    m_open.return_value.__enter__.return_value.read.side_effect = [
        MOCK_PRIVATE_KEY_PEM,
        MOCK_PUBLIC_KEY_PEM.encode("utf-8"),
    ]

    with (
        patch(
            "equus_express.client.rsa.generate_private_key"
        ) as mock_generate_private_key,
        patch("equus_express.client.serialization") as mock_serialization,
        patch("equus_express.client.default_backend"),
        patch("equus_express.client.open", m_open),
        patch("equus_express.client.os.path.exists") as mock_os_path_exists,
        patch("equus_express.client.os.makedirs") as mock_os_makedirs,
    ):
        # Configure mock_serialization to behave like the actual module
        mock_serialization.Encoding.PEM = MagicMock(name="Encoding.PEM_mock")
        mock_serialization.NoEncryption.return_value = MagicMock(
            name="NoEncryption_mock"
        )
        mock_serialization.PrivateFormat.PKCS8 = MagicMock(
            name="PrivateFormat.PKCS8_mock"
        )
        mock_serialization.PublicFormat.SubjectPublicKeyInfo = MagicMock(
            name="PublicFormat.SubjectPublicKeyInfo_mock"
        )

        mock_generate_private_key.return_value = mock_private_key
        mock_serialization.load_pem_private_key.return_value = mock_private_key

        yield {
            "mock_generate_private_key": mock_generate_private_key,
            "mock_serialization": mock_serialization,
            "mock_private_key": mock_private_key,
            "mock_public_key": mock_public_key,
            "mock_open": m_open,
            "mock_os_path_exists": mock_os_path_exists,
            "mock_os_makedirs": mock_os_makedirs,
        }


@pytest.fixture
def mock_httpx_client():
    """Fixture to mock httpx.Client."""
    with patch("equus_express.client.httpx.Client") as MockClient:
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
def secure_client_no_keys_exist(tmp_key_dir, mock_crypto, mock_httpx_client):
    """SecureAPIClient instance where no keys exist initially, simulating key generation."""
    # Configure mock_os_path_exists to return False for both key files checks
    mock_crypto["mock_os_path_exists"].side_effect = [False, False]

    # os.makedirs is already patched in mock_crypto fixture, and client.py now calls it.
    client = SecureAPIClient(
        base_url=TEST_BASE_URL,
        device_id=TEST_DEVICE_ID,
        key_dir=tmp_key_dir,  # Ensure tmp_key_dir is passed
    )
    yield client
    # Assert that os.makedirs was called for the key_dir
    mock_crypto["mock_os_makedirs"].assert_called_with(
        tmp_key_dir, exist_ok=True
    )
    # Assert that keys were attempted to be written via mocked open
    assert mock_crypto["mock_open"].call_args_list[0].args[0] == os.path.join(
        tmp_key_dir, "device.pem"
    )
    assert mock_crypto["mock_open"].call_args_list[1].args[0] == os.path.join(
        tmp_key_dir, "device.pub"
    )


@pytest.fixture
def secure_client_keys_exist(tmp_key_dir, mock_crypto, mock_httpx_client):
    """SecureAPIClient instance where keys already exist, simulating key loading."""
    # Configure mock_os_path_exists to return True for both key files checks
    mock_crypto["mock_os_path_exists"].side_effect = [True, True]

    client = SecureAPIClient(
        base_url=TEST_BASE_URL,
        device_id=TEST_DEVICE_ID,
        key_dir=tmp_key_dir,
    )
    yield client
    # Assert that os.makedirs was called for the key_dir (even if it exists)
    mock_crypto["mock_os_makedirs"].assert_called_with(
        tmp_key_dir, exist_ok=True
    )
    # Assert that keys were attempted to be read via mocked open
    assert mock_crypto["mock_open"].call_args_list[0].args[0] == os.path.join(
        tmp_key_dir, "device.pem"
    )
    assert mock_crypto["mock_open"].call_args_list[1].args[0] == os.path.join(
        tmp_key_dir, "device.pub"
    )
    # Verify load_pem_private_key was called, indicating successful key loading path
    mock_crypto["mock_serialization"].load_pem_private_key.assert_called_once()


def test_secure_client_register_device_no_public_key(mock_httpx_client, tmp_key_dir):
    """Test register_device raises RuntimeError if public_key_pem is not set."""
    # Create a client that hasn't loaded/generated keys (e.g., mock _load_or_generate_keys to do nothing)
    with patch("equus_express.client.SecureAPIClient._load_or_generate_keys"):
        client = SecureAPIClient(base_url=TEST_BASE_URL, device_id=TEST_DEVICE_ID, key_dir=tmp_key_dir)
        client.public_key_pem = None # Explicitly ensure public_key_pem is None

        with pytest.raises(RuntimeError, match="Public key not available for registration."):
            client.register_device()
    mock_httpx_client.request.assert_not_called()


def test_secure_client_register_device_network_error(mock_httpx_client, secure_client_keys_exist):
    """Test register_device handles network/server errors."""
    client = secure_client_keys_exist
    mock_httpx_client.request.side_effect = httpx.RequestError(
        "Network unreachable", request=httpx.Request("POST", TEST_BASE_URL)
    )

    with pytest.raises(httpx.RequestError, match="Network unreachable"):
        client.register_device()
    mock_httpx_client.request.assert_called_once()


@pytest.fixture
def mock_device_agent_dependencies():
    """Mocks system calls and client interactions for DeviceAgent tests."""
    fixed_now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    with (
        patch("equus_express.client.SecureAPIClient") as MockClient,
        patch("equus_express.client.os.path.exists", return_value=True),
        patch("equus_express.client.socket.gethostname", return_value=TEST_DEVICE_ID),
        patch("equus_express.client.time.sleep") as mock_sleep,
        patch("equus_express.client.datetime") as mock_datetime,
    ):
        mock_client_instance = MockClient.return_value
        # Configure the mock client methods that DeviceAgent calls by default for success paths
        mock_client_instance.send_telemetry.return_value = {"status": "success"}
        mock_client_instance.update_status.return_value = {"status": "success"}
        mock_client_instance.test_connection.return_value = True
        mock_client_instance.get_device_info.return_value = {"device_id": TEST_DEVICE_ID}
        mock_client_instance.register_device.return_value = {"status": "success"}

        mock_datetime.now.return_value = fixed_now
        mock_datetime.timezone = timezone

        yield {
            "MockClient": MockClient,
            "mock_client_instance": mock_client_instance,
            "mock_sleep": mock_sleep,
            "fixed_now_iso": fixed_now.isoformat(),
            "mock_datetime": mock_datetime, # Provide mock_datetime for specific tests
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
    mock_crypto[
        "mock_serialization"
    ].load_pem_private_key.assert_not_called()  # Updated mock assertion


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
    mock_crypto[
        "mock_serialization"
    ].load_pem_private_key.assert_called_once()


def test_secure_client_init_os_error(tmp_key_dir, mock_crypto, mock_httpx_client):
    """Test that SecureAPIClient initialization handles OSError during key operations."""
    # Simulate an OSError during os.makedirs
    mock_crypto["mock_os_makedirs"].side_effect = OSError("Disk full")

    with pytest.raises(RuntimeError, match="Failed to initialize client keys"):
        SecureAPIClient(
            base_url=TEST_BASE_URL,
            device_id=TEST_DEVICE_ID,
            key_dir=tmp_key_dir,
        )
    mock_crypto["mock_os_makedirs"].assert_called_once_with(tmp_key_dir, exist_ok=True)


def test_secure_client_make_request_success(
    mock_httpx_client, secure_client_keys_exist
):
    """Test _make_request for a successful response."""
    response_data = {"key": "value"}
    mock_httpx_client.request.return_value.json.return_value = response_data
    mock_httpx_client.request.return_value.status_code = 200

    client = secure_client_keys_exist
    result = client.get("/test")

    mock_httpx_client.request.assert_called_with(
        "GET", f"{TEST_BASE_URL}/test"
    )
    assert result == response_data


def test_secure_client_make_request_non_json_response(
    mock_httpx_client, secure_client_keys_exist
):
    """Test _make_request handles non-JSON successful responses."""
    mock_httpx_client.request.return_value.status_code = 200
    mock_httpx_client.request.return_value.json.side_effect = httpx.ReadError("Invalid JSON")
    mock_httpx_client.request.return_value.text = "OK"

    client = secure_client_keys_exist
    with pytest.raises(ConnectionError, match="Request to server failed: Invalid JSON"):
        client.get("/plaintext")


def test_secure_client_make_request_401_error(
    mock_httpx_client, secure_client_keys_exist
):
    """Test _make_request handles 401 Unauthorized HTTP errors."""
    mock_httpx_client.request.return_value.status_code = 401
    mock_httpx_client.request.return_value.raise_for_status.side_effect = httpx.HTTPStatusError(
        "Unauthorized",
        request=httpx.Request("GET", "https://test.com"),
        response=httpx.Response(401, request=httpx.Request("GET", "https://test.com")),
    )

    client = secure_client_keys_exist
    with pytest.raises(PermissionError, match="Authentication failed"):
        client.get("/protected")


def test_secure_client_make_request_403_error(
    mock_httpx_client, secure_client_keys_exist
):
    """Test _make_request handles 403 Forbidden HTTP errors."""
    mock_httpx_client.request.return_value.status_code = 403
    mock_httpx_client.request.return_value.raise_for_status.side_effect = httpx.HTTPStatusError(
        "Forbidden",
        request=httpx.Request("GET", "https://test.com"),
        response=httpx.Response(403, request=httpx.Request("GET", "https://test.com")),
    )

    client = secure_client_keys_exist
    with pytest.raises(PermissionError, match="Access denied"):
        client.get("/forbidden")


def test_secure_client_make_request_http_error(
    mock_httpx_client, secure_client_keys_exist  # Changed fixture name
):
    """Test _make_request handles HTTP errors."""
    mock_httpx_client.request.return_value.status_code = (
        404  # Changed mock_requests_session to mock_httpx_client
    )
    mock_httpx_client.request.return_value.raise_for_status.side_effect = httpx.HTTPStatusError(  # Changed mock_requests_session to mock_httpx_client
        "Not Found",
        request=httpx.Request("GET", "https://test.com"),
        response=httpx.Response(404),
    )  # Changed exception type and added required args

    client = secure_client_keys_exist
    with pytest.raises(httpx.HTTPStatusError):  # Changed exception type
        client.get("/nonexistent")


def test_secure_client_register_device(
    mock_httpx_client, secure_client_keys_exist  # Changed fixture name
):
    """Test register_device sends correct payload."""
    client = secure_client_keys_exist
    client.register_device()
    mock_httpx_client.request.assert_called_with(
        "POST",
        f"{TEST_BASE_URL}/api/register",
        data=None,  # Added data=None to match actual call
        json={
            "device_id": TEST_DEVICE_ID,
            "public_key": MOCK_PUBLIC_KEY_PEM.strip(),
        },
    )


def test_secure_client_health_check(
    mock_httpx_client, secure_client_keys_exist  # Changed fixture name
):
    """Test health_check calls the correct endpoint."""
    client = secure_client_keys_exist
    client.health_check()
    mock_httpx_client.request.assert_called_with(  # Changed mock_requests_session to mock_httpx_client
        "GET", f"{TEST_BASE_URL}/health"
    )


def test_secure_client_send_telemetry(
    mock_httpx_client, secure_client_keys_exist  # Changed fixture name
):
    """Test send_telemetry sends correct payload."""
    client = secure_client_keys_exist
    test_data = {"temp": 25, "hum": 70}
    with patch("equus_express.client.datetime") as mock_dt:  # Removed src.
        mock_dt.now.return_value = datetime(
            2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc
        )
        mock_dt.timezone = (
            timezone  # Attach timezone for `timezone.utc` access
        )
        client.send_telemetry(test_data)
    mock_httpx_client.request.assert_called_with(
        "POST",
        f"{TEST_BASE_URL}/api/telemetry",
        data=None,  # Added data=None to match actual call
        json={
            "device_id": TEST_DEVICE_ID,
            "timestamp": "2025-01-01T12:00:00+00:00",
            "data": test_data,
        },
    )


def test_secure_client_get_configuration(
    mock_httpx_client, secure_client_keys_exist  # Changed fixture name
):
    """Test get_configuration calls the correct endpoint."""
    client = secure_client_keys_exist
    client.get_configuration()
    mock_httpx_client.request.assert_called_with(  # Changed mock_requests_session to mock_httpx_client
        "GET", f"{TEST_BASE_URL}/api/device/{TEST_DEVICE_ID}/config"
    )


def test_secure_client_update_status(
    mock_httpx_client, secure_client_keys_exist  # Changed fixture name
):
    """Test update_status sends correct payload."""
    client = secure_client_keys_exist
    test_status = "idle"
    test_details = {"battery": "90%"}
    with patch("equus_express.client.datetime") as mock_dt:  # Removed src.
        mock_dt.now.return_value = datetime(
            2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc
        )
        mock_dt.timezone = (
            timezone  # Attach timezone for `timezone.utc` access
        )
        client.update_status(test_status, test_details)
    mock_httpx_client.request.assert_called_with(
        "POST",
        f"{TEST_BASE_URL}/api/device/status",
        data=None,  # Added data=None to match actual call
        json={
            "device_id": TEST_DEVICE_ID,
            "status": test_status,
            "timestamp": "2025-01-01T12:00:00+00:00",
            "details": test_details,
        },
    )


def test_secure_client_test_connection_success(
    mock_httpx_client,
    secure_client_keys_exist,
    mock_device_agent_dependencies,  # Added mock_device_agent_dependencies to ensure datetime is mocked
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
    mock_httpx_client,
    secure_client_keys_exist,
    mock_device_agent_dependencies,
):
    """Test test_connection failure path."""
    client = secure_client_keys_exist
    # Make the mock raise a specific httpx error that test_connection catches
    mock_httpx_client.request.side_effect = httpx.ConnectError(
        "Connection failed", request=httpx.Request("GET", TEST_BASE_URL)
    )
    assert client.test_connection() is False


def test_secure_client_test_connection_get_device_info_failure(
    mock_httpx_client,
    secure_client_keys_exist,
    mock_device_agent_dependencies,
):
    """Test test_connection continues if get_device_info fails, but logs a warning."""
    client = secure_client_keys_exist
    # Mock health_check and register_device to succeed
    mock_httpx_client.request.side_effect = [
        MagicMock(status_code=200, json=lambda: {"status": "healthy"}), # for health_check
        MagicMock(status_code=200, json=lambda: {"status": "success", "message": "registered"}), # for register_device
        httpx.RequestError("Device info failed", request=httpx.Request("GET", TEST_BASE_URL)), # for get_device_info
    ]

    with patch('equus_express.client.logger.warning') as mock_warning:
        assert client.test_connection() is True # Should still return True overall
        mock_warning.assert_called_once_with(
            f"Device info endpoint failed (this might be expected if server requires stronger auth post-registration): Device info failed"
        )


# --- DeviceAgent Tests ---


def test_device_agent_start_success(mock_device_agent_dependencies):
    """Test DeviceAgent starts successfully."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    fixed_now_iso = mock_device_agent_dependencies[
        "fixed_now_iso"
    ]  # Get the fixed timestamp
    agent = DeviceAgent(mock_client)
    assert agent.start() is True
    mock_client.test_connection.assert_called_once()
    mock_client.update_status.assert_called_with(
        "online",
        {
            "startup_time": fixed_now_iso,  # Use the fixed timestamp for assertion
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
    assert agent.running is False


def test_device_agent_start_update_status_failure(mock_device_agent_dependencies):
    """Test DeviceAgent handles failure to send initial 'online' status."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_client.test_connection.return_value = True
    mock_client.update_status.side_effect = httpx.RequestError(
        "Status update failed", request=httpx.Request("POST", TEST_BASE_URL)
    )
    agent = DeviceAgent(mock_client)
    with patch('equus_express.client.logger.warning') as mock_warning:
        assert agent.start() is True # Still starts, but logs warning
        mock_warning.assert_called_once_with(
            "Failed to send initial 'online' status: Status update failed"
        )
    assert agent.running is True


def test_device_agent_stop(mock_device_agent_dependencies):
    """Test DeviceAgent stops correctly and sends offline status."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    fixed_now_iso = mock_device_agent_dependencies[
        "fixed_now_iso"
    ]  # Get the fixed timestamp
    agent = DeviceAgent(mock_client)
    agent.running = True  # Manually set to running for stop test
    agent.stop()
    assert agent.running is False
    mock_client.update_status.assert_called_with(
        "offline",
        {
            "shutdown_time": fixed_now_iso
        },  # Use the fixed timestamp for assertion
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

    # The loop executes its body THEN sleeps.
    # Iteration 1: send_telemetry, then sleep (returns None)
    # Iteration 2: send_telemetry, then sleep (returns None)
    # Iteration 3: send_telemetry, then sleep (raises KeyboardInterrupt, breaking loop)
    # So, send_telemetry is called 3 times.
    assert mock_client.send_telemetry.call_count == 3
    mock_sleep.assert_any_call(1)
    # The 'running' flag is not changed by the loop itself upon KeyboardInterrupt
    assert agent.running is True


def test_device_agent_run_telemetry_loop_communication_error(mock_device_agent_dependencies):
    """Test telemetry loop handles client communication errors."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_sleep = mock_device_agent_dependencies["mock_sleep"]
    agent = DeviceAgent(mock_client)

    agent.running = True
    mock_sleep.side_effect = [None, KeyboardInterrupt] # Two iterations
    mock_client.send_telemetry.side_effect = [
        httpx.ConnectError("Simulated connection error"),
        None, # Second call succeeds
    ]

    with patch('equus_express.client.logger.error') as mock_error:
        agent.run_telemetry_loop(interval=1)

    mock_error.assert_called_once_with(
        "Telemetry loop communication or data error: Simulated connection error"
    )
    assert mock_client.send_telemetry.call_count == 2 # First call fails, second succeeds
    mock_sleep.assert_called_with(1) # Should sleep after error


def test_device_agent_run_telemetry_loop_unexpected_error(mock_device_agent_dependencies):
    """Test telemetry loop handles unexpected general errors."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_sleep = mock_device_agent_dependencies["mock_sleep"]
    agent = DeviceAgent(mock_client)

    agent.running = True
    mock_sleep.side_effect = [None, KeyboardInterrupt] # Two iterations
    mock_client.send_telemetry.side_effect = [
        ValueError("Unexpected data format"),
        None, # Second call succeeds
    ]

    with patch('equus_express.client.logger.exception') as mock_exception_logger:
        agent.run_telemetry_loop(interval=1)

    mock_exception_logger.assert_called_once()
    assert "An unexpected error occurred in telemetry loop: Unexpected data format" in mock_exception_logger.call_args[0][0]
    assert mock_client.send_telemetry.call_count == 2
    mock_sleep.assert_called_with(1)


def test_device_agent_collect_telemetry(mock_device_agent_dependencies):
    """Test _collect_telemetry aggregates data from helper methods."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client)

    # Patch the individual _get_* methods for this specific test
    with (
        patch("equus_express.client.DeviceAgent._get_uptime", return_value=100.0),
        patch("equus_express.client.DeviceAgent._get_cpu_usage", return_value=25.0),
        patch("equus_express.client.DeviceAgent._get_memory_usage", return_value={"total": 1000, "percent": 50.0}),
        patch("equus_express.client.DeviceAgent._get_disk_usage", return_value={"total": 1000, "percent": 70.0}),
        patch("equus_express.client.DeviceAgent._get_temperature", return_value=45.0),
        patch("equus_express.client.DeviceAgent._get_ip_address", return_value=MOCK_IP_ADDRESS),
    ):
        telemetry = agent._collect_telemetry()

    assert "system" in telemetry
    assert "network" in telemetry
    assert "application" in telemetry
    assert telemetry["system"]["uptime"] == pytest.approx(100.0)
    assert telemetry["system"]["cpu_usage"] == pytest.approx(25.0)
    assert telemetry["system"]["memory_usage"]["percent"] == pytest.approx(50.0)
    assert telemetry["system"]["disk_usage"]["percent"] == pytest.approx(70.0)
    assert telemetry["system"]["temperature"] == pytest.approx(45.0)
    assert telemetry["network"]["ip_address"] == MOCK_IP_ADDRESS


def test_device_agent_collect_telemetry_error_handling_general(
    mock_device_agent_dependencies,
):
    """Test _collect_telemetry handles general errors in helper methods."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client)

    # Make _get_uptime raise an error
    with patch(
        "equus_express.client.DeviceAgent._get_uptime",
        side_effect=OSError("Uptime error"),
    ):
        telemetry = agent._collect_telemetry()
        assert "uptime: Uptime error" in telemetry["application"]["last_error"]
        assert telemetry["system"]["uptime"] == "error"


def test_device_agent_collect_telemetry_cpu_usage_error(mock_device_agent_dependencies):
    """Test _collect_telemetry handles CPU usage errors."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client)
    with patch(
        "equus_express.client.DeviceAgent._get_cpu_usage",
        side_effect=RuntimeError("CPU error"), # Use generic error to avoid psutil dependency
    ):
        telemetry = agent._collect_telemetry()
        assert "cpu_usage: CPU error" in telemetry["application"]["last_error"]
        assert telemetry["system"]["cpu_usage"] == "error"


def test_device_agent_collect_telemetry_cpu_usage_not_implemented(mock_device_agent_dependencies):
    """Test _collect_telemetry handles CPU usage when psutil is not implemented."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client)
    with (
        patch("equus_express.client.psutil", new=None), # Patch psutil to None
        # Mock other methods to ensure they don't produce errors in this specific test
        patch("equus_express.client.DeviceAgent._get_uptime", return_value=100.0),
        patch("equus_express.client.DeviceAgent._get_memory_usage", side_effect=PsutilNotInstalled("psutil library is not available.")),
        patch("equus_express.client.DeviceAgent._get_disk_usage", side_effect=PsutilNotInstalled("psutil library is not available.")),
        patch("equus_express.client.DeviceAgent._get_temperature", return_value=45.0),
        patch("equus_express.client.DeviceAgent._get_ip_address", return_value=MOCK_IP_ADDRESS),
    ):
        telemetry = agent._collect_telemetry()
        assert "cpu_usage: psutil library is not available." in telemetry["application"]["last_error"]
        assert telemetry["system"]["cpu_usage"] == "error"


def test_device_agent_collect_telemetry_memory_usage_error(mock_device_agent_dependencies):
    """Test _collect_telemetry handles memory usage errors."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client)
    with patch(
        "equus_express.client.DeviceAgent._get_memory_usage",
        side_effect=RuntimeError("Memory error"), # Use generic error
    ):
        telemetry = agent._collect_telemetry()
        assert "memory_usage: Memory error" in telemetry["application"]["last_error"]
        assert "error" in telemetry["system"]["memory_usage"]


def test_device_agent_collect_telemetry_memory_usage_not_implemented(mock_device_agent_dependencies):
    """Test _collect_telemetry handles memory usage when psutil is not implemented."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client)
    with (
        patch("equus_express.client.psutil", new=None), # Patch psutil to None
        # Mock other methods to ensure they don't produce errors in this specific test
        patch("equus_express.client.DeviceAgent._get_uptime", return_value=100.0),
        patch("equus_express.client.DeviceAgent._get_cpu_usage", side_effect=PsutilNotInstalled("psutil library is not available.")),
        patch("equus_express.client.DeviceAgent._get_disk_usage", side_effect=PsutilNotInstalled("psutil library is not available.")),
        patch("equus_express.client.DeviceAgent._get_temperature", return_value=45.0),
        patch("equus_express.client.DeviceAgent._get_ip_address", return_value=MOCK_IP_ADDRESS),
    ):
        telemetry = agent._collect_telemetry()
        assert "memory_usage: psutil library is not available." in telemetry["application"]["last_error"]
        assert "error" in telemetry["system"]["memory_usage"]


def test_device_agent_collect_telemetry_disk_usage_error(mock_device_agent_dependencies):
    """Test _collect_telemetry handles disk usage errors."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client)
    with patch(
        "equus_express.client.DeviceAgent._get_disk_usage",
        side_effect=RuntimeError("Disk error"), # Use generic error
    ):
        telemetry = agent._collect_telemetry()
        assert "disk_usage: Disk error" in telemetry["application"]["last_error"]
        assert "error" in telemetry["system"]["disk_usage"]


def test_device_agent_collect_telemetry_disk_usage_not_implemented(mock_device_agent_dependencies):
    """Test _collect_telemetry handles disk usage when psutil is not implemented."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client)
    with (
        patch("equus_express.client.psutil", new=None), # Patch psutil to None
        # Mock other methods to ensure they don't produce errors in this specific test
        patch("equus_express.client.DeviceAgent._get_uptime", return_value=100.0),
        patch("equus_express.client.DeviceAgent._get_cpu_usage", side_effect=PsutilNotInstalled("psutil library is not available.")),
        patch("equus_express.client.DeviceAgent._get_memory_usage", side_effect=PsutilNotInstalled("psutil library is not available.")),
        patch("equus_express.client.DeviceAgent._get_temperature", return_value=45.0),
        patch("equus_express.client.DeviceAgent._get_ip_address", return_value=MOCK_IP_ADDRESS),
    ):
        telemetry = agent._collect_telemetry()
        assert "disk_usage: psutil library is not available." in telemetry["application"]["last_error"]
        assert "error" in telemetry["system"]["disk_usage"]


def test_device_agent_collect_telemetry_temperature_error(mock_device_agent_dependencies):
    """Test _collect_telemetry handles temperature errors."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client)
    with patch(
        "equus_express.client.DeviceAgent._get_temperature",
        side_effect=OSError("Temp file error"),
    ):
        telemetry = agent._collect_telemetry()
        assert "temperature: Temp file error" in telemetry["application"]["last_error"]
        assert telemetry["system"]["temperature"] == "error"


def test_device_agent_collect_telemetry_ip_address_psutil_error(mock_device_agent_dependencies):
    """Test _collect_telemetry handles IP address errors from psutil."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client)
    # To test psutil error without installing psutil, we mock the module itself
    with patch("equus_express.client.psutil") as mock_psutil_module:
        mock_psutil_module.Error = RuntimeError # Define a mock Error type for psutil
        mock_psutil_module.net_if_addrs.side_effect = mock_psutil_module.Error("Net if addrs error")
        with patch(
            "equus_express.client.socket.gethostbyname",
            side_effect=socket.gaierror("Hostname error")
        ):
            telemetry = agent._collect_telemetry()
            assert "ip_address: Hostname error" in telemetry["application"]["last_error"]
            assert telemetry["network"]["ip_address"] == "error"


def test_device_agent_collect_telemetry_ip_address_os_error(mock_device_agent_dependencies):
    """Test _collect_telemetry handles OSError during IP address retrieval from hostname."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client)
    with patch(
        "equus_express.client.socket.gethostbyname",
        side_effect=OSError("OS error during hostname resolution"),
    ):
        telemetry = agent._collect_telemetry()
        assert "ip_address: OS error during hostname resolution" in telemetry["application"]["last_error"]
        assert telemetry["network"]["ip_address"] == "error"


def test_device_agent_collect_telemetry_ip_address_socket_error(mock_device_agent_dependencies):
    """Test _collect_telemetry handles IP address errors from socket fallback."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client)
    # To test psutil error without installing psutil, we mock the module itself
    with patch("equus_express.client.psutil") as mock_psutil_module:
        mock_psutil_module.Error = RuntimeError # Define a mock Error type for psutil
        mock_psutil_module.net_if_addrs.side_effect = mock_psutil_module.Error("Simulate psutil not finding IP")
        with patch(
            "equus_express.client.socket.gethostbyname",
            side_effect=socket.gaierror("gethostbyname error"),
        ):
            telemetry = agent._collect_telemetry()
            assert "ip_address: gethostbyname error" in telemetry["application"]["last_error"]
            assert telemetry["network"]["ip_address"] == "error"
