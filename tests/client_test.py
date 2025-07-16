import pytest
from unittest.mock import patch, MagicMock, mock_open
from datetime import datetime, timezone
import httpx
# Import the classes to be tested
from equus_express.edge_device_controller import SecureAPIClient, DeviceAgent, PsutilNotInstalled, SMBusNotAvailable
import os
import socket
import logging # Import logging for caplog
import tempfile # Added for NamedTemporaryFile
import sys # Import sys for main function tests
import asyncio # For async tests
import json # For NATS command handling tests
import platform # Import platform module

# Constants for testing
TEST_BASE_URL = "https://mock-server"
TEST_DEVICE_ID = "test_client_device" # Moved definition before first usage

# Dummy Ed25519 keys for mocking
# These are not real keys, just placeholders matching format
MOCK_ED25519_PRIVATE_KEY_PEM = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIBAQEB...DUMMY_ED25519_PRIVATE_KEY...\n-----END PRIVATE KEY-----\n"
MOCK_ED25519_PUBLIC_KEY_OPENSSH = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBAQEB...DUMMY_ED25519_PUBLIC_KEY...\n"
MOCK_DEVICE_ID_CONTENT = TEST_DEVICE_ID.encode('utf-8')

MOCK_IP_ADDRESS = f"192.168.{int.from_bytes(os.urandom(1), 'big')}.{int.from_bytes(os.urandom(1), 'big') % 254 + 1}"


@pytest.fixture
def tmp_key_dir(tmp_path):
    """Fixture to create a temporary directory for client keys and clean up after."""
    key_dir = tmp_path / "test_keys"
    yield str(key_dir)


@pytest.fixture
def mock_crypto():
    """Fixture to mock cryptography functions and file I/O for key generation/loading."""
    m_open = mock_open()

    # Configure mock_private_key and mock_public_key objects
    mock_private_key = MagicMock()
    mock_public_key = MagicMock()

    # Mock methods for Ed25519PrivateKey
    mock_private_key.public_key.return_value = mock_public_key
    mock_private_key.private_bytes.return_value = MOCK_ED25519_PRIVATE_KEY_PEM
    mock_private_key.sign.return_value = b"mock_signature" # Mock the sign method

    # Mock methods for Ed25519PublicKey (VerifyKey)
    mock_public_key.public_bytes.return_value = MOCK_ED25519_PUBLIC_KEY_OPENSSH

    with (
        patch("equus_express.edge_device_controller.ed25519.Ed25519PrivateKey.generate") as mock_generate_private_key,
        patch("equus_express.edge_device_controller.serialization") as mock_serialization,
        patch("equus_express.edge_device_controller.default_backend"),
        patch("equus_express.edge_device_controller.open", m_open),
        patch("equus_express.edge_device_controller.os.path.exists") as mock_os_path_exists,
        patch("equus_express.edge_device_controller.os.makedirs") as mock_os_makedirs,
        patch("equus_express.edge_device_controller.Hash"), # Mock Hash for device_id generation
        patch("equus_express.edge_device_controller.SHA256"), # Mock SHA2556 for device_id generation
    ):
        # Configure mock_serialization to behave like the actual module
        mock_serialization.Encoding.PEM = MagicMock(name="Encoding.PEM_mock")
        mock_serialization.Encoding.OpenSSH = MagicMock(name="Encoding.OpenSSH_mock")
        mock_serialization.Encoding.Raw = MagicMock(name="Encoding.Raw_mock")
        mock_serialization.NoEncryption.return_value = MagicMock(name="NoEncryption_mock")
        mock_serialization.PrivateFormat.PKCS8 = MagicMock(name="PrivateFormat.PKCS8_mock")
        mock_serialization.PublicFormat.OpenSSH = MagicMock(name="PublicFormat.OpenSSH_mock")
        mock_serialization.PublicFormat.Raw = MagicMock(name="PublicFormat.Raw_mock")

        mock_generate_private_key.return_value = mock_private_key
        mock_serialization.load_pem_private_key.return_value = mock_private_key
        mock_serialization.load_ssh_public_key.return_value = mock_public_key # New mock for loading public key

        # Configure mock_open for reading (for secure_client_keys_exist scenario)
        # The read content depends on the order of reads: private, public, device_id
        m_open.return_value.__enter__.return_value.read.side_effect = [
            MOCK_ED25519_PRIVATE_KEY_PEM,
            MOCK_ED25519_PUBLIC_KEY_OPENSSH,
            MOCK_DEVICE_ID_CONTENT.decode('utf-8'), # device_id is read as string
        ]

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
    with patch("equus_express.edge_device_controller.httpx.Client") as MockClient:
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
def mock_ip_address():
    """Fixture to mock SecureAPIClient._get_ip_address."""
    with patch("equus_express.edge_device_controller.SecureAPIClient._get_ip_address", return_value=MOCK_IP_ADDRESS) as mock_get_ip:
        yield mock_get_ip


@pytest.fixture
def secure_client_no_keys_exist(tmp_key_dir, mock_crypto, mock_httpx_client):
    """SecureAPIClient instance where no keys exist initially, simulating key generation."""
    # Configure mock_os_path_exists to return False for all key files checks
    mock_crypto["mock_os_path_exists"].side_effect = [False, False, False] # private, public, device_id

    client = SecureAPIClient(
        base_url=TEST_BASE_URL,
        device_id=TEST_DEVICE_ID,
        key_dir=tmp_key_dir,
    )
    yield client
    mock_crypto["mock_os_makedirs"].assert_called_with(tmp_key_dir, exist_ok=True)
    # Assert that keys and device_id were attempted to be written via mocked open
    # The order of writes is private_key, public_key, device_id
    assert mock_crypto["mock_open"].call_args_list[0].args[0] == os.path.join(tmp_key_dir, "device_private_key.pem")
    assert mock_crypto["mock_open"].call_args_list[1].args[0] == os.path.join(tmp_key_dir, "device_public_key.pub")
    assert mock_crypto["mock_open"].call_args_list[2].args[0] == os.path.join(tmp_key_dir, "device_id.txt")


@pytest.fixture
def secure_client_keys_exist(tmp_key_dir, mock_crypto, mock_httpx_client):
    """SecureAPIClient instance where keys already exist, simulating key loading."""
    # Configure mock_os_path_exists to return True for all key files checks
    mock_crypto["mock_os_path_exists"].side_effect = [True, True, True] # private, public, device_id

    client = SecureAPIClient(
        base_url=TEST_BASE_URL,
        device_id=TEST_DEVICE_ID,
        key_dir=tmp_key_dir,
    )
    yield client
    mock_crypto["mock_os_makedirs"].assert_called_with(tmp_key_dir, exist_ok=True)
    # Assert that keys and device_id were attempted to be read via mocked open
    # The order of reads is private_key, public_key, device_id
    assert mock_crypto["mock_open"].call_args_list[0].args[0] == os.path.join(tmp_key_dir, "device_private_key.pem")
    assert mock_crypto["mock_open"].call_args_list[1].args[0] == os.path.join(tmp_key_dir, "device_public_key.pub")
    assert mock_crypto["mock_open"].call_args_list[2].args[0] == os.path.join(tmp_key_dir, "device_id.txt")
    # Verify load_pem_private_key and load_ssh_public_key were called
    mock_crypto["mock_serialization"].load_pem_private_key.assert_called_once()
    mock_crypto["mock_serialization"].load_ssh_public_key.assert_called_once()


@pytest.fixture
def mock_device_agent_dependencies():
    """Mocks system calls and client interactions for DeviceAgent tests."""
    with (
        patch("equus_express.edge_device_controller.SecureAPIClient") as MockClient,
        patch("equus_express.edge_device_controller.NATSClient") as MockNATSClient, # New mock for NATSClient
        patch("equus_express.edge_device_controller.os.path.exists", return_value=True),
        patch("equus_express.edge_device_controller.socket.gethostname", return_value=TEST_DEVICE_ID),
        patch("equus_express.edge_device_controller.time.time", return_value=1672531200.0), # Mock time.time()
        patch("equus_express.edge_device_controller.asyncio.sleep") as mock_asyncio_sleep, # Mock asyncio.sleep
    ):
        mock_client_instance = MockClient.return_value
        mock_nats_client_instance = MockNATSClient.return_value

        # Configure the mock client methods that DeviceAgent calls by default for success paths
        mock_client_instance.send_telemetry.return_value = {"status": "success"}
        mock_client_instance.update_status.return_value = {"status": "success"}
        mock_client_instance.register_device.return_value = {"status": "success"}
        mock_client_instance.device_id = TEST_DEVICE_ID # Ensure device_id is set on mock client
        mock_client_instance._get_ip_address.return_value = MOCK_IP_ADDRESS # Mock internal IP method

        # Configure mock NATS client methods
        mock_nats_client_instance.connect.return_value = None
        mock_nats_client_instance.disconnect.return_value = None
        mock_nats_client_instance.publish.return_value = None
        mock_nats_client_instance.subscribe.return_value = MagicMock() # Return a mock subscription ID

        yield {
            "MockClient": MockClient,
            "mock_client_instance": mock_client_instance,
            "MockNATSClient": MockNATSClient,
            "mock_nats_client_instance": mock_nats_client_instance,
            "mock_asyncio_sleep": mock_asyncio_sleep,
        }


# --- SecureAPIClient Tests ---


def test_secure_client_initialization_generates_keys(
    secure_client_no_keys_exist, mock_crypto, mock_httpx_client
):
    """Test that SecureAPIClient generates keys if they don't exist."""
    client = secure_client_no_keys_exist
    assert client.private_key is not None
    assert client.public_key.public_bytes(
        encoding=mock_crypto["mock_serialization"].Encoding.OpenSSH,
        format=mock_crypto["mock_serialization"].PublicFormat.OpenSSH
    ) == MOCK_ED25519_PUBLIC_KEY_OPENSSH
    mock_crypto["mock_generate_private_key"].assert_called_once()
    mock_crypto["mock_serialization"].load_pem_private_key.assert_not_called()


def test_secure_client_initialization_loads_keys(
    secure_client_keys_exist, mock_crypto, mock_httpx_client
):
    """Test that SecureAPIClient loads keys if they exist."""
    client = secure_client_keys_exist
    assert client.private_key is not None
    assert client.public_key.public_bytes(
        encoding=mock_crypto["mock_serialization"].Encoding.OpenSSH,
        format=mock_crypto["mock_serialization"].PublicFormat.OpenSSH
    ) == MOCK_ED25519_PUBLIC_KEY_OPENSSH
    mock_crypto["mock_generate_private_key"].assert_not_called()
    mock_crypto["mock_serialization"].load_pem_private_key.assert_called_once()
    mock_crypto["mock_serialization"].load_ssh_public_key.assert_called_once()


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


def test_secure_client_register_device_no_public_key(mock_httpx_client, tmp_key_dir):
    """Test register_device raises RuntimeError if public_key is not available."""
    with patch("equus_express.edge_device_controller.SecureAPIClient._load_or_generate_keys"):
        client = SecureAPIClient(base_url=TEST_BASE_URL, device_id=TEST_DEVICE_ID, key_dir=tmp_key_dir)
        client.public_key = None # Explicitly ensure public_key is None

        with pytest.raises(RuntimeError, match="Public key not available for registration."):
            client.register_device()
    mock_httpx_client.request.assert_not_called()


def test_secure_client_register_device_network_error(mock_httpx_client, secure_client_keys_exist, mock_ip_address):
    """Test register_device handles network/server errors."""
    client = secure_client_keys_exist
    mock_httpx_client.request.side_effect = httpx.RequestError(
        "Network unreachable", request=httpx.Request("POST", TEST_BASE_URL)
    )

    with pytest.raises(httpx.RequestError, match="Network unreachable"):
        client.register_device()
    mock_httpx_client.request.assert_called_once()
    mock_ip_address.assert_called_once()


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
        "GET", f"{TEST_BASE_URL}/test", headers={"X-Device-ID": TEST_DEVICE_ID, "X-Signature": "mock_signature"}
    )
    assert result.json() == response_data


def test_secure_client_make_request_non_json_response(
    mock_httpx_client, secure_client_keys_exist
):
    """Test _make_request handles non-JSON successful responses."""
    mock_httpx_client.request.return_value.status_code = 200
    mock_httpx_client.request.return_value.json.side_effect = json.JSONDecodeError("Invalid JSON", doc="{}", pos=0)
    mock_httpx_client.request.return_value.text = "OK"

    client = secure_client_keys_exist
    with pytest.raises(json.JSONDecodeError, match="Invalid JSON"):
        client.get("/plaintext").json()


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
    with pytest.raises(httpx.HTTPStatusError):
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
    with pytest.raises(httpx.HTTPStatusError):
        client.get("/forbidden")


def test_secure_client_make_request_http_error(
    mock_httpx_client, secure_client_keys_exist
):
    """Test _make_request handles HTTP errors."""
    mock_httpx_client.request.return_value.status_code = 404
    mock_httpx_client.request.return_value.raise_for_status.side_effect = httpx.HTTPStatusError(
        "Not Found",
        request=httpx.Request("GET", "https://test.com"),
        response=httpx.Response(404),
    )

    client = secure_client_keys_exist
    with pytest.raises(httpx.HTTPStatusError):
        client.get("/nonexistent")


def test_secure_client_register_device(
    mock_httpx_client, secure_client_keys_exist, mock_ip_address
):
    """Test register_device sends correct payload."""
    client = secure_client_keys_exist
    client.register_device()
    mock_httpx_client.request.assert_called_with(
        "POST",
        f"{TEST_BASE_URL}/api/register",
        json={
            "device_id": TEST_DEVICE_ID,
            "public_key": MOCK_ED25519_PUBLIC_KEY_OPENSSH.decode('utf-8').strip(),
            "ip_address": MOCK_IP_ADDRESS
        },
        data=None,
    )
    mock_ip_address.assert_called_once()


def test_secure_client_health_check(
    mock_httpx_client, secure_client_keys_exist
):
    """Test health_check calls the correct endpoint."""
    client = secure_client_keys_exist
    client.health_check()
    mock_httpx_client.request.assert_called_with(
        "GET", f"{TEST_BASE_URL}/health", headers={"X-Device-ID": TEST_DEVICE_ID, "X-Signature": "mock_signature"}
    )


def test_secure_client_send_telemetry(
    mock_httpx_client, secure_client_keys_exist
):
    """Test send_telemetry sends correct payload."""
    client = secure_client_keys_exist
    test_data = {"temp": 25, "hum": 70}
    with patch("equus_express.edge_device_controller.time.time", return_value=1672531200.0): # Jan 1, 2023 00:00:00 UTC
        client.send_telemetry(test_data)
    mock_httpx_client.request.assert_called_with(
        "POST",
        f"{TEST_BASE_URL}/api/telemetry",
        json={
            "device_id": TEST_DEVICE_ID,
            "timestamp": 1672531200, # Expect integer timestamp
            "data": test_data,
        },
        data=None,
        headers={"X-Device-ID": TEST_DEVICE_ID, "X-Signature": "mock_signature"}
    )


def test_secure_client_get_configuration(
    mock_httpx_client, secure_client_keys_exist
):
    """Test get_configuration calls the correct endpoint."""
    client = secure_client_keys_exist
    client.get_configuration()
    mock_httpx_client.request.assert_called_with(
        "GET", f"{TEST_BASE_URL}/api/device/{TEST_DEVICE_ID}/config", headers={"X-Device-ID": TEST_DEVICE_ID, "X-Signature": "mock_signature"}
    )


def test_secure_client_update_status(
    mock_httpx_client, secure_client_keys_exist
):
    """Test update_status sends correct payload."""
    client = secure_client_keys_exist
    test_status = "idle"
    test_details = {"battery": "90%"}
    with patch("equus_express.edge_device_controller.time.time", return_value=1672531200.0): # Jan 1, 2023 00:00:00 UTC
        client.update_status(test_status, test_details)
    mock_httpx_client.request.assert_called_with(
        "POST",
        f"{TEST_BASE_URL}/api/device/status",
        json={
            "device_id": TEST_DEVICE_ID,
            "status": test_status,
            "timestamp": 1672531200, # Expect integer timestamp
            "details": test_details,
        },
        data=None,
        headers={"X-Device-ID": TEST_DEVICE_ID, "X-Signature": "mock_signature"}
    )


def test_secure_client_test_connection_success(
    mock_httpx_client,
    secure_client_keys_exist,
    mock_ip_address, # Added mock_ip_address
):
    """Test test_connection success path."""
    client = secure_client_keys_exist
    # Ensure nested calls return success
    mock_httpx_client.request.return_value.json.side_effect = [
        {"status": "healthy"},  # For health_check
        {"status": "success", "message": "registered"},  # For register_device
        {"device_id": TEST_DEVICE_ID},  # For get_device_info
        {"status": "success"}, # For send_telemetry
    ]
    assert client.test_connection() is True


def test_secure_client_test_connection_failure(
    mock_httpx_client,
    secure_client_keys_exist,
    mock_ip_address, # Added mock_ip_address
):
    """Test test_connection failure path."""
    client = secure_client_keys_exist
    # Make the mock raise a specific httpx error that test_connection catches
    mock_httpx_client.request.side_effect = httpx.ConnectError(
        "Connection failed", request=httpx.Request("POST", TEST_BASE_URL)
    )
    assert client.test_connection() is False


def test_secure_client_test_connection_get_device_info_failure(
    mock_httpx_client,
    secure_client_keys_exist,
    mock_ip_address, # Added mock_ip_address
):
    """Test test_connection fails if get_device_info fails."""
    client = secure_client_keys_exist
    # Mock health_check and register_device to succeed
    mock_httpx_client.request.side_effect = [
        MagicMock(status_code=200, json=lambda: {"status": "healthy"}), # for health_check
        MagicMock(status_code=200, json=lambda: {"status": "success", "message": "registered"}), # for register_device
        httpx.RequestError("Device info failed", request=httpx.Request("GET", TEST_BASE_URL)), # for get_device_info
    ]

    with patch('equus_express.edge_device_controller.logger.error') as mock_error:
        assert client.test_connection() is False  # Should return False
        assert "Failed to get device info: Device info failed" in mock_error.call_args[0][0]


# --- DeviceAgent Tests ---

@pytest.mark.asyncio # Mark as async test
async def test_device_agent_start_success(mock_device_agent_dependencies):
    """Test DeviceAgent starts successfully."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]

    agent = DeviceAgent(mock_client, mock_nats_client)
    await agent.start()

    mock_client.register_device.assert_called_once()
    mock_nats_client.connect.assert_called_once()
    mock_client.update_status.assert_called_with("online", {"message": "Device agent started."})
    mock_nats_client.subscribe.assert_called_once_with(f"commands.{TEST_DEVICE_ID}", agent._handle_command_message)

@pytest.mark.asyncio
async def test_device_agent_start_failure(mock_device_agent_dependencies):
    """Test DeviceAgent handles connection failure on start."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    mock_client.register_device.side_effect = Exception("Registration failed") # Force start to fail

    agent = DeviceAgent(mock_client, mock_nats_client)
    with pytest.raises(Exception, match="Registration failed"): # Expect the exception to propagate
        await agent.start()

    mock_client.register_device.assert_called_once()
    mock_client.update_status.assert_called_with("error", {"message": "Failed to start: Registration failed"})
    mock_nats_client.disconnect.assert_called_once() # Should attempt to stop gracefully

@pytest.mark.asyncio
async def test_device_agent_start_update_status_failure(mock_device_agent_dependencies):
    """Test DeviceAgent handles failure to send initial 'online' status."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    mock_client.register_device.return_value = {"status": "success"}
    mock_nats_client.connect.return_value = None
    mock_client.update_status.side_effect = Exception("Status update failed") # Changed to generic Exception

    agent = DeviceAgent(mock_client, mock_nats_client)
    with pytest.raises(Exception, match="Status update failed"): # Expect the exception to propagate
        await agent.start()

    mock_client.update_status.assert_called_once()
    mock_client.update_status.assert_called_with("error", {"message": "Failed to start: Status update failed"})
    mock_nats_client.disconnect.assert_called_once() # Should attempt to stop gracefully


@pytest.mark.asyncio
async def test_device_agent_stop(mock_device_agent_dependencies):
    """Test DeviceAgent stops correctly and sends offline status."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]

    agent = DeviceAgent(mock_client, mock_nats_client)
    # Simulate tasks being created
    agent._telemetry_task = MagicMock(spec=asyncio.Task)
    agent._command_listener_task = MagicMock(spec=asyncio.Task)

    await agent.stop()

    agent._telemetry_task.cancel.assert_called_once()
    agent._command_listener_task.cancel.assert_called_once()
    mock_nats_client.disconnect.assert_called_once()
    mock_client.update_status.assert_called_with("offline", {"message": "Device agent stopped."})

@pytest.mark.asyncio
async def test_device_agent_run_telemetry_loop(mock_device_agent_dependencies):
    """Test telemetry loop sends data at intervals."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_asyncio_sleep = mock_device_agent_dependencies["mock_asyncio_sleep"]
    agent = DeviceAgent(mock_client, mock_device_agent_dependencies["mock_nats_client_instance"])

    # Configure asyncio.sleep to raise CancelledError after 3 calls
    mock_asyncio_sleep.side_effect = [None, None, asyncio.CancelledError]

    with patch("equus_express.edge_device_controller.DeviceAgent._collect_telemetry",
               return_value={"mock_data": 123}):
        await agent.run_telemetry_loop(interval=1)

    assert mock_client.send_telemetry.call_count == 3
    assert mock_asyncio_sleep.call_count == 3 # Called after each telemetry send
    mock_asyncio_sleep.assert_called_with(1)

@pytest.mark.asyncio
async def test_device_agent_run_telemetry_loop_communication_error(mock_device_agent_dependencies, caplog):
    """Test telemetry loop handles client communication errors."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_asyncio_sleep = mock_device_agent_dependencies["mock_asyncio_sleep"]
    agent = DeviceAgent(mock_client, mock_device_agent_dependencies["mock_nats_client_instance"])

    # Simulate an error on the first send, then stop on the second
    mock_client.send_telemetry.side_effect = [
        httpx.RequestError("Simulated connection error", request=httpx.Request("POST", TEST_BASE_URL)),
        asyncio.CancelledError # Stop the loop after the second iteration
    ]
    mock_asyncio_sleep.side_effect = [None, None] # Allow two sleeps

    with caplog.at_level(logging.ERROR):
        with patch("equus_express.edge_device_controller.DeviceAgent._collect_telemetry", return_value={"mock_data": 123}):
            await agent.run_telemetry_loop(interval=1)

    assert "Error collecting or sending telemetry: Simulated connection error" in caplog.text
    mock_client.update_status.assert_called_with("warning", {"message": "Telemetry error: Simulated connection error"})
    assert mock_client.send_telemetry.call_count == 2
    assert mock_asyncio_sleep.call_count == 2

@pytest.mark.asyncio
async def test_device_agent_run_telemetry_loop_unexpected_error(mock_device_agent_dependencies, caplog):
    """Test telemetry loop handles unexpected general errors."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_asyncio_sleep = mock_device_agent_dependencies["mock_asyncio_sleep"]
    agent = DeviceAgent(mock_client, mock_device_agent_dependencies["mock_nats_client_instance"])

    # Simulate an unexpected error on the first send, then stop on the second
    mock_client.send_telemetry.side_effect = [
        ValueError("Unexpected data format"),
        asyncio.CancelledError # Stop the loop after the second iteration
    ]
    mock_asyncio_sleep.side_effect = [None, None] # Allow two sleeps

    with caplog.at_level(logging.ERROR):
        with patch("equus_express.edge_device_controller.DeviceAgent._collect_telemetry", return_value={"mock_data": 123}):
            await agent.run_telemetry_loop(interval=1)

    assert "Error collecting or sending telemetry: Unexpected data format" in caplog.text
    mock_client.update_status.assert_called_with("warning", {"message": "Telemetry error: Unexpected data format"})
    assert mock_client.send_telemetry.call_count == 2
    assert mock_asyncio_sleep.call_count == 2

@pytest.mark.asyncio
async def test_device_agent_handle_command_message_success(mock_device_agent_dependencies):
    """Test _handle_command_message processes a valid command."""
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_nats_client)

    mock_msg = MagicMock()
    mock_msg.subject = "commands.test_device"
    mock_msg.reply = "reply.test_device"
    mock_msg.data = json.dumps({"type": "get_telemetry"}).encode()

    with patch("equus_express.edge_device_controller.DeviceAgent._collect_telemetry", return_value={"mock_telemetry": "data"}):
        await agent._handle_command_message(mock_msg)

    mock_nats_client.publish.assert_called_once()
    published_data = json.loads(mock_nats_client.publish.call_args[0][1].decode())
    assert published_data["status"] == "success"
    assert published_data["result"] == {"mock_telemetry": "data"}

@pytest.mark.asyncio
async def test_device_agent_handle_command_message_invalid_json(mock_device_agent_dependencies, caplog):
    """Test _handle_command_message handles invalid JSON."""
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_nats_client)

    mock_msg = MagicMock()
    mock_msg.subject = "commands.test_device"
    mock_msg.reply = "reply.test_device"
    mock_msg.data = b"invalid json"

    with caplog.at_level(logging.ERROR):
        await agent._handle_command_message(mock_msg)

    assert "Invalid JSON command received: invalid json" in caplog.text
    mock_nats_client.publish.assert_called_once()
    published_data = json.loads(mock_nats_client.publish.call_args[0][1].decode())
    assert published_data["status"] == "error"
    assert "Invalid JSON command format." in published_data["message"]

@pytest.mark.asyncio
async def test_device_agent_handle_command_message_missing_type(mock_device_agent_dependencies, caplog):
    """Test _handle_command_message handles missing command type."""
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_nats_client)

    mock_msg = MagicMock()
    mock_msg.subject = "commands.test_device"
    mock_msg.reply = "reply.test_device"
    mock_msg.data = json.dumps({"params": {"foo": "bar"}}).encode() # Missing 'type'

    with caplog.at_level(logging.ERROR):
        await agent._handle_command_message(mock_msg)

    assert "Command validation error: Command message missing 'type' field." in caplog.text
    mock_nats_client.publish.assert_called_once()
    published_data = json.loads(mock_nats_client.publish.call_args[0][1].decode())
    assert published_data["status"] == "error"
    assert "Command message missing 'type' field." in published_data["message"]

@pytest.mark.asyncio
async def test_device_agent_handle_command_message_unknown_command(mock_device_agent_dependencies, caplog):
    """Test _handle_command_message handles unknown command type."""
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_nats_client)

    mock_msg = MagicMock()
    mock_msg.subject = "commands.test_device"
    mock_msg.reply = "reply.test_device"
    mock_msg.data = json.dumps({"type": "unknown_command"}).encode()

    with caplog.at_level(logging.ERROR):
        await agent._handle_command_message(mock_msg)

    assert "Command validation error: Unknown command type: unknown_command" in caplog.text
    mock_nats_client.publish.assert_called_once()
    published_data = json.loads(mock_nats_client.publish.call_args[0][1].decode())
    assert published_data["status"] == "error"
    assert "Unknown command type: unknown_command" in published_data["message"]

@pytest.mark.asyncio
async def test_device_agent_handle_command_message_exception_during_execution(mock_device_agent_dependencies, caplog):
    """Test _handle_command_message handles exceptions during command execution."""
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_nats_client)

    mock_msg = MagicMock()
    mock_msg.subject = "commands.test_device"
    mock_msg.reply = "reply.test_device"
    mock_msg.data = json.dumps({"type": "get_telemetry"}).encode()

    with patch("equus_express.edge_device_controller.DeviceAgent._collect_telemetry", side_effect=Exception("Simulated execution error")):
        with caplog.at_level(logging.ERROR):
            await agent._handle_command_message(mock_msg)

    assert "Unexpected error during command execution: Simulated execution error" in caplog.text
    mock_nats_client.publish.assert_called_once()
    published_data = json.loads(mock_nats_client.publish.call_args[0][1].decode())
    assert published_data["status"] == "error"
    assert "Error executing command: Simulated execution error" in published_data["message"]

@pytest.mark.asyncio
async def test_device_agent_handle_command_get_telemetry(mock_device_agent_dependencies):
    """Test _handle_command for 'get_telemetry' type."""
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_device_agent_dependencies["mock_nats_client_instance"])
    expected_telemetry = {"cpu": 0.5, "mem": 0.8}
    with patch("equus_express.edge_device_controller.DeviceAgent._collect_telemetry", return_value=expected_telemetry) as mock_collect:
        result = await agent._handle_command("get_telemetry", {})
        mock_collect.assert_called_once()
        assert result == expected_telemetry

@pytest.mark.asyncio
async def test_device_agent_handle_command_update_config_valid(mock_device_agent_dependencies):
    """Test _handle_command for 'update_config' with valid interval."""
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_device_agent_dependencies["mock_nats_client_instance"])
    params = {"telemetry_interval": 30}
    result = await agent._handle_command("update_config", params)
    assert result == {"message": "Telemetry interval updated to 30s (requires restart to apply)."}

@pytest.mark.asyncio
async def test_device_agent_handle_command_update_config_invalid(mock_device_agent_dependencies):
    """Test _handle_command for 'update_config' with invalid interval."""
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_device_agent_dependencies["mock_nats_client_instance"])
    params = {"telemetry_interval": "invalid"}
    with pytest.raises(ValueError, match="Invalid 'telemetry_interval' parameter."):
        await agent._handle_command("update_config", params)

@pytest.mark.asyncio
async def test_device_agent_handle_command_smbus_write_success(mock_device_agent_dependencies):
    """Test _handle_command for 'smbus_write' success."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    agent = DeviceAgent(mock_client, mock_nats_client, smbus_address=0x42, smbus_bus_num=1)
    agent.smbus_bus = MagicMock() # Mock the smbus_bus object

    params = {"address": 0x42, "command_code": 0x01, "data": [0x10, 0x20]}
    with patch("equus_express.edge_device_controller.DeviceAgent._smbus_write_block_data") as mock_write:
        result = await agent._handle_command("smbus_write", params)
        mock_write.assert_called_once_with(0x42, 0x01, [0x10, 0x20])
        assert result == {"message": "SMBus write successful."}

@pytest.mark.asyncio
async def test_device_agent_handle_command_smbus_read_success(mock_device_agent_dependencies):
    """Test _handle_command for 'smbus_read' success."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    agent = DeviceAgent(mock_client, mock_nats_client, smbus_address=0x42, smbus_bus_num=1)
    agent.smbus_bus = MagicMock() # Mock the smbus_bus object

    params = {"address": 0x42, "command_code": 0x02, "length": 4}
    expected_read_data = bytearray([0xAA, 0xBB, 0xCC, 0xDD])
    with patch("equus_express.edge_device_controller.DeviceAgent._smbus_read_block_data", return_value=expected_read_data) as mock_read:
        result = await agent._handle_command("smbus_read", params)
        mock_read.assert_called_once_with(0x42, 0x02, 4)
        assert result == {"data": list(expected_read_data)}

def test_device_agent_smbus_init_success(mock_device_agent_dependencies):
    """Test SMBus initialization success."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    with patch("equus_express.edge_device_controller.smbus2.SMBus") as MockSMBus:
        agent = DeviceAgent(mock_client, mock_nats_client, smbus_address=0x42, smbus_bus_num=1)
        MockSMBus.assert_called_once_with(1)
        assert agent.smbus_bus is not None

def test_device_agent_smbus_init_failure(mock_device_agent_dependencies, caplog):
    """Test SMBus initialization failure."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    with patch("equus_express.edge_device_controller.smbus2.SMBus", side_effect=Exception("SMBus init error")):
        with caplog.at_level(logging.ERROR):
            agent = DeviceAgent(mock_client, mock_nats_client, smbus_address=0x42, smbus_bus_num=1)
            assert agent.smbus_bus is None
            assert "Failed to initialize SMBus on bus 1: SMBus init error" in caplog.text

def test_device_agent_smbus_not_installed(mock_device_agent_dependencies, caplog):
    """Test SMBus initialization when smbus2 is not installed."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    with patch("equus_express.edge_device_controller.smbus2", new=None):
        with caplog.at_level(logging.WARNING):
            agent = DeviceAgent(mock_client, mock_nats_client, smbus_address=0x42, smbus_bus_num=1)
            assert agent.smbus_bus is None
            assert "smbus2 library not found. SMBus communication will be disabled." in caplog.text

def test_device_agent_smbus_write_block_data_no_bus(mock_device_agent_dependencies):
    """Test _smbus_write_block_data raises error if bus not available."""
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_device_agent_dependencies["mock_nats_client_instance"])
    agent.smbus_bus = None # Ensure bus is not initialized
    with pytest.raises(SMBusNotAvailable):
        agent._smbus_write_block_data(0x42, 0x01, [0x10])

def test_device_agent_smbus_read_block_data_no_bus(mock_device_agent_dependencies):
    """Test _smbus_read_block_data raises error if bus not available."""
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_device_agent_dependencies["mock_nats_client_instance"])
    agent.smbus_bus = None # Ensure bus is not initialized
    with pytest.raises(SMBusNotAvailable):
        agent._smbus_read_block_data(0x42, 0x01, 1)

def test_device_agent_smbus_write_block_data_error(mock_device_agent_dependencies, caplog):
    """Test _smbus_write_block_data handles write errors."""
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_device_agent_dependencies["mock_nats_client_instance"], smbus_address=0x42, smbus_bus_num=1)
    agent.smbus_bus = MagicMock()
    agent.smbus_bus.write_i2c_block_data.side_effect = Exception("Write error")
    with caplog.at_level(logging.ERROR):
        with pytest.raises(Exception, match="Write error"):
            agent._smbus_write_block_data(0x42, 0x01, [0x10])
        assert "SMBus write failed: Write error" in caplog.text

def test_device_agent_smbus_read_block_data_error(mock_device_agent_dependencies, caplog):
    """Test _smbus_read_block_data handles read errors."""
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_device_agent_dependencies["mock_nats_client_instance"], smbus_address=0x42, smbus_bus_num=1)
    agent.smbus_bus = MagicMock()
    agent.smbus_bus.read_i2c_block_data.side_effect = Exception("Read error")
    with caplog.at_level(logging.ERROR):
        with pytest.raises(Exception, match="Read error"):
            agent._smbus_read_block_data(0x42, 0x01, 1)
        assert "SMBus read failed: Read error" in caplog.text

def test_device_agent_collect_telemetry_psutil_not_installed(mock_device_agent_dependencies, caplog):
    """Test _collect_telemetry logs warning and returns default values if psutil is None."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client, mock_device_agent_dependencies["mock_nats_client_instance"])
    with patch("equus_express.edge_device_controller.psutil", new=None):
        with caplog.at_level(logging.WARNING):
            telemetry = agent._collect_telemetry()
            assert "psutil not installed, system metrics will be unavailable." in caplog.text
            # Assert that system_metrics are default values
            assert telemetry["system_metrics"]["uptime_seconds"] == 0.0
            assert telemetry["system_metrics"]["cpu_usage_percent"] == 0.0
            assert telemetry["system_metrics"]["memory_usage"] == {}
            assert telemetry["system_metrics"]["disk_usage"] == {}
            assert telemetry["system_metrics"]["temperature_celsius"] == 0.0

def test_device_agent_collect_telemetry_structure(mock_device_agent_dependencies):
    """Test _collect_telemetry aggregates data from helper methods."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client, mock_device_agent_dependencies["mock_nats_client_instance"])

    # Patch the individual _get_* methods for this specific test
    with (
        patch("equus_express.edge_device_controller.DeviceAgent._get_uptime", return_value=100.0),
        patch("equus_express.edge_device_controller.DeviceAgent._get_cpu_usage", return_value=25.0),
        patch("equus_express.edge_device_controller.DeviceAgent._get_memory_usage", return_value={"total_gb": 16.0, "available_gb": 8.0, "percent": 50.0, "used_gb": 8.0, "free_gb": 8.0}),
        patch("equus_express.edge_device_controller.DeviceAgent._get_disk_usage", return_value={"total_gb": 100.0, "used_gb": 70.0, "free_gb": 30.0, "percent": 70.0}),
        patch("equus_express.edge_device_controller.DeviceAgent._get_temperature", return_value=45.0),
        patch("equus_express.edge_device_controller.SecureAPIClient._get_ip_address", return_value=MOCK_IP_ADDRESS), # This is now on SecureAPIClient
        patch("equus_express.edge_device_controller.psutil", MagicMock()), # Ensure psutil is mocked as available
    ):
        telemetry = agent._collect_telemetry()

    assert "timestamp" in telemetry
    assert "device_id" in telemetry
    assert telemetry["device_id"] == TEST_DEVICE_ID
    assert "system_info" in telemetry
    assert "network_info" in telemetry
    assert "system_metrics" in telemetry

    assert telemetry["system_info"]["platform"] == platform.system()
    assert telemetry["system_info"]["release"] == platform.release()
    assert telemetry["system_info"]["architecture"] == platform.machine()
    assert telemetry["system_info"]["python_version"] == platform.python_version()

    assert telemetry["network_info"]["ip_address"] == MOCK_IP_ADDRESS

    assert telemetry["system_metrics"]["uptime_seconds"] == pytest.approx(100.0)
    assert telemetry["system_metrics"]["cpu_usage_percent"] == pytest.approx(25.0)
    assert telemetry["system_metrics"]["memory_usage"]["percent"] == pytest.approx(50.0)
    assert telemetry["system_metrics"]["disk_usage"]["percent"] == pytest.approx(70.0)
    assert telemetry["system_metrics"]["temperature_celsius"] == pytest.approx(45.0)

def test_device_agent_collect_telemetry_error_handling_individual_metrics(
    mock_device_agent_dependencies, caplog
):
    """Test _collect_telemetry handles errors in individual metric collection methods."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client, mock_device_agent_dependencies["mock_nats_client_instance"])

    # Ensure psutil is mocked as available for these tests
    with patch("equus_express.edge_device_controller.psutil", MagicMock()):
        # Make _get_uptime raise an error
        with caplog.at_level(logging.ERROR):
            with patch("equus_express.edge_device_controller.DeviceAgent._get_uptime", side_effect=OSError("Uptime error")):
                telemetry = agent._collect_telemetry()
                assert "uptime_seconds" in telemetry["system_metrics"]
                assert telemetry["system_metrics"]["uptime_seconds"] == 0.0 # Default value on error
                assert "Error collecting uptime_seconds: Uptime error" in caplog.text
        caplog.clear() # Clear logs for next check

        # Make _get_cpu_usage raise an error
        with caplog.at_level(logging.ERROR):
            with patch("equus_express.edge_device_controller.DeviceAgent._get_cpu_usage", side_effect=RuntimeError("CPU error")):
                telemetry = agent._collect_telemetry()
                assert "cpu_usage_percent" in telemetry["system_metrics"]
                assert telemetry["system_metrics"]["cpu_usage_percent"] == 0.0 # Default value on error
                assert "Error collecting cpu_usage_percent: CPU error" in caplog.text
        caplog.clear()

        # Make _get_memory_usage raise an error
        with caplog.at_level(logging.ERROR):
            with patch("equus_express.edge_device_controller.DeviceAgent._get_memory_usage", side_effect=RuntimeError("Memory error")):
                telemetry = agent._collect_telemetry()
                assert "memory_usage" in telemetry["system_metrics"]
                assert telemetry["system_metrics"]["memory_usage"] == {} # Default value on error
                assert "Error collecting memory_usage: Memory error" in caplog.text
        caplog.clear()

        # Make _get_disk_usage raise an error
        with caplog.at_level(logging.ERROR):
            with patch("equus_express.edge_device_controller.DeviceAgent._get_disk_usage", side_effect=RuntimeError("Disk error")):
                telemetry = agent._collect_telemetry()
                assert "disk_usage" in telemetry["system_metrics"]
                assert telemetry["system_metrics"]["disk_usage"] == {} # Default value on error
                assert "Error collecting disk_usage: Disk error" in caplog.text
        caplog.clear()

        # Make _get_temperature raise an error
        with caplog.at_level(logging.ERROR):
            with patch("equus_express.edge_device_controller.DeviceAgent._get_temperature", side_effect=OSError("Temp file error")):
                telemetry = agent._collect_telemetry()
                assert "temperature_celsius" in telemetry["system_metrics"]
                assert telemetry["system_metrics"]["temperature_celsius"] == 0.0 # Default value on error
                assert "Error collecting temperature_celsius: Temp file error" in caplog.text
        caplog.clear()

        # Make _get_ip_address (on SecureAPIClient) raise an error
        with caplog.at_level(logging.ERROR):
            with patch("equus_express.edge_device_controller.SecureAPIClient._get_ip_address", side_effect=socket.gaierror("IP error")):
                telemetry = agent._collect_telemetry()
                assert "ip_address" in telemetry["network_info"]
                assert telemetry["network_info"]["ip_address"] == "0.0.0.0" # Default value on error
                assert "Error collecting ip_address: IP error" in caplog.text
        caplog.clear()


def test_device_agent_get_uptime():
    """Test _get_uptime returns psutil.boot_time()."""
    with patch("equus_express.edge_device_controller.psutil") as mock_psutil:
        mock_psutil.boot_time.return_value = 12345.67
        agent = DeviceAgent(MagicMock(), MagicMock()) # Dummy agent
        assert agent._get_uptime() == 12345.67
        mock_psutil.boot_time.assert_called_once()

def test_device_agent_get_cpu_usage():
    """Test _get_cpu_usage returns psutil.cpu_percent()."""
    with patch("equus_express.edge_device_controller.psutil") as mock_psutil:
        mock_psutil.cpu_percent.return_value = 50.5
        agent = DeviceAgent(MagicMock(), MagicMock())
        assert agent._get_cpu_usage() == 50.5
        mock_psutil.cpu_percent.assert_called_once_with(interval=None)

def test_device_agent_get_memory_usage():
    """Test _get_memory_usage returns formatted memory stats."""
    with patch("equus_express.edge_device_controller.psutil") as mock_psutil:
        mock_mem = MagicMock()
        mock_mem.total = 16 * (1024**3) # 16 GB
        mock_mem.available = 8 * (1024**3) # 8 GB
        mock_mem.used = 8 * (1024**3) # 8 GB
        mock_mem.free = 8 * (1024**3) # 8 GB
        mock_mem.percent = 50.0
        mock_psutil.virtual_memory.return_value = mock_mem
        agent = DeviceAgent(MagicMock(), MagicMock())
        result = agent._get_memory_usage()
        assert result["total_gb"] == 16.0
        assert result["available_gb"] == 8.0
        assert result["percent"] == 50.0
        assert result["used_gb"] == 8.0
        assert result["free_gb"] == 8.0
        mock_psutil.virtual_memory.assert_called_once()

def test_device_agent_get_disk_usage():
    """Test _get_disk_usage returns formatted disk stats."""
    with patch("equus_express.edge_device_controller.psutil") as mock_psutil:
        mock_disk = MagicMock()
        mock_disk.total = 100 * (1024**3) # 100 GB
        mock_disk.used = 70 * (1024**3) # 70 GB
        mock_disk.free = 30 * (1024**3) # 30 GB
        mock_disk.percent = 70.0
        mock_psutil.disk_usage.return_value = mock_disk
        agent = DeviceAgent(MagicMock(), MagicMock())
        result = agent._get_disk_usage()
        assert result["total_gb"] == 100.0
        assert result["used_gb"] == 70.0
        assert result["free_gb"] == 30.0
        assert result["percent"] == 70.0
        mock_psutil.disk_usage.assert_called_once_with('/')

def test_device_agent_get_temperature_coretemp():
    """Test _get_temperature returns coretemp if available."""
    with patch("equus_express.edge_device_controller.psutil") as mock_psutil:
        mock_temp_sensor = MagicMock()
        mock_temp_sensor.current = 60.5
        mock_psutil.sensors_temperatures.return_value = {"coretemp": [mock_temp_sensor]}
        agent = DeviceAgent(MagicMock(), MagicMock())
        assert agent._get_temperature() == 60.5
        mock_psutil.sensors_temperatures.assert_called_once()

def test_device_agent_get_temperature_cpu_thermal():
    """Test _get_temperature returns cpu_thermal if coretemp not available."""
    with patch("equus_express.edge_device_controller.psutil") as mock_psutil:
        mock_temp_sensor = MagicMock()
        mock_temp_sensor.current = 55.0
        mock_psutil.sensors_temperatures.return_value = {"cpu_thermal": [mock_temp_sensor]}
        agent = DeviceAgent(MagicMock(), MagicMock())
        assert agent._get_temperature() == 55.0
        mock_psutil.sensors_temperatures.assert_called_once()

def test_device_agent_get_temperature_not_available():
    """Test _get_temperature returns 0.0 if no temperature data."""
    with patch("equus_express.edge_device_controller.psutil") as mock_psutil:
        mock_psutil.sensors_temperatures.return_value = {} # No temperature sensors
        agent = DeviceAgent(MagicMock(), MagicMock())
        assert agent._get_temperature() == 0.0
        mock_psutil.sensors_temperatures.assert_called_once()

def test_device_agent_get_temperature_psutil_no_sensors_temperatures():
    """Test _get_temperature returns 0.0 if psutil has no sensors_temperatures."""
    with patch("equus_express.edge_device_controller.psutil") as mock_psutil:
        del mock_psutil.sensors_temperatures # Simulate attribute not existing
        agent = DeviceAgent(MagicMock(), MagicMock())
        assert agent._get_temperature() == 0.0
        # mock_psutil.assert_not_called() # sensors_temperatures not called if attribute missing, but psutil itself is still accessed.

def test_device_agent_get_ip_address(mock_device_agent_dependencies):
    """Test DeviceAgent._get_ip_address calls SecureAPIClient._get_ip_address."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client, mock_device_agent_dependencies["mock_nats_client_instance"])
    mock_client._get_ip_address.return_value = "192.168.1.100"
    assert agent._get_ip_address() == "192.168.1.100"
    mock_client._get_ip_address.assert_called_once()

# --- SecureAPIClient._get_ip_address tests (moved from DeviceAgent tests) ---
def test_secure_client_get_ip_address_success():
    """Test _get_ip_address returns a valid IP."""
    client = SecureAPIClient(base_url=TEST_BASE_URL, device_id=TEST_DEVICE_ID, key_dir="/tmp/keys")
    with patch("equus_express.edge_device_controller.socket.socket") as mock_socket:
        mock_sock_instance = mock_socket.return_value
        mock_sock_instance.getsockname.return_value = ("192.168.1.10", 12345)
        assert client._get_ip_address() == "192.168.1.10"
        mock_sock_instance.connect.assert_called_once_with(("8.8.8.8", 80))
        mock_sock_instance.close.assert_called_once()

def test_secure_client_get_ip_address_fallback_to_localhost():
    """Test _get_ip_address falls back to 127.0.0.1 if all attempts fail."""
    client = SecureAPIClient(base_url=TEST_BASE_URL, device_id=TEST_DEVICE_ID, key_dir="/tmp/keys")
    with patch("equus_express.edge_device_controller.socket.socket", side_effect=Exception("No network")):
        with patch("equus_express.edge_device_controller.fcntl.ioctl", side_effect=OSError("No interface")):
            assert client._get_ip_address() == "127.0.0.1"

# --- Main function tests ---
@pytest.mark.asyncio
async def test_main_success(mock_device_agent_dependencies, caplog):
    """Test main function runs successfully."""
    mock_api_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    mock_agent_instance = MagicMock()
    mock_agent_instance.start.return_value = None
    mock_agent_instance.stop.return_value = None

    with patch("equus_express.edge_device_controller.SecureAPIClient", return_value=mock_api_client), \
         patch("equus_express.edge_device_controller.NATSClient", return_value=mock_nats_client), \
         patch("equus_express.edge_device_controller.DeviceAgent", return_value=mock_agent_instance), \
         patch("equus_express.edge_device_controller.asyncio.sleep", side_effect=asyncio.CancelledError): # To exit the infinite loop
        from equus_express.edge_device_controller import main
        await main()

    mock_api_client.assert_called_once() # SecureAPIClient should be instantiated
    mock_nats_client.assert_called_once_with(
        nats_url=os.getenv("NATS_URL", "nats://localhost:4222"),
        device_id=mock_api_client.device_id, # Check device_id passed
        key_dir=os.getenv("KEY_DIR", os.path.expanduser("~/.equus_express/keys"))
    )
    mock_agent_instance.start.assert_called_once()
    mock_agent_instance.stop.assert_called_once()
    assert "Agent main loop cancelled." in caplog.text
    assert "Agent stopped gracefully." in caplog.text

@pytest.mark.asyncio
async def test_main_agent_start_failure(mock_device_agent_dependencies, caplog):
    """Test main function handles device agent failing to start."""
    mock_api_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    mock_agent_instance = MagicMock()
    mock_agent_instance.start.side_effect = Exception("Agent start failed")
    mock_agent_instance.stop.return_value = None # Ensure stop can be called

    with patch("equus_express.edge_device_controller.SecureAPIClient", return_value=mock_api_client), \
         patch("equus_express.edge_device_controller.NATSClient", return_value=mock_nats_client), \
         patch("equus_express.edge_device_controller.DeviceAgent", return_value=mock_agent_instance):
        with caplog.at_level(logging.CRITICAL):
            from equus_express.edge_device_controller import main
            await main()

    mock_agent_instance.start.assert_called_once()
    mock_agent_instance.stop.assert_called_once() # Agent was created, so stop is called
    assert "Agent encountered a critical error: Agent start failed" in caplog.text
    assert "Agent stopped gracefully." in caplog.text # Stop message should still appear

@pytest.mark.asyncio
async def test_main_client_init_critical_error(mock_crypto, caplog):
    """Test main function handles critical client initialization error."""
    mock_crypto["mock_os_makedirs"].side_effect = OSError("Critical init error")  # Simulate error during key setup

    with patch("equus_express.edge_device_controller.SecureAPIClient", side_effect=OSError("Failed to initialize client keys: Critical init error")), \
         patch("equus_express.edge_device_controller.NATSClient") as MockNATSClient, \
         patch("equus_express.edge_device_controller.DeviceAgent") as MockDeviceAgent:
        with caplog.at_level(logging.CRITICAL):
            from equus_express.edge_device_controller import main
            await main()

    MockNATSClient.assert_not_called() # NATSClient should not be instantiated
    MockDeviceAgent.assert_not_called() # DeviceAgent should not be instantiated
    assert "Agent encountered a critical error: Failed to initialize client keys: Critical init error" in caplog.text
    assert "Agent stopped gracefully." not in caplog.text # Agent was never started, so no graceful stop message

@pytest.mark.asyncio
async def test_main_unexpected_error(caplog):
    """Test main function handles unexpected general exceptions during setup."""
    # Mock SecureAPIClient constructor to raise an unexpected error
    with patch("equus_express.edge_device_controller.SecureAPIClient", side_effect=Exception("Unexpected client error")), \
         patch("equus_express.edge_device_controller.NATSClient") as MockNATSClient, \
         patch("equus_express.edge_device_controller.DeviceAgent") as MockDeviceAgent:
        with caplog.at_level(logging.CRITICAL):
            from equus_express.edge_device_controller import main
            await main()

    MockNATSClient.assert_not_called()
    MockDeviceAgent.assert_not_called()
    assert "Agent encountered a critical error: Unexpected client error" in caplog.text
    assert "Agent stopped gracefully." not in caplog.text
