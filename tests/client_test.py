import pytest
from unittest.mock import patch, MagicMock, mock_open, AsyncMock
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

    # Mock the sign method to return a mock object that has a .hex() method
    mock_signature_bytes = b"mock_signature"
    mock_signature_hex = mock_signature_bytes.hex()
    mock_signature_result = MagicMock()
    mock_signature_result.hex.return_value = mock_signature_hex
    mock_private_key.sign.return_value = mock_signature_result

    # Mock methods for Ed25519PublicKey (VerifyKey)
    mock_public_key.public_bytes.return_value = MOCK_ED25519_PUBLIC_KEY_OPENSSH

    with (
        patch("cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate") as mock_generate_private_key, # Correct path for Ed25519 generate
        patch("equus_express.edge_device_controller.serialization") as mock_serialization,
        patch("equus_express.edge_device_controller.default_backend"),
        patch("equus_express.edge_device_controller.open", m_open),
        patch("equus_express.edge_device_controller.os.path.exists") as mock_os_path_exists,
        patch("equus_express.edge_device_controller.os.makedirs") as mock_os_makedirs,
        patch("equus_express.edge_device_controller.Hash"), # Mock Hash for device_id generation
        patch("equus_express.edge_device_controller.SHA256"), # Mock SHA2556 for device_id generation
    ):
        # Configure mock_serialization to behave like the actual module
        mock_serialization.Encoding.PEM = serialization.Encoding.PEM # Use actual enum
        mock_serialization.Encoding.OpenSSH = serialization.Encoding.OpenSSH # Use actual enum
        mock_serialization.Encoding.Raw = serialization.Encoding.Raw # Use actual enum
        mock_serialization.NoEncryption = serialization.NoEncryption # Use actual class
        mock_serialization.PrivateFormat.PKCS8 = serialization.PrivateFormat.PKCS8 # Use actual enum
        mock_serialization.PublicFormat.OpenSSH = serialization.PublicFormat.OpenSSH # Use actual enum
        mock_serialization.PublicFormat.Raw = serialization.PublicFormat.Raw # Use actual enum

        mock_generate_private_key.return_value = mock_private_key
        mock_serialization.load_pem_private_key.return_value = mock_private_key
        mock_serialization.load_ssh_public_key.return_value = mock_public_key # New mock for loading public key

        # Configure mock_open for reading (for secure_client_keys_exist scenario)
        # The read content depends on the order of reads: private, public, device_id
        m_open.return_value.__enter__.return_value.read.side_effect = [
            MOCK_ED25519_PRIVATE_KEY_PEM,
            MOCK_ED25519_PUBLIC_KEY_OPENSSH,
            MOCK_DEVICE_ID_CONTENT.decode('utf-8'), # device_id is read as string
        ] # Ensure these are consumed in order, one per read call

        yield {
            "mock_generate_private_key": mock_generate_private_key,
            "mock_serialization": mock_serialization,
            "mock_private_key": mock_private_key,
            "mock_public_key": mock_public_key,
            "mock_open": m_open,
            "mock_os_path_exists": mock_os_path_exists,
            "mock_os_makedirs": mock_os_makedirs,
            "mock_signature_hex": mock_signature_hex, # Pass this to tests
        }


@pytest.fixture
def mock_httpx_client():
    """Fixture to mock httpx.Client."""
    with patch("equus_express.edge_device_controller.httpx.Client") as MockClient:
        mock_client_instance = MockClient.return_value
        # Default mock response for success
        mock_response_success = MagicMock()
        mock_response_success.status_code = 200
        mock_response_success.json.return_value = {
            "status": "success",
            "message": "Mocked response",
        }
        mock_response_success.raise_for_status.return_value = (
            None  # No HTTP errors by default
        )

        # Set a default return value for request, individual tests can override side_effect
        mock_client_instance.request.return_value = mock_response_success
        yield mock_client_instance


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
        patch("equus_express.edge_device_controller.NATSClient") as MockNATSClient,
        patch("equus_express.edge_device_controller.os.path.exists", return_value=True),
        patch("equus_express.edge_device_controller.socket.gethostname", return_value=TEST_DEVICE_ID),
        patch("equus_express.edge_device_controller.time.time", return_value=1672531200.0), # Mock time.time()
        patch("equus_express.edge_device_controller.asyncio.sleep") as mock_asyncio_sleep, # Mock asyncio.sleep
    ):
        mock_client_instance = MockClient.return_value
        mock_nats_client_instance = MockNATSClient.return_value

        # Configure the mock client methods that DeviceAgent calls by default for success paths
        mock_client_instance.send_telemetry = AsyncMock(return_value=MagicMock(status_code=200, json=lambda: {"status": "success"}))
        mock_client_instance.update_status = AsyncMock(return_value=MagicMock(status_code=200, json=lambda: {"status": "success"}))
        mock_client_instance.register_device.return_value = {"status": "success"} # This is not awaited in agent.start
        mock_client_instance.device_id = TEST_DEVICE_ID # Ensure device_id is set on mock client
        mock_client_instance._get_ip_address.return_value = MOCK_IP_ADDRESS # Mock internal IP method

        # Configure mock NATS client methods
        mock_nats_client_instance.connect = AsyncMock()
        mock_nats_client_instance.disconnect = AsyncMock()
        mock_nats_client_instance.publish = AsyncMock()
        mock_nats_client_instance.subscribe = AsyncMock() # Return a mock subscription ID

        # Configure asyncio.sleep to return awaitable mocks or raise CancelledError
        mock_asyncio_sleep.side_effect = [AsyncMock(), AsyncMock(), AsyncMock(), asyncio.CancelledError] # Added one more AsyncMock for initial sleep(0.1)


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


def test_secure_client_init_os_error(tmp_key_dir):
    """Test that SecureAPIClient initialization handles OSError during key operations."""
    with patch("equus_express.edge_device_controller.os.makedirs", side_effect=OSError("Disk full")): # Removed mock_makedirs alias as it's not asserted directly
        with pytest.raises(RuntimeError, match="Failed to initialize client keys"): # Expect RuntimeError as per _load_or_generate_keys re-raise
            SecureAPIClient(
                base_url=TEST_BASE_URL,
                device_id=TEST_DEVICE_ID,
                key_dir=tmp_key_dir,
            )
        # Assertions on mock_makedirs should be done in a separate test if needed. Here, we just check exception.


def test_secure_client_register_device_no_public_key(mock_httpx_client, tmp_key_dir):
    """Test register_device raises RuntimeError if public_key is not available."""
    with patch("equus_express.edge_device_controller.SecureAPIClient._load_or_generate_keys"):
        client = SecureAPIClient(base_url=TEST_BASE_URL, device_id=TEST_DEVICE_ID, key_dir=tmp_key_dir)
        client.public_key = None # Explicitly ensure public_key is None

        with pytest.raises(RuntimeError, match="Public key not available for registration."):
            client.register_device()
    mock_httpx_client.request.assert_not_called()


def test_secure_client_register_device_network_error(mock_httpx_client, secure_client_keys_exist):
    """Test register_device handles network/server errors."""
    client = secure_client_keys_exist
    # Set side_effect directly on the request method for this test
    mock_httpx_client.request.side_effect = httpx.RequestError(
        "Network unreachable", request=httpx.Request("POST", TEST_BASE_URL)
    )

    with pytest.raises(httpx.RequestError, match="Network unreachable"):
        client.register_device()
    mock_httpx_client.request.assert_called_once()


def test_secure_client_make_request_success(
    mock_httpx_client, secure_client_keys_exist, mock_crypto
):
    """Test _make_request for a successful response."""
    response_data = {"key": "value"}
    mock_httpx_client.request.return_value.json.return_value = response_data
    mock_httpx_client.request.return_value.status_code = 200

    client = secure_client_keys_exist # Use fixture
    result = client.get("/test")

    mock_httpx_client.request.assert_called_with(
        "GET",
        "/test", # Changed from f"{TEST_BASE_URL}/test"
        headers={"X-Device-ID": TEST_DEVICE_ID, "X-Signature": mock_crypto["mock_signature_hex"]}
    )
    assert result.json() == response_data


def test_secure_client_make_request_non_json_response(
    mock_httpx_client, secure_client_keys_exist
):
    """Test _make_request handles non-JSON successful responses when .json() is called."""
    mock_response = MagicMock(status_code=200, text="OK") # Mock text attribute
    mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", doc="OK", pos=0) # Mimic json parse error

    mock_httpx_client.request.return_value = mock_response # Set this for the specific test

    client = secure_client_keys_exist
    with pytest.raises(json.JSONDecodeError, match="Invalid JSON"):
        client.get("/plaintext").json()


def test_secure_client_make_request_401_error(
    mock_httpx_client, secure_client_keys_exist
):
    """Test _make_request handles 401 Unauthorized HTTP errors."""
    mock_httpx_client.request.side_effect = httpx.HTTPStatusError( # Set side_effect directly on request
        "Unauthorized",
        request=httpx.Request("GET", "https://test.com"),
        response=httpx.Response(401, request=httpx.Request("GET", "https://test.com")),
    ) # Set side_effect directly on request

    client = secure_client_keys_exist
    with pytest.raises(httpx.HTTPStatusError):
        client.get("/protected")


def test_secure_client_make_request_403_error(
    mock_httpx_client, secure_client_keys_exist
):
    """Test _make_request handles 403 Forbidden HTTP errors."""
    mock_httpx_client.request.side_effect = httpx.HTTPStatusError( # Set side_effect directly on request
        "Forbidden",
        request=httpx.Request("GET", "https://test.com"),
        response=httpx.Response(403, request=httpx.Request("GET", "https://test.com")),
    ) # Set side_effect directly on request

    client = secure_client_keys_exist
    with pytest.raises(httpx.HTTPStatusError):
        client.get("/forbidden")


def test_secure_client_make_request_http_error(
    mock_httpx_client, secure_client_keys_exist
):
    """Test _make_request handles HTTP errors."""
    mock_httpx_client.request.side_effect = httpx.HTTPStatusError( # Set side_effect directly on request
        "Not Found",
        request=httpx.Request("GET", "https://test.com"),
        response=httpx.Response(404),
    ) # Set side_effect directly on request

    client = secure_client_keys_exist
    with pytest.raises(httpx.HTTPStatusError):
        client.get("/nonexistent")


def test_secure_client_register_device(
    mock_httpx_client, secure_client_keys_exist, mock_crypto
):
    """Test register_device sends correct payload."""
    client = secure_client_keys_exist
    # Mock _get_ip_address locally for this test
    with patch("equus_express.edge_device_controller.SecureAPIClient._get_ip_address", return_value=MOCK_IP_ADDRESS):
        client.register_device()
    mock_httpx_client.request.assert_called_with(
        "POST",
        "/api/register", # Changed from f"{TEST_BASE_URL}/api/register"
        json={
            "device_id": TEST_DEVICE_ID,
            "public_key": MOCK_ED25519_PUBLIC_KEY_OPENSSH.decode('utf-8').strip(),
            "ip_address": MOCK_IP_ADDRESS
        },
        data=None,
        headers={
            "X-Device-ID": TEST_DEVICE_ID,
            "X-Signature": mock_crypto["mock_signature_hex"],
            "Content-Type": "application/json"
        }
    )


def test_secure_client_health_check(
    mock_httpx_client, secure_client_keys_exist, mock_crypto
):
    """Test health_check calls the correct endpoint."""
    client = secure_client_keys_exist
    client.health_check()
    mock_httpx_client.request.assert_called_with(
        "GET",
        "/health", # Changed from f"{TEST_BASE_URL}/health"
        headers={"X-Device-ID": TEST_DEVICE_ID, "X-Signature": mock_crypto["mock_signature_hex"]}
    )


def test_secure_client_send_telemetry(
    mock_httpx_client, secure_client_keys_exist, mock_crypto
):
    """Test send_telemetry sends correct payload."""
    client = secure_client_keys_exist
    test_data = {"temp": 25, "hum": 70}
    with patch("equus_express.edge_device_controller.time.time", return_value=1672531200.0): # Jan 1, 2023 00:00:00 UTC
        client.send_telemetry(test_data)
    mock_httpx_client.request.assert_called_once_with( # Ensure called exactly once
        "POST",
        "/api/telemetry", # Changed from f"{TEST_BASE_URL}/api/telemetry"
        json={
            "device_id": TEST_DEVICE_ID,
            "timestamp": 1672531200, # Expect integer timestamp
            "data": test_data,
        },
        data=None,
        headers={
            "X-Device-ID": TEST_DEVICE_ID,
            "X-Signature": mock_crypto["mock_signature_hex"],
            "Content-Type": "application/json"
        }
    )


def test_secure_client_get_configuration(
    mock_httpx_client, secure_client_keys_exist, mock_crypto
):
    """Test get_configuration calls the correct endpoint."""
    client = secure_client_keys_exist
    client.get_configuration()
    mock_httpx_client.request.assert_called_once_with( # Ensure called exactly once
        "GET",
        f"/api/device/{TEST_DEVICE_ID}/config", # Changed from f"{TEST_BASE_URL}/api/device/{TEST_DEVICE_ID}/config"
        headers={"X-Device-ID": TEST_DEVICE_ID, "X-Signature": mock_crypto["mock_signature_hex"]}
    )


def test_secure_client_update_status(
    mock_httpx_client, secure_client_keys_exist, mock_crypto
):
    """Test update_status sends correct payload."""
    client = secure_client_keys_exist
    test_status = "idle"
    test_details = {"battery": "90%"}
    with patch("equus_express.edge_device_controller.time.time", return_value=1672531200.0): # Jan 1, 2023 00:00:00 UTC
        client.update_status(test_status, test_details)
    mock_httpx_client.request.assert_called_once_with( # Ensure called exactly once
        "POST",
        "/api/device/status", # Changed from f"{TEST_BASE_URL}/api/device/status"
        json={
            "device_id": TEST_DEVICE_ID,
            "status": test_status,
            "timestamp": 1672531200, # Expect integer timestamp
            "details": test_details,
        },
        data=None,
        headers={
            "X-Device-ID": TEST_DEVICE_ID,
            "X-Signature": mock_crypto["mock_signature_hex"],
            "Content-Type": "application/json"
        }
    )


def test_secure_client_test_connection_success(
    mock_httpx_client,
    secure_client_keys_exist,
    mock_crypto # Added mock_crypto to access mock_signature_hex
):
    """Test test_connection success path."""
    client = secure_client_keys_exist
    # Mock _get_ip_address locally for this test
    with patch("equus_express.edge_device_controller.SecureAPIClient._get_ip_address", return_value=MOCK_IP_ADDRESS):
        # Ensure nested calls return success
        mock_httpx_client.request.side_effect = [
            MagicMock(status_code=200, json=lambda: {"status": "healthy"}, raise_for_status=MagicMock()),  # For health_check
            MagicMock(status_code=200, json=lambda: {"status": "success", "message": "registered"}, raise_for_status=MagicMock()),  # For register_device
            MagicMock(status_code=200, json=lambda: {"device_id": TEST_DEVICE_ID}, raise_for_status=MagicMock()),  # For get_device_info
            MagicMock(status_code=200, json=lambda: {"status": "success"}, raise_for_status=MagicMock()),  # For send_telemetry
        ]
        assert client.test_connection() is True


def test_secure_client_test_connection_failure(
    mock_httpx_client,
    secure_client_keys_exist,
):
    """Test test_connection failure path."""
    client = secure_client_keys_exist
    # Mock _get_ip_address locally for this test
    with patch("equus_express.edge_device_controller.SecureAPIClient._get_ip_address", return_value=MOCK_IP_ADDRESS):
        # Make the mock raise a specific httpx error that test_connection catches
        mock_httpx_client.request.side_effect = httpx.ConnectError(
            "Connection failed", request=httpx.Request("POST", TEST_BASE_URL)
        )
        assert client.test_connection() is False # Assert that it returns False


def test_secure_client_test_connection_get_device_info_failure(
    mock_httpx_client,
    secure_client_keys_exist,
):
    """Test test_connection fails if get_device_info fails."""
    client = secure_client_keys_exist
    # Mock _get_ip_address locally for this test
    with patch("equus_express.edge_device_controller.SecureAPIClient._get_ip_address", return_value=MOCK_IP_ADDRESS):
        # Mock health_check and register_device to succeed
        mock_httpx_client.request.side_effect = [
            MagicMock(status_code=200, json=lambda: {"status": "healthy"}, raise_for_status=MagicMock()), # for health_check
            MagicMock(status_code=200, json=lambda: {"status": "success", "message": "registered"}, raise_for_status=MagicMock()), # for register_device
            httpx.RequestError("Device info failed", request=httpx.Request("GET", TEST_BASE_URL)), # for get_device_info
        ]

        with patch('equus_express.edge_device_controller.logger.warning') as mock_log: # test_connection logs warnings if device not found.
            assert client.test_connection() is False  # Should return False
            mock_log.assert_any_call(f"Device {TEST_DEVICE_ID} not recognized by API server. Attempting to register...") # First warning
            mock_log.assert_any_call(f"Connection test failed: Device info failed") # Final log if get_device_info fails


# --- DeviceAgent Tests ---

@pytest.mark.asyncio # Mark as async test
async def test_device_agent_start_success(mock_device_agent_dependencies):
    """Test DeviceAgent starts successfully."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]

    agent = DeviceAgent(mock_client, mock_nats_client)
    # Need to mock the internal _get_ip_address that DeviceAgent calls on its client.
    # This is mocked in the fixture for the client, but agent uses client.get_ip_address()
    mock_client._get_ip_address.return_value = MOCK_IP_ADDRESS
    await agent.start()

    mock_client.register_device.assert_awaited_once() # Now correctly awaited by start()
    mock_nats_client.connect.assert_awaited_once()
    mock_client.update_status.assert_awaited_with("online", {"ip_address": MOCK_IP_ADDRESS})
    mock_nats_client.subscribe.assert_called_once_with(f"commands.{TEST_DEVICE_ID}", agent._handle_command_message)

@pytest.mark.asyncio
async def test_device_agent_start_failure(mock_device_agent_dependencies):
    """Test DeviceAgent handles connection failure on start."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    mock_client.register_device.side_effect = Exception("Registration failed") # Force start to fail
    mock_client._get_ip_address.return_value = MOCK_IP_ADDRESS # Needed for potential status update

    agent = DeviceAgent(mock_client, mock_nats_client)
    with pytest.raises(Exception, match="Registration failed"): # Expected exception to propagate
        await agent.start()

    mock_client.register_device.assert_awaited_once() # Check if it was awaited
    mock_client.update_status.assert_awaited_with("error", {"message": "Failed to start: Registration failed"})
    mock_nats_client.disconnect.assert_awaited_once() # Should attempt to stop gracefully

@pytest.mark.asyncio
async def test_device_agent_start_update_status_failure(mock_device_agent_dependencies):
    """Test DeviceAgent handles failure to send initial 'online' status."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    mock_client.register_device.return_value = {"status": "success"}
    mock_nats_client.connect = AsyncMock()
    mock_client.update_status.side_effect = AsyncMock(side_effect=Exception("Status update failed")) # Make it an awaitable mock that raises
    mock_client._get_ip_address.return_value = MOCK_IP_ADDRESS

    agent = DeviceAgent(mock_client, mock_nats_client)
    with pytest.raises(Exception, match="Status update failed"): # Expect exception to propagate from the `_publish_status` call.
        await agent.start()

    mock_client.update_status.assert_awaited_once() # This confirms the first attempt to update status
    mock_client.update_status.assert_awaited_with("error", {"message": "Failed to start: Status update failed"})
    mock_nats_client.disconnect.assert_awaited_once() # Should attempt to stop gracefully


@pytest.mark.asyncio
async def test_device_agent_stop(mock_device_agent_dependencies):
    """Test DeviceAgent stops correctly and sends offline status."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]

    agent = DeviceAgent(mock_client, mock_nats_client)
    mock_client._get_ip_address.return_value = MOCK_IP_ADDRESS # Needed for final status update
    # Simulate tasks being created
    agent._telemetry_task = AsyncMock(return_value=None) # Mock that it finishes normally
    agent._command_listener_task = AsyncMock(return_value=None) # Mock that it finishes normally
    await agent.stop()

    agent._telemetry_task.cancel.assert_called_once()
    agent._command_listener_task.cancel.assert_called_once() # Ensure cancel is called
    agent._telemetry_task.assert_awaited_once()
    agent._command_listener_task.assert_awaited_once()
    mock_nats_client.disconnect.assert_awaited_once()
    mock_client.update_status.assert_awaited_with("offline", {"message": "Device agent stopped."})

@pytest.mark.asyncio
async def test_device_agent_run_telemetry_loop(mock_device_agent_dependencies):
    """Test telemetry loop sends data at intervals."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_asyncio_sleep = mock_device_agent_dependencies["mock_asyncio_sleep"]
    agent = DeviceAgent(mock_client, mock_device_agent_dependencies["mock_nats_client_instance"])

    # Configure asyncio.sleep to raise CancelledError after a certain number of calls.
    # The loop has an initial 0.1s sleep, then a sleep(interval) after each send.
    mock_asyncio_sleep.side_effect = [
        AsyncMock(), # Initial sleep(0.1)
        AsyncMock(), # Sleep(interval) after 1st telemetry
        asyncio.CancelledError # Sleep(0.1) before 2nd telemetry, causes loop to stop
    ]

    with pytest.raises(asyncio.CancelledError): # Expect the CancelledError to propagate
        with patch("equus_express.edge_device_controller.DeviceAgent._collect_telemetry",
                   return_value={"mock_data": 123}) as mock_collect_telemetry:
            await agent.run_telemetry_loop(interval=1)

    assert mock_collect_telemetry.call_count == 1 # Telemetry collected once
    assert mock_client.send_telemetry.call_count == 1 # Telemetry sent once
    assert mock_asyncio_sleep.call_count == 3 # Sleep calls: 0.1s, 1s, and then the final CancelledError
    mock_asyncio_sleep.assert_any_call(0.1)
    mock_asyncio_sleep.assert_any_call(1)


@pytest.mark.asyncio
async def test_device_agent_run_telemetry_loop_communication_error(mock_device_agent_dependencies, caplog):
    """Test telemetry loop handles client communication errors."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    mock_asyncio_sleep = mock_device_agent_dependencies["mock_asyncio_sleep"]
    agent = DeviceAgent(mock_client, mock_nats_client)

    # Simulate an error on the first attempt to send telemetry
    # And configure to stop the loop after two attempts
    mock_client.send_telemetry.side_effect = [
        httpx.RequestError("Simulated connection error", request=httpx.Request("POST", TEST_BASE_URL)),
        MagicMock(status_code=200, json=lambda: {"status": "success"}), # For the second successful send if loop continues
    ]
    mock_asyncio_sleep.side_effect = [
        AsyncMock(), AsyncMock(), AsyncMock(), asyncio.CancelledError # Allow at least 2 iterations
    ]

    with caplog.at_level(logging.ERROR):
        with patch("equus_express.edge_device_controller.DeviceAgent._collect_telemetry", return_value={"mock_data": 123}) as mock_collect_telemetry:
            with pytest.raises(asyncio.CancelledError):
                await agent.run_telemetry_loop(interval=1)

    assert "Network error during telemetry send: Simulated connection error" in caplog.text
    # Verify that status was updated to warning due to telemetry error
    mock_nats_client.publish.assert_any_call(f"status.{TEST_DEVICE_ID}", json.dumps({"device_id": TEST_DEVICE_ID, "status": "warning", "details": {"message": "Telemetry network error: Simulated connection error"}}).encode('utf-8'))

    assert mock_collect_telemetry.call_count == 2 # Telemetry should be collected twice
    assert mock_client.send_telemetry.call_count == 2 # Send telemetry should be attempted twice
    assert mock_asyncio_sleep.call_count == 4 # Sleep calls: initial, after first send, before second, after second (cancelled)

@pytest.mark.asyncio
async def test_device_agent_run_telemetry_loop_unexpected_error(mock_device_agent_dependencies, caplog):
    """Test telemetry loop handles unexpected general errors."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    mock_asyncio_sleep = mock_device_agent_dependencies["mock_asyncio_sleep"]
    agent = DeviceAgent(mock_client, mock_nats_client)

    # Simulate an unexpected error on the first telemetry collection/send
    mock_client.send_telemetry.side_effect = [
        ValueError("Unexpected data format"),
        MagicMock(status_code=200, json=lambda: {"status": "success"}),
    ]
    mock_asyncio_sleep.side_effect = [
        AsyncMock(), AsyncMock(), AsyncMock(), asyncio.CancelledError
    ]

    with caplog.at_level(logging.ERROR):
        with patch("equus_express.edge_device_controller.DeviceAgent._collect_telemetry", return_value={"mock_data": 123}) as mock_collect_telemetry:
            with pytest.raises(asyncio.CancelledError):
                await agent.run_telemetry_loop(interval=1)

    assert "Unexpected error during telemetry loop: Unexpected data format" in caplog.text
    # Verify status updated to error due to unexpected telemetry error
    mock_nats_client.publish.assert_any_call(f"status.{TEST_DEVICE_ID}", json.dumps({"device_id": TEST_DEVICE_ID, "status": "error", "details": {"message": "Unexpected telemetry error: Unexpected data format"}}).encode('utf-8'))

    assert mock_collect_telemetry.call_count == 2
    assert mock_client.send_telemetry.call_count == 2
    assert mock_asyncio_sleep.call_count == 4

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

    mock_nats_client.publish.assert_awaited_once()
    published_data = json.loads(mock_nats_client.publish.call_args[0][1].decode())
    assert published_data["status"] == "success"
    assert published_data["data"] == {"mock_telemetry": "data"} # Changed from 'result' to 'data'

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
    mock_nats_client.publish.assert_awaited_once()
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

    assert "Command validation error: 'type' field is missing from command." in caplog.text
    mock_nats_client.publish.assert_awaited_once()
    published_data = json.loads(mock_nats_client.publish.call_args[0][1].decode())
    assert published_data["status"] == "error"
    assert "'type' field is missing from command." in published_data["message"]

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
    mock_nats_client.publish.assert_awaited_once()
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

    assert "Error processing command: Simulated execution error" in caplog.text
    mock_nats_client.publish.assert_awaited_once()
    published_data = json.loads(mock_nats_client.publish.call_args[0][1].decode())
    assert published_data["status"] == "error"
    assert "Unexpected error during command execution: Simulated execution error" in published_data["message"]

@pytest.mark.asyncio
async def test_device_agent_handle_command_get_telemetry(mock_device_agent_dependencies):
    """Test _handle_command for 'get_telemetry' type."""
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_device_agent_dependencies["mock_nats_client_instance"])
    expected_telemetry = {"cpu": 0.5, "mem": 0.8}
    with patch("equus_express.edge_device_controller.DeviceAgent._collect_telemetry", return_value=expected_telemetry) as mock_collect:
        result = await agent._handle_command("get_telemetry", {})
        mock_collect.assert_called_once() # Verify that _collect_telemetry was called
        assert result["status"] == "success" # _handle_command wraps result in a status dict
        assert result["data"] == expected_telemetry

@pytest.mark.asyncio
async def test_device_agent_handle_command_update_config_valid(mock_device_agent_dependencies):
    """Test _handle_command for 'update_config' with valid interval."""
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_device_agent_dependencies["mock_nats_client_instance"])
    params = {"telemetry_interval": 30}
    result = await agent._handle_command("update_config", params)
    assert result == {"status": "success", "message": "Telemetry interval updated to 30s (requires restart to apply)."}

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
    agent.smbus = MagicMock() # Mock the smbus object

    params = {"address": 0x42, "command_code": 0x01, "data": [0x10, 0x20]}
    with patch("equus_express.edge_device_controller.DeviceAgent._smbus_write_block_data") as mock_write:
        result = await agent._handle_command("smbus_write", params)
        mock_write.assert_called_once_with(0x42, 0x01, [0x10, 0x20]) # Verify params are passed
        assert result == {"status": "success", "message": "SMBus write to 0x42 command 0x1 successful."}

@pytest.mark.asyncio
async def test_device_agent_handle_command_smbus_read_success(mock_device_agent_dependencies):
    """Test _handle_command for 'smbus_read' success."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    agent = DeviceAgent(mock_client, mock_nats_client, smbus_address=0x42, smbus_bus_num=1)
    agent.smbus = MagicMock() # Mock the smbus object

    params = {"address": 0x42, "command_code": 0x02, "length": 4}
    expected_read_data = bytearray([0xAA, 0xBB, 0xCC, 0xDD])
    with patch("equus_express.edge_device_controller.DeviceAgent._smbus_read_block_data", return_value=expected_read_data) as mock_read:
        result = await agent._handle_command("smbus_read", params)
        mock_read.assert_called_once_with(0x42, 0x02, 4) # Verify params are passed
        assert result == {"status": "success", "message": "SMBus read from 0x42 command 0x2 successful.", "data": list(expected_read_data)}

def test_device_agent_smbus_init_success(mock_device_agent_dependencies):
    """Test SMBus initialization success."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    with patch("equus_express.edge_device_controller.smbus2.SMBus", return_value=MagicMock()) as MockSMBus: # Mock the SMBus constructor
        agent = DeviceAgent(mock_client, mock_nats_client, smbus_address=0x42, smbus_bus_num=1)
        MockSMBus.assert_called_once_with(1)
        assert agent.smbus is not None # Check if smbus attribute is set

def test_device_agent_smbus_init_failure(mock_device_agent_dependencies, caplog):
    """Test SMBus initialization failure."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    with patch("equus_express.edge_device_controller.smbus2.SMBus", side_effect=Exception("SMBus init error")):
        with caplog.at_level(logging.ERROR):
            agent = DeviceAgent(mock_client, mock_nats_client, smbus_address=0x42, smbus_bus_num=1)
            assert agent.smbus is None # Check if smbus is None
            assert "Failed to initialize SMBus on bus 1: SMBus init error" in caplog.text

def test_device_agent_smbus_not_installed(mock_device_agent_dependencies, caplog):
    """Test SMBus initialization when smbus2 is not installed."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    with patch("equus_express.edge_device_controller.smbus2", new=None): # Simulate smbus2 not being available
        with caplog.at_level(logging.WARNING):
            agent = DeviceAgent(mock_client, mock_nats_client, smbus_address=0x42, smbus_bus_num=1)
            assert agent.smbus is None # Should be None
            assert "smbus2 library not found. SMBus communication will be unavailable." in caplog.text

def test_device_agent_smbus_write_block_data_no_bus(mock_device_agent_dependencies):
    """Test _smbus_write_block_data raises error if bus not available."""
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_device_agent_dependencies["mock_nats_client_instance"])
    agent.smbus = None # Ensure bus is not initialized
    with pytest.raises(SMBusNotAvailable):
        agent._smbus_write_block_data(0x42, 0x01, [0x10])

def test_device_agent_smbus_read_block_data_no_bus(mock_device_agent_dependencies):
    """Test _smbus_read_block_data raises error if bus not available."""
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_device_agent_dependencies["mock_nats_client_instance"])
    agent.smbus = None # Ensure bus is not initialized
    with pytest.raises(SMBusNotAvailable):
        agent._smbus_read_block_data(0x42, 0x01, 1)

def test_device_agent_smbus_write_block_data_error(mock_device_agent_dependencies, caplog):
    """Test _smbus_write_block_data handles write errors."""
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_device_agent_dependencies["mock_nats_client_instance"], smbus_address=0x42, smbus_bus_num=1)
    agent.smbus = MagicMock() # Mock the smbus object
    agent.smbus.write_i2c_block_data.side_effect = Exception("Write error")
    with caplog.at_level(logging.ERROR):
        with pytest.raises(Exception, match="Write error"): # Expect this exception to be re-raised
            agent._smbus_write_block_data(0x42, 0x01, [0x10])
        assert "SMBus write failed: Write error" in caplog.text

def test_device_agent_smbus_read_block_data_error(mock_device_agent_dependencies, caplog):
    """Test _smbus_read_block_data handles read errors."""
    agent = DeviceAgent(mock_device_agent_dependencies["mock_client_instance"], mock_device_agent_dependencies["mock_nats_client_instance"], smbus_address=0x42, smbus_bus_num=1)
    agent.smbus = MagicMock() # Mock the smbus object
    agent.smbus.read_i2c_block_data.side_effect = Exception("Read error")
    with caplog.at_level(logging.ERROR):
        with pytest.raises(Exception, match="Read error"): # Expect this exception to be re-raised
            agent._smbus_read_block_data(0x42, 0x01, 1)
        assert "SMBus read failed: Read error" in caplog.text

def test_device_agent_collect_telemetry_psutil_not_installed(mock_device_agent_dependencies, caplog):
    """Test _collect_telemetry logs warning and returns default values if psutil is None."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client, mock_device_agent_dependencies["mock_nats_client_instance"])
    with patch("equus_express.edge_device_controller.psutil", new=None): # Force psutil to be None
        with caplog.at_level(logging.WARNING):
            telemetry = agent._collect_telemetry()
            assert "psutil not installed, system metrics will be unavailable." in caplog.text
            # Assert that system_metrics contains expected default values
            assert telemetry["system_metrics"]["uptime_seconds"] == 0.0
            assert telemetry["system_metrics"]["cpu_usage_percent"] == 0.0
            assert telemetry["system_metrics"]["memory_total_mb"] == 0.0 # Changed to check mb
            assert telemetry["system_metrics"]["disk_total_gb"] == 0.0 # Changed to check gb
            assert telemetry["system_metrics"]["temperature_celsius"] == 0.0

def test_device_agent_collect_telemetry_structure(mock_device_agent_dependencies):
    """Test _collect_telemetry aggregates data from helper methods."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client, mock_device_agent_dependencies["mock_nats_client_instance"])

    # Patch the individual _get_* methods for this specific test
    with (
        patch("equus_express.edge_device_controller.DeviceAgent._get_uptime", return_value=100.0),
        patch("equus_express.edge_device_controller.DeviceAgent._get_cpu_usage", return_value=25.0),
        patch("equus_express.edge_device_controller.DeviceAgent._get_memory_usage", return_value={"total_mb": 16000.0, "available_mb": 8000.0, "percent": 50.0, "used_mb": 8000.0, "free_mb": 8000.0}), # Values in MB
        patch("equus_express.edge_device_controller.DeviceAgent._get_disk_usage", return_value={"total_gb": 100.0, "used_gb": 70.0, "free_gb": 30.0, "percent": 70.0}),
        patch("equus_express.edge_device_controller.DeviceAgent._get_temperature", return_value=45.0),
        patch.object(agent.client, '_get_ip_address', return_value=MOCK_IP_ADDRESS), # Mock method on the client instance
        patch("equus_express.edge_device_controller.psutil", MagicMock()), # Ensure psutil is mocked as available
    ):
        telemetry = agent._collect_telemetry()

    assert "timestamp" in telemetry
    assert telemetry["device_id"] == TEST_DEVICE_ID # Device ID should be present at top level
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
    assert telemetry["system_metrics"]["memory_total_mb"] == pytest.approx(16000.0) # Check specific memory key
    assert telemetry["system_metrics"]["memory_used_percent"] == pytest.approx(50.0)
    assert telemetry["system_metrics"]["disk_total_gb"] == pytest.approx(100.0) # Check specific disk key
    assert telemetry["system_metrics"]["disk_used_percent"] == pytest.approx(70.0)
    assert telemetry["system_metrics"]["temperature_celsius"] == pytest.approx(45.0)

def test_device_agent_collect_telemetry_error_handling_individual_metrics(
    mock_device_agent_dependencies, caplog
):
    """Test _collect_telemetry handles errors in individual metric collection methods."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client, mock_device_agent_dependencies["mock_nats_client_instance"])

    # Ensure psutil is mocked as available for these tests
    with patch("equus_express.edge_device_controller.psutil", MagicMock()), \
         patch.object(agent.client, '_get_ip_address', return_value=MOCK_IP_ADDRESS): # Mock this consistently

@pytest.mark.asyncio
async def test_device_agent_run_telemetry_loop_communication_error(mock_device_agent_dependencies, caplog):
    """Test telemetry loop handles client communication errors."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_asyncio_sleep = mock_device_agent_dependencies["mock_asyncio_sleep"]
    agent = DeviceAgent(mock_client, mock_device_agent_dependencies["mock_nats_client_instance"])

    # Simulate an error on the first send, then stop on the second
    mock_client.send_telemetry.side_effect = [
        AsyncMock(side_effect=httpx.RequestError("Simulated connection error", request=httpx.Request("POST", TEST_BASE_URL))),
        AsyncMock(), # For the second successful send
        asyncio.CancelledError # Stop the loop after the third iteration
    ]
    mock_asyncio_sleep.side_effect = [AsyncMock(), AsyncMock(), AsyncMock(), asyncio.CancelledError] # Allow sleeps

    with caplog.at_level(logging.ERROR):
        with patch("equus_express.edge_device_controller.DeviceAgent._collect_telemetry", return_value={"mock_data": 123}):
            with pytest.raises(asyncio.CancelledError):
                await agent.run_telemetry_loop(interval=1)

    assert "Error collecting or sending telemetry: Simulated connection error" in caplog.text
    mock_client.update_status.assert_awaited_with("warning", {"message": "Telemetry error: Simulated connection error"})
    assert mock_client.send_telemetry.call_count == 2 # First call raises error, second is successful
    assert mock_asyncio_sleep.call_count == 4 # 0.1s sleep, 1s sleep, 0.1s sleep, 1s sleep (cancelled)

@pytest.mark.asyncio
async def test_device_agent_run_telemetry_loop_unexpected_error(mock_device_agent_dependencies, caplog):
    """Test telemetry loop handles unexpected general errors."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_asyncio_sleep = mock_device_agent_dependencies["mock_asyncio_sleep"]
    agent = DeviceAgent(mock_client, mock_device_agent_dependencies["mock_nats_client_instance"])

    # Simulate an unexpected error on the first send, then stop on the second
    mock_client.send_telemetry.side_effect = [
        AsyncMock(side_effect=ValueError("Unexpected data format")),
        AsyncMock(), # For the second successful send
        asyncio.CancelledError # Stop the loop after the third iteration
    ]
    mock_asyncio_sleep.side_effect = [AsyncMock(), AsyncMock(), AsyncMock(), asyncio.CancelledError] # Allow sleeps

    with caplog.at_level(logging.ERROR):
        with patch("equus_express.edge_device_controller.DeviceAgent._collect_telemetry", return_value={"mock_data": 123}):
            with pytest.raises(asyncio.CancelledError):
                await agent.run_telemetry_loop(interval=1)

    assert "Error collecting or sending telemetry: Unexpected data format" in caplog.text
    mock_client.update_status.assert_awaited_with("warning", {"message": "Telemetry error: Unexpected data format"})
    assert mock_client.send_telemetry.call_count == 2
    assert mock_asyncio_sleep.call_count == 4

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

    mock_nats_client.publish.assert_awaited_once()
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
    mock_nats_client.publish.assert_awaited_once()
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
    mock_nats_client.publish.assert_awaited_once()
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
    mock_nats_client.publish.assert_awaited_once()
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
    mock_nats_client.publish.assert_awaited_once()
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
            assert "smbus2 not installed, SMBus communication disabled." in caplog.text # Corrected assertion string

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
                assert telemetry["system_metrics"]["uptime_seconds"] == 0.0 # Default value on error for individual metric
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
        with patch("equus_express.edge_device_controller.time.time", return_value=12345.67 + 100.0): # Mock current time for consistent uptime
            agent = DeviceAgent(MagicMock(), MagicMock()) # Dummy agent
            assert agent._get_uptime() == 100.0 # Expected uptime
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
        mock_psutil.virtual_memory.return_value = mock_mem # No change here
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
        mock_psutil.disk_usage.return_value = mock_disk # No change here
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
        mock_psutil.sensors_temperatures.return_value = {"coretemp": [mock_temp_sensor]} # No change here
        agent = DeviceAgent(MagicMock(), MagicMock())
        assert agent._get_temperature() == 60.5
        mock_psutil.sensors_temperatures.assert_called_once()

def test_device_agent_get_temperature_cpu_thermal():
    """Test _get_temperature returns cpu_thermal if coretemp not available."""
    with patch("equus_express.edge_device_controller.psutil") as mock_psutil:
        mock_temp_sensor = MagicMock()
        mock_temp_sensor.current = 55.0
        mock_psutil.sensors_temperatures.return_value = {"cpu_thermal": [mock_temp_sensor]} # No change here
        agent = DeviceAgent(MagicMock(), MagicMock())
        assert agent._get_temperature() == 55.0
        mock_psutil.sensors_temperatures.assert_called_once()

def test_device_agent_get_temperature_not_available():
    """Test _get_temperature returns 0.0 if no temperature data."""
    with patch("equus_express.edge_device_controller.psutil") as mock_psutil:
        mock_psutil.sensors_temperatures.return_value = {} # No temperature sensors
        agent = DeviceAgent(MagicMock(), MagicMock()) # No change here
        assert agent._get_temperature() == 0.0
        mock_psutil.sensors_temperatures.assert_called_once()

def test_device_agent_get_temperature_psutil_no_sensors_temperatures():
    """Test _get_temperature returns 0.0 if psutil has no sensors_temperatures."""
    with patch("equus_express.edge_device_controller.psutil") as mock_psutil:
        del mock_psutil.sensors_temperatures # Simulate attribute not existing
        agent = DeviceAgent(MagicMock(), MagicMock()) # No change here
        assert agent._get_temperature() == 0.0
        # mock_psutil.assert_not_called() # sensors_temperatures not called if attribute missing, but psutil itself is still accessed.

def test_device_agent_get_ip_address(mock_device_agent_dependencies):
    """Test DeviceAgent._get_ip_address calls SecureAPIClient._get_ip_address."""
    mock_client = mock_device_agent_dependencies["mock_client_instance"]
    agent = DeviceAgent(mock_client, mock_device_agent_dependencies["mock_nats_client_instance"])
    mock_client._get_ip_address.return_value = MOCK_IP_ADDRESS # Using the mock constant from the fixture
    assert agent._get_ip_address() == MOCK_IP_ADDRESS
    mock_client._get_ip_address.assert_called_once()

# --- SecureAPIClient._get_ip_address tests (moved from DeviceAgent tests) ---
def test_secure_client_get_ip_address_success():
    """Test _get_ip_address returns a valid IP."""
    client = SecureAPIClient(base_url=TEST_BASE_URL, device_id=TEST_DEVICE_ID, key_dir="/tmp/keys")
    with patch("equus_express.edge_device_controller.socket.socket") as mock_socket:
        mock_sock_instance = mock_socket.return_value
        mock_sock_instance.getsockname.return_value = ("192.168.1.10", 12345) # No change here
        assert client._get_ip_address() == "192.168.1.10"
        mock_sock_instance.connect.assert_called_once_with(("8.8.8.8", 80))
        mock_sock_instance.close.assert_called_once()

def test_secure_client_get_ip_address_fallback_to_localhost():
    """Test _get_ip_address falls back to 127.0.0.1 if all attempts fail."""
    client = SecureAPIClient(base_url=TEST_BASE_URL, device_id=TEST_DEVICE_ID, key_dir="/tmp/keys")
    with patch("equus_express.edge_device_controller.socket.socket", side_effect=Exception("No network")):
        with patch("equus_express.edge_device_controller.socket.gethostbyname", side_effect=socket.gaierror("No host")): # No change here
            assert client._get_ip_address() == "unknown" # Expecting 'unknown' as final fallback in edge_device_controller.py

# --- Main function tests ---
@pytest.mark.asyncio
async def test_main_success(mock_device_agent_dependencies, caplog):
    """Test main function runs successfully."""
    mock_api_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    mock_agent_instance = MagicMock()
    mock_agent_instance.start = AsyncMock(return_value=None) # Ensure start is an awaitable mock
    mock_agent_instance.stop = AsyncMock(return_value=None) # Ensure stop is an awaitable mock
    mock_agent_instance._running = True # Simulate agent is running for the loop

    # Patch the main function's imports to use our mocks
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
    mock_agent_instance.start.assert_awaited_once() # Check that start was awaited
    mock_agent_instance.stop.assert_awaited_once()
    assert "Agent main loop cancelled." in caplog.text
    assert "Device Agent stopped." in caplog.text # Changed from "Agent stopped gracefully."

@pytest.mark.asyncio
async def test_main_agent_start_failure(mock_device_agent_dependencies, caplog):
    """Test main function handles device agent failing to start."""
    mock_api_client = mock_device_agent_dependencies["mock_client_instance"]
    mock_nats_client = mock_device_agent_dependencies["mock_nats_client_instance"]
    mock_agent_instance = MagicMock()
    mock_agent_instance.start.side_effect = Exception("Agent start failed") # Force start to fail
    mock_agent_instance.stop = AsyncMock(return_value=None) # Ensure stop can be called and is awaitable

    with patch("equus_express.edge_device_controller.SecureAPIClient", return_value=mock_api_client), \
         patch("equus_express.edge_device_controller.NATSClient", return_value=mock_nats_client), \
         patch("equus_express.edge_device_controller.DeviceAgent", return_value=mock_agent_instance):
        with caplog.at_level(logging.CRITICAL):
            from equus_express.edge_device_controller import main
            await main()

    mock_agent_instance.start.assert_awaited_once() # Check that start was awaited
    mock_agent_instance.stop.assert_awaited_once() # Agent was created, so stop is called
    assert "Agent encountered a critical error: Agent start failed" in caplog.text
    assert "Device Agent stopped." in caplog.text # Stop message should still appear

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
    assert "Device Agent stopped." not in caplog.text # Agent was never started, so no graceful stop message

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
    assert "Device Agent stopped." not in caplog.text
