# Equus Express - Design Document

## Overview

Equus Express is a lightweight web frontend for managing and monitoring embedded IoT devices. It provides device registration, telemetry collection, and a web dashboard for visualization.

## MVP Functional Requirements

### Server Component

- [x] FR-S01: Health check endpoint (`GET /health`) returns server status and timestamp
- [x] FR-S02: Device registration endpoint (`POST /api/register`) accepts device_id and public_key
- [x] FR-S03: Telemetry ingestion endpoint (`POST /api/telemetry`) stores device telemetry data
- [x] FR-S04: Device status update endpoint (`POST /api/device/status`) tracks device state
- [x] FR-S05: Device configuration endpoint (`GET /api/device/{device_id}/config`) returns device config
- [x] FR-S06: Device info endpoint (`GET /api/device/info`) returns device details for authenticated requests
- [x] FR-S07: Admin devices list endpoint (`GET /api/admin/devices`) returns all registered devices
- [x] FR-S08: Admin telemetry endpoint (`GET /api/admin/telemetry/{device_id}`) returns device telemetry history
- [x] FR-S09: Web dashboard (`GET /dashboard`) serves HTML dashboard for device monitoring
- [x] FR-S10: Static file serving for dashboard assets (CSS, JavaScript)
- [x] FR-S11: SQLite database for persistent storage of devices, telemetry, status, and config
- [x] FR-S12: Request authentication via X-Device-Id header validation

### Client Component

- [x] FR-C01: RSA key pair generation on first run (2048-bit)
- [x] FR-C02: Key persistence in `~/.equus_express/keys/`
- [x] FR-C03: Device registration with server using public key
- [x] FR-C04: Health check capability to verify server connectivity
- [x] FR-C05: Telemetry collection (CPU, memory, disk, temperature, uptime)
- [x] FR-C06: Periodic telemetry transmission at configurable intervals
- [x] FR-C07: Status updates on agent start/stop
- [x] FR-C08: Graceful error handling for network failures

### Non-Functional Requirements

- [x] NFR-01: Python 3.9+ compatibility
- [x] NFR-02: FastAPI/Uvicorn for async HTTP handling
- [x] NFR-03: httpx for async HTTP client
- [x] NFR-04: Designed for reverse proxy deployment (SSL termination external)
- [x] NFR-05: Docker containerization support
- [x] NFR-06: Comprehensive test coverage for server and client

## Architecture

```
+-------------------+        +-------------------+
|   Device Client   |  HTTP  |    API Server     |
|  (equus_express   | -----> |  (equus_express   |
|     .client)      |        |     .server)      |
+-------------------+        +-------------------+
                                      |
                                      v
                             +-------------------+
                             |    SQLite DB      |
                             | (secure_devices.db)|
                             +-------------------+
                                      ^
                                      |
                             +-------------------+
                             |  Web Dashboard    |
                             |  (Browser UI)     |
                             +-------------------+
```

## Data Models

### Device
- device_id (PK)
- public_key
- first_seen
- last_seen
- status
- ip_address
- device_info

### Telemetry
- id (PK)
- device_id (FK)
- timestamp
- data (JSON)
- received_at

### DeviceStatus
- id (PK)
- device_id (FK)
- status
- timestamp
- details (JSON)
- received_at

### DeviceConfig
- device_id (PK, FK)
- config (JSON)
- updated_at

## Traceability Matrix

| Requirement | Test File | Test Function |
|-------------|-----------|---------------|
| FR-S01 | server_test.py | test_health_check |
| FR-S02 | server_test.py | test_register_device, test_register_device_missing_fields |
| FR-S03 | server_test.py | test_send_telemetry, test_receive_telemetry_device_id_mismatch |
| FR-S04 | server_test.py | test_update_device_status, test_update_device_status_device_id_mismatch |
| FR-S05 | server_test.py | test_get_device_config, test_get_device_config_device_id_mismatch |
| FR-S06 | server_test.py | test_get_device_info, test_get_device_info_not_found |
| FR-S07 | server_test.py | test_list_devices, test_list_devices_empty |
| FR-S08 | server_test.py | test_get_device_telemetry, test_get_device_telemetry_no_telemetry |
| FR-S12 | server_test.py | test_get_authenticated_device_id_missing_header |
| FR-C01 | client_test.py | test_secure_client_initialization_generates_keys |
| FR-C02 | client_test.py | test_secure_client_initialization_loads_keys |
| FR-C03 | client_test.py | test_secure_client_register_device |
| FR-C04 | client_test.py | test_secure_client_health_check |
| FR-C05 | client_test.py | test_device_agent_collect_telemetry |
| FR-C06 | client_test.py | test_device_agent_run_telemetry_loop |
| FR-C07 | client_test.py | test_device_agent_start_success, test_device_agent_stop |
| FR-C08 | client_test.py | test_device_agent_run_telemetry_loop_communication_error |
