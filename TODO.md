# TODO: Equus Express Checklist

This checklist outlines the remaining implementation tasks for the Equus Express project, based on the `DESIGN.md` specification.

## Core System API Features
- [ ] **Authentication & Authorization (RBAC):**
    - [ ] Implement user authentication (e.g., JWT).
    - [ ] Implement Role-Based Access Control (RBAC) for Administrator, Engineer, and Operator roles.
    - [ ] Secure all API endpoints with proper authentication and authorization checks.
- [ ] **API-to-API Provisioning:**
    - [ ] Implement API endpoint to list pending provisioning requests for admin approval.
    - [ ] Implement API endpoint for administrators to approve/reject API provisioning requests.
- [X] **NATS Integration:**
    - [ ] Implement NATS connection and subscription/publication logic within `system_api` (server-side).
        - *Note: This implies the `system_api` itself acting as a NATS client/publisher/subscriber, which is not currently the case. Re-evaluate if `system_api` should directly interact with NATS or if NATS integration is only for edge devices and a separate NATS-to-API bridge is needed.*
    - [ ] Configure `system_api` to use NATS `nkeys` or `tokens` for authentication.
        - *Note: Dependent on the above. If `system_api` is not a NATS client, this task might be for the NATS server configuration itself.*
    - [X] Implement NATS connection and subscription/publication logic within `edge_device_controller` (client-side).
        - *Note: Basic structure is in place, but actual NATS.py library calls are currently mocked.*
    - [ ] Configure `edge_device_controller` to use NATS `nkeys` for authentication.
    - [ ] `edge_device_controller` publishes telemetry (`pvs/update`) and status (`device.status`) to NATS.
        - *Note: Currently, telemetry and status are sent via HTTP to the `system_api`. This needs to be refactored to use NATS.*
    - [X] `edge_device_controller` subscribes to `command/execute` for remote commands.
- [ ] **Batch Executive:**
    - [ ] Implement the core Batch Executive logic for interpreting and executing recipes.
    - [ ] Integrate real-time data from NATS (`pvs/update`, `phase/state`) for condition evaluation.
    - [ ] Send control commands to `edge_device_controller` via NATS (`command/execute`).
- [ ] **Data Management:**
    - [ ] Implement persistent storage for system configurations (beyond initial setup).
    - [ ] Implement full Electronic Batch Record (EBR) generation, storage, and retrieval.
    - [ ] Integrate with a time-series database (e.g., TimescaleDB, InfluxDB) for high-volume process data.
- [X] **SMBus Integration (Edge Device Controller):**
    - [X] Implement SMBus read/write block frame functionality in `edge_device_controller`.
    - [X] Allow SMBus address and bus number to be configurable.
    - [X] Integrate SMBus operations with NATS command reception (`command/execute`).

## Frontend (Web UI) Development
- [ ] Develop the main Single-Page Application (SPA) frontend.
- [ ] Implement the Physical Model Editor (tree view for equipment hierarchy).
- [ ] Implement the Graphical Recipe Editor with SFC elements and a no-code transition builder.
- [ ] Develop the Operator HMI for real-time batch monitoring and control.
- [ ] Establish WebSocket connections for real-time data display.
