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
- [X] **NATS Integration (System API & Edge Device Controller):**
    - [X] Implement NATS connection and subscription/publication logic within `system_api`.
    - [X] Configure `system_api` to use NATS `nkeys` or `tokens` for authentication.
    - [X] Implement NATS connection and subscription/publication logic within `edge_device_controller`.
    - [X] Configure `edge_device_controller` to use NATS `nkeys` for authentication.
    - [X] `edge_device_controller` publishes telemetry (`pvs/update`) and device status (`device.status`) to NATS.
    - [X] `edge_device_controller` subscribes to `command/execute` for remote commands from `system_api`.
- [ ] **Batch Executive (System API):**
    - [ ] Implement the core Batch Executive logic for interpreting and executing recipes (PFC).
    - [ ] Integrate real-time data from NATS (`pvs/update`, `phase/state`) for condition evaluation.
    - [ ] Send control commands to `edge_device_controller` via NATS (`command/execute`).
    - [ ] Manage batch lifecycle (Start, Hold, Abort, Complete).
- [ ] **Data Management (System API):**
    - [ ] Implement persistent storage for Physical Model data (PostgreSQL).
    - [ ] Implement persistent storage for Recipe Model data (PostgreSQL).
    - [ ] Implement persistent storage for User and RBAC data (PostgreSQL).
    - [ ] Implement full Electronic Batch Record (EBR) generation, storage, and retrieval (TimescaleDB/InfluxDB for process data, PostgreSQL for metadata).
    - [ ] Implement NATS Request-Reply endpoint for historical process data retrieval from time-series DB.
- [X] **SMBus Integration (Edge Device Controller):**
    - [X] Implement SMBus read/write block frame functionality in `edge_device_controller`.
    - [X] Allow SMBus address and bus number to be configurable.
    - [X] Integrate SMBus operations with NATS command reception (`command/execute`).

## API Contracts (Backend-specific implementation details)
- [ ] Implement REST API endpoints for:
    - [ ] `/api/physical-models` (GET, POST) for listing/creating equipment hierarchies.
    - [ ] `/api/recipes` (GET, POST) for listing/creating master recipe templates.
    - [ ] `/api/batches` (POST) for creating & starting a batch from a recipe.
    - [ ] `/api/batches/{id}/command` (PUT) for sending commands (HOLD, ABORT) to a batch.
    - [ ] `/api/provision/request` (POST) for requesting authorization for new edge System API instances.
    - [ ] `/api/provision/approve/{id}` (PUT) for administrators to approve/reject provisioning requests.
- [ ] Implement NATS Publish-Subscribe mechanisms for:
    - [ ] Subscribing to `pvs/update` (from firmware) for real-time sensor PV updates.
    - [ ] Subscribing to `phase/state` (from firmware) for phase state changes.
    - [ ] Publishing to `command/execute` (to firmware) for control commands.
    - [ ] Implementing Request-Reply for fetching historical data from the time-series database.

## Non-Functional Requirements (Backend Specific)
- [ ] Implement HTTPS/WSS/TLS for all communication where applicable.
- [ ] Implement API Identity & Provisioning for `system_api` instances.

## Frontend (Web UI) Development (Moved to `TODO.md`)

## Backlog Milestones
- [ ] Add HTML demo
- [ ] Add Frontend demo
- [ ] Rebuild UI with Tailwind and Angular Signals for dynamic UUID monitors
- [ ] Add NATS channel builder and telemetry subscriber classes
- [ ] Migrate device communication to NATS; updated API and telemetry
- [ ] Audit Traefik API security
