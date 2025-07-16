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
- [ ] **NATS Integration:**
    - [ ] Implement NATS connection and subscription/publication logic within `system_api`.
    - [ ] Configure `system_api` to use NATS `nkeys` or `tokens` for authentication.
- [ ] **Batch Executive:**
    - [ ] Implement the core Batch Executive logic for interpreting and executing recipes.
    - [ ] Integrate real-time data from NATS (`pvs/update`, `phase/state`) for condition evaluation.
    - [ ] Send control commands to `edge_device_controller` via NATS (`command/execute`).
- [ ] **Data Management:**
    - [ ] Implement persistent storage for system configurations (beyond initial setup).
    - [ ] Implement full Electronic Batch Record (EBR) generation, storage, and retrieval.
    - [ ] Integrate with a time-series database (e.g., TimescaleDB, InfluxDB) for high-volume process data.

## Frontend (Web UI) Development
- [ ] Develop the main Single-Page Application (SPA) frontend.
- [ ] Implement the Physical Model Editor (tree view for equipment hierarchy).
- [ ] Implement the Graphical Recipe Editor with SFC elements and a no-code transition builder.
- [ ] Develop the Operator HMI for real-time batch monitoring and control.
- [ ] Establish WebSocket connections for real-time data display.
