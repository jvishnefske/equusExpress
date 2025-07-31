# Industrial IoT System - MVP Requirements

## 1. Authentication & Session Management
* [ ] **req-1.1:** The system SHALL allow new users to register with a username and password.
* [ ] **req-1.2:** The system SHALL allow users to log in using a username and password.
* [ ] **req-1.3:** The system SHALL support the initiation of WebAuthn (Passkey) registration.
* [ ] **req-1.4:** The system SHALL support the completion of WebAuthn (Passkey) registration.
* [ ] **req-1.5:** The system SHALL support the initiation of WebAuthn (Passkey) authentication.
* [ ] **req-1.6:** The system SHALL support the completion of WebAuthn (Passkey) authentication, issuing an access token upon success.
* [ ] **req-1.7:** The system SHALL implement JWT-based session management for API access.
* [ ] **req-1.8:** The system SHALL provide secure token refresh mechanisms.

## 2. Multi-Tenant Management
* [ ] **req-2.1:** The system SHALL allow authenticated administrators to create and manage tenant organizations.
* [ ] **req-2.2:** The system SHALL enforce data isolation between tenants at all system layers.
* [ ] **req-2.3:** The system SHALL assign users to specific tenants during registration or by administrator action.
* [ ] **req-2.4:** The system SHALL generate unique NATS subject hierarchies for each tenant (e.g., `tenant.{tenant_id}.*`).
* [ ] **req-2.5:** The system SHALL prevent cross-tenant data access through subject-level security policies.
* [ ] **req-2.6:** The system SHALL allow tenant administrators to manage users within their tenant scope.

## 3. User Management
* [ ] **req-3.1:** The system SHALL allow authenticated administrators to retrieve a list of all registered users within their tenant scope.
* [ ] **req-3.2:** The system SHALL allow authenticated administrators to retrieve details for a specific user by ID.
* [ ] **req-3.3:** The system SHALL allow authenticated administrators to update user information (e.g., username, status).
* [ ] **req-3.4:** The system SHALL allow authenticated administrators to disable (soft delete) a user account.
* [ ] **req-3.5:** The system SHALL allow authenticated administrators to change a user's password.
* [ ] **req-3.6:** The system SHALL allow an authenticated user to change their own password.
* [ ] **req-3.7:** The system SHALL allow an authenticated user to view their own profile information.
* [ ] **req-3.8:** The system SHALL allow an authenticated user to list their registered passkeys.
* [ ] **req-3.9:** The system SHALL allow an authenticated user to delete their registered passkeys.

## 4. Role & Permission Management
* [ ] **req-4.1:** The system SHALL allow authenticated administrators to retrieve a list of all defined roles within their tenant.
* [ ] **req-4.2:** The system SHALL allow authenticated administrators to create new roles.
* [ ] **req-4.3:** The system SHALL allow authenticated administrators to update existing roles.
* [ ] **req-4.4:** The system SHALL allow authenticated administrators to delete roles.
* [ ] **req-4.5:** The system SHALL allow authenticated administrators to assign a specific permission to a role.
* [ ] **req-4.6:** The system SHALL allow authenticated administrators to remove a specific permission from a role.
* [ ] **req-4.7:** The system SHALL allow authenticated administrators to assign a role to a user.
* [ ] **req-4.8:** The system SHALL allow authenticated administrators to remove a role from a user.
* [ ] **req-4.9:** The system SHALL allow authenticated users to retrieve a list of all available permissions.

## 5. Group Management
* [ ] **req-5.1:** The system SHALL allow authenticated administrators to retrieve a list of all defined groups within their tenant.
* [ ] **req-5.2:** The system SHALL allow authenticated administrators to create new groups.
* [ ] **req-5.3:** The system SHALL allow authenticated administrators to update existing groups.
* [ ] **req-5.4:** The system SHALL allow authenticated administrators to delete groups.
* [ ] **req-5.5:** The system SHALL allow authenticated administrators to assign a user to a group.
* [ ] **req-5.6:** The system SHALL allow authenticated administrators to remove a user from a group.
* [ ] **req-5.7:** The system SHALL allow authenticated administrators to retrieve a list of members for a specific group.

## 6. Device Provisioning & Registration
* [ ] **req-6.1:** The system SHALL accept device provisioning requests containing serial number and device-generated public key.
* [ ] **req-6.2:** The system SHALL validate device serial numbers against a pre-authorized device registry.
* [ ] **req-6.3:** The system SHALL generate unique device identifiers and associate them with tenant accounts.
* [ ] **req-6.4:** The system SHALL create NATS user accounts for each provisioned device with tenant-scoped subject permissions.
* [ ] **req-6.5:** The system SHALL provide device credentials (NATS username/password or JWT) upon successful provisioning.
* [ ] **req-6.6:** The system SHALL support device re-provisioning with public key rotation.
* [ ] **req-6.7:** The system SHALL maintain a device registry with provisioning status, last seen timestamp, and firmware version.
* [ ] **req-6.8:** The system SHALL allow administrators to approve or reject pending device provisioning requests.

## 7. NATS Configuration Management
* [ ] **req-7.1:** The system SHALL generate NATS server configuration files including account definitions and subject permissions.
* [ ] **req-7.2:** The system SHALL create tenant-isolated NATS accounts with appropriate subject hierarchies.
* [ ] **req-7.3:** The system SHALL configure device NATS accounts with publish permissions for telemetry subjects (`tenant.{id}.device.{device_id}.telemetry.*`).
* [ ] **req-7.4:** The system SHALL configure device NATS accounts with subscribe permissions for command subjects (`tenant.{id}.device.{device_id}.commands.*`).
* [ ] **req-7.5:** The system SHALL configure user NATS accounts with appropriate pub/sub permissions based on roles and tenant membership.
* [ ] **req-7.6:** The system SHALL support dynamic NATS configuration updates without server restart.

## 8. Device Management & Configuration
* [ ] **req-8.1:** The system SHALL allow authenticated users to view a list of all devices within their tenant.
* [ ] **req-8.2:** The system SHALL allow authenticated users to view device details including status, firmware version, and last seen timestamp.
* [ ] **req-8.3:** The system SHALL provide a web interface for editing device configuration parameters.
* [ ] **req-8.4:** The system SHALL support over-the-air configuration updates via NATS messaging.
* [ ] **req-8.5:** The system SHALL allow users to send control commands to devices through the NATS pub/sub system.
* [ ] **req-8.6:** The system SHALL support device firmware update initiation and progress tracking.
* [ ] **req-8.7:** The system SHALL maintain device configuration history and allow rollback to previous configurations.

## 9. Real-time Data Streaming & Telemetry
* [ ] **req-9.1:** The system SHALL receive and process real-time sensor data from devices via NATS subjects.
* [ ] **req-9.2:** The system SHALL provide WebSocket endpoints for real-time data streaming to web clients.
* [ ] **req-9.3:** The system SHALL implement data aggregation and downsampling for historical data storage.
* [ ] **req-9.4:** The system SHALL support subscription to specific device telemetry streams based on user permissions.
* [ ] **req-9.5:** The system SHALL provide real-time dashboards displaying current device status and sensor readings.
* [ ] **req-9.6:** The system SHALL implement alerting based on configurable thresholds and device status changes.
* [ ] **req-9.7:** The system SHALL store telemetry data with appropriate retention policies per tenant requirements.

## 10. API Documentation & Web Frontend
* [ ] **req-10.1:** The system SHALL serve a web frontend providing user interface for device management and monitoring.
* [ ] **req-10.2:** The system SHALL generate OpenAPI-compliant documentation for all REST endpoints.
* [ ] **req-10.3:** The system SHALL provide interactive API documentation (Swagger UI) for developers.
* [ ] **req-10.4:** The system SHALL serve responsive web interfaces compatible with mobile and desktop browsers.
* [ ] **req-10.5:** The system SHALL implement real-time UI updates using WebSocket connections.

## 11. Physical Model Management
* [ ] **req-11.1:** The system SHALL allow authenticated users to define and manage physical asset hierarchies (Physical Models) within their tenant.
* [ ] **req-11.2:** The system SHALL allow authenticated users to associate Equipment Modules and Control Modules with specific firmware bindings.
* [ ] **req-11.3:** The system SHALL support hierarchical device organization (sites, areas, production lines, equipment).
* [ ] **req-11.4:** The system SHALL allow assignment of devices to physical model entities.

## 12. Recipe Management
* [ ] **req-12.1:** The system SHALL allow authenticated users to define reusable equipment phases with configurable parameters.
* [ ] **req-12.2:** The system SHALL allow authenticated users to create and manage master recipe templates, including procedural flow control (PFC) logic.
* [ ] **req-12.3:** The system SHALL provide a graphical user interface for building recipes using SFC elements (Step, Transition, Parallel Branch, Selection Branch).
* [ ] **req-12.4:** The system SHALL provide a no-code interface for building transition conditions using boolean logic and system tags.

## 13. Batch Execution & Control
* [ ] **req-13.1:** The system SHALL allow authenticated users to create and initiate a batch from a master recipe.
* [ ] **req-13.2:** The system SHALL host a Batch Executive to interpret and execute recipes.
* [ ] **req-13.3:** The Batch Executive SHALL continuously evaluate recipe transition conditions based on real-time data.
* [ ] **req-13.4:** The Batch Executive SHALL send high-level commands to the Control Tier based on recipe steps via NATS messaging.
* [ ] **req-13.5:** The system SHALL allow authenticated users to send control commands (e.g., HOLD, ABORT) to a running batch.

## 14. Device Communication & Edge Intelligence
* [ ] **req-14.1:** Edge devices SHALL execute primitive commands received from the Application Tier via NATS subjects.
* [ ] **req-14.2:** Edge devices SHALL translate logical commands into physical I/O operations.
* [ ] **req-14.3:** Edge devices SHALL publish sensor data and state changes to tenant-specific NATS subjects.
* [ ] **req-14.4:** Edge devices SHALL implement a watchdog timer to transition hardware to a safe state if server communication is lost.
* [ ] **req-14.5:** Edge devices SHALL support secure connection to NATS using device-specific credentials.
* [ ] **req-14.6:** Edge devices SHALL implement local data buffering during network connectivity issues.
* [ ] **req-14.7:** Edge devices SHALL support configuration updates received via NATS messaging.

## 15. Security & Data Integrity
* [ ] **req-15.1:** All communication SHALL be encrypted using TLS/SSL (HTTPS, WSS, NATS TLS).
* [ ] **req-15.2:** Device authentication SHALL use public key cryptography with device-generated keypairs.
* [ ] **req-15.3:** The system SHALL implement message signing for critical control commands.
* [ ] **req-15.4:** The system SHALL generate an immutable Electronic Batch Record (EBR) for every batch, logging operator commands, state changes, alarms, and periodic PV snapshots.
* [ ] **req-15.5:** The system SHALL implement audit logging for all configuration changes and administrative actions.
* [ ] **req-15.6:** The system SHALL support certificate-based device authentication for enhanced security.

## 16. System Administration & Monitoring
* [ ] **req-16.1:** The system SHALL allow authenticated administrators to view a filtered list of audit logs (by limit, offset, event type, user ID, IP address, description keyword).
* [ ] **req-16.2:** The system SHALL provide an emergency break-glass access mechanism via a special code.
* [ ] **req-16.3:** The system SHALL provide a health check endpoint to verify service status.
* [ ] **req-16.4:** The system SHALL serve the admin portal frontend HTML page at the root URL.
* [ ] **req-16.5:** The system SHALL monitor NATS server health and connection status.
* [ ] **req-16.6:** The system SHALL provide system metrics and performance monitoring dashboards.
* [ ] **req-16.7:** The system SHALL support automated backup and recovery procedures for configuration and historical data.

## 17. Integration & Extensibility
* [ ] **req-17.1:** The system SHALL provide webhook endpoints for integration with external systems.
* [ ] **req-17.2:** The system SHALL support plugin architecture for custom data processing and alerting rules.
* [ ] **req-17.3:** The system SHALL provide data export capabilities in standard formats (CSV, JSON, XML).
* [ ] **req-17.4:** The system SHALL support integration with time-series databases for long-term data storage.
