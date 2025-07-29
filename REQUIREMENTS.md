# Equus Express Telemetry and Configuration Portal - MVP Functional Requirements

This document outlines the Minimum Viable Product (MVP) functional requirements for the Local Admin Portal, derived from the documented API endpoints and core features. Each requirement is prefixed with `req-`.

## 1. Authentication & Session Management

* [ ] **req-1.1:** The system SHALL allow new users to register with a username and password.
* [ ] **req-1.2:** The system SHALL allow users to log in using a username and password.
* [ ] **req-1.3:** The system SHALL support the initiation of WebAuthn (Passkey) registration.
* [ ] **req-1.4:** The system SHALL support the completion of WebAuthn (Passkey) registration.
* [ ] **req-1.5:** The system SHALL support the initiation of WebAuthn (Passkey) authentication.
* [ ] **req-1.6:** The system SHALL support the completion of WebAuthn (Passkey) authentication, issuing an access token upon success.

## 2. User Management

* [ ] **req-2.1:** The system SHALL allow authenticated administrators to retrieve a list of all registered users.
* [ ] **req-2.2:** The system SHALL allow authenticated administrators to retrieve details for a specific user by ID.
* [ ] **req-2.3:** The system SHALL allow authenticated administrators to update user information (e.g., username, status).
* [ ] **req-2.4:** The system SHALL allow authenticated administrators to disable (soft delete) a user account.
* [ ] **req-2.5:** The system SHALL allow authenticated administrators to change a user's password.
* [ ] **req-2.6:** The system SHALL allow an authenticated user to change their own password.
* [ ] **req-2.7:** The system SHALL allow an authenticated user to view their own profile information.
* [ ] **req-2.8:** The system SHALL allow an authenticated user to list their registered passkeys.
* [ ] **req-2.9:** The system SHALL allow an authenticated user to delete their registered passkeys.

## 3. Role & Permission Management

* [ ] **req-3.1:** The system SHALL allow authenticated administrators to retrieve a list of all defined roles.
* [ ] **req-3.2:** The system SHALL allow authenticated administrators to create new roles.
* [ ] **req-3.3:** The system SHALL allow authenticated administrators to update existing roles.
* [ ] **req-3.4:** The system SHALL allow authenticated administrators to delete roles.
* [ ] **req-3.5:** The system SHALL allow authenticated administrators to assign a specific permission to a role.
* [ ] **req-3.6:** The system SHALL allow authenticated administrators to remove a specific permission from a role.
* [ ] **req-3.7:** The system SHALL allow authenticated administrators to assign a role to a user.
* [ ] **req-3.8:** The system SHALL allow authenticated administrators to remove a role from a user.
* [ ] **req-3.9:** The system SHALL allow authenticated users to retrieve a list of all available permissions.

## 4. Group Management

* [ ] **req-4.1:** The system SHALL allow authenticated administrators to retrieve a list of all defined groups.
* [ ] **req-4.2:** The system SHALL allow authenticated administrators to create new groups.
* [ ] **req-4.3:** The system SHALL allow authenticated administrators to update existing groups.
* [ ] **req-4.4:** The system SHALL allow authenticated administrators to delete groups.
* [ ] **req-4.5:** The system SHALL allow authenticated administrators to assign a user to a group.
* [ ] **req-4.6:** The system SHALL allow authenticated administrators to remove a user from a group.
* [ ] **req-4.7:** The system SHALL allow authenticated administrators to retrieve a list of members for a specific group.

## 5. Audit & System Utilities

* [ ] **req-5.1:** The system SHALL allow authenticated administrators to view a filtered list of audit logs (by limit, offset, event type, user ID, IP address, description keyword).
* [ ] **req-5.2:** The system SHALL provide an emergency break-glass access mechanism via a special code.
* [ ] **req-5.3:** The system SHALL provide a health check endpoint to verify service status.
* [ ] **req-5.4:** The system SHALL serve the admin portal frontend HTML page at the root URL.

## 6. Physical Model Management
* [ ] **req-6.1:** The system SHALL allow authenticated users to define and manage physical asset hierarchies (Physical Models).
* [ ] **req-6.2:** The system SHALL allow authenticated users to associate Equipment Modules and Control Modules with specific firmware bindings.

## 7. Recipe Management
* [ ] **req-7.1:** The system SHALL allow authenticated users to define reusable equipment phases with configurable parameters.
* [ ] **req-7.2:** The system SHALL allow authenticated users to create and manage master recipe templates, including procedural flow control (PFC) logic.
* [ ] **req-7.3:** The system SHALL provide a graphical user interface for building recipes using SFC elements (Step, Transition, Parallel Branch, Selection Branch).
* [ ] **req-7.4:** The system SHALL provide a no-code interface for building transition conditions using boolean logic and system tags.

## 8. Batch Execution & Control
* [ ] **req-8.1:** The system SHALL allow authenticated users to create and initiate a batch from a master recipe.
* [ ] **req-8.2:** The system SHALL host a Batch Executive to interpret and execute recipes.
* [ ] **req-8.3:** The Batch Executive SHALL continuously evaluate recipe transition conditions based on real-time data.
* [ ] **req-8.4:** The Batch Executive SHALL send high-level commands to the Control Tier based on recipe steps.
* [ ] **req-8.5:** The system SHALL allow authenticated users to send control commands (e.g., HOLD, ABORT) to a running batch.

## 9. Real-time Data & HMI
* [ ] **req-9.1:** The system SHALL publish real-time sensor Process Variable (PV) updates to clients.
* [ ] **req-9.2:** The system SHALL publish real-time phase state changes (e.g., COMPLETE) from the Control Tier to the Application Tier and UI.
* [ ] **req-9.3:** The system SHALL broadcast overall batch status updates to the HMI.
* [ ] **req-9.4:** The system SHALL broadcast process alarms to clients.
* [ ] **req-9.5:** The system SHALL provide a real-time Operator HMI displaying current batch status and process data.

## 10. Device Communication & Firmware
* [ ] **req-10.1:** The Control Tier (firmware) SHALL execute primitive commands received from the Application Tier.
* [ ] **req-10.2:** The Control Tier (firmware) SHALL translate logical commands into physical I/O operations.
* [ ] **req-10.3:** The Control Tier (firmware) SHALL publish sensor data and phase state changes to the Application Tier.
* [ ] **req-10.4:** The Control Tier (firmware) SHALL implement a watchdog timer to transition hardware to a safe state if server communication is lost.
* [ ] **req-10.5:** The system SHALL allow device clients to register their public keys with the server.
* [ ] **req-10.6:** The system SHALL allow device clients to send telemetry and status updates to the server.
* [ ] **req-10.7:** The system SHALL provide a web dashboard to view connected devices and their latest telemetry data.

## 11. Data Integrity & Security
* [ ] **req-11.1:** The system SHALL generate an immutable Electronic Batch Record (EBR) for every batch, logging operator commands, state changes, alarms, and periodic PV snapshots.
* [ ] **req-11.2:** All communication on public communication channels SHALL be encrypted (HTTPS/WSS/TLS).
