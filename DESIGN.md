Of course. Here is a `DESIGN.md` file that distills the essential technical information into a concise guide for your development team, keeping the 6-page constraint in mind.

---

# Bioreactor Control System: Technical Design

**Version:** 1.0  
**Status:** DRAFT  
**Audience:** Engineering Team (Frontend, Backend, Firmware)

## 1. Guiding Principles & Core Philosophy

This document outlines the technical design for a web-based, ISA-88 compliant PLC interface. Our success hinges on one core principle: the strict **separation of the procedural recipe from the equipment control logic**.

-   **The Recipe (The "What")**: Defines the process strategy. This logic lives on the server and is created by users in our web UI. It contains **no** hardware-specific code.
-   **Equipment Control (The "How")**: The basic actions the hardware can perform (e.g., heat, agitate). This logic is implemented once in the firmware and is reused across all recipes.

Our system is a **Recipe Orchestration Engine**, not a low-level PLC programmer. The firmware is a simple, robust command executor. The server contains the complex procedural logic. This architecture is our blueprint for building a flexible, reusable, and maintainable system.

---

## 2. System Architecture

We will implement a three-tier architecture that clearly delineates responsibilities.



1.  **Presentation Tier (Web UI)**
    -   A Single-Page Application (SPA) running in a standard web browser.
    -   Responsible for all user interaction: model configuration, recipe authoring, and the real-time Operator HMI.
    -   Communicates with the server via a REST API (for configuration) and WebSockets (for real-time data).

2.  **Application Tier (Web Server)**
    -   The "brain" of the system.
    -   Hosts the **Batch Executive**, the engine that interprets and executes recipes.
    -   Provides the REST API for CRUD operations on models and recipes.
    -   Manages the WebSocket-based publish-subscribe (Pub/Sub) hub for real-time communication.
    -   Leverages **NATS** for all real-time publish-subscribe messaging.
    -   Handles user authentication and Role-Based Access Control (RBAC).

3.  **Control Tier (Microcontroller/Firmware)**
    -   A **Hardware Abstraction Layer (HAL)**. Its sole responsibility is to execute primitive commands and report sensor data/state changes.
    -   It contains **no recipe-specific logic**.
    -   It communicates with the server via a lightweight, real-time protocol (e.g., MQTT or custom protocol over a TCP socket).
    -   It communicates with the server via **NATS**.
    -   It **must** implement a watchdog timer to fail-safe if server communication is lost.

---

## 3. Data Models & API Contracts

This section defines the critical data structures and communication protocols that enable parallel development across the team.

### 3.1. Physical Model Data Structure

This is how we represent the physical equipment hierarchy. It will be stored in the database and manipulated via the REST API.

```json
{
  "id": "pm_12345",
  "name": "Bioreactor_Cell_01",
  "type": "ProcessCell",
  "children": [
    {
      "id": "unit_67890",
      "name": "BR-101",
      "type": "Unit",
      "children": [
        {
          "id": "em_abcde",
          "name": "TemperatureControlSystem",
          "type": "EquipmentModule",
          "children": [
            {
              "id": "cm_fghij",
              "name": "HeaterValve",
              "type": "ControlModule",
              "binding": "mcu.digital_out.0"
            },
            {
              "id": "cm_klmno",
              "name": "TemperatureSensor",
              "type": "ControlModule",
              "binding": "mcu.analog_in.1"
            }
          ]
        }
      ]
    }
  ]
}
```

### 3.2. Recipe Model Data Structure (PFC)

This is the output of our graphical Recipe Editor. It represents the procedural logic that the Batch Executive will interpret.

```json
{
  "id": "recipe_pqrst",
  "name": "Standard Fermentation",
  "version": "1.0.0",
  "startStep": "step_1",
  "steps": [
    {
      "id": "step_1",
      "phase": "HEAT",
      "parameters": { "TargetTemp": 85.0 },
      "transitionTo": "step_2",
      "transitionCondition": {
        "logic": "AND",
        "conditions": [
          { "tag": "BR101.TEMP.PV", "op": ">=", "value": 84.5 },
          { "tag": "HEAT.State", "op": "==", "value": "COMPLETE" }
        ]
      }
    },
    {
      "id": "step_2",
      "phase": "AGITATE",
      "parameters": { "Speed": 200 },
      "transitionTo": "step_3",
      "transitionCondition": {
        "logic": "AND",
        "conditions": [ { "type": "delay", "value": "30m" } ]
      }
    }
  ]
}
```

### 3.3. API Contracts

#### REST API (Configuration - Stateless)

| Resource         | Endpoint                      | Method        | Description                               |
| ---------------- | ----------------------------- | ------------- | ----------------------------------------- |
| Physical Model   | `/api/physical-models`        | GET, POST     | List or create physical asset hierarchies.|
| Recipes          | `/api/recipes`                | GET, POST     | List or create master recipe templates.   |
| Batches          | `/api/batches`                | POST          | Create & start a batch from a recipe.     |
| Batch Control    | `/api/batches/{id}/command`   | PUT           | Send commands (HOLD, ABORT) to a batch.   |

#### NATS Publish-Subscribe Topics (Real-Time - Stateful)

| Topic Name         | Publisher  | Subscriber | Purpose                                       |
| ------------------ | ---------- | ---------- | --------------------------------------------- |
| `pvs/update`       | Firmware   | Server, UI | Real-time sensor Process Variable (PV) updates. |
| `command/execute`  | Server     | Firmware   | High-level command from the Batch Executive.  |
| `phase/state`      | Firmware   | Server     | Firmware reports a phase state change (e.g., COMPLETE). |
| `batch/status`     | Server     | UI         | Overall batch status updates for the HMI.     |
| `batch/alarm`      | Server     | UI         | Broadcasts process alarms to clients.         |

---

## 4. Key Component Implementation

### 4.1. Firmware: The Primitive Executor

The firmware's role is simple but critical. It is a **Hardware Abstraction Layer (HAL)**.
-   It listens for commands on the `command/execute` topic.
-   It listens for commands on the **NATS** `command/execute` topic.
-   It maintains the state for each phase (IDLE, RUNNING, HOLDING, etc.).
-   It translates logical commands into physical I/O operations.
-   It publishes sensor data on `pvs/update` and phase state changes on `phase/state`.
-   It publishes sensor data on the **NATS** `pvs/update` topic and phase state changes on the `phase/state` topic.
-   **It does NOT contain any recipe logic or transition conditions.**

**Example Primitive Functions to Implement:**
-   `HEAT(target_temp)`
-   `AGITATE(speed)`
-   `ADD_LIQUID(pump_id, volume)`
-   `AWAIT_CONDITION(sensor, operator, value, timeout)`
-   `SET_DIGITAL_OUT(channel, state)`

### 4.2. Server: The Batch Executive

This is the core execution engine on the backend. Its primary loop for a running batch is:
1.  Identify the current active step(s) in the recipe's PFC.
2.  Continuously monitor incoming real-time data (`pvs/update`, `phase/state`).
3.  Evaluate the transition condition(s) for the active step(s).
4.  When a transition condition evaluates to `true`:
    -   Log the transition in the Electronic Batch Record (EBR).
    -   Identify the next step(s).
    -   Send the corresponding command(s) for the new phase(s) to the firmware via the `command/execute` topic.
    -   Send the corresponding command(s) for the new phase(s) to the firmware via the **NATS** `command/execute` topic.
5.  Repeat from step 1.

### 4.3. Frontend: The Graphical Recipe Editor

This is the most complex UI component. It must be intuitive for non-programmers.
-   **Canvas:** Use a dedicated diagramming library (**JointJS+, React Flow, GoJS**) to build a graphical PFC/SFC editor.
-   **Elements:** The editor toolbox must provide standard SFC elements: Step, Transition, Parallel Branch, and Selection Branch.
-   **No-Code Transition Builder:** This is a critical requirement. When a user selects a transition, a modal or side panel must open with a rule builder. The user will construct boolean logic using dropdown menus (for tags and operators) and input fields, not by writing code.

---

## 5. Core User & System Flows

### 5.1. Design-Time Flow: Creating a Recipe

1.  **Engineer** uses the **Physical Model Editor** (tree view) to define the bioreactor's Units, EMs, and CMs, binding them to firmware tags. This is saved via the REST API.
2.  **Engineer** defines reusable **Equipment Phases** (e.g., HEAT) and associates them with their parent Equipment Module. They define the phase parameters (e.g., `TargetTemp`).
3.  **Scientist** opens the **Graphical Recipe Editor**.
4.  They drag-and-drop steps and transitions onto the canvas to build the PFC.
5.  For each step, they select a pre-defined Phase (e.g., HEAT) and provide a value for its parameters (e.g., `85.0`).
6.  For each transition, they use the **No-Code Transition Builder** to define the gating logic.
7.  The completed recipe JSON is saved to the server via the REST API.

### 5.2. Run-Time Flow: Executing a Batch

1.  **Operator** selects a master recipe on the HMI and clicks "Start Batch". This sends a POST request to `/api/batches`.
2.  The **Server** creates a control recipe instance (a batch) and starts the **Batch Executive**.
3.  The **Batch Executive** reads the first step of the recipe (e.g., HEAT phase).
4.  It sends a command to the `command/execute` topic: `{ "cmd": "HEAT", "params": {"target_temp": 85.0} }`.
5.  The **Firmware** receives the command, transitions the HEAT phase to `RUNNING`, and begins activating the heater. It publishes the new state on the `phase/state` topic.
4.  It sends a command to the **NATS** `command/execute` topic: `{ "cmd": "HEAT", "params": {"target_temp": 85.0} }`.
5.  The **Firmware** receives the command via NATS, transitions the HEAT phase to `RUNNING`, and begins activating the heater. It publishes the new state on the **NATS** `phase/state` topic.
6.  The **Server** receives the state update and relays it to the **HMI**, which highlights the step as active.
7.  The **Firmware** continuously publishes temperature updates on the **NATS** `pvs/update` topic. The HMI displays this data in real-time.
8.  The **Batch Executive** continuously evaluates the transition condition (`BR101.TEMP.PV >= 84.5`).
9.  Once the temperature is reached, the firmware reports the phase `COMPLETE` on `phase/state`.
9.  Once the temperature is reached, the firmware reports the phase `COMPLETE` on the **NATS** `phase/state` topic.
10. The **Batch Executive** sees the `COMPLETE` state, evaluates the transition as `true`, and proceeds to the next step in the recipe. This cycle repeats until the recipe ends.

---

## 6. Non-Functional Requirements & Technology

-   **Security**: **Role-Based Access Control (RBAC) is mandatory**. At minimum: Administrator, Engineer, Operator. All communication must be encrypted (HTTPS/WSS/TLS).
-   **Reliability**: **Firmware watchdog is non-negotiable**. If communication is lost, the firmware must transition hardware to a pre-defined safe state.
-   **Data Integrity**: The system **must** generate an immutable **Electronic Batch Record (EBR)** for every batch, logging all operator commands, state changes, alarms, and periodic PV snapshots.
-   **Technology Stack Recommendation**:
    -   **Frontend:** React or Vue with a dedicated diagramming library.
    -   **Backend:** Node.js (with TypeScript) or Python (with FastAPI) for strong async/WebSocket support.
    -   **Database:** A dual-database approach is recommended.
        -   **Relational (PostgreSQL):** For structured configuration data (models, recipes, users).
        -   **Time-Series (TimescaleDB, InfluxDB):** For high-volume process data for the EBR and trend charts.
    -   **Real-time Messaging:** NATS (for all Pub/Sub communication).
