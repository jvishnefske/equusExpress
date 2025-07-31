# MVP Checklist

This document outlines the minimum viable product (MVP) features for the project.

## 🔌 NATS Integration
- [ ] Real-time connection status indicator
- [ ] Configurable NATS server URL
- [ ] Channel subscription management
- [ ] Automatic reconnection handling

## 📊 Dynamic UI Components
- [ ] Analog Widgets: Display converted values with units, ranges, and real-time charts
- [ ] Digital Widgets: Visual indicators for binary states (ON/OFF)
- [ ] Widgets are created/destroyed dynamically based on channel selection
- [ ] Each widget includes historical data visualization

## 🔧 Data Models & UI State Management
- [ ] Implement UI components to display and edit Physical Model data (fetched via REST API)
- [ ] Implement UI components to display and edit Recipe Model data (Blockly integration for PFC, fetched via REST API)
- [ ] Display and manage structured configuration data (e.g., models, recipes, users)
- [ ] Display real-time and historical high-volume process data (fetched via NATS Pub/Sub from System API)
- [ ] Implement UI-side unit conversion for various sensor types (e.g., °C, %RH, kPa, V)

## 🤝 API Communication
- [ ] Implement REST API client calls for Physical Model management (GET, POST)
- [ ] Implement REST API client calls for Recipe management (GET, POST)
- [ ] Implement REST API client calls for Batch creation and control (POST, PUT for commands like HOLD, ABORT)
- [ ] Subscribe to NATS topics for real-time Process Variable (PV) updates (`pvs/update`)
- [ ] Subscribe to NATS topics for real-time phase state updates (`phase/state`)
- [ ] Implement NATS Request-Reply for fetching historical data (e.g., from time-series DB via System API)

## 📈 Real-Time Data Visualization
- [ ] Integrate Chart.js for live updating charts
- [ ] Ensure smooth animations and responsive design for data visualizations
- [ ] Display historical data trending (e.g., last 20 data points from NATS-fed history)
- [ ] Implement color-coded status indicators for various data points and states

## 🔍 Diagnostic Section
- [ ] Display system event logs with timestamps (received via NATS)
- [ ] Monitor and display NATS connection status
- [ ] Display current NATS channel subscriptions
- [ ] Present error handling and reporting messages to the user
- [ ] Implement auto-scrolling log display (e.g., last 20 entries)

## 🎛️ Control Features
- [ ] Implement UI elements for Batch Control actions (Start, Hold, Abort batch) that trigger REST API calls
- [ ] Implement UI for sending commands to firmware via NATS Request-Reply (through System API)
- [ ] Display real-time data updates (e.g., simulated 1Hz for initial development)
- [ ] Implement channel selection UI in sidebar for data display/monitoring
- [ ] Implement widget management UI (add/remove widgets from display)
