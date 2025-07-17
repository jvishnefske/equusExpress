// Helper function to generate a valid UUID (mock for client-side, actual UUIDs come from server)
// In a real application, device IDs would be retrieved from registered devices.
// This is just for demonstration if generating local mock IDs.
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// Class to build NATS channel names based on custom UUID format.
// This encapsulates the naming convention for different message types.
class NatsChannelBuilder {
    constructor(deviceId) {
        if (!deviceId) {
            throw new Error("DeviceId is required for NatsChannelBuilder.");
        }
        this.deviceId = deviceId;
    }

    /**
     * Builds the NATS subject for telemetry data.
     * @returns {string} The NATS subject for telemetry.
     */
    getTelemetrySubject() {
        return `telemetry.${this.deviceId}`;
    }

    /**
     * Builds the NATS subject for device commands.
     * @returns {string} The NATS subject for commands.
     */
    getCommandSubject() {
        return `commands.${this.deviceId}`;
    }

    /**
     * Builds the NATS subject for device status updates.
     * @returns {string} The NATS subject for status.
     */
    getStatusSubject() {
        return `status.${this.deviceId}`;
    }

    // Add other channel types as needed (e.g., config, logs)
}

// Custom wrapper for subscribing to NATS telemetry.
// This class assumes a NATS client library is available (e.g., loaded via CDN).
// For example, if using the official NATS.js client, you'd typically have `Nats.connect()` available.
class NatsTelemetrySubscriber {
    /**
     * @param {object} natsConnection - The connected NATS client instance.
     * @param {string} deviceId - The ID of the device to subscribe to.
     * @param {NatsChannelBuilder} channelBuilder - An instance of NatsChannelBuilder.
     */
    constructor(natsConnection, deviceId, channelBuilder) {
        if (!natsConnection) {
            console.warn("NATS connection not provided. Subscriptions will not be active.");
        }
        if (!deviceId) {
            throw new Error("DeviceId is required for NatsTelemetrySubscriber.");
        }
        this.natsConnection = natsConnection;
        this.channelBuilder = channelBuilder || new NatsChannelBuilder(deviceId);
        this.deviceId = deviceId;
        this.subscription = null;
    }

    /**
     * Subscribes to the telemetry channel for the specified device.
     * @param {function(msg: object)} callback - The function to call with incoming telemetry messages.
     */
    async subscribeToTelemetry(callback) {
        if (!this.natsConnection) {
            console.error("NATS connection not established. Cannot subscribe to telemetry.");
            return;
        }
        const subject = this.channelBuilder.getTelemetrySubject();
        try {
            console.log(`Attempting to subscribe to NATS telemetry for device: ${this.deviceId} on subject: ${subject}`);
            // Example using NATS.js client syntax:
            this.subscription = await this.natsConnection.subscribe(subject, {
                callback: (err, msg) => {
                    if (err) {
                        console.error(`Error receiving NATS message on ${subject}:`, err);
                        return;
                    }
                    try {
                        // NATS messages are typically byte arrays; convert to string then parse JSON
                        const telemetryData = JSON.parse(msg.data.toString());
                        callback(telemetryData);
                    } catch (e) {
                        console.error(`Failed to parse telemetry message from ${subject}:`, e, msg.data.toString());
                    }
                },
            });
            console.log(`Successfully subscribed to ${subject}`);
        } catch (e) {
            console.error(`Failed to subscribe to ${subject}:`, e);
        }
    }

    /**
     * Unsubscribes from the telemetry channel.
     */
    unsubscribe() {
        if (this.subscription) {
            this.subscription.unsubscribe();
            console.log(`Unsubscribed from telemetry for device: ${this.deviceId}`);
            this.subscription = null;
        }
    }
}

// Example Usage (commented out as NATS client library is not included in this file directly):
// To use these classes, you would first need to load a NATS client library
// For example, in your HTML head: <script src="https://unpkg.com/nats.ws@latest/bundles/nats.js"></script>
// Then, you could do something like:
// document.addEventListener('DOMContentLoaded', async () => {
//     const testDeviceId = "some_device_uuid"; // Replace with actual device ID
//     const natsUrl = "ws://localhost:4222"; // Replace with your NATS server URL
//
//     try {
//         // Assuming 'Nats' global object is available from the CDN
//         const nc = await Nats.connect({ servers: [natsUrl] });
//         console.log(`Connected to NATS ${nc.getServer()}`);
//
//         const channelBuilder = new NatsChannelBuilder(testDeviceId);
//         const telemetrySubscriber = new NatsTelemetrySubscriber(nc, testDeviceId, channelBuilder);
//
//         telemetrySubscriber.subscribeToTelemetry((telemetry) => {
//             console.log(`Received NATS Telemetry for ${testDeviceId}:`, telemetry);
//             // Update your UI here
//         });
//
//         // Remember to unsubscribe when no longer needed, e.g., on component unmount or page exit
//         // window.addEventListener('beforeunload', () => telemetrySubscriber.unsubscribe());
//
//         // If you were using Angular (from CDN or a build system), you might integrate these
//         // classes into an Angular Service or Component, typically injecting the NATS connection.
//         // e.g., in an Angular Service:
//         // import { Injectable } from '@angular/core';
//         // @Injectable({ providedIn: 'root' })
//         // export class TelemetryService {
//         //   private natsConnection: any; // Type 'any' for simplicity; use proper NATS types if available
//         //   constructor() {
//         //     // Initialize NATS connection here or inject it
//         //     Nats.connect({ servers: [natsUrl] }).then(nc => this.natsConnection = nc);
//         //   }
//         //   subscribeToDeviceTelemetry(deviceId: string): Observable<any> {
//         //     const channelBuilder = new NatsChannelBuilder(deviceId);
//         //     const subscriber = new NatsTelemetrySubscriber(this.natsConnection, deviceId, channelBuilder);
//         //     return new Observable(observer => {
//         //       subscriber.subscribeToTelemetry(telemetry => observer.next(telemetry));
//         //       return () => subscriber.unsubscribe(); // Cleanup on unsubscribe
//         //     });
//         //   }
//         // }
//
//     } catch (err) {
//         console.error(`Error connecting to NATS: ${err}`);
//     }
// });

// Existing functions continue below...

async function fetchDevices() {
    try {
        const response = await fetch('/api/admin/devices');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        const container = document.getElementById('devices-container');
        container.innerHTML = ''; // Clear loading message

        if (data.devices && data.devices.length > 0) {
            for (const device of data.devices) {
                const deviceCard = document.createElement('div');
                deviceCard.className = 'device-card';
                deviceCard.innerHTML = `
                    <h2>Device ID: ${device.device_id}</h2>
                    <p><strong>Status:</strong> ${device.status}</p>
                    <p><strong>Last Seen:</strong> ${new Date(device.last_seen).toLocaleString()}</p>
                    <p><strong>IP Address:</strong> ${device.ip_address}</p>
                    <h3>Latest Telemetry:</h3>
                    <div id="telemetry-${device.device_id}">Loading telemetry...</div>
                `;
                container.appendChild(deviceCard);
                fetchTelemetry(device.device_id);
            }
        } else {
            container.innerHTML = '<p class="no-devices">No devices registered yet.</p>';
        }
    } catch (error) {
        console.error('Error fetching devices:', error);
        document.getElementById('devices-container').innerHTML = '<p class="error-message">Error loading devices. Please check server logs.</p>';
    }
}

async function fetchTelemetry(deviceId) {
    try {
        const response = await fetch(`/api/admin/telemetry/${deviceId}?limit=1`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        const telemetryContainer = document.getElementById(`telemetry-${deviceId}`);
        if (data.telemetry && data.telemetry.length > 0) {
            const latestTelemetry = data.telemetry[0];
            telemetryContainer.innerHTML = `
                <p>Timestamp: ${new Date(latestTelemetry.timestamp).toLocaleString()}</p>
                <pre>${JSON.stringify(latestTelemetry.data, null, 2)}</pre>
            `;
        } else {
            telemetryContainer.innerHTML = '<p>No telemetry data available.</p>';
        }
    } catch (error) {
        console.error(`Error fetching telemetry for ${deviceId}:`, error);
        document.getElementById(`telemetry-${deviceId}`).innerHTML = '<p style="color: red;">Error loading telemetry.</p>';
    }
}

// Fetch data initially and then every 10 seconds
fetchDevices();
setInterval(fetchDevices, 10000); // Refresh every 10 seconds
