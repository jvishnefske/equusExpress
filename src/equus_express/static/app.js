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
