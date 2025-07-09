from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates # New import
import uvicorn
import ssl
import os
import sqlite3
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import logging
from pydantic import BaseModel
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import socket
from contextlib import asynccontextmanager # New import

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles startup and shutdown events for the application.
    Initializes the database on startup.
    """
    logger.info("Application starting up...")
    init_secure_db()
    yield
    logger.info("Application shutting down...")

app = FastAPI(title="Secure IoT API Server", lifespan=lifespan) # Updated FastAPI init
security = HTTPBearer()

# Initialize Jinja2Templates
templates = Jinja2Templates(directory="templates")

# Mount a static directory to serve files like favicon.ico
app.mount("/static", StaticFiles(directory="static"), name="static")


# Data models
class TelemetryData(BaseModel):
    device_id: str
    timestamp: str
    data: Dict[Any, Any]


class StatusUpdate(BaseModel):
    device_id: str
    status: str
    timestamp: str
    details: Optional[Dict[Any, Any]] = None


class DeviceConfig(BaseModel):
    device_id: str
    config: Dict[str, Any]

class PublicKeyRegistration(BaseModel):
    device_id: str
    public_key: str

# Database initialization
def init_secure_db():
    """Initialize the secure database for device management"""
    db_file = os.getenv("SQLITE_DB_PATH", 'secure_devices.db')
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    # Devices table
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS devices
                   (
                       device_id
                       TEXT
                       PRIMARY
                       KEY,
                       public_key
                       TEXT,
                       first_seen
                       TIMESTAMP
                       DEFAULT
                       CURRENT_TIMESTAMP,
                       last_seen
                       TIMESTAMP
                       DEFAULT
                       CURRENT_TIMESTAMP,
                       status
                       TEXT
                       DEFAULT
                       'unknown',
                       ip_address
                       TEXT,
                       device_info
                       TEXT
                   )
                   ''')

    # Telemetry table
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS telemetry
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       device_id
                       TEXT,
                       timestamp
                       TIMESTAMP,
                       data
                       TEXT,
                       received_at
                       TIMESTAMP
                       DEFAULT
                       CURRENT_TIMESTAMP,
                       FOREIGN
                       KEY
                   (
                       device_id
                   ) REFERENCES devices
                   (
                       device_id
                   )
                       )
                   ''')

    # Device status table
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS device_status
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       device_id
                       TEXT,
                       status
                       TEXT,
                       timestamp
                       TIMESTAMP,
                       details
                       TEXT,
                       received_at
                       TIMESTAMP
                       DEFAULT
                       CURRENT_TIMESTAMP,
                       FOREIGN
                       KEY
                   (
                       device_id
                   ) REFERENCES devices
                   (
                       device_id
                   )
                       )
                   ''')

    # Device configuration table
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS device_config
                   (
                       device_id
                       TEXT
                       PRIMARY
                       KEY,
                       config
                       TEXT,
                       updated_at
                       TIMESTAMP
                       DEFAULT
                       CURRENT_TIMESTAMP,
                       FOREIGN
                       KEY
                   (
                       device_id
                   ) REFERENCES devices
                   (
                       device_id
                   )
                       )
                   ''')

    conn.commit()
    conn.close()


# Placeholder for future authentication and device identification logic.
# This function will need to be replaced with logic that validates incoming requests
# based on the client's public key (e.g., signed JWTs or request bodies).
# For now, we will rely on device_id being passed in the payload for certain endpoints,
# and introduce a registration endpoint.
def get_authenticated_device_id(request: Request, device_id: Optional[str] = None) -> str:
    """
    Placeholder: Authenticates the client and returns their device ID.
    In a real system, this would verify a signature or token.
    For initial registration, this might not be called, or it might accept a temporary token.
    """
    # For now, we'll rely on the device_id passed in the body or path for non-registration endpoints.
    # This needs robust implementation for production (e.g., validating a signed payload or token).
    if device_id:
        return device_id
    # Attempt to get device_id from headers for initial compatibility or simple tests
    header_device_id = request.headers.get("X-Device-Id")
    if header_device_id:
        return header_device_id
    
    # If no device_id can be determined for an authenticated endpoint, raise an error
    raise HTTPException(status_code=401, detail="Authentication required: Device ID not provided or authenticated.")


def register_or_update_device(device_id: str, public_key: str, ip_address: str):
    """Register or update device in the database with its public key"""
    try:
        db_file = os.getenv("SQLITE_DB_PATH", 'secure_devices.db')
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Check if device exists
        cursor.execute("SELECT device_id FROM devices WHERE device_id = ?", (device_id,))
        exists = cursor.fetchone()

        if exists:
            # Update existing device's public key and last seen
            cursor.execute('''
                           UPDATE devices
                           SET last_seen  = CURRENT_TIMESTAMP,
                               public_key = ?,
                               ip_address = ?
                           WHERE device_id = ?
                           ''', (public_key, ip_address, device_id))
        else:
            # Insert new device with public key
            cursor.execute('''
                           INSERT INTO devices
                               (device_id, public_key, ip_address)
                           VALUES (?, ?, ?)
                           ''', (device_id, public_key, ip_address))

        conn.commit()
        conn.close()
        logger.info(f"Device {device_id} registered/updated with public key.")

    except Exception as e:
        logger.error(f"Failed to register/update device {device_id}: {e}")


@app.get("/")
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse("static/favicon.ico")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Simple dashboard to display device telemetry."""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Equus Express Dashboard</title>
        <style>
            body { font-family: sans-serif; margin: 20px; line-height: 1.6; }
            .container { max-width: 1200px; margin: auto; padding: 0 15px; }
            h1 { text-align: center; color: #333; }
            .device-card {
                border: 1px solid #ddd;
                padding: 20px;
                margin-bottom: 15px;
                border-radius: 8px;
                background-color: #f9f9f9;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }
            .device-card h2 { color: #0056b3; margin-top: 0; }
            .device-card p { margin: 5px 0; }
            pre {
                background-color: #eee;
                padding: 15px;
                border-radius: 5px;
                overflow-x: auto;
                font-family: 'Courier New', monospace;
                white-space: pre-wrap; /* Ensures long lines wrap */
                word-wrap: break-word; /* Ensures long words break */
            }
            .no-devices { text-align: center; color: #666; padding: 20px; }
            .error-message { color: red; text-align: center; padding: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Equus Express Device Dashboard</h1>
            <div id="devices-container">Loading devices...</div>
        </div>

        <script>
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
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.post("/api/register")
async def register_device(registration_data: PublicKeyRegistration, request: Request):
    """
    Register a new device with its public key.
    This endpoint is designed to be initially unauthenticated for onboarding.
    """
    device_id = registration_data.device_id
    public_key = registration_data.public_key
    client_ip = request.client.host

    if not device_id or not public_key:
        raise HTTPException(status_code=400, detail="Device ID and public key are required for registration.")

    try:
        register_or_update_device(device_id, public_key, client_ip)
        logger.info(f"Device '{device_id}' successfully registered/updated from IP: {client_ip}")
        return {"status": "success", "message": "Device registered successfully."}
    except Exception as e:
        logger.error(f"Error during device registration for {device_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to register device: {e}")


@app.get("/api/device/info")
async def get_device_info(request: Request, device_id: str = Depends(get_authenticated_device_id)):
    """Get device information"""
    # For now, device_id is expected to be passed via query param or headers,
    # or determined by a future authentication mechanism.
    # The Depends(get_authenticated_device_id) indicates this endpoint requires authentication.

    try:
        db_file = os.getenv("SQLITE_DB_PATH", 'secure_devices.db')
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute('''
                       SELECT device_id, first_seen, last_seen, status, ip_address
                       FROM devices
                       WHERE device_id = ?
                       ''', (device_id,))
        device_data = cursor.fetchone()
        conn.close()

        if device_data:
            return {
                "device_id": device_data[0],
                "first_seen": device_data[1],
                "last_seen": device_data[2],
                "status": device_data[3],
                "ip_address": device_data[4],
                "certificate_valid": True
            }
        else:
            return {"error": "Device not found"}

    except Exception as e:
        logger.error(f"Failed to get device info: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve device info")


@app.post("/api/telemetry")
async def receive_telemetry(telemetry: TelemetryData, request: Request,
                            authenticated_device_id: str = Depends(get_authenticated_device_id)):
    """Receive telemetry data from devices"""
    # Verify device_id in payload matches authenticated device ID
    if telemetry.device_id != authenticated_device_id:
        raise HTTPException(status_code=403, detail="Device ID in payload does not match authenticated device.")
    device_id = telemetry.device_id # Use the ID from the payload after authentication check

    try:
        db_file = os.getenv("SQLITE_DB_PATH", 'secure_devices.db')
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Store telemetry data
        cursor.execute('''
                       INSERT INTO telemetry (device_id, timestamp, data)
                       VALUES (?, ?, ?)
                       ''', (device_id, telemetry.timestamp, json.dumps(telemetry.data)))

        # Update device last seen
        cursor.execute('''
                       UPDATE devices
                       SET last_seen = CURRENT_TIMESTAMP,
                           status    = 'online'
                       WHERE device_id = ?
                       ''', (device_id,))

        conn.commit()
        conn.close()

        logger.info(f"Received telemetry from {device_id}")
        return {"status": "success", "message": "Telemetry received"}

    except Exception as e:
        logger.error(f"Failed to store telemetry: {e}")
        raise HTTPException(status_code=500, detail="Failed to store telemetry")


@app.post("/api/device/status")
async def update_device_status(status_update: StatusUpdate, request: Request,
                               authenticated_device_id: str = Depends(get_authenticated_device_id)):
    """Update device status"""
    # Verify device_id in payload matches authenticated device ID
    if status_update.device_id != authenticated_device_id:
        raise HTTPException(status_code=403, detail="Device ID in payload does not match authenticated device.")
    device_id = status_update.device_id # Use the ID from the payload after authentication check

    try:
        db_file = os.getenv("SQLITE_DB_PATH", 'secure_devices.db')
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Store status update
        cursor.execute('''
                       INSERT INTO device_status (device_id, status, timestamp, details)
                       VALUES (?, ?, ?, ?)
                       ''', (device_id, status_update.status, status_update.timestamp,
                             json.dumps(status_update.details) if status_update.details else None))

        # Update device status
        cursor.execute('''
                       UPDATE devices
                       SET status    = ?,
                           last_seen = CURRENT_TIMESTAMP
                       WHERE device_id = ?
                       ''', (status_update.status, device_id))

        conn.commit()
        conn.close()

        logger.info(f"Status update from {device_id}: {status_update.status}")
        return {"status": "success", "message": "Status updated"}

    except Exception as e:
        logger.error(f"Failed to update device status: {e}")
        raise HTTPException(status_code=500, detail="Failed to update status")


@app.get("/api/device/{device_id}/config")
async def get_device_config(device_id: str, request: Request,
                            authenticated_device_id: str = Depends(get_authenticated_device_id)):
    """Get device configuration"""
    # Verify device_id in path matches authenticated device ID
    if device_id != authenticated_device_id:
        raise HTTPException(status_code=403, detail="Access denied: Device ID mismatch.")

    try:
        db_file = os.getenv("SQLITE_DB_PATH", 'secure_devices.db')
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute('''
                       SELECT config
                       FROM device_config
                       WHERE device_id = ?
                       ''', (device_id,))
        result = cursor.fetchone()
        conn.close()

        if result:
            config = json.loads(result[0])
            return {"device_id": device_id, "config": config}
        else:
            # Return default configuration
            default_config = {
                "telemetry_interval": 60,
                "log_level": "INFO",
                "features": {
                    "telemetry_enabled": True,
                    "remote_control": False,
                    "auto_update": True
                }
            }
            return {"device_id": device_id, "config": default_config}

    except Exception as e:
        logger.error(f"Failed to get device config: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve configuration")


@app.get("/api/admin/devices")
async def list_devices():
    """List all devices (admin endpoint)"""
    try:
        db_file = os.getenv("SQLITE_DB_PATH", 'secure_devices.db')
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute('''
                       SELECT device_id, first_seen, last_seen, status, ip_address
                       FROM devices
                       ORDER BY last_seen DESC
                       ''')
        devices = cursor.fetchall()
        conn.close()

        return {
            "devices": [
                {
                    "device_id": device[0],
                    "first_seen": device[1],
                    "last_seen": device[2],
                    "status": device[3],
                    "ip_address": device[4]
                }
                for device in devices
            ]
        }

    except Exception as e:
        logger.error(f"Failed to list devices: {e}")
        raise HTTPException(status_code=500, detail="Failed to list devices")


@app.get("/api/admin/telemetry/{device_id}")
async def get_device_telemetry(device_id: str, limit: int = 100):
    """Get telemetry data for a specific device (admin endpoint)"""
    try:
        db_file = os.getenv("SQLITE_DB_PATH", 'secure_devices.db')
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute('''
                       SELECT timestamp, data, received_at
                       FROM telemetry
                       WHERE device_id = ?
                       ORDER BY received_at DESC LIMIT ?
                       ''', (device_id, limit))
        telemetry = cursor.fetchall()
        conn.close()

        return {
            "device_id": device_id,
            "telemetry": [
                {
                    "timestamp": row[0],
                    "data": json.loads(row[1]),
                    "received_at": row[2]
                }
                for row in telemetry
            ]
        }

    except Exception as e:
        logger.error(f"Failed to get telemetry: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve telemetry")


if __name__ == "__main__":
    # The server is intended to run behind a proxy like Traefik that handles SSL/TLS.
    # Therefore, we run on HTTP.
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,  # Changed to a standard HTTP port
        log_level="info"
    )
