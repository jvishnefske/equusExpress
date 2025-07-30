from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
import ssl
import os  # Keep for os.getenv
import sqlite3
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import logging
from pydantic import BaseModel
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import socket
from contextlib import asynccontextmanager, ExitStack
import importlib.resources as pkg_resources
import tempfile
import shutil
from pathlib import Path # New import for Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles startup and shutdown events for the application.
    Initializes the database on startup and sets up static file serving.
    """
    logger.info("Application starting up...")
    init_secure_db()

    # Use ExitStack to manage the lifecycle of temporary resources (e.g., extracted static files, templates)
    # This ensures cleanup on application shutdown.
    app.state.temp_resource_manager = ExitStack()

    try:
        # --- Handle Static Files ---
        temp_static_dir = app.state.temp_resource_manager.enter_context(
            tempfile.TemporaryDirectory()
        )
        static_files_path = Path(temp_static_dir)

        source_static_dir_resource = pkg_resources.files("equus_express").joinpath("static")

        if source_static_dir_resource.is_dir():
            static_files_path = Path(str(source_static_dir_resource))
            logger.info(
                f"Mounted static files directly from package directory: {static_files_path}"
            )
        else:
            logger.info(
                f"Extracting static files from package to temporary directory: {static_files_path}"
            )
            for item in source_static_dir_resource.iterdir():
                with pkg_resources.as_file(item) as item_path_on_disk:
                    shutil.copy(
                        item_path_on_disk,
                        static_files_path / item.name,
                    )
            logger.info(f"Static files extracted to {static_files_path}")

        app.mount(
            "/static",
            StaticFiles(directory=static_files_path),
            name="static",
        )
        app.state.static_path = static_files_path # Store for favicon serving

        # --- Handle Templates ---
        temp_templates_dir = app.state.temp_resource_manager.enter_context(
            tempfile.TemporaryDirectory()
        )
        templates_path = Path(temp_templates_dir)

        source_templates_dir_resource = pkg_resources.files("equus_express").joinpath("templates")

        if source_templates_dir_resource.is_dir():
            templates_path = Path(str(source_templates_dir_resource))
            logger.info(
                f"Loaded templates directly from package directory: {templates_path}"
            )
        else:
            logger.info(
                f"Extracting templates from package to temporary directory: {templates_path}"
            )
            for item in source_templates_dir_resource.iterdir():
                with pkg_resources.as_file(item) as item_path_on_disk:
                    shutil.copy(
                        item_path_on_disk,
                        templates_path / item.name,
                    )
            logger.info(f"Templates extracted to {templates_path}")

        # Initialize Jinja2Templates with the dynamically determined path
        app.state.templates = Jinja2Templates(directory=templates_path)

    except Exception as e:
        logger.error(f"Failed to set up static files or templates during startup: {e}", exc_info=True)
        raise RuntimeError(f"Failed to initialize server resources: {e}")

    yield  # This is where your application starts running and serves requests

    logger.info("Application shutting down...")
    app.state.temp_resource_manager.close()  # This will clean up all temporary directories
    logger.info("Temporary resources cleaned up.")


app = FastAPI(title="Secure IoT API Server", lifespan=lifespan)
security = HTTPBearer()


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
    db_file = dp_path()
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    # Devices table
    cursor.execute(
        """
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
                   """
    )

    # Telemetry table
    cursor.execute(
        """
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
                   """
    )

    # Device status table
    cursor.execute(
        """
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
                   """
    )

    # Device configuration table
    cursor.execute(
        """
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
                   """
    )

    conn.commit()
    conn.close()


def dp_path():
    return os.getenv("SQLITE_DB_PATH", "secure_devices.db")


# Placeholder for future authentication and device identification logic.
# This function will need to be replaced with logic that validates incoming requests
# based on the client's public key (e.g., signed JWTs or request bodies).
# For now, we will rely on device_id being passed in the payload for certain endpoints,
# and introduce a registration endpoint.
def get_authenticated_device_id(request: Request) -> str:
    """
    Placeholder: Authenticates the client and returns their device ID.
    For now, this relies solely on the 'X-Device-Id' header.
    In a real system, this would verify a signature or token.
    """
    header_device_id = request.headers.get("X-Device-Id")
    if header_device_id:
        return header_device_id

    # If no device_id can be determined from the header for an authenticated endpoint, raise an error
    raise HTTPException(
        status_code=401,
        detail="Authentication required: 'X-Device-Id' header not provided or authenticated.",
    )


def register_or_update_device(
    device_id: str, public_key: str, ip_address: str
):
    """Register or update device in the database with its public key"""
    try:
        db_file = dp_path()
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Check if device exists
        cursor.execute(
            "SELECT device_id FROM devices WHERE device_id = ?", (device_id,)
        )
        exists = cursor.fetchone()

        if exists:
            # Update existing device's public key and last seen
            cursor.execute(
                """
                           UPDATE devices
                           SET last_seen  = CURRENT_TIMESTAMP,
                               public_key = ?,
                               ip_address = ?
                           WHERE device_id = ?
                           """,
                (public_key, ip_address, device_id),
            )
        else:
            # Insert new device with public key
            cursor.execute(
                """
                           INSERT INTO devices
                               (device_id, public_key, ip_address)
                           VALUES (?, ?, ?)
                           """,
                (device_id, public_key, ip_address),
            )

        conn.commit()
        conn.close()
        logger.info(
            f"Device {repr(device_id)} registered/updated with public key."
        )

    except sqlite3.Error as e:  # Catch specific database errors
        logger.error(
            f"Failed to register/update device {repr(device_id)}: {e}"
        )
        raise HTTPException(
            status_code=500, detail=f"Database error during registration: {e}"
        )
    except Exception as e:  # Catch any other unexpected errors
        logger.error(
            f"An unexpected error occurred during device registration for device {repr(device_id)}: {e}"
        )


@app.get("/")
async def root(request: Request):
    return request.app.state.templates.TemplateResponse("index.html", {"request": request})


@app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def admin_portal(request: Request):
    return request.app.state.templates.TemplateResponse("admin_portal_frontend.html", {"request": request})


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """
    Serves the favicon.ico directly from the package's static resources.
    This is for browsers that automatically look for /favicon.ico at the root.
    """
    try:
        # The static files are already mounted at /static, so FastAPI will serve it from there.
        # This endpoint is just a redirect to ensure browsers find it at the root.
        # We can directly return a FileResponse pointing to the expected mounted path.
        # However, to avoid hardcoding the path derived from the mounted dir, it's better
        # to rely on the static files functionality. A simple redirect is more appropriate
        # if favicon.ico is explicitly requested at root for a browser.
        # A more robust way is to just let StaticFiles handle it, by making sure the favicon
        # is placed at the root of the mounted static directory.
        # Since it's already in 'static', just ensuring the mount point is correct handles it.
        # This endpoint can technically just serve the specific file from the mounted path.
        # For simplicity, given static is mounted to `/static`, a browser requesting `/favicon.ico`
        # would typically not hit this endpoint if it's placed within the root of the mounted static path.
        # If it's expected to be served from the top level, we explicitly fetch it.

        try:
            # Access the path used for static files from app.state
            static_base_path = Path(app.state.static_path)
            favicon_path = static_base_path / "favicon.ico"

            if not favicon_path.exists():
                raise HTTPException(status_code=404, detail="Favicon not found")
                
            return FileResponse(str(favicon_path))
        except (AttributeError, KeyError) as e:
            # Catch if app.state.static_path is not yet set or accessible
            logger.error(f"Static path not initialized for favicon: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Server resources not fully initialized for favicon")
    except Exception as e:
        logger.error(f"Failed to serve favicon.ico: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error serving favicon")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Simple dashboard to display device telemetry."""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Equus Express Dashboard</title>
        <link rel="stylesheet" href="/static/style.css">
    </head>
    <body>
        <div class="container">
            <h1>Equus Express Device Dashboard</h1>
            <div id="devices-container">Loading devices...</div>
        </div>
        <script src="/static/app.js"></script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.post("/api/register")
async def register_device(
    registration_data: PublicKeyRegistration, request: Request
):
    """
    Register a new device with its public key.
    This endpoint is designed to be initially unauthenticated for onboarding.
    """
    device_id = registration_data.device_id
    public_key = registration_data.public_key
    client_ip = request.client.host

    if not device_id or not public_key:
        raise HTTPException(
            status_code=400,
            detail="Device ID and public key are required for registration.",
        )

    try:
        register_or_update_device(device_id, public_key, client_ip)
        logger.info(
            f"Device '{repr(device_id)}' successfully registered/updated from IP: {client_ip}"
        )
        return {
            "status": "success",
            "message": "Device registered successfully.",
        }
    except Exception as e:
        logger.error(
            f"Error during device registration for {repr(device_id)}: {e}"
        )
        raise HTTPException(
            status_code=500, detail=f"Failed to register device: {e}"
        )


@app.get("/api/device/info")
async def get_device_info(
    request: Request, device_id: str = Depends(get_authenticated_device_id)
):
    """Get device information"""
    # For now, device_id is expected to be passed via query param or headers,
    # or determined by a future authentication mechanism.
    # The Depends(get_authenticated_device_id) indicates this endpoint requires authentication.

    try:
        db_file = dp_path()
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(
            """
                       SELECT device_id, first_seen, last_seen, status, ip_address
                       FROM devices
                       WHERE device_id = ?
                       """,
            (device_id,),
        )
        device_data = cursor.fetchone()
        conn.close()

        if device_data:
            return {
                "device_id": device_data[0],
                "first_seen": device_data[1],
                "last_seen": device_data[2],
                "status": device_data[3],
                "ip_address": device_data[4],
                "certificate_valid": True,
            }
        else:
            # Uncovered: Device not found in get_device_info
            return {"error": "Device not found"}

    except Exception as e:
        # Uncovered: Unexpected error in get_device_info
        logger.error(f"Failed to get device info: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to retrieve device info"
        )


@app.post("/api/telemetry")
async def receive_telemetry(
    telemetry: TelemetryData,
    request: Request,
    authenticated_device_id: str = Depends(get_authenticated_device_id),
):
    """Receive telemetry data from devices"""
    # Verify device_id in payload matches authenticated device ID
    if telemetry.device_id != authenticated_device_id:
        raise HTTPException(
            status_code=403,
            detail="Device ID in payload does not match authenticated device.",
        )
    device_id = (
        telemetry.device_id
    )  # Use the ID from the payload after authentication check

    try:
        db_file = dp_path()
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Store telemetry data
        cursor.execute(
            """
                       INSERT INTO telemetry (device_id, timestamp, data)
                       VALUES (?, ?, ?)
                       """,
            (device_id, telemetry.timestamp, json.dumps(telemetry.data)),
        )

        # Update device last seen
        cursor.execute(
            """
                       UPDATE devices
                       SET last_seen = CURRENT_TIMESTAMP,
                           status    = 'online'
                       WHERE device_id = ?
                       """,
            (device_id,),
        )

        conn.commit()
        conn.close()

        logger.info(f"Received telemetry from {repr(device_id)}")
        return {"status": "success", "message": "Telemetry received"}

    except Exception as e:
        # Uncovered: Unexpected error in receive_telemetry
        logger.error(f"Failed to store telemetry: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to store telemetry"
        )


@app.post("/api/device/status")
async def update_device_status(
    status_update: StatusUpdate,
    request: Request,
    authenticated_device_id: str = Depends(get_authenticated_device_id),
):
    """Update device status"""
    # Verify device_id in payload matches authenticated device ID
    if status_update.device_id != authenticated_device_id:
        raise HTTPException(
            status_code=403,
            detail="Device ID in payload does not match authenticated device.",
        )
    device_id = (
        status_update.device_id
    )  # Use the ID from the payload after authentication check

    try:
        db_file = dp_path()  # Corrected: Call dp_path function
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Store status update
        cursor.execute(
            """
                       INSERT INTO device_status (device_id, status, timestamp, details)
                       VALUES (?, ?, ?, ?)
                       """,
            (
                device_id,
                status_update.status,
                status_update.timestamp,
                (
                    json.dumps(status_update.details)
                    if status_update.details
                    else None
                ),
            ),
        )

        # Update device status
        cursor.execute(
            """
                       UPDATE devices
                       SET status    = ?,
                           last_seen = CURRENT_TIMESTAMP
                       WHERE device_id = ?
                       """,
            (status_update.status, device_id),
        )

        conn.commit()
        conn.close()

        logger.info(
            f"Status update from {repr(device_id)}: {status_update.status}"
        )
        return {"status": "success", "message": "Status updated"}

    except Exception as e:
        # Uncovered: Unexpected error in update_device_status
        logger.error(f"Failed to update device status: {e}")
        raise HTTPException(status_code=500, detail="Failed to update status")


@app.get("/api/device/{device_id}/config")
async def get_device_config(
    device_id: str,
    request: Request,
    authenticated_device_id: str = Depends(get_authenticated_device_id),
):
    """Get device configuration"""
    # Verify device_id in path matches authenticated device ID
    if device_id != authenticated_device_id:
        raise HTTPException(
            status_code=403, detail="Access denied: Device ID mismatch."
        )

    try:
        db_file = dp_path()
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(
            """
                       SELECT config
                       FROM device_config
                       WHERE device_id = ?
                       """,
            (device_id,),
        )
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
                    "auto_update": True,
                },
            }
            return {"device_id": device_id, "config": default_config}

    except Exception as e:
        # Uncovered: Unexpected error in get_device_config
        logger.error(f"Failed to get device config: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to retrieve configuration"
        )


@app.get("/api/admin/devices")
async def list_devices():
    """List all devices (admin endpoint)"""
    try:
        db_file = dp_path()
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(
            """
                       SELECT device_id, first_seen, last_seen, status, ip_address
                       FROM devices
                       ORDER BY last_seen DESC
                       """
        )
        devices = cursor.fetchall()
        conn.close()

        return {
            "devices": [
                {
                    "device_id": device[0],
                    "first_seen": device[1],
                    "last_seen": device[2],
                    "status": device[3],
                    "ip_address": device[4],
                }
                for device in devices
            ]
        }

    except Exception as e:
        # Uncovered: Unexpected error in list_devices
        logger.error(f"Failed to list devices: {e}")
        raise HTTPException(status_code=500, detail="Failed to list devices")


@app.get("/api/admin/telemetry/{device_id}")
async def get_device_telemetry(device_id: str, limit: int = 100):
    """Get telemetry data for a specific device (admin endpoint)"""
    try:
        db_file = dp_path()
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(
            """
                       SELECT timestamp, data, received_at
                       FROM telemetry
                       WHERE device_id = ?
                       ORDER BY received_at DESC LIMIT ?
                       """,
            (device_id, limit),
        )
        telemetry = cursor.fetchall()
        conn.close()

        return {
            "device_id": device_id,
            "telemetry": [
                {
                    "timestamp": row[0],
                    "data": json.loads(row[1]),
                    "received_at": row[2],
                }
                for row in telemetry
            ],
        }

    except Exception as e:
        # Uncovered: Unexpected error in get_device_telemetry
        logger.error(f"Failed to get telemetry: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to retrieve telemetry"
        )


if __name__ == "__main__":
    # The server is intended to run behind a proxy like Traefik that handles SSL/TLS.
    # Therefore, we run on HTTP.
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,  # Changed to a standard HTTP port
        log_level="info",
    )
