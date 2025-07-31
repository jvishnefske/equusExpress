from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager, ExitStack
import importlib.resources as pkg_resources
import tempfile
import shutil
from pathlib import Path

from equus_express.internal.session import Base, engine, SessionLocal
from equus_express.routers import authentication, telemetry
import uvicorn
import logging

logger = logging.getLogger(__name__)

@asynccontextmanager
async def combined_lifespan(app: FastAPI):
    """Handles startup and shutdown events for the entire application."""
    logger.info("Application startup: Initializing database and setting up resources.")

    # Use ExitStack to manage the lifecycle of temporary resources (e.g., extracted static files, templates)
    # This ensures cleanup on application shutdown.
    app.state.temp_resource_manager = ExitStack()

    try:
        with SessionLocal() as db:
            Base.metadata.create_all(bind=engine) # Create all tables
            authentication.create_db_and_tables(db) # Populate authentication-related default data
            telemetry.init_secure_db() # Populate telemetry-related default data or ensure its DB is ready

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
        logger.error(f"Failed to set up resources during startup: {e}", exc_info=True)
        raise RuntimeError(f"Failed to initialize server resources: {e}")

    yield  # This is where your application starts running and serves requests

    logger.info("Application shutdown: Cleaning up resources.")
    app.state.temp_resource_manager.close()  # This will clean up all temporary directories
    logger.info("Temporary resources cleaned up.")


app = FastAPI(title="Secure IoT API Server", lifespan=combined_lifespan)
app.include_router(authentication.router)
app.include_router(telemetry.router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Temporarily allow all origins to confirm CORS issue
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "Content-Type", "Authorization"],
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
