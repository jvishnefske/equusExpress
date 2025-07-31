from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from equus_express.internal.session import Base, engine, SessionLocal
from equus_express.routers import authentication, telemetry
import uvicorn
import logging

logger = logging.getLogger(__name__)

@asynccontextmanager
async def combined_lifespan(app: FastAPI):
    """Handles startup and shutdown events for the entire application."""
    logger.info("Application startup: Initializing database and default data.")
    with SessionLocal() as db:
        Base.metadata.create_all(bind=engine) # Create all tables
        authentication.create_db_and_tables(db) # Populate authentication-related default data
        # Assuming telemetry.init_secure_db() exists and handles telemetry-specific DB setup
        telemetry.init_secure_db() # Populate telemetry-related default data or ensure its DB is ready
    yield
    logger.info("Application shutdown: Cleaning up resources (if any).")


app = FastAPI(title="Secure IoT API Server", lifespan=combined_lifespan)
app.include_router(authentication.router)
app.include_router(telemetry.router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=authentication.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=[
        "*",
        "Content-Type",
        "Authorization",
    ],  # Explicitly allow Content-Type and Authorization headers
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
