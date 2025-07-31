from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from equus_express.routers.telemetry import lifespan
from equus_express.routers import authentication, telemetry
import uvicorn

# app = FastAPI(title="Local Admin Portal", version="1.0.0", lifespan=lifespan)
app = FastAPI(title="Secure IoT API Server", lifespan=lifespan)
# app = lifespan()
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