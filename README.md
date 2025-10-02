# Equus Express 🐎

**Automation Engineers, are you tired of the complexity of managing and monitoring your custom industrial devices running critical batch processes?** ⚙️

Equus Express provides solution for device registration. Take control of your industrial IoT deployment with confidence. ✨

## Badges

[![Docker](https://github.com/jvishnefske/equusExpress/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/jvishnefske/equusExpress/actions/workflows/docker-publish.yml)
[![Docker](https://github.com/jvishnefske/equusExpress/actions/workflows/build.yml/badge.svg)](https://github.com/jvishnefske/equusExpress/actions/workflows/build.yml)
[![SonarCloud Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=jvishnefske_equusExpress&metric=coverage)](https://sonarcloud.io/component_measures?id=jvishnefske_equusExpress&metric=coverage)
[![SonarCloud Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=jvishnefske_equusExpress&metric=security_rating)](https://sonarcloud.io/component_measures?metric=Security&id=jvishnefske_equusExpress)
[![SonarCloud Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=jvishnefske_equusExpress&metric=ncloc)](https://sonarcloud.io/dashboard?id=jvishnefske_equusExpress)
[![SonarCloud Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=jvishnefske_equusExpress&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=jvishnefske_equusExpress)


## Getting Started 🚀

# Certificate Provisioning System Setup Guide 📜

This guide walks you through setting up a complete certificate provisioning system for Raspberry Pi devices 🍓 with FastAPI.

## Architecture Overview 🏗️

1.  **API Server** 🖥️ (HTTP) - Handles public key registration, telemetry, and device management. Designed to run behind a reverse proxy (e.g., Traefik) that handles HTTPS/SSL.
2.  **Device Client** 🔌 - Automatically generates an RSA public/private key pair on first run and registers its public key with the server. Sends telemetry and status updates.
3.  **Web Dashboard** 📊 - A simple web interface provided by the server to view connected devices and their telemetry.

## Prerequisites 🛠️

### Server Requirements 💻
-   Python 3.8+
-   SQLite3
-   Network access for clients (typically via a proxy)

### Client Requirements 📱
-   Python 3.8+
-   `cryptography` library for key generation
-   Network connectivity to the server (or proxy)

## Docker Compose Environment Variables 🐳

For Docker Compose deployments, environment variables (e.g., `HOSTNAME`, `LETSENCRYPT_EMAIL`, `CF_API_KEY`) can be configured by creating a `.env` file in the same directory as your `docker-compose.yml`. Docker Compose automatically loads variables from this file.


## Getting Started

### 1. Install Dependencies 📦

Install the required Python packages using `uv`:

```bash
uv pip install .[dev] # Install main and development dependencies from pyproject.toml
```

### 2. Run the Server ▶️

The server runs on HTTP (default port 8000) and is designed to be placed behind an SSL-terminating proxy like Traefik.

```bash
uv run python3 -m equus_express.server
```

Once running, you can access the server's health check at `http://localhost:8000/health`. ✅

### 3. Run the Client ▶️

The client will generate a new RSA key pair in `~/.equus_express/keys/` on its first run and register its public key with the server.

```bash
uv run python3 -m equus_express.client http://localhost:8000 [your_device_id]
```
Replace `http://localhost:8000` with the actual URL of your server (or proxy). `[your_device_id]` is optional; if not provided, it defaults to your hostname.

### 4. View the Dashboard 🌐

Open your web browser to access the device dashboard:

```
http://localhost:8000/dashboard
```

This dashboard will display registered devices and their latest telemetry data. 📈
