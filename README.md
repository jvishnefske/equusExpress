# Equus Express

A lightweight Python web frontend for managing and monitoring embedded IoT devices. Register devices, collect telemetry, and view dashboards - all through a simple REST API.

[![Docker](https://github.com/jvishnefske/equusExpress/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/jvishnefske/equusExpress/actions/workflows/docker-publish.yml)
[![Build](https://github.com/jvishnefske/equusExpress/actions/workflows/ci.yml/badge.svg)](https://github.com/jvishnefske/equusExpress/actions/workflows/ci.yml)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=jvishnefske_equusExpress&metric=coverage)](https://sonarcloud.io/component_measures?id=jvishnefske_equusExpress&metric=coverage)

## Quick Start

```bash
pip install -e .
python -m equus_express.server
# Visit http://localhost:8000/dashboard
```

## Architecture

1. **API Server** - FastAPI backend handling device registration, telemetry ingestion, and configuration management. Runs on HTTP (port 8000) and is designed for deployment behind a reverse proxy (e.g., Traefik) for SSL termination.

2. **Device Client** - Python agent that generates RSA key pairs, registers with the server, and sends periodic telemetry (CPU, memory, disk, temperature).

3. **Web Dashboard** - Browser-based interface for viewing connected devices and their telemetry data.

## Prerequisites

- Python 3.9+
- SQLite3 (bundled with Python)

## Installation

```bash
# Using uv (recommended)
uv pip install -e .[dev]

# Using pip
pip install -e .[dev]
```

## Usage

### Start the Server

```bash
python -m equus_express.server
```

The server exposes:
- `GET /health` - Health check endpoint
- `GET /dashboard` - Web dashboard
- `POST /api/register` - Device registration
- `POST /api/telemetry` - Telemetry ingestion
- `GET /api/admin/devices` - List all devices

### Run a Device Client

```bash
python -m equus_express.client http://localhost:8000 [device_id]
```

The client will:
1. Generate an RSA key pair (stored in `~/.equus_express/keys/`)
2. Register with the server
3. Send telemetry at 30-second intervals

## Docker Deployment

```bash
docker-compose up -d
```

Environment variables can be configured via a `.env` file in the same directory as `docker-compose.yml`.

## Development

```bash
make test       # Run tests
make coverage   # Generate coverage report
make lint       # Run linter
make clean      # Clean build artifacts
```

## License

See LICENSE file for details.
