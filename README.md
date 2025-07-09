# Placeholder App 🐎

This is a placeholder repository for a generic application. It serves as a starting point for new projects.

## Badges

[![Docker](https://github.com/jvishnefske/equusExpress/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/jvishnefske/equusExpress/actions/workflows/docker-publish.yml)
[![Docker](https://github.com/jvishnefske/equusExpress/actions/workflows/build.yml/badge.svg)](https://github.com/jvishnefske/equusExpress/actions/workflows/build.yml)
[![SonarCloud Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=jvishnefske_equusExpress&metric=coverage)](https://sonarcloud.io/component_measures?id=jvishnefske_equusExpress&metric=coverage)
[![SonarCloud Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=jvishnefske_equusExpress&metric=security_rating)](https://sonarcloud.io/component_measures?metric=Security&id=jvishnefske_equusExpress)
[![SonarCloud Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=jvishnefske_equusExpress&metric=ncloc)](https://sonarcloud.io/dashboard?id=jvishnefske_equusExpress)
[![SonarCloud Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=jvishnefske_equusExpress&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=jvishnefske_equusExpress)


## Getting Started

# Certificate Provisioning System Setup Guide

This guide walks you through setting up a complete certificate provisioning system for Raspberry Pi devices with FastAPI.

## Architecture Overview

1. **Provisioning Server** (HTTP) - Handles certificate requests and approval workflow
2. **Secure Server** (HTTPS with mTLS) - Provides authenticated API services
3. **Raspberry Pi Client** - Requests certificates and operates with mTLS
4. **Admin Interface** - Web-based certificate approval system

## Prerequisites

### Server Requirements
- Python 3.8+
- OpenSSL
- SQLite3
- Network access for clients

### Client Requirements (Raspberry Pi)
- Raspberry Pi OS
- Python 3.8+
- Network connectivity to servers

## Step 1: Generate Root Certificates

First, create the Certificate Authority (CA) and server certificates:

```bash
# Create certificate directory
mkdir -p /opt/iot-certs
cd /opt/iot-certs

# Generate CA private key
openssl genrsa -out ca.key 4096

# Generate CA certificate (valid for 10 years)
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=US/ST=State/L=City/O=IoT Company/CN=IoT-CA"

# Generate server private key
openssl genrsa -out server.key 4096

# Generate server certificate signing request
openssl req -new -key server.key -out server.c