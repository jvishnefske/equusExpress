#!/bin/bash

set -euo pipefail

echo "Building frontend..."

# Ensure yarn is installed if not already
if ! command -v yarn &> /dev/null
then
    echo "yarn could not be found, please install it (e.g., npm install -g yarn)."
    exit 1
fi

# Navigate to the frontend directory
pushd frontend

# Install dependencies
echo "Installing frontend dependencies..."
yarn install

# Build the frontend
echo "Running yarn build..."
yarn build

# Navigate back to the root directory
popd

# Ensure the destination directory exists
mkdir -p src/equus_express/dashboard

# Copy the build output to the desired location
echo "Copying frontend/dist to src/equus_express/src/dist..."
cp -R frontend/dist/* src/equus_express/dashboard/
touch src/equus_express/dashboard/__init__.py

echo "Frontend build and copy complete!"
