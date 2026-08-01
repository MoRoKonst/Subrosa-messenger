#!/bin/bash
set -e

echo ""
echo "========================================"
echo "Beacon Messenger Docker Quick Start"
echo "========================================"
echo ""

# Check Docker is installed
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed"
    echo "Install from: https://www.docker.com/products/docker-desktop"
    exit 1
fi

if ! command -v docker compose &> /dev/null; then
    echo "ERROR: Docker Compose is not installed"
    echo "Install from: https://docs.docker.com/compose/install/"
    exit 1
fi

# Generate certificates if needed
if [ ! -d "certs" ] || [ ! -f "certs/cert.pem" ]; then
    echo ""
    echo "Generating self-signed certificate..."
    chmod +x generate-certs.sh
    ./generate-certs.sh
fi

# Create .env if missing
if [ ! -f ".env" ]; then
    echo ""
    echo "Creating .env from template..."
    cp .env.example .env
    echo ""
    read -p "Press Enter to continue or Ctrl+C to edit .env first..."
fi

# Start services
echo ""
echo "Starting Beacon Messenger services..."
echo ""

docker compose up -d

sleep 2

echo ""
echo "✓ Services started!"
echo ""
echo "Container status:"
docker compose ps
echo ""
echo "Next steps:"
echo "  1. View logs: docker compose logs -f"
echo "  2. Test WebSocket connection:"
echo "     websocat --insecure wss://localhost/ws"
echo "     (or use browser console with WebSocket client)"
echo "  3. Stop server: docker compose down"
echo ""
echo "For production deployment, see DEPLOY.md"
echo ""
