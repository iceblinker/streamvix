#!/bin/bash

# StreamViX Personal - Docker Setup Script
# Run this script on your VPS

set -e

echo "🐳 StreamViX Personal Docker Setup Script"
echo "=========================================="

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Docker
echo "🐳 Installing Docker..."
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
rm get-docker.sh

# Install Docker Compose
echo "🐳 Installing Docker Compose..."
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Clone repository
echo "📥 Cloning StreamViX repository..."
if [ -d "streamvix" ]; then
    echo "⚠️  StreamViX directory already exists. Pulling latest changes..."
    cd streamvix
    git pull origin main
else
    git clone https://github.com/iceblinker/streamvix.git
    cd streamvix
fi

# Build and start with Docker Compose
echo "🔨 Building and starting with Docker Compose..."
docker-compose up -d --build

# Wait for service to start
echo "⏳ Waiting for service to start..."
sleep 10

# Check if service is running
echo "✅ Checking service status..."
docker-compose ps

# Show logs
echo "📋 Showing recent logs..."
docker-compose logs --tail=20

echo ""
echo "🎉 StreamViX Personal Docker setup completed!"
echo "=============================================="
echo ""
echo "Your addon is now running at: http://$(curl -s ifconfig.me):7860"
echo ""
echo "To add to Stremio, use: http://$(curl -s ifconfig.me):7860/manifest.json"
echo ""
echo "Useful Docker commands:"
echo "  View logs:    docker-compose logs -f"
echo "  Restart:      docker-compose restart"
echo "  Stop:         docker-compose down"
echo "  Rebuild:      docker-compose up -d --build"
echo ""
echo "⚠️  Important: Make sure port 7860 is open in your VPS firewall settings!"
echo ""
echo "🔄 To log out and back in to apply Docker group membership, run:"
echo "   newgrp docker"