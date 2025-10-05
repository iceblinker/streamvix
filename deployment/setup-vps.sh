#!/bin/bash

# StreamViX Personal - VPS Setup Script
# Run this script on your VPS as a regular user (not root)

set -e

echo "🚀 StreamViX Personal VPS Setup Script"
echo "======================================="

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Node.js 20
echo "📦 Installing Node.js 20..."
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install Python and dependencies
echo "📦 Installing Python and system dependencies..."
sudo apt-get install -y python3 python3-pip python3-dev build-essential ca-certificates

# Install Tesseract OCR
echo "📦 Installing Tesseract OCR..."
sudo apt-get install -y tesseract-ocr tesseract-ocr-ita tesseract-ocr-eng libtesseract-dev libleptonica-dev

# Install Python packages globally
echo "📦 Installing Python packages..."
sudo pip3 install --break-system-packages requests beautifulsoup4 pycryptodome pyDes pillow pytesseract curl_cffi fake-headers lxml

# Clone repository (assuming you've pushed it to GitHub)
echo "📥 Cloning StreamViX repository..."
if [ -d "streamvix" ]; then
    echo "⚠️  StreamViX directory already exists. Pulling latest changes..."
    cd streamvix
    git pull origin main
else
    git clone https://github.com/iceblinker/streamvix.git
    cd streamvix
fi

# Install Node.js dependencies
echo "📦 Installing Node.js dependencies..."
npm install

# Build the project
echo "🔨 Building the project..."
npm run build

# Create systemd service
echo "⚙️  Setting up systemd service..."
sudo cp deployment/streamvix.service /etc/systemd/system/
sudo sed -i "s|/home/ubuntu/streamvix|$(pwd)|g" /etc/systemd/system/streamvix.service
sudo sed -i "s|User=ubuntu|User=$(whoami)|g" /etc/systemd/system/streamvix.service

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable streamvix

# Start the service
echo "🚀 Starting StreamViX service..."
sudo systemctl start streamvix

# Check service status
echo "✅ Checking service status..."
sudo systemctl status streamvix --no-pager

# Configure firewall
echo "🔒 Configuring firewall..."
sudo ufw allow 7860/tcp

echo ""
echo "🎉 StreamViX Personal setup completed!"
echo "======================================="
echo ""
echo "Your addon is now running at: http://$(curl -s ifconfig.me):7860"
echo ""
echo "To add to Stremio, use: http://$(curl -s ifconfig.me):7860/manifest.json"
echo ""
echo "Useful commands:"
echo "  Check status: sudo systemctl status streamvix"
echo "  View logs:    sudo journalctl -u streamvix -f"
echo "  Restart:      sudo systemctl restart streamvix"
echo "  Stop:         sudo systemctl stop streamvix"
echo ""
echo "⚠️  Important: Make sure port 7860 is open in your VPS firewall settings!"