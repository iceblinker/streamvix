#!/bin/bash

# StreamViX Personal - VPS Setup Script
# This script sets up the StreamViX addon on your VPS

set -e

echo "🚀 StreamViX Personal VPS Setup Starting..."
echo "============================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "❌ This script should not be run as root for security reasons."
   echo "💡 Please run as a regular user with sudo privileges."
   exit 1
fi

# Variables
INSTALL_DIR="/opt/streamvix"
SERVICE_USER="streamvix"
SERVICE_NAME="streamvix-personal"

echo "📋 Configuration:"
echo "   Install Directory: $INSTALL_DIR"
echo "   Service User: $SERVICE_USER"
echo "   Service Name: $SERVICE_NAME"
echo ""

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install required packages
echo "📦 Installing required packages..."
sudo apt install -y curl wget git build-essential python3 python3-pip python3-venv nodejs npm nginx

# Install Node.js 20 (if not already installed)
echo "📦 Installing Node.js 20..."
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Create service user
echo "👤 Creating service user..."
if ! id "$SERVICE_USER" &>/dev/null; then
    sudo useradd -r -s /bin/bash -d "$INSTALL_DIR" "$SERVICE_USER"
    echo "✅ User $SERVICE_USER created"
else
    echo "✅ User $SERVICE_USER already exists"
fi

# Create installation directory
echo "📁 Creating installation directory..."
sudo mkdir -p "$INSTALL_DIR"
sudo chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

# Copy files to install directory
echo "📁 Copying application files..."
if [ -d "streamvix-deploy" ]; then
    sudo cp -r streamvix-deploy/* "$INSTALL_DIR/"
elif [ -f "streamvix-personal-deployment.tar.gz" ]; then
    sudo tar -xzf streamvix-personal-deployment.tar.gz -C /tmp/
    sudo cp -r /tmp/streamvix-deploy/* "$INSTALL_DIR/"
    sudo rm -rf /tmp/streamvix-deploy
else
    echo "❌ No deployment files found. Please ensure you have either:"
    echo "   - streamvix-deploy directory, or"
    echo "   - streamvix-personal-deployment.tar.gz file"
    exit 1
fi

# Set correct ownership
sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

# Switch to service user for setup
echo "🔧 Setting up application as $SERVICE_USER user..."
sudo -u "$SERVICE_USER" bash << 'EOF'
cd /opt/streamvix

# Create Python virtual environment
echo "🐍 Creating Python virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install Node.js dependencies
echo "📦 Installing Node.js dependencies..."
npm install

# Build the project
echo "🔨 Building the project..."
npm run build

echo "✅ Application setup completed"
EOF

# Create systemd service
echo "🔧 Creating systemd service..."
sudo tee /etc/systemd/system/$SERVICE_NAME.service > /dev/null << EOF
[Unit]
Description=StreamViX Personal Stremio Addon
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=NODE_ENV=production
Environment=PORT=7860
Environment=PYTHON_BIN=$INSTALL_DIR/.venv/bin/python
Environment=PYTHONPATH=$INSTALL_DIR/.venv/lib/python3.*/site-packages
ExecStart=/usr/bin/node $INSTALL_DIR/dist/addon.js
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=$SERVICE_NAME

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
echo "🚀 Enabling and starting service..."
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME
sudo systemctl start $SERVICE_NAME

# Configure firewall (if ufw is installed)
if command -v ufw > /dev/null; then
    echo "🔒 Configuring firewall..."
    sudo ufw allow 7860/tcp
    echo "✅ Port 7860 opened in firewall"
fi

# Setup nginx reverse proxy (optional)
echo "🌐 Would you like to set up Nginx reverse proxy? (y/n)"
read -r setup_nginx

if [[ $setup_nginx =~ ^[Yy]$ ]]; then
    echo "🌐 Setting up Nginx reverse proxy..."
    
    echo "Enter your domain name (or press Enter for IP-based access):"
    read -r domain_name
    
    if [[ -z "$domain_name" ]]; then
        server_name="_"
    else
        server_name="$domain_name"
    fi
    
    sudo tee /etc/nginx/sites-available/streamvix > /dev/null << EOF
server {
    listen 80;
    server_name $server_name;

    location / {
        proxy_pass http://127.0.0.1:7860;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

    sudo ln -sf /etc/nginx/sites-available/streamvix /etc/nginx/sites-enabled/
    sudo nginx -t && sudo systemctl reload nginx
    echo "✅ Nginx reverse proxy configured"
fi

# Display status
echo ""
echo "🎉 StreamViX Personal Setup Complete!"
echo "======================================"
echo ""
echo "📊 Service Status:"
sudo systemctl status $SERVICE_NAME --no-pager -l

echo ""
echo "🌐 Access Information:"
echo "   Direct Access: http://YOUR_SERVER_IP:7860"
if [[ -n "$domain_name" ]]; then
    echo "   Domain Access: http://$domain_name"
fi
echo "   Manifest: http://YOUR_SERVER_IP:7860/manifest.json"
echo ""
echo "📋 Useful Commands:"
echo "   Check status: sudo systemctl status $SERVICE_NAME"
echo "   View logs: sudo journalctl -u $SERVICE_NAME -f"
echo "   Restart: sudo systemctl restart $SERVICE_NAME"
echo "   Stop: sudo systemctl stop $SERVICE_NAME"
echo ""
echo "🎊 Your StreamViX Personal addon is now running on your VPS!"