#!/bin/bash

# StreamViX Personal - GitHub-Based VPS Setup Script
# This script clones from GitHub and sets up the StreamViX addon on your VPS

set -e

echo "🚀 StreamViX Personal VPS Setup (GitHub-Based)"
echo "=============================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "❌ This script should not be run as root for security reasons."
   echo "💡 Please run as a regular user with sudo privileges."
   exit 1
fi

# Variables
REPO_URL="https://github.com/iceblinker/streamvix.git"
INSTALL_DIR="/opt/streamvix"
SERVICE_USER="streamvix"
SERVICE_NAME="streamvix-personal"

echo "📋 Configuration:"
echo "   Repository: $REPO_URL"
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

# Clone repository
echo "📥 Cloning repository from GitHub..."
if [ -d "$INSTALL_DIR/.git" ]; then
    echo "🔄 Repository exists, pulling latest changes..."
    sudo -u "$SERVICE_USER" git -C "$INSTALL_DIR" pull
else
    echo "📥 Cloning fresh repository..."
    sudo git clone "$REPO_URL" "$INSTALL_DIR"
    sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
fi

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

# Create update script for easy maintenance
sudo tee /opt/streamvix/update-addon.sh > /dev/null << 'EOF'
#!/bin/bash
echo "🔄 Updating StreamViX Personal from GitHub..."

# Stop the service
sudo systemctl stop streamvix-personal

# Pull latest changes
sudo -u streamvix git -C /opt/streamvix pull

# Rebuild as service user
sudo -u streamvix bash -c '
cd /opt/streamvix
source .venv/bin/activate
pip install -r requirements.txt
npm install
npm run build
'

# Restart the service
sudo systemctl start streamvix-personal

echo "✅ Update completed!"
sudo systemctl status streamvix-personal
EOF

sudo chmod +x /opt/streamvix/update-addon.sh

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
echo "   Update from GitHub: sudo /opt/streamvix/update-addon.sh"
echo ""
echo "🎊 Your StreamViX Personal addon is now running on your VPS!"
echo "🔄 To update in the future, just run: sudo /opt/streamvix/update-addon.sh"