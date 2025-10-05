# StreamViX Personal - Deployment Guide

## Prerequisites for VPS Deployment

### System Requirements
- Ubuntu 20.04+ or similar Linux distribution
- Node.js 20.x
- Python 3.9+ with pip
- Docker and Docker Compose (recommended)
- Minimum 1GB RAM, 2GB recommended
- 10GB free disk space

### Required Packages
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install Python and dependencies
sudo apt-get install -y python3 python3-pip python3-dev build-essential

# Install Tesseract OCR
sudo apt-get install -y tesseract-ocr tesseract-ocr-ita tesseract-ocr-eng libtesseract-dev libleptonica-dev

# Install Docker (optional but recommended)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

## Deployment Options

### Option 1: Docker Deployment (Recommended)

1. **Clone your repository on the VPS:**
```bash
git clone https://github.com/iceblinker/streamvix.git
cd streamvix
```

2. **Build and run with Docker Compose:**
```bash
docker-compose up -d
```

3. **Access your addon at:**
```
http://your-vps-ip:7860
```

### Option 2: Direct Node.js Deployment

1. **Clone and setup:**
```bash
git clone https://github.com/iceblinker/streamvix.git
cd streamvix
npm install
```

2. **Install Python dependencies:**
```bash
pip3 install requests beautifulsoup4 pycryptodome pyDes pillow pytesseract curl_cffi fake-headers lxml
```

3. **Build the project:**
```bash
npm run build
```

4. **Create systemd service:**
```bash
sudo cp deployment/streamvix.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable streamvix
sudo systemctl start streamvix
```

## Configuration

### Environment Variables
Create a `.env` file in the project root:
```bash
PYTHON_BIN=/usr/bin/python3
PORT=7860
NODE_ENV=production
```

### Firewall Configuration
```bash
# Allow the addon port
sudo ufw allow 7860/tcp

# Optional: Set up reverse proxy with nginx
sudo apt install nginx
sudo cp deployment/nginx.conf /etc/nginx/sites-available/streamvix
sudo ln -s /etc/nginx/sites-available/streamvix /etc/nginx/sites-enabled/
sudo systemctl restart nginx
```

## Security Considerations

1. **Change default port** if needed
2. **Set up SSL certificate** with Let's Encrypt if using domain
3. **Configure firewall** properly
4. **Regular updates** of dependencies
5. **Monitor logs** for any issues

## Adding to Stremio

After deployment, add your addon to Stremio using:
- **Local:** `http://your-vps-ip:7860/manifest.json`
- **With domain:** `https://your-domain.com/manifest.json`

## Monitoring

Check addon status:
```bash
# Docker
docker-compose logs -f

# SystemD
sudo journalctl -u streamvix -f

# Manual check
curl http://localhost:7860/manifest.json
```

## Troubleshooting

### Common Issues:
1. **Python not found:** Ensure Python 3.x is installed and PYTHON_BIN is set
2. **Port already in use:** Change PORT in environment variables
3. **Permission denied:** Check file permissions and user access
4. **Memory issues:** Increase VPS RAM or add swap

### Logs Location:
- Docker: `docker-compose logs`
- SystemD: `/var/log/syslog` and `journalctl -u streamvix`
- Manual: Console output

## Updates

To update the addon:
```bash
git pull origin main
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

Or for direct deployment:
```bash
git pull origin main
npm run build
sudo systemctl restart streamvix
```