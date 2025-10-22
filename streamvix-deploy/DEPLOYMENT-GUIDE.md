# 🚀 StreamViX Personal - VPS Deployment Guide

## 📋 Pre-Deployment Checklist

✅ **Local Testing Completed**: Your addon works perfectly locally
✅ **Python Environment Fixed**: All hardcoded paths resolved
✅ **Personal Configuration**: Addon branded as "StreamViX Personal"
✅ **Deployment Package Created**: Ready for VPS upload

## 🌐 VPS Requirements

- **OS**: Ubuntu 20.04+ or Debian 11+ (recommended)
- **RAM**: Minimum 1GB, recommended 2GB+
- **Disk**: At least 5GB free space
- **Network**: Open port 7860 (or configure reverse proxy)
- **Access**: SSH access with sudo privileges

## 📦 Step-by-Step Deployment

### Step 1: Upload Files to VPS

1. **Zip the deployment folder** (if not already done):
   ```bash
   # On Windows
   Compress-Archive -Path streamvix-deploy -DestinationPath streamvix-personal.zip
   
   # Or manually zip the 'streamvix-deploy' folder
   ```

2. **Upload to your VPS** using your preferred method:
   - **SCP**: `scp streamvix-personal.zip user@your-vps-ip:~/`
   - **SFTP**: Use FileZilla, WinSCP, or similar
   - **Cloud**: Upload to Dropbox/Google Drive, then download on VPS

### Step 2: Connect to Your VPS

```bash
ssh your-username@your-vps-ip
```

### Step 3: Extract and Setup

```bash
# Extract the deployment package
unzip streamvix-personal.zip
# OR if you uploaded the tar.gz
# tar -xzf streamvix-personal-deployment.tar.gz

# Navigate to the directory
cd streamvix-deploy

# Make the setup script executable
chmod +x vps-setup.sh

# Run the setup script
./vps-setup.sh
```

### Step 4: Follow Setup Prompts

The setup script will:
- ✅ Install all required dependencies (Node.js, Python, etc.)
- ✅ Create a dedicated service user
- ✅ Set up the Python virtual environment
- ✅ Install Node.js and Python dependencies
- ✅ Build the application
- ✅ Create a systemd service for auto-startup
- ✅ Configure firewall rules
- ✅ Optionally set up Nginx reverse proxy

## 🧪 Testing Your Deployment

### Test the Service

```bash
# Check if service is running
sudo systemctl status streamvix-personal

# View logs
sudo journalctl -u streamvix-personal -f

# Test the endpoint
curl http://localhost:7860/manifest.json
```

### Test External Access

```bash
# Replace YOUR_SERVER_IP with your actual VPS IP
curl http://YOUR_SERVER_IP:7860/manifest.json
```

## 🔧 Configuration Options

### Environment Variables

Edit `/opt/streamvix/.env.production` if needed:

```env
NODE_ENV=production
PORT=7860
PYTHON_BIN=/opt/streamvix/.venv/bin/python
```

### Service Management

```bash
# Start the service
sudo systemctl start streamvix-personal

# Stop the service
sudo systemctl stop streamvix-personal

# Restart the service
sudo systemctl restart streamvix-personal

# Enable auto-start on boot
sudo systemctl enable streamvix-personal

# View detailed logs
sudo journalctl -u streamvix-personal --since "1 hour ago"
```

## 🌍 Adding to Stremio

Once deployed and running:

1. **Get your manifest URL**:
   ```
   http://YOUR_SERVER_IP:7860/manifest.json
   ```

2. **Add to Stremio**:
   - Open Stremio
   - Go to Settings → Add-ons
   - Click "Add Addon"
   - Enter your manifest URL
   - Click "Install"

## 🔍 Troubleshooting

### Common Issues

1. **Port 7860 blocked**:
   ```bash
   sudo ufw allow 7860/tcp
   ```

2. **Service won't start**:
   ```bash
   # Check logs for errors
   sudo journalctl -u streamvix-personal -n 50
   
   # Check Python environment
   sudo -u streamvix /opt/streamvix/.venv/bin/python --version
   ```

3. **Permission issues**:
   ```bash
   sudo chown -R streamvix:streamvix /opt/streamvix
   ```

### Log Locations

- **Service logs**: `sudo journalctl -u streamvix-personal`
- **Nginx logs**: `/var/log/nginx/access.log` and `/var/log/nginx/error.log`

## 🎉 Success Indicators

✅ Service status shows "active (running)"
✅ Manifest URL responds with JSON
✅ Channels load in catalogs
✅ Streams are accessible
✅ EPG data is updating

## 🔄 Updates and Maintenance

To update your addon:

1. **Prepare new deployment package** locally
2. **Upload to VPS**
3. **Stop service**: `sudo systemctl stop streamvix-personal`
4. **Backup current installation**: `sudo cp -r /opt/streamvix /opt/streamvix.backup`
5. **Replace files**: Copy new files to `/opt/streamvix`
6. **Rebuild**: `sudo -u streamvix bash -c 'cd /opt/streamvix && npm run build'`
7. **Start service**: `sudo systemctl start streamvix-personal`

---

## 🆘 Need Help?

If you encounter issues:
1. Check the service logs: `sudo journalctl -u streamvix-personal`
2. Verify Python environment: `sudo -u streamvix /opt/streamvix/.venv/bin/python --version`
3. Test local connectivity: `curl http://localhost:7860/manifest.json`
4. Check firewall: `sudo ufw status`