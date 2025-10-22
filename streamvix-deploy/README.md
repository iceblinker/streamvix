# StreamViX Personal - Deployment Package

This is your ready-to-deploy StreamViX Personal Stremio addon package.

## 🚀 Quick Start

1. **Upload this entire folder** to your VPS
2. **Make setup script executable**: `chmod +x vps-setup.sh`
3. **Run setup**: `./vps-setup.sh`
4. **Follow the prompts**

## 📁 Package Contents

- `dist/` - Compiled JavaScript application
- `src/` - Source TypeScript code
- `config/` - Configuration files (channels, domains, EPG)
- `public/` - Static assets (icons, landing page)
- `*.py` - Python scripts for live events and channel scraping
- `package.json` - Node.js dependencies
- `requirements.txt` - Python dependencies
- `vps-setup.sh` - Automated VPS setup script
- `DEPLOYMENT-GUIDE.md` - Detailed deployment instructions

## ⚡ Features Included

- ✅ **240+ TV Channels** (Vavoo, TVTap sources)
- ✅ **Live Sports Events** (Football, F1, MotoGP, Tennis, etc.)
- ✅ **EPG Data** (Electronic Program Guide)
- ✅ **Multiple Providers** (VixSrc and others)
- ✅ **Real-time Updates** (Live events every 2 minutes)
- ✅ **Personal Branding** ("StreamViX Personal")

## 🌐 Access After Deployment

- **Manifest**: `http://YOUR_VPS_IP:7860/manifest.json`
- **Landing Page**: `http://YOUR_VPS_IP:7860`
- **TV Channels**: Available in Stremio after adding the addon

## 📋 System Requirements

- Ubuntu 20.04+ or Debian 11+
- 1GB+ RAM (2GB+ recommended)
- 5GB+ free disk space
- Open port 7860 or reverse proxy setup

## 🔧 Service Management

After deployment, use these commands:

```bash
# Check status
sudo systemctl status streamvix-personal

# View logs
sudo journalctl -u streamvix-personal -f

# Restart service
sudo systemctl restart streamvix-personal
```

## 📖 Full Documentation

See `DEPLOYMENT-GUIDE.md` for complete deployment instructions and troubleshooting.

---

**Ready to deploy!** 🎊