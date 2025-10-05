# 🚀 GitHub-Based VPS Deployment Guide

## ✨ **Much Better Approach!** 

Using GitHub for deployment is professional, version-controlled, and easy to maintain.

## 🎯 **Super Simple VPS Deployment**

### **Single Command Deployment**

SSH into your VPS and run:

```bash
curl -sSL https://raw.githubusercontent.com/iceblinker/streamvix/main/github-vps-setup.sh | bash
```

**That's it!** ✨ The script will:
- ✅ Install all dependencies (Node.js, Python, etc.)
- ✅ Clone your repo from GitHub
- ✅ Set up Python virtual environment  
- ✅ Install all packages
- ✅ Build the application
- ✅ Create systemd service
- ✅ Configure firewall
- ✅ Start the addon

### **Manual Method (if you prefer)**

```bash
# SSH into your VPS
ssh your-username@your-vps-ip

# Download the setup script
wget https://raw.githubusercontent.com/iceblinker/streamvix/main/github-vps-setup.sh

# Make it executable
chmod +x github-vps-setup.sh

# Run it
./github-vps-setup.sh
```

## 🔄 **Easy Updates**

When you push changes to GitHub, update your VPS with:

```bash
sudo /opt/streamvix/update-addon.sh
```

This will:
- ✅ Pull latest changes from GitHub
- ✅ Rebuild the application
- ✅ Restart the service

## 🌐 **Access Your Addon**

After deployment:
- **Manifest**: `http://YOUR_VPS_IP:7860/manifest.json`
- **Landing**: `http://YOUR_VPS_IP:7860`

## 📊 **Service Management**

```bash
# Check status
sudo systemctl status streamvix-personal

# View logs
sudo journalctl -u streamvix-personal -f

# Restart
sudo systemctl restart streamvix-personal
```

## 🎊 **Advantages of GitHub Deployment**

✅ **Version Control** - Track all changes
✅ **Easy Updates** - Just git pull and rebuild
✅ **No File Uploads** - Direct from GitHub
✅ **Professional** - Industry standard practice
✅ **Automated** - One command deployment
✅ **Maintainable** - Easy to manage and update

---

## 🚀 **Ready to Deploy!**

Your repo is now available at: `https://github.com/iceblinker/streamvix`

**Single command VPS deployment:** 
```bash
curl -sSL https://raw.githubusercontent.com/iceblinker/streamvix/main/github-vps-setup.sh | bash
```

**Much cleaner and more professional!** 🎯