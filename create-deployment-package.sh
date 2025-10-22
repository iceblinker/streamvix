#!/bin/bash

# StreamViX Personal - VPS Deployment Package Creator
# This script prepares your addon for VPS deployment

echo "🚀 Creating StreamViX Personal deployment package..."

# Create deployment directory
mkdir -p streamvix-deploy

# Copy essential files
echo "📁 Copying core files..."
cp -r dist/ streamvix-deploy/
cp -r src/ streamvix-deploy/
cp -r config/ streamvix-deploy/
cp -r public/ streamvix-deploy/
cp -r scripts/ streamvix-deploy/

# Copy configuration files
cp package.json streamvix-deploy/
cp addon-config.json streamvix-deploy/
cp requirements.txt streamvix-deploy/
cp tsconfig.json streamvix-deploy/
cp docker-compose.yml streamvix-deploy/
cp Dockerfile streamvix-deploy/

# Copy Python scripts
cp *.py streamvix-deploy/

# Copy deployment scripts
cp deploy-*.sh streamvix-deploy/ 2>/dev/null || true
cp deploy-*.ps1 streamvix-deploy/ 2>/dev/null || true

# Create production environment file
cat > streamvix-deploy/.env.production << 'EOF'
NODE_ENV=production
PORT=7860
PYTHON_BIN=/opt/streamvix/.venv/bin/python
PYTHONPATH=/opt/streamvix/.venv/lib/python*/site-packages
EOF

echo "✅ Deployment package created in 'streamvix-deploy' directory"
echo "📦 Ready to upload to your VPS!"

# Create archive for easy transfer
tar -czf streamvix-personal-deployment.tar.gz streamvix-deploy/
echo "📦 Archive created: streamvix-personal-deployment.tar.gz"
echo ""
echo "Next steps:"
echo "1. Upload streamvix-personal-deployment.tar.gz to your VPS"
echo "2. Extract it on your VPS"
echo "3. Run the VPS setup script"