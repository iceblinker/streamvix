# StreamViX Personal - VPS Deployment Package Creator (Windows)
# This script prepares your addon for VPS deployment

Write-Host "🚀 Creating StreamViX Personal deployment package..." -ForegroundColor Green

# Create deployment directory
New-Item -ItemType Directory -Force -Path "streamvix-deploy" | Out-Null

# Copy essential files
Write-Host "📁 Copying core files..." -ForegroundColor Yellow
Copy-Item -Recurse -Force "dist" "streamvix-deploy\"
Copy-Item -Recurse -Force "src" "streamvix-deploy\"
Copy-Item -Recurse -Force "config" "streamvix-deploy\"
Copy-Item -Recurse -Force "public" "streamvix-deploy\"
Copy-Item -Recurse -Force "scripts" "streamvix-deploy\"

# Copy configuration files
Copy-Item -Force "package.json" "streamvix-deploy\"
Copy-Item -Force "addon-config.json" "streamvix-deploy\"
Copy-Item -Force "requirements.txt" "streamvix-deploy\"
Copy-Item -Force "tsconfig.json" "streamvix-deploy\"
Copy-Item -Force "docker-compose.yml" "streamvix-deploy\"
Copy-Item -Force "Dockerfile" "streamvix-deploy\"

# Copy Python scripts
Get-ChildItem -Filter "*.py" | Copy-Item -Destination "streamvix-deploy\"

# Copy deployment scripts if they exist
Get-ChildItem -Filter "deploy-*" | Copy-Item -Destination "streamvix-deploy\"

# Create production environment file
$envContent = @"
NODE_ENV=production
PORT=7860
PYTHON_BIN=/opt/streamvix/.venv/bin/python
PYTHONPATH=/opt/streamvix/.venv/lib/python*/site-packages
"@
$envContent | Out-File -FilePath "streamvix-deploy\.env.production" -Encoding UTF8

Write-Host "✅ Deployment package created in 'streamvix-deploy' directory" -ForegroundColor Green

# Create archive for easy transfer
if (Get-Command "tar" -ErrorAction SilentlyContinue) {
    tar -czf streamvix-personal-deployment.tar.gz streamvix-deploy/
    Write-Host "📦 Archive created: streamvix-personal-deployment.tar.gz" -ForegroundColor Green
} elseif (Get-Command "7z" -ErrorAction SilentlyContinue) {
    7z a streamvix-personal-deployment.zip streamvix-deploy\
    Write-Host "📦 Archive created: streamvix-personal-deployment.zip" -ForegroundColor Green
} else {
    Write-Host "📦 Package ready in 'streamvix-deploy' directory" -ForegroundColor Green
    Write-Host "💡 Tip: Compress this folder manually or use your preferred archiving tool" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Upload the archive to your VPS" -ForegroundColor White
Write-Host "2. Extract it on your VPS" -ForegroundColor White
Write-Host "3. Run the VPS setup script" -ForegroundColor White