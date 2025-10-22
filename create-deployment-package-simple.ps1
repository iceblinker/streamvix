# StreamViX Personal - VPS Deployment Package Creator (Windows)
Write-Host "🚀 Creating StreamViX Personal deployment package..." -ForegroundColor Green

# Create deployment directory
New-Item -ItemType Directory -Force -Path "streamvix-deploy" | Out-Null

# Copy essential files
Write-Host "📁 Copying core files..." -ForegroundColor Yellow
Copy-Item -Recurse -Force "dist" "streamvix-deploy\"
Copy-Item -Recurse -Force "src" "streamvix-deploy\"
Copy-Item -Recurse -Force "config" "streamvix-deploy\"
Copy-Item -Recurse -Force "public" "streamvix-deploy\"

# Copy configuration files
Copy-Item -Force "package.json" "streamvix-deploy\"
Copy-Item -Force "addon-config.json" "streamvix-deploy\"
Copy-Item -Force "requirements.txt" "streamvix-deploy\"
Copy-Item -Force "docker-compose.yml" "streamvix-deploy\"
Copy-Item -Force "Dockerfile" "streamvix-deploy\"

# Copy Python scripts
Get-ChildItem -Filter "*.py" | Copy-Item -Destination "streamvix-deploy\"

# Create production environment file
"NODE_ENV=production`nPORT=7860`nPYTHON_BIN=/opt/streamvix/.venv/bin/python" | Out-File -FilePath "streamvix-deploy\.env.production" -Encoding UTF8

Write-Host "✅ Deployment package created in 'streamvix-deploy' directory" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Upload the 'streamvix-deploy' folder to your VPS" -ForegroundColor White
Write-Host "2. Extract it on your VPS" -ForegroundColor White
Write-Host "3. Run the VPS setup script" -ForegroundColor White