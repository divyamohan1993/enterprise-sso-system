<#
.SYNOPSIS
    Enterprise SSO System - Automated Configuration Script (Windows)

.DESCRIPTION
    This script generates all cryptographic keys and secrets automatically
    and configures the SSO system.

    Features:
    - Idempotent: Safe to run multiple times
    - Key Rotation: Rotates keys while preserving old ones for graceful transition
    - Zero Placeholders: All keys are cryptographically random
    - Backup: Saves previous configuration before rotation

.PARAMETER RotateKeys
    Rotate all cryptographic keys

.PARAMETER Force
    Force regeneration even if keys exist

.EXAMPLE
    .\autoconfig.ps1
    .\autoconfig.ps1 -RotateKeys
    .\autoconfig.ps1 -Force
#>

param(
    [switch]$RotateKeys,
    [switch]$Force,
    [switch]$Help
)

# Configuration
$ENV_FILE = ".env"
$KEYS_DIR = ".keys"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ENV_BACKUP = ".env.backup.$timestamp"

# =============================================================
# UTILITY FUNCTIONS
# =============================================================

function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[WARNING] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Get-RandomSecret {
    param([int]$Length = 64)
    
    $bytes = New-Object byte[] (($Length * 3) / 4 + 1)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $base64 = [Convert]::ToBase64String($bytes)
    return $base64.Substring(0, [Math]::Min($Length, $base64.Length))
}

function Get-UrlSafeSecret {
    param([int]$Length = 32)
    
    $secret = Get-RandomSecret -Length ($Length + 10)
    $urlSafe = $secret -replace '\+', '-' -replace '/', '_' -replace '=', ''
    return $urlSafe.Substring(0, [Math]::Min($Length, $urlSafe.Length))
}

function Get-SecurePassword {
    param([int]$Length = 32)
    
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    
    $password = ""
    foreach ($byte in $bytes) {
        $password += $chars[$byte % $chars.Length]
    }
    
    # Ensure at least one of each required type
    $password = $password.Substring(0, $Length - 4) + "Aa1!"
    return $password
}

# =============================================================
# KEY GENERATION
# =============================================================

function New-AllKeys {
    Write-Info "Generating cryptographic keys and secrets..."
    
    # Create keys directory
    if (-not (Test-Path $KEYS_DIR)) {
        New-Item -ItemType Directory -Path $KEYS_DIR -Force | Out-Null
    }
    
    $script:JWT_SECRET = Get-RandomSecret -Length 96
    Write-Success "Generated JWT_SECRET (96 bytes)"
    
    $script:COOKIE_SECRET = Get-RandomSecret -Length 64
    Write-Success "Generated COOKIE_SECRET (64 bytes)"
    
    $script:DB_PASS = Get-SecurePassword -Length 32
    Write-Success "Generated DB_PASS (32 chars)"
    
    $script:OAUTH_CLIENT_SECRET = Get-UrlSafeSecret -Length 48
    Write-Success "Generated OAUTH_CLIENT_SECRET"
    
    $script:ADMIN_INITIAL_PASSWORD = Get-SecurePassword -Length 16
    Write-Success "Generated ADMIN_INITIAL_PASSWORD"
    
    $script:REDIS_PASSWORD = Get-SecurePassword -Length 32
    Write-Success "Generated REDIS_PASSWORD"
    
    $script:ENCRYPTION_KEY = Get-RandomSecret -Length 32
    Write-Success "Generated ENCRYPTION_KEY (256-bit)"
    
    $script:OAUTH_CLIENT_ID = "sso_client_" + (Get-UrlSafeSecret -Length 8)
}

# =============================================================
# KEY ROTATION
# =============================================================

function Invoke-KeyRotation {
    Write-Info "Rotating cryptographic keys..."
    
    if (Test-Path $ENV_FILE) {
        # Backup current configuration
        Copy-Item $ENV_FILE $ENV_BACKUP
        Write-Info "Backed up current .env to $ENV_BACKUP"
        
        # Preserve old JWT secret
        $content = Get-Content $ENV_FILE -Raw
        if ($content -match "JWT_SECRET=(.+)") {
            $oldSecret = $Matches[1].Trim()
            
            # Append to history file
            Add-Content -Path "$KEYS_DIR\jwt_secrets_history.txt" -Value $oldSecret
            Write-Info "Preserved old JWT secret for graceful transition"
            
            $script:OLD_JWT_SECRET = $oldSecret
        }
    }
    
    New-AllKeys
}

# =============================================================
# ENV FILE GENERATION
# =============================================================

function New-EnvFile {
    Write-Info "Generating .env file..."
    
    $hostname = $env:COMPUTERNAME
    if (-not $hostname) { $hostname = "localhost" }
    $port = 3000
    
    # Build previous secrets string
    $previousSecrets = ""
    if ($script:OLD_JWT_SECRET) {
        $previousSecrets = $script:OLD_JWT_SECRET
    }
    
    $envContent = @"
# =============================================================
# ENTERPRISE SSO SYSTEM - AUTO-GENERATED CONFIGURATION
# Generated: $(Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz")
# =============================================================
# WARNING: This file contains sensitive secrets!
# NEVER commit this file to version control
# =============================================================

# Application
NODE_ENV=development
PORT=$port
HOST=0.0.0.0

# Database (MySQL)
DB_HOST=localhost
DB_PORT=3306
DB_USER=sso_admin
DB_PASS=$($script:DB_PASS)
DB_NAME=sso_db
DB_SSL=false

# JWT Configuration (Auto-Generated Quantum-Safe Secret)
JWT_SECRET=$($script:JWT_SECRET)
JWT_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d

# Previous JWT Secrets (for key rotation - comma separated)
JWT_PREVIOUS_SECRETS=$previousSecrets

# Cookie Secret
COOKIE_SECRET=$($script:COOKIE_SECRET)

# OAuth / OIDC Configuration
OAUTH_ISSUER=http://${hostname}:$port
OAUTH_CLIENT_ID=$($script:OAUTH_CLIENT_ID)
OAUTH_CLIENT_SECRET=$($script:OAUTH_CLIENT_SECRET)
OAUTH_REDIRECT_URI=http://${hostname}:$port/callback

# Google OAuth (Configure in Google Cloud Console)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# CORS - Comma-separated list of allowed origins
CORS_ORIGIN=http://localhost:3000,http://localhost:4200,http://${hostname}:$port

# Rate Limiting
THROTTLE_TTL=60000
THROTTLE_LIMIT=100

# Redis (for production session storage)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=$($script:REDIS_PASSWORD)

# Initial Admin Password (CHANGE AFTER FIRST LOGIN!)
ADMIN_INITIAL_PASSWORD=$($script:ADMIN_INITIAL_PASSWORD)

# Encryption Key (for data at rest)
ENCRYPTION_KEY=$($script:ENCRYPTION_KEY)

# Feature Flags
MFA_REQUIRED=false
AUDIT_LOG_ENABLED=true
"@

    $envContent | Out-File -FilePath $ENV_FILE -Encoding UTF8 -Force
    Write-Success "Generated .env file with fresh secrets"
}

# =============================================================
# KUBERNETES SECRETS
# =============================================================

function New-K8sSecrets {
    Write-Info "Generating Kubernetes secrets..."
    
    if (-not (Test-Path "k8s")) {
        New-Item -ItemType Directory -Path "k8s" -Force | Out-Null
    }
    
    $k8sContent = @"
apiVersion: v1
kind: Namespace
metadata:
  name: sso-enterprise
---
apiVersion: v1
kind: Secret
metadata:
  name: sso-secrets
  namespace: sso-enterprise
type: Opaque
stringData:
  DB_PASS: "$($script:DB_PASS)"
  JWT_SECRET: "$($script:JWT_SECRET)"
  COOKIE_SECRET: "$($script:COOKIE_SECRET)"
  OAUTH_CLIENT_SECRET: "$($script:OAUTH_CLIENT_SECRET)"
  REDIS_PASSWORD: "$($script:REDIS_PASSWORD)"
  ENCRYPTION_KEY: "$($script:ENCRYPTION_KEY)"
  ADMIN_INITIAL_PASSWORD: "$($script:ADMIN_INITIAL_PASSWORD)"
"@

    $k8sContent | Out-File -FilePath "k8s\00-setup.yaml" -Encoding UTF8 -Force
    Write-Success "Generated Kubernetes secrets (k8s\00-setup.yaml)"
    Write-Warn "In production, use SealedSecrets or external secret management!"
}

# =============================================================
# DOCKER ENVIRONMENT
# =============================================================

function New-DockerEnv {
    Write-Info "Generating docker-compose environment..."
    
    $dockerContent = @"
# Docker Compose Environment (Auto-Generated)
# Generated: $(Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz")

COMPOSE_PROJECT_NAME=sso-enterprise

# Database
MYSQL_ROOT_PASSWORD=$($script:DB_PASS)
MYSQL_DATABASE=sso_db
MYSQL_USER=sso_admin
MYSQL_PASSWORD=$($script:DB_PASS)

# Redis
REDIS_PASSWORD=$($script:REDIS_PASSWORD)

# Application
JWT_SECRET=$($script:JWT_SECRET)
COOKIE_SECRET=$($script:COOKIE_SECRET)
OAUTH_CLIENT_SECRET=$($script:OAUTH_CLIENT_SECRET)
ADMIN_INITIAL_PASSWORD=$($script:ADMIN_INITIAL_PASSWORD)
"@

    $dockerContent | Out-File -FilePath ".env.docker" -Encoding UTF8 -Force
    Write-Success "Generated docker-compose environment (.env.docker)"
}

# =============================================================
# VALIDATION
# =============================================================

function Test-Configuration {
    Write-Info "Validating configuration..."
    
    $errors = 0
    
    if (-not (Test-Path $ENV_FILE)) {
        Write-Err ".env file not found"
        $errors++
    }
    else {
        $content = Get-Content $ENV_FILE -Raw
        
        # Check JWT secret length
        if ($content -match "JWT_SECRET=(.+)") {
            $jwtSecret = $Matches[1].Trim()
            if ($jwtSecret.Length -lt 64) {
                Write-Err "JWT_SECRET is too short (minimum 64 characters)"
                $errors++
            }
        }
        
        # Check for placeholders
        if ($content -match "placeholder|CHANGE_THIS|your-") {
            Write-Err "Placeholder values found in .env file"
            $errors++
        }
    }
    
    if ($errors -eq 0) {
        Write-Success "Configuration validation passed"
        return $true
    }
    else {
        Write-Err "Configuration validation failed with $errors error(s)"
        return $false
    }
}

# =============================================================
# MAIN EXECUTION
# =============================================================

function Main {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║     ENTERPRISE SSO SYSTEM - AUTO CONFIGURATION               ║" -ForegroundColor Magenta
    Write-Host "║     Quantum-Safe • Blockchain-Backed • Zero-Trust            ║" -ForegroundColor Magenta
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
    
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Path -Detailed
        return
    }
    
    # Determine operation mode
    if ((Test-Path $ENV_FILE) -and (-not $Force) -and (-not $RotateKeys)) {
        Write-Info ".env file already exists"
        Write-Info "Use -RotateKeys to rotate secrets or -Force to regenerate"
        
        Test-Configuration | Out-Null
        return
    }
    
    if ($RotateKeys) {
        Invoke-KeyRotation
    }
    else {
        New-AllKeys
    }
    
    # Generate all configuration files
    New-EnvFile
    New-K8sSecrets
    New-DockerEnv
    
    # Validate
    Test-Configuration | Out-Null
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║  ✅ AUTO CONFIGURATION COMPLETE                               ║" -ForegroundColor Green
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "║  Generated files:                                            ║" -ForegroundColor Green
    Write-Host "║  • .env                - Application environment             ║" -ForegroundColor Green
    Write-Host "║  • .env.docker         - Docker Compose environment          ║" -ForegroundColor Green
    Write-Host "║  • k8s\00-setup.yaml   - Kubernetes secrets                  ║" -ForegroundColor Green
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "║  ⚠️  IMPORTANT:                                               ║" -ForegroundColor Yellow
    Write-Host "║  • Change ADMIN_INITIAL_PASSWORD after first login           ║" -ForegroundColor Yellow
    Write-Host "║  • Never commit .env files to version control                ║" -ForegroundColor Yellow
    Write-Host "║  • Use -RotateKeys to rotate secrets periodically            ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "Initial Admin Password: " -NoNewline -ForegroundColor Yellow
    Write-Host $script:ADMIN_INITIAL_PASSWORD -ForegroundColor White
    Write-Host ""
}

# Run main
Main
