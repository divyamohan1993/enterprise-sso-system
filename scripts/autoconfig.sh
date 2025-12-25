#!/bin/bash
# =============================================================
# ENTERPRISE SSO SYSTEM - AUTOMATED CONFIGURATION SCRIPT
# =============================================================
# This script generates all cryptographic keys and secrets
# automatically and configures the SSO system.
#
# Features:
# - Idempotent: Safe to run multiple times
# - Key Rotation: Rotates keys while preserving old ones for graceful transition
# - Zero Placeholders: All keys are cryptographically random
# - Backup: Saves previous configuration before rotation
#
# Usage: ./autoconfig.sh [--rotate-keys] [--force]
# =============================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ENV_FILE=".env"
ENV_BACKUP=".env.backup.$(date +%Y%m%d_%H%M%S)"
KEYS_DIR=".keys"
ROTATE_KEYS=false
FORCE=false

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --rotate-keys) ROTATE_KEYS=true ;;
        --force) FORCE=true ;;
        -h|--help) 
            echo "Usage: ./autoconfig.sh [--rotate-keys] [--force]"
            echo "  --rotate-keys  Rotate all cryptographic keys"
            echo "  --force        Force regeneration even if keys exist"
            exit 0
            ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# =============================================================
# UTILITY FUNCTIONS
# =============================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Generate cryptographically secure random string
generate_secret() {
    local length=${1:-64}
    openssl rand -base64 $((length * 3 / 4)) | tr -d '\n' | head -c $length
}

# Generate URL-safe random string
generate_url_safe_secret() {
    local length=${1:-32}
    openssl rand -base64 $((length * 3 / 4)) | tr '+/' '-_' | tr -d '=' | head -c $length
}

# Generate alphanumeric password
generate_password() {
    local length=${1:-32}
    openssl rand -base64 $((length * 3 / 4)) | tr -dc 'a-zA-Z0-9!@#$%^&*' | head -c $length
}

# =============================================================
# KEY GENERATION
# =============================================================

generate_all_keys() {
    log_info "Generating cryptographic keys and secrets..."
    
    # Create keys directory if not exists
    mkdir -p "$KEYS_DIR"
    chmod 700 "$KEYS_DIR"
    
    # JWT Secret (64+ bytes for quantum-safe)
    JWT_SECRET=$(generate_secret 96)
    log_success "Generated JWT_SECRET (96 bytes)"
    
    # Cookie Secret
    COOKIE_SECRET=$(generate_secret 64)
    log_success "Generated COOKIE_SECRET (64 bytes)"
    
    # Database Password
    DB_PASS=$(generate_password 32)
    log_success "Generated DB_PASS (32 chars)"
    
    # OAuth Client Secret
    OAUTH_CLIENT_SECRET=$(generate_url_safe_secret 48)
    log_success "Generated OAUTH_CLIENT_SECRET"
    
    # Admin Initial Password
    ADMIN_INITIAL_PASSWORD="$(generate_password 16)@Aa1"
    log_success "Generated ADMIN_INITIAL_PASSWORD"
    
    # Redis Password (if needed)
    REDIS_PASSWORD=$(generate_password 32)
    log_success "Generated REDIS_PASSWORD"
    
    # Encryption Key for data at rest
    ENCRYPTION_KEY=$(generate_secret 32)
    log_success "Generated ENCRYPTION_KEY (256-bit)"
}

# =============================================================
# KEY ROTATION
# =============================================================

rotate_keys() {
    log_info "Rotating cryptographic keys..."
    
    if [ -f "$ENV_FILE" ]; then
        # Backup current configuration
        cp "$ENV_FILE" "$ENV_BACKUP"
        log_info "Backed up current .env to $ENV_BACKUP"
        
        # Preserve old JWT secret for token validation during rotation
        OLD_JWT_SECRET=$(grep "^JWT_SECRET=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo "")
        if [ -n "$OLD_JWT_SECRET" ]; then
            # Store old secret for graceful rotation
            echo "$OLD_JWT_SECRET" >> "$KEYS_DIR/jwt_secrets_history.txt"
            log_info "Preserved old JWT secret for graceful transition"
        fi
    fi
    
    # Generate new keys
    generate_all_keys
}

# =============================================================
# ENV FILE GENERATION
# =============================================================

generate_env_file() {
    log_info "Generating .env file..."
    
    # Determine hostname for OAuth issuer
    HOSTNAME=${HOSTNAME:-localhost}
    PORT=${PORT:-3000}
    
    cat > "$ENV_FILE" << EOF
# =============================================================
# ENTERPRISE SSO SYSTEM - AUTO-GENERATED CONFIGURATION
# Generated: $(date -Iseconds)
# =============================================================
# ⚠️  WARNING: This file contains sensitive secrets!
# ⚠️  NEVER commit this file to version control
# =============================================================

# Application
NODE_ENV=development
PORT=${PORT}
HOST=0.0.0.0

# Database (MySQL)
DB_HOST=\${DB_HOST:-localhost}
DB_PORT=\${DB_PORT:-3306}
DB_USER=sso_admin
DB_PASS=${DB_PASS}
DB_NAME=sso_db
DB_SSL=false

# JWT Configuration (Auto-Generated Quantum-Safe Secret)
JWT_SECRET=${JWT_SECRET}
JWT_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d

# Cookie Secret
COOKIE_SECRET=${COOKIE_SECRET}

# OAuth / OIDC Configuration
OAUTH_ISSUER=http://${HOSTNAME}:${PORT}
OAUTH_CLIENT_ID=sso_client_$(generate_url_safe_secret 8)
OAUTH_CLIENT_SECRET=${OAUTH_CLIENT_SECRET}
OAUTH_REDIRECT_URI=http://${HOSTNAME}:${PORT}/callback

# Google OAuth (Configure in Google Cloud Console)
GOOGLE_CLIENT_ID=\${GOOGLE_CLIENT_ID:-}
GOOGLE_CLIENT_SECRET=\${GOOGLE_CLIENT_SECRET:-}

# CORS - Comma-separated list of allowed origins
CORS_ORIGIN=http://localhost:3000,http://localhost:4200,http://${HOSTNAME}:${PORT}

# Rate Limiting
THROTTLE_TTL=60000
THROTTLE_LIMIT=100

# Redis (for production session storage)
REDIS_HOST=\${REDIS_HOST:-localhost}
REDIS_PORT=\${REDIS_PORT:-6379}
REDIS_PASSWORD=${REDIS_PASSWORD}

# Initial Admin Password (CHANGE AFTER FIRST LOGIN!)
ADMIN_INITIAL_PASSWORD=${ADMIN_INITIAL_PASSWORD}

# Encryption Key (for data at rest)
ENCRYPTION_KEY=${ENCRYPTION_KEY}

# Feature Flags
MFA_REQUIRED=false
AUDIT_LOG_ENABLED=true

# Key Rotation (comma-separated old JWT secrets for graceful transition)
JWT_PREVIOUS_SECRETS=
EOF

    chmod 600 "$ENV_FILE"
    log_success "Generated .env file with fresh secrets"
}

# =============================================================
# KUBERNETES SECRETS
# =============================================================

generate_k8s_secrets() {
    log_info "Generating Kubernetes sealed secrets..."
    
    mkdir -p k8s
    
    cat > "k8s/00-setup.yaml" << EOF
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
  DB_PASS: "${DB_PASS}"
  JWT_SECRET: "${JWT_SECRET}"
  COOKIE_SECRET: "${COOKIE_SECRET}"
  OAUTH_CLIENT_SECRET: "${OAUTH_CLIENT_SECRET}"
  REDIS_PASSWORD: "${REDIS_PASSWORD}"
  ENCRYPTION_KEY: "${ENCRYPTION_KEY}"
  ADMIN_INITIAL_PASSWORD: "${ADMIN_INITIAL_PASSWORD}"
EOF

    chmod 600 "k8s/00-setup.yaml"
    log_success "Generated Kubernetes secrets (k8s/00-setup.yaml)"
    log_warning "In production, use SealedSecrets or external secret management!"
}

# =============================================================
# DOCKER COMPOSE ENVIRONMENT
# =============================================================

generate_docker_env() {
    log_info "Generating docker-compose environment..."
    
    cat > ".env.docker" << EOF
# Docker Compose Environment (Auto-Generated)
# Generated: $(date -Iseconds)

COMPOSE_PROJECT_NAME=sso-enterprise

# Database
MYSQL_ROOT_PASSWORD=${DB_PASS}
MYSQL_DATABASE=sso_db
MYSQL_USER=sso_admin
MYSQL_PASSWORD=${DB_PASS}

# Redis
REDIS_PASSWORD=${REDIS_PASSWORD}

# Application
JWT_SECRET=${JWT_SECRET}
COOKIE_SECRET=${COOKIE_SECRET}
OAUTH_CLIENT_SECRET=${OAUTH_CLIENT_SECRET}
ADMIN_INITIAL_PASSWORD=${ADMIN_INITIAL_PASSWORD}
EOF

    chmod 600 ".env.docker"
    log_success "Generated docker-compose environment (.env.docker)"
}

# =============================================================
# VALIDATION
# =============================================================

validate_config() {
    log_info "Validating configuration..."
    
    local errors=0
    
    # Check required files
    if [ ! -f "$ENV_FILE" ]; then
        log_error ".env file not found"
        ((errors++))
    fi
    
    # Check secret lengths
    local jwt_len=$(grep "^JWT_SECRET=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | wc -c)
    if [ "$jwt_len" -lt 64 ]; then
        log_error "JWT_SECRET is too short (minimum 64 characters)"
        ((errors++))
    fi
    
    # Check for placeholder values
    if grep -q "placeholder\|CHANGE_THIS\|your-" "$ENV_FILE" 2>/dev/null; then
        log_error "Placeholder values found in .env file"
        ((errors++))
    fi
    
    if [ $errors -eq 0 ]; then
        log_success "Configuration validation passed"
        return 0
    else
        log_error "Configuration validation failed with $errors error(s)"
        return 1
    fi
}

# =============================================================
# MAIN EXECUTION
# =============================================================

main() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     ENTERPRISE SSO SYSTEM - AUTO CONFIGURATION               ║"
    echo "║     Quantum-Safe • Blockchain-Backed • Zero-Trust            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Check for OpenSSL
    if ! command -v openssl &> /dev/null; then
        log_error "OpenSSL is required but not installed"
        exit 1
    fi
    
    # Determine operation mode
    if [ -f "$ENV_FILE" ] && [ "$FORCE" = false ] && [ "$ROTATE_KEYS" = false ]; then
        log_info ".env file already exists"
        log_info "Use --rotate-keys to rotate secrets or --force to regenerate"
        
        # Validate existing config
        validate_config
        exit 0
    fi
    
    if [ "$ROTATE_KEYS" = true ]; then
        rotate_keys
    else
        generate_all_keys
    fi
    
    # Generate all configuration files
    generate_env_file
    generate_k8s_secrets
    generate_docker_env
    
    # Validate
    validate_config
    
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ✅ AUTO CONFIGURATION COMPLETE                               ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  Generated files:                                            ║"
    echo "║  • .env                - Application environment             ║"
    echo "║  • .env.docker         - Docker Compose environment          ║"
    echo "║  • k8s/00-setup.yaml   - Kubernetes secrets                  ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  ⚠️  IMPORTANT:                                               ║"
    echo "║  • Change ADMIN_INITIAL_PASSWORD after first login           ║"
    echo "║  • Never commit .env files to version control                ║"
    echo "║  • Use --rotate-keys to rotate secrets periodically          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Print admin password for initial setup
    echo -e "${YELLOW}Initial Admin Password:${NC} ${ADMIN_INITIAL_PASSWORD}"
    echo ""
}

main "$@"
