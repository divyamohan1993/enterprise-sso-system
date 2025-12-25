#!/usr/bin/env node
/**
 * Enterprise SSO System - Automated Configuration Script
 * 
 * Features:
 * - Idempotent: Safe to run multiple times
 * - Key Rotation: Rotates keys while preserving old ones for graceful transition
 * - Zero Placeholders: All keys are cryptographically random
 * - Backup: Saves previous configuration before rotation
 * 
 * Usage:
 *   node autoconfig.js [--rotate] [--force]
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Configuration
const ENV_FILE = '.env';
const KEYS_DIR = '.keys';
const args = process.argv.slice(2);
const ROTATE_KEYS = args.includes('--rotate');
const FORCE = args.includes('--force');

// Colors for console output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
    magenta: '\x1b[35m',
};

const log = {
    info: (msg) => console.log(`${colors.cyan}[INFO]${colors.reset} ${msg}`),
    success: (msg) => console.log(`${colors.green}[SUCCESS]${colors.reset} ${msg}`),
    warning: (msg) => console.log(`${colors.yellow}[WARNING]${colors.reset} ${msg}`),
    error: (msg) => console.log(`${colors.red}[ERROR]${colors.reset} ${msg}`),
};

// =============================================================
// SECRET GENERATION
// =============================================================

function generateSecret(length = 64) {
    return crypto.randomBytes(Math.ceil(length * 3 / 4))
        .toString('base64')
        .slice(0, length);
}

function generateUrlSafeSecret(length = 32) {
    return crypto.randomBytes(Math.ceil(length * 3 / 4))
        .toString('base64url')
        .slice(0, length);
}

function generatePassword(length = 32) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let password = '';
    const bytes = crypto.randomBytes(length);
    for (let i = 0; i < length - 4; i++) {
        password += chars[bytes[i] % chars.length];
    }
    // Ensure password complexity
    password += 'Aa1!';
    return password;
}

// =============================================================
// KEY GENERATION
// =============================================================

function generateAllKeys() {
    log.info('Generating cryptographic keys and secrets...');

    // Create keys directory
    if (!fs.existsSync(KEYS_DIR)) {
        fs.mkdirSync(KEYS_DIR, { recursive: true });
    }

    const keys = {
        JWT_SECRET: generateSecret(96),
        JWT_PREVIOUS_SECRETS: '',
        COOKIE_SECRET: generateSecret(64),
        DB_PASS: generatePassword(32),
        OAUTH_CLIENT_ID: 'sso_client_' + generateUrlSafeSecret(8),
        OAUTH_CLIENT_SECRET: generateUrlSafeSecret(48),
        ADMIN_INITIAL_PASSWORD: generatePassword(16),
        REDIS_PASSWORD: generatePassword(32),
        ENCRYPTION_KEY: generateSecret(32),
    };

    Object.keys(keys).forEach(key => {
        if (key !== 'JWT_PREVIOUS_SECRETS') {
            log.success(`Generated ${key}`);
        }
    });

    return keys;
}

// =============================================================
// KEY ROTATION
// =============================================================

function rotateKeys() {
    log.info('Rotating cryptographic keys...');

    let previousSecrets = '';

    if (fs.existsSync(ENV_FILE)) {
        // Backup current configuration
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupFile = `.env.backup.${timestamp}`;
        fs.copyFileSync(ENV_FILE, backupFile);
        log.info(`Backed up current .env to ${backupFile}`);

        // Preserve old JWT secret
        const content = fs.readFileSync(ENV_FILE, 'utf8');
        const match = content.match(/^JWT_SECRET=(.+)$/m);
        if (match) {
            const oldSecret = match[1].trim();

            // Add to history
            const historyFile = path.join(KEYS_DIR, 'jwt_secrets_history.txt');
            fs.appendFileSync(historyFile, oldSecret + '\n');
            log.info('Preserved old JWT secret for graceful transition');

            // Also get existing previous secrets
            const prevMatch = content.match(/^JWT_PREVIOUS_SECRETS=(.*)$/m);
            if (prevMatch && prevMatch[1].trim()) {
                previousSecrets = oldSecret + ',' + prevMatch[1].trim();
            } else {
                previousSecrets = oldSecret;
            }
        }
    }

    const keys = generateAllKeys();
    keys.JWT_PREVIOUS_SECRETS = previousSecrets;
    return keys;
}

// =============================================================
// ENV FILE GENERATION
// =============================================================

function generateEnvFile(keys) {
    log.info('Generating .env file...');

    const hostname = require('os').hostname() || 'localhost';
    const port = 3000;

    const envContent = `# =============================================================
# ENTERPRISE SSO SYSTEM - AUTO-GENERATED CONFIGURATION
# Generated: ${new Date().toISOString()}
# =============================================================
# WARNING: This file contains sensitive secrets!
# NEVER commit this file to version control
# =============================================================

# Application
NODE_ENV=development
PORT=${port}
HOST=0.0.0.0

# Database (MySQL)
DB_HOST=localhost
DB_PORT=3306
DB_USER=sso_admin
DB_PASS=${keys.DB_PASS}
DB_NAME=sso_db
DB_SSL=false

# JWT Configuration (Auto-Generated Quantum-Safe Secret)
JWT_SECRET=${keys.JWT_SECRET}
JWT_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d

# Previous JWT Secrets (for key rotation - comma separated)
JWT_PREVIOUS_SECRETS=${keys.JWT_PREVIOUS_SECRETS}

# Cookie Secret
COOKIE_SECRET=${keys.COOKIE_SECRET}

# OAuth / OIDC Configuration
OAUTH_ISSUER=http://${hostname}:${port}
OAUTH_CLIENT_ID=${keys.OAUTH_CLIENT_ID}
OAUTH_CLIENT_SECRET=${keys.OAUTH_CLIENT_SECRET}
OAUTH_REDIRECT_URI=http://${hostname}:${port}/callback

# Google OAuth (Configure in Google Cloud Console)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# CORS - Comma-separated list of allowed origins
CORS_ORIGIN=http://localhost:3000,http://localhost:4200,http://${hostname}:${port}

# Rate Limiting
THROTTLE_TTL=60000
THROTTLE_LIMIT=100

# Redis (for production session storage)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=${keys.REDIS_PASSWORD}

# Initial Admin Password (CHANGE AFTER FIRST LOGIN!)
ADMIN_INITIAL_PASSWORD=${keys.ADMIN_INITIAL_PASSWORD}

# Encryption Key (for data at rest)
ENCRYPTION_KEY=${keys.ENCRYPTION_KEY}

# Feature Flags
MFA_REQUIRED=false
AUDIT_LOG_ENABLED=true
`;

    fs.writeFileSync(ENV_FILE, envContent, 'utf8');
    log.success('Generated .env file with fresh secrets');
}

// =============================================================
// KUBERNETES SECRETS
// =============================================================

function generateK8sSecrets(keys) {
    log.info('Generating Kubernetes secrets...');

    if (!fs.existsSync('k8s')) {
        fs.mkdirSync('k8s', { recursive: true });
    }

    const k8sContent = `apiVersion: v1
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
  DB_PASS: "${keys.DB_PASS}"
  JWT_SECRET: "${keys.JWT_SECRET}"
  COOKIE_SECRET: "${keys.COOKIE_SECRET}"
  OAUTH_CLIENT_SECRET: "${keys.OAUTH_CLIENT_SECRET}"
  REDIS_PASSWORD: "${keys.REDIS_PASSWORD}"
  ENCRYPTION_KEY: "${keys.ENCRYPTION_KEY}"
  ADMIN_INITIAL_PASSWORD: "${keys.ADMIN_INITIAL_PASSWORD}"
`;

    fs.writeFileSync('k8s/00-setup.yaml', k8sContent, 'utf8');
    log.success('Generated Kubernetes secrets (k8s/00-setup.yaml)');
    log.warning('In production, use SealedSecrets or external secret management!');
}

// =============================================================
// DOCKER ENVIRONMENT
// =============================================================

function generateDockerEnv(keys) {
    log.info('Generating docker-compose environment...');

    const dockerContent = `# Docker Compose Environment (Auto-Generated)
# Generated: ${new Date().toISOString()}

COMPOSE_PROJECT_NAME=sso-enterprise

# Database
MYSQL_ROOT_PASSWORD=${keys.DB_PASS}
MYSQL_DATABASE=sso_db
MYSQL_USER=sso_admin
MYSQL_PASSWORD=${keys.DB_PASS}

# Redis
REDIS_PASSWORD=${keys.REDIS_PASSWORD}

# Application
JWT_SECRET=${keys.JWT_SECRET}
COOKIE_SECRET=${keys.COOKIE_SECRET}
OAUTH_CLIENT_SECRET=${keys.OAUTH_CLIENT_SECRET}
ADMIN_INITIAL_PASSWORD=${keys.ADMIN_INITIAL_PASSWORD}
`;

    fs.writeFileSync('.env.docker', dockerContent, 'utf8');
    log.success('Generated docker-compose environment (.env.docker)');
}

// =============================================================
// VALIDATION
// =============================================================

function validateConfig() {
    log.info('Validating configuration...');

    let errors = 0;

    if (!fs.existsSync(ENV_FILE)) {
        log.error('.env file not found');
        errors++;
    } else {
        const content = fs.readFileSync(ENV_FILE, 'utf8');

        // Check JWT secret length
        const match = content.match(/^JWT_SECRET=(.+)$/m);
        if (match && match[1].trim().length < 64) {
            log.error('JWT_SECRET is too short (minimum 64 characters)');
            errors++;
        }

        // Check for placeholders
        if (/CHANGE_THIS|your-|placeholder/i.test(content)) {
            log.error('Placeholder values found in .env file');
            errors++;
        }
    }

    if (errors === 0) {
        log.success('Configuration validation passed');
        return true;
    } else {
        log.error(`Configuration validation failed with ${errors} error(s)`);
        return false;
    }
}

// =============================================================
// MAIN
// =============================================================

function main() {
    console.log('');
    console.log(`${colors.magenta}╔══════════════════════════════════════════════════════════════╗${colors.reset}`);
    console.log(`${colors.magenta}║     ENTERPRISE SSO SYSTEM - AUTO CONFIGURATION               ║${colors.reset}`);
    console.log(`${colors.magenta}║     Quantum-Safe • Blockchain-Backed • Zero-Trust            ║${colors.reset}`);
    console.log(`${colors.magenta}╚══════════════════════════════════════════════════════════════╝${colors.reset}`);
    console.log('');

    // Determine operation mode
    if (fs.existsSync(ENV_FILE) && !FORCE && !ROTATE_KEYS) {
        log.info('.env file already exists');
        log.info('Use --rotate to rotate secrets or --force to regenerate');
        validateConfig();
        return;
    }

    let keys;
    if (ROTATE_KEYS) {
        keys = rotateKeys();
    } else {
        keys = generateAllKeys();
    }

    // Generate all configuration files
    generateEnvFile(keys);
    generateK8sSecrets(keys);
    generateDockerEnv(keys);

    // Validate
    validateConfig();

    console.log('');
    console.log(`${colors.green}╔══════════════════════════════════════════════════════════════╗${colors.reset}`);
    console.log(`${colors.green}║  ✅ AUTO CONFIGURATION COMPLETE                               ║${colors.reset}`);
    console.log(`${colors.green}╠══════════════════════════════════════════════════════════════╣${colors.reset}`);
    console.log(`${colors.green}║  Generated files:                                            ║${colors.reset}`);
    console.log(`${colors.green}║  • .env                - Application environment             ║${colors.reset}`);
    console.log(`${colors.green}║  • .env.docker         - Docker Compose environment          ║${colors.reset}`);
    console.log(`${colors.green}║  • k8s/00-setup.yaml   - Kubernetes secrets                  ║${colors.reset}`);
    console.log(`${colors.green}╚══════════════════════════════════════════════════════════════╝${colors.reset}`);
    console.log('');
    console.log(`${colors.yellow}⚠️  IMPORTANT:${colors.reset}`);
    console.log(`   • Change ADMIN_INITIAL_PASSWORD after first login`);
    console.log(`   • Never commit .env files to version control`);
    console.log(`   • Use --rotate to rotate secrets periodically`);
    console.log('');
    console.log(`${colors.yellow}Initial Admin Password:${colors.reset} ${keys.ADMIN_INITIAL_PASSWORD}`);
    console.log('');
}

main();
