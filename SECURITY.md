# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously at Enterprise SSO System. If you discover a security vulnerability, please follow these steps:

### 1. Do NOT disclose publicly

Please **do not** create a public GitHub issue for security vulnerabilities.

### 2. Report privately

Send a detailed report to: security@your-domain.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### 3. Response timeline

- **24 hours**: Initial acknowledgment
- **72 hours**: Preliminary assessment
- **7 days**: Detailed response with remediation plan
- **30 days**: Target for fix deployment

## Security Features

This SSO system implements:

- **Quantum-Safe Cryptography**: ML-DSA-65 (Dilithium) for post-quantum digital signatures
- **Blockchain Audit Trail**: Immutable, cryptographically signed audit logs
- **Argon2id Password Hashing**: OWASP-recommended password hashing
- **MFA Support**: TOTP-based two-factor authentication
- **Rate Limiting**: Protection against brute force attacks
- **OIDC/OAuth 2.0**: Standards-compliant authentication protocols
- **PKCE Support**: Proof Key for Code Exchange for mobile/SPA clients
- **Secure Headers**: Comprehensive security headers via Helmet.js

## Security Best Practices

1. **Secrets Management**: Never commit secrets to version control
2. **Environment Variables**: Use encrypted secrets in production
3. **TLS/HTTPS**: Always use HTTPS in production
4. **Regular Updates**: Keep dependencies updated
5. **Audit Logs**: Monitor blockchain audit trail for anomalies
6. **MFA Enforcement**: Enable MFA for all administrative accounts

## Vulnerability Disclosure

We follow responsible disclosure practices. Security researchers who report vulnerabilities responsibly will be acknowledged in our security hall of fame (with permission).
