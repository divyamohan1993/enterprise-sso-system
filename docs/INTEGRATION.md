
# Enterprise SSO Integration Guide

This guide explains how to integrate any application (Java, Python, Node, etc.) with the Enterprise SSO System.

## Architecture

The SSO System acts as an **OpenID Connect (OIDC)** compatible Identity Provider. Your application acts as a **Relying Party (RP)**.

### Endpoints (Base URL: `http://localhost:3000` or Configured Domain)

1.  **Discovery**: `/.well-known/openid-configuration`
    *   Returns all necessary endpoint URLs and public keys locations.
    *   **Recommendation**: Use an OIDC Client library that checks this endpoint automatically.

2.  **Authorization**: `/oauth/authorize`
    *   Redirect user here to login.
    *   Params: `response_type=code`, `client_id=...`, `redirect_uri=...`, `scope=openid profile`

3.  **Token**: `/oauth/token`
    *   Exchange the code returned for Access/ID tokens.
    *   Auth: Basic Auth with Client ID & Secret.

4.  **UserInfo**: `/oauth/userinfo`
    *   Get user details using the Access Token.

## Integration Steps

### 1. Register Your Client
Currently, valid clients are defined in the SSO Global Config.
*   Client ID: `default_client`
*   Redirect URI: Must match `OAUTH_REDIRECT_URI` in config (Default: `http://localhost:3000/callback`).

### 2. Configure Your Application

#### Node.js (Passport)
```javascript
const crypto = require('crypto');
const Strategy = require('passport-openidconnect').Strategy;

passport.use(new Strategy({
  issuer: 'http://localhost:3000',
  authorizationURL: 'http://localhost:3000/oauth/authorize',
  tokenURL: 'http://localhost:3000/oauth/token',
  userInfoURL: 'http://localhost:3000/oauth/userinfo',
  clientID: 'default_client',
  clientSecret: 'secret', // Not enforced strictly in demo
  callbackURL: 'http://yourapp.com/callback'
},
function(issuer, sub, profile, accessToken, refreshToken, cb) {
  return cb(null, profile);
}));
```

#### Generic (Manual Flow)
1. Redirect user to: `http://localhost:3000/oauth/authorize?client_id=default_client&redirect_uri=http://yourapp.com/cb&response_type=code&scope=openid`
2. User Logs in. SSO Redirects to: `http://yourapp.com/cb?code=AUTH_CODE`
3. POST to `http://localhost:3000/oauth/token` with `code=AUTH_CODE` and `grant_type=authorization_code`.
4. Receive JWT. Validate signature using keys from `/.well-known/jwks.json`.

## Security Features
*   **Quantum-Safe**: Audit logs are signed with Post-Quantum Cryptography.
*   **Blockchain**: Every login is immutably recorded.
*   **Strict Mode**: All domains and redirects are strictly validated against the Allowlist.
