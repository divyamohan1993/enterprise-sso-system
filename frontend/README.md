# MILNET SSO Frontend

Self-contained single-page web MVP for the Enterprise SSO system. No build tools, no dependencies -- just one HTML file with embedded CSS and JavaScript.

## Quick start

```bash
# Serve the frontend on port 3000
cd frontend && python3 -m http.server 3000
```

Then open http://localhost:3000 in your browser.

## With the admin API (reverse proxy)

When the admin API is running, the frontend calls `/api/*` endpoints. Configure your reverse proxy or API server to:

1. Serve `frontend/index.html` at `/`
2. Proxy `/api/*` to the backend

Example with nginx:

```nginx
server {
    listen 3000;

    location / {
        root /path/to/frontend;
        index index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

Or the admin API can serve this file directly at `/`.

## Pages

| Tab | Description |
|-----|-------------|
| **Login** | Username/password authentication against `/api/auth/login` |
| **Dashboard** | System stats, user registration, portal management, device enrollment |
| **Portal Simulator** | 5 simulated service portals demonstrating SSO token reuse |
| **Audit Log** | Audit trail viewer with hash-chain integrity verification |
| **Security Demo** | Token tampering, expiry, tier, and scope enforcement demos |

## API endpoints used

- `POST /api/auth/login` -- authenticate and receive a token
- `POST /api/auth/verify` -- verify a token (used by security demos)
- `GET  /api/status` -- system status counts
- `POST /api/users` -- register a new user
- `GET  /api/portals` -- list registered portals
- `POST /api/portals` -- register a new portal
- `DELETE /api/portals/:id` -- delete a portal
- `POST /api/devices` -- enroll a device
- `GET  /api/audit` -- fetch audit log entries
- `GET  /api/audit/verify` -- verify audit chain integrity
