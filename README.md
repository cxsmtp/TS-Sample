# Insecure TypeScript Ecommerce Portal (Training Only)

> **Warning**
> This project is intentionally insecure for secure-coding education, SAST benchmarking, and lab use only.
> Do **not** deploy to production or expose it to untrusted networks.

## What is included

- Lightweight **backend** with Express + sqlite (TypeScript).
- Lightweight **frontend** portal (HTML + JS + TS source).
- More than **50 intentionally planted security issues** across auth, injection, crypto, data exposure, and client-side flaws.

## Run

```bash
npm install
npm run dev
```

Then open: `http://localhost:3000`

## Security gap catalog

The backend includes `VULN-01` through `VULN-60` and frontend includes `VULN-FE-*` markers.
These cover categories such as:

- SQL Injection
- Command Injection
- SSRF
- Path Traversal / LFI
- XSS (stored/reflected/DOM)
- Open Redirect
- Broken Authentication / Session Issues
- Hardcoded Secrets
- Sensitive Data Exposure
- Broken Cryptography
- Prototype Pollution
- Missing Authorization / IDOR
- CSRF-related design gaps
- Log/Header/CSV Injection
- Unsafe Eval

## Notes for SAST tuning

- Search for `VULN-` comments to map findings to expected training issues.
- You can tune severity rules by grouping:
  - `VULN-01..15`: secrets/auth
  - `VULN-16..30`: injection/access/data
  - `VULN-31..45`: authz/execution/logic
  - `VULN-46..60`: token/admin/config and platform leaks
