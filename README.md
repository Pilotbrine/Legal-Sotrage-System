# Sentinel DMS — Secure Evidence Operations & Document Management System

Sentinel DMS is a secure, role-based Document and Evidence Management System designed for law enforcement, legal investigations, and corporate security operations. It provides browser-side cryptographic ingestion (AES-GCM 256-bit encryption, SHA-256 hashing, and ECDSA P-256 digital signatures), cryptographically linked chain-of-custody tracking, multi-factor authentication (Email 2FA), and complete audit logging.

---

## Key Features

### End-to-End Cryptography & Ingestion
- **Browser-Side AES-GCM 256-bit Encryption**: Files are encrypted in the user's browser using PBKDF2 (100,000 iterations) key derivation before transmission. Plaintext evidence is never stored on disk or sent unencrypted.
- **SHA-256 Integrity Verification**: Calculates real-time cryptographic hashes for zero-tamper evidence validation.
- **ECDSA P-256 Digital Signatures**: Securely signs evidence payloads client-side during ingestion.
- **Cryptographic Chain of Custody**: Every access, transfer, metadata change, and status update generates an immutable, SHA-256 cryptographically linked ledger event.

### Access Control & User Management
- **Role-Based Access Control (RBAC)**: Support for 4 granular roles:
  - **Admin**: Full system management, user approvals, role assignments, security alerts, and system integrity audits.
  - **Supervisor**: Oversight across cases, documents, chain of custody, and security timelines.
  - **Investigator**: Case creation, evidence ingestion, version control, and status tracking.
  - **External Witness**: Limited access for specific document submissions and viewings.
- **Multi-Factor Authentication (Email 2FA)**: Required for enabled accounts, sending 6-digit OTPs with short TTL expiration (`OTP_TTL_SECONDS`). Includes fallback development mode (`DEMO_2FA=true`).
- **Account Protection**: Automatic account lockout after 5 consecutive failed login attempts and administrative reset workflows.

### Case & Evidence Management
- **Vault & Advanced Search**: Filter evidence by case number, FIR identifier, security clearance level (*Official*, *Confidential*, *Secret*, *Top Secret*), categories, status, and tags.
- **Document Versioning**: Track document evolution with version histories while preserving historical hashes.
- **Access Expiration & Time-Bound Clearance**: Automatic enforcement of document expiration hours.
- **Mandatory Custody Justification**: Access to decrypt and view sensitive documents requires mandatory legal/custody justification logging.

---

## Architecture Overview

The system consists of two primary components:

1. **Backend Engine (`BACKEND_V2.py`)**:
   - Built with **Flask**, **Flask-CORS**, and **SQLite3** (operating in WAL mode for safe concurrency).
   - Enforces authentication (`X-User-ID`, `X-Auth-Token`), password hashing via PBKDF2 (`310,000` iterations), session management, and role decorators (`@require_role`, `@require_auth`).
   - Exposes RESTful endpoints for authentication, 2FA verification, document metadata updates, custody tracking, and audit verification.

2. **Frontend Console (`FRONTEND_V2.html`)**:
   - Single-page web application (SPA) styled with custom CSS variables, FontAwesome 6 icons, and dynamic Chart.js visualizations.
   - Utilizes the browser's native **Web Crypto API** (`window.crypto.subtle`) for client-side hashing, key derivation, AES-GCM encryption/decryption, and ECDSA signing.

---

## Getting Started & Local Development

### Prerequisites

- Python 3.8 or higher
- Modern web browser (Chrome, Firefox, Edge, Safari) supporting Web Crypto API

### Installation & Setup

1. **Clone or navigate to the project directory:**
   ```bash
   cd /path/to/sentinel-dms
