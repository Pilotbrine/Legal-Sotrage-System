Sentinel DMS README Generation
How to Delete a GitHub Repository
Encrypting PDF Files in Python
Secure Database Storage for Files
Original Versus Remastered Music
Identifying Alya Sometimes Hides Her Feelings in Russian
Professional Self-Introduction Templates and Options
Management Quota Admission Inquiry Letter
iPad Air vs. iPad Pro Comparison
Evening Greeting and Offer of Help
Coloring Pages for a 9-Year-Old
Fix Missing App Icons In Windows
Access Google Saved Passwords Mobile
Wholesome Roblox Game Idea Generation
Git Permission Denied on AppData
Roblox One Piece Battle Scene
Calculating Induced EMF Using Faraday's Law
Induced EMF Calculation
Creative Python Project Ideas
Python Project Ideas for Computer Science
Python Flight Path Optimization Program
CorelDRAW Upgrade Installation Error
Conversation with Gemini
create me a readme.md for this

Install Python dependencies:

Bash
pip install flask flask-cors
Configure Environment Variables (Optional):

DMS_DB: Path to SQLite database file (Default: gov_dms_v4.db).

SESSION_TTL_SECONDS: Session expiration time in seconds (Default: 28800 / 8 hours).

OTP_TTL_SECONDS: 2FA code expiration time in seconds (Default: 300 / 5 minutes).

DEMO_2FA: Set to true to display 2FA codes directly in UI notifications when local SMTP is unavailable.

SMTP Setup (for live email 2FA):

Bash
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your-email@example.com"
export SMTP_PASSWORD="your-app-password"
export SMTP_FROM="sentinel-dms@example.com"
Start the Backend Server:

Bash
python BACKEND_V2.py
The server will initialize the SQLite database tables automatically and run on http://127.0.0.1:8000.

Launch the Frontend:
Open FRONTEND_V2.html directly in your web browser, or serve it using a local server:

Bash
python -m http.server 3000
Navigate to http://localhost:3000/FRONTEND_V2.html.

🔑 Default Credentials & Demonstration
Upon initial startup, a default administrator account is automatically initialized:

Badge ID: ADMIN-01

Password: admin

Role: Admin

Note: For local demonstration without an SMTP server configured, launch the backend with DEMO_2FA=true:

Bash
DEMO_2FA=true python BACKEND_V2.py
📡 Key REST API Endpoints
Method	Endpoint	Description	Auth / Role
POST	/login	Authenticate badge ID & password; trigger 2FA	Public
POST	/verify-2fa	Complete email 2FA verification & obtain session token	Public
POST	/register	Register new officer/user account	Public
POST	/upload	Ingest new encrypted evidence payload & metadata	Authenticated
GET	/documents	Search and filter evidence vault	Authenticated
POST	/documents/<id>/access	Request decryption payload with legal justification	Authenticated
GET	/documents/<id>/custody	Fetch cryptographically verified custody chain	Admin / Supervisor
POST	/cases	Create a new investigative case record	Authenticated
GET	/admin/users	Retrieve user list and access state	Admin
PATCH	/admin/users/<id>	Update user role, clearance status, and 2FA settings	Admin
GET	/system/verify-integrity	Audit chain of custody ledger integrity	Admin / Supervisor
🔒 Security Architecture Details
Client-Side Cryptography: Zero-knowledge payload protection ensuring raw evidence binaries never hit the network without AES-256-GCM encryption.

PBKDF2 Derivation: Passwords and encryption keys are derived using SHA-256 PBKDF2 with high iteration counts (310,000 for user auth, 100,000 for file encryption).

Chain of Custody Ledger: Each custody record stores a hash of the previous event:

EventHash=SHA256(ID∥DocID∥Actor∥Action∥⋯∥PreviousHash)
This guarantees tamper-evident verification across all evidence actions.
"""

with open("README.md", "w", encoding="utf-8") as f:
f.write(readme_content.strip())

print("README.md generated successfully.")


```text?code_stdout&code_event_index=1
README.md generated successfully.

Your README.md file has been generated:

MD icon
README
 MD 
Markdown Content Preview
Markdown
# Sentinel DMS — Secure Evidence Operations & Document Management System

Sentinel DMS is a secure, role-based Document and Evidence Management System designed for law enforcement, legal investigations, and corporate security operations. It provides browser-side cryptographic ingestion (AES-GCM 256-bit encryption, SHA-256 hashing, and ECDSA P-256 digital signatures), cryptographically linked chain-of-custody tracking, multi-factor authentication (Email 2FA), and complete audit logging.

---

## 🌟 Key Features

### 🔐 End-to-End Cryptography & Ingestion
- **Browser-Side AES-GCM 256-bit Encryption**: Files are encrypted in the user's browser using PBKDF2 (100,000 iterations) key derivation before transmission to the server. Plaintext evidence content is never stored on disk or sent unencrypted.
- **SHA-256 Integrity Verification**: Calculates real-time cryptographic hashes for zero-tamper evidence validation.
- **ECDSA P-256 Digital Signatures**: Securely signs evidence payloads client-side during ingestion.
- **Cryptographic Chain of Custody**: Every access, transfer, metadata change, and status update generates an immutable, SHA-256 cryptographically linked ledger event.

### 🛡️ Access Control & User Management
- **Role-Based Access Control (RBAC)**: Support for 4 granular roles:
  - **Admin**: Full system management, user approvals, role assignments, security alerts, and system integrity audits.
  - **Supervisor**: Oversight across cases, documents, chain of custody, and security timelines.
  - **Investigator**: Case creation, evidence ingestion, version control, and status tracking.
  - **External Witness**: Limited access for specific document submissions and viewings.
- **Multi-Factor Authentication (Email 2FA)**: Required for enabled accounts, sending 6-digit OTPs with short TTL expiration (`OTP_TTL_SECONDS`). Includes fallback development mode (`DEMO_2FA=true`).
- **Account Protection**: Automatic account lockout after 5 consecutive failed login attempts and administrative reset workflows.

### 📁 Case & Evidence Management
- **Vault & Advanced Search**: Filter evidence by case number, FIR identifier, security clearance level (*Official*, *Confidential*, *Secret*, *Top Secret*), categories, status, and tags.
- **Document Versioning**: Track document evolution with version histories while preserving historical hashes.
- **Access Expiration & Time-Bound Clearance**: Automatic enforcement of document expiration hours.
- **Mandatory Custody Justification**: Access to decrypt and view sensitive documents requires mandatory legal/custody justification logging.

---

## 🛠️ Architecture Overview

The system consists of two primary components:

1. **Backend Engine (`BACKEND_V2.py`)**:
   - Built with **Flask** and **SQLite3** (operating in WAL mode for safe concurrency).
   - Enforces authentication (`X-User-ID`, `X-Auth-Token`), password hashing via PBKDF2 (`310,000` iterations), session management, and role decorators (`@require_role`, `@require_auth`).
   - Exposes RESTful endpoints for authentication, 2FA verification, document metadata updates, custody tracking, and audit verification.

2. **Frontend Console (`FRONTEND_V2.html`)**:
   - Single-page web application (SPA) styled with custom CSS variables, FontAwesome 6 icons, and dynamic Chart.js visualizations.
   - Utilizes the browser's native **Web Crypto API** (`window.crypto.subtle`) for client-side hashing, key derivation, AES-GCM encryption/decryption, and ECDSA signing.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- Modern web browser (Chrome, Firefox, Edge, Safari) supporting Web Crypto API

### Installation & Setup

1. **Clone or navigate to the project directory:**
   ```bash
   cd /path/to/sentinel-dms
Install Python dependencies:

Bash
pip install flask flask-cors
Configure Environment Variables (Optional):

DMS_DB: Path to SQLite database file (Default: gov_dms_v4.db).

SESSION_TTL_SECONDS: Session expiration time in seconds (Default: 28800 / 8 hours).

OTP_TTL_SECONDS: 2FA code expiration time in seconds (Default: 300 / 5 minutes).

DEMO_2FA: Set to true to display 2FA codes directly in UI notifications when local SMTP is unavailable.

SMTP Setup (for live email 2FA):

Bash
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your-email@example.com"
export SMTP_PASSWORD="your-app-password"
export SMTP_FROM="sentinel-dms@example.com"
Start the Backend Server:

Bash
python BACKEND_V2.py
The server will initialize the SQLite database tables automatically and run on http://127.0.0.1:8000.

Launch the Frontend:
Open FRONTEND_V2.html directly in your web browser, or serve it using a local server:

Bash
python -m http.server 3000
Navigate to http://localhost:3000/FRONTEND_V2.html.

🔑 Default Credentials & Demonstration
Upon initial startup, a default administrator account is automatically initialized:

Badge ID: ADMIN-01

Password: admin

Role: Admin

Note: For local demonstration without an SMTP server configured, launch the backend with DEMO_2FA=true:

Bash
DEMO_2FA=true python BACKEND_V2.py
📡 Key REST API Endpoints
Method	Endpoint	Description	Auth / Role
POST	/login	Authenticate badge ID & password; trigger 2FA	Public
POST	/verify-2fa	Complete email 2FA verification & obtain session token	Public
POST	/register	Register new officer/user account	Public
POST	/upload	Ingest new encrypted evidence payload & metadata	Authenticated
GET	/documents	Search and filter evidence vault	Authenticated
POST	/documents/<id>/access	Request decryption payload with legal justification	Authenticated
GET	/documents/<id>/custody	Fetch cryptographically verified custody chain	Admin / Supervisor
POST	/cases	Create a new investigative case record	Authenticated
GET	/admin/users	Retrieve user list and access state	Admin
PATCH	/admin/users/<id>	Update user role, clearance status, and 2FA settings	Admin
GET	/system/verify-integrity	Audit chain of custody ledger integrity	Admin / Supervisor
🔒 Security Architecture Details
Client-Side Cryptography: Zero-knowledge payload protection ensuring raw evidence binaries never hit the network without AES-256-GCM encryption.

PBKDF2 Derivation: Passwords and encryption keys are derived using SHA-256 PBKDF2 with high iteration counts (310,000 for user auth, 100,000 for file encryption).

Chain of Custody Ledger: Each custody record stores a hash of the previous event:

EventHash=SHA256(ID∥DocID∥Actor∥Action∥⋯∥PreviousHash)
This guarantees tamper-evident verification across all evidence actions.

i mean give me as a text

Sentinel DMS — Secure Evidence Operations & Document Management System
Sentinel DMS is a secure, role-based Document and Evidence Management System designed for law enforcement, legal investigations, and corporate security operations. It provides browser-side cryptographic ingestion (AES-GCM 256-bit encryption, SHA-256 hashing, and ECDSA P-256 digital signatures), cryptographically linked chain-of-custody tracking, multi-factor authentication (Email 2FA), and complete audit logging.  
MD
+ 1

🌟 Key Features
🔐 End-to-End Cryptography & Ingestion
Browser-Side AES-GCM 256-bit Encryption: Files are encrypted in the user's browser using PBKDF2 (100,000 iterations) key derivation before transmission to the server. Plaintext evidence content is never stored on disk or sent unencrypted.  
MD
+ 1

SHA-256 Integrity Verification: Calculates real-time cryptographic hashes for zero-tamper evidence validation.  
MD

ECDSA P-256 Digital Signatures: Securely signs evidence payloads client-side during ingestion.  
MD

Cryptographic Chain of Custody: Every access, transfer, metadata change, and status update generates an immutable, SHA-256 cryptographically linked ledger event.  
MD

🛡️ Access Control & User Management
Role-Based Access Control (RBAC): Support for 4 granular roles:

Admin: Full system management, user approvals, role assignments, security alerts, and system integrity audits.  
MD

Supervisor: Oversight across cases, documents, chain of custody, and security timelines.  
MD

Investigator: Case creation, evidence ingestion, version control, and status tracking.  
MD

External Witness: Limited access for specific document submissions and viewings.  
MD

Multi-Factor Authentication (Email 2FA): Required for enabled accounts, sending 6-digit OTPs with short TTL expiration (OTP_TTL_SECONDS). Includes fallback development mode (DEMO_2FA=true).  
MD
+ 1

Account Protection: Automatic account lockout after 5 consecutive failed login attempts and administrative reset workflows.  
MD

📁 Case & Evidence Management
Vault & Advanced Search: Filter evidence by case number, FIR identifier, security clearance level (Official, Confidential, Secret, Top Secret), categories, status, and tags.  
MD

Document Versioning: Track document evolution with version histories while preserving historical hashes.  
MD

Access Expiration & Time-Bound Clearance: Automatic enforcement of document expiration hours.  
MD

Mandatory Custody Justification: Access to decrypt and view sensitive documents requires mandatory legal/custody justification logging.  
MD

🛠️ Architecture Overview
The system consists of two primary components:  
MD

Backend Engine (BACKEND_V2.py):

Built with Flask and SQLite3 (operating in WAL mode for safe concurrency).  
MD

Enforces authentication (X-User-ID, X-Auth-Token), password hashing via PBKDF2 (310,000 iterations), session management, and role decorators (@require_role, @require_auth).  
MD

Exposes RESTful endpoints for authentication, 2FA verification, document metadata updates, custody tracking, and audit verification.  
MD

Frontend Console (FRONTEND_V2.html):

Single-page web application (SPA) styled with custom CSS variables, FontAwesome 6 icons, and dynamic Chart.js visualizations.  
MD

Utilizes the browser's native Web Crypto API (window.crypto.subtle) for client-side hashing, key derivation, AES-GCM encryption/decryption, and ECDSA signing.  
MD

🚀 Getting Started
Prerequisites
Python 3.8 or higher  
MD

Modern web browser (Chrome, Firefox, Edge, Safari) supporting Web Crypto API  
MD

Installation & Setup
Clone or navigate to the project directory:

Bash
cd /path/to/sentinel-dms
Install Python dependencies:

Bash
pip install flask flask-cors
Configure Environment Variables (Optional):

DMS_DB: Path to SQLite database file (Default: gov_dms_v4.db).  
MD

SESSION_TTL_SECONDS: Session expiration time in seconds (Default: 28800 / 8 hours).  
MD

OTP_TTL_SECONDS: 2FA code expiration time in seconds (Default: 300 / 5 minutes).  
MD

DEMO_2FA: Set to true to display 2FA codes directly in UI notifications when local SMTP is unavailable.  
MD

SMTP Setup (for live email 2FA):  
MD

Bash
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your-email@example.com"
export SMTP_PASSWORD="your-app-password"
export SMTP_FROM="sentinel-dms@example.com"
Start the Backend Server:

Bash
python BACKEND_V2.py
The server will initialize the SQLite database tables automatically and run on [http://127.0.0.1:8000](http://127.0.0.1:8000).  
MD

Launch the Frontend:
Open FRONTEND_V2.html directly in your web browser, or serve it using a local server:  
MD

Bash
python -m http.server 3000
Navigate to http://localhost:3000/FRONTEND_V2.html.  
MD

🔑 Default Credentials & Demonstration
Upon initial startup, a default administrator account is automatically initialized:  
MD

Badge ID: ADMIN-01

  
MD

Password: admin

  
MD

Role: Admin

  
MD

Note: For local demonstration without an SMTP server configured, launch the backend with DEMO_2FA=true:  
MD

Bash
DEMO_2FA=true python BACKEND_V2.py
📡 Key REST API Endpoints
Method	Endpoint	Description	Auth / Role
POST	/login	Authenticate badge ID & password; trigger 2FA	Public
POST	/verify-2fa	Complete email 2FA verification & obtain session token	Public
POST	/register	Register new officer/user account	Public
POST	/upload	Ingest new encrypted evidence payload & metadata	Authenticated
GET	/documents	Search and filter evidence vault	Authenticated
POST	/documents/<id>/access	Request decryption payload with legal justification	Authenticated
GET	/documents/<id>/custody	Fetch cryptographically verified custody chain	Admin / Supervisor
POST	/cases	Create a new investigative case record	Authenticated
GET	/admin/users	Retrieve user list and access state	Admin
PATCH	/admin/users/<id>	Update user role, clearance status, and 2FA settings	Admin
GET	/system/verify-integrity	Audit chain of custody ledger integrity	Admin / Supervisor
🔒 Security Architecture Details
Client-Side Cryptography: Zero-knowledge payload protection ensuring raw evidence binaries never hit the network without AES-256-GCM encryption.  
MD

PBKDF2 Derivation: Passwords and encryption keys are derived using SHA-256 PBKDF2 with high iteration counts (310,000 for user auth, 100,000 for file encryption).  
MD

Chain of Custody Ledger: Each custody record stores a hash of the previous event:
  
MD

EventHash=SHA256(ID∥DocID∥Actor∥Action∥⋯∥PreviousHash)

This guarantees tamper-evident verification across all evidence actions.  
MD

give me a text download

Install Python dependencies:

Bash
pip install flask flask-cors
Configure Environment Variables (Optional):

DMS_DB: Path to SQLite database file (Default: gov_dms_v4.db).

SESSION_TTL_SECONDS: Session expiration time in seconds (Default: 28800 / 8 hours).

OTP_TTL_SECONDS: 2FA code expiration time in seconds (Default: 300 / 5 minutes).

DEMO_2FA: Set to true to display 2FA codes directly in UI notifications when local SMTP is unavailable.

SMTP Setup (for live email 2FA):

Bash
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your-email@example.com"
export SMTP_PASSWORD="your-app-password"
export SMTP_FROM="sentinel-dms@example.com"
Start the Backend Server:

Bash
python BACKEND_V2.py
The server will initialize the SQLite database tables automatically and run on http://127.0.0.1:8000.

Launch the Frontend:
Open FRONTEND_V2.html directly in your web browser, or serve it using a local server:

Bash
python -m http.server 3000
Navigate to http://localhost:3000/FRONTEND_V2.html.

🔑 Default Credentials & Demonstration
Upon initial startup, a default administrator account is automatically initialized:

Badge ID: ADMIN-01

Password: admin

Role: Admin

Note: For local demonstration without an SMTP server configured, launch the backend with DEMO_2FA=true:

Bash
DEMO_2FA=true python BACKEND_V2.py
📡 Key REST API Endpoints
Method	Endpoint	Description	Auth / Role
POST	/login	Authenticate badge ID & password; trigger 2FA	Public
POST	/verify-2fa	Complete email 2FA verification & obtain session token	Public
POST	/register	Register new officer/user account	Public
POST	/upload	Ingest new encrypted evidence payload & metadata	Authenticated
GET	/documents	Search and filter evidence vault	Authenticated
POST	/documents/<id>/access	Request decryption payload with legal justification	Authenticated
GET	/documents/<id>/custody	Fetch cryptographically verified custody chain	Admin / Supervisor
POST	/cases	Create a new investigative case record	Authenticated
GET	/admin/users	Retrieve user list and access state	Admin
PATCH	/admin/users/<id>	Update user role, clearance status, and 2FA settings	Admin
GET	/system/verify-integrity	Audit chain of custody ledger integrity	Admin / Supervisor
🔒 Security Architecture Details
Client-Side Cryptography: Zero-knowledge payload protection ensuring raw evidence binaries never hit the network without AES-256-GCM encryption.

PBKDF2 Derivation: Passwords and encryption keys are derived using SHA-256 PBKDF2 with high iteration counts (310,000 for user auth, 100,000 for file encryption).

Chain of Custody Ledger: Each custody record stores a hash of the previous event:

EventHash=SHA256(ID∥DocID∥Actor∥Action∥⋯∥PreviousHash)
This guarantees tamper-evident verification across all evidence actions.
"""

with open("README.txt", "w", encoding="utf-8") as f:
f.write(readme_content.strip())

print("README.txt generated successfully.")


```text?code_stdout&code_event_index=2
README.txt generated successfully.

Here is the plain text .txt file available for download:

TXT icon
README
 TXT 



Gemini is AI and can make mistakes.

Analyzing
# Sentinel DMS — Secure Evidence Operations & Document Management System

Sentinel DMS is a secure, role-based Document and Evidence Management System designed for law enforcement, legal investigations, and corporate security operations. It provides browser-side cryptographic ingestion (AES-GCM 256-bit encryption, SHA-256 hashing, and ECDSA P-256 digital signatures), cryptographically linked chain-of-custody tracking, multi-factor authentication (Email 2FA), and complete audit logging.

---

## 🌟 Key Features

### 🔐 End-to-End Cryptography & Ingestion
- **Browser-Side AES-GCM 256-bit Encryption**: Files are encrypted in the user's browser using PBKDF2 (100,000 iterations) key derivation before transmission to the server. Plaintext evidence content is never stored on disk or sent unencrypted.
- **SHA-256 Integrity Verification**: Calculates real-time cryptographic hashes for zero-tamper evidence validation.
- **ECDSA P-256 Digital Signatures**: Securely signs evidence payloads client-side during ingestion.
- **Cryptographic Chain of Custody**: Every access, transfer, metadata change, and status update generates an immutable, SHA-256 cryptographically linked ledger event.

### 🛡️ Access Control & User Management
- **Role-Based Access Control (RBAC)**: Support for 4 granular roles:
  - **Admin**: Full system management, user approvals, role assignments, security alerts, and system integrity audits.
  - **Supervisor**: Oversight across cases, documents, chain of custody, and security timelines.
  - **Investigator**: Case creation, evidence ingestion, version control, and status tracking.
  - **External Witness**: Limited access for specific document submissions and viewings.
- **Multi-Factor Authentication (Email 2FA)**: Required for enabled accounts, sending 6-digit OTPs with short TTL expiration (`OTP_TTL_SECONDS`). Includes fallback development mode (`DEMO_2FA=true`).
- **Account Protection**: Automatic account lockout after 5 consecutive failed login attempts and administrative reset workflows.

### 📁 Case & Evidence Management
- **Vault & Advanced Search**: Filter evidence by case number, FIR identifier, security clearance level (*Official*, *Confidential*, *Secret*, *Top Secret*), categories, status, and tags.
- **Document Versioning**: Track document evolution with version histories while preserving historical hashes.
- **Access Expiration & Time-Bound Clearance**: Automatic enforcement of document expiration hours.
- **Mandatory Custody Justification**: Access to decrypt and view sensitive documents requires mandatory legal/custody justification logging.

---

## 🛠️ Architecture Overview

The system consists of two primary components:

1. **Backend Engine (`BACKEND_V2.py`)**:
   - Built with **Flask** and **SQLite3** (operating in WAL mode for safe concurrency).
   - Enforces authentication (`X-User-ID`, `X-Auth-Token`), password hashing via PBKDF2 (`310,000` iterations), session management, and role decorators (`@require_role`, `@require_auth`).
   - Exposes RESTful endpoints for authentication, 2FA verification, document metadata updates, custody tracking, and audit verification.

2. **Frontend Console (`FRONTEND_V2.html`)**:
   - Single-page web application (SPA) styled with custom CSS variables, FontAwesome 6 icons, and dynamic Chart.js visualizations.
   - Utilizes the browser's native **Web Crypto API** (`window.crypto.subtle`) for client-side hashing, key derivation, AES-GCM encryption/decryption, and ECDSA signing.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- Modern web browser (Chrome, Firefox, Edge, Safari) supporting Web Crypto API

### Installation & Setup

1. **Clone or navigate to the project directory:**
   ```bash
   cd /path/to/sentinel-dms
   ```

2. **Install Python dependencies:**
   ```bash
   pip install flask flask-cors
   ```

3. **Configure Environment Variables (Optional):**
   - `DMS_DB`: Path to SQLite database file (Default: `gov_dms_v4.db`).
   - `SESSION_TTL_SECONDS`: Session expiration time in seconds (Default: `28800` / 8 hours).
   - `OTP_TTL_SECONDS`: 2FA code expiration time in seconds (Default: `300` / 5 minutes).
   - `DEMO_2FA`: Set to `true` to display 2FA codes directly in UI notifications when local SMTP is unavailable.
   - **SMTP Setup** (for live email 2FA):
     ```bash
     export SMTP_HOST="smtp.gmail.com"
     export SMTP_PORT="587"
     export SMTP_USER="your-email@example.com"
     export SMTP_PASSWORD="your-app-password"
     export SMTP_FROM="sentinel-dms@example.com"
     ```

4. **Start the Backend Server:**
   ```bash
   python BACKEND_V2.py
   ```
   *The server will initialize the SQLite database tables automatically and run on `http://127.0.0.1:8000`.*

5. **Launch the Frontend:**
   Open `FRONTEND_V2.html` directly in your web browser, or serve it using a local server:
   ```bash
   python -m http.server 3000
   ```
   Navigate to `http://localhost:3000/FRONTEND_V2.html`.

---

## 🔑 Default Credentials & Demonstration

Upon initial startup, a default administrator account is automatically initialized:

- **Badge ID**: `ADMIN-01`
- **Password**: `admin`
- **Role**: `Admin`

*Note: For local demonstration without an SMTP server configured, launch the backend with `DEMO_2FA=true`:*
```bash
DEMO_2FA=true python BACKEND_V2.py
```

---

## 📡 Key REST API Endpoints

| Method | Endpoint | Description | Auth / Role |
| :--- | :--- | :--- | :--- |
| `POST` | `/login` | Authenticate badge ID & password; trigger 2FA | Public |
| `POST` | `/verify-2fa` | Complete email 2FA verification & obtain session token | Public |
| `POST` | `/register` | Register new officer/user account | Public |
| `POST` | `/upload` | Ingest new encrypted evidence payload & metadata | Authenticated |
| `GET` | `/documents` | Search and filter evidence vault | Authenticated |
| `POST` | `/documents/<id>/access` | Request decryption payload with legal justification | Authenticated |
| `GET` | `/documents/<id>/custody` | Fetch cryptographically verified custody chain | Admin / Supervisor |
| `POST` | `/cases` | Create a new investigative case record | Authenticated |
| `GET` | `/admin/users` | Retrieve user list and access state | Admin |
| `PATCH` | `/admin/users/<id>` | Update user role, clearance status, and 2FA settings | Admin |
| `GET` | `/system/verify-integrity` | Audit chain of custody ledger integrity | Admin / Supervisor |

---

## 🔒 Security Architecture Details

1. **Client-Side Cryptography**: Zero-knowledge payload protection ensuring raw evidence binaries never hit the network without AES-256-GCM encryption.
2. **PBKDF2 Derivation**: Passwords and encryption keys are derived using SHA-256 PBKDF2 with high iteration counts (310,000 for user auth, 100,000 for file encryption).
3. **Chain of Custody Ledger**: Each custody record stores a hash of the previous event:
   $$	ext{EventHash} = 	ext{SHA256}(	ext{ID} \parallel 	ext{DocID} \parallel 	ext{Actor} \parallel 	ext{Action} \parallel \dots \parallel 	ext{PreviousHash})$$
   This guarantees tamper-evident verification across all evidence actions.
README.txt
Displaying README.txt.
