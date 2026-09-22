# 🛡️ Sentinel

### Security Operations & Threat Detection Platform

Sentinel is a security monitoring and threat detection platform designed to analyze authentication and network logs, identify suspicious activity using rule-based detection engines, generate security alerts, and provide security analysts with a real-time SOC-style dashboard.

---

## 🚀 Features

### 🔐 Authentication & Security

- JWT-based authentication
- Secure password hashing with bcrypt
- Password complexity validation
- Protected security APIs
- JWT expiry handling
- Authenticated WebSocket connections
- CORS restrictions
- API rate limiting
- Request payload limits
- Environment-based secret management

### 🧠 Threat Detection

Sentinel currently detects:

- SSH brute-force attacks
- Suspicious login after repeated failed attempts
- Network port scans
- Multiple-account authentication attempts

### 📊 SOC Dashboard

- Real-time security monitoring
- Security alert dashboard
- Threat summary
- Security statistics
- Event timeline
- Alert search
- Severity filtering
- Alert status filtering
- Alert details
- Investigation activity timeline
- Analyst investigation notes

### 🔎 Investigation Workflow

Analysts can move alerts through:

```text
DETECTED
    ↓
INVESTIGATING
    ↓
RESOLVED
```

Sentinel records investigation activity, status changes, and analyst notes for security alerts.

---

## ⚡ Real-Time Monitoring

Sentinel uses authenticated WebSocket connections to deliver newly detected security alerts to connected dashboard clients in real time.

```text
New Security Event
        ↓
Detection Engine
        ↓
Alert Generated
        ↓
MongoDB
        ↓
WebSocket Broadcast
        ↓
SOC Dashboard
```

---

# 🏗️ Architecture

```text
                    ┌───────────────────────┐
                    │     Sentinel UI       │
                    │   React + Tailwind    │
                    └───────────┬───────────┘
                                │
                       REST API + WebSocket
                                │
                                ▼
                    ┌───────────────────────┐
                    │    FastAPI Backend    │
                    │                       │
                    │ Authentication        │
                    │ API Routes            │
                    │ Rate Limiting         │
                    │ Request Validation    │
                    └───────────┬───────────┘
                                │
                ┌───────────────┴────────────────┐
                │                                │
                ▼                                ▼
       ┌─────────────────┐             ┌─────────────────┐
       │  Log Ingestion  │             │  JWT Security   │
       │     Parser      │             │   Middleware    │
       └────────┬────────┘             └─────────────────┘
                │
                ▼
       ┌─────────────────────┐
       │  Detection Engine   │
       └──────────┬──────────┘
                  │
        ┌─────────┼─────────────┐
        │         │             │
        ▼         ▼             ▼
     Brute     Suspicious     Port
     Force       Login        Scan
        │
        ▼
 Multiple Account
    Attempts
        │
        ▼
 ┌─────────────────────┐
 │ Alert & Threat      │
 │ Summary Generation  │
 └──────────┬──────────┘
            │
            ▼
 ┌─────────────────────┐
 │    MongoDB Atlas    │
 │                     │
 │ Users               │
 │ Events              │
 │ Alerts              │
 │ Activity            │
 │ Threat Summaries    │
 └──────────┬──────────┘
            │
            ▼
 ┌─────────────────────┐
 │ WebSocket Broadcast │
 └──────────┬──────────┘
            │
            ▼
      SOC Dashboard
```

---

# 🧠 Detection Engine

Sentinel uses independent rule-based detectors to analyze structured security events.

## 1. SSH Brute Force

Detects repeated failed SSH authentication attempts from the same source IP within a defined time window.

**Severity:** HIGH

---

## 2. Suspicious Login

Detects a successful authentication occurring after multiple recent failed authentication attempts from the same source IP.

**Severity:** HIGH

---

## 3. Port Scan

Detects connections to multiple unique destination ports from the same source IP within a defined time window.

**Severity:** MEDIUM

---

## 4. Multiple Account Authentication Attempts

Detects repeated failed authentication attempts targeting multiple usernames from the same source IP within a defined time window.

**Severity:** HIGH

---

# 🔄 Detection Pipeline

```text
Log Input
    ↓
Log Parser
    ↓
Structured Security Events
    ↓
Detection Engine
    ↓
Detection Rules
    ↓
Security Alerts
    ↓
MongoDB
    ↓
WebSocket Broadcast
    ↓
SOC Dashboard
    ↓
Analyst Investigation
```

---

# 🛠️ Technology Stack

## Frontend

- React
- Tailwind CSS
- Vite
- JavaScript
- WebSocket API

## Backend

- Python
- FastAPI
- Uvicorn
- Pydantic
- JWT
- bcrypt

## Database

- MongoDB Atlas
- Motor
- PyMongo

## Security

- JWT authentication
- bcrypt password hashing
- Password complexity validation
- Protected API endpoints
- CORS restrictions
- Request validation
- Payload limits
- Rate limiting
- Environment-based secrets
- Authenticated WebSocket connections

---

# 📁 Project Structure

```text
sentinel/
│
├── backend/
│   ├── app/
│   │   ├── detection/
│   │   │   ├── brute_force.py
│   │   │   ├── suspicious_login.py
│   │   │   ├── port_scan.py
│   │   │   ├── multiple_accounts.py
│   │   │   └── engine.py
│   │   │
│   │   ├── routes/
│   │   │   ├── analyze.py
│   │   │   └── auth.py
│   │   │
│   │   ├── services/
│   │   │   ├── log_ingestion.py
│   │   │   ├── threat_summary.py
│   │   │   └── alert_activity.py
│   │   │
│   │   ├── utils/
│   │   │   ├── auth.py
│   │   │   └── dependencies.py
│   │   │
│   │   ├── database.py
│   │   └── main.py
│   │
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/
│
├── sample_logs/
│
├── docs/
│
├── .gitignore
└── README.md
```

---

# ⚙️ Installation

## 1. Clone the Repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd sentinel
```

---

## 2. Backend Setup

Navigate to the backend:

```bash
cd backend
```

Create a Python virtual environment:

```bash
python3 -m venv venv
```

Activate the virtual environment.

### macOS / Linux

```bash
source venv/bin/activate
```

### Windows

```powershell
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# 🔑 Environment Variables

Create:

```text
backend/.env
```

Add:

```env
MONGODB_URL=your_mongodb_connection_string
DATABASE_NAME=sentinel
SECRET_KEY=your_secure_secret_key
```

### Important

Never commit `.env` to GitHub.

The repository should contain an `.env.example` file with placeholder values instead.

Example:

```env
MONGODB_URL=your_mongodb_connection_string
DATABASE_NAME=sentinel
SECRET_KEY=your_secure_secret_key
```

---

# ▶️ Running the Backend

From:

```text
sentinel/backend
```

run:

```bash
python3 -m uvicorn app.main:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

Swagger API documentation:

```text
http://127.0.0.1:8000/docs
```

Health check:

```text
http://127.0.0.1:8000/health
```

---

# ▶️ Running the Frontend

Open another terminal:

```bash
cd frontend
```

Install dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

Frontend:

```text
http://localhost:5173
```

---

# 🔐 Authentication Flow

Sentinel uses JWT-based authentication for protected API access.

```text
User
 ↓
Register / Login
 ↓
FastAPI Authentication
 ↓
Password Verification
 ↓
JWT Access Token
 ↓
Frontend
 ↓
Bearer Token
 ↓
Protected API
```

---

# 🔌 WebSocket Authentication

Sentinel also authenticates WebSocket connections using JWT.

```text
Frontend
 ↓
WebSocket Connection
 ↓
JWT Authentication Message
 ↓
Token Validation
 ↓
Authenticated Connection
 ↓
Live Alert Broadcasts
```

Expired or invalid JWT tokens cause the session to be cleared and the user is returned to the login flow.

---

# 📡 API Overview

## Authentication

```text
POST /api/auth/register
POST /api/auth/login
```

## Security Analysis

```text
POST /api/analyze
```

## Alerts

```text
GET   /api/alerts
PATCH /api/alerts/{alert_id}
GET   /api/alerts/{alert_id}/activity
POST  /api/alerts/{alert_id}/notes
```

## Monitoring

```text
GET /api/events
GET /api/stats
GET /api/threat-summary
```

## WebSocket

```text
/ws
```

---

# 🛡️ API Security

Security-related endpoints require authentication through a Bearer JWT.

Example:

```http
Authorization: Bearer <access_token>
```

Unauthenticated access to protected endpoints is rejected by the backend.

---

# 📦 Request Protection

Sentinel applies limits to log analysis requests.

Current protections include:

- Maximum number of submitted log lines
- Maximum individual log-line length
- Maximum total log payload size
- Empty log submission rejection

These controls help prevent unnecessarily large requests from reaching the detection engine.

---

# 🚦 Rate Limiting

Sentinel includes a lightweight in-memory API rate limiter.

Current configuration:

```text
120 requests
within
60 seconds
per client IP
```

The limiter is designed for the current single-instance deployment.

For a distributed production deployment, a shared store such as Redis could be used instead.

---

# 🌐 CORS

The backend restricts browser requests to the configured Sentinel frontend origins.

Development origins currently include:

```text
http://localhost:5173
http://127.0.0.1:5173
```

Allowed HTTP methods and headers are explicitly configured.

---

# 🗄️ Database

Sentinel uses MongoDB Atlas for persistent storage.

The platform stores security-related information including:

```text
Users
Events
Alerts
Alert Activity
Threat Summaries
```

The MongoDB connection string is loaded from environment variables and is never hard-coded into the application.

---

# 🧪 Validation

Sentinel has been validated through end-to-end testing covering:

- User authentication
- JWT-protected APIs
- JWT WebSocket authentication
- Log ingestion
- Event parsing
- Threat detection
- Alert creation
- MongoDB persistence
- WebSocket alert broadcasting
- Dashboard updates
- Alert status transitions
- Analyst notes
- Investigation activity tracking
- Threat summary generation

### Tested Detection Scenarios

```text
SSH Brute Force
        ↓
Suspicious Login
        ↓
Port Scan
        ↓
Multiple Account Authentication Attempts
        ↓
Normal / Non-malicious Authentication Activity
```

---

# 🔎 Investigation Workflow

Sentinel provides a basic SOC-style alert investigation workflow.

```text
                    ┌──────────────┐
                    │   DETECTED   │
                    └──────┬───────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  INVESTIGATING  │
                  └────────┬────────┘
                           │
                           ▼
                    ┌────────────┐
                    │  RESOLVED  │
                    └────────────┘
```

Analysts can:

- Change alert status
- Add investigation notes
- Review activity history
- Inspect source IP information
- Review detected threat context
- Track investigation progress

---

# 📊 Threat Summary

Sentinel generates a threat summary based on detected alerts.

The summary provides:

- Overall threat level
- Detected threats
- Security alert count
- Recommended investigation actions

High-severity alerts result in a high threat level in the current rule-based summary logic.

---

# 🛡️ Security Controls

```text
                 Sentinel Security
                        │
        ┌───────────────┼────────────────┐
        │               │                │
        ▼               ▼                ▼
   JWT Auth        Password Hashing   API Protection
        │               │                │
        └───────────────┼────────────────┘
                        │
                        ▼
                Request Validation
                        │
             ┌──────────┴──────────┐
             ▼                     ▼
        Payload Limits        Rate Limiting
             │                     │
             └──────────┬──────────┘
                        ▼
                  CORS Controls
                        │
                        ▼
              Environment Secrets
                        │
                        ▼
             Authenticated WebSocket
```

---

# 📸 Screenshots

Screenshots can be stored under:

```text
docs/screenshots/
```

Suggested screenshots:

```text
docs/screenshots/
├── login.png
├── dashboard.png
├── alerts.png
├── alert-details.png
├── threat-summary.png
└── live-monitoring.png
```

Screenshots can be added to this README later to demonstrate the Sentinel SOC dashboard.

---

# 🚧 Future Improvements

Potential future development includes:

- Additional detection rules
- MITRE ATT&CK technique mapping
- Threat intelligence integration
- IP reputation enrichment
- SIEM log connectors
- Email and notification alerts
- Role-based access control
- Redis-based distributed rate limiting
- Docker deployment
- Automated detection-rule testing
- Advanced security analytics
- Detection rule configuration through the dashboard
- External log source integrations

---

# 🎯 Project Goals

Sentinel was designed to demonstrate practical concepts involved in building a security monitoring platform, including:

- Security event parsing
- Rule-based threat detection
- Authentication and authorization
- Secure API design
- Real-time security monitoring
- Alert management
- Analyst investigation workflows
- Database-backed security applications
- WebSocket-based event delivery

---

# 👨‍💻 Author

## Ashwin V G

Computer Science & Engineering  
Cybersecurity Enthusiast

---

# 📄 License

This project is intended for educational, research, and portfolio purposes.
