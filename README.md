# AITrustLens

AITrustLens is an intelligent, high-performance cybersecurity intelligence platform designed for digital identity protection and cyber threat analysis. 

Built with a robust **Deterministic Risk Engine** and **Defense-in-Depth Architecture**, it analyzes digital threats—including URLs, Emails, Passwords, Privacy Policies, Claims, and APKs—without ever relying on AI to guess security scores. AI (via OpenRouter) is utilized strictly as a translation layer to turn complex threat intelligence JSON into accessible, human-readable summaries.

## ✨ Key Features
- **Deterministic Risk Scoring**: Scores are mathematically calculated from verified threat intelligence.
- **Multi-Vector Analysis**: 
  - 🔗 URL Security & Phishing Detection
  - 📧 Email Scam & Phishing Analysis
  - 🔑 K-Anonymity Password Breach Checks
  - 📜 Privacy Policy Predatory Clause Detection
  - 📱 APK Privacy Analysis
  - 📱 QR Code Security Extraction & Analysis
- **AI Translation Layer**: Converts JSON evidence from VirusTotal, URLScan, Safe Browsing, etc., into plain English.
- **Real-Time SSE**: Long-running scans are queued with BullMQ and streamed to the client via Server-Sent Events (SSE).
- **Bulletproof Security**: Features SSRF protection, strict XML boundary sandboxing to prevent AI prompt injection, and Zod schema validation across all inputs and AI outputs.

---

## 🏗️ Architecture

AITrustLens utilizes a Service-Oriented Architecture (SOA) split across a modern React frontend and a robust Node.js/Express backend.

- **Frontend**: React, Vite, Framer Motion, Glassmorphism CSS design system.
- **Backend**: Node.js, Express, Prisma (PostgreSQL), Redis, BullMQ.
- **Threat Intelligence Integrations**:
  - VirusTotal
  - Google Safe Browsing
  - URLScan.io
  - Google Fact Check Tools
  - Have I Been Pwned (K-Anonymity)
- **AI Layer**: OpenRouter (Claude / Gemini).

---

## 🔒 Security Posture

This repository has been designed with security as a first-class citizen:
- **No Secrets in Source**: All API keys, database URLs, and JWT secrets are injected via environment variables.
- **K-Anonymity**: Passwords are never sent to external APIs in plaintext. A local SHA-1 hash is generated, and only the first 5 characters are transmitted to Have I Been Pwned.
- **Prompt Injection Defense**: All untrusted user content sent to the AI is sandboxed within strict `<UNTRUSTED_CONTENT>` XML boundaries to prevent the AI from confusing data with instructions.
- **SSRF Protection**: All URLs are resolved and validated against a blocklist of private internal IPs (e.g., `127.0.0.1`, `169.254.169.254`) before any requests are made.

---

## 🚀 Getting Started

### Prerequisites
- Node.js (v18+)
- PostgreSQL
- Redis

### 1. Clone & Install
```bash
git clone https://github.com/yourusername/aitrustlens.git
cd aitrustlens

# Install backend dependencies
cd server
npm install

# Install frontend dependencies
cd ../client
npm install
```

### 2. Environment Variables
Copy the example environment file and fill in your secrets. **Never commit your `.env` file to version control.**

```bash
cd server
cp ../.env.example .env
```
Update `.env` with your PostgreSQL URL, Redis URL, JWT Secret, and required API keys (VirusTotal, Safe Browsing, OpenRouter, etc.).

### 3. Database Setup
```bash
cd server
npx prisma generate
npx prisma db push
```

### 4. Run the Application
You can run both the frontend and backend concurrently for development:

**Terminal 1 (Backend):**
```bash
cd server
npm run dev
```

**Terminal 2 (Frontend):**
```bash
cd client
npm run dev
```

The app will be available at `http://localhost:5173`.

---

## 🧪 Testing

AITrustLens includes a comprehensive native ES Modules Jest test suite (67+ passing tests).

```bash
cd server
npm test
```
Tests cover the Deterministic Risk Engine mathematical accuracy, SSRF protections, XML prompt injection boundaries, Zod schema validation, and QR code analysis logic.

---

## 📝 License
MIT License. See `LICENSE` for more information.
