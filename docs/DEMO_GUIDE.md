# Demo Guide for Reviewers

Welcome to AITrustLens! This guide provides step-by-step walkthroughs to test and verify the core modules of the system.

## General Setup
1. Ensure Redis is running locally (`redis-server`).
2. Ensure PostgreSQL is running and seeded (`npm run db:seed` in `/server`).
3. Start the backend (`npm run dev` in `/server`).
4. Start the frontend (`npm run dev` in `/client`).
5. Open `http://localhost:5173` and log in with the seeded test account (or create a new one).

---

## 1. Digital Identity Module Demo
**Goal:** Verify deterministic DNS checks (MX, SPF, DMARC) and risk score generation.

1. Navigate to **Digital Identity** in the sidebar (`/analyze/identity`).
2. **Test Case A (Safe):** Enter `security@google.com`.
   - **Expected:** Trust score near 100. Evidence cards show `VERIFIED` for MX, SPF, and DMARC.
3. **Test Case B (Disposable/Critical):** Enter `test@mailinator.com`.
   - **Expected:** Trust score drops below 40. The Risk Engine instantly penalizes the score because it is a known disposable domain.
4. **Test Case C (Missing Records):** Enter `admin@example.com`.
   - **Expected:** Moderate score. AI explanation highlights missing security policies.

---

## 2. APK Analysis Module Demo
**Goal:** Verify real binary AXML manifest parsing, zero hard-coded logic.

1. Navigate to **APK Assessment** in the sidebar (`/analyze/apk`).
2. **File Upload Mode:**
   - Select the "Upload .apk File" mode.
   - You can zip one of the XML fixtures in `server/tests/fixtures/apk/` into a `.zip` and rename it to `.apk` to test the manifest extraction, or use any real Android APK.
   - Click **Upload & Analyze APK**.
   - **Expected:** The backend `adm-zip` parser extracts the manifest, decodes permissions, and triggers the deterministic threat database.
3. **DEMO Mode (If no APK is available):**
   - Click the "⚠️ DEMO MODE — Load Fixture Preset" button on the right side.
   - Click "Targeted Trojan".
   - Click **Run APK Assessment**.
   - **Expected:** The backend receives the manual permission JSON payload and accurately calculates a Critical risk score without requiring a file upload.

---

## 3. QR Code Analysis Demo
**Goal:** Verify URL pipeline reuse and SSRF blocking.

1. Navigate to **QR Scanner** in the sidebar (`/analyze/qr`).
2. **Test Case A (Safe URL):** Drag and drop a QR code containing `https://google.com`.
   - **Expected:** Extracts the URL and runs the full URL analysis pipeline (VirusTotal, URLScan).
3. **Test Case B (Plain Text):** Drag and drop a QR code containing `WIFI:S:MyNetwork;T:WPA;P:secret;;`.
   - **Expected:** Identifies the content as non-URL text. Does *not* generate a fake trust score (trust score will be omitted/null).
4. **Test Case C (SSRF Block):** Drag and drop a QR code containing `http://169.254.169.254/latest/meta-data/`.
   - **Expected:** The scan is instantly rejected by `ssrfChecker.js` with an SSRF violation error.

---

## 4. Password Security Demo
**Goal:** Verify K-Anonymity pattern.

1. Navigate to **Password Check** in the sidebar.
2. Enter `password123`.
3. **Expected:** Critical risk. The system uses K-Anonymity (SHA-1 prefix matching) to securely query Have I Been Pwned. Observe the network tab to ensure the plaintext password is never sent out of your browser.
