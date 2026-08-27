# Security Model

This document outlines the defense-in-depth security measures implemented in AITrustLens. Every security control cited here is actively running in the codebase.

## 1. Input Sanitization & Validation (Zod)
All incoming requests are strictly type-checked and sanitized using Zod schemas before any business logic executes.
- **Implementation:** `server/src/validators/inputValidator.js`
- **Coverage:** URLs, Emails, Passwords, Claims, APK Permissions, Digital Identities. Strings are trimmed, lengths are bounded, and invalid formats are immediately rejected with `400 Bad Request`.

## 2. Server-Side Request Forgery (SSRF) Protection
To prevent attackers from using AITrustLens as a proxy to attack internal networks or cloud metadata endpoints, all URLs (direct or extracted from Privacy Policies / QR codes) undergo SSRF checks.
- **Implementation:** `server/src/utils/ssrfChecker.js`
- **Mechanism:** The hostname is resolved to an IP address. If the IP falls within private subnets (e.g., `127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`) or cloud metadata ranges (`169.254.169.254`), the request is blocked. Non-HTTP/HTTPS schemes (like `file://` or `ftp://`) are rejected.

## 3. Prompt Injection Boundaries (XML Sandboxing)
When sending untrusted user content (emails, scam texts) to the AI for explanation generation, the system must prevent the user from hijacking the system prompt.
- **Implementation:** `server/src/providers/openRouterProvider.js`
- **Mechanism:** User content is wrapped in strict `<UNTRUSTED_CONTENT>` XML tags. Any instances of `<UNTRUSTED_CONTENT>` or `</UNTRUSTED_CONTENT>` within the user's input are aggressively stripped to prevent sandbox escape. The system prompt instructs the LLM to analyze the content within the tags, not obey it.

## 4. K-Anonymity for Passwords
The system never sends a user's plaintext password, or even the full hash of the password, to any external service.
- **Implementation:** `server/src/services/passwordBreachService.js`
- **Mechanism:** The password is hashed locally using SHA-1. Only the first 5 characters of the hash are sent to the Have I Been Pwned API. The API returns all hashes matching that prefix. The exact match is found locally on the server.

## 5. File Upload Security
File uploads (APKs, QR images) are carefully constrained.
- **Implementation:** `server/src/middleware/uploadGuard.js`
- **Mechanism:** Uses `multer` with strict MIME-type and extension checking. File sizes are hard-capped. Original filenames are discarded and replaced with randomized UUIDs to prevent directory traversal and injection attacks. Temporary files are routinely purged.

## 6. Authentication & Access Control
- **Implementation:** `server/src/services/authService.js` and `server/src/middleware/auth.js`
- **Mechanism:** Secure JWT Access Tokens (15m expiry). Cryptographically random opaque Refresh Tokens stored in PostgreSQL with family rotation (detects token theft). HTTP-Only, Secure cookies protect the refresh tokens from XSS. `requireAdmin` enforces Role-Based Access Control (RBAC).

## 7. AI Output Constriction
To prevent LLM hallucination and ensure safe rendering on the client, AI responses are forced into a strict JSON schema.
- **Implementation:** `server/src/utils/aiOutputSchema.js`
- **Mechanism:** Uses Zod to parse the LLM's string output. Extra fields are stripped. If the LLM generates malformed JSON or violates the schema (e.g., summary too long), it is caught and safely handled before reaching the client.

## 8. Deterministic Scoring Separation
AI models are completely decoupled from the numeric Trust Score calculation to prevent manipulation via adversarial inputs.
- **Implementation:** `server/src/risk/riskEngine.js`
- **Mechanism:** Hardcoded weights and formulas apply deterministic penalties based on API evidence. The AI only *reads* the score; it cannot *write* or influence it.
