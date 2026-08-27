# Codebase Audit (Phase 0 Baseline)

## 1. What already works
- **Frontend-Backend Integration:** The React Vite frontend successfully communicates with the Express backend using an Axios instance with JWT interceptors.
- **Providers:** Basic implementations for VirusTotal, Safe Browsing, HIBP (K-Anonymity), OpenRouter (AI explainability), and Google Fact Check are functional.
- **Risk Engine:** The separation between deterministic risk scoring (`riskRules.js`) and AI explanation is fundamentally intact. Evidence drives the score mathematically.
- **UI Design:** The Glassmorphism design system in pure CSS is implemented across all pages.
- **Basic Auth:** JWT generation and bcrypt password hashing work for login/registration.

## 2. What partially works
- **SSRF Protection:** `ssrfChecker.js` exists but relies on naive string matching for internal IPs. It does not resolve DNS or protect against DNS rebinding, IPv6 loopbacks, or malicious redirects.
- **Error Handling:** Basic try/catch exists, but robust provider failure handling (circuit breakers, exponential backoff) is missing. `Promise.allSettled` is used, but timeout management per provider is primitive.
- **Scam / Email Analysis:** Relies on basic regex patterns. Needs structured normalization and robust extraction.

## 3. What is missing
- **JWT Refresh Rotation:** Only access tokens are used. There is no refresh token logic, meaning sessions are either insecurely long-lived or annoyingly short.
- **Authorization (RBAC):** Middleware checks if a user is logged in, but does not verify ownership of resources (e.g., User A could theoretically query User B's scan if they knew the ID).
- **Prompt Injection Defenses:** Untrusted user input (emails, scam texts, privacy policies) is sent to OpenRouter without explicit system prompt instructions to ignore injected commands.
- **Async Queues:** All scans run synchronously in the HTTP request cycle. This will cause timeouts for slower providers (URLScan takes 10+ seconds).
- **Comprehensive Evidence Normalization:** Providers return slightly different data structures; a unified "Evidence Model" does not exist yet.
- **Testing:** Unit, integration, security, and fuzz tests are entirely absent.

## 4. What is insecure
- **SSRF:** Vulnerable to DNS rebinding and advanced SSRF vectors.
- **XSS:** While React automatically escapes some content, the AI-generated explanations and raw evidence might be unsafely rendered if not carefully managed.
- **Prompt Injection:** Untrusted data fed directly to LLMs.
- **Rate Limiting:** Basic rate limiting exists, but lacks distributed capability (Redis) or granular provider-level throttling.

## 5. What is duplicated
- **URL Extraction:** Email and Scam analyzers both attempt to extract URLs. This logic should be centralized.
- **Risk Calculation Logic:** While centralized in `riskEngine.js`, the way penalties are applied could be simplified with a unified rule engine.

## 6. What is technically incorrect
- **Confidence vs Trust Score:** Currently, the system somewhat conflates these or hard-codes confidence. Evidence coverage is not calculated mathematically.
- **Domain Age:** Currently not fully implemented as a partial risk modifier; mostly a placeholder in the RDAP provider.

## 7. What requires refactoring
- **Provider Layer:** Needs to be rewritten to implement an Adapter pattern that produces a normalized `Evidence` object, rather than passing raw API responses directly to the Risk Engine.
- **Controllers:** Need to adopt an async queue model (return a job ID, process in background) for long-running scans.

## 8. What must not be changed
- **The Core Rule:** AI must NEVER determine the Trust Score.
- **Frontend Framework:** React + Vite + Vanilla CSS Glassmorphism must be preserved. (No Tailwind, No TypeScript).
- **ORM:** Prisma + PostgreSQL remains the database standard.
