# Project State (Formerly Codebase Audit)

This document reflects the current state of the AITrustLens codebase after Phases 1 and 2 completion. Every claim here is verified against the implemented codebase.

## 1. What Works (Fully Implemented & Verified)
- **Frontend-Backend Integration:** React Vite frontend communicates with Express backend using Axios interceptors. See `client/src/services/api.js`.
- **JWT Refresh Rotation & Auth:** Refresh tokens are stored with family rotation. See `server/src/services/authService.js` (lines 40+) and `server/src/controllers/authController.js`.
- **Authorization (RBAC):** `requireAdmin` middleware protects admin routes. See `server/src/middleware/auth.js` and `server/src/routes/admin.js`.
- **Async Queues & SSE:** BullMQ orchestrates long-running jobs in `server/src/workers/scanWorker.js`. Real-time SSE updates are handled by `server/src/utils/sseManager.js`.
- **Risk Engine:** Strict deterministic scoring using predefined weights. See `server/src/risk/riskEngine.js` and `server/src/risk/riskRules.js`.
- **SSRF Protection:** Resolves DNS and blocks internal IPs (including AWS metadata and loopbacks). See `server/src/utils/ssrfChecker.js`.
- **Prompt Injection Defenses:** AI prompts are strictly wrapped in `<UNTRUSTED_CONTENT>` tags and sanitized. See `server/src/providers/openRouterProvider.js` and `server/tests/unit/promptInjection.test.js`.
- **APK Analysis:** True binary AXML parsing via `adm-zip`. No simulation is used. See `server/src/utils/apkParser.js`.
- **Digital Identity Analysis:** Deterministic checking of MX, SPF, DMARC, and disposable domains. See `server/src/risk/identityEvidenceCollector.js` and `server/src/risk/identityRiskRules.js`.
- **Zod Validation:** All inputs are strictly typed. See `server/src/validators/inputValidator.js`. AI outputs are strictly constrained. See `server/src/utils/aiOutputSchema.js`.

## 2. What Needs Expansion (Current Limitations)
- **Integration Tests:** The test suite is currently heavily unit-tested (80 tests passing). True end-to-end integration tests hitting `analyze.js` routes are missing (Phase 4 scope).
- **AXML Parsing Breadth:** The custom AXML parser successfully extracts permissions, application tags, services, activities, and receivers. However, more complex binary chunk decoding (e.g., resource map indexing) is partially skipped to focus on security-relevant strings.
- **Provider Retries:** While `Promise.allSettled()` is used, robust circuit breakers for specific external API timeouts could be improved.
- **Threat Intelligence Feeds:** Scam/Email analysis heavily relies on NLP regex and keyword mapping. True ML classification is out of scope to preserve the deterministic rule engine.

## 3. What is Missing
- **Integration & Security Scenario Tests:** Need tests for SSRF attempts, tampered JWTs, and full SSE stream lifecycles. (Targeted for Phase 4).

## 4. Architectural Constants
- **The Core Rule:** AI must NEVER determine the Trust Score. Scoring remains 100% in `riskEngine.js`.
- **Frontend:** React + Vite + Vanilla CSS Glassmorphism.
- **Backend:** Express + Prisma PostgreSQL + Redis (BullMQ).
