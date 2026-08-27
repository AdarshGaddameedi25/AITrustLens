# Feature-to-Code Traceability Matrix

This matrix maps every core feature module of AITrustLens directly to the file that implements it. No row is marked as complete without a verifiable file path.

| Module | Frontend Page | Route | Controller | Service | Risk Rules / Evidence | DB Persistence | Tests |
|---|---|---|---|---|---|---|---|
| **URL Scan** | `client/src/pages/UrlAnalysis.jsx` | `server/src/routes/analyze.js` | `server/src/controllers/analyzeController.js` | `server/src/services/urlAnalyzerService.js` | `server/src/risk/evidenceCollector.js` | `server/prisma/schema.prisma` (ScanResult) | `server/tests/unit/inputValidator.test.js` |
| **QR Code** | `client/src/pages/QrAnalysis.jsx` | `server/src/routes/analyze.js` | `server/src/controllers/analyzeController.js` | `server/src/services/qrAnalyzerService.js` | (Reuses URL Pipeline) | `server/prisma/schema.prisma` | `server/tests/unit/qrAnalyzer.test.js` |
| **Email** | `client/src/pages/EmailAnalysis.jsx` | `server/src/routes/analyze.js` | `server/src/controllers/analyzeController.js` | `server/src/services/emailAnalyzerService.js` | `server/src/risk/riskRules.js` | `server/prisma/schema.prisma` | `server/tests/unit/inputValidator.test.js` |
| **Scam** | `client/src/pages/ScamAnalysis.jsx` | `server/src/routes/analyze.js` | `server/src/controllers/analyzeController.js` | `server/src/services/scamDetectorService.js` | `server/src/risk/riskRules.js` | `server/prisma/schema.prisma` | `server/tests/unit/inputValidator.test.js` |
| **Password** | `client/src/pages/PasswordAnalysis.jsx` | `server/src/routes/analyze.js` | `server/src/controllers/analyzeController.js` | `server/src/services/passwordBreachService.js` | `server/src/providers/pwnedPasswordsProvider.js` | `server/prisma/schema.prisma` | `server/tests/unit/inputValidator.test.js` |
| **Privacy** | `client/src/pages/PrivacyAnalysis.jsx` | `server/src/routes/analyze.js` | `server/src/controllers/analyzeController.js` | `server/src/services/privacyAnalyzerService.js` | `server/src/utils/ssrfChecker.js` | `server/prisma/schema.prisma` | `server/tests/unit/inputValidator.test.js` |
| **APK** | `client/src/pages/ApkAnalysis.jsx` | `server/src/routes/analyze.js` | `server/src/controllers/analyzeController.js` | `server/src/services/apkAnalyzerService.js` | `server/src/utils/apkParser.js` | `server/prisma/schema.prisma` | `server/tests/unit/apkAnalyzer.test.js` |
| **Claim** | `client/src/pages/ClaimAnalysis.jsx` | `server/src/routes/analyze.js` | `server/src/controllers/analyzeController.js` | `server/src/services/claimVerificationService.js` | `server/src/providers/factCheckProvider.js` | `server/prisma/schema.prisma` | `server/tests/unit/inputValidator.test.js` |
| **Identity** | `client/src/pages/IdentityAnalysis.jsx` | `server/src/routes/analyze.js` | `server/src/controllers/analyzeController.js` | `server/src/services/identityAnalyzerService.js` | `server/src/risk/identityEvidenceCollector.js` | `server/prisma/schema.prisma` | `server/tests/unit/identityAnalyzer.test.js` |

## Infrastructure & Security Mappings

| System | Implementation File |
|---|---|
| **JWT Refresh Rotation** | `server/src/services/authService.js` (Lines 40+) |
| **RBAC / Admin Protection** | `server/src/middleware/auth.js` (`requireAdmin`) |
| **SSRF Protection** | `server/src/utils/ssrfChecker.js` |
| **Prompt Injection Protection** | `server/src/providers/openRouterProvider.js` |
| **Zod Input Validation** | `server/src/validators/inputValidator.js` |
| **Zod Output Validation** | `server/src/utils/aiOutputSchema.js` |
| **Async Queues (BullMQ)** | `server/src/workers/scanWorker.js` |
| **Real-time SSE Streams** | `server/src/utils/sseManager.js` |
