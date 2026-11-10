# 🏆 Devpost Submission Dossier — VeilVault (`#BuildHybridAI 2026`)

> **Project Title:** VeilVault — Zero-Trust Split-Inference Privacy Firewall  
> **Tagline:** Never leak raw SSNs, medical MRNs, or credit cards to the cloud: Gemini Nano redacts PII strictly on-device (`ONLY_ON_DEVICE`), while Cloud Gemini audits anonymized risks via Firebase AI Logic.  
> **Live Web App:** https://bhomvratrai-glitch.github.io/veilvault-hybrid-ai/  
> **Public Repository:** https://github.com/bhomvratrai-glitch/veilvault-hybrid-ai

---

### 1. Inspiration
Every hospital, law firm, and accounting team faces the same AI deadlock: cloud models like `gemini-3.8-flash` are extraordinary at spotting CPT billing upcoding, predatory SaaS indemnification clauses, and cross-border tax traps—**but HIPAA, GDPR, and PCI-DSS legally forbid uploading unredacted patient or financial PII to external cloud endpoints.**

Instead of treating hybrid inference as a simple fallback toggle, we asked: *What if on-device AI and cloud AI physically split the computation across the trust boundary?*

### 2. What It Does
- **Stage 1 (`InferenceMode.ONLY_ON_DEVICE` Edge Firewall):** Uses Chrome's built-in Gemini Nano (plus a deterministic edge regex engine) strictly locally in browser RAM to strip names, SSNs, Aadhaar/PAN IDs, MRNs, credit cards, bank accounts, phones, emails, and addresses before any network call is allowed.
- **Stage 2 (`InferenceMode.PREFER_IN_CLOUD` / `PREFER_ON_DEVICE` Hybrid Audit):** Transmits only `[TOKEN]`-anonymized text to `gemini-3.8-flash` via Firebase AI Logic (`Schema.object` structured JSON) to uncover critical compliance risks.
- **Airgap Offline Resilience:** Toggling Offline / Strict Airgap (`ONLY_ON_DEVICE`) continues running locally with 0 bytes leaving the device.
- **Multimodal Document Scan Inspection:** Upload PNG/JPEG bills or contracts via Firebase AI Logic `InlineDataPart`.
- **Verifiable Provenance Receipt:** Logs every stage's `InferenceMode`, actual `response.inferenceSource` (`ON_DEVICE` vs `IN_CLOUD`), latency (ms), and bytes kept local vs sent to cloud, exportable as JSON.

### 3. How We Built It
- **Frontend & SDK:** React 19 + TypeScript + Vite + `firebase@latest` (`@firebase/ai@3.0.0`).
- **Privacy Firewall Core:** Reversible RAM-only Token Vault (`src/engine/piiFirewall.ts`) with a strict `verifyZeroPIILeakage` pre-egress guard.
- **Verification:** Automated Vitest unit suite (`6/6 passing`) verifying zero PII leakage invariants, AI-entity redaction fusion, RAM re-hydration, and airgap offline execution.
