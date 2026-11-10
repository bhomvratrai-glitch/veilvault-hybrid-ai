# 🛡️ VeilVault — Zero-Trust Split-Inference Firewall (`#BuildHybridAI 2026`)

> **Built for Google Firebase `#BuildHybridAI 2026` ($30,000 Challenge)**  
> **Live Hosted App:** https://bhomvratrai-glitch.github.io/veilvault-hybrid-ai/  
> **Core SDK:** `firebase@latest` (`firebase/ai` — `getAI`, `getGenerativeModel`, `GoogleAIBackend`, `InferenceMode`, `Schema`)

---

## 💡 Why Hybrid Inference Is Architecturally Mandatory Here

Enterprises in **Healthcare (HIPAA)**, **Legal (GDPR)**, and **Finance (PCI-DSS)** want to audit contracts, medical discharge invoices, and tax payouts using cloud Gemini (`gemini-3.8-flash`). **However, compliance law forbids transmitting raw PII/PHI (SSNs, Credit Cards, MRNs, Aadhaar/PAN, Names, Addresses) to cloud endpoints.**

Using *only* cloud AI leaks PII. Using *only* a small on-device model sacrifices deep multi-clause legal/tax reasoning.

**VeilVault solves both via Split-Inference Hybrid Architecture powered by Firebase AI Logic:**

1. **Stage 1 — Edge Privacy Firewall (`InferenceMode.ONLY_ON_DEVICE`):**
   - Runs strictly on-device via Chrome's built-in **Gemini Nano** Prompt API + deterministic structured PII sweeps inside browser RAM.
   - Extracts and replaces SSNs, Credit Cards, MRNs, Bank Accounts, Emails, Phones, Names, and Addresses with reversible bracketed tokens (`[SSN_1]`, `[CARD_1]`, `[PERSON_1]`).
   - A cryptographic invariant check (`verifyZeroPIILeakage`) aborts egress if even 1 byte of raw PII remains.
2. **Stage 2 — Sanitized Hybrid Audit (`InferenceMode.PREFER_IN_CLOUD` / `PREFER_ON_DEVICE` / `ONLY_ON_DEVICE`):**
   - Sends **only 100% anonymized tokens** to `gemini-3.8-flash` via Firebase AI Logic structured JSON output (`Schema.object`).
   - Seamlessly degrades to offline **Airgap Gemini Nano** if network connectivity drops.
   - Captures `result.response.inferenceSource` (`ON_DEVICE` vs `IN_CLOUD`), latency, and cloud egress bytes in an exportable **Cryptographic Provenance Receipt**.
3. **Stage 3 — Multimodal Receipt Scan + Local RAM Re-Hydration:**
   - Supports PNG/JPEG receipt & medical statement vision inspection via Firebase AI Logic `InlineDataPart` (`generateContent([prompt, imagePart])`).
   - Re-hydrates masked findings back into human-readable form strictly inside local browser memory.

---

## 🧪 Quick Start & Verification

```bash
npm install
npm test
npm run dev
```

To test **live Firebase AI Logic** with your Firebase project:
1. Enable Firebase AI Logic in your Firebase Console (`npx firebase-tools init ailogic`).
2. Click **"Connect Firebase SDK"** in the top bar (or configure `VITE_FIREBASE_*` env vars).
3. For Chrome On-Device Gemini Nano, enable `chrome://flags/#prompt-api-for-gemini-nano-multimodal-input` in Chrome Desktop v139+ and click **"Warm Up Nano"**.
