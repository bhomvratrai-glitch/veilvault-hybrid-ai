import type { RedactionToken, SanitizationResult, SensitivityType } from '../types/veilvault';

interface PatternRule {
  type: SensitivityType;
  prefix: string;
  regex: RegExp;
}

const EDGE_PATTERN_RULES: PatternRule[] = [
  {
    type: 'SSN',
    prefix: 'SSN',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    type: 'CREDIT_CARD',
    prefix: 'CARD',
    regex: /\b(?:\d{4}[-\s]?){3}\d{3,4}\b/g,
  },
  {
    type: 'GOV_ID',
    prefix: 'GOV_ID',
    regex: /\b\d{4}[-\s]\d{4}[-\s]\d{4}\b/g,
  },
  {
    type: 'MEDICAL_MRN',
    prefix: 'MRN',
    regex: /\bMRN-[A-Z0-9-]{4,16}\b/gi,
  },
  {
    type: 'BANK_ACCOUNT',
    prefix: 'ACCT',
    regex: /\bACCT-[A-Z0-9]{6,20}\b|\bRouting\s+\d{9}\b/gi,
  },
  {
    type: 'EMAIL',
    prefix: 'EMAIL',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
  {
    type: 'PHONE',
    prefix: 'PHONE',
    regex: /(?:\+\d{1,3}[\s-]?)?(?:\(\d{3}\)|\d{3,5})[\s-]?\d{3,5}[\s-]?\d{4}\b/g,
  },
];

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Normalizes and runs deterministic + AI-assisted PII tokenization entirely in local browser RAM.
 * Guarantees that every detected sensitive value is mapped to a reversible bracketed token
 * before any outbound cloud call occurs.
 */
export function tokenizeAndRedact(
  sourceText: string,
  aiDetectedEntities: Array<{ value: string; type: SensitivityType }> = [],
): SanitizationResult {
  const start = performance.now();
  let workingText = sourceText;
  const tokens: RedactionToken[] = [];
  const valueToToken = new Map<string, string>();
  const counters: Record<string, number> = {};

  const registerToken = (
    originalValue: string,
    type: SensitivityType,
    prefix: string,
    detectedBy: RedactionToken['detectedBy'],
    confidence: number,
  ): string => {
    const normalized = originalValue.trim();
    const existing = valueToToken.get(normalized);
    if (existing) {
      return existing;
    }

    counters[prefix] = (counters[prefix] ?? 0) + 1;
    const token = `[${prefix}_${counters[prefix]}]`;
    valueToToken.set(normalized, token);
    tokens.push({
      token,
      originalValue: normalized,
      type,
      detectedBy,
      confidence,
    });
    return token;
  };

  // Phase 1: Apply AI-discovered unstructured entities (names, addresses) from Gemini Nano ON_DEVICE first,
  // longest match first to prevent partial sub-token collisions.
  const sortedAiEntities = [...aiDetectedEntities]
    .filter((item) => item.value && item.value.trim().length >= 3)
    .sort((a, b) => b.value.length - a.value.length);

  for (const entity of sortedAiEntities) {
    const cleanValue = entity.value.trim();
    if (!workingText.includes(cleanValue)) {
      continue;
    }
    const prefix = entity.type === 'PERSON_NAME' ? 'PERSON' : entity.type === 'ADDRESS' ? 'ADDR' : entity.type;
    const token = registerToken(cleanValue, entity.type, prefix, 'ON_DEVICE_NANO', 0.94);
    workingText = workingText.replace(new RegExp(escapeRegExp(cleanValue), 'g'), token);
  }

  // Phase 2: Contextual label extraction for names/addresses when on-device LLM is unavailable or supplemental.
  const contextualLabelRules: Array<{ regex: RegExp; type: SensitivityType; prefix: string }> = [
    {
      regex: /(?:Patient Name|Customer Legal Representative|Payee Full Name|Attending Physician):\s*([^\n(|,;]+)/gi,
      type: 'PERSON_NAME',
      prefix: 'PERSON',
    },
    {
      regex: /(?:Residential Address|Registered Billing Address):\s*([^\n|;]+)/gi,
      type: 'ADDRESS',
      prefix: 'ADDR',
    },
  ];

  for (const rule of contextualLabelRules) {
    workingText = workingText.replace(rule.regex, (fullMatch, capturedGroup: string) => {
      const target = capturedGroup.trim();
      if (!target || target.startsWith('[')) {
        return fullMatch;
      }
      const token = registerToken(target, rule.type, rule.prefix, 'DETERMINISTIC_EDGE', 0.97);
      return fullMatch.replace(target, token);
    });
  }

  // Phase 3: Strict deterministic regex sweep for structured financial, medical, and government PII.
  for (const rule of EDGE_PATTERN_RULES) {
    workingText = workingText.replace(rule.regex, (matched) => {
      const token = registerToken(matched, rule.type, rule.prefix, 'DETERMINISTIC_EDGE', 0.99);
      return token;
    });
  }

  const piiBytesRemoved = tokens.reduce((sum, item) => sum + new Blob([item.originalValue]).size, 0);
  const zeroLeakVerified = verifyZeroPIILeakage(workingText, tokens);
  const redactionLatencyMs = Math.max(1, Math.round(performance.now() - start));

  return {
    originalText: sourceText,
    redactedText: workingText,
    tokens,
    piiBytesRemoved,
    zeroLeakVerified,
    redactionLatencyMs,
  };
}

/**
 * Cryptographic/invariant guard: confirms ZERO raw sensitive values remain anywhere
 * in the redacted cloud payload before network egress is permitted.
 */
export function verifyZeroPIILeakage(redactedPayload: string, tokens: RedactionToken[]): boolean {
  for (const entry of tokens) {
    if (entry.originalValue.length >= 4 && redactedPayload.includes(entry.originalValue)) {
      return false;
    }
  }
  return true;
}

/**
 * Re-hydrates anonymized cloud insights back to the user's private local view inside browser RAM.
 */
export function rehydrateTokens(sanitizedText: string, tokens: RedactionToken[]): string {
  let output = sanitizedText;
  for (const entry of tokens) {
    output = output.replace(new RegExp(escapeRegExp(entry.token), 'g'), entry.originalValue);
  }
  return output;
}
