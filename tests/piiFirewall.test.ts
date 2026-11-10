import { describe, expect, it } from 'vitest';
import { SAMPLE_DOCUMENTS } from '../src/data/sampleDocuments';
import { rehydrateTokens, tokenizeAndRedact, verifyZeroPIILeakage } from '../src/engine/piiFirewall';

describe('VeilVault Edge PII Firewall', () => {
  it('redacts SSN, Credit Card, MRN, Email, Phone, and contextual Name/Address with zero leaks', () => {
    const sample = SAMPLE_DOCUMENTS[0].content;
    const result = tokenizeAndRedact(sample);

    expect(result.zeroLeakVerified).toBe(true);
    expect(result.tokens.length).toBeGreaterThanOrEqual(6);
    expect(result.redactedText).not.toContain('543-29-8104');
    expect(result.redactedText).not.toContain('4532-8910-4421-9012');
    expect(result.redactedText).not.toContain('MRN-88492014');
    expect(result.redactedText).not.toContain('r.sharma.bayarea@gmail.com');
    expect(result.redactedText).not.toContain('Rajeshwar Sharma');
    expect(result.redactedText).toContain('[SSN_1]');
    expect(result.redactedText).toContain('[CARD_1]');
    expect(result.redactedText).toContain('[MRN_1]');
  });

  it('incorporates AI-discovered entities from Chrome Gemini Nano before deterministic sweep', () => {
    const text = 'Signed by Elena Rostova at 410 Terry Ave N, Seattle. Contact elena@example.org.';
    const result = tokenizeAndRedact(text, [
      { value: 'Elena Rostova', type: 'PERSON_NAME' },
      { value: '410 Terry Ave N, Seattle', type: 'ADDRESS' },
    ]);

    expect(result.zeroLeakVerified).toBe(true);
    expect(result.redactedText).toContain('[PERSON_1]');
    expect(result.redactedText).toContain('[ADDR_1]');
    expect(result.redactedText).toContain('[EMAIL_1]');
    expect(result.tokens.find((t) => t.originalValue === 'Elena Rostova')?.detectedBy).toBe('ON_DEVICE_NANO');
  });

  it('re-hydrates anonymized cloud insights strictly back inside local memory', () => {
    const source = 'Patient Name: Priya Nair | Email: priya.nair@acme.co | Balance due on CARD 4111-2222-3333-4444';
    const sanitized = tokenizeAndRedact(source);
    const cloudSummary = 'Audit complete for [PERSON_1] ([EMAIL_1]): dispute charge on [CARD_1].';
    const localView = rehydrateTokens(cloudSummary, sanitized.tokens);

    expect(localView).toBe('Audit complete for Priya Nair (priya.nair@acme.co): dispute charge on 4111-2222-3333-4444.');
  });

  it('verifyZeroPIILeakage catches any unredacted raw value before network egress', () => {
    const tokens = [
      {
        token: '[SSN_1]',
        originalValue: '123-45-6789',
        type: 'SSN' as const,
        detectedBy: 'DETERMINISTIC_EDGE' as const,
        confidence: 0.99,
      },
    ];

    expect(verifyZeroPIILeakage('Redacted payload [SSN_1]', tokens)).toBe(true);
    expect(verifyZeroPIILeakage('Leaked payload 123-45-6789', tokens)).toBe(false);
  });
});
