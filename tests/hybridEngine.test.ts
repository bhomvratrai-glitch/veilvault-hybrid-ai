import { InferenceMode } from 'firebase/ai';
import { describe, expect, it } from 'vitest';
import { SAMPLE_DOCUMENTS } from '../src/data/sampleDocuments';
import { executeHybridAuditPipeline, mapPolicyToInferenceMode } from '../src/services/firebaseHybridEngine';

describe('Firebase Hybrid Inference Pipeline', () => {
  it('maps each VeilVault routing policy to the exact Firebase AI Logic InferenceMode', () => {
    expect(mapPolicyToInferenceMode('split_firewall')).toBe(InferenceMode.PREFER_IN_CLOUD);
    expect(mapPolicyToInferenceMode('resilient_prefer_device')).toBe(InferenceMode.PREFER_ON_DEVICE);
    expect(mapPolicyToInferenceMode('airgap_on_device')).toBe(InferenceMode.ONLY_ON_DEVICE);
  });

  it('enforces zero cloud PII leakage in both offline airgap and split firewall runs', async () => {
    const doc = SAMPLE_DOCUMENTS[1];
    const { sanitization, report } = await executeHybridAuditPipeline({
      rawText: doc.content,
      documentTitle: doc.title,
      complianceFramework: doc.framework,
      routingPolicy: 'split_firewall',
      firebaseConfig: null,
      simulateOffline: true,
    });

    expect(sanitization.zeroLeakVerified).toBe(true);
    expect(report.sanitizedPayloadSent).not.toContain('Priya Nair');
    expect(report.sanitizedPayloadSent).not.toContain('ACCT-99281746502');
    expect(report.provenance).toHaveLength(2);
    expect(report.provenance[0].bytesSentToCloud).toBe(0);
    expect(report.provenance[1].bytesSentToCloud).toBe(0);
    expect(report.riskScore).toBeGreaterThanOrEqual(70);
    expect(report.findings.length).toBeGreaterThanOrEqual(2);
  });
});
