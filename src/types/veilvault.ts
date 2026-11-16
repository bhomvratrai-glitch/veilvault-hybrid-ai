import type { InferenceMode, InferenceSource } from 'firebase/ai';

export type SensitivityType =
  | 'SSN'
  | 'CREDIT_CARD'
  | 'BANK_ACCOUNT'
  | 'EMAIL'
  | 'PHONE'
  | 'GOV_ID'
  | 'MEDICAL_MRN'
  | 'PERSON_NAME'
  | 'ADDRESS'
  | 'API_SECRET'
  | 'IP_ADDRESS'
  | 'CRYPTO_WALLET';

export interface RedactionToken {
  token: string;
  originalValue: string;
  type: SensitivityType;
  detectedBy: 'ON_DEVICE_NANO' | 'DETERMINISTIC_EDGE';
  confidence: number;
}

export interface CryptographicVaultProof {
  sha256PayloadHash: string;
  sha256VaultHash: string;
  keyAlgorithm: string;
  encryptedTokenCount: number;
  generatedAt: string;
  zeroLeakVerified: boolean;
}

export interface SanitizationResult {
  originalText: string;
  redactedText: string;
  tokens: RedactionToken[];
  piiBytesRemoved: number;
  zeroLeakVerified: boolean;
  redactionLatencyMs: number;
  vaultProof?: CryptographicVaultProof;
}

export type AuditSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface AuditFinding {
  id: string;
  title: string;
  severity: AuditSeverity;
  category: string;
  explanation: string;
  remediation: string;
}

export interface ProvenanceStep {
  stage: string;
  requestedMode: InferenceMode | string;
  actualSource: InferenceSource | 'LOCAL_DETERMINISTIC' | 'SIMULATED_OFFLINE';
  latencyMs: number;
  bytesSentToCloud: number;
  bytesKeptLocal: number;
  notes: string;
}

export interface ComplianceFrameworkScore {
  frameworkName: string;
  standardRef: string;
  status: 'CERTIFIED_COMPLIANT' | 'REQUIRES_REMEDIATION';
  score: number;
  criteriaChecked: string[];
  findingsSummary: string;
}

export interface AuditReport {
  documentTitle: string;
  complianceFramework: string;
  riskScore: number;
  executiveSummary: string;
  findings: AuditFinding[];
  provenance: ProvenanceStep[];
  sanitizedPayloadSent: string;
  rehydratedSummary: string;
  liveFirebaseExecution: boolean;
  vaultProof?: CryptographicVaultProof;
  complianceScores?: ComplianceFrameworkScore[];
}

export type OnDeviceStatus = 'available' | 'downloading' | 'downloadable' | 'unavailable';

export interface DeviceAICapability {
  supportedBrowser: boolean;
  nanoStatus: OnDeviceStatus;
  downloadProgress: number | null;
  online: boolean;
}

export type HybridRoutingPolicy = 'split_firewall' | 'airgap_on_device' | 'resilient_prefer_device';

export interface SampleDocument {
  id: string;
  title: string;
  domain: string;
  framework: string;
  description: string;
  content: string;
}

export interface FirebaseRuntimeConfig {
  apiKey: string;
  authDomain: string;
  projectId: string;
  appId: string;
  storageBucket?: string;
  messagingSenderId?: string;
  measurementId?: string;
  recaptchaSiteKey?: string;
}
