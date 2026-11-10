import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cloud,
  Cpu,
  Download,
  Eye,
  EyeOff,
  FileText,
  Image as ImageIcon,
  Lock,
  Play,
  RefreshCw,
  Settings,
  Shield,
  ShieldCheck,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';
import { SAMPLE_DOCUMENTS } from './data/sampleDocuments';
import { tokenizeAndRedact } from './engine/piiFirewall';
import {
  executeHybridAuditPipeline,
  getDefaultFirebaseConfigFromEnv,
  inspectMultimodalDocumentImage,
  isValidFirebaseConfig,
  probeOnDeviceAI,
  resetFirebaseInstance,
  warmUpOnDeviceModel,
} from './services/firebaseHybridEngine';
import type {
  AuditReport,
  DeviceAICapability,
  FirebaseRuntimeConfig,
  HybridRoutingPolicy,
  SanitizationResult,
} from './types/veilvault';

function renderHighlightedSanitizedText(text: string): React.ReactNode[] {
  const parts = text.split(/(\[[A-Z0-9_]+\])/g);
  return parts.map((part, idx) =>
    /^\[[A-Z0-9_]+\]$/.test(part) ? (
      <span key={`${part}-${idx}`} className="token-highlight mono">
        {part}
      </span>
    ) : (
      <React.Fragment key={idx}>{part}</React.Fragment>
    ),
  );
}

const STORAGE_CONFIG_KEY = 'veilvault_firebase_runtime_config';

function loadSavedFirebaseConfig(): FirebaseRuntimeConfig | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_CONFIG_KEY);
    if (raw) {
      return JSON.parse(raw) as FirebaseRuntimeConfig;
    }
  } catch {
    // Ignore storage read errors
  }
  return getDefaultFirebaseConfigFromEnv();
}

export default function App() {
  const [selectedPresetId, setSelectedPresetId] = useState<string>(SAMPLE_DOCUMENTS[0].id);
  const activePreset = useMemo(
    () => SAMPLE_DOCUMENTS.find((d) => d.id === selectedPresetId) ?? SAMPLE_DOCUMENTS[0],
    [selectedPresetId],
  );

  const [documentText, setDocumentText] = useState<string>(SAMPLE_DOCUMENTS[0].content);
  const [routingPolicy, setRoutingPolicy] = useState<HybridRoutingPolicy>('split_firewall');
  const [simulateOffline, setSimulateOffline] = useState<boolean>(false);
  const [showRehydrated, setShowRehydrated] = useState<boolean>(false);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [multimodalStatus, setMultimodalStatus] = useState<string | null>(null);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);

  const [capability, setCapability] = useState<DeviceAICapability>({
    supportedBrowser: false,
    nanoStatus: 'unavailable',
    downloadProgress: null,
    online: true,
  });

  const [firebaseConfig, setFirebaseConfig] = useState<FirebaseRuntimeConfig | null>(() =>
    loadSavedFirebaseConfig(),
  );
  const [showConfigModal, setShowConfigModal] = useState<boolean>(false);
  const [draftConfig, setDraftConfig] = useState<FirebaseRuntimeConfig>(
    firebaseConfig ?? { apiKey: '', authDomain: '', projectId: '', appId: '' },
  );

  const [sanitization, setSanitization] = useState<SanitizationResult | null>(null);
  const [report, setReport] = useState<AuditReport | null>(null);

  const imageInputRef = useRef<HTMLInputElement>(null);

  // Live preview redaction so user sees zero-trust firewall barrier immediately while typing
  const liveFirewallPreview = useMemo(() => tokenizeAndRedact(documentText), [documentText]);

  useEffect(() => {
    void probeOnDeviceAI().then(setCapability);
    const syncOnline = () => {
      setCapability((prev) => ({ ...prev, online: navigator.onLine }));
    };
    window.addEventListener('online', syncOnline);
    window.addEventListener('offline', syncOnline);
    return () => {
      window.removeEventListener('online', syncOnline);
      window.removeEventListener('offline', syncOnline);
    };
  }, []);

  const handleSelectPreset = (docId: string) => {
    const found = SAMPLE_DOCUMENTS.find((item) => item.id === docId);
    if (!found) return;
    setSelectedPresetId(found.id);
    setDocumentText(found.content);
    setReport(null);
    setSanitization(null);
    setMultimodalStatus(null);
    setErrorBanner(null);
  };

  const handleRunAudit = async () => {
    if (!documentText.trim()) {
      setErrorBanner('Enter or select a sensitive document first.');
      return;
    }
    setIsRunning(true);
    setErrorBanner(null);
    try {
      const result = await executeHybridAuditPipeline({
        rawText: documentText,
        documentTitle: activePreset.title,
        complianceFramework: activePreset.framework,
        routingPolicy,
        firebaseConfig,
        simulateOffline,
      });
      setSanitization(result.sanitization);
      setReport(result.report);
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : 'Pipeline execution error');
    } finally {
      setIsRunning(false);
    }
  };

  const handleImageUpload = async (evt: React.ChangeEvent<HTMLInputElement>) => {
    const file = evt.target.files?.[0];
    if (!file) return;
    setIsRunning(true);
    setErrorBanner(null);
    try {
      const res = await inspectMultimodalDocumentImage({
        imageFile: file,
        routingPolicy,
        firebaseConfig,
      });
      setDocumentText(res.extractedText);
      setMultimodalStatus(
        `Multimodal ${res.live ? 'Live Firebase' : 'Sandbox'} (${res.inferenceSource}) extracted text in ${res.latencyMs}ms`,
      );
      setReport(null);
      setSanitization(null);
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : 'Multimodal image processing failed');
    } finally {
      setIsRunning(false);
      evt.target.value = '';
    }
  };

  const handleWarmUpNano = async () => {
    setCapability((prev) => ({ ...prev, nanoStatus: 'downloading', downloadProgress: 0 }));
    const nextStatus = await warmUpOnDeviceModel((pct) => {
      setCapability((prev) => ({ ...prev, downloadProgress: pct }));
    });
    const refreshed = await probeOnDeviceAI();
    setCapability({ ...refreshed, nanoStatus: nextStatus });
  };

  const handleSaveFirebaseConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    if (firebaseConfig?.projectId) {
      await resetFirebaseInstance(firebaseConfig.projectId);
    }
    if (isValidFirebaseConfig(draftConfig)) {
      sessionStorage.setItem(STORAGE_CONFIG_KEY, JSON.stringify(draftConfig));
      setFirebaseConfig(draftConfig);
    } else {
      sessionStorage.removeItem(STORAGE_CONFIG_KEY);
      setFirebaseConfig(null);
    }
    setShowConfigModal(false);
  };

  const handleExportProvenance = () => {
    if (!report || !sanitization) return;
    const bundle = {
      generatedAt: new Date().toISOString(),
      product: 'VeilVault Zero-Trust Hybrid AI Firewall (Firebase AI Logic)',
      zeroPIILeakVerified: sanitization.zeroLeakVerified,
      piiTokensShieldedCount: sanitization.tokens.length,
      piiBytesRemoved: sanitization.piiBytesRemoved,
      complianceFramework: report.complianceFramework,
      riskScore: report.riskScore,
      provenance: report.provenance,
      findings: report.findings,
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `veilvault-provenance-${Date.now()}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const activeSanitization = sanitization ?? liveFirewallPreview;
  const totalCloudBytes = report?.provenance.reduce((s, p) => s + p.bytesSentToCloud, 0) ?? 0;
  const totalLatency = report?.provenance.reduce((s, p) => s + p.latencyMs, 0) ?? activeSanitization.redactionLatencyMs;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-wrap">
          <div className="brand-icon">
            <ShieldCheck size={24} />
          </div>
          <div>
            <div className="brand-title">
              VeilVault
              <span className="badge badge-blue">Firebase AI Logic Hybrid</span>
            </div>
            <div className="brand-sub">
              Zero-Trust Split-Inference Firewall — On-Device Gemini Nano PII Redaction + Cloud Gemini Reasoning
            </div>
          </div>
        </div>

        <div className="topbar-controls">
          <span className={`badge ${capability.nanoStatus === 'available' ? 'badge-emerald' : 'badge-amber'}`}>
            <Cpu size={14} />
            Gemini Nano:{' '}
            {capability.nanoStatus === 'downloading'
              ? `Downloading (${capability.downloadProgress ?? 0}%)`
              : capability.nanoStatus}
          </span>

          {capability.nanoStatus === 'downloadable' && (
            <button type="button" className="btn" onClick={handleWarmUpNano}>
              <Download size={15} /> Warm Up Nano
            </button>
          )}

          <button
            type="button"
            className={`btn ${simulateOffline ? 'btn-danger-outline' : ''}`}
            onClick={() => setSimulateOffline((v) => !v)}
            title="Toggle simulated airgap offline mode to verify on-device resilience"
          >
            {simulateOffline || !capability.online ? <WifiOff size={15} /> : <Wifi size={15} />}
            {simulateOffline ? 'Airgap Offline: ON' : 'Network: Online'}
          </button>

          <button type="button" className="btn" onClick={() => setShowConfigModal(true)}>
            <Settings size={15} />
            {isValidFirebaseConfig(firebaseConfig) ? `Firebase: ${firebaseConfig.projectId}` : 'Connect Firebase SDK'}
          </button>
        </div>
      </header>

      {errorBanner && (
        <div className="badge badge-rose" style={{ width: '100%', padding: '10px 16px', borderRadius: 12, marginBottom: 16 }}>
          <AlertTriangle size={16} /> {errorBanner}
        </div>
      )}

      {/* Telemetry KPI Strip */}
      <section className="kpi-strip">
        <div className="kpi-card">
          <div className="kpi-label">PII Leak Guarantee</div>
          <div className="kpi-value" style={{ color: 'var(--accent-emerald)' }}>
            0 Bytes Leaked
          </div>
          <div className="kpi-hint">
            {activeSanitization.tokens.length} sensitive entities ({activeSanitization.piiBytesRemoved} B) locked in RAM
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">Firebase Execution Mode</div>
          <div className="kpi-value" style={{ fontSize: '1.15rem' }}>
            {report
              ? report.liveFirebaseExecution
                ? 'LIVE FIREBASE SDK'
                : simulateOffline
                  ? 'OFFLINE RESILIENCE'
                  : 'SANDBOX ENGINE'
              : 'READY TO AUDIT'}
          </div>
          <div className="kpi-hint">
            Stage 1: ONLY_ON_DEVICE • Stage 2: {simulateOffline ? 'ONLY_ON_DEVICE' : routingPolicy.toUpperCase()}
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">Actual inferenceSource</div>
          <div className="kpi-value" style={{ fontSize: '1.15rem' }}>
            {report ? report.provenance[report.provenance.length - 1]?.actualSource : 'Pending Run'}
          </div>
          <div className="kpi-hint">
            Cloud Egress: {totalCloudBytes} B • Latency: {totalLatency} ms
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">Compliance Risk Score</div>
          <div
            className="kpi-value"
            style={{
              color:
                (report?.riskScore ?? 0) >= 70
                  ? 'var(--accent-rose)'
                  : (report?.riskScore ?? 0) > 0
                    ? 'var(--accent-amber)'
                    : 'var(--text-muted)',
            }}
          >
            {report ? `${report.riskScore} / 100` : '-- / 100'}
          </div>
          <div className="kpi-hint">
            {report ? `${report.findings.length} critical audit flags detected` : 'Run hybrid audit to inspect'}
          </div>
        </div>
      </section>

      {/* Main 3-Column Pipeline Workspace */}
      <main className="workspace-grid">
        {/* Column 1: Sensitive Input & Hybrid Policy Controls */}
        <section className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <FileText size={18} color="#2563eb" /> 1. Sensitive Source Document
            </div>
            <div>
              <input
                ref={imageInputRef}
                type="file"
                accept="image/png,image/jpeg"
                style={{ display: 'none' }}
                onChange={handleImageUpload}
              />
              <button
                type="button"
                className="btn"
                style={{ padding: '6px 10px', fontSize: '0.78rem' }}
                onClick={() => imageInputRef.current?.click()}
              >
                <ImageIcon size={14} /> Upload Receipt / Scan
              </button>
            </div>
          </div>

          <div className="preset-row">
            {SAMPLE_DOCUMENTS.map((doc) => (
              <button
                key={doc.id}
                type="button"
                className={`preset-chip ${selectedPresetId === doc.id ? 'active' : ''}`}
                onClick={() => handleSelectPreset(doc.id)}
              >
                {doc.domain}
              </button>
            ))}
          </div>

          {multimodalStatus && (
            <div className="badge badge-blue" style={{ marginBottom: 10 }}>
              <CheckCircle2 size={14} /> {multimodalStatus}
            </div>
          )}

          <textarea
            className="doc-textarea mono"
            value={documentText}
            onChange={(e) => {
              setDocumentText(e.target.value);
              setReport(null);
              setSanitization(null);
            }}
            placeholder="Paste a medical invoice, contract with SSN/Bank accounts, or upload a PNG/JPEG receipt..."
          />

          <div className="routing-group">
            <div className="kpi-label" style={{ marginTop: 4 }}>
              Firebase AI Logic Hybrid Policy
            </div>

            <label className={`routing-option ${routingPolicy === 'split_firewall' ? 'active' : ''}`}>
              <input
                type="radio"
                name="routingPolicy"
                checked={routingPolicy === 'split_firewall'}
                onChange={() => setRoutingPolicy('split_firewall')}
              />
              <div>
                <div style={{ fontWeight: 700, fontSize: '0.84rem' }}>
                  Zero-Trust Split (`ONLY_ON_DEVICE` → `PREFER_IN_CLOUD`)
                </div>
                <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                  Gemini Nano strips PII locally; `gemini-3.8-flash` audits sanitized tokens only.
                </div>
              </div>
            </label>

            <label className={`routing-option ${routingPolicy === 'resilient_prefer_device' ? 'active' : ''}`}>
              <input
                type="radio"
                name="routingPolicy"
                checked={routingPolicy === 'resilient_prefer_device'}
                onChange={() => setRoutingPolicy('resilient_prefer_device')}
              />
              <div>
                <div style={{ fontWeight: 700, fontSize: '0.84rem' }}>
                  Edge-First (`PREFER_ON_DEVICE` Hybrid Fallback)
                </div>
                <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                  Runs full pipeline on-device at $0 cost; auto-falls back to Cloud Gemini when needed.
                </div>
              </div>
            </label>

            <label className={`routing-option ${routingPolicy === 'airgap_on_device' ? 'active' : ''}`}>
              <input
                type="radio"
                name="routingPolicy"
                checked={routingPolicy === 'airgap_on_device'}
                onChange={() => setRoutingPolicy('airgap_on_device')}
              />
              <div>
                <div style={{ fontWeight: 700, fontSize: '0.84rem' }}>
                  Strict Airgap (`ONLY_ON_DEVICE`)
                </div>
                <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                  100% local execution even when offline. Throws before ever touching cloud APIs.
                </div>
              </div>
            </label>
          </div>

          <button
            type="button"
            className="btn btn-primary"
            style={{ width: '100%', marginTop: 14, padding: '12px 16px' }}
            onClick={handleRunAudit}
            disabled={isRunning}
          >
            {isRunning ? <RefreshCw size={16} /> : <Play size={16} />}
            {isRunning ? 'Executing Hybrid Pipeline...' : 'Run Zero-Trust Hybrid Audit'}
          </button>
        </section>

        {/* Column 2: Edge Privacy Firewall & Token Vault */}
        <section className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <Lock size={18} color="#059669" /> 2. Edge Privacy Firewall
            </div>
            <span className="badge badge-emerald">
              <Shield size={13} /> Zero PII Outbound
            </span>
          </div>

          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 10 }}>
            <strong>Outbound Cloud Payload Preview:</strong> Every raw identifier below is replaced by deterministic tokens in browser RAM before network egress.
          </div>

          <div className="redacted-box mono">{renderHighlightedSanitizedText(activeSanitization.redactedText)}</div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 14 }}>
            <div className="kpi-label">Local Browser RAM Token Vault ({activeSanitization.tokens.length})</div>
            <span className="badge badge-neutral" style={{ fontSize: '0.72rem' }}>
              Never transmitted
            </span>
          </div>

          <div className="vault-list">
            {activeSanitization.tokens.length === 0 ? (
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', padding: '8px 0' }}>
                No structured PII entities detected yet.
              </div>
            ) : (
              activeSanitization.tokens.map((item) => (
                <div key={item.token} className="vault-row">
                  <div>
                    <span className="token-highlight mono">{item.token}</span>{' '}
                    <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>({item.type})</span>
                  </div>
                  <div className="mono" style={{ fontWeight: 600, color: 'var(--accent-rose)' }}>
                    {item.originalValue}
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        {/* Column 3: Audit Report & Hybrid Provenance Receipt */}
        <section className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <Cloud size={18} color="#2563eb" /> 3. Audited Findings & Provenance
            </div>
            {report && (
              <div style={{ display: 'flex', gap: 6 }}>
                <button
                  type="button"
                  className="btn"
                  style={{ padding: '5px 10px', fontSize: '0.75rem' }}
                  onClick={() => setShowRehydrated((v) => !v)}
                >
                  {showRehydrated ? <EyeOff size={13} /> : <Eye size={13} />}
                  {showRehydrated ? 'Mask Tokens' : 'Re-hydrate Locally'}
                </button>
                <button
                  type="button"
                  className="btn"
                  style={{ padding: '5px 10px', fontSize: '0.75rem' }}
                  onClick={handleExportProvenance}
                >
                  <Download size={13} /> Receipt
                </button>
              </div>
            )}
          </div>

          {!report ? (
            <div style={{ textAlign: 'center', padding: '44px 18px', color: 'var(--text-muted)' }}>
              <Activity size={34} style={{ marginBottom: 10, opacity: 0.6 }} />
              <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 6 }}>
                Ready for Zero-Trust Hybrid Analysis
              </div>
              <div style={{ fontSize: '0.82rem' }}>
                Click <strong>Run Zero-Trust Hybrid Audit</strong> to watch Stage 1 tokenize sensitive data locally and Stage 2 generate a verifiable compliance report + provenance receipt.
              </div>
            </div>
          ) : (
            <>
              <div
                style={{
                  background: 'var(--bg-canvas)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 12,
                  padding: 12,
                  marginBottom: 14,
                  fontSize: '0.82rem',
                }}
              >
                <div style={{ fontWeight: 700, marginBottom: 4 }}>Executive Summary</div>
                <div style={{ color: 'var(--text-secondary)' }}>
                  {showRehydrated ? report.rehydratedSummary : report.executiveSummary}
                </div>
              </div>

              {report.findings.map((finding) => (
                <div key={finding.id} className={`finding-card ${finding.severity.toLowerCase()}`}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontWeight: 700, fontSize: '0.84rem' }}>{finding.title}</span>
                    <span
                      className={`badge ${
                        finding.severity === 'CRITICAL'
                          ? 'badge-rose'
                          : finding.severity === 'HIGH'
                            ? 'badge-amber'
                            : 'badge-blue'
                      }`}
                    >
                      {finding.severity}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 6 }}>
                    {finding.explanation}
                  </div>
                  <div style={{ fontSize: '0.76rem', color: 'var(--accent-emerald)', fontWeight: 600 }}>
                    Action: {finding.remediation}
                  </div>
                </div>
              ))}

              <div className="kpi-label" style={{ marginTop: 14 }}>
                Cryptographic Inference Provenance Receipt
              </div>
              <table className="provenance-table">
                <thead>
                  <tr>
                    <th>Stage</th>
                    <th>SDK Mode</th>
                    <th>inferenceSource</th>
                    <th>Cloud B</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {report.provenance.map((step) => (
                    <tr key={step.stage}>
                      <td style={{ fontWeight: 600 }}>{step.stage}</td>
                      <td className="mono">{step.requestedMode}</td>
                      <td className="mono" style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>
                        {step.actualSource}
                      </td>
                      <td>{step.bytesSentToCloud} B</td>
                      <td>{step.latencyMs} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 6 }}>
                {report.provenance.map((step) => (
                  <div
                    key={`${step.stage}-note`}
                    style={{
                      fontSize: '0.74rem',
                      color: 'var(--text-secondary)',
                      background: 'var(--bg-canvas)',
                      padding: '6px 10px',
                      borderRadius: 8,
                      border: '1px solid var(--border-subtle)',
                    }}
                  >
                    <strong>{step.stage}:</strong> {step.notes}
                  </div>
                ))}
              </div>
            </>
          )}
        </section>
      </main>

      {/* Firebase AI Logic Runtime Config Modal */}
      {showConfigModal && (
        <div className="modal-backdrop">
          <form className="modal-card" onSubmit={handleSaveFirebaseConfig}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div style={{ fontWeight: 800, fontSize: '1.05rem' }}>Connect Live Firebase AI Logic Project</div>
              <button
                type="button"
                className="btn"
                style={{ padding: '4px 8px' }}
                onClick={() => setShowConfigModal(false)}
              >
                <X size={16} />
              </button>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 14 }}>
              Paste your Firebase Web App credentials from Firebase Console (stored in browser sessionStorage only). Leave blank to use the Sandbox Engine.
            </p>
            <div className="field-group">
              <label className="field-label">Firebase API Key</label>
              <input
                className="field-input"
                value={draftConfig.apiKey}
                onChange={(e) => setDraftConfig({ ...draftConfig, apiKey: e.target.value })}
                placeholder="AIzaSy..."
              />
            </div>
            <div className="field-group">
              <label className="field-label">Project ID</label>
              <input
                className="field-input"
                value={draftConfig.projectId}
                onChange={(e) => setDraftConfig({ ...draftConfig, projectId: e.target.value })}
                placeholder="veilvault-hybrid-ai"
              />
            </div>
            <div className="field-group">
              <label className="field-label">Auth Domain</label>
              <input
                className="field-input"
                value={draftConfig.authDomain}
                onChange={(e) => setDraftConfig({ ...draftConfig, authDomain: e.target.value })}
                placeholder="veilvault-hybrid-ai.firebaseapp.com"
              />
            </div>
            <div className="field-group">
              <label className="field-label">App ID</label>
              <input
                className="field-input"
                value={draftConfig.appId}
                onChange={(e) => setDraftConfig({ ...draftConfig, appId: e.target.value })}
                placeholder="1:123456789:web:abcdef..."
              />
            </div>
            <div className="field-group">
              <label className="field-label">Firebase App Check reCAPTCHA v3 Site Key (Optional)</label>
              <input
                className="field-input"
                value={draftConfig.recaptchaSiteKey ?? ''}
                onChange={(e) => setDraftConfig({ ...draftConfig, recaptchaSiteKey: e.target.value })}
                placeholder="6Lc... (from Firebase Console -> App Check)"
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 16 }}>
              <button type="button" className="btn" onClick={() => setShowConfigModal(false)}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary">
                Save & Activate SDK
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}

