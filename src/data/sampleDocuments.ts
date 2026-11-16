import type { SampleDocument } from '../types/veilvault';

export const SAMPLE_DOCUMENTS: SampleDocument[] = [
  {
    id: 'hipaa-clinical',
    title: 'Hospital Discharge & Billing Audit',
    domain: 'Healthcare (HIPAA PHI)',
    framework: 'HIPAA Privacy (§164.514) & Billing Compliance',
    description: 'Emergency discharge invoice containing SSN, MRN, attending doctor details, and potential upcoded CPT procedures.',
    content: `ST. JUDE REGIONAL MEDICAL CENTER — INPATIENT BILLING STATEMENT
Patient Name: Rajeshwar Sharma
Medical Record Number: MRN-88492014
Social Security / National ID: 543-29-8104
Contact Phone: +1 (415) 891-3340
Patient Email: r.sharma.bayarea@gmail.com
Residential Address: 742 Evergreen Terrace, San Jose, CA 95112
Attending Physician: Dr. Elena Vance (elena.vance@stjudemed.org)
Insurance Card Charged: 4532-8910-4421-9012

CLINICAL PROCEDURES & CHARGES:
1. CPT-99285 Emergency Dept Visit Level 5 (Critical Care) — $4,850.00
   Note: Patient triage intake sheet marks vitals stable, ESI Level 3, discharged after 45 mins oral hydration.
2. CPT-99285 Duplicate Facility Emergency Evaluation Fee — $4,850.00
3. CPT-71046 Chest X-Ray 2 Views (Portable) — $1,420.00
4. Unlisted Medication Supply Fee (Undocumented dosage) — $980.00

Net Payable Balance Due within 10 Days or sent to External Collections at 24% APR.`,
  },
  {
    id: 'gdpr-msa',
    title: 'Enterprise SaaS MSA & Wire Addendum',
    domain: 'Legal & Finance (GDPR / SOC2)',
    framework: 'GDPR Data Protection & Commercial Risk',
    description: 'Cross-border software agreement with signatory PII, corporate bank routing numbers, and hidden uncapped liability.',
    content: `MASTER SOFTWARE & DATA PROCESSING ADDENDUM (CONFIDENTIAL)
Customer Legal Representative: Priya Nair
Direct Phone: +44 7700 900412
Signatory Email: priya.nair@meridianfintech.co.uk
Registered Billing Address: 22 Bishopsgate, Floor 14, London EC2N 4BQ
Beneficiary Settlement IBAN / Account: ACCT-99281746502 (Routing 021000021)
Backup Corporate Amex on File: 3782-822463-10005

KEY COMMERCIAL CLAUSES:
Section 4.2 (Pricing & Renewal): Annual subscription of $148,000 renews automatically for successive 36-month terms unless written cancellation is delivered via registered mail exactly 120 days prior, with an uncapped 18% annual price escalator.
Section 8.1 (Liability & Data Rights): Vendor caps all direct liability at $500 USD total, while Customer grants Vendor a perpetual, irrevocable license to retain and train commercial foundation models on raw uploaded Customer production logs and end-user PII without deletion SLA.
Section 9.4 (Termination): Immediate termination forfeits remaining multi-year prepaid balance with zero pro-rata refund.`,
  },
  {
    id: 'pci-contractor',
    title: 'Cross-Border Vendor Payout Invoice',
    domain: 'Fintech & Tax (PCI-DSS)',
    framework: 'PCI-DSS & International Tax Compliance',
    description: 'International contractor settlement invoice containing government IDs, PAN/Aadhaar, payout card, and withholding discrepancy.',
    content: `CONTRACTOR PAYOUT & TAX SETTLEMENT STATEMENT — Q4
Payee Full Name: Vikramaditya Rao
Government Tax ID (PAN / Aadhaar): 8912-4401-7732
Settlement Bank Account: ACCT-440192837112
Payout Card Reference: 5412-7512-8900-4412
Payee Contact: +91 98201-44519 | vikram.rao.dev@outlook.com

INVOICE LINE ITEMS:
- Cloud Infrastructure Audit (140 hrs @ $125/hr): $17,500.00
- Emergency Weekend Incident Response Retainer: $2,500.00
Gross Invoice Amount: $20,000.00
Withholding Tax Applied: 0% (Form W-8BEN expired 14 months ago; no treaty certificate attached)
FX Conversion Spread Fee Deducted by Intermediary: 6.8% ($1,360.00 undisclosed markup)
Settlement Notice: Funds routed via unverified third-party intermediary wallet.`,
  },
  {
    id: 'devops-incident',
    title: 'Production Incident Post-Mortem & Leak',
    domain: 'Cloud Security & DevOps (SOC 2 / ISO 27001)',
    framework: 'SOC 2 Type II Confidentiality & NIST SP 800-61',
    description: 'Critical Kubernetes outage post-mortem containing leaked AWS root access keys, GitHub PATs, and internal database passwords.',
    content: `INCIDENT ROOT-CAUSE POST-MORTEM — TICKET #SEC-9082
Severity: P0 Critical Infrastructure Outage
Lead SRE: Marcus Chen (marcus.chen@infra-corp.internal)
Server Node IP: 10.240.12.84
Incident Location: US-East-1 Datacenter Cluster 4A

EXECUTIVE TIMELINE & EXPOSURE LOG:
14:22 UTC - Deploy pipeline failed with unauthorized AWS STS exception.
14:25 UTC - Emergency debug session initiated with unmasked credentials:
  - AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
  - GITHUB_DEPLOY_TOKEN: ghp_EXAMPLE_DEMO_CREDENTIAL_9999
  - STRIPE_PAYOUT_GATEWAY: sk_test_DEMO_STRIPE_KEY_SAMPLE_1234
  - DATABASE_URI: postgres://postgres:P@ssw0rd9912!@192.168.1.105:5432/core_production
  - ETH_TREASURY_ESCROW: 0x71C8360f3a804f364286f7b129759239841804E1

ROOT CAUSE & BLAST RADIUS:
The hardcoded AWS root key and GitHub PAT were logged directly to standard out in plaintext during container crash loop. Over 4.2 million user session records were exposed on internal subnet 10.240.12.84 prior to emergency network termination. Immediate credential rotation required across all 3 cloud providers.`,
  },
  {
    id: 'hr-whistleblower',
    title: 'Executive Compensation & Ethics Investigation',
    domain: 'HR & Corporate Governance (Whistleblower Directive)',
    framework: 'SOX Section 301 & EU Whistleblower Directive',
    description: 'Internal ethics committee inquiry containing confidential whistleblower identity, executive salary overrides, and severance escrow.',
    content: `CONFIDENTIAL ETHICS COMMITTEE INQUIRY — FILE #ETH-2026-441
Investigator: Sarah Jenkins, Chief Compliance Officer (s.jenkins@apex-holdings.com)
Protected Whistleblower: David Miller (Senior Financial Controller, Badge #EMP-0914)
Phone: +1 (212) 555-0198
Residential Address: 450 Lexington Ave, Suite 2200, New York, NY 10017
Employee SSN on File: 092-44-8819

INQUIRY FINDINGS:
1. Undisclosed Executive Bonus Pool: $1,450,000 paid to CEO via off-ledger bank wire ACCT-88291044719 without Compensation Committee sign-off.
2. Disputed Severance Escrow Card: 4111-2222-3333-5555 issued to departing VP with unlimited monthly entertainment allowance.
3. Retaliatory Termination Risk: Performance review for David Miller was retroactively downgraded 48 hours following internal audit disclosure to external auditors.`,
  },
];
