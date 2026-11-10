import type { SampleDocument } from '../types/veilvault';

export const SAMPLE_DOCUMENTS: SampleDocument[] = [
  {
    id: 'hipaa-clinical',
    title: 'Hospital Discharge & Billing Audit',
    domain: 'Healthcare (HIPAA PHI)',
    framework: 'HIPAA Privacy & Billing Compliance',
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
];

