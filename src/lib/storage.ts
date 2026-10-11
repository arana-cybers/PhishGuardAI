import { supabase } from './supabaseClient';
import type { AnyRiskResult, RiskResult, EmailRiskResult, ScanRecord, HeuristicCheck, UrlRiskResult, Verdict } from './types';

const MAX_RECORDS = 100;

// ---- Mapping between RiskResult objects and ScanRecord / DB rows ----

interface ScanRow {
  id: string;
  scan_type: 'url' | 'email';
  label: string;
  sublabel: string;
  score: number;
  verdict: Verdict;
  confidence: number;
  checks: HeuristicCheck[];
  extracted_urls: UrlRiskResult[] | null;
  scanned_at: string;
}

function rowToRecord(r: ScanRow): ScanRecord {
  return {
    id: r.id,
    scanType: r.scan_type,
    label: r.label,
    sublabel: r.sublabel,
    score: r.score,
    verdict: r.verdict,
    confidence: r.confidence,
    checks: r.checks ?? [],
    extractedUrls: r.extracted_urls ?? undefined,
    scannedAt: r.scanned_at,
  };
}

function urlResultToRecord(r: RiskResult): Omit<ScanRecord, 'id'> {
  return {
    scanType: 'url',
    label: r.url,
    sublabel: r.normalizedUrl,
    score: r.score,
    verdict: r.verdict,
    confidence: r.confidence,
    checks: r.checks,
    scannedAt: r.scannedAt,
  };
}

function emailResultToRecord(r: EmailRiskResult): Omit<ScanRecord, 'id'> {
  return {
    scanType: 'email',
    label: r.sender,
    sublabel: r.subject,
    score: r.score,
    verdict: r.verdict,
    confidence: r.confidence,
    checks: r.checks,
    extractedUrls: r.extractedUrls,
    scannedAt: r.scannedAt,
  };
}

export function resultToRecord(r: AnyRiskResult): Omit<ScanRecord, 'id'> {
  return r.scanType === 'url' ? urlResultToRecord(r) : emailResultToRecord(r);
}

// ---- Database operations ----

export async function loadHistory(): Promise<ScanRecord[]> {
  const { data, error } = await supabase
    .from('scans')
    .select('*')
    .order('scanned_at', { ascending: false })
    .limit(MAX_RECORDS);
  if (error) {
    console.error('Failed to load scan history:', error.message);
    return [];
  }
  return (data as ScanRow[]).map(rowToRecord);
}

export async function insertScan(r: AnyRiskResult): Promise<ScanRecord | null> {
  const record = resultToRecord(r);
  const row = {
    scan_type: record.scanType,
    label: record.label,
    sublabel: record.sublabel,
    score: record.score,
    verdict: record.verdict,
    confidence: record.confidence,
    checks: record.checks,
    extracted_urls: record.extractedUrls ?? null,
    scanned_at: record.scannedAt,
  };
  const { data, error } = await supabase
    .from('scans')
    .insert(row)
    .select('*')
    .single();
  if (error) {
    console.error('Failed to insert scan:', error.message);
    return null;
  }
  return rowToRecord(data as ScanRow);
}

export async function clearHistory(): Promise<boolean> {
  const { error } = await supabase.from('scans').delete().neq('id', '00000000-0000-0000-0000-000000000000');
  if (error) {
    console.error('Failed to clear scan history:', error.message);
    return false;
  }
  return true;
}

// ---- Example data (kept for the UI chips) ----

export const EXAMPLE_URLS: { label: string; url: string; note: string }[] = [
  {
    label: 'Google (safe)',
    url: 'https://www.google.com',
    note: 'Trusted, HTTPS, short domain — should score Safe.',
  },
  {
    label: 'Verify-account phishing',
    url: 'http://192.168.0.5/verify-account/login?token=abc123xyz&continue=https://secure-banking-update.confirm.user-login-session.reauth.longpath.example.net',
    note: 'IP host, HTTP, suspicious keywords, long URL — should score Phishing.',
  },
  {
    label: 'Shortened link',
    url: 'https://bit.ly/3xY9zK',
    note: 'Link shortener hides the real destination — Suspicious.',
  },
  {
    label: 'Hyphenated impersonation',
    url: 'https://www.pay-pal-login.com/account/update',
    note: 'Hyphen + sensitive keywords on an untrusted domain — Suspicious/Phishing.',
  },
];

export const EXAMPLE_EMAILS: {
  label: string;
  sender: string;
  subject: string;
  body: string;
  note: string;
}[] = [
  {
    label: 'Bank spoof (phishing)',
    sender: 'Bank of America Security <security@bank-america-alerts.com>',
    subject: 'URGENT: Your account has been suspended',
    body: `Dear valued customer,

We have detected unusual activity on your account. Your account will be suspended within 24 hours unless you verify your identity immediately.

Please confirm your password and update your payment information by signing in below:

https://www.bank-america-alerts.com/verify-account/login?session=abc123

Failure to do so will result in permanent account closure.

Thank you,
Bank of America Security Team`,
    note: 'Spoofed sender, urgency, credential request, risky link — should score Phishing.',
  },
  {
    label: 'Safe newsletter',
    sender: 'newsletter@github.com',
    subject: 'Your weekly GitHub digest',
    body: `Hi there,

Here are the top repositories trending this week in your followed topics.

Explore them at https://github.com/trending

Happy coding,
The GitHub Team`,
    note: 'Trusted sender, no urgency, safe link — should score Safe.',
  },
  {
    label: 'IT helpdesk spoof',
    sender: 'IT Support <it-support@company-helpdesk-secure.net>',
    subject: 'Action required: validate your mailbox',
    body: `Dear user,

Your mailbox will be deactivated unless you reset your password and confirm your login credentials within 48 hours.

Validate your account here: http://mail-update.company-helpdesk-secure.net/confirm

IT Support Department`,
    note: 'Untrusted hyphenated domain, urgency, credential bait, HTTP link — Suspicious/Phishing.',
  },
];
