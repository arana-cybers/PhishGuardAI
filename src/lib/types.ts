// Core domain types shared across the app.

export type Verdict = 'Safe' | 'Suspicious' | 'Phishing';
export type ScanType = 'url' | 'email';

export interface HeuristicCheck {
  id: string;
  label: string;
  passed: boolean;
  explanation: string;
  weight: number; // contribution to the risk score when failed
  triggered: boolean; // whether this heuristic added risk
}

/** Result of analyzing a single URL (used standalone and inside email scans). */
export interface UrlRiskResult {
  url: string;
  normalizedUrl: string;
  score: number; // 0-100
  verdict: Verdict;
  checks: HeuristicCheck[];
}

/** Result of analyzing a URL via the scanner view. */
export interface RiskResult {
  scanType: 'url';
  url: string;
  normalizedUrl: string;
  score: number; // 0-100
  verdict: Verdict;
  confidence: number; // 0-100
  checks: HeuristicCheck[];
  modelSource: 'local-heuristics'; // would become 'ai-model' once external API is wired
  scannedAt: string; // ISO timestamp
}

/** Result of analyzing an email for phishing. */
export interface EmailRiskResult {
  scanType: 'email';
  subject: string;
  sender: string;
  score: number; // 0-100
  verdict: Verdict;
  confidence: number; // 0-100
  checks: HeuristicCheck[]; // email-level heuristics
  extractedUrls: UrlRiskResult[]; // URLs found in the body, each analyzed
  modelSource: 'local-heuristics';
  scannedAt: string; // ISO timestamp
}

export type AnyRiskResult = RiskResult | EmailRiskResult;

/** A persisted scan record (URL or email). */
export interface ScanRecord {
  id: string;
  scanType: ScanType;
  // For URL scans: the scanned URL. For email scans: the sender address.
  label: string;
  // For URL scans: the normalized URL. For email scans: the subject line.
  sublabel: string;
  score: number;
  verdict: Verdict;
  confidence: number;
  checks: HeuristicCheck[];
  // Email scans only:
  extractedUrls?: UrlRiskResult[];
  scannedAt: string;
}
