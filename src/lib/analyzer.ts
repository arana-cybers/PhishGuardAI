import type { HeuristicCheck, RiskResult, UrlRiskResult, Verdict } from './types';
import { classifyUrl as classifyRuleUrl } from './phishingRules.js';
import { getLearnedUrlSignals } from './trainingSignals';

/**
 * PhishGuard AI — local heuristic phishing risk analyzer.
 *
 * `analyzePhishingRisk(url)` runs a set of URL-structure heuristics and returns
 * a weighted risk score (0-100), a verdict, a confidence value, and a per-check
 * breakdown. This is intentionally written as a single, swappable function so
 * that the local logic can later be replaced with a call to an external AI
 * model API without touching any of the UI code.
 *
 * ------------------------------------------------------------------
 * TODO (model swap): replace the local heuristic block below with a fetch()
 * to an external Python Flask/FastAPI model endpoint. Example:
 *
 *   const res = await fetch('https://my-model-api.com/predict', {
 *     method: 'POST',
 *     headers: { 'Content-Type': 'application/json' },
 *     body: JSON.stringify({ url }),
 *   });
 *   const data = await res.json();
 *   // expected shape: { label: 'Safe'|'Suspicious'|'Phishing', confidence: 0-100, features: {...} }
 *   return mapModelResponseToRiskResult(url, data);
 *
 * The UI only consumes the RiskResult shape, so swapping the implementation
 * here is the only change required.
 * ------------------------------------------------------------------
 */

const SUSPICIOUS_KEYWORDS = [
  'login',
  'log-in',
  'verify',
  'verification',
  'secure',
  'account',
  'update',
  'confirm',
  'banking',
  'signin',
  'sign-in',
  'password',
  'credential',
  'wallet',
  'recovery',
];

const BRAND_DOMAINS: Record<string, string[]> = {
  amazon: ['amazon.com'],
  apple: ['apple.com'],
  bankofamerica: ['bankofamerica.com'],
  facebook: ['facebook.com', 'fb.com'],
  github: ['github.com'],
  google: ['google.com'],
  linkedin: ['linkedin.com'],
  microsoft: ['microsoft.com', 'office.com', 'outlook.com'],
  netflix: ['netflix.com'],
  paypal: ['paypal.com'],
  usps: ['usps.com'],
  walmart: ['walmart.com'],
  chase: ['chase.com'],
  youtube: ['youtube.com', 'youtu.be'],
  instagram: ['instagram.com'],
  twitter: ['twitter.com', 'x.com'],
  whatsapp: ['whatsapp.com'],
  tiktok: ['tiktok.com'],
  dropbox: ['dropbox.com'],
  spotify: ['spotify.com'],
  zoom: ['zoom.us'],
};

// Common typo-squatting variants of brand names that don't contain the exact
// brand as a substring (e.g. "facebool" vs "facebook"). Each entry maps the
// lookalike to the brand it imitates.
const BRAND_TYPOSQUATS: { pattern: RegExp; brand: string }[] = [
  { pattern: /faceb[0o][0o]k/, brand: 'facebook' },
  { pattern: /faceb[0o][0o]l/, brand: 'facebook' },
  { pattern: /facebok/, brand: 'facebook' },
  { pattern: /faecebook/, brand: 'facebook' },
  { pattern: /g[0o][0o]gle/, brand: 'google' },
  { pattern: /gogle/, brand: 'google' },
  { pattern: /go0gle/, brand: 'google' },
  { pattern: /arnaz[0o]n/, brand: 'amazon' },
  { pattern: /amaz[0o]n/, brand: 'amazon' },
  { pattern: /netfl[1i]x/, brand: 'netflix' },
  { pattern: /netflix/, brand: 'netflix' },
  { pattern: /paypa[1l]/, brand: 'paypal' },
  { pattern: /paypaal/, brand: 'paypal' },
  { pattern: /y[0o]utube/, brand: 'youtube' },
  { pattern: /youtub/, brand: 'youtube' },
  { pattern: /instagr[arn]m/, brand: 'instagram' },
  { pattern: /t[1i]kt[0o]k/, brand: 'tiktok' },
  { pattern: /whatsa[p]p/, brand: 'whatsapp' },
  { pattern: /dr[0o]pb[0o]x/, brand: 'dropbox' },
  { pattern: /sp[0o]t[1i]fy/, brand: 'spotify' },
  { pattern: /micr[0o]s[0o]ft/, brand: 'microsoft' },
  { pattern: /microsft/, brand: 'microsoft' },
  { pattern: /1inked[1i]n/, brand: 'linkedin' },
  { pattern: /linkedln/, brand: 'linkedin' },
  { pattern: /bank[0o]famerica/, brand: 'bankofamerica' },
  { pattern: /cha[s]e/, brand: 'chase' },
];

const DANGEROUS_EXTENSIONS = new Set([
  'exe', 'scr', 'bat', 'cmd', 'com', 'msi', 'jar', 'ps1', 'apk', 'lnk', 'iso', 'hta',
  'js', 'jse', 'vbs', 'dll',
]);

const MACRO_EXTENSIONS = new Set([
  'docm', 'xlsm', 'pptm', 'xlam',
]);

const ARCHIVE_EXTENSIONS = new Set([
  'zip', 'rar', '7z', 'gz', 'tar',
]);

const SUSPICIOUS_TLDS = new Set([
  'click', 'download', 'fit', 'gdn', 'icu', 'live', 'loan', 'mobi', 'online',
  'pw', 'quest', 'review', 'support', 'top', 'vip', 'work', 'world', 'xyz',
  'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'info', 'rest', 'mov', 'zip',
]);

const CREDENTIAL_PATH_WORDS = [
  'login', 'log-in', 'signin', 'sign-in', 'verify', 'verification', 'password',
  'credential', 'authenticate', 'account', 'recovery', 'security-check',
];

const SUSPICIOUS_QUERY_WORDS = [
  'token', 'session', 'redirect', 'continue', 'return', 'auth', 'verify',
  'login', 'password',
];

const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  'goo.gl',
  't.co',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'rebrand.ly',
  'shorte.st',
  'cutt.ly',
  't.ly',
  'rb.gy',
  'soo.gd',
]);

// Well-known, trusted domains used to contextualize suspicious-keyword checks.
const TRUSTED_DOMAINS = new Set([
  'google.com',
  'www.google.com',
  'microsoft.com',
  'www.microsoft.com',
  'github.com',
  'www.github.com',
  'apple.com',
  'www.apple.com',
  'amazon.com',
  'www.amazon.com',
  'wikipedia.org',
  'www.wikipedia.org',
  'linkedin.com',
  'www.linkedin.com',
  'youtube.com',
  'www.youtube.com',
  'youtu.be',
  'instagram.com',
  'www.instagram.com',
  'twitter.com',
  'www.twitter.com',
  'x.com',
  'www.x.com',
  'whatsapp.com',
  'www.whatsapp.com',
  'tiktok.com',
  'www.tiktok.com',
  'dropbox.com',
  'www.dropbox.com',
  'spotify.com',
  'www.spotify.com',
  'zoom.us',
  'www.zoom.us',
  'facebook.com',
  'www.facebook.com',
  'fb.com',
  'www.fb.com',
  'netflix.com',
  'www.netflix.com',
  'paypal.com',
  'www.paypal.com',
  'usps.com',
  'www.usps.com',
  'walmart.com',
  'www.walmart.com',
  'chase.com',
  'www.chase.com',
  'bankofamerica.com',
  'www.bankofamerica.com',
  'office.com',
  'www.office.com',
  'outlook.com',
  'www.outlook.com',
  'icloud.com',
  'www.icloud.com',
]);

// IPv4 regex (covers dotted-quad; IPv6 handled separately by colon-bracket check).
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
const IPV6_BRACKET_RE = /^\[[0-9a-fA-F:]+\]$/;
const MAX_URL_LENGTH = 2048;

export function isValidUrl(raw: string): boolean {
  if (!raw || typeof raw !== 'string') return false;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > MAX_URL_LENGTH || hasControlCharacters(trimmed)) return false;
  try {
    // Accept URLs with or without an explicit protocol.
    const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    const u = new URL(candidate);
    // Must have a dot in the hostname (reject "localhost", "foo", etc.) OR be an IP.
    return !!u.hostname && (u.hostname.includes('.') || IPV4_RE.test(u.hostname));
  } catch {
    return false;
  }
}

function hasControlCharacters(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 32 || code === 127) return true;
  }
  return false;
}

function normalizeUrl(raw: string): string {
  const trimmed = raw.trim();
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function isIpAddress(host: string): boolean {
  return IPV4_RE.test(host) || IPV6_BRACKET_RE.test(host);
}

function isTrustedDomain(host: string, trustedDomains: Set<string>): boolean {
  return [...trustedDomains].some((domain) => host === domain || host.endsWith(`.${domain}`));
}

function findBrandImpersonation(host: string): { brand: string; expected: string[] } | null {
  const hostname = host.replace(/[^a-z0-9]/g, '');
  for (const [brand, expected] of Object.entries(BRAND_DOMAINS)) {
    if (hostname.includes(brand) && !expected.some((domain) => isTrustedDomain(host, new Set([domain])))) {
      return { brand, expected };
    }
  }
  // Check typo-squatting: a lookalike variant that doesn't contain the exact
  // brand as a substring (e.g. "facebool.com" imitating "facebook.com").
  for (const { pattern, brand } of BRAND_TYPOSQUATS) {
    if (pattern.test(hostname)) {
      const expected = BRAND_DOMAINS[brand] ?? [`${brand}.com`];
      if (!expected.some((domain) => isTrustedDomain(host, new Set([domain])))) {
        return { brand, expected };
      }
    }
  }
  return null;
}

export function classify(score: number): Verdict {
  if (score <= 30) return 'Safe';
  if (score <= 65) return 'Suspicious';
  return 'Phishing';
}

/**
 * Run the URL-structure heuristics and return a score + checks without the
 * top-level RiskResult envelope. Reused by both the URL scanner and the
 * email analyzer (for each URL extracted from an email body).
 */
export function analyzeUrlOnly(rawUrl: string): UrlRiskResult {
  const trimmed = rawUrl.trim();
  const normalized = normalizeUrl(trimmed);
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    return {
      url: trimmed,
      normalizedUrl: normalized,
      score: 50,
      verdict: 'Suspicious',
      checks: [
        {
          id: 'malformed-url',
          label: 'Valid URL structure',
          passed: false,
          explanation: 'The URL could not be parsed — malformed URLs are a strong phishing signal.',
          weight: 50,
          triggered: true,
        },
      ],
    };
  }
  const host = parsed.hostname.toLowerCase();
  const fullUrl = normalized.toLowerCase();
  const supportedProtocol = parsed.protocol === 'http:' || parsed.protocol === 'https:';
  if (!supportedProtocol || !host || fullUrl.length > MAX_URL_LENGTH) {
    return {
      url: trimmed,
      normalizedUrl: normalized,
      score: 100,
      verdict: 'Phishing',
      checks: [{
        id: 'unsafe-url-structure',
        label: 'Safe URL structure',
        passed: false,
        explanation: 'The URL uses an unsupported protocol, has no hostname, or exceeds the safe length limit.',
        weight: 100,
        triggered: true,
      }],
    };
  }

  const checks: HeuristicCheck[] = [];

  // --- Heuristic 1: URL length ---
  {
    const long = fullUrl.length > 75;
    const veryLong = fullUrl.length > 120;
    const weight = veryLong ? 18 : long ? 12 : 0;
    checks.push({
      id: 'url-length',
      label: 'URL length',
      passed: !long,
      explanation: long
        ? veryLong
          ? 'URL is extremely long — phishing links often hide behind very long strings.'
          : 'URL is longer than typical — can be used to hide the real destination.'
        : 'URL length is within a normal range.',
      weight,
      triggered: long,
    });
  }

  // --- Heuristic 2: "@" symbol in URL ---
  {
    const hasAt = fullUrl.includes('@');
    checks.push({
      id: 'at-symbol',
      label: '@ symbol in URL',
      passed: !hasAt,
      explanation: hasAt
        ? 'The "@" symbol can force the browser to ignore everything before it — a classic obfuscation trick.'
        : 'No "@" symbol present in the URL.',
      weight: hasAt ? 14 : 0,
      triggered: hasAt,
    });
  }

  // --- Heuristic 3: IP address instead of domain ---
  {
    const ip = isIpAddress(host);
    checks.push({
      id: 'ip-host',
      label: 'IP address as host',
      passed: !ip,
      explanation: ip
        ? 'URL uses an IP address instead of a domain name — common phishing tactic.'
        : 'URL uses a registered domain name, not a raw IP address.',
      weight: ip ? 20 : 0,
      triggered: ip,
    });
  }

  // --- Heuristic 4: subdomain / dot count ---
  {
    const dotCount = host.split('.').length - 1;
    const manyDots = dotCount >= 4;
    checks.push({
      id: 'subdomains',
      label: 'Subdomain depth',
      passed: !manyDots,
      explanation: manyDots
        ? `Domain has ${dotCount} dots — excessive subdomains can mimic a trusted brand (e.g. login.paypal.com.attacker.net).`
        : `Domain has a reasonable subdomain structure (${dotCount} dot${dotCount === 1 ? '' : 's'}).`,
      weight: manyDots ? 12 : 0,
      triggered: manyDots,
    });
  }

  // --- Heuristic 5: hyphen in domain ---
  {
    const hyphen = host.includes('-');
    checks.push({
      id: 'hyphen',
      label: 'Hyphen in domain',
      passed: !hyphen,
      explanation: hyphen
        ? 'Domain contains a hyphen ("-") — often used to impersonate brands (e.g. "pay-pal.com").'
        : 'No hyphen in the domain name.',
      weight: hyphen ? 8 : 0,
      triggered: hyphen,
    });
  }

  // --- Heuristic 6: protocol (http vs https) ---
  {
    const insecure = parsed.protocol === 'http:';
    checks.push({
      id: 'protocol',
      label: 'Protocol (HTTPS)',
      passed: !insecure,
      explanation: insecure
        ? 'URL uses insecure HTTP instead of HTTPS — legitimate sites almost always encrypt traffic.'
        : 'URL uses HTTPS — connection is encrypted.',
      weight: insecure ? 10 : 0,
      triggered: insecure,
    });
  }

  // --- Heuristic 7: suspicious keywords + unusual domain ---
  {
    const keywordHits = SUSPICIOUS_KEYWORDS.filter((k) => fullUrl.includes(k));
    const isTrusted = isTrustedDomain(host, TRUSTED_DOMAINS);
    const triggered = keywordHits.length > 0 && !isTrusted;
    checks.push({
      id: 'suspicious-keywords',
      label: 'Suspicious keywords',
      passed: !triggered,
      explanation: triggered
        ? `URL contains sensitive keyword(s) (${keywordHits.slice(0, 3).join(', ')}) on a non-trusted domain — phishing pages use these to bait users.`
        : keywordHits.length > 0
          ? `Contains sensitive keyword(s), but on a well-known trusted domain.`
          : 'No high-risk sensitive keywords detected.',
      weight: triggered ? Math.min(22, 12 + (keywordHits.length - 1) * 4) : 0,
      triggered,
    });
  }

  // --- Heuristic 8: brand impersonation ---
  {
    const impersonation = findBrandImpersonation(host);
    checks.push({
      id: 'brand-impersonation',
      label: 'Brand impersonation',
      passed: !impersonation,
      explanation: impersonation
        ? `Hostname contains "${impersonation.brand}" but is not an official ${impersonation.brand} domain — a strong phishing signal.`
        : 'No known brand impersonation detected in the hostname.',
      weight: impersonation ? 28 : 0,
      triggered: !!impersonation,
    });
  }

  // --- Heuristic 9: credential or payment path ---
  {
    const pathAndQuery = `${parsed.pathname} ${parsed.search}`.toLowerCase();
    const pathHits = CREDENTIAL_PATH_WORDS.filter((word) => pathAndQuery.includes(word));
    const isTrusted = isTrustedDomain(host, TRUSTED_DOMAINS);
    const triggered = pathHits.length > 0 && !isTrusted;
    checks.push({
      id: 'credential-path',
      label: 'Credential-focused path',
      passed: !triggered,
      explanation: triggered
        ? `Path asks users to visit a credential or account flow (${pathHits.slice(0, 3).join(', ')}) on a non-trusted domain.`
        : 'No suspicious credential-focused path detected.',
      weight: triggered ? Math.min(18, 10 + (pathHits.length - 1) * 4) : 0,
      triggered,
    });
  }

  // --- Heuristic 10: URL obfuscation ---
  {
    const encoded = /%[0-9a-f]{2}/i.test(fullUrl);
    const punycode = host.includes('xn--');
    const mixedNumeric = /[a-z]\d|\d[a-z]/i.test(host);
    const triggered = encoded || punycode || mixedNumeric;
    checks.push({
      id: 'obfuscation',
      label: 'URL obfuscation',
      passed: !triggered,
      explanation: triggered
        ? punycode
          ? 'Hostname uses punycode, which can visually imitate another domain.'
          : encoded
            ? 'URL contains percent-encoded characters that can hide its real destination.'
            : 'Hostname mixes letters and digits in a way commonly used to imitate a brand.'
        : 'No common URL obfuscation pattern detected.',
      weight: triggered ? 16 : 0,
      triggered,
    });
  }

  // --- Heuristic 11: suspicious query parameters ---
  {
    const queryHits = SUSPICIOUS_QUERY_WORDS.filter((word) => parsed.search.toLowerCase().includes(word));
    const triggered = queryHits.length >= 2 && !isTrustedDomain(host, TRUSTED_DOMAINS);
    checks.push({
      id: 'suspicious-query',
      label: 'Suspicious query parameters',
      passed: !triggered,
      explanation: triggered
        ? `Query string contains multiple authentication or redirect parameters (${queryHits.slice(0, 3).join(', ')}).`
        : 'No suspicious combination of authentication or redirect parameters detected.',
      weight: triggered ? 12 : 0,
      triggered,
    });
  }

  // --- Heuristic 12: URL shortener ---
  {
    const isShortener = URL_SHORTENERS.has(host);
    checks.push({
      id: 'shortener',
      label: 'URL shortener',
      passed: !isShortener,
      explanation: isShortener
        ? `URL uses a shortener (${host}) — the real destination is hidden, a common phishing vector.`
        : 'URL is not a known link shortener.',
      weight: isShortener ? 22 : 0,
      triggered: isShortener,
    });
  }

  // --- Heuristic 13: suspicious top-level domain ---
  {
    const tld = host.split('.').pop() ?? '';
    const suspiciousTld = SUSPICIOUS_TLDS.has(tld);
    checks.push({
      id: 'suspicious-tld',
      label: 'Top-level domain reputation',
      passed: !suspiciousTld,
      explanation: suspiciousTld
        ? `The .${tld} top-level domain is frequently abused for short-lived phishing sites.`
        : `The .${tld || 'unknown'} top-level domain is not on the high-risk list.`,
      weight: suspiciousTld ? 12 : 0,
      triggered: suspiciousTld,
    });
  }

  // --- Heuristic 14: dangerous file extension in path ---
  {
    const pathLower = parsed.pathname.toLowerCase();
    const segments = pathLower.split('/').filter(Boolean);
    const lastSegment = segments[segments.length - 1] ?? '';
    const ext = lastSegment.includes('.') ? lastSegment.split('.').pop() ?? '' : '';
    const isDangerous = DANGEROUS_EXTENSIONS.has(ext);
    const isMacro = MACRO_EXTENSIONS.has(ext);
    const isArchive = ARCHIVE_EXTENSIONS.has(ext);
    const triggered = isDangerous || isMacro || isArchive;
    const label = isDangerous ? 'dangerous executable' : isMacro ? 'macro-enabled document' : isArchive ? 'archive file' : '';
    checks.push({
      id: 'dangerous-extension',
      label: 'Dangerous file extension',
      passed: !triggered,
      explanation: triggered
        ? `URL path ends in .${ext} (${label}) — frequently used to deliver malware or phishing payloads.`
        : 'No dangerous file extension detected in the URL path.',
      weight: isDangerous ? 20 : isMacro ? 12 : isArchive ? 8 : 0,
      triggered,
    });
  }

  // --- Heuristic 15: independent rule-based classifier ---
  {
    const ruleResult = classifyRuleUrl(trimmed);
    const triggered = ruleResult.verdict === 'Suspicious';
    checks.push({
      id: 'rule-classifier',
      label: 'Rule-based phishing classifier',
      passed: !triggered,
      explanation: triggered
        ? `Independent rule set flagged this URL (score ${ruleResult.score}): ${ruleResult.reasons.slice(0, 4).join('; ')}.`
        : 'Independent rule set found no high-risk combination of URL signals.',
      weight: triggered ? Math.min(35, 12 + ruleResult.score * 2) : 0,
      triggered,
    });
  }

  // --- Heuristic 16: signals learned from labeled examples ---
  {
    const learned = getLearnedUrlSignals(trimmed);
    const triggered = learned.hits.length > 0;
    checks.push({
      id: 'dataset-signals',
      label: 'Labeled-example signals',
      passed: !triggered,
      explanation: triggered
        ? `Matches phishing patterns learned from the supplied URL examples: ${learned.hits.slice(0, 5).join(', ')}.`
        : 'No high-confidence pattern from the supplied labeled URL examples matched.',
      weight: triggered ? Math.min(24, 8 + learned.score) : 0,
      triggered,
    });
  }

  // --- Heuristic 17: domain age (placeholder) ---
  {
    checks.push({
      id: 'domain-age',
      label: 'Domain age',
      passed: true,
      explanation:
        'Domain age check is a placeholder — a backend WHOIS/RDAP lookup is required to flag newly registered domains.',
      weight: 0,
      triggered: false,
    });
  }

  // --- Weighted risk score ---
  const totalWeight = checks.reduce((sum, c) => sum + c.weight, 0);
  const triggeredCount = checks.filter((check) => check.triggered).length;
  // Multiple independent phishing signals should not remain Safe merely because
  // the URL is short or uses HTTPS. Compound signals are more meaningful than
  // any single heuristic, so apply a conservative floor for combinations.
  // A single high-weight signal (>= 20) should also not stay Safe.
  const maxSingleWeight = Math.max(...checks.map((c) => c.weight));
  const compoundFloor = triggeredCount >= 3 ? 48 : triggeredCount >= 2 ? 35 : maxSingleWeight >= 20 ? 32 : 0;
  const score = Math.min(100, Math.max(compoundFloor, Math.round(totalWeight)));
  const verdict = classify(score);

  return {
    url: rawUrl.trim(),
    normalizedUrl: normalized,
    score,
    verdict,
    checks,
  };
}

/**
 * Analyze a URL for phishing risk (full scanner result). Currently runs local
 * heuristics; see the TODO block at the top of this file for how to swap in an
 * external AI model.
 */
export function analyzePhishingRisk(rawUrl: string): RiskResult {
  const u = analyzeUrlOnly(rawUrl);
  const confidence = computeConfidence(u.score, u.verdict);
  return {
    scanType: 'url',
    url: u.url,
    normalizedUrl: u.normalizedUrl,
    score: u.score,
    verdict: u.verdict,
    confidence,
    checks: u.checks,
    modelSource: 'local-heuristics',
    scannedAt: new Date().toISOString(),
  };
}

function computeConfidence(score: number, verdict: Verdict): number {
  const bands: Record<Verdict, [number, number]> = {
    Safe: [0, 30],
    Suspicious: [31, 65],
    Phishing: [66, 100],
  };
  const [low, high] = bands[verdict];
  const center = (low + high) / 2;
  const halfWidth = (high - low) / 2;
  // Distance from center, normalized to 0..1 (1 = at center, 0 = at band edge).
  const distance = Math.abs(score - center);
  const edgeRatio = halfWidth === 0 ? 1 : 1 - distance / halfWidth;
  // Map to a 62%-99% confidence range (heuristics are never 100% certain).
  const conf = 62 + Math.round(edgeRatio * 37);
  return Math.max(62, Math.min(99, conf));
}
