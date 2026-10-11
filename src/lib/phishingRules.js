/**
 * Rule-based URL classifier: returns "Suspicious" or "Safe".
 * No dependencies; works in the browser (Vite/React) and Node.
 *
 * Usage:
 *   import { classifyUrl } from "./phishingRules.js";
 *   const r = classifyUrl("http://secure-login.verify-acct.xyz/update?token=abc");
 *   // { verdict: "Suspicious", score: 9, reasons: [...] }
 */

export const THRESHOLD = 4; // score >= THRESHOLD -> Suspicious. Lower = stricter.

const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "buzz", "icu",
  "info", "live", "rest", "zip", "mov",
]);

const KEYWORDS = [
  "login", "signin", "verify", "secure", "account", "update", "confirm",
  "billing", "password", "support", "webscr", "authenticate", "recover",
  "wallet", "suspend", "unlock",
];

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy",
]);

// Add brands you want to protect. Flags them appearing OUTSIDE their real domain.
export const PROTECTED_BRANDS = {
  paypal: ["paypal.com"],
  google: ["google.com"],
  microsoft: ["microsoft.com", "live.com"],
  amazon: ["amazon.com"],
  apple: ["apple.com", "icloud.com"],
  facebook: ["facebook.com"],
  netflix: ["netflix.com"],
  youtube: ["youtube.com", "youtu.be"],
  instagram: ["instagram.com"],
  twitter: ["twitter.com", "x.com"],
  whatsapp: ["whatsapp.com"],
  tiktok: ["tiktok.com"],
  dropbox: ["dropbox.com"],
  spotify: ["spotify.com"],
  zoom: ["zoom.us"],
  github: ["github.com"],
  linkedin: ["linkedin.com"],
  usps: ["usps.com"],
  bankofamerica: ["bankofamerica.com"],
  chase: ["chase.com"],
};

// Typosquatting patterns: lookalike brand names that don't contain the exact
// brand as a substring (e.g. "facebool" vs "facebook").
const BRAND_TYPOSQUATS = [
  { pattern: /faceb[0o][0o]k/, brand: "facebook" },
  { pattern: /faceb[0o][0o]l/, brand: "facebook" },
  { pattern: /facebok/, brand: "facebook" },
  { pattern: /g[0o][0o]gle/, brand: "google" },
  { pattern: /gogle/, brand: "google" },
  { pattern: /amaz[0o]n/, brand: "amazon" },
  { pattern: /netfl[1i]x/, brand: "netflix" },
  { pattern: /paypa[1l]/, brand: "paypal" },
  { pattern: /y[0o]utube/, brand: "youtube" },
  { pattern: /instagr[arn]m/, brand: "instagram" },
  { pattern: /micr[0o]s[0o]ft/, brand: "microsoft" },
];

const MULTI_PART_TLDS = new Set(["co.uk", "org.uk", "com.au", "co.in", "co.jp", "com.br"]);

export function registeredDomain(host) {
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const lastTwo = parts.slice(-2).join(".");
  return MULTI_PART_TLDS.has(lastTwo) ? parts.slice(-3).join(".") : lastTwo;
}

function entropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  return -Object.values(freq).reduce((sum, n) => {
    const p = n / s.length;
    return sum + p * Math.log2(p);
  }, 0);
}

export function classifyUrl(input, threshold = THRESHOLD) {
  const reasons = [];
  let score = 0;
  const add = (pts, why) => { score += pts; reasons.push(`+${pts} ${why}`); };

  let raw = String(input || "").trim();
  if (!raw) return { verdict: "Safe", score: 0, reasons: ["empty input"] };
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = "http://" + raw;

  let url;
  try {
    url = new URL(raw);
  } catch {
    return { verdict: "Suspicious", score: 5, reasons: ["+5 malformed URL"] };
  }

  const host = url.hostname.toLowerCase();
  const labels = host.split(".");
  const tld = labels[labels.length - 1];
  const regDomain = registeredDomain(host);
  const subdomains = labels.slice(0, labels.length - regDomain.split(".").length);
  const full = raw.toLowerCase();
  const pathAndQuery = (url.pathname + url.search).toLowerCase();

  // 1. Host is a raw IP address
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) {
    add(3, "IP address used instead of a domain");
  }
  // 2. '@' in the URL (hides the real destination)
  if (url.username || raw.slice(0, raw.indexOf(url.hostname)).includes("@")) {
    add(3, "'@' credentials trick in URL");
  }
  // 3. Not HTTPS
  if (url.protocol === "http:") add(1, "no HTTPS");
  // 4. Suspicious TLD
  if (SUSPICIOUS_TLDS.has(tld)) add(2, `high-abuse TLD .${tld}`);
  // 5. Too many subdomains
  if (subdomains.length >= 3) add(2, `${subdomains.length} subdomain levels`);
  // 6. Long URL
  if (raw.length > 100) add(2, `very long URL (${raw.length} chars)`);
  else if (raw.length > 75) add(1, `long URL (${raw.length} chars)`);
  // 7. Hyphen-stuffed hostname
  const hyphens = (host.match(/-/g) || []).length;
  if (hyphens >= 2) add(1, `${hyphens} hyphens in hostname`);
  // 8. Sensitive keywords
  const kwHits = KEYWORDS.filter((k) => full.includes(k));
  if (kwHits.length >= 2) add(2, `keywords: ${kwHits.slice(0, 4).join(", ")}`);
  else if (kwHits.length === 1) add(1, `keyword: ${kwHits[0]}`);
  // 9. Non-standard port
  if (url.port && !["80", "443"].includes(url.port)) add(2, `non-standard port ${url.port}`);
  // 10. Punycode (possible homograph attack)
  if (labels.some((l) => l.startsWith("xn--"))) add(2, "punycode / lookalike characters");
  // 11. Digits mixed into word-like labels (g00gle style)
  if (labels.some((l) => /[a-z]/.test(l) && /\d/.test(l) && /[a-z]\d[a-z]|\d[a-z]\d/.test(l) && l.length > 5)) {
    add(1, "digits mixed into hostname letters");
  }
  // 12. Random-looking domain (high entropy, long)
  const mainLabel = regDomain.split(".")[0];
  if (mainLabel.length >= 12 && entropy(mainLabel) > 3.5) add(2, "random-looking domain name");
  // 13. URL shortener
  if (SHORTENERS.has(regDomain)) add(1, "URL shortener hides destination");
  // 14. Credential-style query params
  if (/[?&](pass(word)?|pwd|token|session|otp|ssn|card)=/.test(pathAndQuery)) {
    add(1, "sensitive-looking query parameter");
  }
  // 15. Executable/script file in path
  if (/\.(php|asp|aspx|exe|scr|zip|apk|bat|cmd|msi|jar|ps1|lnk|iso|hta|vbs|js)(\?|$)/.test(url.pathname.toLowerCase())) {
    add(2, "script or executable file in path");
  }
  // 16. Brand name appears but domain isn't the brand's real one
  for (const [brand, realDomains] of Object.entries(PROTECTED_BRANDS)) {
    const mentioned = host.includes(brand) || pathAndQuery.includes(brand);
    if (mentioned && !realDomains.includes(regDomain)) {
      add(3, `mentions "${brand}" but domain is ${regDomain}`);
      break;
    }
  }
  // 16b. Typosquatting: lookalike brand name in hostname
  const hostnameStripped = host.replace(/[^a-z0-9]/g, "");
  for (const { pattern, brand } of BRAND_TYPOSQUATS) {
    if (pattern.test(hostnameStripped)) {
      const realDomains = PROTECTED_BRANDS[brand];
      if (!realDomains.includes(regDomain)) {
        add(3, `typosquatting "${brand}" lookalike in domain ${regDomain}`);
        break;
      }
    }
  }
  // 17. Embedded redirect (second http:// in the URL)
  if ((full.match(/https?:\/\//g) || []).length > 1) add(2, "embedded redirect URL");

  return {
    verdict: score >= threshold ? "Suspicious" : "Safe",
    score,
    reasons,
  };
}
