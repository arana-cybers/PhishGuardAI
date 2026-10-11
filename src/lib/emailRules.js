/**
 * Rule-based email classifier + unified entry point.
 * Requires phishingRules.js in the same folder.
 *
 * Usage:
 *   import { classify, classifyEmail } from "./emailRules.js";
 *
 *   classify("http://paypa1-login.xyz/verify");          // URL string -> URL rules
 *   classify({ from, subject, body, ... });              // object     -> email rules
 *   classify(rawEmlText);                                // raw email  -> parsed, then email rules
 *
 * Result: { type: "url" | "email", verdict: "Suspicious" | "Safe", score, reasons }
 */
import { classifyUrl, registeredDomain, PROTECTED_BRANDS, THRESHOLD } from "./phishingRules.js";

const EMAIL_THRESHOLD = THRESHOLD; // score >= this -> Suspicious

const FREE_MAIL = new Set([
  "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
  "proton.me", "protonmail.com", "mail.com", "gmx.com", "yandex.com", "mail.ru",
]);
const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "buzz", "icu", "info", "zip",
]);
const URGENCY = [
  "urgent", "immediately", "act now", "within 24 hours", "within 48 hours", "final notice",
  "last warning", "expires today", "limited time", "as soon as possible", "right away",
];
const THREATS = [
  "account suspended", "account will be closed", "account has been locked", "unauthorized login",
  "unusual activity", "suspicious activity", "legal action", "permanently disabled", "security alert",
];
const CREDENTIAL_ASKS = [
  "verify your account", "confirm your password", "enter your password", "update your payment",
  "confirm your identity", "provide your card", "social security", "bank details", "login to confirm",
  "verify your identity", "reset your password now",
];
const BAIT = [
  "you have won", "claim your prize", "lottery", "unclaimed funds", "inheritance", "refund is pending",
  "gift card", "wire transfer", "crypto giveaway", "congratulations",
];
const GENERIC_GREETINGS = [
  "dear customer", "dear user", "dear client", "dear account holder", "dear member", "dear sir/madam",
];
const DANGEROUS_EXT = ["exe", "scr", "bat", "cmd", "js", "jse", "vbs", "msi", "jar", "ps1", "apk", "lnk", "iso", "hta"];
const MACRO_EXT = ["docm", "xlsm", "pptm", "xlam"];
const ARCHIVE_EXT = ["zip", "rar", "7z", "gz", "tar"];

// ---------- helpers ----------

function parseAddress(str = "") {
  const m = String(str).match(/^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$/);
  const email = (m ? m[2] : str).trim().toLowerCase();
  const name = m ? m[1].trim() : "";
  const domain = email.includes("@") ? email.split("@").pop() : "";
  return { name, email, domain };
}

function stripHtml(html) {
  return html
    .replace(/<(style|script)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function extractLinks(body = "") {
  const links = [];
  const seen = new Set();
  const anchorRe = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = anchorRe.exec(body))) {
    const href = m[1].trim();
    if (!/^https?:\/\//i.test(href)) continue;
    links.push({ href, text: stripHtml(m[2]) });
    seen.add(href);
  }
  const plain = body.match(/https?:\/\/[^\s<>"')]+/gi) || [];
  for (const u of plain) if (!seen.has(u)) { links.push({ href: u, text: "" }); seen.add(u); }
  return links;
}

function hostOf(url) {
  try { return new URL(/^https?:\/\//i.test(url) ? url : "http://" + url).hostname.toLowerCase(); }
  catch { return ""; }
}

function authResult(headers, name) {
  const text = typeof headers === "string" ? headers : JSON.stringify(headers || {});
  const m = text.match(new RegExp(`${name}\\s*=\\s*(pass|fail|softfail|neutral|none|temperror|permerror)`, "i"));
  return m ? m[1].toLowerCase() : null;
}

function countHits(text, list) { return list.filter((p) => text.includes(p)); }

/** Minimal raw .eml parser (headers + body). */
export function parseRawEmail(raw) {
  const split = raw.split(/\r?\n\r?\n/);
  const headerBlock = split.shift() || "";
  const body = split.join("\n\n");
  const unfolded = headerBlock.replace(/\r?\n[ \t]+/g, " ");
  const get = (h) => (unfolded.match(new RegExp(`^${h}:\\s*(.*)$`, "im")) || [])[1] || "";
  const attachments = [...raw.matchAll(/filename\*?=\s*"?([^";\r\n]+)"?/gi)].map((m) => m[1]);
  return {
    from: get("From"), replyTo: get("Reply-To"), subject: get("Subject"),
    headers: unfolded, body, attachments,
  };
}

// ---------- email classifier ----------

export function classifyEmail(email, threshold = EMAIL_THRESHOLD) {
  const reasons = [];
  let score = 0;
  const add = (pts, why) => { score += pts; reasons.push(`+${pts} ${why}`); };

  const from = parseAddress(email.from);
  const replyTo = parseAddress(email.replyTo);
  const subject = String(email.subject || "");
  const rawBody = String(email.body || "");
  const text = (subject + " " + stripHtml(rawBody)).toLowerCase();
  const nameLower = from.name.toLowerCase();
  const fromReg = from.domain ? registeredDomain(from.domain) : "";

  // --- Sender ---
  if (!from.email) add(2, "missing sender address");

  for (const [brand, real] of Object.entries(PROTECTED_BRANDS)) {
    if ((nameLower.includes(brand) || from.domain.includes(brand)) && !real.includes(fromReg)) {
      add(3, `sender claims "${brand}" but sends from ${fromReg || "unknown"}`);
      break;
    }
  }
  if (FREE_MAIL.has(fromReg) && /support|security|billing|admin|service|helpdesk|team|bank|account/.test(nameLower)) {
    add(2, "official-sounding name sent from a free webmail address");
  }
  if (from.domain && SUSPICIOUS_TLDS.has(from.domain.split(".").pop())) add(2, `sender uses high-abuse TLD .${from.domain.split(".").pop()}`);
  if (from.domain.includes("xn--")) add(2, "sender domain uses punycode lookalike characters");
  if ((from.domain.match(/-/g) || []).length >= 2 || /\d{3,}/.test(from.domain)) add(1, "sender domain has many hyphens/digits");
  if (replyTo.domain && fromReg && registeredDomain(replyTo.domain) !== fromReg) {
    add(2, `Reply-To domain (${registeredDomain(replyTo.domain)}) differs from sender`);
  }
  // Display name that itself contains an email address of a different domain
  const nameEmail = from.name.match(/[\w.+-]+@([\w.-]+)/);
  if (nameEmail && registeredDomain(nameEmail[1].toLowerCase()) !== fromReg) add(2, "display name contains a different email address");

  // --- Authentication headers (only if headers were supplied) ---
  if (email.headers) {
    const spf = authResult(email.headers, "spf");
    const dkim = authResult(email.headers, "dkim");
    const dmarc = authResult(email.headers, "dmarc");
    const failed = [["SPF", spf], ["DKIM", dkim], ["DMARC", dmarc]].filter(([, v]) => v && v !== "pass" && v !== "neutral");
    if (failed.length) add(Math.min(4, 2 * failed.length), `authentication failed: ${failed.map(([k, v]) => `${k}=${v}`).join(", ")}`);
    else if (!spf && !dkim && !dmarc) add(1, "no SPF/DKIM/DMARC results in headers");
  }

  // --- Wording ---
  const urg = countHits(text, URGENCY);
  const thr = countHits(text, THREATS);
  const cred = countHits(text, CREDENTIAL_ASKS);
  const bait = countHits(text, BAIT);
  const greet = countHits(text, GENERIC_GREETINGS);
  if (urg.length >= 2) add(2, `urgency language: ${urg.slice(0, 3).join(", ")}`);
  else if (urg.length === 1) add(1, `urgency language: ${urg[0]}`);
  if (thr.length) add(2, `threatening language: ${thr[0]}`);
  if (cred.length) add(2, `asks for credentials/payment info: ${cred[0]}`);
  if (bait.length) add(2, `prize/refund bait: ${bait[0]}`);
  if (greet.length) add(1, "generic greeting");
  if (subject.length > 6 && subject === subject.toUpperCase() && /[A-Z]/.test(subject)) add(1, "subject is ALL CAPS");
  if ((subject.match(/!/g) || []).length >= 3) add(1, "excessive exclamation marks in subject");
  if (/display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden/i.test(rawBody)) add(1, "hidden text in HTML body");

  // --- Links ---
  const links = extractLinks(rawBody);
  let suspiciousLinks = 0;
  let mismatches = 0;
  for (const { href, text: linkText } of links) {
    const res = classifyUrl(href);
    if (res.verdict === "Suspicious") suspiciousLinks++;
    // visible text looks like a URL/domain but href goes elsewhere
    const shown = linkText.match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:\/\S*)?/i);
    if (shown) {
      const shownReg = registeredDomain(shown[1].toLowerCase());
      const realReg = registeredDomain(hostOf(href));
      if (shownReg && realReg && shownReg !== realReg) mismatches++;
    }
  }
  if (mismatches) add(3, `${mismatches} link(s) whose visible text shows a different domain than the real destination`);
  if (suspiciousLinks) add(3 + Math.min(2, suspiciousLinks - 1), `${suspiciousLinks} suspicious link(s) (per URL rules)`);
  if (links.length >= 10) add(1, `${links.length} links in one message`);

  // --- Attachments ---
  for (const file of email.attachments || []) {
    const parts = String(file).toLowerCase().split(".");
    const ext = parts.length > 1 ? parts.pop() : "";
    if (parts.length >= 2 && DANGEROUS_EXT.includes(ext)) add(4, `double-extension executable: ${file}`);
    else if (DANGEROUS_EXT.includes(ext)) add(3, `dangerous attachment type: ${file}`);
    else if (MACRO_EXT.includes(ext)) add(2, `macro-enabled document: ${file}`);
    else if (ARCHIVE_EXT.includes(ext)) add(1, `archive attachment: ${file}`);
  }

  return { type: "email", verdict: score >= threshold ? "Suspicious" : "Safe", score, reasons };
}

// ---------- unified entry point ----------

const looksLikeRawEmail = (s) => /^(from|to|subject|received|return-path|delivered-to|date):/im.test(s) && /\r?\n\r?\n/.test(s);

export function classify(input) {
  if (input && typeof input === "object") return classifyEmail(input);
  const s = String(input || "").trim();
  if (looksLikeRawEmail(s)) return classifyEmail(parseRawEmail(s));
  return { type: "url", ...classifyUrl(s) };
}
