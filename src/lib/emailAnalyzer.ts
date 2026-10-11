import type {
  EmailRiskResult,
  HeuristicCheck,
  UrlRiskResult,
  Verdict,
} from './types';
import { analyzeUrlOnly, classify } from './analyzer';
import { classifyEmail as classifyRuleEmail } from './emailRules.js';
import { getLearnedEmailSignals } from './trainingSignals';

/**
 * PhishGuard AI — email phishing analyzer.
 *
 * `analyzeEmailPhishingRisk(input)` runs email-specific heuristics on the
 * sender address, subject, and body, then extracts every URL from the body
 * and runs the existing URL heuristics on each one. The two signal groups are
 * combined into a single 0-100 risk score and verdict.
 *
 * ------------------------------------------------------------------
 * TODO (model swap): replace the local heuristic block below with a fetch()
 * to an external Python Flask/FastAPI model endpoint. Example:
 *
 *   const res = await fetch('https://my-model-api.com/predict-email', {
 *     method: 'POST',
 *     headers: { 'Content-Type': 'application/json' },
 *     body: JSON.stringify({ sender, subject, body }),
 *   });
 *   const data = await res.json();
 *   // expected: { label, confidence, features }
 *   return mapModelResponseToEmailResult(data);
 *
 * ------------------------------------------------------------------
 */

export interface EmailInput {
  sender: string; // e.g. "IT Support <it-support@weird-domain.com>"
  subject: string;
  body: string;
}

const MAX_SENDER_LENGTH = 320;
const MAX_SUBJECT_LENGTH = 998;
const MAX_BODY_LENGTH = 100_000;

function boundEmailInput(input: EmailInput): EmailInput {
  return {
    sender: input.sender.trim().slice(0, MAX_SENDER_LENGTH),
    subject: input.subject.trim().slice(0, MAX_SUBJECT_LENGTH),
    body: input.body.slice(0, MAX_BODY_LENGTH),
  };
}

function countPhraseHits(text: string, phrases: string[]): string[] {
  return phrases.filter((phrase) => text.includes(phrase));
}

// Urgency / manipulation phrases common in phishing emails.
const URGENCY_PHRASES = [
  'urgent',
  'immediate',
  'immediately',
  'asap',
  'account will be suspended',
  'account will be closed',
  'verify your account',
  'confirm your identity',
  'action required',
  'final notice',
  'last warning',
  'within 24 hours',
  'within 48 hours',
  'failure to',
  'your account has been',
  'unusual activity',
  'suspended',
  'deactivated',
  'terminate',
];

// Credential / payment bait phrases.
const CREDENTIAL_PHRASES = [
  'password',
  'login',
  'sign in',
  'verify',
  'confirm',
  'update your',
  'credit card',
  'bank account',
  'payment',
  'invoice',
  'wire',
  'social security',
  'ssn',
  'pin',
  'otp',
  'two-factor',
  'reset your password',
  'validate',
];

// Generic / impersonal greetings.
const GENERIC_GREETINGS = [
  'dear user',
  'dear customer',
  'dear valued',
  'dear member',
  'dear account holder',
  'dear sir',
  'dear madam',
  'hi user',
  'hello user',
  'to whom it may concern',
];

// Trusted sender domains used to contextualize mismatch checks.
const TRUSTED_SENDER_DOMAINS = new Set([
  'google.com',
  'microsoft.com',
  'github.com',
  'apple.com',
  'amazon.com',
  'paypal.com',
  'linkedin.com',
  'facebook.com',
  'wikipedia.org',
  'yourbank.com',
]);

const URL_REGEX = /https?:\/\/[^\s<>"')\]]+|www\.[^\s<>"')\]]+/gi;

export function extractEmailParts(raw: string): EmailInput {
  // Best-effort parse of a pasted raw email into structured fields.
  let sender = '';
  let subject = '';
  let body = raw;

  const fromMatch = raw.match(/^From:\s*(.+)$/im);
  if (fromMatch) sender = fromMatch[1].trim();

  const subjectMatch = raw.match(/^Subject:\s*(.+)$/im);
  if (subjectMatch) subject = subjectMatch[1].trim();

  // Body = everything after the first blank line that follows headers, else whole text.
  const normalizedRaw = raw.replace(/\r\n/g, '\n');
  const headerEnd = normalizedRaw.indexOf('\n\n');
  if (headerEnd !== -1) body = normalizedRaw.slice(headerEnd + 2).trim();

  return { sender, subject, body };
}

function parseEmailAddress(raw: string): { display: string; address: string; domain: string } {
  const m = raw.match(/<([^>]+)>/);
  const address = (m ? m[1] : raw).trim().toLowerCase();
  const display = m ? raw.slice(0, m.index).trim() : '';
  const at = address.lastIndexOf('@');
  const domain = at > 0 ? address.slice(at + 1).replace(/[>\s].*$/, '') : '';
  return { display, address, domain };
}

function domainMatches(domain: string, trustedDomain: string): boolean {
  return domain === trustedDomain || domain.endsWith(`.${trustedDomain}`);
}

function extractUrls(body: string): string[] {
  const matches = body.match(URL_REGEX) ?? [];
  // Dedupe and normalize bare www. links. Limit work on untrusted pasted input.
  const seen = new Set<string>();
  const out: string[] = [];
  for (let u of matches.slice(0, 100)) {
    u = u.replace(/[.,;:!?]+$/, '');
    if (!/^https?:\/\//i.test(u)) u = `https://${u}`;
    if (!seen.has(u)) {
      seen.add(u);
      out.push(u);
    }
  }
  return out;
}

export function analyzeEmailPhishingRisk(input: EmailInput): EmailRiskResult {
  const bounded = boundEmailInput(input);
  const { sender, subject, body } = bounded;
  const { display, address, domain } = parseEmailAddress(sender);
  const bodyLower = body.toLowerCase();
  const subjectLower = subject.toLowerCase();

  const checks: HeuristicCheck[] = [];

  // --- Email Heuristic 1: display-name / domain mismatch ---
  {
    let triggered = false;
    let explanation = 'Sender display name and email domain are consistent.';
    if (display && domain) {
      // Does the display name mention a trusted brand the domain doesn't own?
      const displayBrand = display.toLowerCase().replace(/[^a-z0-9]/g, '');
      const brandMention = [...TRUSTED_SENDER_DOMAINS].find((d) =>
        displayBrand.includes(d.split('.')[0].replace(/[^a-z0-9]/g, '')),
      );
      if (brandMention && !domainMatches(domain, brandMention)) {
        triggered = true;
        explanation = `Display name "${display}" impersonates a brand but the sender domain is "${domain}" — a classic spoofing tactic.`;
      }
    }
    checks.push({
      id: 'sender-mismatch',
      label: 'Sender identity',
      passed: !triggered,
      explanation,
      weight: triggered ? 22 : 0,
      triggered,
    });
  }

  // --- Email Heuristic 2: untrusted / suspicious sender domain ---
  {
    const validAddress = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(address);
    const noDomain = !validAddress || !domain || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(domain);
    const isTrusted = [...TRUSTED_SENDER_DOMAINS].some((trusted) => domainMatches(domain, trusted));
    const hasHyphen = domain.includes('-');
    const manyDots = domain.split('.').length - 1 >= 4;
    const punycode = domain.includes('xn--');
    const triggered = noDomain || (!isTrusted && (hasHyphen || manyDots || punycode));
    checks.push({
      id: 'sender-domain',
      label: 'Sender domain reputation',
      passed: !triggered,
      explanation: noDomain
        ? 'No valid sender domain could be parsed from the email address.'
        : isTrusted
          ? `Sender domain "${domain}" is a known/trusted domain.`
          : triggered
            ? `Sender domain "${domain}" is untrusted${hasHyphen ? ' and contains a hyphen' : ''}${manyDots ? ' with excessive subdomains' : ''}${punycode ? ' and uses punycode' : ''} — often used in phishing.`
            : `Sender domain "${domain}" is not on the trusted list but looks structurally normal.`,
      weight: triggered ? 16 : 0,
      triggered,
    });
  }

  // --- Email Heuristic 3: urgency / pressure language ---
  {
    const hits = countPhraseHits(`${subjectLower} ${bodyLower}`, URGENCY_PHRASES);
    checks.push({
      id: 'urgency',
      label: 'Urgency / pressure language',
      passed: hits.length === 0,
      explanation: hits.length > 0
        ? `Message uses urgency phrasing (${hits.slice(0, 3).join(', ')}) — phishing emails pressure victims to act before thinking.`
        : 'No high-urgency or pressure language detected.',
      weight: hits.length > 0 ? Math.min(18, 8 + hits.length * 3) : 0,
      triggered: hits.length > 0,
    });
  }

  // --- Email Heuristic 4: credential / payment requests ---
  {
    const hits = countPhraseHits(`${subjectLower} ${bodyLower}`, CREDENTIAL_PHRASES);
    checks.push({
      id: 'credential-request',
      label: 'Credential / payment request',
      passed: hits.length === 0,
      explanation: hits.length > 0
        ? `Message references sensitive information (${hits.slice(0, 3).join(', ')}) — phishing emails often bait for credentials or payment.`
        : 'No direct credential or payment request detected.',
      weight: hits.length > 0 ? Math.min(20, 10 + hits.length * 3) : 0,
      triggered: hits.length > 0,
    });
  }

  // --- Email Heuristic 5: generic greeting ---
  {
    const hit = GENERIC_GREETINGS.find((g) => bodyLower.includes(g));
    checks.push({
      id: 'generic-greeting',
      label: 'Generic greeting',
      passed: !hit,
      explanation: hit
        ? `Uses an impersonal greeting ("${hit}") — legitimate senders usually address you by name.`
        : 'No generic/impersonal greeting detected.',
      weight: hit ? 6 : 0,
      triggered: !!hit,
    });
  }

  // --- Email Heuristic 6: subject-line alarm keywords ---
  {
    const alarmWords = ['suspended', 'locked', 'verify', 'update', 'alert', 'security', 'unauthorized', 'breach'];
    const hit = alarmWords.find((w) => subjectLower.includes(w));
    checks.push({
      id: 'subject-alarm',
      label: 'Subject alarm keywords',
      passed: !hit,
      explanation: hit
        ? `Subject contains an alarm word ("${hit}") designed to provoke immediate action.`
        : 'Subject line does not contain common alarm keywords.',
      weight: hit ? 8 : 0,
      triggered: !!hit,
    });
  }

  // --- Email Heuristic 7: links in body ---
  const extractedUrlStrings = extractUrls(body);
  const extractedUrls: UrlRiskResult[] = extractedUrlStrings.map((u) => analyzeUrlOnly(u));
  {
    const hasLinks = extractedUrls.length > 0;
    const hasRiskyLink = extractedUrls.some((u) => u.verdict !== 'Safe');
    checks.push({
      id: 'body-links',
      label: 'Links in body',
      passed: !hasRiskyLink,
      explanation: !hasLinks
        ? 'No links found in the email body.'
        : hasRiskyLink
          ? `${extractedUrls.length} link(s) found, and at least one is Suspicious or Phishing — see the URL breakdown below.`
          : `${extractedUrls.length} link(s) found, all scoring Safe on URL heuristics.`,
      weight: hasRiskyLink ? 18 : 0,
      triggered: hasRiskyLink,
    });
  }

  // --- Email Heuristic 8: mismatch between visible link text and link URL ---
  {
    // Look for <a href="...">text</a> style or [text](url) markdown style mismatches.
    const htmlLinkRe = /<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/gi;
    const mdLinkRe = /\[([^\]]+)\]\(([^)]+)\)/gi;
    let mismatch = false;
    let example = '';
    let m: RegExpExecArray | null;
    while ((m = htmlLinkRe.exec(body)) !== null) {
      const href = m[1].toLowerCase();
      const text = m[2].toLowerCase();
      if (text.includes('http') && !href.startsWith(text)) continue;
      if (!href.includes(text) && text.length > 3) {
        mismatch = true;
        example = `"${m[2]}" → ${m[1]}`;
        break;
      }
    }
    if (!mismatch) {
      while ((m = mdLinkRe.exec(body)) !== null) {
        const href = m[2].toLowerCase();
        const text = m[1].toLowerCase();
        if (text.includes('http') && !href.startsWith(text)) continue;
        if (!href.includes(text) && text.length > 3) {
          mismatch = true;
          example = `"${m[1]}" → ${m[2]}`;
          break;
        }
      }
    }
    checks.push({
      id: 'link-mismatch',
      label: 'Link text vs. URL mismatch',
      passed: !mismatch,
      explanation: mismatch
        ? `A link's visible text doesn't match its destination (${example}) — a hallmark of phishing.`
        : 'No link-text/URL mismatches detected (or no styled links present).',
      weight: mismatch ? 16 : 0,
      triggered: mismatch,
    });
  }

  // --- Email Heuristic 9: body asks to reply to a different domain (placeholder) ---
  // A full reply-to mismatch check would require parsing the Reply-To header
  // from raw email source, which the structured-input mode doesn't provide.
  {
    checks.push({
      id: 'reply-to',
      label: 'Reply-to mismatch',
      passed: true,
      explanation:
        'Reply-to header check is a placeholder — would require raw email headers to detect a Reply-To address on a different domain than the sender.',
      weight: 0,
      triggered: false,
    });
  }

  // --- Email Heuristic 10: independent email rule classifier ---
  {
    const ruleResult = classifyRuleEmail({ from: sender, subject, body });
    const triggered = ruleResult.verdict === 'Suspicious';
    checks.push({
      id: 'email-rule-classifier',
      label: 'Rule-based email classifier',
      passed: !triggered,
      explanation: triggered
        ? `Independent email rules flagged this message (score ${ruleResult.score}): ${ruleResult.reasons.slice(0, 4).join('; ')}.`
        : 'Independent email rules found no high-risk combination of sender, wording, links, or attachments.',
      weight: triggered ? Math.min(40, 14 + ruleResult.score * 3) : 0,
      triggered,
    });
  }

  // --- Email Heuristic 11: signals learned from labeled examples ---
  {
    const learned = getLearnedEmailSignals(`${sender} ${subject} ${body}`);
    const triggered = learned.hits.length > 0;
    checks.push({
      id: 'email-dataset-signals',
      label: 'Labeled-example email signals',
      passed: !triggered,
      explanation: triggered
        ? `Matches phishing patterns learned from the supplied email examples: ${learned.hits.slice(0, 5).join(', ')}.`
        : 'No high-confidence pattern from the supplied labeled email examples matched.',
      weight: triggered ? Math.min(28, 8 + learned.score) : 0,
      triggered,
    });
  }

  // --- Combined score ---
  const emailWeight = checks.reduce((sum, c) => sum + c.weight, 0);
  // Factor in the worst extracted URL score (up to 25 points) so a dangerous
  // link in the body can push an otherwise mild email into Suspicious/Phishing.
  const worstUrlScore = extractedUrls.reduce((max, u) => Math.max(max, u.score), 0);
  const urlContribution = Math.round((worstUrlScore / 100) * 25);
  const score = Math.min(100, Math.round(emailWeight) + urlContribution);
  const verdict: Verdict = classify(score);
  const confidence = computeEmailConfidence(score, verdict);

  return {
    scanType: 'email',
    subject,
    sender: address || sender,
    score,
    verdict,
    confidence,
    checks,
    extractedUrls,
    modelSource: 'local-heuristics',
    scannedAt: new Date().toISOString(),
  };
}

function computeEmailConfidence(score: number, verdict: Verdict): number {
  const bands: Record<Verdict, [number, number]> = {
    Safe: [0, 30],
    Suspicious: [31, 65],
    Phishing: [66, 100],
  };
  const [low, high] = bands[verdict];
  const center = (low + high) / 2;
  const halfWidth = (high - low) / 2;
  const distance = Math.abs(score - center);
  const edgeRatio = halfWidth === 0 ? 1 : 1 - distance / halfWidth;
  const conf = 60 + Math.round(edgeRatio * 38);
  return Math.max(60, Math.min(98, conf));
}
