import urlsCsv from './urls.csv?raw';
import phishingEmailText from './phishing_emails.txt?raw';
import safeEmailText from './safe_emails.txt?raw';

interface LabeledExample {
  text: string;
  label: 0 | 1;
}

export interface LearnedSignals {
  hits: string[];
  score: number;
}

const IGNORED_TOKENS = new Set([
  'http', 'https', 'www', 'com', 'org', 'net', 'www', 'html', 'php', 'page',
  'home', 'index', 'docs', 'products', 'news', 'help', 'user', 'token', 'id',
  'session', 'href', 'mail', 'subject', 'from', 'to',
]);

function tokens(value: string): string[] {
  return [...new Set(
    value
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((token) => /^[a-z]{4,}$/.test(token) && !IGNORED_TOKENS.has(token)),
  )];
}

function train(examples: LabeledExample[]): Set<string> {
  const counts = new Map<string, { positive: number; negative: number }>();
  for (const example of examples) {
    for (const token of tokens(example.text)) {
      const count = counts.get(token) ?? { positive: 0, negative: 0 };
      if (example.label === 1) count.positive += 1;
      else count.negative += 1;
      counts.set(token, count);
    }
  }

  return new Set(
    [...counts.entries()]
      .filter(([, count]) => count.positive >= 2 && count.positive / (count.positive + count.negative) >= 0.8)
      .map(([token]) => token),
  );
}

function parseUrlExamples(): LabeledExample[] {
  return urlsCsv
    .trim()
    .split(/\r?\n/)
    .slice(1)
    .map((line) => {
      const separator = line.lastIndexOf(',');
      return {
        text: line.slice(0, separator),
        label: line.slice(separator + 1).trim() === '1' ? 1 : 0,
      };
    });
}

function parseEmailExamples(raw: string, label: 0 | 1): LabeledExample[] {
  return raw
    .split(/#{5,}[^\n]*#{5,}/)
    .map((block) => block.trim())
    .filter(Boolean)
    .map((block) => ({ text: block, label }));
}

const urlSignals = train(parseUrlExamples());
const emailSignals = train([
  ...parseEmailExamples(phishingEmailText, 1),
  ...parseEmailExamples(safeEmailText, 0),
]);

function scoreSignals(value: string, signals: Set<string>, limit: number): LearnedSignals {
  const hits = tokens(value).filter((token) => signals.has(token));
  return {
    hits,
    score: Math.min(limit, hits.length * 4),
  };
}

export function getLearnedUrlSignals(url: string): LearnedSignals {
  return scoreSignals(url, urlSignals, 20);
}

export function getLearnedEmailSignals(email: string): LearnedSignals {
  return scoreSignals(email, emailSignals, 24);
}

export const trainingExampleCounts = {
  urls: parseUrlExamples().length,
  phishingEmails: parseEmailExamples(phishingEmailText, 1).length,
  safeEmails: parseEmailExamples(safeEmailText, 0).length,
};
