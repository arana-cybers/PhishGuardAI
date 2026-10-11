export interface EmailRuleInput {
  from?: string;
  replyTo?: string;
  subject?: string;
  body?: string;
  headers?: string | Record<string, unknown>;
  attachments?: string[];
}

export interface EmailRuleClassification {
  type: 'email';
  verdict: 'Suspicious' | 'Safe';
  score: number;
  reasons: string[];
}

export function classifyEmail(input: EmailRuleInput, threshold?: number): EmailRuleClassification;
export function classify(input: EmailRuleInput | string): EmailRuleClassification | { type: 'url'; verdict: 'Suspicious' | 'Safe'; score: number; reasons: string[] };
export function parseRawEmail(raw: string): EmailRuleInput;
