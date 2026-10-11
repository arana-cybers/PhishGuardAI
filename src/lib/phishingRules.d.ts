export interface RuleClassification {
  verdict: 'Suspicious' | 'Safe';
  score: number;
  reasons: string[];
}

export function classifyUrl(input: string, threshold?: number): RuleClassification;
