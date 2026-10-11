import { Check, X } from 'lucide-react';
import type { HeuristicCheck } from '@/lib/types';

interface HeuristicBreakdownProps {
  checks: HeuristicCheck[];
}

export default function HeuristicBreakdown({ checks }: HeuristicBreakdownProps) {
  const failed = checks.filter((c) => c.triggered).length;

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h3 className="font-mono text-sm font-semibold uppercase tracking-wider text-slate-300">
          Heuristic Breakdown
        </h3>
        <span className="font-mono text-xs text-slate-500">
          {checks.length - failed} passed · {failed} flagged
        </span>
      </div>

      <ul className="space-y-2.5">
        {checks.map((c, i) => (
          <li
            key={c.id}
            className="flex items-start gap-3 rounded-lg border border-ink-700 bg-ink-850/50 p-3 transition-colors animate-slide-up"
            style={{ animationDelay: `${i * 45}ms` }}
          >
            <span
              className={`mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full ${
                c.passed
                  ? 'bg-neon-500/15 text-neon-400'
                  : 'bg-threat-500/15 text-threat-400'
              }`}
            >
              {c.passed ? (
                <Check className="h-3.5 w-3.5" strokeWidth={3} />
              ) : (
                <X className="h-3.5 w-3.5" strokeWidth={3} />
              )}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <p className="font-mono text-sm font-medium text-slate-200">{c.label}</p>
                {c.triggered && (
                  <span className="shrink-0 font-mono text-xs text-threat-400">
                    +{c.weight}
                  </span>
                )}
              </div>
              <p className="mt-0.5 text-xs leading-relaxed text-slate-400">{c.explanation}</p>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
