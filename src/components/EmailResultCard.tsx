import { useEffect, useState } from 'react';
import {
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Mail,
  Link as LinkIcon,
} from 'lucide-react';
import type { EmailRiskResult, Verdict } from '@/lib/types';
import HeuristicBreakdown from './HeuristicBreakdown';

interface EmailResultCardProps {
  result: EmailRiskResult;
}

const VERDICT_STYLES: Record<
  Verdict,
  { ring: string; text: string; bg: string; border: string; icon: typeof CheckCircle2; label: string }
> = {
  Safe: {
    ring: '#10b981',
    text: 'text-neon-400',
    bg: 'bg-neon-500/10',
    border: 'border-neon-500/40',
    icon: ShieldCheck,
    label: 'Safe',
  },
  Suspicious: {
    ring: '#f97316',
    text: 'text-warn-400',
    bg: 'bg-warn-500/10',
    border: 'border-warn-500/40',
    icon: AlertTriangle,
    label: 'Suspicious',
  },
  Phishing: {
    ring: '#ef4444',
    text: 'text-threat-400',
    bg: 'bg-threat-500/10',
    border: 'border-threat-500/40',
    icon: ShieldAlert,
    label: 'Phishing',
  },
};

const URL_VERDICT_DOT: Record<Verdict, string> = {
  Safe: 'bg-neon-500',
  Suspicious: 'bg-warn-500',
  Phishing: 'bg-threat-500',
};

function useAnimatedScore(target: number, durationMs = 900) {
  const [value, setValue] = useState(0);
  useEffect(() => {
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / durationMs);
      const eased = 1 - Math.pow(1 - t, 3);
      setValue(Math.round(target * eased));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, durationMs]);
  return value;
}

function Gauge({ score, color }: { score: number; color: string }) {
  const animated = useAnimatedScore(score);
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (animated / 100) * circumference;
  return (
    <div className="relative h-44 w-44 shrink-0">
      <svg className="h-full w-full -rotate-90" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r={radius} fill="none" stroke="#1e2839" strokeWidth="10" />
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke 0.4s ease' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-4xl font-bold text-slate-50">{animated}</span>
        <span className="text-xs font-medium uppercase tracking-wider text-slate-500">Risk Score</span>
      </div>
    </div>
  );
}

export default function EmailResultCard({ result }: EmailResultCardProps) {
  const style = VERDICT_STYLES[result.verdict];
  const Icon = style.icon;

  return (
    <div className={`card-surface animate-scale-in overflow-hidden border ${style.border}`}>
      <div className={`flex flex-col gap-6 p-6 sm:flex-row sm:items-center sm:p-8 ${style.bg}`}>
        <Gauge score={result.score} color={style.ring} />

        <div className="flex-1">
          <div className="flex items-center gap-3">
            <span className={`inline-flex h-12 w-12 items-center justify-center rounded-xl ${style.bg} ${style.border} border`}>
              <Icon className={`h-7 w-7 ${style.text}`} strokeWidth={2.4} />
            </span>
            <div>
              <p className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Verdict</p>
              <p className={`font-mono text-2xl font-bold ${style.text}`}>{style.label}</p>
            </div>
          </div>

          <div className="mt-4 space-y-2">
            <div className="flex items-start gap-2 text-sm">
              <span className="w-20 shrink-0 text-slate-500">Sender</span>
              <span className="break-all font-mono text-slate-300">{result.sender}</span>
            </div>
            <div className="flex items-start gap-2 text-sm">
              <span className="w-20 shrink-0 text-slate-500">Subject</span>
              <span className="break-words font-mono text-slate-300">{result.subject || '(empty)'}</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <span className="w-20 shrink-0 text-slate-500">Confidence</span>
              <div className="flex flex-1 items-center gap-2">
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-ink-700">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${result.confidence}%`, backgroundColor: style.ring }}
                  />
                </div>
                <span className="font-mono text-xs text-slate-400">{result.confidence}%</span>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <span className="w-20 shrink-0">Engine</span>
              <span className="font-mono uppercase tracking-wider">{result.modelSource.replace('-', ' ')}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Extracted URLs */}
      {result.extractedUrls.length > 0 && (
        <div className="border-t border-ink-700 px-6 py-5 sm:px-8">
          <div className="mb-3 flex items-center gap-2">
            <LinkIcon className="h-4 w-4 text-electric-400" strokeWidth={2.2} />
            <h3 className="font-mono text-sm font-semibold uppercase tracking-wider text-slate-300">
              Links found in email body ({result.extractedUrls.length})
            </h3>
          </div>
          <ul className="space-y-2">
            {result.extractedUrls.map((u, i) => (
              <li
                key={`${u.url}-${i}`}
                className="flex items-center gap-3 rounded-lg border border-ink-700 bg-ink-850/50 p-3 animate-slide-up"
                style={{ animationDelay: `${i * 50}ms` }}
              >
                <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${URL_VERDICT_DOT[u.verdict]}`} />
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-slate-300">{u.normalizedUrl}</span>
                <span className="shrink-0 font-mono text-xs text-slate-500">
                  {u.verdict} · {u.score}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Email heuristic breakdown */}
      <div className="border-t border-ink-700 p-6 sm:p-8">
        <div className="mb-4 flex items-center gap-2">
          <Mail className="h-4 w-4 text-electric-400" strokeWidth={2.2} />
          <h3 className="font-mono text-sm font-semibold uppercase tracking-wider text-slate-300">
            Email Heuristic Breakdown
          </h3>
        </div>
        <HeuristicBreakdown checks={result.checks} />
      </div>
    </div>
  );
}
