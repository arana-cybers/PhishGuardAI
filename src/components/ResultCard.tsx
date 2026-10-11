import { useEffect, useState } from 'react';
import { CheckCircle2, AlertTriangle, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { RiskResult, Verdict } from '@/lib/types';
import HeuristicBreakdown from './HeuristicBreakdown';

interface ResultCardProps {
  result: RiskResult;
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

function useAnimatedScore(target: number, durationMs = 900) {
  const [value, setValue] = useState(0);
  useEffect(() => {
    let raf = 0;
    const start = performance.now();
    const from = 0;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / durationMs);
      const eased = 1 - Math.pow(1 - t, 3);
      setValue(Math.round(from + (target - from) * eased));
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
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke="#1e2839"
          strokeWidth="10"
        />
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
        <span className="text-xs font-medium uppercase tracking-wider text-slate-500">
          Risk Score
        </span>
      </div>
    </div>
  );
}

export default function ResultCard({ result }: ResultCardProps) {
  const style = VERDICT_STYLES[result.verdict];
  const Icon = style.icon;

  return (
    <div className={`card-surface animate-scale-in overflow-hidden border ${style.border}`}>
      <div className={`flex flex-col gap-6 p-6 sm:flex-row sm:items-center sm:p-8 ${style.bg}`}>
        <Gauge score={result.score} color={style.ring} />

        <div className="flex-1">
          <div className="flex items-center gap-3">
            <span
              className={`inline-flex h-12 w-12 items-center justify-center rounded-xl ${style.bg} ${style.border} border`}
            >
              <Icon className={`h-7 w-7 ${style.text}`} strokeWidth={2.4} />
            </span>
            <div>
              <p className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">
                Verdict
              </p>
              <p className={`font-mono text-2xl font-bold ${style.text}`}>{style.label}</p>
            </div>
          </div>

          <div className="mt-4 space-y-2">
            <div className="flex items-start gap-2 text-sm">
              <span className="w-20 shrink-0 text-slate-500">URL</span>
              <span className="break-all font-mono text-slate-300">{result.normalizedUrl}</span>
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
              <span className="font-mono uppercase tracking-wider">
                {result.modelSource.replace('-', ' ')}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="border-t border-ink-700 p-6 sm:p-8">
        <HeuristicBreakdown checks={result.checks} />
      </div>
    </div>
  );
}
