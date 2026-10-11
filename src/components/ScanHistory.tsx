import { Trash2, Clock, ShieldCheck, AlertTriangle, ShieldAlert, ArrowUpRight, Mail, Link as LinkIcon } from 'lucide-react';
import type { ScanRecord, Verdict } from '@/lib/types';

interface ScanHistoryProps {
  records: ScanRecord[];
  onSelect: (r: ScanRecord) => void;
  onClear: () => void;
}

const VERDICT_META: Record<Verdict, { icon: typeof ShieldCheck; color: string; dot: string }> = {
  Safe: { icon: ShieldCheck, color: 'text-neon-400', dot: 'bg-neon-500' },
  Suspicious: { icon: AlertTriangle, color: 'text-warn-400', dot: 'bg-warn-500' },
  Phishing: { icon: ShieldAlert, color: 'text-threat-400', dot: 'bg-threat-500' },
};

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

export default function ScanHistory({ records, onSelect, onClear }: ScanHistoryProps) {
  return (
    <section className="w-full">
      <div className="card-surface overflow-hidden">
        <div className="flex items-center justify-between border-b border-ink-700 px-5 py-4 sm:px-6">
          <div className="flex items-center gap-2">
            <Clock className="h-5 w-5 text-electric-400" strokeWidth={2.2} />
            <h2 className="font-mono text-base font-semibold text-slate-100">Scan History</h2>
            <span className="rounded-full bg-ink-700 px-2 py-0.5 font-mono text-xs text-slate-400">
              {records.length}
            </span>
          </div>
          {records.length > 0 && (
            <button
              onClick={onClear}
              className="inline-flex items-center gap-1.5 rounded-lg border border-ink-600 px-3 py-1.5 text-xs font-medium text-slate-400 transition-colors hover:border-threat-500/50 hover:bg-threat-500/10 hover:text-threat-400"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Clear History
            </button>
          )}
        </div>

        {records.length === 0 ? (
          <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
            <div className="mb-3 flex h-14 w-14 items-center justify-center rounded-full bg-ink-800">
              <Clock className="h-7 w-7 text-slate-600" strokeWidth={1.8} />
            </div>
            <p className="font-mono text-sm text-slate-400">No scans yet</p>
            <p className="mt-1 text-xs text-slate-600">
              Scanned URLs and emails will appear here for the rest of your session.
            </p>
          </div>
        ) : (
          <ul className="divide-y divide-ink-700">
            {records.map((r) => {
              const meta = VERDICT_META[r.verdict];
              const Icon = meta.icon;
              const isEmail = r.scanType === 'email';
              const TypeIcon = isEmail ? Mail : LinkIcon;
              return (
                <li key={r.id}>
                  <button
                    onClick={() => onSelect(r)}
                    className="group flex w-full items-center gap-3 px-5 py-3.5 text-left transition-colors hover:bg-ink-800/60 sm:px-6"
                  >
                    <span className={`inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-ink-800 ${meta.color}`}>
                      <Icon className="h-4 w-4" strokeWidth={2.2} />
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-mono text-sm text-slate-200">{r.label}</p>
                      <p className="mt-0.5 flex items-center gap-2 text-xs text-slate-500">
                        <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
                        <span className="inline-flex items-center gap-1">
                          <TypeIcon className="h-3 w-3" />
                          {isEmail ? 'Email' : 'URL'}
                        </span>
                        <span className="text-slate-600">·</span>
                        {r.verdict} · score {r.score} · {formatTime(r.scannedAt)}
                      </p>
                      {isEmail && r.sublabel && (
                        <p className="mt-0.5 truncate text-xs text-slate-600">{r.sublabel}</p>
                      )}
                    </div>
                    <ArrowUpRight className="h-4 w-4 shrink-0 text-slate-600 transition-colors group-hover:text-electric-400" />
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </section>
  );
}
