import { Shield } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="mt-20 border-t border-ink-700 bg-ink-950/60">
      <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-3 px-4 py-6 sm:flex-row sm:px-6">
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <Shield className="h-4 w-4 text-electric-500" strokeWidth={2.2} />
          <span className="font-mono">
            PhishGuard AI <span className="text-slate-600">—</span> Cybersecurity Academic Project
          </span>
        </div>
        <p className="text-xs text-slate-600">
          For educational purposes only. Always verify URLs independently.
        </p>
      </div>
    </footer>
  );
}
