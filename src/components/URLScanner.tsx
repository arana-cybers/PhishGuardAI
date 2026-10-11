import { useState } from 'react';
import { Search, Loader2, AlertCircle, Zap } from 'lucide-react';
import { isValidUrl } from '@/lib/analyzer';
import { EXAMPLE_URLS } from '@/lib/storage';

interface URLScannerProps {
  onScan: (url: string) => void;
  scanning: boolean;
}

export default function URLScanner({ onScan, scanning }: URLScannerProps) {
  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);

  function validate(v: string): string | null {
    if (!v.trim()) return 'Please enter a URL to scan.';
    if (!isValidUrl(v)) return 'That doesn\'t look like a valid URL. Example: https://example.com';
    return null;
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    const err = validate(value);
    setError(err);
    if (err) return;
    onScan(value.trim());
  }

  function handleExample(url: string) {
    setValue(url);
    setError(null);
    setTouched(true);
    onScan(url);
  }

  return (
    <section className="w-full">
      <div className="card-surface relative overflow-hidden p-6 sm:p-8">
        <div className="pointer-events-none absolute inset-0 bg-grid opacity-40" />
        <div className="relative">
          <div className="mb-5 flex items-center gap-2 text-xs font-medium uppercase tracking-[0.18em] text-electric-400">
            <Zap className="h-3.5 w-3.5" strokeWidth={2.5} />
            URL Scanner
          </div>
          <h1 className="font-mono text-2xl font-bold tracking-tight text-slate-50 sm:text-3xl">
            Detect phishing URLs in real time
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">
            Paste any URL below. PhishGuard AI analyzes its structure with a suite of
            security heuristics and returns an instant risk verdict.
          </p>

          <form onSubmit={handleSubmit} className="mt-6">
            <div
              className={`flex flex-col gap-3 rounded-xl border bg-ink-950/60 p-2 transition-colors sm:flex-row sm:items-center ${
                error && touched
                  ? 'border-threat-500/60'
                  : 'border-ink-600 focus-within:border-electric-500/70'
              }`}
            >
              <div className="flex flex-1 items-center gap-2 pl-2">
                <Search className="h-5 w-5 shrink-0 text-slate-500" strokeWidth={2} />
                <input
                  type="text"
                  value={value}
                  onChange={(e) => {
                    setValue(e.target.value);
                    if (touched) setError(validate(e.target.value));
                  }}
                  onBlur={() => {
                    setTouched(true);
                    setError(validate(value));
                  }}
                  placeholder="https://example.com/some-path"
                  maxLength={2048}
                  spellCheck={false}
                  autoComplete="off"
                  className="w-full bg-transparent py-2.5 font-mono text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none"
                  aria-label="URL to scan"
                  aria-invalid={!!error && touched}
                />
              </div>
              <button
                type="submit"
                disabled={scanning}
                className="group inline-flex items-center justify-center gap-2 rounded-lg bg-electric-500 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-electric-500/25 transition-all hover:bg-electric-600 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-60"
              >
                {scanning ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Scanning…
                  </>
                ) : (
                  <>
                    <Search className="h-4 w-4" strokeWidth={2.5} />
                    Scan URL
                  </>
                )}
              </button>
            </div>

            {error && touched && (
              <div className="mt-3 flex items-center gap-2 text-sm text-threat-400 animate-fade-in">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </form>

          <div className="mt-6">
            <p className="mb-2 text-xs font-medium uppercase tracking-wider text-slate-500">
              Try an example
            </p>
            <div className="flex flex-wrap gap-2">
              {EXAMPLE_URLS.map((ex) => (
                <button
                  key={ex.url}
                  onClick={() => handleExample(ex.url)}
                  disabled={scanning}
                  title={ex.note}
                  className="group rounded-full border border-ink-600 bg-ink-800/60 px-3 py-1.5 font-mono text-xs text-slate-300 transition-all hover:border-electric-500/50 hover:bg-electric-500/10 hover:text-electric-300 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {ex.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
