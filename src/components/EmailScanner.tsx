import { useState } from 'react';
import { Mail, Loader2, AlertCircle, Zap, FileText, ClipboardPaste } from 'lucide-react';
import { extractEmailParts } from '@/lib/emailAnalyzer';
import { EXAMPLE_EMAILS } from '@/lib/storage';

interface EmailScannerProps {
  onScan: (input: { sender: string; subject: string; body: string }) => void;
  scanning: boolean;
}

type InputMode = 'structured' | 'raw';

export default function EmailScanner({ onScan, scanning }: EmailScannerProps) {
  const [mode, setMode] = useState<InputMode>('structured');
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [raw, setRaw] = useState('');
  const [error, setError] = useState<string | null>(null);

  function validate(): string | null {
    if (mode === 'raw') {
      if (!raw.trim()) return 'Please paste an email to scan.';
      return null;
    }
    if (!sender.trim() && !subject.trim() && !body.trim())
      return 'Please fill in at least the sender, subject, or body.';
    return null;
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const err = validate();
    setError(err);
    if (err) return;

    if (mode === 'raw') {
      onScan(extractEmailParts(raw));
    } else {
      onScan({ sender: sender.trim(), subject: subject.trim(), body: body.trim() });
    }
  }

  function handleExample(ex: (typeof EXAMPLE_EMAILS)[number]) {
    setMode('structured');
    setSender(ex.sender);
    setSubject(ex.subject);
    setBody(ex.body);
    setError(null);
    onScan({ sender: ex.sender, subject: ex.subject, body: ex.body });
  }

  return (
    <section className="w-full">
      <div className="card-surface relative overflow-hidden p-6 sm:p-8">
        <div className="pointer-events-none absolute inset-0 bg-grid opacity-40" />
        <div className="relative">
          <div className="mb-5 flex items-center gap-2 text-xs font-medium uppercase tracking-[0.18em] text-electric-400">
            <Zap className="h-3.5 w-3.5" strokeWidth={2.5} />
            Email Scanner
          </div>
          <h1 className="font-mono text-2xl font-bold tracking-tight text-slate-50 sm:text-3xl">
            Detect phishing emails in real time
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">
            Paste a suspicious email's sender, subject, and body — or paste the raw
            email source. PhishGuard AI analyzes sender identity, manipulation
            language, and any links in the body.
          </p>

          {/* Mode toggle */}
          <div className="mt-5 inline-flex rounded-lg border border-ink-600 bg-ink-950/60 p-1">
            <button
              type="button"
              onClick={() => setMode('structured')}
              className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                mode === 'structured'
                  ? 'bg-electric-500/15 text-electric-300'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileText className="h-3.5 w-3.5" />
              Structured
            </button>
            <button
              type="button"
              onClick={() => setMode('raw')}
              className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                mode === 'raw'
                  ? 'bg-electric-500/15 text-electric-300'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <ClipboardPaste className="h-3.5 w-3.5" />
              Raw paste
            </button>
          </div>

          <form onSubmit={handleSubmit} className="mt-5 space-y-4">
            {mode === 'structured' ? (
              <>
                <div>
                <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-slate-500">
                    Sender
                  </label>
                  <input
                    type="text"
                    value={sender}
                    onChange={(e) => setSender(e.target.value)}
                    placeholder="IT Support <it-support@weird-domain.com>"
                    maxLength={320}
                    spellCheck={false}
                    className="w-full rounded-xl border border-ink-600 bg-ink-950/60 px-3 py-2.5 font-mono text-sm text-slate-100 placeholder:text-slate-600 transition-colors focus:border-electric-500/70 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-slate-500">
                    Subject
                  </label>
                  <input
                    type="text"
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    placeholder="URGENT: Your account has been suspended"
                    maxLength={998}
                    spellCheck={false}
                    className="w-full rounded-xl border border-ink-600 bg-ink-950/60 px-3 py-2.5 font-mono text-sm text-slate-100 placeholder:text-slate-600 transition-colors focus:border-electric-500/70 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-slate-500">
                    Body
                  </label>
                  <textarea
                    value={body}
                    onChange={(e) => setBody(e.target.value)}
                    placeholder="Paste the email body here…"
                    rows={7}
                    maxLength={100000}
                    spellCheck={false}
                    className="w-full resize-y rounded-xl border border-ink-600 bg-ink-950/60 px-3 py-2.5 font-mono text-sm leading-relaxed text-slate-100 placeholder:text-slate-600 transition-colors focus:border-electric-500/70 focus:outline-none"
                  />
                </div>
              </>
            ) : (
              <div>
                <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-slate-500">
                  Raw email source
                </label>
                <textarea
                  value={raw}
                  onChange={(e) => setRaw(e.target.value)}
                  placeholder={`From: IT Support <it-support@weird-domain.com>\nSubject: URGENT: verify your account\n\nDear user, please confirm your password at http://…`}
                  rows={10}
                  maxLength={100000}
                  spellCheck={false}
                  className="w-full resize-y rounded-xl border border-ink-600 bg-ink-950/60 px-3 py-2.5 font-mono text-sm leading-relaxed text-slate-100 placeholder:text-slate-600 transition-colors focus:border-electric-500/70 focus:outline-none"
                />
                <p className="mt-1.5 text-xs text-slate-600">
                  We'll parse the From / Subject headers and body automatically.
                </p>
              </div>
            )}

            {error && (
              <div className="flex items-center gap-2 text-sm text-threat-400 animate-fade-in">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={scanning}
              className="group inline-flex items-center justify-center gap-2 rounded-lg bg-electric-500 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-electric-500/25 transition-all hover:bg-electric-600 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-60"
            >
              {scanning ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Analyzing email…
                </>
              ) : (
                <>
                  <Mail className="h-4 w-4" strokeWidth={2.5} />
                  Scan Email
                </>
              )}
            </button>
          </form>

          <div className="mt-6">
            <p className="mb-2 text-xs font-medium uppercase tracking-wider text-slate-500">
              Try an example
            </p>
            <div className="flex flex-wrap gap-2">
              {EXAMPLE_EMAILS.map((ex) => (
                <button
                  key={ex.label}
                  onClick={() => handleExample(ex)}
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
