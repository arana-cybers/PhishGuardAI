import { useEffect, useRef, useState } from 'react';
import { AlertCircle, Loader2, Radar, Link as LinkIcon, Mail } from 'lucide-react';
import Navbar, { type View } from '@/components/Navbar';
import Footer from '@/components/Footer';
import URLScanner from '@/components/URLScanner';
import EmailScanner from '@/components/EmailScanner';
import ResultCard from '@/components/ResultCard';
import EmailResultCard from '@/components/EmailResultCard';
import ScanHistory from '@/components/ScanHistory';
import DashboardStats from '@/components/DashboardStats';
import AboutSection from '@/components/AboutSection';
import { analyzePhishingRisk, isValidUrl } from '@/lib/analyzer';
import { analyzeEmailPhishingRisk } from '@/lib/emailAnalyzer';
import { loadHistory, insertScan, clearHistory } from '@/lib/storage';
import type { AnyRiskResult, RiskResult, EmailRiskResult, ScanRecord } from '@/lib/types';

type ScanMode = 'url' | 'email';

function App() {
  const [view, setView] = useState<View>('scanner');
  const [scanMode, setScanMode] = useState<ScanMode>('url');
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [currentResult, setCurrentResult] = useState<AnyRiskResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  // Load persisted history from Supabase once on mount.
  useEffect(() => {
    loadHistory().then(setRecords).catch(() => {
      setScanError('Scan history is temporarily unavailable. New scans still work.');
    });
  }, []);

  function runUrlScan(url: string) {
    if (!isValidUrl(url)) return;
    setScanning(true);
    setScanError(null);
    setCurrentResult(null);
    window.setTimeout(async () => {
      try {
        const result = analyzePhishingRisk(url);
        setCurrentResult(result);
        const stored = await insertScan(result);
      const newRecord: ScanRecord = stored ?? {
        id: `${result.scannedAt}-${result.url}`,
        scanType: 'url',
        label: result.url,
        sublabel: result.normalizedUrl,
        score: result.score,
        verdict: result.verdict,
        confidence: result.confidence,
        checks: result.checks,
        scannedAt: result.scannedAt,
      };
        setRecords((prev) => [newRecord, ...prev].slice(0, 100));
      } catch {
        setScanError('We could not complete this URL scan. Please try again.');
      } finally {
        setScanning(false);
      }
    }, 1300);
  }

  function runEmailScan(input: { sender: string; subject: string; body: string }) {
    setScanning(true);
    setScanError(null);
    setCurrentResult(null);
    window.setTimeout(async () => {
      try {
        const result = analyzeEmailPhishingRisk(input);
        setCurrentResult(result);
        const stored = await insertScan(result);
      const newRecord: ScanRecord = stored ?? {
        id: `${result.scannedAt}-${result.sender}`,
        scanType: 'email',
        label: result.sender,
        sublabel: result.subject,
        score: result.score,
        verdict: result.verdict,
        confidence: result.confidence,
        checks: result.checks,
        extractedUrls: result.extractedUrls,
        scannedAt: result.scannedAt,
      };
        setRecords((prev) => [newRecord, ...prev].slice(0, 100));
      } catch {
        setScanError('We could not complete this email scan. Please try again.');
      } finally {
        setScanning(false);
      }
    }, 1500);
  }

  function handleSelectRecord(r: ScanRecord) {
    // Reconstruct the appropriate result type from the stored record.
    let result: AnyRiskResult;
    if (r.scanType === 'url') {
      result = {
        scanType: 'url',
        url: r.label,
        normalizedUrl: r.sublabel,
        score: r.score,
        verdict: r.verdict,
        confidence: r.confidence,
        checks: r.checks,
        modelSource: 'local-heuristics',
        scannedAt: r.scannedAt,
      } as RiskResult;
    } else {
      result = {
        scanType: 'email',
        subject: r.sublabel,
        sender: r.label,
        score: r.score,
        verdict: r.verdict,
        confidence: r.confidence,
        checks: r.checks,
        extractedUrls: r.extractedUrls ?? [],
        modelSource: 'local-heuristics',
        scannedAt: r.scannedAt,
      } as EmailRiskResult;
    }
    setCurrentResult(result);
    setView('scanner');
    requestAnimationFrame(() => {
      resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }

  async function handleClearHistory() {
    const ok = await clearHistory();
    if (ok) setRecords([]);
  }

  return (
    <div className="flex min-h-screen flex-col">
      <Navbar view={view} onNavigate={setView} />

      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6 sm:py-10">
        {view === 'scanner' && (
          <div className="space-y-6">
            {/* Scan mode toggle */}
            <div className="flex justify-center">
              <div className="inline-flex rounded-xl border border-ink-600 bg-ink-950/60 p-1">
                <button
                  onClick={() => setScanMode('url')}
                  className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
                    scanMode === 'url'
                      ? 'bg-electric-500/15 text-electric-300'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <LinkIcon className="h-4 w-4" strokeWidth={2.2} />
                  URL Scanner
                </button>
                <button
                  onClick={() => setScanMode('email')}
                  className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
                    scanMode === 'email'
                      ? 'bg-electric-500/15 text-electric-300'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Mail className="h-4 w-4" strokeWidth={2.2} />
                  Email Scanner
                </button>
              </div>
            </div>

            {scanMode === 'url' ? (
              <URLScanner onScan={runUrlScan} scanning={scanning} />
            ) : (
              <EmailScanner onScan={runEmailScan} scanning={scanning} />
            )}

            {scanning && <ScanningState mode={scanMode} />}

            {scanError && !scanning && (
              <div className="card-surface flex items-center gap-3 border border-threat-500/40 bg-threat-500/10 px-5 py-4 text-sm text-threat-300">
                <AlertCircle className="h-5 w-5 shrink-0" />
                <span>{scanError}</span>
              </div>
            )}

            {currentResult && !scanning && !scanError && (
              <div ref={resultsRef} className="animate-fade-in">
                {currentResult.scanType === 'url' ? (
                  <ResultCard result={currentResult} />
                ) : (
                  <EmailResultCard result={currentResult} />
                )}
              </div>
            )}

            {!currentResult && !scanning && !scanError && <EmptyHint mode={scanMode} />}
          </div>
        )}

        {view === 'history' && (
          <ScanHistory
            records={records}
            onSelect={handleSelectRecord}
            onClear={handleClearHistory}
          />
        )}

        {view === 'dashboard' && <DashboardStats records={records} />}

        {view === 'about' && <AboutSection />}
      </main>

      <Footer />
    </div>
  );
}

function ScanningState({ mode }: { mode: ScanMode }) {
  return (
    <div className="card-surface flex flex-col items-center justify-center gap-5 px-6 py-16 animate-fade-in">
      <div className="relative flex h-20 w-20 items-center justify-center">
        <span className="absolute inline-flex h-16 w-16 rounded-full border-2 border-electric-500/40 animate-pulse-ring" />
        <span
          className="absolute inline-flex h-16 w-16 rounded-full border-2 border-electric-500/20 animate-pulse-ring"
          style={{ animationDelay: '0.4s' }}
        />
        <Radar className="h-9 w-9 text-electric-400 animate-spin" style={{ animationDuration: '2.4s' }} strokeWidth={1.8} />
      </div>
      <div className="text-center">
        <p className="font-mono text-sm font-semibold text-slate-200">
          {mode === 'url' ? 'Analyzing URL…' : 'Analyzing email…'}
        </p>
        <p className="mt-1 text-xs text-slate-500">
          {mode === 'url'
            ? 'Running heuristic checks and computing risk score'
            : 'Inspecting sender, language, and embedded links'}
        </p>
      </div>
      <div className="flex items-center gap-1.5">
        {[0, 1, 2].map((i) => (
          <Loader2
            key={i}
            className="h-3.5 w-3.5 text-electric-500/60 animate-spin"
            style={{ animationDelay: `${i * 0.15}s` }}
          />
        ))}
      </div>
    </div>
  );
}

function EmptyHint({ mode }: { mode: ScanMode }) {
  return (
    <div className="card-surface flex flex-col items-center justify-center px-6 py-14 text-center">
      <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-ink-800">
        {mode === 'url' ? (
          <LinkIcon className="h-6 w-6 text-slate-600" strokeWidth={1.8} />
        ) : (
          <Mail className="h-6 w-6 text-slate-600" strokeWidth={1.8} />
        )}
      </div>
      <p className="font-mono text-sm text-slate-400">
        {mode === 'url' ? 'Awaiting a URL to scan' : 'Awaiting an email to scan'}
      </p>
      <p className="mt-1 text-xs text-slate-600">
        {mode === 'url'
          ? 'Paste a link above or tap an example to see the verdict appear here.'
          : 'Paste an email above or tap an example to see the verdict appear here.'}
      </p>
    </div>
  );
}

export default App;
