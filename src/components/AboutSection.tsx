import { Shield, Brain, ListChecks, Database, Lock, GraduationCap } from 'lucide-react';

const STEPS = [
  {
    icon: ListChecks,
    title: 'URL structure heuristics',
    body: 'The engine inspects dozens of structural signals — URL length, embedded IP addresses, excessive subdomains, hyphenated impersonation, link shorteners, insecure protocols, and sensitive keywords like "verify" or "login".',
  },
  {
    icon: Brain,
    title: 'Weighted risk scoring',
    body: 'Each signal contributes a weighted risk weight. The total maps to a 0–100 score and a verdict: Safe (0–30), Suspicious (31–65), or Phishing (66–100), with a confidence estimate.',
  },
  {
    icon: Database,
    title: 'Trained on real phishing data',
    body: 'The architecture mirrors models trained on public phishing datasets (e.g. PhishTank, OpenPhish). The local heuristic engine is designed to be swapped for a Python Flask/FastAPI model endpoint that performs ML-based classification.',
  },
  {
    icon: Lock,
    title: 'Privacy-first',
    body: 'Analysis runs on the URL string itself — no browsing, no remote fetches, no tracking. Your scanned URLs stay in your browser via localStorage.',
  },
];

export default function AboutSection() {
  return (
    <section className="w-full space-y-8">
      <div className="card-surface relative overflow-hidden p-6 sm:p-8">
        <div className="pointer-events-none absolute inset-0 bg-grid opacity-30" />
        <div className="relative">
          <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-electric-500/30 bg-electric-500/10 px-3 py-1">
            <GraduationCap className="h-3.5 w-3.5 text-electric-400" strokeWidth={2.5} />
            <span className="font-mono text-xs font-medium uppercase tracking-wider text-electric-300">
              Academic Project
            </span>
          </div>
          <h2 className="font-mono text-2xl font-bold text-slate-50 sm:text-3xl">
            How PhishGuard AI works
          </h2>
          <p className="mt-3 max-w-3xl text-sm leading-relaxed text-slate-400 sm:text-base">
            PhishGuard AI is an AI-powered phishing URL and website detector built as a
            final-year cybersecurity academic project. It analyzes the structure of a URL
            using a suite of security heuristics and a weighted risk-scoring model — the
            same approach used by production phishing classifiers, which are trained on real
            phishing datasets to recognize malicious patterns in URL structure and website
            content.
          </p>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        {STEPS.map((s, i) => {
          const Icon = s.icon;
          return (
            <div
              key={s.title}
              className="card-surface animate-slide-up p-6"
              style={{ animationDelay: `${i * 80}ms` }}
            >
              <div className="mb-3 inline-flex h-10 w-10 items-center justify-center rounded-xl bg-electric-500/15 text-electric-400">
                <Icon className="h-5 w-5" strokeWidth={2.2} />
              </div>
              <h3 className="font-mono text-base font-semibold text-slate-100">{s.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-slate-400">{s.body}</p>
            </div>
          );
        })}
      </div>

      <div className="card-surface flex items-start gap-3 border-warn-500/30 p-5">
        <Shield className="mt-0.5 h-5 w-5 shrink-0 text-warn-400" strokeWidth={2.2} />
        <p className="text-sm leading-relaxed text-slate-400">
          <span className="font-semibold text-slate-200">Disclaimer:</span> PhishGuard AI is an
          educational tool for demonstrating phishing-detection techniques. Heuristic scores are
          indicative, not definitive — always verify URLs independently and never rely on a single
          signal when deciding whether a site is safe.
        </p>
      </div>
    </section>
  );
}
