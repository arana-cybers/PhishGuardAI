import { Shield, Search, Clock, BarChart3, Info } from 'lucide-react';

export type View = 'scanner' | 'history' | 'dashboard' | 'about';

interface NavbarProps {
  view: View;
  onNavigate: (v: View) => void;
}

const LINKS: { id: View; label: string; icon: typeof Search }[] = [
  { id: 'scanner', label: 'Scanner', icon: Search },
  { id: 'history', label: 'History', icon: Clock },
  { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
  { id: 'about', label: 'About', icon: Info },
];

export default function Navbar({ view, onNavigate }: NavbarProps) {
  return (
    <header className="sticky top-0 z-40 border-b border-ink-700 bg-ink-950/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
        <button
          onClick={() => onNavigate('scanner')}
          className="group flex items-center gap-2.5"
          aria-label="PhishGuard AI home"
        >
          <span className="relative flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-electric-500 to-electric-600 shadow-lg shadow-electric-500/20">
            <Shield className="h-5 w-5 text-white" strokeWidth={2.5} />
            <span className="absolute inset-0 rounded-xl ring-1 ring-inset ring-white/20" />
          </span>
          <span className="flex flex-col leading-none">
            <span className="font-mono text-sm font-bold tracking-tight text-slate-50">
              PhishGuard<span className="text-electric-400"> AI</span>
            </span>
            <span className="hidden text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500 sm:block">
              Phishing Detector
            </span>
          </span>
        </button>

        <nav className="flex items-center gap-1">
          {LINKS.map(({ id, label, icon: Icon }) => {
            const active = view === id;
            return (
              <button
                key={id}
                onClick={() => onNavigate(id)}
                className={`nav-link flex items-center gap-1.5 ${active ? 'nav-link-active' : ''}`}
              >
                <Icon className="h-4 w-4" strokeWidth={2.2} />
                <span className="hidden sm:inline">{label}</span>
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
