import { useMemo } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { Activity, ShieldCheck, AlertTriangle, ShieldAlert, BarChart3, Link as LinkIcon, Mail } from 'lucide-react';
import type { ScanRecord, Verdict } from '@/lib/types';

interface DashboardStatsProps {
  records: ScanRecord[];
}

const COLORS: Record<Verdict, string> = {
  Safe: '#10b981',
  Suspicious: '#f97316',
  Phishing: '#ef4444',
};

function StatCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: number;
  icon: typeof Activity;
  accent: string;
}) {
  return (
    <div className="card-surface relative overflow-hidden p-5">
      <div className="pointer-events-none absolute inset-0 bg-grid opacity-30" />
      <div className="relative flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-slate-500">{label}</p>
          <p className="mt-1 font-mono text-3xl font-bold text-slate-50">{value}</p>
        </div>
        <span className={`inline-flex h-11 w-11 items-center justify-center rounded-xl ${accent}`}>
          <Icon className="h-5 w-5" strokeWidth={2.2} />
        </span>
      </div>
    </div>
  );
}

export default function DashboardStats({ records }: DashboardStatsProps) {
  const stats = useMemo(() => {
    const counts = { Safe: 0, Suspicious: 0, Phishing: 0 } as Record<Verdict, number>;
    let totalScore = 0;
    let urlCount = 0;
    let emailCount = 0;
    records.forEach((r) => {
      counts[r.verdict]++;
      totalScore += r.score;
      if (r.scanType === 'url') urlCount++;
      else emailCount++;
    });
    return {
      total: records.length,
      counts,
      avgScore: records.length ? Math.round(totalScore / records.length) : 0,
      urlCount,
      emailCount,
    };
  }, [records]);

  const pieData = (['Safe', 'Suspicious', 'Phishing'] as Verdict[])
    .map((v) => ({ name: v, value: stats.counts[v], color: COLORS[v] }))
    .filter((d) => d.value > 0);

  const barData = (['Safe', 'Suspicious', 'Phishing'] as Verdict[]).map((v) => ({
    name: v,
    count: stats.counts[v],
    color: COLORS[v],
  }));

  const hasData = stats.total > 0;

  return (
    <section className="w-full space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <BarChart3 className="h-5 w-5 text-electric-400" strokeWidth={2.2} />
          <h2 className="font-mono text-lg font-semibold text-slate-100">Dashboard</h2>
        </div>
        <p className="mt-1 text-sm text-slate-500">
          Summary of all scans performed in this session.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Total Scans" value={stats.total} icon={Activity} accent="bg-electric-500/15 text-electric-400" />
        <StatCard label="Safe" value={stats.counts.Safe} icon={ShieldCheck} accent="bg-neon-500/15 text-neon-400" />
        <StatCard label="Suspicious" value={stats.counts.Suspicious} icon={AlertTriangle} accent="bg-warn-500/15 text-warn-400" />
        <StatCard label="Phishing" value={stats.counts.Phishing} icon={ShieldAlert} accent="bg-threat-500/15 text-threat-400" />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <StatCard label="URL Scans" value={stats.urlCount} icon={LinkIcon} accent="bg-electric-500/15 text-electric-400" />
        <StatCard label="Email Scans" value={stats.emailCount} icon={Mail} accent="bg-electric-500/15 text-electric-400" />
      </div>

      {hasData ? (
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="card-surface p-6">
            <h3 className="mb-4 font-mono text-sm font-semibold uppercase tracking-wider text-slate-300">
              Verdict Distribution
            </h3>
            <div className="flex flex-col items-center gap-4 sm:flex-row">
              <div className="h-56 w-full sm:w-1/2">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={55}
                      outerRadius={85}
                      paddingAngle={3}
                      stroke="#0a0e17"
                      strokeWidth={2}
                    >
                      {pieData.map((d) => (
                        <Cell key={d.name} fill={d.color} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="flex flex-1 flex-col gap-3">
                {(['Safe', 'Suspicious', 'Phishing'] as Verdict[]).map((v) => (
                  <div key={v} className="flex items-center justify-between rounded-lg border border-ink-700 bg-ink-850/50 px-3 py-2.5">
                    <div className="flex items-center gap-2">
                      <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: COLORS[v] }} />
                      <span className="text-sm text-slate-300">{v}</span>
                    </div>
                    <span className="font-mono text-sm text-slate-400">
                      {stats.counts[v]}{' '}
                      <span className="text-slate-600">
                        ({stats.total ? Math.round((stats.counts[v] / stats.total) * 100) : 0}%)
                      </span>
                    </span>
                  </div>
                ))}
                <div className="flex items-center justify-between rounded-lg border border-ink-700 bg-ink-850/50 px-3 py-2.5">
                  <span className="text-sm text-slate-400">Avg. Risk Score</span>
                  <span className="font-mono text-sm font-semibold text-slate-200">{stats.avgScore}</span>
                </div>
              </div>
            </div>
          </div>

          <div className="card-surface p-6">
            <h3 className="mb-4 font-mono text-sm font-semibold uppercase tracking-wider text-slate-300">
              Scan Counts
            </h3>
            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData} margin={{ top: 8, right: 8, bottom: 4, left: -18 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2839" vertical={false} />
                  <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 12, fontFamily: 'JetBrains Mono' }} axisLine={{ stroke: '#1e2839' }} tickLine={false} />
                  <YAxis allowDecimals={false} tick={{ fill: '#64748b', fontSize: 12 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    cursor={{ fill: 'rgba(59,130,246,0.06)' }}
                    contentStyle={{
                      background: '#0d1320',
                      border: '1px solid #1e2839',
                      borderRadius: 10,
                      fontFamily: 'JetBrains Mono',
                      fontSize: 12,
                      color: '#e2e8f0',
                    }}
                  />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]} barSize={48}>
                    {barData.map((d) => (
                      <Cell key={d.name} fill={d.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      ) : (
        <div className="card-surface flex flex-col items-center justify-center px-6 py-16 text-center">
          <div className="mb-3 flex h-14 w-14 items-center justify-center rounded-full bg-ink-800">
            <BarChart3 className="h-7 w-7 text-slate-600" strokeWidth={1.8} />
          </div>
          <p className="font-mono text-sm text-slate-400">No data to chart yet</p>
          <p className="mt-1 text-xs text-slate-600">
            Run a few scans to populate the dashboard charts.
          </p>
        </div>
      )}
    </section>
  );
}
