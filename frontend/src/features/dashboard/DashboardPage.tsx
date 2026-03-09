// src/features/dashboard/DashboardPage.tsx
// ─── DASHBOARD PAGE ───────────────────────────────────────────────────────────
// Shows: summary stat cards, risk distribution bar chart, recent scan history
// Integrates: useQuery (React Query), reportsAPI, RiskChart component

import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../../api/client';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell,
} from 'recharts';
import { RiskDistribution, ScanJob } from '../../types';
import { useAuthStore } from '../../store/authStore';

// ── API calls (add to endpoints.ts if you haven't) ────────────────────────────
const fetchDashboard = () =>
  apiClient.get<{
    totalAssets: number;
    criticalCount: number;
    activeScans: number;
    pqcCompliant: number;
    riskDistribution: RiskDistribution[];
    recentScans: ScanJob[];
  }>('/dashboard').then(r => r.data);

// ── Subcomponents ─────────────────────────────────────────────────────────────
const StatCard = ({
  label, value, accent, sub,
}: {
  label: string; value: string | number; accent: string; sub?: string;
}) => (
  <div className="
    background: '#0a0d14',
    border: `1px solid #1e293b`,
    borderTop: `3px solid ${accent}`,
    borderRadius: 8,
    padding: '20px 22px',
    flex: '1 1 160px',
    minWidth: 0,
  ">
    <div className=" text-xs font-medium text-muted-foreground letter-spacing: '0.1em', text-transform: 'uppercase', margin-bottom: 8 ">
      {label}
    </div>
    <div className=" text-2xl font-bold text-foreground letter-spacing: '-0.03em' ">
      {value}
    </div>
    {sub && <div className=" text-xs text-muted-foreground margin-top: 4 ">{sub}</div>}
  </div>
);

const riskColors: Record<string, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#10B981',
};

const statusBadge = (status: string) => {
  const map: Record<string, { bg: string; color: string }> = {
    completed: { bg: 'rgba(16,185,129,0.1)', color: '#10B981' },
    running: { bg: 'rgba(0,212,255,0.1)', color: '#00D4FF' },
    failed: { bg: 'rgba(239,68,68,0.1)', color: '#EF4444' },
    idle: { bg: 'rgba(100,116,139,0.1)', color: '#64748b' },
  };
  const s = map[status] || map.idle;
  return (
    <span className=" text-xs font-medium padding: '2px 8px', borderRadius: 20, fontWeight: 600,
      background: s.bg, color: s.color, textTransform: 'uppercase', letterSpacing: '0.06em',
    ">
      {status}
    </span>
  );
};

// ── MOCK DATA — remove once backend is ready ──────────────────────────────────
const MOCK = {
  totalAssets: 142,
  criticalCount: 4,
  activeScans: 2,
  pqcCompliant: 89,
  riskDistribution: [
    { category: 'critical' as const, count: 4 },
    { category: 'high' as const, count: 13 },
    { category: 'medium' as const, count: 31 },
    { category: 'low' as const, count: 94 },
  ],
  recentScans: [
    { id: 's1', target: '192.168.1.0/24', status: 'completed' as const, progress: 100, createdAt: '2024-03-07T10:22:00Z' },
    { id: 's2', target: 'https://api.acme.com', status: 'running' as const, progress: 62, createdAt: '2024-03-07T11:05:00Z' },
    { id: 's3', target: '10.0.0.1', status: 'failed' as const, progress: 30, createdAt: '2024-03-06T09:14:00Z' },
  ],
};

// ── Component ─────────────────────────────────────────────────────────────────
export const DashboardPage = () => {
  const { user } = useAuthStore();

  // ── INTEGRATION: replace MOCK with real API call ───────────────────────────
  // const { data, isLoading, error } = useQuery({
  //   queryKey: ['dashboard'],
  //   queryFn: fetchDashboard,
  // });
  // const d = data ?? MOCK;

  const d = MOCK; // ← remove this line once backend is ready

  return (
    <div className=" padding: '32px', display: 'flex', flexDirection: 'column', gap: 28 }">

      {/* Header */}
      <div>
        <h1 className=" text-2xl font-bold text-foreground margin: '0 0 4px'">
          Dashboard
        </h1>
        <p className=" text-sm text-muted-foreground margin: 0">
          Welcome back{user?.email ? `, ${user.email}` : ''}. Here's your security overview.
        </p>
      </div>

      {/* ── Stat Cards ────────────────────────────── */}
      <div className=" display: 'flex', gap: 14, flexWrap: 'wrap' ">
        <StatCard label="Total Assets" value={d.totalAssets} accent="#00D4FF" sub="Monitored endpoints" />
        <StatCard label="Critical Risk" value={d.criticalCount} accent="#EF4444" sub="Needs immediate action" />
        <StatCard label="Active Scans" value={d.activeScans} accent="#F59E0B" sub="Currently running" />
        <StatCard label="PQC Compliant" value={`${d.pqcCompliant}%`} accent="#10B981" sub="Post-quantum ready" />
      </div>

      {/* ── Charts + Recent Scans row ─────────────── */}
      <div className="display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }">

        {/* Risk Distribution Chart */}
        <div className="background: '#0a0d14', border: '1px solid #1e293b', borderRadius: 8, padding: '22px'">
          <h2 className=" text-lg font-semibold text-foreground margin: '0 0 20px'">
            Risk Distribution
          </h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={d.riskDistribution} margin={{ top: 0, right: 10, bottom: 0, left: -10 }}>
              <XAxis dataKey="category" tick={{ fontSize: 11, fill: '#64748b' }} />
              <YAxis tick={{ fontSize: 11, fill: '#64748b' }} />
              <Tooltip
                contentStyle={{ background: '#111827', border: '1px solid #1e293b', borderRadius: 6, fontSize: 12 }}
                cursor={{ fill: 'rgba(255,255,255,0.03)' }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {d.riskDistribution.map(entry => (
                  <Cell key={entry.category} fill={riskColors[entry.category]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Recent Scans */}
        <div className="background: '#0a0d14', border: '1px solid #1e293b', borderRadius: 8, padding: '22px'">
          <h2 className=" text-lg font-semibold text-foreground margin: '0 0 20px'">
            Recent Scans
          </h2>
          <div className="flex flex-col gap-2.5">
            {d.recentScans.map(scan => (
              <div key={scan.id} className="
                padding: '12px 14px', borderRadius: 6,
                background: '#111827', border: '1px solid #1e293b',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10,
              ">
                <div className="min-w-0">
                  <div className=" text-lg font-semibold text-foreground overflow-hidden text-ellipsis whitespace-nowrap">
                    {scan.target}
                  </div>
                  <div className=" text-sm text-muted-foreground mt-1">
                    {new Date(scan.createdAt).toLocaleString()}
                  </div>
                </div>
                <div className="flex flex-col items-end gap-2.5 flex-shrink-0">
                  {statusBadge(scan.status)}
                  {scan.status === 'running' && (
                    <div className="w-20 h-0.75 bg-gray-600 rounded overflow-hidden">
                      <div className=" width: `${scan.progress}%`, height: '100%', background: '#00D4FF', borderRadius: 2 " />
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
};