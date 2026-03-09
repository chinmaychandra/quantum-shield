// src/features/reports/ReportsPage.tsx
// ─── REPORTS PAGE ─────────────────────────────────────────────────────────────
// Shows: list of completed scan reports, PDF + JSON download buttons per report
// Integrates: reportsAPI, ExportButton (FileSaver), admin-only route guard
// NOTE: This page is only accessible to users with role = 'admin'
//       (enforced by ProtectedRoute in router/index.tsx)

import { useState } from 'react';
import { ExportButton } from './ExportButton';
import { useAuthStore } from '../../store/authStore';

// ── Types ─────────────────────────────────────────────────────────────────────
interface Report {
  id: string;
  scanId: string;
  target: string;
  completedAt: string;
  totalAssets: number;
  criticalFindings: number;
  pqcScore: number;
}

// ── MOCK REPORTS — remove once backend is ready ───────────────────────────────
const MOCK_REPORTS: Report[] = [
  { id: 'r1', scanId: 'sc-001', target: '192.168.1.0/24', completedAt: '2024-03-07T10:45:00Z', totalAssets: 24, criticalFindings: 3, pqcScore: 72 },
  { id: 'r2', scanId: 'sc-002', target: 'https://api.acme.com', completedAt: '2024-03-06T14:30:00Z', totalAssets: 8, criticalFindings: 1, pqcScore: 91 },
  { id: 'r3', scanId: 'sc-004', target: 'https://mail.acme.com', completedAt: '2024-03-04T17:10:00Z', totalAssets: 3, criticalFindings: 0, pqcScore: 98 },
];

// ── Subcomponents ─────────────────────────────────────────────────────────────
const ScoreRing = ({ score }: { score: number }) => {
  const color = score >= 90 ? '#10B981' : score >= 70 ? '#F59E0B' : '#EF4444';
  return (
    <div className=" textAlign: 'center' ">
      <div className="
        width: 52, height: 52, borderRadius: '50%',
        background: `conic-gradient(${color} ${score * 3.6}deg, #1e293b 0deg)`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        margin: '0 auto',
      ">
        <div className="
          width: 38, height: 38, borderRadius: '50%', background: '#0a0d14',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 11, fontWeight: 700, color,
        ">
          {score}
        </div>
      </div>
      <div className=" fontSize: 9, color: '#475569', marginTop: 3, textTransform: 'uppercase', letterSpacing: '0.06em' ">
        PQC
      </div>
    </div>
  );
};

// ── Component ─────────────────────────────────────────────────────────────────
export const ReportsPage = () => {
  const { role } = useAuthStore();
  const [searchTerm, setSearchTerm] = useState('');

  // ── INTEGRATION: fetch reports from API ───────────────────────────────────
  // Add to endpoints.ts:  getReports: () => apiClient.get<Report[]>('/reports')
  // const { data: reports = [] } = useQuery({
  //   queryKey: ['reports'],
  //   queryFn: () => reportsAPI.getAll().then(r => r.data),
  // });
  const reports = MOCK_REPORTS; // ← remove once backend is ready

  const filtered = reports.filter(r =>
    r.target.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className=" padding: '32px', display: 'flex', flexDirection: 'column', gap: 24, fontFamily: 'Segoe UI', sans-serif ">

      {/* Header */}
      <div className=" display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 ">
        <div>
          <h1 className=" fontSize: 22, fontWeight: 700, margin: '0 0 4px', color: '#f1f5f9' ">
            Reports
          </h1>
          <p className=" fontSize: 13, color: '#475569', margin: 0 ">
            {reports.length} completed scan reports · Admin only
          </p>
        </div>

        {/* Search */}
        <input
          value={searchTerm}
          onChange={e => setSearchTerm(e.target.value)}
          placeholder="Search by target..."
          className=" padding: '8px 14px', borderRadius: 6,
            background: '#0a0d14', border: '1px solid #1e293b',
            color: '#e2e8f0', fontSize: 13, outline: 'none', width: 220,
            transition: 'border-color 0.15s'"
        />
      </div>

      {/* Reports table */}
      <div className=" background: '#0a0d14', border: '1px solid #1e293b', borderRadius: 8, overflow: 'hidden' ">

        {/* Table header */}
        <div className="
          display: 'grid',
          gridTemplateColumns: '1fr 120px 80px 80px 200px',
          padding: '10px 20px',
          background: '#111827',
          borderBottom: '1px solid #1e293b',
          fontSize: 10, color: '#475569', fontWeight: 700,
          textTransform: 'uppercase', letterSpacing: '0.08em',
          gap: 12,
        ">
          <span>Target</span>
          <span>Completed</span>
          <span>Assets</span>
          <span>PQC Score</span>
          <span>Export</span>
        </div>

        {/* Rows */}
        {filtered.map((report, i) => (
          <div
            key={report.id}
            className=" display: 'grid', gridTemplateColumns: '1fr 120px 80px 80px 200px', padding: '16px 20px', borderBottom: i < filtered.length - 1 ? '1px solid #111827' : 'none', alignItems: 'center', gap: 12 transition: 'background 0.1s', cursor: 'pointer' "
            onMouseEnter={e => e.currentTarget.style.background = '#111827'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            {/* Target */}
            <div>
              <div className=" fontSize: 13, fontWeight: 500, color: '#e2e8f0' ">{report.target}</div>
              <div className=" fontSize: 10, color: '#475569', marginTop: 2 ">
                Scan ID: {report.scanId}
                {report.criticalFindings > 0 && (
                  <span className=" marginLeft: 8, color: '#EF4444', fontWeight: 600 ">
                    ⚠ {report.criticalFindings} critical
                  </span>
                )}
              </div>
            </div>

            {/* Date */}
            <div className=" fontSize: 12, color: '#64748b' ">
              {new Date(report.completedAt).toLocaleDateString()}
            </div>

            {/* Asset count */}
            <div className=" fontSize: 13, color: '#94a3b8', fontWeight: 600 ">
              {report.totalAssets}
            </div>

            {/* PQC Score ring */}
            <ScoreRing score={report.pqcScore} />

            {/* ── INTEGRATION: ExportButton uses FileSaver + reportsAPI ── */}
            {/* Calls: GET /api/reports/{scanId}/pdf  → downloads PDF blob   */}
            {/* Calls: GET /api/reports/{scanId}/json → downloads JSON file  */}
            <ExportButton scanId={report.scanId} />
          </div>
        ))}

        {filtered.length === 0 && (
          <div className=" padding: '40px' textAlign: 'center' color: '#475569' fontSize: 13 ">
            No reports match your search.
          </div>
        )}
      </div>

    </div>
  );
};