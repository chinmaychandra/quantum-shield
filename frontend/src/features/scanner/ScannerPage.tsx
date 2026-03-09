// src/features/scanner/ScannerPage.tsx
// ─── SCANNER PAGE ─────────────────────────────────────────────────────────────
// Shows: scan config form, live progress bar (WebSocket), scan history list
// Integrates: ScanConfigForm, useScanProgress (Socket.io), useScanHistory

import { useState } from 'react';
import { ScanConfigForm } from './ScanConfigForm';
import { useScanProgress } from '../../hooks/useScanProgress';
import { useScanHistory } from './hooks/useScanner';
import { ScanJob } from '../../types';

// ── MOCK scan history — remove once backend is ready ──────────────────────────
const MOCK_HISTORY: ScanJob[] = [
  { id: 'sc-001', target: '192.168.1.0/24', status: 'completed', progress: 100, createdAt: '2024-03-07T10:22:00Z' },
  { id: 'sc-002', target: 'https://api.acme.com', status: 'completed', progress: 100, createdAt: '2024-03-06T14:10:00Z' },
  { id: 'sc-003', target: '10.0.0.1', status: 'failed', progress: 33, createdAt: '2024-03-05T09:00:00Z' },
  { id: 'sc-004', target: 'https://mail.acme.com', status: 'completed', progress: 100, createdAt: '2024-03-04T16:55:00Z' },
];

// ── Subcomponents ─────────────────────────────────────────────────────────────
const ProgressBar = ({ value, status }: { value: number; status: string }) => {
  const color = status === 'failed' ? '#EF4444' : status === 'completed' ? '#10B981' : '#00D4FF';
  return (
    <div>
      <div className=" display: 'flex', justifyContent: 'space-between', marginBottom: 6 ">
        <span className=" fontSize: 12, color: '#94a3b8' ">Progress</span>
        <span className=" fontSize: 12, color, fontWeight: 600 ">{value}%</span>
      </div>
      <div className=" height: 6, background: '#1e293b', borderRadius: 3, overflow: 'hidden' ">
        <div className="
          height: '100%', width: `${value}%`, background: color,
          borderRadius: 3, transition: 'width 0.4s ease',
        " />
      </div>
    </div>
  );
};

const HistoryRow = ({ scan, onSelect }: { scan: ScanJob; onSelect: (id: string) => void }) => {
  const statusColors: Record<string, string> = {
    completed: '#10B981', running: '#00D4FF', failed: '#EF4444', idle: '#64748b',
  };
  return (
    <div
      onClick={() => onSelect(scan.id)}
      className="
        padding: '12px 16px', borderRadius: 6,
        background: '#0a0d14', border: '1px solid #1e293b',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        cursor: 'pointer', transition: 'border-color 0.15s', gap: 12,
      "
      onMouseEnter={e => e.currentTarget.style.borderColor = '#334155'}
      onMouseLeave={e => e.currentTarget.style.borderColor = '#1e293b'}
    >
      <div>
        <div className="fontSize: 13, color: '#e2e8f0', fontWeight: 500 ">{scan.target}</div>
        <div className=" fontSize: 10, color: '#475569', marginTop: 2 ">
          ID: {scan.id} · {new Date(scan.createdAt).toLocaleString()}
        </div>
      </div>
      <div className=" display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 ">
        <span className="
          fontSize: 10, padding: '2px 8px', borderRadius: 20, fontWeight: 700,
          background: `${statusColors[scan.status]}15`,
          color: statusColors[scan.status],
          textTransform: 'uppercase', letterSpacing: '0.06em',
        ">
          {scan.status}
        </span>
      </div>
    </div>
  );
};

// ── Main Component ─────────────────────────────────────────────────────────────
export const ScannerPage = () => {
  const [activeScanId, setActiveScanId] = useState<string | null>(null);

  // ── INTEGRATION: Socket.io live progress ──────────────────────────────────
  // This hook connects to your FastAPI Socket.io server.
  // It subscribes to scan_progress and scan_complete events.
  const { progress, status, message } = useScanProgress(activeScanId);

  // ── INTEGRATION: React Query fetch scan history ───────────────────────────
  // const { data: history = [] } = useScanHistory();
  const history = MOCK_HISTORY; // ← remove once backend is ready

  return (
    <div className=" padding: '32px', display: 'flex', flexDirection: 'column', gap: 28, fontFamily: 'Segoe UI', system-ui, sans-serif ">

      {/* Header */}
      <div>
        <h1 className=" fontSize: 22, fontWeight: 700, margin: '0 0 4px', color: '#f1f5f9' ">
          Scanner
        </h1>
        <p className=" fontSize: 13, color: '#475569', margin: 0 ">
          Configure and run quantum-proof TLS scans
        </p>
      </div>

      <div className=" display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 ">

        {/* ── Left: Scan form + live progress ─────── */}
        <div className=" display: 'flex', flexDirection: 'column', gap: 20 ">

          {/* Scan config form */}
          <div className=" background: '#0a0d14', border: '1px solid #1e293b', borderRadius: 8, padding: '24px' ">
            <h2 className=" fontSize: 14, fontWeight: 600, color: '#f1f5f9', margin: '0 0 20px' ">
              New Scan
            </h2>

            {/* ── INTEGRATION: ScanConfigForm uses RHF + Zod + useStartScan ── */}
            {/* When submitted, it calls scannerAPI.startScan() and returns a scanId */}
            {/* Pass that scanId to setActiveScanId to start WebSocket tracking  */}
            <ScanConfigForm />

            {/* NOTE: To wire up live tracking, modify ScanConfigForm's onSuccess: */}
            {/* mutate(data, { onSuccess: (job) => setActiveScanId(job.id) })      */}
          </div>

          {/* Live progress — shown when a scan is active */}
          {activeScanId && (
            <div className="
              background: '#0a0d14', border: '1px solid rgba(0,212,255,0.3)',
              borderRadius: 8, padding: '24px',
            ">
              <div className=" display: 'flex', justifyContent: 'space-between', marginBottom: 16 ">
                <h2 className=" fontSize: 14, fontWeight: 600, color: '#f1f5f9', margin: 0 ">
                  Live Progress
                </h2>
                <button
                  onClick={() => setActiveScanId(null)}
                  className="fontSize: 11, color: '#475569', background: 'none', border: 'none', cursor: 'pointer' "
                >
                  ✕ dismiss
                </button>
              </div>

              <ProgressBar value={progress} status={status} />

              {message && (
                <div className=" fontSize: 12, color: '#64748b', marginTop: 10, fontFamily: 'monospace' ">
                  › {message}
                </div>
              )}

              {status === 'completed' && (
                <div className=" marginTop: 14, padding: '10px 14px', background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.3)', borderRadius: 6, fontSize: 13, color: '#10B981' ">
                  ✓ Scan complete — view results in Reports
                </div>
              )}
              {status === 'failed' && (
                <div className=" marginTop: 14, padding: '10px 14px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 6, fontSize: 13, color: '#ef4444' ">
                  ✗ Scan failed — check target and retry
                </div>
              )}
            </div>
          )}
        </div>

        {/* ── Right: Scan history ──────────────────── */}
        <div className=" background: '#0a0d14', border: '1px solid #1e293b', borderRadius: 8, padding: '24px' ">
          <h2 className=" fontSize: 14, fontWeight: 600, color: '#f1f5f9', margin: '0 0 16px' ">
            Scan History
          </h2>
          <div className=" display: 'flex', flexDirection: 'column', gap: 8 ">
            {history.map(scan => (
              <HistoryRow
                key={scan.id}
                scan={scan}
                // Click a completed scan to track it (for rerunning or viewing)
                onSelect={(id) => setActiveScanId(id)}
              />
            ))}
          </div>
        </div>

      </div>
    </div>
  );
};