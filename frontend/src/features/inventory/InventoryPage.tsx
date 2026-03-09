

import { useInventory } from './hooks/useInventory';
import { InventoryTable } from './InventoryTable';
import { BulkUpload } from './BulkUpload';
import { Asset } from '../../types';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';
import { ErrorMessage } from '../../components/shared/ErrorMessage';

// ── Component ─────────────────────────────────────────────────────────────────
export const InventoryPage = () => {

  // ── INTEGRATION: uncomment to use real API ────────────────────────────────
  const { data, isLoading, error } = useInventory();
  if (isLoading) {
  return (
    <LoadingSpinner
      size="lg"
      message="Fetching inventory assets..."
    />
  );
}
  if (error) return <ErrorMessage message="Failed to load inventory" />;
  const assets = data ?? [];


  const riskCounts = {
    critical: assets.filter(a => a.riskLevel === 'critical').length,
    high: assets.filter(a => a.riskLevel === 'high').length,
    medium: assets.filter(a => a.riskLevel === 'medium').length,
    low: assets.filter(a => a.riskLevel === 'low').length,
  };

  return (
    <div style={{ padding: '32px', display: 'flex', flexDirection: 'column', gap: 24, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>

      {/* Header */}
      <div className="display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' ">
        <div>
          <h1 className=" fontSize: 22, fontWeight: 700, margin: '0 0 4px', color: '#f1f5f9' ">
            Asset Inventory
          </h1>
          <p className=" fontSize: 13, color: '#475569', margin: 0 ">
            {assets.length} total assets monitored
          </p>
        </div>
        {/* ── BulkUpload integrates PapaParse + your API ── */}
        <BulkUpload />
      </div>

      {/* Risk summary pills */}
      <div className="display: 'flex', gap: 10, flexWrap: 'wrap' ">
        {([
          { label: 'Critical', count: riskCounts.critical, color: '#EF4444' },
          { label: 'High', count: riskCounts.high, color: '#F97316' },
          { label: 'Medium', count: riskCounts.medium, color: '#F59E0B' },
          { label: 'Low', count: riskCounts.low, color: '#10B981' },
        ] as const).map(item => (
          <div key={item.label}  className=" padding: '6px 14px', borderRadius: 20,
            background: `${item.color}15` border: `1px solid ${item.color}30`,
            fontSize: 12, color: item.color, fontWeight: 600,
            display: 'flex', alignItems: 'center', gap: 6,
          ">
            <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />
            {item.label}: {item.count}
          </div>
        ))}
      </div>

      {/* ── InventoryTable integrates TanStack Table ─────── */}
      <div className=" background: '#0a0d14' border: '1px solid #1e293b' borderRadius: 8 overflow: 'hidden' ">
        <InventoryTable data={assets} />
      </div>

    </div>
  );
};