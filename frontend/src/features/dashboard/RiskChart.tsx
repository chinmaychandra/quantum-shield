import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell, Legend
} from 'recharts';
import { RiskDistribution } from '../../types';

const COLORS = {
  critical: '#EF4444',
  high:     '#F97316',
  medium:   '#F59E0B',
  low:      '#10B981',
};

export const RiskChart = ({ data }: { data: RiskDistribution[] }) => (
  <div className="bg-white rounded-lg border p-6">
    <h3 className="text-lg font-semibold mb-4">Risk Distribution</h3>
    <ResponsiveContainer width="100%" height={280}>
      <BarChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
        <XAxis dataKey="category" />
        <YAxis />
        <Tooltip
          formatter={(value) => [value, 'Assets']}
          labelFormatter={(label) => `Risk Level: ${label}`}
        />
        <Bar dataKey="count" radius={[6, 6, 0, 0]}>
          {data.map((entry) => (
            <Cell
              key={entry.category}
              fill={COLORS[entry.category]}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  </div>
);

// ─── USAGE IN DashboardPage ──────────────────────
// const data = [
//   { category: 'critical', count: 4 },
//   { category: 'high', count: 12 },
//   { category: 'medium', count: 28 },
//   { category: 'low', count: 56 },
// ];

{/* <RiskChart data={data} /> */}