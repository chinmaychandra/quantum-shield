import { RiskLevel } from '../../types';

const colors: Record<RiskLevel, string> = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high:     'bg-orange-100 text-orange-700 border-orange-200',
  medium:   'bg-yellow-100 text-yellow-700 border-yellow-200',
  low:      'bg-green-100 text-green-700 border-green-200',
};

export const RiskBadge = ({ level }: { level: RiskLevel }) => (
  <span className={`px-2 py-1 text-xs font-semibold rounded border ${colors[level]}`}>
    {level.toUpperCase()}
  </span>
);