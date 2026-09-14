import React from 'react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ReactNode;
  trend?: {
    value: string;
    isPositive: boolean;
  };
  color?: 'cyan' | 'red' | 'green' | 'amber' | 'purple';
  onClick?: () => void;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  trend,
  color = 'cyan',
  onClick,
}) => {
  const colorGradients = {
    cyan: 'from-cyan-500/10 to-transparent border-cyan-500/30 text-cyan-400',
    red: 'from-red-500/10 to-transparent border-red-500/30 text-red-400',
    green: 'from-emerald-500/10 to-transparent border-emerald-500/30 text-emerald-400',
    amber: 'from-amber-500/10 to-transparent border-amber-500/30 text-amber-400',
    purple: 'from-purple-500/10 to-transparent border-purple-500/30 text-purple-400',
  };

  const iconBg = {
    cyan: 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30',
    red: 'bg-red-500/15 text-red-400 border border-red-500/30',
    green: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
    amber: 'bg-amber-500/15 text-amber-400 border border-amber-500/30',
    purple: 'bg-purple-500/15 text-purple-400 border border-purple-500/30',
  };

  return (
    <div
      onClick={onClick}
      className={`cyber-card p-5 rounded-xl relative overflow-hidden transition-all duration-300 hover:border-slate-600 ${
        onClick ? 'cursor-pointer hover:scale-[1.01]' : ''
      }`}
    >
      <div className={`absolute top-0 left-0 right-0 h-1 bg-gradient-to-r ${colorGradients[color]}`} />
      
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</p>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-bold tracking-tight text-white font-mono">{value}</span>
            {trend && (
              <span
                className={`text-xs font-medium font-mono px-1.5 py-0.5 rounded ${
                  trend.isPositive ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'
                }`}
              >
                {trend.value}
              </span>
            )}
          </div>
          {subtitle && <p className="mt-1 text-xs text-slate-400">{subtitle}</p>}
        </div>
        <div className={`p-3 rounded-lg ${iconBg[color]}`}>
          {icon}
        </div>
      </div>
    </div>
  );
};
