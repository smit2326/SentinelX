import React from 'react';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success' | 'warning' | 'purple' | 'neutral';
  size?: 'sm' | 'md' | 'lg';
  pulse?: boolean;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'neutral',
  size = 'sm',
  pulse = false,
}) => {
  const variantStyles = {
    critical: 'bg-red-500/15 text-red-400 border-red-500/40 shadow-red-500/20',
    high: 'bg-amber-500/15 text-amber-400 border-amber-500/40 shadow-amber-500/20',
    medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40 shadow-yellow-500/20',
    low: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/40 shadow-cyan-500/20',
    info: 'bg-blue-500/15 text-blue-400 border-blue-500/40 shadow-blue-500/20',
    success: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40 shadow-emerald-500/20',
    warning: 'bg-orange-500/15 text-orange-400 border-orange-500/40 shadow-orange-500/20',
    purple: 'bg-purple-500/15 text-purple-400 border-purple-500/40 shadow-purple-500/20',
    neutral: 'bg-slate-800 text-slate-300 border-slate-700 shadow-slate-900/40',
  };

  const sizeStyles = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-xs font-semibold',
    lg: 'px-3 py-1.5 text-sm font-semibold',
  };

  const strChild = typeof children === 'string' ? children.toUpperCase() : '';
  let activeVariant = variant;
  if (strChild === 'CRITICAL' || strChild === 'QUARANTINED' || strChild === 'FAILED' || strChild === 'BLOCKED') activeVariant = 'critical';
  else if (strChild === 'HIGH' || strChild === 'WARNING') activeVariant = 'high';
  else if (strChild === 'MEDIUM') activeVariant = 'medium';
  else if (strChild === 'LOW') activeVariant = 'low';
  else if (strChild === 'ONLINE' || strChild === 'SUCCESS' || strChild === 'RESOLVED' || strChild === 'MITIGATED') activeVariant = 'success';
  else if (strChild === 'ACTIVE' || strChild === 'INVESTIGATING' || strChild === 'OPEN') activeVariant = 'warning';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-mono border transition-all ${
        variantStyles[activeVariant]
      } ${sizeStyles[size]} ${pulse ? 'animate-pulse' : ''}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${
        activeVariant === 'critical' ? 'bg-red-400' :
        activeVariant === 'high' || activeVariant === 'warning' ? 'bg-amber-400' :
        activeVariant === 'success' ? 'bg-emerald-400' :
        activeVariant === 'low' ? 'bg-cyan-400' : 'bg-slate-400'
      }`} />
      {children}
    </span>
  );
};
