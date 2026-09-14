import React from 'react';
import { ShieldAlert, Activity, CheckCircle2 } from 'lucide-react';

interface RiskGaugeProps {
  score: number;
  grade: string;
  level: string;
  criticalAssets: number;
  quarantinedCount: number;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  grade,
  level,
  criticalAssets,
  quarantinedCount,
}) => {
  // SVG gauge calculation
  const radius = 80;
  const strokeWidth = 14;
  const circumference = 2 * Math.PI * radius;
  // Use a semi-circle or 240-degree arc
  const arcLength = circumference * 0.75;
  const strokeDashoffset = arcLength - (arcLength * Math.min(100, Math.max(0, score))) / 100;

  const getColor = (s: number) => {
    if (s >= 75) return { stroke: '#FF2E54', text: 'text-red-400', glow: 'rgba(255, 46, 84, 0.4)' };
    if (s >= 50) return { stroke: '#FFB800', text: 'text-amber-400', glow: 'rgba(255, 184, 0, 0.4)' };
    if (s >= 25) return { stroke: '#00F0FF', text: 'text-cyan-400', glow: 'rgba(0, 240, 255, 0.4)' };
    return { stroke: '#00FF66', text: 'text-emerald-400', glow: 'rgba(0, 255, 102, 0.4)' };
  };

  const theme = getColor(score);

  return (
    <div className="cyber-card p-6 rounded-2xl flex flex-col items-center justify-between relative overflow-hidden h-full">
      <div className="w-full flex items-center justify-between">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
            GLOBAL THREAT INDEX
          </span>
          <p className="text-xs text-slate-400 mt-0.5">Automated Multi-Vector Risk Engine</p>
        </div>
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300">
          <Activity className="h-3 w-3 text-cyan-400 animate-pulse" />
          <span>REALTIME</span>
        </div>
      </div>

      {/* SVG Arc Gauge */}
      <div className="relative my-4 flex items-center justify-center">
        <svg className="w-48 h-48 transform -rotate-[135deg]" viewBox="0 0 200 200">
          {/* Background track */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="transparent"
            stroke="#1a2642"
            strokeWidth={strokeWidth}
            strokeDasharray={arcLength}
            strokeDashoffset={0}
            strokeLinecap="round"
          />
          {/* Active progress arc */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="transparent"
            stroke={theme.stroke}
            strokeWidth={strokeWidth}
            strokeDasharray={arcLength}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{
              transition: 'stroke-dashoffset 1s ease-in-out, stroke 0.5s ease',
              filter: `drop-shadow(0 0 8px ${theme.glow})`,
            }}
          />
        </svg>

        {/* Center score readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-4xl font-black font-mono tracking-tight text-white">
            {score.toFixed(1)}
          </span>
          <div className="flex items-center gap-1.5 mt-1">
            <span className={`text-xs font-extrabold font-mono uppercase px-2 py-0.5 rounded bg-slate-900/90 border border-slate-700 ${theme.text}`}>
              GRADE {grade}
            </span>
          </div>
          <span className="text-[10px] font-mono uppercase text-slate-400 mt-1">
            {level} RISK
          </span>
        </div>
      </div>

      {/* Lower Metrics footer */}
      <div className="w-full grid grid-cols-2 gap-2 pt-3 border-t border-slate-800/80 text-center font-mono">
        <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
          <span className="text-[10px] text-slate-400 block uppercase">Critical Assets</span>
          <span className="text-sm font-bold text-red-400">{criticalAssets} Nodes</span>
        </div>
        <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
          <span className="text-[10px] text-slate-400 block uppercase">Quarantined</span>
          <span className="text-sm font-bold text-amber-400">{quarantinedCount} Isolated</span>
        </div>
      </div>
    </div>
  );
};
