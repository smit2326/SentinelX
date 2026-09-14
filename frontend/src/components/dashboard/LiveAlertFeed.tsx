import React from 'react';
import { AlertTriangle, Clock, ArrowRight, ShieldAlert, CheckCircle } from 'lucide-react';
import { Alert } from '../../types';
import { Badge } from '../common/Badge';

interface LiveAlertFeedProps {
  alerts: Alert[];
  onSelectAlert: (alert: Alert) => void;
  onAcknowledge: (alertId: number) => void;
}

export const LiveAlertFeed: React.FC<LiveAlertFeedProps> = ({
  alerts,
  onSelectAlert,
  onAcknowledge,
}) => {
  return (
    <div className="cyber-card p-6 rounded-2xl flex flex-col justify-between h-full">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-red-400 animate-pulse" />
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
            LIVE INCIDENT TELEMETRY
          </span>
        </div>
        <span className="text-[11px] font-mono text-slate-400">
          Showing {alerts.length} Incidents
        </span>
      </div>

      <div className="space-y-2.5 overflow-y-auto max-h-[380px] pr-1">
        {alerts.length === 0 ? (
          <div className="text-center py-12 text-slate-400 font-mono text-xs">
            <CheckCircle className="h-8 w-8 text-emerald-400 mx-auto mb-2 opacity-60" />
            No active alerts detected. All security perimeters nominal.
          </div>
        ) : (
          alerts.map((alert) => {
            const isResolved = alert.status === 'RESOLVED';
            return (
              <div
                key={alert.id}
                className={`p-3.5 rounded-xl border transition-all duration-200 ${
                  isResolved
                    ? 'bg-slate-900/40 border-slate-800/80 text-slate-400'
                    : alert.severity === 'CRITICAL'
                    ? 'bg-red-950/40 border-red-500/40 text-slate-200 shadow-sm shadow-red-950/40'
                    : 'bg-slate-900/80 border-slate-800 text-slate-200 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 cursor-pointer" onClick={() => onSelectAlert(alert)}>
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge size="sm" variant={alert.severity.toLowerCase() as any}>
                        {alert.severity}
                      </Badge>
                      <span className="text-[10px] font-mono uppercase text-slate-400 px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800">
                        {alert.category}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400 flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {new Date(alert.created_at).toLocaleTimeString()}
                      </span>
                    </div>

                    <p className="mt-1.5 text-xs font-bold font-mono text-white hover:text-cyan-400 transition-colors line-clamp-1">
                      {alert.title}
                    </p>
                    <p className="mt-1 text-[11px] text-slate-400 line-clamp-1 font-mono">
                      SRC: <span className="text-cyan-300">{alert.source_ip || 'N/A'}</span> → DST: <span className="text-amber-300">{alert.destination_ip || 'N/A'}</span> ({alert.protocol})
                    </p>
                  </div>

                  <div className="flex items-center gap-1.5">
                    {!isResolved && (
                      <button
                        onClick={() => onAcknowledge(alert.id)}
                        className="px-2.5 py-1 text-[10px] font-mono font-bold rounded bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-500/40 transition-all"
                        title="Mark Resolved"
                      >
                        RESOLVE
                      </button>
                    )}
                    <button
                      onClick={() => onSelectAlert(alert)}
                      className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-all"
                      title="Inspect Incident"
                    >
                      <ArrowRight className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
