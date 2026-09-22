import React, { useState } from 'react';
import { Shield, Radio, Flame, LogOut, User as UserIcon, RefreshCw, Zap, Bell, CheckCircle } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useWebSocket } from '../../context/WebSocketContext';
import { Badge } from '../common/Badge';

export const Navbar: React.FC = () => {
  const { user, logout, loginAsRole } = useAuth();
  const { isConnected, triggerSimulatedAlert, scanProgress } = useWebSocket();
  const [isSimulating, setIsSimulating] = useState(false);
  const [simSuccess, setSimSuccess] = useState(false);

  const handleSimulate = async () => {
    setIsSimulating(true);
    await triggerSimulatedAlert();
    setIsSimulating(false);
    setSimSuccess(true);
    setTimeout(() => setSimSuccess(false), 3000);
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-[#070a12]/90 backdrop-blur-md">
      <div className="flex h-16 items-center justify-between px-6">
        {/* Left: Brand & Status */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-tr from-cyan-600 to-cyan-400 text-slate-950 font-bold shadow-lg shadow-cyan-500/20">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-extrabold tracking-wider text-white font-mono">SENTINEL-X</span>
                <span className="rounded bg-cyan-950/80 px-1.5 py-0.5 text-[10px] font-bold text-cyan-400 border border-cyan-500/30">
                  PHASE 1
                </span>
                <span className="hidden sm:inline-block rounded bg-amber-950/80 px-1.5 py-0.5 text-[10px] font-bold text-amber-400 border border-amber-500/40 font-mono">
                  SIMULATION MODE
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono">UNIFIED SECURITY PLATFORM</p>
            </div>
          </div>

          <div className="h-6 w-px bg-slate-800 ml-2" />

          {/* WebSocket Status Indicator */}
          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900/60 border border-slate-800 text-xs font-mono" title="Phase-1 WebSocket streaming synthetic SOC telemetry and incident events">
            <Radio className={`h-3.5 w-3.5 ${isConnected ? 'text-emerald-400 animate-pulse' : 'text-amber-500'}`} />
            <span className={isConnected ? 'text-emerald-400' : 'text-amber-500'}>
              {isConnected ? 'WS: SIMULATED SOC FEED' : 'CONNECTING...'}
            </span>
          </div>

          {/* Scan In-Progress Bar */}
          {scanProgress && (
            <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-cyan-950/60 border border-cyan-500/40 text-xs font-mono text-cyan-300 animate-pulse">
              <RefreshCw className="h-3.5 w-3.5 animate-spin text-cyan-400" />
              <span>SIMULATED SCAN: {scanProgress.progress}% [{scanProgress.status}]</span>
            </div>
          )}
        </div>

        {/* Right: Role switcher, Incident simulator & Profile */}
        <div className="flex items-center gap-3">
          {/* Quick Demo Role Switcher */}
          <div className="hidden lg:flex items-center gap-1 bg-slate-900/80 p-1 rounded-lg border border-slate-800 text-xs font-mono">
            <span className="text-slate-400 px-2 text-[11px]">ROLE:</span>
            <button
              onClick={() => loginAsRole('admin')}
              className={`px-2.5 py-1 rounded transition-all ${
                user?.role === 'admin'
                  ? 'bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              ADMIN
            </button>
            <button
              onClick={() => loginAsRole('analyst')}
              className={`px-2.5 py-1 rounded transition-all ${
                user?.role === 'analyst'
                  ? 'bg-amber-500/20 text-amber-300 font-semibold border border-amber-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              ANALYST
            </button>
            <button
              onClick={() => loginAsRole('auditor')}
              className={`px-2.5 py-1 rounded transition-all ${
                user?.role === 'auditor'
                  ? 'bg-purple-500/20 text-purple-300 font-semibold border border-purple-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              AUDITOR
            </button>
          </div>

          {/* Simulate Live Attack Alert */}
          <button
            onClick={handleSimulate}
            disabled={isSimulating}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all shadow-md ${
              simSuccess
                ? 'bg-emerald-600 text-white border border-emerald-400'
                : 'bg-red-950/70 hover:bg-red-900/80 text-red-300 border border-red-700/60 hover:border-red-500 shadow-red-950/50'
            }`}
            title="Inject a live simulated threat incident across WebSockets"
          >
            {simSuccess ? (
              <>
                <CheckCircle className="h-3.5 w-3.5 text-white" />
                <span>ALERT BROADCAST!</span>
              </>
            ) : (
              <>
                <Zap className={`h-3.5 w-3.5 text-red-400 ${isSimulating ? 'animate-spin' : ''}`} />
                <span>SIMULATE ATTACK</span>
              </>
            )}
          </button>

          {/* User Profile */}
          <div className="flex items-center gap-3 pl-3 border-l border-slate-800">
            <div className="flex items-center gap-2">
              <div className="h-8 w-8 rounded-full overflow-hidden border border-slate-700 bg-slate-800 flex items-center justify-center">
                {user?.avatar_url ? (
                  <img src={user.avatar_url} alt={user.full_name} className="h-full w-full object-cover" />
                ) : (
                  <UserIcon className="h-4 w-4 text-slate-400" />
                )}
              </div>
              <div className="hidden sm:block text-left">
                <p className="text-xs font-medium text-white line-clamp-1">{user?.full_name || 'Operator'}</p>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <Badge size="sm" variant={user?.role === 'admin' ? 'critical' : user?.role === 'analyst' ? 'warning' : 'purple'}>
                    {user?.role?.toUpperCase() || 'ANALYST'}
                  </Badge>
                </div>
              </div>
            </div>

            <button
              onClick={logout}
              className="p-2 rounded-lg text-slate-400 hover:text-red-400 hover:bg-slate-800/80 transition-all"
              title="Sign Out"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
