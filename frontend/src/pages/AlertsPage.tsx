import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Search,
  Filter,
  Radio,
  Zap,
  Clock,
  ShieldCheck,
  CheckCircle,
  X,
  RefreshCw,
  Terminal,
  UserCheck
} from 'lucide-react';
import { api } from '../services/api';
import { Alert, AlertStats } from '../types';
import { useAuth } from '../context/AuthContext';
import { useWebSocket } from '../context/WebSocketContext';
import { Badge } from '../components/common/Badge';

export const AlertsPage: React.FC = () => {
  const { isAnalyst, user } = useAuth();
  const { liveAlerts, triggerSimulatedAlert } = useWebSocket();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<AlertStats | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [search, setSearch] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);

  const fetchAlerts = async () => {
    try {
      setIsLoading(true);
      const [alertsRes, statsRes] = await Promise.all([
        api.get('/alerts?limit=100'),
        api.get('/alerts/stats')
      ]);
      setAlerts(alertsRes.data);
      setStats(statsRes.data);
    } catch (e) {
      console.error('Error fetching alerts:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [liveAlerts]);

  const handleUpdateStatus = async (alertId: number, newStatus: string) => {
    try {
      const res = await api.put(`/alerts/${alertId}/status`, {
        status: newStatus,
        assigned_to: user?.full_name
      });
      setAlerts(alerts.map(a => a.id === alertId ? res.data : a));
      if (selectedAlert?.id === alertId) {
        setSelectedAlert(res.data);
      }
      await fetchAlerts();
    } catch (e) {
      console.error('Failed to update alert status:', e);
    }
  };

  const handleSimulate = async () => {
    setIsSimulating(true);
    await triggerSimulatedAlert();
    setTimeout(async () => {
      await fetchAlerts();
      setIsSimulating(false);
    }, 500);
  };

  const filteredAlerts = alerts.filter(a => {
    const matchesSearch =
      a.title.toLowerCase().includes(search.toLowerCase()) ||
      a.description.toLowerCase().includes(search.toLowerCase()) ||
      (a.source_ip || '').toLowerCase().includes(search.toLowerCase()) ||
      (a.destination_ip || '').toLowerCase().includes(search.toLowerCase()) ||
      a.category.toLowerCase().includes(search.toLowerCase());

    if (!matchesSearch) return false;
    if (severityFilter !== 'all' && a.severity !== severityFilter.toUpperCase()) return false;
    if (statusFilter !== 'all' && a.status !== statusFilter.toUpperCase()) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-red-400 animate-pulse" />
            INCIDENT RESPONSE &amp; TRAFFIC MONITORING
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Phase-1 Emulation: Simulated traffic anomaly generation, synthetic brute-force alerts, and demo RTSP stream hijacking forensics.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {isAnalyst && (
            <button
              onClick={handleSimulate}
              disabled={isSimulating}
              className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-700/60 text-xs font-mono font-bold transition-all shadow-md shadow-red-950/50"
            >
              <Zap className={`h-4 w-4 text-red-400 ${isSimulating ? 'animate-spin' : ''}`} />
              <span>INJECT SIMULATED ATTACK</span>
            </button>
          )}
          <button
            onClick={fetchAlerts}
            className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-all"
            title="Refresh Alert Queue"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Phase-1 Simulation Scope Notice */}
      <div className="flex items-center justify-between gap-3 px-4 py-2.5 rounded-xl bg-slate-900/80 border border-slate-800 text-xs font-mono">
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 rounded bg-amber-950/80 text-amber-400 font-bold border border-amber-500/40 text-[10px]">
            SYNTHETIC TELEMETRY
          </span>
          <span className="text-slate-300 text-[11px]">
            All incidents in this queue are simulated scenarios generated to evaluate risk correlation and analyst triage.
          </span>
        </div>
        <span className="text-[10px] text-slate-400 hidden sm:inline">
          LIVE TAP / SPAN MIRRORING DEFERRED TO PHASE 2
        </span>
      </div>

      {/* KPI Stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
          <div className="cyber-card p-3 rounded-xl border border-red-500/40 bg-red-950/20 text-center">
            <span className="text-[10px] text-red-400 uppercase block">Active Critical</span>
            <span className="text-xl font-bold text-red-400">{stats.critical_active}</span>
          </div>
          <div className="cyber-card p-3 rounded-xl border border-amber-500/30 text-center bg-amber-950/20">
            <span className="text-[10px] text-amber-400 uppercase block">Active High</span>
            <span className="text-xl font-bold text-amber-400">{stats.high_active}</span>
          </div>
          <div className="cyber-card p-3 rounded-xl border border-slate-800 text-center">
            <span className="text-[10px] text-slate-400 uppercase block">Under Investigation</span>
            <span className="text-xl font-bold text-cyan-400">{stats.investigating}</span>
          </div>
          <div className="cyber-card p-3 rounded-xl border border-emerald-500/30 text-center bg-emerald-950/20">
            <span className="text-[10px] text-emerald-400 uppercase block">Resolved Today</span>
            <span className="text-xl font-bold text-emerald-400">{stats.resolved_today}</span>
          </div>
        </div>
      )}

      {/* Search & Filters */}
      <div className="cyber-card p-4 rounded-xl flex flex-col md:flex-row items-center justify-between gap-4 font-mono text-xs">
        <div className="relative w-full md:w-80">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search IP, category, title..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
          />
        </div>

        <div className="flex items-center gap-2 flex-wrap w-full md:w-auto">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Statuses</option>
            <option value="active">Active</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="dismissed">Dismissed</option>
          </select>
        </div>
      </div>

      {/* Alerts Grid & Detail Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Alerts List (7 cols) */}
        <div className="lg:col-span-7 space-y-3 max-h-[700px] overflow-y-auto pr-1">
          {filteredAlerts.length === 0 ? (
            <div className="cyber-card p-12 text-center text-slate-400 font-mono text-xs rounded-2xl">
              No matching alerts found in current filter.
            </div>
          ) : (
            filteredAlerts.map((alert) => {
              const isSelected = selectedAlert?.id === alert.id;
              return (
                <div
                  key={alert.id}
                  onClick={() => setSelectedAlert(alert)}
                  className={`cyber-card p-4 rounded-xl border transition-all cursor-pointer ${
                    isSelected
                      ? 'border-cyan-400 bg-slate-900/90 shadow-md shadow-cyan-950/50'
                      : 'hover:border-slate-700 bg-slate-900/50'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge size="sm" variant={alert.severity.toLowerCase() as any}>
                          {alert.severity}
                        </Badge>
                        <span className="text-[10px] font-mono uppercase text-amber-400 px-1.5 py-0.5 rounded bg-amber-950/60 border border-amber-500/40">
                          SIMULATED
                        </span>
                        <span className="text-[10px] font-mono text-slate-400 px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800">
                          {alert.category}
                        </span>
                        <span className="text-[10px] font-mono text-slate-400 flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {new Date(alert.created_at).toLocaleTimeString()}
                        </span>
                      </div>

                      <h3 className="text-xs font-bold font-mono text-white mt-2">
                        {alert.title}
                      </h3>

                      <p className="text-[11px] font-mono text-slate-400 mt-1">
                        SRC: <span className="text-cyan-300">{alert.source_ip || 'Internal'}</span> → DST: <span className="text-amber-300">{alert.destination_ip || 'N/A'}</span> ({alert.protocol})
                      </p>
                    </div>

                    <Badge size="sm" variant={alert.status === 'RESOLVED' ? 'success' : alert.status === 'INVESTIGATING' ? 'warning' : 'critical'}>
                      {alert.status}
                    </Badge>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Selected Alert Forensics Panel (5 cols) */}
        <div className="lg:col-span-5">
          {selectedAlert ? (
            <div className="cyber-card p-6 rounded-2xl border border-slate-700 sticky top-20 font-mono text-xs space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Badge size="md" variant={selectedAlert.severity.toLowerCase() as any}>
                    {selectedAlert.severity} PRIORITY
                  </Badge>
                  <span className="text-[10px] font-mono text-amber-400 px-1.5 py-0.5 rounded bg-amber-950/70 border border-amber-500/40">
                    SIMULATED SCENARIO
                  </span>
                </div>
                <span className="text-slate-400 text-[11px]">
                  ID #{selectedAlert.id}
                </span>
              </div>

              <div>
                <h2 className="text-sm font-bold text-white">
                  {selectedAlert.title}
                </h2>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Category: {selectedAlert.category}
                </p>
              </div>

              <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 text-slate-300 leading-relaxed text-[11px]">
                {selectedAlert.description}
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-[10px] text-slate-400 block uppercase">Source IP</span>
                  <span className="font-bold text-cyan-400">{selectedAlert.source_ip || 'Internal'}</span>
                </div>
                <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-[10px] text-slate-400 block uppercase">Destination IP</span>
                  <span className="font-bold text-amber-400">{selectedAlert.destination_ip || 'N/A'}</span>
                </div>
              </div>

              {selectedAlert.raw_packet_hex && (
                <div>
                  <div className="flex items-center justify-between text-slate-400 mb-1">
                    <div className="flex items-center gap-1.5">
                      <Terminal className="h-3.5 w-3.5 text-emerald-400" />
                      <span className="text-[10px] uppercase font-bold">SYNTHETIC PCAP CAPTURE (HEX DUMP)</span>
                    </div>
                    <span className="text-[9px] text-amber-400 font-mono">DEMO PAYLOAD</span>
                  </div>
                  <pre className="p-2.5 rounded-xl bg-black text-[10px] font-mono text-emerald-400 border border-slate-800 overflow-x-auto whitespace-pre-wrap">
                    {selectedAlert.raw_packet_hex}
                  </pre>
                </div>
              )}

              {/* Triage Actions */}
              {isAnalyst && (
                <div className="pt-3 border-t border-slate-800 space-y-2">
                  <span className="text-[10px] uppercase text-slate-400 block">INCIDENT ACTION DISPATCH</span>
                  <div className="grid grid-cols-3 gap-2">
                    <button
                      onClick={() => handleUpdateStatus(selectedAlert.id, 'INVESTIGATING')}
                      className="py-2 rounded-lg bg-amber-950 hover:bg-amber-900 text-amber-300 border border-amber-500/40 font-bold text-[10px] transition-all"
                    >
                      INVESTIGATE
                    </button>
                    <button
                      onClick={() => handleUpdateStatus(selectedAlert.id, 'RESOLVED')}
                      className="py-2 rounded-lg bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-500/40 font-bold text-[10px] transition-all"
                    >
                      RESOLVE
                    </button>
                    <button
                      onClick={() => handleUpdateStatus(selectedAlert.id, 'DISMISSED')}
                      className="py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 border border-slate-700 font-bold text-[10px] transition-all"
                    >
                      DISMISS
                    </button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="cyber-card p-12 rounded-2xl border border-slate-800 text-center text-slate-400 font-mono text-xs">
              <ShieldCheck className="h-10 w-10 text-cyan-400/40 mx-auto mb-3" />
              Select an incident from the stream to inspect raw packet bytes, protocol metadata, and assign analyst remediation.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
