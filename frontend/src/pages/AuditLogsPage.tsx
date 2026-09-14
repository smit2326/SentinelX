import React, { useState, useEffect } from 'react';
import {
  History,
  Search,
  Filter,
  RefreshCw,
  ShieldAlert,
  Clock,
  User as UserIcon,
  X,
  Code
} from 'lucide-react';
import { api } from '../services/api';
import { AuditLog } from '../types';
import { Badge } from '../components/common/Badge';

export const AuditLogsPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [search, setSearch] = useState<string>('');
  const [actionFilter, setActionFilter] = useState<string>('all');
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);

  const fetchLogs = async () => {
    try {
      setIsLoading(true);
      const res = await api.get('/audit-logs?limit=150');
      setLogs(res.data);
    } catch (e) {
      console.error('Failed to fetch audit logs:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const filteredLogs = logs.filter(l => {
    const matchesSearch =
      l.action.toLowerCase().includes(search.toLowerCase()) ||
      l.actor_email.toLowerCase().includes(search.toLowerCase()) ||
      l.resource.toLowerCase().includes(search.toLowerCase()) ||
      l.ip_address.includes(search);

    if (!matchesSearch) return false;
    if (actionFilter !== 'all' && l.action !== actionFilter) return false;
    return true;
  });

  const uniqueActions = Array.from(new Set(logs.map(l => l.action)));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center gap-2">
            <History className="h-5 w-5 text-cyan-400" />
            SECURITY AUDIT TRAIL &amp; COMPLIANCE LOGS
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Tamper-resistant ledger recording authentication, scan triggers, quarantine changes, and configuration updates.
          </p>
        </div>

        <button
          onClick={fetchLogs}
          className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-all self-start md:self-auto"
          title="Refresh Logs"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {/* Search & Filters */}
      <div className="cyber-card p-4 rounded-xl flex flex-col md:flex-row items-center justify-between gap-4 font-mono text-xs">
        <div className="relative w-full md:w-80">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search actor, action, resource, IP..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
          />
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Actions ({uniqueActions.length})</option>
            {uniqueActions.map((act) => (
              <option key={act} value={act}>{act}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Logs Table */}
      <div className="cyber-card rounded-2xl overflow-hidden border border-slate-800">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 uppercase text-[10px]">
              <tr>
                <th className="py-3.5 px-4">Timestamp (UTC)</th>
                <th className="py-3.5 px-4">Actor</th>
                <th className="py-3.5 px-4">Action</th>
                <th className="py-3.5 px-4">Resource Target</th>
                <th className="py-3.5 px-4">IP Address</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400 font-mono">
                    No matching audit records found.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr
                    key={log.id}
                    className="hover:bg-slate-900/40 transition-colors cursor-pointer"
                    onClick={() => setSelectedLog(log)}
                  >
                    <td className="py-3.5 px-4 text-slate-400 flex items-center gap-1.5 whitespace-nowrap">
                      <Clock className="h-3 w-3 text-cyan-400" />
                      {new Date(log.timestamp).toLocaleString()}
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white truncate max-w-[150px]">{log.actor_email}</span>
                        <Badge size="sm" variant={log.actor_role === 'admin' ? 'critical' : log.actor_role === 'analyst' ? 'warning' : 'purple'}>
                          {log.actor_role}
                        </Badge>
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <span className="font-bold text-cyan-300 px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
                        {log.action}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 text-slate-300">
                      <span>{log.resource}</span>
                      {log.resource_id && (
                        <span className="text-slate-400 ml-1">#{log.resource_id}</span>
                      )}
                    </td>

                    <td className="py-3.5 px-4 text-slate-400">
                      {log.ip_address}
                    </td>

                    <td className="py-3.5 px-4">
                      <Badge size="sm" variant={log.status === 'SUCCESS' ? 'success' : 'critical'}>
                        {log.status}
                      </Badge>
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => setSelectedLog(log)}
                        className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
                      >
                        <Code className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* METADATA JSON INSPECTOR MODAL */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="cyber-card w-full max-w-lg rounded-2xl p-6 relative border border-slate-700 animate-in fade-in zoom-in-95">
            <button
              onClick={() => setSelectedLog(null)}
              className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-white bg-slate-800"
            >
              <X className="h-4 w-4" />
            </button>

            <div className="flex items-center gap-2 mb-2">
              <Badge variant={selectedLog.status === 'SUCCESS' ? 'success' : 'critical'}>
                {selectedLog.status}
              </Badge>
              <span className="text-xs font-mono font-bold text-cyan-400">
                AUDIT LOG #{selectedLog.id}
              </span>
            </div>

            <h2 className="text-base font-bold font-mono text-white">
              {selectedLog.action} by {selectedLog.actor_email}
            </h2>

            <div className="my-4 space-y-2 font-mono text-xs">
              <div className="flex justify-between p-2 rounded bg-slate-900">
                <span className="text-slate-400">Actor Role:</span>
                <span className="text-white uppercase font-bold">{selectedLog.actor_role}</span>
              </div>
              <div className="flex justify-between p-2 rounded bg-slate-900">
                <span className="text-slate-400">Origin IP:</span>
                <span className="text-cyan-300">{selectedLog.ip_address}</span>
              </div>
              <div className="flex justify-between p-2 rounded bg-slate-900">
                <span className="text-slate-400">Timestamp:</span>
                <span className="text-slate-300">{new Date(selectedLog.timestamp).toISOString()}</span>
              </div>
            </div>

            <div>
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono block mb-1">
                AUDIT METADATA PAYLOAD (JSON)
              </span>
              <pre className="p-3 rounded-xl bg-black text-xs font-mono text-emerald-400 border border-slate-800 overflow-x-auto max-h-48">
                {JSON.stringify(selectedLog.details, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
