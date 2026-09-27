import React, { useState, useEffect } from 'react';
import {
  Bug,
  Search,
  Filter,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  CheckCircle,
  X,
  FileText,
  Laptop,
  Shield,
  FileUp,
  Server,
  Upload,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { api } from '../services/api';
import { Vulnerability, VulnerabilityStats } from '../types';
import { useAuth } from '../context/AuthContext';
import { Badge } from '../components/common/Badge';

export const VulnerabilitiesPage: React.FC = () => {
  const { isAnalyst } = useAuth();
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [stats, setStats] = useState<VulnerabilityStats | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [search, setSearch] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [isAuditingLaptop, setIsAuditingLaptop] = useState<boolean>(false);
  
  // OpenVAS Ingestion & Connector Modal
  const [isOpenVASModalOpen, setIsOpenVASModalOpen] = useState<boolean>(false);
  const [openvasTab, setOpenvasTab] = useState<'import' | 'remote'>('import');
  const [openvasStatus, setOpenvasStatus] = useState<any>(null);
  const [isUploadingReport, setIsUploadingReport] = useState<boolean>(false);
  const [uploadFeedback, setUploadFeedback] = useState<{ type: 'success' | 'error', text: string } | null>(null);
  const [gvmHost, setGvmHost] = useState<string>('127.0.0.1');
  const [gvmPort, setGvmPort] = useState<string>('9390');
  const [gvmUser, setGvmUser] = useState<string>('admin');
  const [isTestingConn, setIsTestingConn] = useState<boolean>(false);
  const [connResult, setConnResult] = useState<{ success: boolean, message: string } | null>(null);

  // Triage Modal
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [triageStatus, setTriageStatus] = useState<string>('OPEN');
  const [remediationNotes, setRemediationNotes] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  const fetchVulns = async () => {
    try {
      setIsLoading(true);
      const [vulnsRes, statsRes] = await Promise.all([
        api.get('/vulnerabilities'),
        api.get('/vulnerabilities/stats')
      ]);
      setVulns(vulnsRes.data);
      setStats(statsRes.data);
    } catch (e) {
      console.error('Error fetching vulnerabilities:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchVulns();
  }, []);

  const handleAuditThisLaptop = async () => {
    try {
      setIsAuditingLaptop(true);
      await api.post('/assets/scan/laptop', { target_ip: '127.0.0.1' });
      setTimeout(async () => {
        await fetchVulns();
        setIsAuditingLaptop(false);
      }, 14000);
    } catch (e) {
      console.error('Failed to run laptop audit:', e);
      setIsAuditingLaptop(false);
    }
  };

  const fetchOpenVASStatus = async () => {
    try {
      const res = await api.get('/openvas/status');
      setOpenvasStatus(res.data);
      if (res.data.host) setGvmHost(res.data.host);
      if (res.data.port) setGvmPort(String(res.data.port));
      if (res.data.username) setGvmUser(res.data.username);
    } catch (e) {
      console.error('Failed to get OpenVAS status:', e);
    }
  };

  const handleOpenOpenVASModal = async () => {
    setIsOpenVASModalOpen(true);
    setUploadFeedback(null);
    setConnResult(null);
    await fetchOpenVASStatus();
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      setIsUploadingReport(true);
      setUploadFeedback(null);
      const formData = new FormData();
      formData.append('file', file);
      const res = await api.post('/openvas/import', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setUploadFeedback({ type: 'success', text: res.data.message });
      await fetchVulns();
      await fetchOpenVASStatus();
    } catch (err: any) {
      const msg = err.response?.data?.detail || 'Failed to parse OpenVAS report.';
      setUploadFeedback({ type: 'error', text: msg });
    } finally {
      setIsUploadingReport(false);
    }
  };

  const handleTestConnection = async () => {
    try {
      setIsTestingConn(true);
      setConnResult(null);
      await api.post('/openvas/config', {
        host: gvmHost,
        port: parseInt(gvmPort, 10) || 9390,
        username: gvmUser,
        use_tls: true
      });
      const res = await api.post('/openvas/test-connection');
      setConnResult({ success: res.data.success, message: res.data.message });
      await fetchOpenVASStatus();
    } catch (err: any) {
      setConnResult({ success: false, message: err.response?.data?.detail || 'Connection test failed.' });
    } finally {
      setIsTestingConn(false);
    }
  };

  const handleOpenTriage = (v: Vulnerability) => {
    setSelectedVuln(v);
    setTriageStatus(v.status);
    setRemediationNotes(v.remediation || '');
  };

  const handleSaveTriage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedVuln) return;
    try {
      setIsSubmitting(true);
      const res = await api.put(`/vulnerabilities/${selectedVuln.id}/triage`, {
        status: triageStatus,
        remediation: remediationNotes
      });
      setVulns(vulns.map(v => v.id === selectedVuln.id ? res.data : v));
      setSelectedVuln(null);
      await fetchVulns();
    } catch (e) {
      console.error('Triage error:', e);
    } finally {
      setIsSubmitting(false);
    }
  };

  const filteredVulns = vulns.filter(v => {
    const matchesSearch =
      v.cve_id.toLowerCase().includes(search.toLowerCase()) ||
      v.title.toLowerCase().includes(search.toLowerCase()) ||
      v.description.toLowerCase().includes(search.toLowerCase()) ||
      (v.affected_service || '').toLowerCase().includes(search.toLowerCase());

    if (!matchesSearch) return false;
    if (severityFilter !== 'all' && v.severity !== severityFilter.toUpperCase()) return false;
    if (statusFilter !== 'all' && v.status !== statusFilter.toUpperCase()) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center gap-2">
            <Bug className="h-5 w-5 text-amber-400" />
            VULNERABILITY ASSESSMENT &amp; CVE TRIAGE
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Real-time correlation of open ports and services against Nmap security audit engine and CVE catalog.
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {isAnalyst && (
            <>
              <button
                onClick={handleAuditThisLaptop}
                disabled={isAuditingLaptop}
                className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-slate-950 text-xs font-mono font-bold transition-all shadow-md shadow-amber-500/25 disabled:opacity-50"
                title="Executes authentic Nmap scan and security posture assessment on this machine"
              >
                <Laptop className={`h-4 w-4 ${isAuditingLaptop ? 'animate-pulse' : ''}`} />
                <span>{isAuditingLaptop ? 'AUDITING LAPTOP...' : 'AUDIT THIS LAPTOP (NMAP)'}</span>
              </button>

              <button
                onClick={handleOpenOpenVASModal}
                className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 text-xs font-mono font-bold transition-all shadow-md shadow-emerald-500/25"
                title="OpenVAS / Greenbone Report Ingestion and Daemon Connector"
              >
                <FileUp className="h-4 w-4" />
                <span>OPENVAS SCANNER</span>
              </button>
            </>
          )}

          <button
            onClick={fetchVulns}
            className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-all self-start md:self-auto"
            title="Refresh CVE Catalog"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Summary KPI Pills */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 font-mono text-xs">
          <div className="cyber-card p-3 rounded-xl border border-slate-800 text-center">
            <span className="text-[10px] text-slate-400 uppercase block">Total CVEs</span>
            <span className="text-xl font-bold text-white">{stats.total}</span>
          </div>
          <div className="cyber-card p-3 rounded-xl border border-red-500/30 text-center bg-red-950/20">
            <span className="text-[10px] text-red-400 uppercase block">Critical (CVSS 9.0+)</span>
            <span className="text-xl font-bold text-red-400">{stats.critical}</span>
          </div>
          <div className="cyber-card p-3 rounded-xl border border-amber-500/30 text-center bg-amber-950/20">
            <span className="text-[10px] text-amber-400 uppercase block">High (CVSS 7.0+)</span>
            <span className="text-xl font-bold text-amber-400">{stats.high}</span>
          </div>
          <div className="cyber-card p-3 rounded-xl border border-yellow-500/30 text-center bg-yellow-950/20">
            <span className="text-[10px] text-yellow-400 uppercase block">Medium</span>
            <span className="text-xl font-bold text-yellow-400">{stats.medium}</span>
          </div>
          <div className="cyber-card p-3 rounded-xl border border-emerald-500/30 text-center bg-emerald-950/20">
            <span className="text-[10px] text-emerald-400 uppercase block">Mitigated</span>
            <span className="text-xl font-bold text-emerald-400">{stats.mitigated}</span>
          </div>
        </div>
      )}

      {/* Search & Filters */}
      <div className="cyber-card p-4 rounded-xl flex flex-col md:flex-row items-center justify-between gap-4 font-mono text-xs">
        <div className="relative w-full md:w-80">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search CVE-ID, service, keyword..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
          />
        </div>

        <div className="flex items-center gap-2 flex-wrap w-full md:w-auto">
          {/* Severity filter */}
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

          {/* Status filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="mitigated">Mitigated</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>
      </div>

      {/* Vulnerabilities Table */}
      <div className="cyber-card rounded-2xl overflow-hidden border border-slate-800">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 uppercase text-[10px]">
              <tr>
                <th className="py-3.5 px-4">CVE Identifier</th>
                <th className="py-3.5 px-4">Severity &amp; CVSS</th>
                <th className="py-3.5 px-4">Vulnerability Title</th>
                <th className="py-3.5 px-4">Affected Target</th>
                <th className="py-3.5 px-4">Exploit Vector</th>
                <th className="py-3.5 px-4">Triage Status</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredVulns.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400 font-mono">
                    No matching vulnerabilities found.
                  </td>
                </tr>
              ) : (
                filteredVulns.map((v) => (
                  <tr key={v.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3.5 px-4 font-bold text-cyan-300">
                      {v.cve_id}
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        <Badge size="sm" variant={v.severity.toLowerCase() as any}>
                          {v.severity}
                        </Badge>
                        <span className="font-bold text-white">
                          {v.cvss_score.toFixed(1)}
                        </span>
                      </div>
                    </td>

                    <td className="py-3.5 px-4 max-w-xs">
                      <p className="font-bold text-white truncate">{v.title}</p>
                      <p className="text-[10px] text-slate-400 line-clamp-1">{v.description}</p>
                    </td>

                    <td className="py-3.5 px-4 text-slate-300">
                      <p>{v.affected_service || 'Network Service'}</p>
                      {v.port_affected && (
                        <span className="text-[10px] text-cyan-400">Port {v.port_affected}</span>
                      )}
                    </td>

                    <td className="py-3.5 px-4">
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                          v.exploit_available === 'Weaponized'
                            ? 'bg-red-950 text-red-400 border border-red-500/40 animate-pulse'
                            : v.exploit_available === 'POC'
                            ? 'bg-amber-950 text-amber-400 border border-amber-500/40'
                            : 'bg-slate-900 text-slate-400 border border-slate-800'
                        }`}
                      >
                        {v.exploit_available}
                      </span>
                    </td>

                    <td className="py-3.5 px-4">
                      <Badge size="sm" variant={v.status === 'MITIGATED' ? 'success' : v.status === 'OPEN' ? 'critical' : 'warning'}>
                        {v.status}
                      </Badge>
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => handleOpenTriage(v)}
                        className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 font-mono text-[11px] font-bold border border-slate-700 transition-all"
                      >
                        TRIAGE / REMEDIATE
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* TRIAGE / REMEDIATION MODAL */}
      {selectedVuln && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="cyber-card w-full max-w-xl rounded-2xl p-6 relative border border-slate-700 max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setSelectedVuln(null)}
              className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-white bg-slate-800"
            >
              <X className="h-4 w-4" />
            </button>

            <div className="flex items-center gap-2 mb-2">
              <Badge variant={selectedVuln.severity.toLowerCase() as any}>
                {selectedVuln.severity}
              </Badge>
              <span className="text-xs font-mono font-bold text-cyan-400">
                {selectedVuln.cve_id} (CVSS {selectedVuln.cvss_score})
              </span>
            </div>

            <h2 className="text-base font-bold font-mono text-white">
              {selectedVuln.title}
            </h2>

            <p className="text-xs text-slate-300 font-mono mt-2 leading-relaxed bg-slate-900/60 p-3 rounded-xl border border-slate-800">
              {selectedVuln.description}
            </p>

            <form onSubmit={handleSaveTriage} className="mt-4 space-y-4 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-bold">TRIAGE STATUS</label>
                <select
                  value={triageStatus}
                  onChange={(e) => setTriageStatus(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400"
                  disabled={!isAnalyst}
                >
                  <option value="OPEN">OPEN (Unresolved threat vector)</option>
                  <option value="INVESTIGATING">INVESTIGATING (Under active triage)</option>
                  <option value="MITIGATED">MITIGATED (Patch / firewall isolation applied)</option>
                  <option value="FALSE_POSITIVE">FALSE POSITIVE (Verified non-applicable)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-bold">REMEDIATION GUIDANCE &amp; PATCH NOTES</label>
                <textarea
                  rows={4}
                  value={remediationNotes}
                  onChange={(e) => setRemediationNotes(e.target.value)}
                  placeholder="Document vendor patch versions, configuration updates, or mitigation controls..."
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400"
                  disabled={!isAnalyst}
                />
              </div>

              {isAnalyst && (
                <div className="pt-2 flex justify-end gap-3">
                  <button
                    type="button"
                    onClick={() => setSelectedVuln(null)}
                    className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isSubmitting}
                    className="px-5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold transition-all shadow-md shadow-cyan-500/20"
                  >
                    {isSubmitting ? 'Saving...' : 'UPDATE TRIAGE STATUS'}
                  </button>
                </div>
              )}
            </form>
          </div>
        </div>
      )}

      {/* OpenVAS Scanner & Report Ingestion Modal */}
      {isOpenVASModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
          <div className="cyber-card w-full max-w-2xl p-6 rounded-2xl border border-emerald-500/40 shadow-2xl shadow-emerald-500/10 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                  <FileUp className="h-5 w-5" />
                </div>
                <div>
                  <h2 className="text-base font-bold font-mono text-white flex items-center gap-2">
                    OPENVAS / GREENBONE CONNECTOR
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-950/50 border border-emerald-500/30 text-emerald-400">
                      PHASE 2
                    </span>
                  </h2>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Ingest OpenVAS XML/CSV vulnerability reports or interface with remote GVM daemons.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsOpenVASModalOpen(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-all"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Navigation Tabs */}
            <div className="flex items-center gap-2 mt-4 border-b border-slate-800/80 pb-2 font-mono text-xs">
              <button
                onClick={() => setOpenvasTab('import')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg transition-all ${
                  openvasTab === 'import'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Upload className="h-3.5 w-3.5" />
                <span>REPORT INGESTION (XML / CSV)</span>
              </button>

              <button
                onClick={() => setOpenvasTab('remote')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg transition-all ${
                  openvasTab === 'remote'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Server className="h-3.5 w-3.5" />
                <span>REMOTE GVM DAEMON (GMP)</span>
              </button>
            </div>

            {/* Tab 1: Report Ingestion */}
            {openvasTab === 'import' && (
              <div className="mt-4 space-y-4 font-mono text-xs">
                <div className="p-4 rounded-xl border-2 border-dashed border-slate-700 hover:border-emerald-500/60 bg-slate-900/50 text-center transition-all">
                  <FileUp className="h-8 w-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                  <p className="text-white font-bold mb-1">Select or drop an OpenVAS Scan Report</p>
                  <p className="text-[11px] text-slate-400 mb-3">
                    Supports Greenbone Vulnerability Management XML (*.xml) and CSV (*.csv) exports.
                  </p>
                  <label className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold cursor-pointer transition-all shadow-md shadow-emerald-500/20">
                    <Upload className="h-4 w-4" />
                    <span>{isUploadingReport ? 'PROCESSING REPORT...' : 'CHOOSE FILE'}</span>
                    <input
                      type="file"
                      accept=".xml,.csv"
                      onChange={handleFileUpload}
                      disabled={isUploadingReport}
                      className="hidden"
                    />
                  </label>
                </div>
              </div>
            )}

            {/* Tab 2: Remote GVM Daemon */}
            {openvasTab === 'remote' && (
              <div className="mt-4 space-y-4 font-mono text-xs">
                <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase block">Daemon Status</span>
                    <span className="text-white font-bold">
                      {openvasStatus?.last_connection_status || 'NOT_CONNECTED'}
                    </span>
                  </div>
                  <span className={`text-[10px] px-2.5 py-1 rounded-full font-bold uppercase border ${
                    openvasStatus?.last_connection_status === 'CONNECTED'
                      ? 'bg-emerald-950/50 text-emerald-400 border-emerald-500/40'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}>
                    GMP Protocol (Port 9390)
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-400 mb-1 font-bold">DAEMON HOST / IP</label>
                    <input
                      type="text"
                      value={gvmHost}
                      onChange={(e) => setGvmHost(e.target.value)}
                      placeholder="e.g. 192.168.1.50 or 127.0.0.1"
                      className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-emerald-400"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1 font-bold">GMP PORT</label>
                    <input
                      type="text"
                      value={gvmPort}
                      onChange={(e) => setGvmPort(e.target.value)}
                      placeholder="9390"
                      className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-emerald-400"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 font-bold">API USERNAME</label>
                  <input
                    type="text"
                    value={gvmUser}
                    onChange={(e) => setGvmUser(e.target.value)}
                    placeholder="admin"
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-emerald-400"
                  />
                </div>

                <div className="pt-2 flex justify-end">
                  <button
                    onClick={handleTestConnection}
                    disabled={isTestingConn}
                    className="flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold transition-all shadow-md shadow-emerald-500/20"
                  >
                    <Server className="h-4 w-4" />
                    <span>{isTestingConn ? 'TESTING CONNECTIVITY...' : 'TEST DAEMON CONNECTION'}</span>
                  </button>
                </div>

                {connResult && (
                  <div className={`p-3 rounded-xl border flex items-start gap-2 ${
                    connResult.success
                      ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
                      : 'bg-amber-950/20 border-amber-500/40 text-amber-300'
                  }`}>
                    {connResult.success ? <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" /> : <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />}
                    <span className="text-[11px] leading-relaxed">{connResult.message}</span>
                  </div>
                )}
              </div>
            )}

            {/* Ingestion Feedback Banner */}
            {uploadFeedback && (
              <div className={`mt-4 p-3 rounded-xl border font-mono text-xs flex items-start gap-2 ${
                uploadFeedback.type === 'success'
                  ? 'bg-emerald-950/30 border-emerald-500/50 text-emerald-300'
                  : 'bg-red-950/30 border-red-500/50 text-red-300'
              }`}>
                {uploadFeedback.type === 'success' ? <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" /> : <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />}
                <span className="text-[11px] leading-relaxed">{uploadFeedback.text}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
