import React, { useState, useEffect } from 'react';
import {
  Activity,
  Radio,
  FileCode,
  Download,
  Upload,
  Play,
  Square,
  RefreshCw,
  Search,
  Filter,
  ShieldAlert,
  AlertTriangle,
  Server,
  Layers,
  ArrowRight,
  ExternalLink,
  Eye,
  CheckCircle,
  Clock,
  Terminal,
  FileText,
  ChevronRight,
  ChevronDown,
  Info,
  Cpu,
  Wifi,
  HardDrive
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  PieChart,
  Pie
} from 'recharts';
import { api } from '../services/api';
import {
  NetworkCapture,
  PacketEvent,
  NetworkConnection,
  TrafficOverviewStats,
  CorrelatedFinding,
  DeviceCorrelation,
  NetworkInterface
} from '../types';
import { useAuth } from '../context/AuthContext';
import { Badge } from '../components/common/Badge';

export const NetworkTrafficPage: React.FC = () => {
  const { isAnalyst, user } = useAuth();
  const [activeTab, setActiveTab] = useState<'dashboard' | 'captures' | 'correlations' | 'findings'>('dashboard');

  // Traffic & Capture Data States
  const [trafficStats, setTrafficStats] = useState<TrafficOverviewStats | null>(null);
  const [captures, setCaptures] = useState<NetworkCapture[]>([]);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [correlations, setCorrelations] = useState<DeviceCorrelation[]>([]);
  const [findings, setFindings] = useState<CorrelatedFinding[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Capture Modal & Controls
  const [isCapturing, setIsCapturing] = useState<boolean>(false);
  const [selectedInterface, setSelectedInterface] = useState<string>('eth0');
  const [captureDuration, setCaptureDuration] = useState<number>(30);
  const [captureFilter, setCaptureFilter] = useState<string>('');
  const [captureSource, setCaptureSource] = useState<string>('TCPDump Local Monitor Point');

  // Inspector / Analyst Workflow Modals
  const [inspectCapture, setInspectCapture] = useState<NetworkCapture | null>(null);
  const [packets, setPackets] = useState<PacketEvent[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<PacketEvent | null>(null);
  const [packetFilterProtocol, setPacketFilterProtocol] = useState<string>('all');
  const [isLoadingPackets, setIsLoadingPackets] = useState<boolean>(false);

  // Analyst Triage Modal
  const [selectedFinding, setSelectedFinding] = useState<CorrelatedFinding | null>(null);
  const [triageStatus, setTriageStatus] = useState<string>('INVESTIGATING');
  const [triageConclusion, setTriageConclusion] = useState<string>('');
  const [triageNotes, setTriageNotes] = useState<string>('');
  const [isSubmittingTriage, setIsSubmittingTriage] = useState<boolean>(false);

  // Filters
  const [findingSearch, setFindingSearch] = useState<string>('');
  const [findingSeverity, setFindingSeverity] = useState<string>('all');

  const fetchAllData = async () => {
    try {
      setIsLoading(true);
      const [trafficRes, capsRes, ifRes, connsRes, corrRes, findingsRes] = await Promise.all([
        api.get('/network/traffic'),
        api.get('/network/captures'),
        api.get('/network/interfaces'),
        api.get('/network/connections?limit=50'),
        api.get('/network/correlations'),
        api.get('/network/alerts')
      ]);

      setTrafficStats(trafficRes.data);
      setCaptures(capsRes.data);
      setInterfaces(ifRes.data);
      setConnections(connsRes.data);
      setCorrelations(corrRes.data);
      setFindings(findingsRes.data);

      const active = capsRes.data.some((c: NetworkCapture) => c.status === 'CAPTURING');
      setIsCapturing(active);
    } catch (e) {
      console.error('Failed to load network traffic data:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAllData();
  }, []);

  const handleStartCapture = async () => {
    try {
      setIsCapturing(true);
      await api.post('/network/captures/start', {
        interface: selectedInterface,
        duration_seconds: captureDuration,
        capture_filter: captureFilter || undefined,
        capture_source: captureSource
      });
      await fetchAllData();
    } catch (e) {
      console.error('Start capture failed:', e);
      setIsCapturing(false);
    }
  };

  const handleStopCapture = async (capId: string) => {
    try {
      await api.post('/network/captures/stop', { capture_id: capId });
      setIsCapturing(false);
      await fetchAllData();
    } catch (e) {
      console.error('Stop capture failed:', e);
    }
  };

  const handleInspectCapture = async (cap: NetworkCapture) => {
    setInspectCapture(cap);
    setSelectedPacket(null);
    setIsLoadingPackets(true);
    try {
      const res = await api.get(`/network/captures/${cap.capture_id}/packets?limit=100`);
      setPackets(res.data);
      if (res.data.length > 0) {
        setSelectedPacket(res.data[0]);
      }
    } catch (e) {
      console.error('Failed to load packets:', e);
    } finally {
      setIsLoadingPackets(false);
    }
  };

  const handleDownloadPcap = (cap: NetworkCapture) => {
    window.open(`${api.defaults.baseURL}/network/captures/${cap.capture_id}/download`, '_blank');
  };

  const handleReAnalyze = async (capId: string) => {
    try {
      await api.post(`/network/captures/${capId}/analyze`);
      await fetchAllData();
    } catch (e) {
      console.error('Re-analysis failed:', e);
    }
  };

  const handleSaveTriage = async () => {
    if (!selectedFinding) return;
    setIsSubmittingTriage(true);
    try {
      const res = await api.post(`/network/alerts/${selectedFinding.id}/investigate`, {
        status: triageStatus,
        analyst_conclusion: triageConclusion,
        analyst_notes: triageNotes,
        assigned_to: user?.full_name
      });
      setFindings(findings.map(f => f.id === selectedFinding.id ? res.data : f));
      setSelectedFinding(null);
    } catch (e) {
      console.error('Failed to save investigation conclusion:', e);
    } finally {
      setIsSubmittingTriage(false);
    }
  };

  // Protocols chart data
  const protocolData = trafficStats?.protocol_distribution
    ? Object.entries(trafficStats.protocol_distribution).map(([name, count]) => ({ name, count }))
    : [];

  const PROTOCOL_COLORS: Record<string, string> = {
    TCP: '#06b6d4',
    UDP: '#3b82f6',
    HTTP: '#10b981',
    TLS: '#8b5cf6',
    RTSP: '#f59e0b',
    SMB: '#ef4444',
    DNS: '#ec4899',
    ICMP: '#64748b',
    ARP: '#14b8a6',
    'MODBUS-TCP': '#f97316'
  };

  const filteredFindings = findings.filter(f => {
    const matchesSearch =
      f.title.toLowerCase().includes(findingSearch.toLowerCase()) ||
      f.observation.toLowerCase().includes(findingSearch.toLowerCase()) ||
      f.alert_code.toLowerCase().includes(findingSearch.toLowerCase()) ||
      (f.source_ip || '').includes(findingSearch) ||
      (f.destination_ip || '').includes(findingSearch);
    if (!matchesSearch) return false;
    if (findingSeverity !== 'all' && f.severity !== findingSeverity.toUpperCase()) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Page Title & Navigation Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold font-mono text-white flex items-center gap-2">
              <Radio className="h-5 w-5 text-cyan-400 animate-pulse" />
              NETWORK TRAFFIC &amp; PCAP SURVEILLANCE
            </h1>
            <Badge size="sm" variant="info">PHASE 2 ENGINE</Badge>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            TCPDump Capture Pipeline • TShark Deep Packet Inspection • Vulnerability + Traffic Correlation
          </p>
        </div>

        {/* Global Action Toolbar */}
        <div className="flex items-center gap-2">
          <button
            onClick={fetchAllData}
            disabled={isLoading}
            className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 flex items-center gap-2 transition"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>SYNC</span>
          </button>
        </div>
      </div>

      {/* Architecture & Visibility Disclaimer Notice (Module 1 Requirement) */}
      <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 p-4 text-xs font-mono flex items-start gap-3">
        <Info className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="font-bold text-amber-300 uppercase tracking-wide">
            Network Architecture &amp; Capture Visibility Scope
          </span>
          <p className="text-slate-300 leading-relaxed text-[11px]">
            {trafficStats?.visibility_disclaimer || (
              "Capture visibility depends on capture location and network architecture (SPAN port, mirror port, network TAP, or local interface). A host running TCPDump only observes packets traversing its authorized network attachment point."
            )}
          </p>
        </div>
      </div>

      {/* Section Sub-Navigation Tabs */}
      <div className="flex border-b border-slate-800 space-x-6 text-xs font-mono">
        <button
          onClick={() => setActiveTab('dashboard')}
          className={`pb-3 font-semibold transition-all border-b-2 flex items-center gap-2 ${
            activeTab === 'dashboard'
              ? 'border-cyan-400 text-cyan-300'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="h-4 w-4" />
          <span>TRAFFIC DASHBOARD</span>
        </button>

        <button
          onClick={() => setActiveTab('captures')}
          className={`pb-3 font-semibold transition-all border-b-2 flex items-center gap-2 ${
            activeTab === 'captures'
              ? 'border-cyan-400 text-cyan-300'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <HardDrive className="h-4 w-4" />
          <span>TCPDUMP &amp; PCAP REPOSITORY</span>
          {captures.length > 0 && (
            <span className="bg-slate-800 text-slate-300 px-1.5 py-0.2 rounded text-[10px]">
              {captures.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('correlations')}
          className={`pb-3 font-semibold transition-all border-b-2 flex items-center gap-2 ${
            activeTab === 'correlations'
              ? 'border-cyan-400 text-cyan-300'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Server className="h-4 w-4" />
          <span>DEVICE &amp; FIRMWARE CORRELATION</span>
        </button>

        <button
          onClick={() => setActiveTab('findings')}
          className={`pb-3 font-semibold transition-all border-b-2 flex items-center gap-2 ${
            activeTab === 'findings'
              ? 'border-cyan-400 text-cyan-300'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="h-4 w-4 text-red-400" />
          <span>SECURITY INDICATORS &amp; TRIAGE</span>
          {findings.length > 0 && (
            <span className="bg-red-500/20 text-red-400 border border-red-500/30 px-1.5 py-0.2 rounded text-[10px]">
              {findings.length}
            </span>
          )}
        </button>
      </div>

      {/* ─────────────────────────────────────────────────────────── */}
      {/* TAB 1: TRAFFIC DASHBOARD (Module 5)                         */}
      {/* ─────────────────────────────────────────────────────────── */}
      {activeTab === 'dashboard' && (
        <div className="space-y-6">
          {/* Top KPI Metric Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 font-mono">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">TOTAL PACKETS</span>
              <p className="text-xl font-bold text-white mt-1">
                {trafficStats?.total_packets.toLocaleString() || 0}
              </p>
              <span className="text-[10px] text-cyan-400">Captured in PCAP</span>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 font-mono">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">TCP PACKETS</span>
              <p className="text-xl font-bold text-cyan-300 mt-1">
                {trafficStats?.tcp_packets.toLocaleString() || 0}
              </p>
              <span className="text-[10px] text-slate-400">HTTP/TLS/RTSP/SMB</span>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 font-mono">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">UDP PACKETS</span>
              <p className="text-xl font-bold text-blue-400 mt-1">
                {trafficStats?.udp_packets.toLocaleString() || 0}
              </p>
              <span className="text-[10px] text-slate-400">DNS / NTP Datagrams</span>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 font-mono">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">ICMP PACKETS</span>
              <p className="text-xl font-bold text-emerald-400 mt-1">
                {trafficStats?.icmp_packets.toLocaleString() || 0}
              </p>
              <span className="text-[10px] text-slate-400">Ping Sweeps</span>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 font-mono">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">COMMUNICATING NODES</span>
              <p className="text-xl font-bold text-purple-400 mt-1">
                {trafficStats?.unique_devices || 0}
              </p>
              <span className="text-[10px] text-slate-400">Distinct Endpoints</span>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 font-mono">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">DESTINATIONS</span>
              <p className="text-xl font-bold text-amber-400 mt-1">
                {trafficStats?.unique_destinations || 0}
              </p>
              <span className="text-[10px] text-slate-400">Subnet &amp; External</span>
            </div>
          </div>

          {/* Charts & Breakdown Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Protocol Distribution Bar Chart */}
            <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/40 p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Layers className="h-4 w-4 text-cyan-400" />
                  <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                    PROTOCOL DISTRIBUTION (TSHARK EXTRACTED)
                  </span>
                </div>
                <span className="text-[10px] font-mono text-slate-400">Automated L3/L4/L7 Profiling</span>
              </div>

              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={protocolData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                    <XAxis
                      dataKey="name"
                      tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
                      axisLine={{ stroke: '#334155' }}
                    />
                    <YAxis
                      tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
                      axisLine={{ stroke: '#334155' }}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        border: '1px solid #334155',
                        borderRadius: '8px',
                        fontFamily: 'monospace',
                        fontSize: '12px'
                      }}
                    />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {protocolData.map((entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={PROTOCOL_COLORS[entry.name] || '#06b6d4'}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Top Communicating Devices List */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 space-y-4 font-mono">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Server className="h-4 w-4 text-purple-400" />
                  <span className="text-xs font-bold text-white uppercase tracking-wider">
                    TOP COMMUNICATING DEVICES
                  </span>
                </div>
              </div>

              <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                {trafficStats?.top_communicating_devices.map((dev, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg border border-slate-800/80 bg-slate-950/60 flex items-center justify-between text-xs hover:border-slate-700 transition"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-cyan-300">{dev.device_ip}</span>
                        {dev.hostname && (
                          <span className="text-[10px] text-slate-400 truncate max-w-[110px]">
                            ({dev.hostname})
                          </span>
                        )}
                      </div>
                      <span className="text-[10px] text-slate-400 block">{dev.device_type}</span>
                    </div>

                    <div className="text-right">
                      <span className="font-bold text-slate-200">{dev.packet_count.toLocaleString()} pkts</span>
                      <span className="text-[10px] text-slate-400 block">
                        {dev.connections} flows
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Active Network Connection Flows Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden font-mono">
            <div className="px-5 py-3 border-b border-slate-800 bg-slate-950/40 flex items-center justify-between">
              <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Activity className="h-4 w-4 text-cyan-400" />
                OBSERVED NETWORK CONVERSATIONS &amp; FLOWS
              </span>
              <span className="text-[11px] text-slate-400">
                Showing {connections.length} active sessions
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800 uppercase text-[10px]">
                  <tr>
                    <th className="py-2.5 px-4">SOURCE IP</th>
                    <th className="py-2.5 px-4">DESTINATION IP</th>
                    <th className="py-2.5 px-4">PROTOCOL</th>
                    <th className="py-2.5 px-4">DST PORT</th>
                    <th className="py-2.5 px-4">PACKETS</th>
                    <th className="py-2.5 px-4">VOLUME</th>
                    <th className="py-2.5 px-4">EGRESS TYPE</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {connections.map((c) => (
                    <tr key={c.id} className="hover:bg-slate-800/30 transition">
                      <td className="py-2.5 px-4 font-bold text-cyan-300">{c.source_ip}</td>
                      <td className="py-2.5 px-4 font-bold text-slate-200">
                        <div className="flex items-center gap-1.5">
                          <ArrowRight className="h-3 w-3 text-slate-400" />
                          <span>{c.destination_ip}</span>
                        </div>
                      </td>
                      <td className="py-2.5 px-4">
                        <span
                          className="px-2 py-0.5 rounded text-[10px] font-bold"
                          style={{
                            backgroundColor: `${PROTOCOL_COLORS[c.protocol] || '#06b6d4'}20`,
                            color: PROTOCOL_COLORS[c.protocol] || '#06b6d4',
                            border: `1px solid ${PROTOCOL_COLORS[c.protocol] || '#06b6d4'}40`
                          }}
                        >
                          {c.protocol}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-slate-300">{c.destination_port || 'N/A'}</td>
                      <td className="py-2.5 px-4 text-slate-300">{c.packet_count}</td>
                      <td className="py-2.5 px-4 text-slate-400">
                        {(c.byte_count / 1024).toFixed(1)} KB
                      </td>
                      <td className="py-2.5 px-4">
                        {c.is_external ? (
                          <span className="text-[10px] text-amber-400 font-bold bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/30">
                            EXTERNAL PUBLIC
                          </span>
                        ) : (
                          <span className="text-[10px] text-emerald-400 font-bold bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/30">
                            INTERNAL LAN
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────── */}
      {/* TAB 2: TCPDUMP CAPTURE & PCAP REPOSITORY (Modules 1 & 2)    */}
      {/* ─────────────────────────────────────────────────────────── */}
      {activeTab === 'captures' && (
        <div className="space-y-6">
          {/* Capture Trigger Panel */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 space-y-4 font-mono">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
              <div>
                <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Terminal className="h-4 w-4 text-cyan-400" />
                  TCPDUMP PACKET CAPTURE CONTROLLER
                </span>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Launch authorized live capture session on network interface with BPF filtering.
                </p>
              </div>

              {isCapturing ? (
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-2 text-red-400 text-xs font-bold animate-pulse">
                    <span className="h-2.5 w-2.5 rounded-full bg-red-500 inline-block" />
                    <span>CAPTURING PACKETS...</span>
                  </div>
                  <button
                    onClick={() => {
                      const active = captures.find(c => c.status === 'CAPTURING');
                      if (active) handleStopCapture(active.capture_id);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition"
                  >
                    <Square className="h-3.5 w-3.5 fill-current" />
                    <span>STOP CAPTURE</span>
                  </button>
                </div>
              ) : (
                <button
                  onClick={handleStartCapture}
                  disabled={!isAnalyst}
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition disabled:opacity-50 shadow-lg shadow-cyan-500/20"
                >
                  <Play className="h-3.5 w-3.5 fill-current" />
                  <span>START TCPDUMP CAPTURE</span>
                </button>
              )}
            </div>

            {/* Capture Parameter Inputs */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
              <div>
                <label className="text-[11px] text-slate-400 block mb-1.5">NETWORK INTERFACE</label>
                <select
                  value={selectedInterface}
                  onChange={(e) => setSelectedInterface(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  {interfaces.map((iface) => (
                    <option key={iface.name} value={iface.name}>
                      {iface.name} ({iface.type}) - {iface.ip_address || 'Unassigned'}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-[11px] text-slate-400 block mb-1.5">DURATION (SECONDS)</label>
                <input
                  type="number"
                  min="5"
                  max="300"
                  value={captureDuration}
                  onChange={(e) => setCaptureDuration(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-[11px] text-slate-400 block mb-1.5">BPF CAPTURE FILTER</label>
                <input
                  type="text"
                  placeholder="e.g. tcp port 80 or 443"
                  value={captureFilter}
                  onChange={(e) => setCaptureFilter(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-[11px] text-slate-400 block mb-1.5">MONITORING SOURCE</label>
                <input
                  type="text"
                  value={captureSource}
                  onChange={(e) => setCaptureSource(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>
          </div>

          {/* PCAP Evidence Layer Table (Module 2) */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden font-mono">
            <div className="px-5 py-3 border-b border-slate-800 bg-slate-950/40 flex items-center justify-between">
              <div>
                <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <HardDrive className="h-4 w-4 text-purple-400" />
                  PCAP NETWORK EVIDENCE REPOSITORY
                </span>
                <p className="text-[10px] text-slate-400 mt-0.5">
                  Preserved standard libpcap captures with forensic timestamps and retention metadata.
                </p>
              </div>

              <span className="text-[11px] text-slate-400">
                {captures.length} PCAPs Stored
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800 uppercase text-[10px]">
                  <tr>
                    <th className="py-2.5 px-4">CAPTURE ID</th>
                    <th className="py-2.5 px-4">FILENAME</th>
                    <th className="py-2.5 px-4">INTERFACE</th>
                    <th className="py-2.5 px-4">TIMESTAMPS</th>
                    <th className="py-2.5 px-4">PACKETS</th>
                    <th className="py-2.5 px-4">SIZE</th>
                    <th className="py-2.5 px-4">SOURCE</th>
                    <th className="py-2.5 px-4">STATUS</th>
                    <th className="py-2.5 px-4 text-right">ACTIONS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {captures.map((cap) => (
                    <tr key={cap.id} className="hover:bg-slate-800/30 transition">
                      <td className="py-3 px-4 font-bold text-cyan-300">{cap.capture_id}</td>
                      <td className="py-3 px-4 text-slate-200">
                        <div className="flex items-center gap-1.5">
                          <FileCode className="h-3.5 w-3.5 text-slate-400" />
                          <span>{cap.filename}</span>
                        </div>
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        <span className="bg-slate-800 px-2 py-0.5 rounded text-[10px]">
                          {cap.interface}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        <div>{new Date(cap.start_time).toLocaleTimeString()}</div>
                        <div className="text-[10px] text-slate-400">
                          {cap.end_time ? `${cap.duration_seconds}s duration` : 'Active'}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-bold text-slate-200">
                        {cap.packet_count.toLocaleString()}
                      </td>
                      <td className="py-3 px-4 text-slate-400">
                        {(cap.file_size_bytes / 1024).toFixed(1)} KB
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px] truncate max-w-[140px]">
                        {cap.capture_source}
                      </td>
                      <td className="py-3 px-4">
                        <Badge
                          size="sm"
                          variant={
                            cap.status === 'ANALYZED'
                              ? 'success'
                              : cap.status === 'CAPTURING'
                              ? 'critical'
                              : 'info'
                          }
                        >
                          {cap.status}
                        </Badge>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => handleInspectCapture(cap)}
                            className="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-[11px] font-bold flex items-center gap-1 transition"
                            title="Inspect frames and decode layers in browser"
                          >
                            <Eye className="h-3 w-3" />
                            <span>INSPECT</span>
                          </button>

                          <button
                            onClick={() => handleDownloadPcap(cap)}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-bold flex items-center gap-1 transition"
                            title="Download standard .pcap for Wireshark investigation"
                          >
                            <Download className="h-3 w-3" />
                            <span>WIRESHARK</span>
                          </button>

                          <button
                            onClick={() => handleReAnalyze(cap.capture_id)}
                            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition"
                            title="Re-run TShark analysis"
                          >
                            <RefreshCw className="h-3 w-3" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────── */}
      {/* TAB 3: DEVICE & FIRMWARE CORRELATION (Modules 6 & 7)        */}
      {/* ─────────────────────────────────────────────────────────── */}
      {activeTab === 'correlations' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 font-mono text-xs text-slate-300">
            <span className="font-bold text-cyan-400 uppercase tracking-wider block mb-1">
              Phase 1 Asset Context + Phase 2 Observed Network Behavior
            </span>
            <p className="text-slate-400 text-[11px]">
              Correlating discovered hardware, operating system, open service banners, and CVEs with actual network traffic conversations.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono">
            {correlations.map((item) => (
              <div
                key={item.asset_id}
                className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 space-y-4 hover:border-slate-700 transition"
              >
                {/* Asset Header */}
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-white">{item.hostname || item.ip_address}</span>
                      <Badge
                        size="sm"
                        variant={item.device_type.includes('CCTV') || item.device_type.includes('IoT') ? 'warning' : 'info'}
                      >
                        {item.device_type}
                      </Badge>
                    </div>
                    <span className="text-xs text-cyan-400">{item.ip_address}</span>
                  </div>

                  <div className="text-right">
                    <span className="text-[10px] text-slate-400 uppercase block">RISK SCORE</span>
                    <span
                      className={`text-sm font-bold ${
                        item.risk_score >= 70 ? 'text-red-400' : item.risk_score >= 40 ? 'text-amber-400' : 'text-emerald-400'
                      }`}
                    >
                      {item.risk_score} / 100
                    </span>
                  </div>
                </div>

                {/* Identity & Firmware Spec */}
                <div className="grid grid-cols-2 gap-2 text-[11px] p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <div>
                    <span className="text-slate-400 block text-[10px]">VENDOR / OS:</span>
                    <span className="text-slate-200 font-semibold truncate block">
                      {item.vendor || 'Generic'} ({item.os_name || 'Embedded'})
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">FIRMWARE / VERSION:</span>
                    <span className="text-slate-200 font-semibold truncate block">
                      {item.firmware_version || item.os_version || 'N/A'}
                    </span>
                  </div>
                </div>

                {/* Vulnerability Context (Phase 1) */}
                <div>
                  <span className="text-[10px] text-slate-400 uppercase tracking-wider block mb-1.5">
                    KNOWN VULNERABILITIES ({item.vulnerabilities.length})
                  </span>
                  {item.vulnerabilities.length > 0 ? (
                    <div className="space-y-1.5">
                      {item.vulnerabilities.map((v, i) => (
                        <div
                          key={i}
                          className="flex items-center justify-between p-2 rounded bg-red-950/20 border border-red-500/20 text-xs"
                        >
                          <span className="font-bold text-red-400">{v.cve_id}</span>
                          <span className="text-[11px] text-slate-300 truncate max-w-[200px]">{v.title}</span>
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-red-500/20 text-red-300 font-bold">
                            CVSS {v.cvss_score}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-[11px] text-slate-400 italic">No critical CVEs mapped.</span>
                  )}
                </div>

                {/* Observed Network Activity (Phase 2) */}
                <div className="border-t border-slate-800/80 pt-3">
                  <span className="text-[10px] text-cyan-400 uppercase tracking-wider block mb-2">
                    OBSERVED NETWORK ACTIVITY (PHASE 2)
                  </span>
                  <div className="space-y-1.5 text-xs">
                    <div className="flex justify-between text-slate-300">
                      <span className="text-slate-400">Total Packets / Flows:</span>
                      <span>{item.network_activity.total_packets.toLocaleString()} pkts ({item.network_activity.total_flows} flows)</span>
                    </div>

                    <div className="flex justify-between text-slate-300">
                      <span className="text-slate-400">Active Protocols:</span>
                      <span className="font-bold text-slate-200">
                        {item.network_activity.protocols.join(', ') || 'Idle'}
                      </span>
                    </div>

                    <div className="flex justify-between items-center text-slate-300">
                      <span className="text-slate-400">External Egress:</span>
                      {item.network_activity.has_external_communication ? (
                        <span className="text-amber-400 font-bold flex items-center gap-1 text-[11px]">
                          <AlertTriangle className="h-3 w-3 text-amber-400" />
                          <span>Observed ({item.network_activity.external_destinations.join(', ')})</span>
                        </span>
                      ) : (
                        <span className="text-emerald-400 text-[11px]">Internal Only</span>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────── */}
      {/* TAB 4: SECURITY INDICATORS & TRIAGE (Modules 8, 9, 10, 11)   */}
      {/* ─────────────────────────────────────────────────────────── */}
      {activeTab === 'findings' && (
        <div className="space-y-6">
          {/* Finding Search & Severity Filter */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono">
            <div className="flex items-center gap-3 flex-1 max-w-md">
              <div className="relative w-full">
                <Search className="h-4 w-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Filter security findings by title, IP, or rule..."
                  value={findingSearch}
                  onChange={(e) => setFindingSearch(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="flex items-center gap-2 text-xs">
              <span className="text-slate-400">SEVERITY:</span>
              {['all', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setFindingSeverity(sev)}
                  className={`px-2.5 py-1 rounded text-xs uppercase font-bold transition ${
                    findingSeverity === sev
                      ? 'bg-cyan-500 text-slate-950'
                      : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Correlated Findings Cards List */}
          <div className="space-y-4 font-mono">
            {filteredFindings.map((finding) => (
              <div
                key={finding.id}
                className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 space-y-4 hover:border-slate-700 transition"
              >
                <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <span className="text-xs font-bold text-cyan-400">{finding.alert_code}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-bold border border-slate-700">
                        {finding.rule_id}
                      </span>
                      <Badge
                        size="sm"
                        variant={
                          finding.severity === 'CRITICAL'
                            ? 'critical'
                            : finding.severity === 'HIGH'
                            ? 'warning'
                            : 'info'
                        }
                      >
                        {finding.severity}
                      </Badge>
                      <span className="text-[10px] text-purple-400 font-semibold">
                        {finding.category}
                      </span>
                    </div>

                    <h3 className="text-sm font-bold text-white mt-1">{finding.title}</h3>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => {
                        setSelectedFinding(finding);
                        setTriageStatus(finding.status);
                        setTriageConclusion(finding.analyst_conclusion || '');
                        setTriageNotes(finding.analyst_notes || '');
                      }}
                      className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition"
                    >
                      <span>TRIAGE INCIDENT</span>
                      <ArrowRight className="h-3 w-3" />
                    </button>
                  </div>
                </div>

                {/* Evidence Chain Visualization (Module 11) */}
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 text-xs space-y-2">
                  <div className="flex items-center gap-2 text-cyan-300 text-[11px] font-bold">
                    <ShieldAlert className="h-4 w-4" />
                    <span>CORRELATED EVIDENCE CHAIN</span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-[11px] pt-1">
                    <div>
                      <span className="text-slate-400 block text-[10px]">AFFECTED ASSET</span>
                      <span className="text-slate-200 font-semibold">
                        {finding.asset_hostname || finding.source_ip || '192.168.1.1'}
                      </span>
                      <span className="text-slate-400 text-[10px] block">
                        ({finding.asset_device_type || 'Internal Host'})
                      </span>
                    </div>

                    <div>
                      <span className="text-slate-400 block text-[10px]">CORRELATED VULN</span>
                      {finding.cve_id ? (
                        <span className="text-red-400 font-bold">{finding.cve_id}</span>
                      ) : (
                        <span className="text-slate-400 italic">Behavioral Anomaly</span>
                      )}
                    </div>

                    <div>
                      <span className="text-slate-400 block text-[10px]">OBSERVED NETWORK EVENT</span>
                      <span className="text-slate-200 font-semibold">
                        {finding.source_ip} → {finding.destination_ip}:{finding.destination_port}
                      </span>
                      <span className="text-slate-400 text-[10px] block">Protocol: {finding.protocol}</span>
                    </div>

                    <div>
                      <span className="text-slate-400 block text-[10px]">PCAP EVIDENCE FILE</span>
                      <span className="text-cyan-300 font-bold truncate block">
                        {finding.evidence_pcap}
                      </span>
                      <span className="text-amber-400 text-[10px] block">
                        {finding.evidence_frames || 'Frames #1 - #10'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Observation & Correlation Explanation */}
                <div className="space-y-1.5 text-xs text-slate-300">
                  <div>
                    <span className="text-slate-400 font-bold uppercase text-[10px]">OBSERVATION:</span>
                    <p className="mt-0.5 text-slate-300 leading-relaxed">{finding.observation}</p>
                  </div>
                  <div>
                    <span className="text-slate-400 font-bold uppercase text-[10px]">
                      CORRELATION RATIONALE (NOT PROOF OF COMPROMISE):
                    </span>
                    <p className="mt-0.5 text-slate-400 leading-relaxed text-[11px]">
                      {finding.correlation_explanation}
                    </p>
                  </div>
                </div>

                {/* Analyst Notes if triaged */}
                {finding.analyst_conclusion && (
                  <div className="p-2.5 rounded bg-blue-950/30 border border-blue-500/30 text-xs">
                    <span className="text-[10px] font-bold text-blue-400 uppercase tracking-wide block mb-1">
                      ANALYST TRIAGE CONCLUSION ({finding.assigned_to || 'Analyst'}):
                    </span>
                    <p className="text-slate-200">{finding.analyst_conclusion}</p>
                    {finding.analyst_notes && (
                      <p className="text-slate-400 text-[11px] mt-1">{finding.analyst_notes}</p>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────── */}
      {/* MODAL 1: DEEP PACKET INSPECTOR (Module 3 & 4)                */}
      {/* ─────────────────────────────────────────────────────────── */}
      {inspectCapture && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#080d1a] border border-slate-700 rounded-2xl w-full max-w-6xl max-h-[90vh] flex flex-col shadow-2xl font-mono overflow-hidden">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
              <div className="flex items-center gap-3">
                <FileCode className="h-5 w-5 text-cyan-400" />
                <div>
                  <h3 className="text-sm font-bold text-white">
                    TSHARK PACKET DISASSEMBLER — {inspectCapture.filename}
                  </h3>
                  <span className="text-[11px] text-slate-400">
                    Capture ID: {inspectCapture.capture_id} • Interface: {inspectCapture.interface} • {packets.length} parsed frames
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleDownloadPcap(inspectCapture)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold flex items-center gap-1.5 border border-slate-700 transition"
                >
                  <Download className="h-3.5 w-3.5" />
                  <span>OPEN IN WIRESHARK (.PCAP)</span>
                </button>
                <button
                  onClick={() => setInspectCapture(null)}
                  className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200"
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Modal Body: Split view (Packet List & Decoded Layers) */}
            <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 overflow-hidden">
              {/* Left Column: Packet List Table */}
              <div className="border-r border-slate-800 overflow-y-auto max-h-[60vh]">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900/90 text-slate-400 sticky top-0 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="py-2 px-3">FRAME</th>
                      <th className="py-2 px-3">SOURCE</th>
                      <th className="py-2 px-3">DEST</th>
                      <th className="py-2 px-3">PROTO</th>
                      <th className="py-2 px-3">INFO</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {packets.map((pkt) => {
                      const isSelected = selectedPacket?.frame_number === pkt.frame_number;
                      return (
                        <tr
                          key={pkt.id}
                          onClick={() => setSelectedPacket(pkt)}
                          className={`cursor-pointer transition ${
                            isSelected ? 'bg-cyan-500/20 text-cyan-200 font-semibold' : 'hover:bg-slate-800/40 text-slate-300'
                          }`}
                        >
                          <td className="py-2 px-3 text-slate-400">#{pkt.frame_number}</td>
                          <td className="py-2 px-3">{pkt.source_ip}</td>
                          <td className="py-2 px-3">{pkt.destination_ip}</td>
                          <td className="py-2 px-3">
                            <span
                              className="px-1.5 py-0.5 rounded text-[9px] font-bold"
                              style={{
                                backgroundColor: `${PROTOCOL_COLORS[pkt.protocol] || '#06b6d4'}20`,
                                color: PROTOCOL_COLORS[pkt.protocol] || '#06b6d4'
                              }}
                            >
                              {pkt.protocol}
                            </span>
                          </td>
                          <td className="py-2 px-3 text-[11px] truncate max-w-[150px] text-slate-400">
                            {pkt.info}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Right Column: Layer Breakdown & Raw Hex Dump */}
              <div className="overflow-y-auto max-h-[60vh] p-5 space-y-4">
                {selectedPacket ? (
                  <>
                    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <span className="text-xs font-bold text-white uppercase tracking-wider">
                        FRAME #{selectedPacket.frame_number} PROTOCOL TREE
                      </span>
                      <span className="text-[11px] text-slate-400">
                        Length: {selectedPacket.packet_length} bytes
                      </span>
                    </div>

                    {/* Protocol Layer Accordions */}
                    <div className="space-y-2 text-xs">
                      {/* Layer 2: Ethernet */}
                      <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800">
                        <span className="text-cyan-400 font-bold block mb-1">
                          Ethernet II, Src: 52:54:00:xx:xx:xx, Dst: 52:54:00:yy:yy:yy
                        </span>
                        <div className="text-[11px] text-slate-400 space-y-0.5 pl-2">
                          <div>Destination: Broadcast / Unicast</div>
                          <div>Type: IPv4 (0x0800)</div>
                        </div>
                      </div>

                      {/* Layer 3: IPv4 */}
                      <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800">
                        <span className="text-blue-400 font-bold block mb-1">
                          Internet Protocol Version 4, Src: {selectedPacket.source_ip}, Dst: {selectedPacket.destination_ip}
                        </span>
                        <div className="text-[11px] text-slate-400 space-y-0.5 pl-2">
                          <div>Version: 4, Header Length: 20 bytes</div>
                          <div>Protocol: {selectedPacket.protocol}</div>
                          <div>Source Address: {selectedPacket.source_ip}</div>
                          <div>Destination Address: {selectedPacket.destination_ip}</div>
                        </div>
                      </div>

                      {/* Layer 4: Transport (TCP / UDP) */}
                      <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800">
                        <span className="text-purple-400 font-bold block mb-1">
                          {selectedPacket.protocol} Transport Layer (Src Port: {selectedPacket.source_port}, Dst Port: {selectedPacket.destination_port})
                        </span>
                        <div className="text-[11px] text-slate-400 space-y-0.5 pl-2">
                          {selectedPacket.tcp_flags && <div>Flags: [{selectedPacket.tcp_flags}]</div>}
                          <div>Payload Summary: {selectedPacket.info}</div>
                        </div>
                      </div>

                      {/* Wireshark Display Filter Helper */}
                      <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                        <div>
                          <span className="text-[10px] text-slate-400 uppercase block">WIRESHARK FILTER:</span>
                          <span className="text-cyan-300 font-mono text-[11px]">
                            ip.addr == {selectedPacket.source_ip} && tcp.port == {selectedPacket.destination_port || 80}
                          </span>
                        </div>
                        <button
                          onClick={() => {
                            navigator.clipboard.writeText(`ip.addr == ${selectedPacket.source_ip} && tcp.port == ${selectedPacket.destination_port || 80}`);
                          }}
                          className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px]"
                        >
                          COPY
                        </button>
                      </div>

                      {/* Raw Hex Dump Inspector */}
                      {selectedPacket.raw_hex && (
                        <div className="space-y-1">
                          <span className="text-[10px] text-slate-400 uppercase font-bold block">
                            RAW PACKET PAYLOAD HEX DUMP (FIRST 64 BYTES):
                          </span>
                          <div className="p-3 bg-slate-950 border border-slate-800 rounded font-mono text-[11px] text-cyan-400 break-all leading-relaxed">
                            {selectedPacket.raw_hex}
                          </div>
                        </div>
                      )}
                    </div>
                  </>
                ) : (
                  <div className="h-full flex items-center justify-center text-slate-400 text-xs">
                    Select a packet to inspect protocol breakdown.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────── */}
      {/* MODAL 2: ANALYST WORKFLOW & TRIAGE (Module 12)               */}
      {/* ─────────────────────────────────────────────────────────── */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#080d1a] border border-slate-700 rounded-2xl w-full max-w-2xl p-6 shadow-2xl font-mono space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-xs font-bold text-white uppercase flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-red-400" />
                  INCIDENT TRIAGE WORKFLOW — {selectedFinding.alert_code}
                </span>
                <span className="text-[11px] text-slate-400">
                  {selectedFinding.title}
                </span>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="p-1.5 rounded hover:bg-slate-800 text-slate-400"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">INCIDENT TRIAGE STATUS</label>
                <select
                  value={triageStatus}
                  onChange={(e) => setTriageStatus(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="INVESTIGATING">INVESTIGATING (Under active analysis)</option>
                  <option value="RESOLVED">RESOLVED (Mitigation / Firewall applied)</option>
                  <option value="BENIGN_ANOMALY">BENIGN ANOMALY (Authorized vendor telemetry)</option>
                  <option value="FALSE_POSITIVE">FALSE POSITIVE (Dismissed)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">ANALYST FORENSIC CONCLUSION</label>
                <textarea
                  rows={3}
                  placeholder="e.g. Verified RTSP stream exfiltration attempt matching CVE-2021-36260 in Wireshark. Device isolated."
                  value={triageConclusion}
                  onChange={(e) => setTriageConclusion(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">INVESTIGATION NOTES &amp; WIRESHARK FINDINGS</label>
                <textarea
                  rows={2}
                  placeholder="Record specific packet frame numbers, TCP streams, or SIEM ticket IDs..."
                  value={triageNotes}
                  onChange={(e) => setTriageNotes(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="p-3 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
                <span>EVIDENCE: {selectedFinding.evidence_pcap} ({selectedFinding.evidence_frames})</span>
                <span className="text-cyan-400 font-bold">Assigned: {user?.full_name}</span>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedFinding(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold"
              >
                CANCEL
              </button>
              <button
                onClick={handleSaveTriage}
                disabled={isSubmittingTriage}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold flex items-center gap-2 shadow-lg shadow-cyan-500/20"
              >
                <CheckCircle className="h-4 w-4" />
                <span>SAVE &amp; UPDATE INCIDENT</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
