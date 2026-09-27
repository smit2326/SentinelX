import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Server,
  Bug,
  AlertTriangle,
  Radio,
  Search,
  Scan,
  RefreshCw,
  Video,
  Cpu,
  Lock,
  X
} from 'lucide-react';
import { api } from '../services/api';
import { Asset, DashboardTelemetry, Alert, Vulnerability } from '../types';
import { useAuth } from '../context/AuthContext';
import { useWebSocket } from '../context/WebSocketContext';
import { StatCard } from '../components/common/StatCard';
import { RiskGauge } from '../components/dashboard/RiskGauge';
import { AssetTopologyMap } from '../components/dashboard/AssetTopologyMap';
import { LiveAlertFeed } from '../components/dashboard/LiveAlertFeed';
import { Badge } from '../components/common/Badge';

export const DashboardPage: React.FC<{ onNavigate: (tab: string) => void }> = ({ onNavigate }) => {
  const { isAnalyst } = useAuth();
  const { liveAlerts, scanProgress } = useWebSocket();
  const [telemetry, setTelemetry] = useState<DashboardTelemetry | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  
  // Modals & Drawers
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [isScanModalOpen, setIsScanModalOpen] = useState<boolean>(false);
  const [scanSubnet, setScanSubnet] = useState<string>('192.168.1.0/24');
  const [scanType, setScanType] = useState<string>('full');

  const fetchDashboardData = async () => {
    try {
      const [telRes, assetsRes] = await Promise.all([
        api.get('/telemetry/dashboard'),
        api.get('/assets')
      ]);
      setTelemetry(telRes.data);
      setAssets(assetsRes.data);
    } catch (e) {
      console.error('Failed to load dashboard telemetry:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleTriggerScan = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.post('/assets/scan', {
        target_subnet: scanSubnet,
        scan_type: scanType
      });
      setIsScanModalOpen(false);
    } catch (e) {
      console.error('Scan trigger error:', e);
    }
  };

  const handleToggleQuarantine = async (assetId: number) => {
    try {
      const res = await api.post(`/assets/${assetId}/quarantine`);
      setSelectedAsset(res.data.asset);
      await fetchDashboardData();
    } catch (e) {
      console.error('Quarantine toggle error:', e);
    }
  };

  const handleAcknowledgeAlert = async (alertId: number) => {
    try {
      await api.put(`/alerts/${alertId}/status`, { status: 'RESOLVED' });
      await fetchDashboardData();
      if (selectedAlert?.id === alertId) {
        setSelectedAlert(null);
      }
    } catch (e) {
      console.error('Error resolving alert:', e);
    }
  };

  if (isLoading && !telemetry) {
    return (
      <div className="flex items-center justify-center min-h-[500px]">
        <div className="flex flex-col items-center gap-3">
          <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
          <span className="text-xs font-mono text-slate-400">CONNECTING TO AEGIS CORRELATION ENGINE...</span>
        </div>
      </div>
    );
  }

  const risk = telemetry?.risk_summary || {
    overall_score: 45,
    grade: 'B',
    risk_level: 'MODERATE',
    total_assets: assets.length,
    quarantined: 1,
    critical_assets: 2,
    active_critical_alerts: 1
  };

  return (
    <div className="space-y-6">
      {/* Top Banner / Hero Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center gap-2.5">
            <Radio className="h-5 w-5 text-cyan-400 animate-pulse" />
            AEGIS SOC OVERVIEW &amp; RISK CORRELATION
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Unified multi-vector risk correlation &amp; live network traffic telemetry stream.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {isAnalyst && (
            <>
              <button
                onClick={() => onNavigate('network')}
                className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/40 text-xs font-mono font-bold shadow-md shadow-cyan-950/50 transition-all"
              >
                <Radio className="h-4 w-4 text-cyan-400 animate-pulse" />
                <span>NETWORK TRAFFIC &amp; PCAP</span>
              </button>
              <button
                onClick={() => setIsScanModalOpen(true)}
                className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono font-bold transition-all"
              >
                <Scan className="h-4 w-4 text-cyan-400" />
                <span>DISCOVERY SCAN</span>
              </button>
            </>
          )}
          <button
            onClick={fetchDashboardData}
            className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-all"
            title="Refresh Metrics"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Hero Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Monitored Assets"
          value={telemetry?.assets_summary.total || assets.length}
          subtitle={`${telemetry?.assets_summary.online || 0} Online • ${telemetry?.assets_summary.cctv_iot || 0} CCTV/IoT`}
          icon={<Server className="h-5 w-5" />}
          color="cyan"
          onClick={() => onNavigate('assets')}
        />
        <StatCard
          title="Active Threat Alerts"
          value={telemetry?.active_alerts_count || 0}
          subtitle={`${risk.active_critical_alerts} Critical Alerts`}
          icon={<AlertTriangle className="h-5 w-5" />}
          color="red"
          onClick={() => onNavigate('alerts')}
        />
        <StatCard
          title="Vulnerabilities (CVEs)"
          value={
            (telemetry?.vulnerabilities_summary.critical || 0) +
            (telemetry?.vulnerabilities_summary.high || 0) +
            (telemetry?.vulnerabilities_summary.medium || 0)
          }
          subtitle={`${telemetry?.vulnerabilities_summary.critical || 0} Critical • ${telemetry?.vulnerabilities_summary.high || 0} High`}
          icon={<Bug className="h-5 w-5" />}
          color="amber"
          onClick={() => onNavigate('vulnerabilities')}
        />
        <StatCard
          title="Quarantine Enforced"
          value={telemetry?.assets_summary.quarantined || 0}
          subtitle="Isolated from Core Subnet"
          icon={<Lock className="h-5 w-5" />}
          color="purple"
          onClick={() => onNavigate('assets')}
        />
      </div>

      {/* Main Grid: Risk Gauge & Network Topology Map */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Risk Gauge: 4 cols on large */}
        <div className="lg:col-span-4 h-full">
          <RiskGauge
            score={risk.overall_score}
            grade={risk.grade}
            level={risk.risk_level}
            criticalAssets={risk.critical_assets}
            quarantinedCount={risk.quarantined}
          />
        </div>

        {/* Network Topology Map: 8 cols on large */}
        <div className="lg:col-span-8 h-full">
          <AssetTopologyMap
            assets={assets}
            onSelectAsset={(asset) => setSelectedAsset(asset)}
          />
        </div>
      </div>

      {/* Lower Grid: Live Alerts Feed & CCTV / IoT Telemetry Widget */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Live Incident Stream */}
        <div className="lg:col-span-7">
          <LiveAlertFeed
            alerts={telemetry?.recent_alerts || []}
            onSelectAlert={(alert) => setSelectedAlert(alert)}
            onAcknowledge={handleAcknowledgeAlert}
          />
        </div>

        {/* CCTV & IoT Device Inventory Highlight */}
        <div className="lg:col-span-5 cyber-card p-6 rounded-2xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Video className="h-4 w-4 text-cyan-400" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                  CCTV &amp; IOT DEVICE RADAR
                </span>
              </div>
              <span className="text-[11px] font-mono text-cyan-400">
                {assets.filter(a => a.is_cctv || a.is_iot).length} Monitored Units
              </span>
            </div>

            <div className="space-y-3">
              {assets.filter(a => a.is_cctv || a.is_iot).slice(0, 4).map((dev) => (
                <div
                  key={dev.id}
                  onClick={() => setSelectedAsset(dev)}
                  className="p-3 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all flex items-center justify-between"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-cyan-400">
                      {dev.is_cctv ? <Video className="h-4 w-4" /> : <Cpu className="h-4 w-4" />}
                    </div>
                    <div>
                      <p className="text-xs font-bold font-mono text-white truncate max-w-[160px]">
                        {dev.hostname || dev.ip_address}
                      </p>
                      <p className="text-[11px] font-mono text-slate-400">
                        {dev.ip_address} • {dev.vendor || 'Unknown'}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <Badge size="sm" variant={dev.is_quarantined ? 'critical' : 'success'}>
                      {dev.status}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <button
            onClick={() => onNavigate('assets')}
            className="w-full mt-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-xs font-mono text-cyan-400 border border-slate-800 transition-all text-center"
          >
            VIEW ALL HARDWARE ASSETS →
          </button>
        </div>
      </div>

      {/* ASSET DETAILS DRAWER / MODAL */}
      {selectedAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="cyber-card w-full max-w-2xl rounded-2xl p-6 relative border border-slate-700 animate-in fade-in zoom-in-95 duration-150 max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setSelectedAsset(null)}
              className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-white bg-slate-800"
            >
              <X className="h-4 w-4" />
            </button>

            <div className="flex items-center gap-3">
              <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                {selectedAsset.is_cctv ? <Video className="h-6 w-6" /> : <Server className="h-6 w-6" />}
              </div>
              <div>
                <h2 className="text-base font-bold font-mono text-white">
                  {selectedAsset.hostname || selectedAsset.ip_address}
                </h2>
                <p className="text-xs text-slate-400 font-mono">
                  {selectedAsset.ip_address} • MAC: {selectedAsset.mac_address || 'Unknown'}
                </p>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 my-4 font-mono text-xs">
              <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 block">TYPE</span>
                <span className="font-bold text-white">{selectedAsset.device_type}</span>
              </div>
              <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 block">RISK SCORE</span>
                <span className={`font-bold ${selectedAsset.risk_score >= 70 ? 'text-red-400' : 'text-cyan-400'}`}>
                  {selectedAsset.risk_score} / 100
                </span>
              </div>
              <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 block">OS / PLATFORM</span>
                <span className="font-bold text-white truncate block">{selectedAsset.os_name || 'N/A'}</span>
              </div>
              <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 block">STATUS</span>
                <Badge size="sm">{selectedAsset.status}</Badge>
              </div>
            </div>

            {/* Ports & Services */}
            <div className="mt-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono mb-2">
                OPEN PORTS &amp; SERVICE FINGERPRINTS
              </h3>
              <div className="space-y-1.5 max-h-40 overflow-y-auto">
                {selectedAsset.open_ports?.map((p, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono">
                    <span className="text-cyan-400 font-bold">PORT {p.port}/{p.protocol}</span>
                    <span className="text-white">{p.service}</span>
                    <span className="text-slate-400">{p.version || 'Banner Captured'}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Actions: Quarantine */}
            {isAnalyst && (
              <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between">
                <span className="text-xs text-slate-400 font-mono">
                  Network Containment Controls
                </span>
                <button
                  onClick={() => handleToggleQuarantine(selectedAsset.id)}
                  className={`px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all ${
                    selectedAsset.is_quarantined
                      ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                      : 'bg-red-600 hover:bg-red-500 text-white'
                  }`}
                >
                  {selectedAsset.is_quarantined ? 'RELEASE FROM QUARANTINE' : 'ISOLATE / QUARANTINE DEVICE'}
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ALERT INSPECTION MODAL */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="cyber-card w-full max-w-2xl rounded-2xl p-6 relative border border-slate-700 animate-in fade-in zoom-in-95 duration-150 max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setSelectedAlert(null)}
              className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-white bg-slate-800"
            >
              <X className="h-4 w-4" />
            </button>

            <div className="flex items-center gap-2">
              <Badge variant={selectedAlert.severity.toLowerCase() as any}>
                {selectedAlert.severity}
              </Badge>
              <span className="text-xs font-mono text-slate-400">
                {selectedAlert.category} • {new Date(selectedAlert.created_at).toLocaleString()}
              </span>
            </div>

            <h2 className="text-base font-bold font-mono text-white mt-2">
              {selectedAlert.title}
            </h2>

            <p className="text-xs text-slate-300 font-mono mt-3 leading-relaxed bg-slate-900/60 p-3 rounded-xl border border-slate-800">
              {selectedAlert.description}
            </p>

            <div className="grid grid-cols-2 gap-3 my-4 font-mono text-xs">
              <div className="bg-slate-900 p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-400 block uppercase">Source IP</span>
                <span className="font-bold text-cyan-400">{selectedAlert.source_ip || 'Internal'}</span>
              </div>
              <div className="bg-slate-900 p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-400 block uppercase">Destination IP</span>
                <span className="font-bold text-amber-400">{selectedAlert.destination_ip || 'N/A'}</span>
              </div>
            </div>

            {selectedAlert.raw_packet_hex && (
              <div className="mt-4">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                    RAW PCAP PACKET PAYLOAD (HEX DUMP)
                  </span>
                </div>
                <pre className="p-3 rounded-xl bg-black text-[11px] font-mono text-emerald-400 border border-slate-800 overflow-x-auto whitespace-pre-wrap">
                  {selectedAlert.raw_packet_hex}
                </pre>
              </div>
            )}

            <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-end gap-3">
              {selectedAlert.status !== 'RESOLVED' && isAnalyst && (
                <button
                  onClick={() => handleAcknowledgeAlert(selectedAlert.id)}
                  className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-mono font-bold text-xs"
                >
                  ACKNOWLEDGE &amp; RESOLVE INCIDENT
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* DISCOVERY SCAN MODAL */}
      {isScanModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="cyber-card w-full max-w-md rounded-2xl p-6 relative border border-slate-700 animate-in fade-in zoom-in-95 duration-150">
            <button
              onClick={() => setIsScanModalOpen(false)}
              className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-white bg-slate-800"
            >
              <X className="h-4 w-4" />
            </button>

            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Scan className="h-5 w-5 text-cyan-400" />
                <h2 className="text-sm font-bold font-mono text-white uppercase">
                  ACTIVE ASSET DISCOVERY SCAN
                </h2>
              </div>
              <span className="text-[10px] font-mono text-cyan-400 px-1.5 py-0.5 rounded bg-cyan-950/60 border border-cyan-500/40">
                ACTIVE SOCKET PROBE
              </span>
            </div>

            <p className="text-[11px] font-mono text-slate-400 mb-3 bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
              Performs real asynchronous socket probing, port inspection, and hostname resolution on target network devices.
            </p>

            <form onSubmit={handleTriggerScan} className="space-y-4 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1">TARGET HOST / CIDR / SUBNET</label>
                <input
                  type="text"
                  value={scanSubnet}
                  onChange={(e) => setScanSubnet(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">DISCOVERY PROFILE</label>
                <select
                  value={scanType}
                  onChange={(e) => setScanType(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400"
                >
                  <option value="full">Full Port &amp; Service Fingerprint (TCP SYN + Banners)</option>
                  <option value="quick">Quick Probe (Top Common Ports)</option>
                  <option value="cctv_iot">CCTV / RTSP / Modbus Endpoint Sweep</option>
                </select>
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  className="w-full py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold tracking-wider transition-all shadow-lg shadow-cyan-500/20"
                >
                  START ACTIVE DISCOVERY SCAN
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
