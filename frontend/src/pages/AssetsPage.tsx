import React, { useState, useEffect } from 'react';
import {
  Server,
  Search,
  Scan,
  Video,
  Cpu,
  Shield,
  Laptop,
  Plus,
  Lock,
  Unlock,
  RefreshCw,
  ExternalLink,
  X,
  Filter
} from 'lucide-react';
import { api } from '../services/api';
import { Asset } from '../types';
import { useAuth } from '../context/AuthContext';
import { Badge } from '../components/common/Badge';

export const AssetsPage: React.FC = () => {
  const { isAnalyst, isAdmin } = useAuth();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [search, setSearch] = useState<string>('');
  const [filterType, setFilterType] = useState<string>('all');
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);

  // Discovery Scan Modal
  const [isScanModalOpen, setIsScanModalOpen] = useState<boolean>(false);
  const [scanSubnet, setScanSubnet] = useState<string>('192.168.1.0/24');
  const [scanType, setScanType] = useState<string>('full');

  const fetchAssets = async () => {
    try {
      setIsLoading(true);
      const res = await api.get('/assets');
      setAssets(res.data);
    } catch (e) {
      console.error('Error fetching assets:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  const handleToggleQuarantine = async (assetId: number) => {
    try {
      const res = await api.post(`/assets/${assetId}/quarantine`);
      setAssets(assets.map(a => a.id === assetId ? res.data.asset : a));
      if (selectedAsset?.id === assetId) {
        setSelectedAsset(res.data.asset);
      }
    } catch (e) {
      console.error('Failed to toggle quarantine:', e);
    }
  };

  const handleTriggerScan = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.post('/assets/scan', {
        target_subnet: scanSubnet,
        scan_type: scanType
      });
      setIsScanModalOpen(false);
      setTimeout(fetchAssets, 3000);
    } catch (e) {
      console.error('Scan dispatch error:', e);
    }
  };

  const filteredAssets = assets.filter(a => {
    const matchesSearch =
      a.ip_address.toLowerCase().includes(search.toLowerCase()) ||
      (a.hostname || '').toLowerCase().includes(search.toLowerCase()) ||
      (a.vendor || '').toLowerCase().includes(search.toLowerCase()) ||
      (a.os_name || '').toLowerCase().includes(search.toLowerCase());

    if (!matchesSearch) return false;
    if (filterType === 'cctv') return a.is_cctv;
    if (filterType === 'iot') return a.is_iot;
    if (filterType === 'quarantined') return a.is_quarantined;
    if (filterType === 'server') return a.device_type === 'Server';
    if (filterType === 'firewall') return a.device_type === 'Firewall' || a.device_type === 'Router';
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center gap-2">
            <Server className="h-5 w-5 text-cyan-400" />
            ASSET INVENTORY &amp; CCTV/IOT DISCOVERY
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Automated fingerprinting of network devices, open ports, firmware versions, and video endpoints.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {isAnalyst && (
            <button
              onClick={() => setIsScanModalOpen(true)}
              className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-mono font-bold transition-all shadow-md shadow-cyan-500/20"
            >
              <Scan className="h-4 w-4" />
              <span>DISCOVERY SCAN</span>
            </button>
          )}
          <button
            onClick={fetchAssets}
            className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-all"
            title="Refresh"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="cyber-card p-4 rounded-xl flex flex-col md:flex-row items-center justify-between gap-4 font-mono text-xs">
        <div className="relative w-full md:w-80">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search IP, hostname, vendor..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900/80 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
          />
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto w-full md:w-auto pb-1 md:pb-0">
          {[
            { id: 'all', label: 'All Assets' },
            { id: 'cctv', label: 'CCTV Cameras' },
            { id: 'iot', label: 'IoT Devices' },
            { id: 'server', label: 'Servers' },
            { id: 'firewall', label: 'Firewalls' },
            { id: 'quarantined', label: 'Quarantined' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setFilterType(tab.id)}
              className={`px-3 py-1.5 rounded-lg whitespace-nowrap transition-all ${
                filterType === tab.id
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                  : 'text-slate-400 hover:text-white bg-slate-900/60 border border-slate-800'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Assets Table */}
      <div className="cyber-card rounded-2xl overflow-hidden border border-slate-800">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 uppercase text-[10px]">
              <tr>
                <th className="py-3.5 px-4">Device / Hostname</th>
                <th className="py-3.5 px-4">IP &amp; MAC</th>
                <th className="py-3.5 px-4">Type / Vendor</th>
                <th className="py-3.5 px-4">Operating System</th>
                <th className="py-3.5 px-4">Open Ports</th>
                <th className="py-3.5 px-4">Risk Score</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400 font-mono">
                    No matching assets discovered.
                  </td>
                </tr>
              ) : (
                filteredAssets.map((asset) => (
                  <tr
                    key={asset.id}
                    className="hover:bg-slate-900/40 transition-colors cursor-pointer"
                    onClick={() => setSelectedAsset(asset)}
                  >
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2.5">
                        <div className="p-1.5 rounded-md bg-slate-900 border border-slate-800 text-cyan-400">
                          {asset.is_cctv ? <Video className="h-4 w-4" /> : asset.is_iot ? <Cpu className="h-4 w-4" /> : <Server className="h-4 w-4" />}
                        </div>
                        <div>
                          <p className="font-bold text-white">{asset.hostname || 'Unknown Host'}</p>
                          <span className="text-[10px] text-slate-400">{asset.location}</span>
                        </div>
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <p className="font-bold text-cyan-300">{asset.ip_address}</p>
                      <p className="text-[10px] text-slate-400">{asset.mac_address || 'N/A'}</p>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-slate-300">{asset.device_type}</span>
                        {asset.is_cctv && (
                          <span className="px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 text-[9px] border border-cyan-500/30">
                            CCTV
                          </span>
                        )}
                        {asset.is_iot && !asset.is_cctv && (
                          <span className="px-1.5 py-0.5 rounded bg-purple-950 text-purple-400 text-[9px] border border-purple-500/30">
                            IoT
                          </span>
                        )}
                      </div>
                      <span className="text-[10px] text-slate-400 block">{asset.vendor || 'Unknown Vendor'}</span>
                    </td>

                    <td className="py-3.5 px-4 text-slate-300">
                      <p>{asset.os_name || 'Generic OS'}</p>
                      <span className="text-[10px] text-slate-400">{asset.os_version || 'N/A'}</span>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-1 flex-wrap max-w-[140px]">
                        {asset.open_ports.slice(0, 3).map((p, i) => (
                          <span key={i} className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] text-slate-300">
                            {p.port}
                          </span>
                        ))}
                        {asset.open_ports.length > 3 && (
                          <span className="text-[10px] text-slate-400">+{asset.open_ports.length - 3}</span>
                        )}
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <span
                        className={`font-bold px-2 py-0.5 rounded text-xs ${
                          asset.risk_score >= 70
                            ? 'bg-red-500/15 text-red-400 border border-red-500/30'
                            : asset.risk_score >= 40
                            ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                            : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                        }`}
                      >
                        {asset.risk_score}
                      </span>
                    </td>

                    <td className="py-3.5 px-4">
                      <Badge variant={asset.is_quarantined ? 'critical' : 'success'}>
                        {asset.status}
                      </Badge>
                    </td>

                    <td className="py-3.5 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                      {isAnalyst && (
                        <button
                          onClick={() => handleToggleQuarantine(asset.id)}
                          className={`p-1.5 rounded-lg transition-all ${
                            asset.is_quarantined
                              ? 'bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-500/40'
                              : 'bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-500/40'
                          }`}
                          title={asset.is_quarantined ? 'Release Quarantine' : 'Quarantine Asset'}
                        >
                          {asset.is_quarantined ? <Unlock className="h-4 w-4" /> : <Lock className="h-4 w-4" />}
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* SCAN TRIGGER MODAL */}
      {isScanModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="cyber-card w-full max-w-md rounded-2xl p-6 relative border border-slate-700 animate-in fade-in zoom-in-95 duration-150">
            <button
              onClick={() => setIsScanModalOpen(false)}
              className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-white bg-slate-800"
            >
              <X className="h-4 w-4" />
            </button>

            <div className="flex items-center gap-2 mb-4">
              <Scan className="h-5 w-5 text-cyan-400" />
              <h2 className="text-sm font-bold font-mono text-white uppercase">
                LAUNCH ASSET DISCOVERY SCAN
              </h2>
            </div>

            <form onSubmit={handleTriggerScan} className="space-y-4 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1">TARGET SUBNET (CIDR)</label>
                <input
                  type="text"
                  value={scanSubnet}
                  onChange={(e) => setScanSubnet(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">SCAN METHODOLOGY</label>
                <select
                  value={scanType}
                  onChange={(e) => setScanType(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400"
                >
                  <option value="full">Comprehensive Nmap SYN + Version Fingerprinting</option>
                  <option value="cctv_iot">Dedicated CCTV / RTSP / ONVIF Deep Probing</option>
                  <option value="quick">Quick Discovery (Top 100 Common Ports)</option>
                </select>
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  className="w-full py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold tracking-wider transition-all shadow-lg shadow-cyan-500/20"
                >
                  START DISCOVERY
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ASSET DETAIL MODAL */}
      {selectedAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="cyber-card w-full max-w-2xl rounded-2xl p-6 relative border border-slate-700 max-h-[90vh] overflow-y-auto">
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
                  {selectedAsset.ip_address} • Vendor: {selectedAsset.vendor || 'Unknown'}
                </p>
              </div>
            </div>

            {selectedAsset.is_cctv && selectedAsset.cctv_stream_protocol && (
              <div className="mt-4 p-3 rounded-xl bg-cyan-950/40 border border-cyan-500/40 text-xs font-mono text-cyan-300 flex items-center justify-between">
                <span>RTSP VIDEO PROTOCOL: {selectedAsset.cctv_stream_protocol}</span>
                <span className="text-amber-400">Firmware: {selectedAsset.firmware_version || 'v1.0'}</span>
              </div>
            )}

            <div className="mt-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono mb-2">
                FINGERPRINTED PORTS &amp; SERVICES
              </h3>
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {selectedAsset.open_ports.map((p, i) => (
                  <div key={i} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-900 border border-slate-800 font-mono text-xs">
                    <span className="text-cyan-400 font-bold">{p.port}/{p.protocol}</span>
                    <span className="text-white">{p.service}</span>
                    <span className="text-slate-400">{p.version || 'Captured'}</span>
                  </div>
                ))}
              </div>
            </div>

            {isAnalyst && (
              <div className="mt-6 pt-4 border-t border-slate-800 flex justify-end">
                <button
                  onClick={() => handleToggleQuarantine(selectedAsset.id)}
                  className={`px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all ${
                    selectedAsset.is_quarantined
                      ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                      : 'bg-red-600 hover:bg-red-500 text-white'
                  }`}
                >
                  {selectedAsset.is_quarantined ? 'RELEASE FROM QUARANTINE' : 'QUARANTINE / CONTAIN DEVICE'}
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
