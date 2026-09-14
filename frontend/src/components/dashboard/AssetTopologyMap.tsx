import React, { useState } from 'react';
import { Server, Shield, Video, Cpu, Laptop, Lock, Unlock, ExternalLink } from 'lucide-react';
import { Asset } from '../../types';
import { Badge } from '../common/Badge';

interface AssetTopologyMapProps {
  assets: Asset[];
  onSelectAsset: (asset: Asset) => void;
}

export const AssetTopologyMap: React.FC<AssetTopologyMapProps> = ({ assets, onSelectAsset }) => {
  const [hoveredNode, setHoveredNode] = useState<Asset | null>(null);

  const getNodeIcon = (type: string, isCctv: boolean, isIot: boolean) => {
    if (isCctv) return <Video className="h-4 w-4" />;
    if (isIot) return <Cpu className="h-4 w-4" />;
    if (type === 'Firewall' || type === 'Router') return <Shield className="h-4 w-4" />;
    if (type === 'Workstation') return <Laptop className="h-4 w-4" />;
    return <Server className="h-4 w-4" />;
  };

  const getNodeColor = (asset: Asset) => {
    if (asset.is_quarantined) return 'border-red-500 bg-red-950/70 text-red-400 shadow-red-500/30';
    if (asset.risk_score >= 75) return 'border-red-400/80 bg-slate-900 text-red-400 shadow-red-500/20';
    if (asset.risk_score >= 45) return 'border-amber-400/80 bg-slate-900 text-amber-400 shadow-amber-500/20';
    return 'border-cyan-400/80 bg-slate-900 text-cyan-400 shadow-cyan-500/20';
  };

  return (
    <div className="cyber-card p-6 rounded-2xl relative overflow-hidden flex flex-col justify-between h-full">
      <div className="flex items-center justify-between mb-4">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
            NETWORK TOPOLOGY & ASSET MATRIX
          </span>
          <p className="text-xs text-slate-400 mt-0.5">Discovered Subnets (192.168.1.0/24)</p>
        </div>
        <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-cyan-400" /> Secure
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-amber-400" /> Warning
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" /> Threat/Quarantine
          </span>
        </div>
      </div>

      {/* Grid of Nodes in SOC Layout */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3.5 my-2">
        {assets.map((asset) => {
          const isQuarantined = asset.is_quarantined;
          return (
            <div
              key={asset.id}
              onClick={() => onSelectAsset(asset)}
              onMouseEnter={() => setHoveredNode(asset)}
              onMouseLeave={() => setHoveredNode(null)}
              className={`p-3 rounded-xl border transition-all duration-200 cursor-pointer relative group flex flex-col justify-between ${getNodeColor(
                asset
              )} hover:scale-105 hover:z-20`}
            >
              {/* Header inside card */}
              <div className="flex items-start justify-between">
                <div className="p-1.5 rounded-md bg-slate-950/80 border border-slate-800">
                  {getNodeIcon(asset.device_type, asset.is_cctv, asset.is_iot)}
                </div>
                <div className="flex items-center gap-1">
                  {isQuarantined && (
                    <span className="p-1 rounded bg-red-500/20 text-red-400 border border-red-500/40" title="Quarantined">
                      <Lock className="h-3 w-3" />
                    </span>
                  )}
                  <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800">
                    {asset.risk_score}
                  </span>
                </div>
              </div>

              {/* Node IP & Hostname */}
              <div className="mt-3">
                <p className="text-xs font-bold font-mono text-white truncate">
                  {asset.hostname || asset.ip_address}
                </p>
                <p className="text-[11px] font-mono text-slate-400">{asset.ip_address}</p>
              </div>

              {/* Type / CCTV badge */}
              <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
                <span className="truncate max-w-[85px]">{asset.device_type}</span>
                <span>{asset.open_ports?.length || 0} Ports</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Hover preview tooltip drawer */}
      {hoveredNode && (
        <div className="mt-3 p-3 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono flex items-center justify-between text-slate-300">
          <div>
            <span className="text-cyan-400 font-bold">{hoveredNode.hostname || hoveredNode.ip_address}</span>
            <span className="text-slate-400 ml-2">({hoveredNode.os_name} {hoveredNode.os_version})</span>
          </div>
          <div className="flex items-center gap-2">
            <span>Ports: {hoveredNode.open_ports.map(p => p.port).join(', ')}</span>
            <span className="text-slate-400">|</span>
            <span className="text-amber-400 font-bold">Risk: {hoveredNode.risk_score}</span>
          </div>
        </div>
      )}
    </div>
  );
};
