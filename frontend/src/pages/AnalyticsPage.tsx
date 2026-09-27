import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  TrendingUp,
  Activity,
  Cpu,
  RefreshCw,
  Search,
  ChevronRight,
  Info,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Database
} from 'lucide-react';
import { api } from '../services/api';
import {
  RiskOverviewResponse,
  RiskScoreBreakdown,
  MLPredictionItem,
  ModelVersionItem,
  EvaluationResultItem
} from '../types';

export const AnalyticsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'risk' | 'ml'>('risk');
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Risk & Behavioral state
  const [overview, setOverview] = useState<RiskOverviewResponse | null>(null);
  const [allRiskAssets, setAllRiskAssets] = useState<RiskScoreBreakdown[]>([]);
  const [selectedAssetRisk, setSelectedAssetRisk] = useState<RiskScoreBreakdown | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');

  // ML Transparency state
  const [predictions, setPredictions] = useState<MLPredictionItem[]>([]);
  const [models, setModels] = useState<ModelVersionItem[]>([]);
  const [evaluations, setEvaluations] = useState<EvaluationResultItem[]>([]);

  const fetchAnalyticsData = useCallback(async () => {
    try {
      setError(null);
      const [overviewRes, assetsRes, predsRes, modelsRes, evalsRes] = await Promise.allSettled([
        api.get('/analytics/risk'),
        api.get('/assets'),
        api.get('/ml/predictions?limit=50'),
        api.get('/ml/models'),
        api.get('/ml/evaluation')
      ]);

      if (overviewRes.status === 'fulfilled' && overviewRes.value.data) {
        setOverview(overviewRes.value.data);
      }

      if (assetsRes.status === 'fulfilled' && Array.isArray(assetsRes.value.data)) {
        const assets = assetsRes.value.data;
        const riskPromises = assets.map((a: any) =>
          api.get(`/analytics/assets/${a.id}`).then((r) => r.data).catch(() => null)
        );
        const risks = await Promise.all(riskPromises);
        const validRisks = risks.filter((r): r is RiskScoreBreakdown => r !== null && typeof r === 'object');
        setAllRiskAssets(validRisks);
      }

      if (predsRes.status === 'fulfilled' && Array.isArray(predsRes.value.data)) {
        setPredictions(predsRes.value.data);
      }
      if (modelsRes.status === 'fulfilled' && Array.isArray(modelsRes.value.data)) {
        setModels(modelsRes.value.data);
      }
      if (evalsRes.status === 'fulfilled' && Array.isArray(evalsRes.value.data)) {
        setEvaluations(evalsRes.value.data);
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Failed to load analytics telemetry');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchAnalyticsData();
  }, [fetchAnalyticsData]);

  const handleManualRefresh = () => {
    setRefreshing(true);
    fetchAnalyticsData();
  };

  const getRiskBandBadge = (band?: string) => {
    switch (band) {
      case 'Critical':
        return 'bg-red-500/10 text-red-400 border border-red-500/30';
      case 'High':
        return 'bg-amber-500/10 text-amber-400 border border-amber-500/30';
      case 'Moderate':
        return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30';
      case 'Low':
      default:
        return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30';
    }
  };

  const getSeverityBadge = (sev?: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/15 text-red-300 border border-red-500/30';
      case 'HIGH':
        return 'bg-amber-500/15 text-amber-300 border border-amber-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30';
      case 'LOW':
        return 'bg-blue-500/15 text-blue-300 border border-blue-500/30';
      default:
        return 'bg-slate-700/50 text-slate-300 border border-slate-600';
    }
  };

  const filteredAssets = allRiskAssets.filter((a) => {
    if (!a) return false;
    const q = (searchQuery || '').toLowerCase().trim();
    if (!q) return true;
    const ip = (a.ip_address || '').toLowerCase();
    const host = (a.hostname || '').toLowerCase();
    const devType = (a.device_type || '').toLowerCase();
    return ip.includes(q) || host.includes(q) || devType.includes(q);
  });

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-slate-100 font-mono">
              SECURITY ANALYTICS &amp; ML GOVERNANCE
            </h1>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-semibold">
              PHASE 3 ACTIVE
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic risk scoring, empirical behavioral baselines, and transparent machine learning telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <div className="flex rounded-lg bg-slate-900/90 border border-slate-800 p-1 text-xs font-mono">
            <button
              onClick={() => setActiveTab('risk')}
              className={`px-3 py-1.5 rounded-md transition-all ${
                activeTab === 'risk'
                  ? 'bg-slate-800 text-cyan-300 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Risk &amp; Baselines
            </button>
            <button
              onClick={() => setActiveTab('ml')}
              className={`px-3 py-1.5 rounded-md transition-all ${
                activeTab === 'ml'
                  ? 'bg-slate-800 text-cyan-300 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              ML Transparency &amp; Models
            </button>
          </div>

          <button
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700/80 text-xs font-mono text-slate-300 hover:text-white hover:bg-slate-800 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin text-cyan-400' : ''}`} />
            <span>{refreshing ? 'Evaluating...' : 'Refresh'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded-lg bg-red-950/40 border border-red-800/60 text-xs text-red-300 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Primary KPI Overview Cards (Section 30) */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="p-3.5 rounded-xl border border-slate-800/90 bg-slate-900/40">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wide">
            Total Evaluated
          </span>
          <div className="mt-1 flex items-baseline justify-between">
            <span className="text-xl font-bold font-mono text-slate-100">
              {overview?.summary?.total_evaluated ?? allRiskAssets.length}
            </span>
            <Activity className="h-4 w-4 text-slate-500" />
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Normalized assets</span>
        </div>

        <div className="p-3.5 rounded-xl border border-red-900/30 bg-red-950/10">
          <span className="text-[11px] font-mono text-red-400 uppercase tracking-wide">
            Critical (75-100)
          </span>
          <div className="mt-1 flex items-baseline justify-between">
            <span className="text-xl font-bold font-mono text-red-400">
              {overview?.summary?.critical ?? 0}
            </span>
            <ShieldAlert className="h-4 w-4 text-red-400/80" />
          </div>
          <span className="text-[10px] text-red-500/80 font-mono">Immediate remediation</span>
        </div>

        <div className="p-3.5 rounded-xl border border-amber-900/30 bg-amber-950/10">
          <span className="text-[11px] font-mono text-amber-400 uppercase tracking-wide">
            High (50-74)
          </span>
          <div className="mt-1 flex items-baseline justify-between">
            <span className="text-xl font-bold font-mono text-amber-400">
              {overview?.summary?.high ?? 0}
            </span>
            <AlertTriangle className="h-4 w-4 text-amber-400/80" />
          </div>
          <span className="text-[10px] text-amber-500/80 font-mono">Prioritized action</span>
        </div>

        <div className="p-3.5 rounded-xl border border-yellow-900/30 bg-yellow-950/10">
          <span className="text-[11px] font-mono text-yellow-400 uppercase tracking-wide">
            Moderate (25-49)
          </span>
          <div className="mt-1 flex items-baseline justify-between">
            <span className="text-xl font-bold font-mono text-yellow-400">
              {overview?.summary?.moderate ?? 0}
            </span>
            <TrendingUp className="h-4 w-4 text-yellow-400/80" />
          </div>
          <span className="text-[10px] text-yellow-500/80 font-mono">Standard posture</span>
        </div>

        <div className="p-3.5 rounded-xl border border-emerald-900/30 bg-emerald-950/10 col-span-2 md:col-span-1">
          <span className="text-[11px] font-mono text-emerald-400 uppercase tracking-wide">
            Low (0-24)
          </span>
          <div className="mt-1 flex items-baseline justify-between">
            <span className="text-xl font-bold font-mono text-emerald-400">
              {overview?.summary?.low ?? 0}
            </span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400/80" />
          </div>
          <span className="text-[10px] text-emerald-500/80 font-mono">Controlled posture</span>
        </div>
      </div>

      {/* Main Tab Content */}
      {activeTab === 'risk' && (
        <div className="space-y-6">
          {/* Section: Behavioral Anomaly Signals (Section 30) */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-cyan-400" />
                <h2 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
                  BEHAVIORAL SIGNALS &amp; TELEMETRY DEVIATIONS
                </h2>
              </div>
              <span className="text-[11px] text-slate-500 font-mono">
                {overview?.behavioral_signals?.length || 0} active signals
              </span>
            </div>

            {loading ? (
              <div className="py-6 text-center text-xs font-mono text-slate-500">
                Evaluating behavioral baselines against empirical flows...
              </div>
            ) : overview?.behavioral_signals && overview.behavioral_signals.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                      <th className="py-2 px-3">Asset</th>
                      <th className="py-2 px-3">Signal Name</th>
                      <th className="py-2 px-3">Severity</th>
                      <th className="py-2 px-3">Empirical Evidence</th>
                      <th className="py-2 px-3">Recommended Investigation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {overview.behavioral_signals.map((sig) => (
                      <tr key={sig.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-2.5 px-3">
                          <div className="font-semibold text-slate-200">{sig.hostname || 'Unknown'}</div>
                          <div className="text-[11px] text-slate-400">{sig.ip_address}</div>
                        </td>
                        <td className="py-2.5 px-3 text-cyan-300 font-medium">{sig.signal_name}</td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getSeverityBadge(sig.severity)}`}>
                            {sig.severity}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 max-w-md">
                          {sig.evidence}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 max-w-xs text-[11px]">
                          {sig.recommended_investigation}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="py-6 px-4 text-center rounded-lg border border-dashed border-slate-800 text-xs font-mono text-slate-400">
                Behavioral analysis unavailable — insufficient historical data or all hosts operating within normal empirical thresholds.
              </div>
            )}
          </div>

          {/* Section: Recent Risk Changes (Section 30) */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-amber-400" />
                <h2 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
                  RECENT RISK SCORE MOVEMENTS
                </h2>
              </div>
              <span className="text-[11px] text-slate-500 font-mono">
                Trigger-based score audit
              </span>
            </div>

            {loading ? (
              <div className="py-6 text-center text-xs font-mono text-slate-500">
                Fetching risk trajectory...
              </div>
            ) : overview?.recent_changes && overview.recent_changes.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                      <th className="py-2 px-3">Asset</th>
                      <th className="py-2 px-3">Previous</th>
                      <th className="py-2 px-3">Current</th>
                      <th className="py-2 px-3">Delta</th>
                      <th className="py-2 px-3">Documented Reason / Factor</th>
                      <th className="py-2 px-3">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {overview.recent_changes.map((ch, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-2.5 px-3">
                          <div className="font-semibold text-slate-200">{ch.hostname || 'Host'}</div>
                          <div className="text-[11px] text-slate-400">{ch.ip_address}</div>
                        </td>
                        <td className="py-2.5 px-3 text-slate-400">{(ch.previous_score ?? 0).toFixed(1)}</td>
                        <td className="py-2.5 px-3 font-semibold text-slate-200">{(ch.current_score ?? 0).toFixed(1)}</td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              (ch.change_delta ?? 0) > 0
                                ? 'bg-red-500/15 text-red-400'
                                : (ch.change_delta ?? 0) < 0
                                ? 'bg-emerald-500/15 text-emerald-400'
                                : 'bg-slate-800 text-slate-400'
                            }`}
                          >
                            {(ch.change_delta ?? 0) > 0 ? `+${(ch.change_delta ?? 0).toFixed(1)}` : (ch.change_delta ?? 0).toFixed(1)}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 max-w-md">{ch.reason}</td>
                        <td className="py-2.5 px-3 text-slate-400 text-[11px]">{ch.timestamp}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="py-4 text-center text-xs font-mono text-slate-500">
                No recent score mutations recorded.
              </div>
            )}
          </div>

          {/* Section: Asset Inventory Risk Directory & Detail Inspection */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4 pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-emerald-400" />
                <h2 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
                  EXPLAINABLE ASSET RISK DIRECTORY
                </h2>
              </div>

              <div className="relative">
                <Search className="h-3.5 w-3.5 absolute left-2.5 top-2.5 text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter by IP, hostname, type..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-64"
                />
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                    <th className="py-2 px-3">Asset</th>
                    <th className="py-2 px-3">Device Type</th>
                    <th className="py-2 px-3">Risk Band</th>
                    <th className="py-2 px-3">Formula Breakdown (40/25/20/15)</th>
                    <th className="py-2 px-3">Total Score</th>
                    <th className="py-2 px-3 text-right">Inspection</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredAssets.map((asset) => (
                    <tr
                      key={asset.asset_id}
                      onClick={() => setSelectedAssetRisk(asset)}
                      className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                    >
                      <td className="py-3 px-3">
                        <div className="font-semibold text-slate-100">{asset.hostname || 'Host'}</div>
                        <div className="text-[11px] text-slate-400">{asset.ip_address}</div>
                      </td>
                      <td className="py-3 px-3 text-slate-300">{asset.device_type || 'Server'}</td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getRiskBandBadge(asset.risk_band)}`}>
                          {asset.risk_band}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
                          <span title="Vulnerability (max 40)" className="text-red-400 font-semibold">
                            V:{(asset.vulnerability_score ?? 0).toFixed(1)}
                          </span>
                          <span>+</span>
                          <span title="Exposure (max 25)" className="text-amber-400 font-semibold">
                            E:{(asset.exposure_score ?? 0).toFixed(1)}
                          </span>
                          <span>+</span>
                          <span title="Criticality (max 20)" className="text-cyan-400 font-semibold">
                            C:{(asset.criticality_score ?? 0).toFixed(1)}
                          </span>
                          <span>+</span>
                          <span title="Behavioral (max 15)" className="text-purple-400 font-semibold">
                            B:{(asset.behavioral_score ?? 0).toFixed(1)}
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <span className="font-bold text-sm text-slate-100">
                          {(asset.total_score ?? 0).toFixed(1)}
                        </span>
                        <span className="text-[10px] text-slate-500"> / 100</span>
                      </td>
                      <td className="py-3 px-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedAssetRisk(asset);
                          }}
                          className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-mono"
                        >
                          <span>Inspect Evidence</span>
                          <ChevronRight className="h-3 w-3" />
                        </button>
                      </td>
                    </tr>
                  ))}
                  {filteredAssets.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-6 text-center text-xs text-slate-500">
                        No assets found matching filter.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ML Transparency & Model Registry Tab (Section 34) */}
      {activeTab === 'ml' && (
        <div className="space-y-6">
          {/* Active Model Versions Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Cpu className="h-4 w-4 text-cyan-400" />
                <h2 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
                  REGISTERED MODEL VERSIONS &amp; SPECIFICATIONS
                </h2>
              </div>
              <span className="text-[10px] text-emerald-400 font-mono px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20">
                SCIKIT-LEARN v1.9.1 HOSTED
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                    <th className="py-2 px-3">Model Name</th>
                    <th className="py-2 px-3">Version</th>
                    <th className="py-2 px-3">Algorithm</th>
                    <th className="py-2 px-3">Training Dataset Size</th>
                    <th className="py-2 px-3">Key Hyperparameters</th>
                    <th className="py-2 px-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {models.map((m) => (
                    <tr key={m.id} className="hover:bg-slate-800/30">
                      <td className="py-2.5 px-3 font-semibold text-slate-200">{m.model_name}</td>
                      <td className="py-2.5 px-3 text-cyan-300">{m.model_version}</td>
                      <td className="py-2.5 px-3 text-slate-300">{m.algorithm}</td>
                      <td className="py-2.5 px-3 text-slate-400">{m.dataset_size} real records</td>
                      <td className="py-2.5 px-3 text-[11px] text-slate-400 max-w-xs truncate">
                        {JSON.stringify(m.hyperparameters)}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                          ACTIVE
                        </span>
                      </td>
                    </tr>
                  ))}
                  {models.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-4 text-center text-slate-500">
                        No model versions registered in database.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Model Evaluation Metrics (Section 34) */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Layers className="h-4 w-4 text-amber-400" />
                <h2 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
                  EMPIRICAL MODEL EVALUATION METRICS
                </h2>
              </div>
              <span className="text-[11px] text-slate-500 font-mono">
                Verified against ground truth test sets
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                    <th className="py-2 px-3">Model</th>
                    <th className="py-2 px-3">Evaluation Split</th>
                    <th className="py-2 px-3">Accuracy</th>
                    <th className="py-2 px-3">Precision</th>
                    <th className="py-2 px-3">Recall</th>
                    <th className="py-2 px-3">F1 Score</th>
                    <th className="py-2 px-3">ROC-AUC</th>
                    <th className="py-2 px-3">False Positive Rate</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {evaluations.map((ev) => (
                    <tr key={ev.id} className="hover:bg-slate-800/30">
                      <td className="py-2.5 px-3">
                        <div className="font-semibold text-slate-200">{ev.model_name}</div>
                        <div className="text-[10px] text-slate-400">{ev.model_version}</div>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">{ev.dataset_split}</td>
                      <td className="py-2.5 px-3 font-semibold text-emerald-400">
                        {((ev.accuracy ?? 0) * 100).toFixed(1)}%
                      </td>
                      <td className="py-2.5 px-3 text-slate-200">{((ev.precision ?? 0) * 100).toFixed(1)}%</td>
                      <td className="py-2.5 px-3 text-slate-200">{((ev.recall ?? 0) * 100).toFixed(1)}%</td>
                      <td className="py-2.5 px-3 font-semibold text-cyan-300">
                        {(ev.f1_score ?? 0).toFixed(3)}
                      </td>
                      <td className="py-2.5 px-3 text-purple-300">{(ev.roc_auc ?? 0).toFixed(3)}</td>
                      <td className="py-2.5 px-3 text-amber-400">
                        {ev.false_positive_rate !== undefined
                          ? `${(ev.false_positive_rate * 100).toFixed(1)}%`
                          : '0.0%'}
                      </td>
                    </tr>
                  ))}
                  {evaluations.length === 0 && (
                    <tr>
                      <td colSpan={8} className="py-4 text-center text-slate-500">
                        No empirical evaluation results recorded yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Recent Model Predictions & Explainability */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-purple-400" />
                <h2 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
                  REAL-TIME ML INFERENCE AUDIT LOG
                </h2>
              </div>
              <span className="text-[11px] text-slate-500 font-mono">
                Model decisions with feature attribution
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                    <th className="py-2 px-3">Target Asset</th>
                    <th className="py-2 px-3">Model Inferred</th>
                    <th className="py-2 px-3">Prediction</th>
                    <th className="py-2 px-3">Confidence</th>
                    <th className="py-2 px-3">Feature Contributions</th>
                    <th className="py-2 px-3">Plain-English Explainability</th>
                    <th className="py-2 px-3">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {predictions.map((p) => {
                    const inferenceStr = p.inference || 'Normal';
                    const isAnomaly = inferenceStr.toLowerCase().includes('anomal');
                    return (
                      <tr key={p.id} className="hover:bg-slate-800/30">
                        <td className="py-2.5 px-3">
                          <div className="font-semibold text-slate-200">{p.hostname || 'Host'}</div>
                          <div className="text-[11px] text-slate-400">{p.ip_address}</div>
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          <div>{p.model_name}</div>
                          <div className="text-[10px] text-slate-500">{p.model_version}</div>
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              isAnomaly
                                ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                                : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                            }`}
                          >
                            {inferenceStr}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-200 font-semibold">
                          {((p.confidence ?? 0) * 100).toFixed(1)}%
                        </td>
                        <td className="py-2.5 px-3 text-[11px] text-slate-400 max-w-xs truncate">
                          {p.feature_contributions
                            ? Object.entries(p.feature_contributions)
                                .map(([k, v]) => `${k}: ${(Number(v) || 0).toFixed(2)}`)
                                .join(', ')
                            : 'Uniform'}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 max-w-md">{p.plain_explanation}</td>
                        <td className="py-2.5 px-3 text-slate-400 text-[11px]">{p.created_at}</td>
                      </tr>
                    );
                  })}
                  {predictions.length === 0 && (
                    <tr>
                      <td colSpan={7} className="py-4 text-center text-slate-500">
                        No ML inference records found.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Explainable Risk Inspection Drawer / Modal (Section 30/49) */}
      {selectedAssetRisk && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="w-full max-w-2xl rounded-xl border border-slate-700 bg-slate-900 shadow-2xl p-6 font-mono text-xs max-h-[90vh] overflow-y-auto space-y-5">
            <div className="flex items-start justify-between pb-3 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-slate-100">
                    {selectedAssetRisk.hostname || 'Target Host'}
                  </h3>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getRiskBandBadge(selectedAssetRisk.risk_band)}`}>
                    {selectedAssetRisk.risk_band} ({(selectedAssetRisk.total_score ?? 0).toFixed(1)}/100)
                  </span>
                </div>
                <p className="text-slate-400 text-xs mt-0.5">
                  IP: {selectedAssetRisk.ip_address} | Type: {selectedAssetRisk.device_type || 'Server'}
                </p>
              </div>

              <button
                onClick={() => setSelectedAssetRisk(null)}
                className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            {/* Formula Breakdown Grid */}
            <div>
              <p className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold mb-2">
                DETERMINISTIC FORMULA COMPONENTS
              </p>
              <div className="grid grid-cols-4 gap-2 text-center">
                <div className="p-2.5 rounded-lg border border-red-900/40 bg-red-950/20">
                  <span className="text-[10px] text-red-400 uppercase">Vulnerability</span>
                  <div className="text-lg font-bold text-red-300 mt-0.5">
                    {(selectedAssetRisk.vulnerability_score ?? 0).toFixed(1)}
                  </div>
                  <span className="text-[9px] text-slate-500">Max 40.0 pts</span>
                </div>

                <div className="p-2.5 rounded-lg border border-amber-900/40 bg-amber-950/20">
                  <span className="text-[10px] text-amber-400 uppercase">Exposure</span>
                  <div className="text-lg font-bold text-amber-300 mt-0.5">
                    {(selectedAssetRisk.exposure_score ?? 0).toFixed(1)}
                  </div>
                  <span className="text-[9px] text-slate-500">Max 25.0 pts</span>
                </div>

                <div className="p-2.5 rounded-lg border border-cyan-900/40 bg-cyan-950/20">
                  <span className="text-[10px] text-cyan-400 uppercase">Criticality</span>
                  <div className="text-lg font-bold text-cyan-300 mt-0.5">
                    {(selectedAssetRisk.criticality_score ?? 0).toFixed(1)}
                  </div>
                  <span className="text-[9px] text-slate-500">Max 20.0 pts</span>
                </div>

                <div className="p-2.5 rounded-lg border border-purple-900/40 bg-purple-950/20">
                  <span className="text-[10px] text-purple-400 uppercase">Behavioral</span>
                  <div className="text-lg font-bold text-purple-300 mt-0.5">
                    {(selectedAssetRisk.behavioral_score ?? 0).toFixed(1)}
                  </div>
                  <span className="text-[9px] text-slate-500">Max 15.0 pts</span>
                </div>
              </div>
            </div>

            {/* Formula Explanation */}
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 space-y-1">
              <div className="flex items-center gap-1.5 text-cyan-400 font-semibold text-[11px]">
                <Info className="h-3.5 w-3.5" />
                <span>FORMULA DEFINITION</span>
              </div>
              <p className="text-[11px] leading-relaxed text-slate-400">
                {selectedAssetRisk.formula_explanation}
              </p>
            </div>

            {/* Evidence Checklist */}
            <div>
              <p className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold mb-2">
                VERIFIED EMPIRICAL EVIDENCE &amp; FACTORS
              </p>
              <div className="space-y-1.5">
                {selectedAssetRisk.factors && selectedAssetRisk.factors.length > 0 ? (
                  selectedAssetRisk.factors.map((factor, idx) => (
                    <div
                      key={idx}
                      className="p-2 rounded bg-slate-950/60 border border-slate-800 flex items-start gap-2 text-slate-200"
                    >
                      <ChevronRight className="h-3.5 w-3.5 text-cyan-400 shrink-0 mt-0.5" />
                      <span className="leading-snug">{factor}</span>
                    </div>
                  ))
                ) : (
                  <div className="p-3 text-center text-slate-500 bg-slate-950 rounded border border-slate-800">
                    No elevating factors detected for this host.
                  </div>
                )}
              </div>
            </div>

            <div className="pt-2 flex justify-end border-t border-slate-800">
              <button
                onClick={() => setSelectedAssetRisk(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs"
              >
                Close Inspection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default AnalyticsPage;
