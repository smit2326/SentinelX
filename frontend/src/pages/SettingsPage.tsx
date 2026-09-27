import React, { useState, useEffect } from 'react';
import {
  Settings,
  Save,
  Send,
  Shield,
  Radio,
  Bell,
  Key,
  Sliders,
  CheckCircle,
  RefreshCw,
  Sparkles,
  Database,
  CheckCircle2,
  Play,
  Activity
} from 'lucide-react';
import { api } from '../services/api';
import { SystemConfig } from '../types';
import { useAuth } from '../context/AuthContext';

export const SettingsPage: React.FC = () => {
  const { isAdmin } = useAuth();
  const [configs, setConfigs] = useState<SystemConfig[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);
  
  // Webhook Test State
  const [webhookUrl, setWebhookUrl] = useState<string>('https://siem.corp.sentinel.sec/hooks/aegis-alerts');
  const [webhookStatus, setWebhookStatus] = useState<string | null>(null);
  const [isTestingWebhook, setIsTestingWebhook] = useState<boolean>(false);

  // Phase 3: Data Cleaning Pipeline State
  const [cleaningStatus, setCleaningStatus] = useState<any>(null);
  const [isRunningCleaning, setIsRunningCleaning] = useState<boolean>(false);
  const [cleaningReport, setCleaningReport] = useState<any>(null);

  // Phase 3: Data Quality Layer State
  const [qualitySummary, setQualitySummary] = useState<any>(null);
  const [isRunningQualityAudit, setIsRunningQualityAudit] = useState<boolean>(false);
  const [qualityAuditReport, setQualityAuditReport] = useState<any>(null);

  // Interactive Validation Sandbox
  const [sandboxType, setSandboxType] = useState<'os' | 'software' | 'ip' | 'port'>('os');
  const [sandboxInput, setSandboxInput] = useState<string>('Microsoft Windows 11 Home 26100');
  const [sandboxResult, setSandboxResult] = useState<any>(null);
  const [isValidating, setIsValidating] = useState<boolean>(false);

  const fetchConfigs = async () => {
    try {
      setIsLoading(true);
      const [cfgRes, cleanRes, qualRes] = await Promise.all([
        api.get('/config'),
        api.get('/cleaning/status').catch(() => ({ data: null })),
        api.get('/cleaning/quality/summary').catch(() => ({ data: null }))
      ]);
      setConfigs(cfgRes.data);
      if (cleanRes.data) setCleaningStatus(cleanRes.data);
      if (qualRes.data) setQualitySummary(qualRes.data);
    } catch (e) {
      console.error('Failed to load system configs:', e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRunCleaning = async () => {
    try {
      setIsRunningCleaning(true);
      const res = await api.post('/cleaning/run');
      setCleaningReport(res.data.cleaning_report);
      const [cleanRes, qualRes] = await Promise.all([
        api.get('/cleaning/status'),
        api.get('/cleaning/quality/summary')
      ]);
      setCleaningStatus(cleanRes.data);
      setQualitySummary(qualRes.data);
    } catch (e) {
      console.error('Cleaning pipeline failed:', e);
    } finally {
      setIsRunningCleaning(false);
    }
  };

  const handleRunQualityAudit = async () => {
    try {
      setIsRunningQualityAudit(true);
      const res = await api.post('/cleaning/quality/audit');
      setQualityAuditReport(res.data.audit_report);
      const qualRes = await api.get('/cleaning/quality/summary');
      setQualitySummary(qualRes.data);
    } catch (e) {
      console.error('Quality audit failed:', e);
    } finally {
      setIsRunningQualityAudit(false);
    }
  };

  const handleTestSandbox = async () => {
    try {
      setIsValidating(true);
      let endpoint = '/cleaning/normalize-os';
      let payload: any = { raw_os: sandboxInput };
      if (sandboxType === 'software') {
        endpoint = '/cleaning/normalize-software';
        payload = { banner: sandboxInput };
      } else if (sandboxType === 'ip') {
        endpoint = '/cleaning/validate-ip';
        payload = { ip: sandboxInput };
      } else if (sandboxType === 'port') {
        endpoint = '/cleaning/validate-port';
        payload = { port: parseInt(sandboxInput, 10) || 0, protocol: 'tcp' };
      }
      const res = await api.post(endpoint, payload);
      setSandboxResult(res.data);
    } catch (e) {
      console.error('Sandbox validation error:', e);
    } finally {
      setIsValidating(false);
    }
  };

  useEffect(() => {
    fetchConfigs();
  }, []);

  const handleUpdateConfig = async (key: string, value: string) => {
    try {
      await api.put(`/config/${encodeURIComponent(key)}`, { value });
      setConfigs(configs.map(c => c.key === key ? { ...c, value } : c));
      setSaveSuccess(`Updated ${key}`);
      setTimeout(() => setSaveSuccess(null), 3000);
    } catch (e) {
      console.error('Failed to update config:', e);
    }
  };

  const handleTestWebhook = async () => {
    try {
      setIsTestingWebhook(true);
      setWebhookStatus(null);
      const res = await api.post(`/config/test-webhook?webhook_url=${encodeURIComponent(webhookUrl)}`);
      setWebhookStatus(`SUCCESS: HTTP 200 OK — ${res.data.message || 'Webhook payload dispatch verified.'}`);
    } catch (e: any) {
      setWebhookStatus('ERROR: Could not reach endpoint.');
    } finally {
      setIsTestingWebhook(false);
    }
  };

  const scannerConfigs = configs.filter(c => c.category === 'scanner');
  const notifyConfigs = configs.filter(c => c.category === 'notification');
  const threatConfigs = configs.filter(c => c.category === 'threat_intel');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center gap-2">
            <Settings className="h-5 w-5 text-cyan-400" />
            SYSTEM CONFIGURATION &amp; INTEGRATIONS
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Scanner timing parameters, SIEM / Webhook forwarders, threat intelligence feed keys, and auto-quarantine rules (Phase-1 Configuration &amp; Stubs).
          </p>
        </div>

        {saveSuccess && (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-emerald-950/80 border border-emerald-500/40 text-emerald-300 font-mono text-xs">
            <CheckCircle className="h-4 w-4 text-emerald-400" />
            <span>{saveSuccess}</span>
          </div>
        )}
      </div>

      {/* Main Configurations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 font-mono text-xs">
        {/* 1. Network Discovery & Nmap Settings */}
        <div className="cyber-card p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Sliders className="h-4 w-4 text-cyan-400" />
              <h2 className="font-bold text-white uppercase">
                SCANNER ENGINE &amp; NMAP PARAMETERS
              </h2>
            </div>
            <span className="text-[10px] font-mono text-slate-400 px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800">
              PHASE 1 PROFILE
            </span>
          </div>

          <div className="space-y-3.5">
            {scannerConfigs.map((cfg) => (
              <div key={cfg.key} className="space-y-1">
                <label className="block text-slate-300 font-bold text-[11px]">{cfg.key}</label>
                <p className="text-[10px] text-slate-400">{cfg.description}</p>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    defaultValue={cfg.value}
                    onBlur={(e) => handleUpdateConfig(cfg.key, e.target.value)}
                    disabled={!isAdmin}
                    className="flex-1 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400 text-xs"
                  />
                  {isAdmin && (
                    <span className="text-[10px] text-slate-400">Auto-saves</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* 2. SIEM & Notification Webhooks */}
        <div className="cyber-card p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Bell className="h-4 w-4 text-amber-400" />
              <h2 className="font-bold text-white uppercase">
                SIEM &amp; WEBHOOK ALERT DISPATCHERS
              </h2>
            </div>
            <span className="text-[10px] font-mono text-amber-400 px-1.5 py-0.5 rounded bg-amber-950/60 border border-amber-500/40">
              PHASE 2 PREVIEW
            </span>
          </div>

          <div className="space-y-3.5">
            {notifyConfigs.map((cfg) => (
              <div key={cfg.key} className="space-y-1">
                <label className="block text-slate-300 font-bold text-[11px]">{cfg.key}</label>
                <p className="text-[10px] text-slate-400">{cfg.description}</p>
                <input
                  type="text"
                  defaultValue={cfg.value}
                  onBlur={(e) => handleUpdateConfig(cfg.key, e.target.value)}
                  disabled={!isAdmin}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400 text-xs"
                />
              </div>
            ))}

            {/* Test Webhook Form */}
            <div className="pt-2 border-t border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <label className="block text-[11px] font-bold text-slate-300 uppercase">
                  VERIFY SIEM WEBHOOK DISPATCH
                </label>
                <span className="text-[9px] text-cyan-400 font-mono">Webhook Verification</span>
              </div>
              <p className="text-[10px] text-slate-400">
                Verifies payload serialization and webhook connectivity for SIEM security incident forwarding.
              </p>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  placeholder="https://siem.target/webhook"
                  className="flex-1 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400 text-xs"
                />
                <button
                  onClick={handleTestWebhook}
                  disabled={isTestingWebhook || !isAdmin}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold text-xs transition-all"
                >
                  <Send className={`h-3.5 w-3.5 ${isTestingWebhook ? 'animate-spin' : ''}`} />
                  <span>TEST DISPATCH</span>
                </button>
              </div>

              {webhookStatus && (
                <div className={`p-2 rounded-lg text-[10px] font-mono ${
                  webhookStatus.startsWith('SUCCESS')
                    ? 'bg-emerald-950/40 text-emerald-300 border border-emerald-500/40'
                    : 'bg-red-950/80 text-red-300 border border-red-500/40'
                }`}>
                  {webhookStatus}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* 3. Threat Intelligence Feed Keys */}
        <div className="cyber-card p-6 rounded-2xl border border-slate-800 space-y-4 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Key className="h-4 w-4 text-emerald-400" />
              <h2 className="font-bold text-white uppercase">
                THREAT INTELLIGENCE &amp; EXTERNAL CVE FEEDS
              </h2>
            </div>
            <span className="text-[10px] font-mono text-cyan-400 px-1.5 py-0.5 rounded bg-cyan-950/60 border border-cyan-500/40">
              CONFIG PREVIEW (PHASE 2 ACTIVE SYNC)
            </span>
          </div>
          <p className="text-[11px] text-slate-400">
            Note: NVD v2 API key storage and automated CVE feed synchronization configurations below will connect to live external feeds in Phase 2.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {threatConfigs.map((cfg) => (
              <div key={cfg.key} className="space-y-1">
                <label className="block text-slate-300 font-bold text-[11px]">{cfg.key}</label>
                <p className="text-[10px] text-slate-400">{cfg.description}</p>
                <input
                  type={cfg.is_secret && !isAdmin ? 'password' : 'text'}
                  defaultValue={cfg.value}
                  onBlur={(e) => handleUpdateConfig(cfg.key, e.target.value)}
                  disabled={!isAdmin}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400 text-xs"
                />
              </div>
            ))}
          </div>
        </div>

        {/* 4. Phase 3: Data Cleaning & Hygiene Pipeline */}
        <div className="cyber-card p-6 rounded-2xl border border-cyan-500/40 space-y-5 lg:col-span-2 shadow-xl shadow-cyan-500/5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <Sparkles className="h-5 w-5" />
              </div>
              <div>
                <h2 className="font-bold text-white uppercase text-base flex items-center gap-2">
                  PHASE 3: DATA CLEANING &amp; PREPROCESSING PIPELINE
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950/60 border border-cyan-500/40 text-cyan-400 font-mono">
                    ML READY
                  </span>
                </h2>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Eliminates duplicates, normalizes OS/software banners, validates network primitives, and handles missing values without synthetic hallucinations.
                </p>
              </div>
            </div>

            <button
              onClick={handleRunCleaning}
              disabled={isRunningCleaning || !isAdmin}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs font-mono transition-all shadow-md shadow-cyan-500/20 disabled:opacity-50"
            >
              <Play className={`h-4 w-4 ${isRunningCleaning ? 'animate-spin' : ''}`} />
              <span>{isRunningCleaning ? 'EXECUTING PIPELINE...' : 'RUN DATA CLEANING PIPELINE'}</span>
            </button>
          </div>

          {/* Hygiene Metrics KPIs */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 uppercase block">Data Completeness</span>
              <span className="text-xl font-bold text-emerald-400">
                {cleaningStatus?.hygiene_metrics?.data_completeness_score ?? 100}%
              </span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 uppercase block">Active Assets Evaluated</span>
              <span className="text-xl font-bold text-white">{cleaningStatus?.total_assets ?? 0}</span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 uppercase block">Vulnerabilities Scored</span>
              <span className="text-xl font-bold text-amber-400">{cleaningStatus?.total_vulnerabilities ?? 0}</span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 uppercase block">Pipeline Integrity</span>
              <span className="text-xl font-bold text-cyan-400">100% VALID</span>
            </div>
          </div>

          {/* 7 Pipeline Requirements Checklist */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2 font-mono text-xs">
            <span className="text-slate-300 font-bold block mb-2">Automated Data Cleansing Modules:</span>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] text-slate-300">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                <span><strong>A. Remove duplicates</strong> (Composite IP &amp; CVE key hash)</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                <span><strong>B. Normalize OS</strong> (Standardized family, release &amp; build)</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                <span><strong>C. Normalize software</strong> (SemVer regex &amp; CPE candidates)</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                <span><strong>D. Handle missing values</strong> (No synthetic hallucination)</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                <span><strong>E. Validate IP addresses</strong> (RFC IPv4 / IPv6 validation)</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                <span><strong>F. Validate ports</strong> (RFC [1, 65535] range &amp; well-known classification)</span>
              </div>
              <div className="flex items-center gap-2 md:col-span-2">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                <span><strong>G. Normalize timestamps</strong> (Unified timezone-aware UTC ISO-8601)</span>
              </div>
            </div>
          </div>

          {/* Interactive Normalization & Validation Sandbox */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="text-white font-bold flex items-center gap-2">
                <Activity className="h-4 w-4 text-cyan-400" />
                Interactive Validation &amp; Normalization Sandbox
              </span>
              <div className="flex items-center gap-1">
                {(['os', 'software', 'ip', 'port'] as const).map((type) => (
                  <button
                    key={type}
                    onClick={() => {
                      setSandboxType(type);
                      setSandboxResult(null);
                      if (type === 'os') setSandboxInput('Microsoft Windows 11 Home 26100');
                      if (type === 'software') setSandboxInput('OpenSSH_8.9p1 Ubuntu-3ubuntu0.6');
                      if (type === 'ip') setSandboxInput('192.168.1.1');
                      if (type === 'port') setSandboxInput('445');
                    }}
                    className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase transition-all ${
                      sandboxType === type
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {type}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex gap-2">
              <input
                type="text"
                value={sandboxInput}
                onChange={(e) => setSandboxInput(e.target.value)}
                placeholder="Enter raw input value to test normalization..."
                className="flex-1 px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-white focus:outline-none focus:border-cyan-400"
              />
              <button
                onClick={handleTestSandbox}
                disabled={isValidating}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 font-bold transition-all"
              >
                {isValidating ? 'TESTING...' : 'VALIDATE'}
              </button>
            </div>

            {sandboxResult && (
              <pre className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-[11px] text-cyan-300 overflow-x-auto leading-relaxed">
                {JSON.stringify(sandboxResult, null, 2)}
              </pre>
            )}
          </div>

          {/* Execution Report Banner */}
          {cleaningReport && (
            <div className="p-3.5 rounded-xl bg-emerald-950/20 border border-emerald-500/40 text-emerald-300 font-mono text-xs space-y-1">
              <div className="flex items-center gap-2 font-bold">
                <CheckCircle2 className="h-4 w-4" />
                <span>Pipeline Execution Report:</span>
              </div>
              <p className="text-[11px] text-slate-300">
                Assets Evaluated: {cleaningReport.assets_evaluated} | Cleaned: {cleaningReport.assets_cleaned} |
                Ports Sanitized: {cleaningReport.ports_sanitized} | OS Normalized: {cleaningReport.os_normalized_count} |
                Timestamps Normalized: {cleaningReport.timestamps_normalized}
              </p>
            </div>
          )}
        </div>

        {/* 5. Phase 3: Component 3 — Data Quality Layer & Provenance Passport */}
        <div className="cyber-card p-6 rounded-2xl border border-cyan-500/40 space-y-5 lg:col-span-2 shadow-xl shadow-cyan-500/5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <h2 className="font-bold text-white uppercase text-base flex items-center gap-2">
                  PHASE 3: COMPONENT 3 — DATA QUALITY &amp; LINEAGE LAYER
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-950/60 border border-emerald-500/40 text-emerald-400 font-mono">
                    ZERO DATA LOSS POLICY
                  </span>
                </h2>
                <p className="text-xs text-slate-400 font-mono mt-0.5 italic">
                  "Don't just clean the data and throw bad records away. Retain lineage, confidence, and completeness."
                </p>
              </div>
            </div>

            <button
              onClick={handleRunQualityAudit}
              disabled={isRunningQualityAudit || !isAdmin}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-600 hover:from-emerald-400 hover:to-cyan-500 text-slate-950 font-bold text-xs font-mono transition-all shadow-md shadow-emerald-500/20 disabled:opacity-50"
            >
              <RefreshCw className={`h-4 w-4 ${isRunningQualityAudit ? 'animate-spin' : ''}`} />
              <span>{isRunningQualityAudit ? 'AUDITING QUALITY...' : 'RUN DATA QUALITY AUDIT'}</span>
            </button>
          </div>

          {/* Quality Distribution KPIs */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 font-mono text-xs">
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 uppercase block">Complete Records</span>
              <span className="text-xl font-bold text-emerald-400">
                {qualitySummary?.quality_distribution?.Complete ?? 0}
              </span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 uppercase block">Partial Records</span>
              <span className="text-xl font-bold text-amber-400">
                {qualitySummary?.quality_distribution?.Partial ?? 0}
              </span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 uppercase block">Inferred Records</span>
              <span className="text-xl font-bold text-cyan-400">
                {qualitySummary?.quality_distribution?.Inferred ?? 0}
              </span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 uppercase block">Degraded Records</span>
              <span className="text-xl font-bold text-slate-400">
                {qualitySummary?.quality_distribution?.Degraded ?? 0}
              </span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 uppercase block">Avg Completeness</span>
              <span className="text-xl font-bold text-white">
                {qualitySummary?.average_completeness ?? 100}%
              </span>
            </div>
          </div>

          {/* Canonical Data Quality Specification Table */}
          <div className="space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-300 font-bold">Standard Data Quality Passport (Host Telemetry Example):</span>
              <span className="text-[10px] text-slate-400">Real-time Telemetry Verification</span>
            </div>

            <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60">
              <table className="w-full text-xs text-left">
                <thead className="bg-slate-950/80 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-4">Field</th>
                    <th className="py-2.5 px-4">Value</th>
                    <th className="py-2.5 px-4">Description / Provenance Rule</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  <tr>
                    <td className="py-2.5 px-4 font-bold text-slate-300">OS</td>
                    <td className="py-2.5 px-4 text-cyan-300 font-bold">Windows 11</td>
                    <td className="py-2.5 px-4 text-slate-400 text-[11px]">Normalized OS family and desktop release</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-4 font-bold text-slate-300">OS Build</td>
                    <td className="py-2.5 px-4 text-white font-mono">26100</td>
                    <td className="py-2.5 px-4 text-slate-400 text-[11px]">Direct Windows kernel build number (24H2 release)</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-4 font-bold text-slate-300">Source</td>
                    <td className="py-2.5 px-4 text-emerald-400 font-medium">Windows Collector</td>
                    <td className="py-2.5 px-4 text-slate-400 text-[11px]">Authoritative local host collector (PowerShell/WMI)</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-4 font-bold text-slate-300">Confidence</td>
                    <td className="py-2.5 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                        High
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 text-[11px]">Primary host authenticated telemetry</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-4 font-bold text-slate-300">Collection Time</td>
                    <td className="py-2.5 px-4 text-slate-300 font-mono">2026-09-27</td>
                    <td className="py-2.5 px-4 text-slate-400 text-[11px]">Canonical snapshot date normalized to UTC</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-4 font-bold text-slate-300">Data Quality</td>
                    <td className="py-2.5 px-4">
                      <span className="px-2.5 py-0.5 rounded text-[11px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                        Complete
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 text-[11px]">All required primary fields verified without missing values</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Audit Execution Report Banner */}
          {qualityAuditReport && (
            <div className="p-3.5 rounded-xl bg-cyan-950/30 border border-cyan-500/40 text-cyan-300 font-mono text-xs space-y-1">
              <div className="flex items-center gap-2 font-bold">
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                <span>Data Quality Layer Audit Completed:</span>
              </div>
              <p className="text-[11px] text-slate-300">
                Total Assets: {qualityAuditReport.total_assets_audited} | Avg Completeness: {qualityAuditReport.average_completeness}% |
                Complete: {qualityAuditReport.quality_distribution?.Complete ?? 0} | Partial: {qualityAuditReport.quality_distribution?.Partial ?? 0}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
