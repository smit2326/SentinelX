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
  RefreshCw
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

  const fetchConfigs = async () => {
    try {
      setIsLoading(true);
      const res = await api.get('/config');
      setConfigs(res.data);
    } catch (e) {
      console.error('Failed to load system configs:', e);
    } finally {
      setIsLoading(false);
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
      </div>
    </div>
  );
};
