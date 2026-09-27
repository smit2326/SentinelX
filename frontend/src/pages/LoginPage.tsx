import React, { useState } from 'react';
import { Shield, Lock, Mail, ArrowRight, UserCheck, ShieldAlert, Cpu } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { UserRole } from '../types';

export const LoginPage: React.FC = () => {
  const { login, loginAsRole } = useAuth();
  const [email, setEmail] = useState<string>('admin@sentinel-x.sec');
  const [password, setPassword] = useState<string>('SentinelAdmin2026!');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);
    try {
      await login(email, password);
    } catch (err: any) {
      if (!err.response) {
        setError('Backend API is unreachable (http://localhost:8000). Please ensure the FastAPI backend is running.');
      } else if (err.response.status === 401) {
        setError('Authentication failed. Invalid email or security passphrase.');
      } else {
        setError(err.response?.data?.detail || 'Authentication failed. Please check credentials.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleQuickRole = async (role: UserRole) => {
    setError(null);
    setIsLoading(true);
    try {
      await loginAsRole(role);
    } catch (err: any) {
      if (!err.response) {
        setError('Backend API is unreachable (http://localhost:8000). Please ensure the FastAPI backend is running.');
      } else {
        setError('Failed to login with preset credentials: ' + (err.response?.data?.detail || err.message));
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#060913] text-white flex flex-col justify-center items-center px-4 relative overflow-hidden cyber-grid">
      {/* Background glowing orbs */}
      <div className="absolute top-1/4 left-1/3 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/3 w-96 h-96 bg-red-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md z-10 space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-tr from-cyan-600 to-cyan-400 text-slate-950 font-bold shadow-xl shadow-cyan-500/30 mb-2">
            <Shield className="h-8 w-8" />
          </div>
          <h1 className="text-2xl font-black font-mono tracking-wider text-white">
            SENTINEL-X
          </h1>
          <p className="text-xs font-mono text-cyan-400 uppercase tracking-widest">
            SECURITY PLATFORM • PHASE 1
          </p>
        </div>

        {/* Login Form Container */}
        <div className="cyber-card p-8 rounded-3xl border border-slate-800 shadow-2xl relative">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-4 mb-6">
            <span className="text-xs font-mono text-slate-400 uppercase">OPERATOR ACCESS GATEWAY</span>
            <span className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              SYSTEM SECURE
            </span>
          </div>

          {error && (
            <div className="p-3 mb-4 rounded-xl bg-red-950/80 border border-red-500/50 text-red-300 font-mono text-xs flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 shrink-0 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4 font-mono text-xs">
            <div>
              <label className="block text-slate-400 mb-1">OPERATOR EMAIL</label>
              <div className="relative">
                <Mail className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-9 pr-3 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400 transition-all"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">SECURITY PASSPHRASE</label>
              <div className="relative">
                <Lock className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-9 pr-3 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400 transition-all"
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold tracking-wider transition-all shadow-lg shadow-cyan-500/25 flex items-center justify-center gap-2 mt-2"
            >
              <span>{isLoading ? 'AUTHENTICATING...' : 'ESTABLISH SECURE SESSION'}</span>
              <ArrowRight className="h-4 w-4" />
            </button>
          </form>

          {/* Instant 1-Click Role Access */}
          <div className="mt-6 pt-5 border-t border-slate-800/80">
            <span className="text-[10px] font-mono text-slate-400 uppercase block text-center mb-2.5">
              OR SIGN IN WITH PRE-CONFIGURED ENTERPRISE ROLES
            </span>
            <div className="grid grid-cols-3 gap-2 font-mono text-[11px]">
              <button
                type="button"
                onClick={() => handleQuickRole('admin')}
                className="py-2 px-1 rounded-xl bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border border-cyan-500/40 text-center font-bold transition-all"
              >
                ADMIN
              </button>
              <button
                type="button"
                onClick={() => handleQuickRole('analyst')}
                className="py-2 px-1 rounded-xl bg-amber-950/80 hover:bg-amber-900 text-amber-300 border border-amber-500/40 text-center font-bold transition-all"
              >
                ANALYST
              </button>
              <button
                type="button"
                onClick={() => handleQuickRole('auditor')}
                className="py-2 px-1 rounded-xl bg-purple-950/80 hover:bg-purple-900 text-purple-300 border border-purple-500/40 text-center font-bold transition-all"
              >
                AUDITOR
              </button>
            </div>
          </div>
        </div>

        {/* Footer info */}
        <p className="text-center text-[11px] font-mono text-slate-400">
          SENTINEL-X SECURITY PLATFORM • ENTERPRISE SOC v1.0
        </p>
      </div>
    </div>
  );
};
