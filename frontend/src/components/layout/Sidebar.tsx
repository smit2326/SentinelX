import React from 'react';
import {
  LayoutDashboard,
  Server,
  Bug,
  AlertTriangle,
  FileText,
  History,
  Users,
  Settings,
  ShieldCheck,
  Video,
  Cpu
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface SidebarProps {
  currentTab: string;
  onTabChange: (tab: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onTabChange }) => {
  const { user, isAdmin, isAuditor } = useAuth();

  const navItems = [
    {
      id: 'dashboard',
      label: 'Executive SOC',
      icon: <LayoutDashboard className="h-4 w-4" />,
      badge: null,
      visible: true
    },
    {
      id: 'assets',
      label: 'Asset Discovery & IoT',
      icon: <Server className="h-4 w-4" />,
      badge: 'NMAP',
      visible: true
    },
    {
      id: 'vulnerabilities',
      label: 'Vulnerability / CVEs',
      icon: <Bug className="h-4 w-4" />,
      badge: null,
      visible: true
    },
    {
      id: 'alerts',
      label: 'Live Threat Stream',
      icon: <AlertTriangle className="h-4 w-4" />,
      badge: 'LIVE',
      badgeColor: 'bg-red-500/20 text-red-400 border border-red-500/30',
      visible: true
    },
    {
      id: 'reports',
      label: 'Security Reports',
      icon: <FileText className="h-4 w-4" />,
      badge: null,
      visible: true
    },
    {
      id: 'audit-logs',
      label: 'Audit & Compliance',
      icon: <History className="h-4 w-4" />,
      badge: null,
      visible: true
    },
    {
      id: 'users',
      label: 'User Roles & RBAC',
      icon: <Users className="h-4 w-4" />,
      badge: 'ADMIN',
      badgeColor: 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30',
      visible: isAdmin
    },
    {
      id: 'settings',
      label: 'System Configuration',
      icon: <Settings className="h-4 w-4" />,
      badge: null,
      visible: true
    },
  ];

  return (
    <aside className="w-64 shrink-0 border-r border-slate-800/80 bg-[#070a12] p-4 flex flex-col justify-between hidden md:flex min-h-[calc(100vh-4rem)]">
      <div className="space-y-6">
        <div>
          <p className="px-3 text-[11px] font-bold uppercase tracking-wider text-slate-400 font-mono">
            OPERATIONS CENTER
          </p>
          <div className="mt-3 space-y-1">
            {navItems.filter(i => i.visible).map((item) => {
              const active = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onTabChange(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-mono font-medium transition-all ${
                    active
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span className={active ? 'text-cyan-400' : 'text-slate-400'}>
                      {item.icon}
                    </span>
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span
                      className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${
                        item.badgeColor || 'bg-slate-800 text-slate-400 border border-slate-700'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Security Posture Status Card */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-3.5 text-xs font-mono">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-slate-300">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              <span className="font-semibold text-[11px]">SOC STATUS</span>
            </div>
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
          </div>
          <p className="mt-2 text-[11px] text-slate-400 leading-relaxed">
            AEGIS Core Correlation Engine v1.0 running with active port inspection.
          </p>
        </div>
      </div>

      {/* Footer System Specs */}
      <div className="border-t border-slate-800/80 pt-3 text-[11px] font-mono text-slate-400 space-y-1">
        <div className="flex justify-between">
          <span>HOST IP:</span>
          <span className="text-slate-400">192.168.1.0/24</span>
        </div>
        <div className="flex justify-between">
          <span>ROLE:</span>
          <span className="text-cyan-400 uppercase font-semibold">{user?.role || 'ANALYST'}</span>
        </div>
      </div>
    </aside>
  );
};
