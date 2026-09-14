import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { WebSocketProvider, useWebSocket } from './context/WebSocketContext';
import { Navbar } from './components/layout/Navbar';
import { Sidebar } from './components/layout/Sidebar';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { AssetsPage } from './pages/AssetsPage';
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage';
import { AlertsPage } from './pages/AlertsPage';
import { SecurityReportPage } from './pages/SecurityReportPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { UserRolesPage } from './pages/UserRolesPage';
import { SettingsPage } from './pages/SettingsPage';
import { AlertTriangle, X, ArrowRight } from 'lucide-react';
import { Badge } from './components/common/Badge';

const MainApp: React.FC = () => {
  const { isAuthenticated, isLoading, isAdmin } = useAuth();
  const { latestAlert, clearLatestAlert } = useWebSocket();
  const [currentTab, setCurrentTab] = useState<string>('dashboard');

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#060913] flex items-center justify-center text-cyan-400 font-mono text-sm">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
          <span>INITIALIZING SENTINEL-X SOC INTERFACE...</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  return (
    <div className="min-h-screen bg-[#060913] text-slate-200 flex flex-col font-sans">
      <Navbar />

      {/* Real-time incoming Toast Alert Banner */}
      {latestAlert && (
        <div className="bg-red-950/90 border-b border-red-500 text-white px-6 py-2.5 flex items-center justify-between text-xs font-mono animate-in slide-in-from-top duration-200 z-50">
          <div className="flex items-center gap-3 flex-wrap">
            <AlertTriangle className="h-4 w-4 text-red-400 animate-pulse" />
            <Badge size="sm" variant="critical">
              {latestAlert.severity} ALERT
            </Badge>
            <span className="font-bold">{latestAlert.title}</span>
            <span className="text-slate-400">
              (Target: {latestAlert.destination_ip || '192.168.1.1'})
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                setCurrentTab('alerts');
                clearLatestAlert();
              }}
              className="px-2.5 py-1 rounded bg-red-600 hover:bg-red-500 text-slate-950 font-bold flex items-center gap-1 text-[11px]"
            >
              <span>INSPECT</span>
              <ArrowRight className="h-3 w-3" />
            </button>
            <button
              onClick={clearLatestAlert}
              className="p-1 hover:bg-red-900 rounded text-slate-300"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      <div className="flex-1 flex">
        <Sidebar currentTab={currentTab} onTabChange={setCurrentTab} />

        <main className="flex-1 p-6 md:p-8 max-w-7xl mx-auto w-full overflow-x-hidden">
          {currentTab === 'dashboard' && <DashboardPage onNavigate={setCurrentTab} />}
          {currentTab === 'assets' && <AssetsPage />}
          {currentTab === 'vulnerabilities' && <VulnerabilitiesPage />}
          {currentTab === 'alerts' && <AlertsPage />}
          {currentTab === 'reports' && <SecurityReportPage />}
          {currentTab === 'audit-logs' && <AuditLogsPage />}
          {currentTab === 'users' && isAdmin && <UserRolesPage />}
          {currentTab === 'settings' && <SettingsPage />}
        </main>
      </div>
    </div>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <WebSocketProvider>
        <MainApp />
      </WebSocketProvider>
    </AuthProvider>
  );
}
