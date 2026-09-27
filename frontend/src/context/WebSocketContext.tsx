import React, { createContext, useContext, useEffect, useState } from 'react';
import { wsClient } from '../services/websocket';
import { Alert } from '../types';

interface ScanProgress {
  progress: number;
  status: string;
  details: Record<string, any>;
}

interface WebSocketContextType {
  isConnected: boolean;
  liveAlerts: Alert[];
  latestAlert: Alert | null;
  scanProgress: ScanProgress | null;
  clearLatestAlert: () => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

export const WebSocketProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [liveAlerts, setLiveAlerts] = useState<Alert[]>([]);
  const [latestAlert, setLatestAlert] = useState<Alert | null>(null);
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);

  useEffect(() => {
    wsClient.connect();

    const handleConn = (data: { connected: boolean }) => {
      setIsConnected(data.connected);
    };

    const handleNewAlert = (payload: { data: Alert }) => {
      if (payload && payload.data) {
        setLatestAlert(payload.data);
        setLiveAlerts((prev) => [payload.data, ...prev.slice(0, 49)]);
      }
    };

    const handleScanProgress = (payload: ScanProgress) => {
      setScanProgress(payload);
      if (payload.progress >= 100) {
        setTimeout(() => setScanProgress(null), 4000);
      }
    };

    wsClient.on('connection_status', handleConn);
    wsClient.on('NEW_ALERT', handleNewAlert);
    wsClient.on('SCAN_PROGRESS', handleScanProgress);

    return () => {
      wsClient.off('connection_status', handleConn);
      wsClient.off('NEW_ALERT', handleNewAlert);
      wsClient.off('SCAN_PROGRESS', handleScanProgress);
    };
  }, []);

  const clearLatestAlert = () => {
    setLatestAlert(null);
  };

  return (
    <WebSocketContext.Provider
      value={{
        isConnected,
        liveAlerts,
        latestAlert,
        scanProgress,
        clearLatestAlert,
      }}
    >
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};
