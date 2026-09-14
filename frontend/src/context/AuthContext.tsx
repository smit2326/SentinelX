import React, { createContext, useContext, useState, useEffect } from 'react';
import { User, UserRole } from '../types';
import { api } from '../services/api';

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  loginAsRole: (role: UserRole) => Promise<void>;
  logout: () => Promise<void>;
  isAdmin: boolean;
  isAnalyst: boolean;
  isAuditor: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const PRESET_CREDENTIALS: Record<UserRole, { email: string; pass: string }> = {
  admin: { email: 'admin@sentinel-x.sec', pass: 'SentinelAdmin2026!' },
  analyst: { email: 'analyst@sentinel-x.sec', pass: 'SentinelAnalyst2026!' },
  auditor: { email: 'auditor@sentinel-x.sec', pass: 'SentinelAuditor2026!' },
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('sentinel_token'));
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchMe = async () => {
      if (!token) {
        setIsLoading(false);
        return;
      }
      try {
        const res = await api.get('/auth/me');
        setUser(res.data);
      } catch (e) {
        localStorage.removeItem('sentinel_token');
        localStorage.removeItem('sentinel_user');
        setToken(null);
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    };
    fetchMe();
  }, [token]);

  const login = async (email: string, password: string) => {
    const res = await api.post('/auth/login', { email, password });
    const { access_token, user: loggedUser } = res.data;
    localStorage.setItem('sentinel_token', access_token);
    localStorage.setItem('sentinel_user', JSON.stringify(loggedUser));
    setToken(access_token);
    setUser(loggedUser);
  };

  const loginAsRole = async (role: UserRole) => {
    const creds = PRESET_CREDENTIALS[role];
    if (creds) {
      await login(creds.email, creds.pass);
    }
  };

  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } catch (e) {
      // Ignore network errors on logout
    } finally {
      localStorage.removeItem('sentinel_token');
      localStorage.removeItem('sentinel_user');
      setToken(null);
      setUser(null);
    }
  };

  const isAdmin = user?.role === 'admin';
  const isAnalyst = user?.role === 'analyst' || user?.role === 'admin';
  const isAuditor = user?.role === 'auditor' || user?.role === 'analyst' || user?.role === 'admin';

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user,
        isLoading,
        login,
        loginAsRole,
        logout,
        isAdmin,
        isAnalyst,
        isAuditor,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
