import React, { useState, useEffect } from 'react';
import {
  Users,
  UserPlus,
  Shield,
  Search,
  RefreshCw,
  X,
  Lock,
  Mail,
  UserCheck,
  UserX
} from 'lucide-react';
import { api } from '../services/api';
import { User, UserRole } from '../types';
import { useAuth } from '../context/AuthContext';
import { Badge } from '../components/common/Badge';

export const UserRolesPage: React.FC = () => {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [search, setSearch] = useState<string>('');
  
  // Create User Modal
  const [isCreateOpen, setIsCreateOpen] = useState<boolean>(false);
  const [email, setEmail] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [fullName, setFullName] = useState<string>('');
  const [role, setRole] = useState<UserRole>('analyst');
  const [createError, setCreateError] = useState<string | null>(null);

  const fetchUsers = async () => {
    try {
      setIsLoading(true);
      const res = await api.get('/users');
      setUsers(res.data);
    } catch (e) {
      console.error('Failed to fetch users:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError(null);
    try {
      const res = await api.post('/users', {
        email,
        password,
        full_name: fullName,
        role
      });
      setUsers([...users, res.data]);
      setIsCreateOpen(false);
      setEmail('');
      setPassword('');
      setFullName('');
    } catch (err: any) {
      setCreateError(err.response?.data?.detail || 'Failed to create user');
    }
  };

  const handleToggleActive = async (targetUser: User) => {
    if (targetUser.id === currentUser?.id) return;
    try {
      const res = await api.put(`/users/${targetUser.id}`, {
        is_active: !targetUser.is_active
      });
      setUsers(users.map(u => u.id === targetUser.id ? res.data : u));
    } catch (e) {
      console.error('Failed to update user status:', e);
    }
  };

  const handleRoleChange = async (targetUser: User, newRole: UserRole) => {
    try {
      const res = await api.put(`/users/${targetUser.id}`, {
        role: newRole
      });
      setUsers(users.map(u => u.id === targetUser.id ? res.data : u));
    } catch (e) {
      console.error('Failed to update role:', e);
    }
  };

  const filteredUsers = users.filter(u =>
    u.email.toLowerCase().includes(search.toLowerCase()) ||
    u.full_name.toLowerCase().includes(search.toLowerCase()) ||
    u.role.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center gap-2">
            <Users className="h-5 w-5 text-cyan-400" />
            USER MANAGEMENT &amp; ROLE-BASED ACCESS CONTROL (RBAC)
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Assign security roles (Super Admin, Security Analyst, Compliance Auditor) and enforce zero-trust access permissions.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsCreateOpen(true)}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-mono font-bold shadow-md shadow-cyan-500/20 transition-all"
          >
            <UserPlus className="h-4 w-4" />
            <span>CREATE USER</span>
          </button>
          <button
            onClick={fetchUsers}
            className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-all"
            title="Refresh"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div className="cyber-card p-4 rounded-xl flex items-center justify-between font-mono text-xs">
        <div className="relative w-full md:w-80">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search email, name, role..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
          />
        </div>
        <span className="text-slate-400 hidden sm:block">
          Total Operators: <strong className="text-white">{users.length}</strong>
        </span>
      </div>

      {/* Users Table */}
      <div className="cyber-card rounded-2xl overflow-hidden border border-slate-800">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 uppercase text-[10px]">
              <tr>
                <th className="py-3.5 px-4">Operator Name</th>
                <th className="py-3.5 px-4">Email Address</th>
                <th className="py-3.5 px-4">Role Assignment</th>
                <th className="py-3.5 px-4">Last Activity</th>
                <th className="py-3.5 px-4">Account Status</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredUsers.map((u) => {
                const isSelf = u.id === currentUser?.id;
                return (
                  <tr key={u.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3.5 px-4 font-bold text-white">
                      {u.full_name} {isSelf && <span className="text-cyan-400 text-[10px] ml-1">(You)</span>}
                    </td>

                    <td className="py-3.5 px-4 text-cyan-300">
                      {u.email}
                    </td>

                    <td className="py-3.5 px-4">
                      <select
                        value={u.role}
                        onChange={(e) => handleRoleChange(u, e.target.value as UserRole)}
                        disabled={isSelf}
                        className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-cyan-400"
                      >
                        <option value="admin">Super Admin</option>
                        <option value="analyst">Security Analyst</option>
                        <option value="auditor">Compliance Auditor</option>
                      </select>
                    </td>

                    <td className="py-3.5 px-4 text-slate-400">
                      {u.last_login ? new Date(u.last_login).toLocaleString() : 'Never logged in'}
                    </td>

                    <td className="py-3.5 px-4">
                      <Badge variant={u.is_active ? 'success' : 'critical'}>
                        {u.is_active ? 'ACTIVE' : 'DEACTIVATED'}
                      </Badge>
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      {!isSelf && (
                        <button
                          onClick={() => handleToggleActive(u)}
                          className={`p-1.5 rounded-lg font-mono text-[11px] font-bold transition-all ${
                            u.is_active
                              ? 'bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-500/40'
                              : 'bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-500/40'
                          }`}
                          title={u.is_active ? 'Deactivate User' : 'Activate User'}
                        >
                          {u.is_active ? <UserX className="h-4 w-4" /> : <UserCheck className="h-4 w-4" />}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* CREATE USER MODAL */}
      {isCreateOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="cyber-card w-full max-w-md rounded-2xl p-6 relative border border-slate-700 animate-in fade-in zoom-in-95">
            <button
              onClick={() => setIsCreateOpen(false)}
              className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-white bg-slate-800"
            >
              <X className="h-4 w-4" />
            </button>

            <div className="flex items-center gap-2 mb-4">
              <UserPlus className="h-5 w-5 text-cyan-400" />
              <h2 className="text-sm font-bold font-mono text-white uppercase">
                CREATE NEW SECURITY OPERATOR
              </h2>
            </div>

            {createError && (
              <div className="p-3 mb-4 rounded-xl bg-red-950/60 border border-red-500/40 text-red-300 font-mono text-xs">
                {createError}
              </div>
            )}

            <form onSubmit={handleCreateUser} className="space-y-4 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1">OPERATOR FULL NAME</label>
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="e.g. Jordan Miller"
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">EMAIL ADDRESS</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="operator@sentinel-x.sec"
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">INITIAL PASSWORD</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Minimum 8 characters"
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">SECURITY ROLE (RBAC)</label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value as UserRole)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-400"
                >
                  <option value="analyst">Security Analyst (Triage, Scans, Incidents)</option>
                  <option value="admin">Super Admin (Full Root Control)</option>
                  <option value="auditor">Compliance Auditor (Read-only Reports &amp; Logs)</option>
                </select>
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  className="w-full py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold tracking-wider transition-all shadow-lg shadow-cyan-500/20"
                >
                  PROVISION ACCOUNT
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
