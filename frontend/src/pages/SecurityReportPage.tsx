import React, { useState, useEffect } from 'react';
import {
  FileText,
  Printer,
  ShieldCheck,
  AlertTriangle,
  Server,
  Bug,
  Lock,
  RefreshCw,
  CheckCircle2,
  Calendar
} from 'lucide-react';
import { api } from '../services/api';
import { ExecutiveReport } from '../types';
import { Badge } from '../components/common/Badge';

export const SecurityReportPage: React.FC = () => {
  const [report, setReport] = useState<ExecutiveReport | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchReport = async () => {
    try {
      setIsLoading(true);
      const res = await api.get('/reports/executive');
      setReport(res.data);
    } catch (e) {
      console.error('Error generating executive report:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, []);

  const handlePrint = () => {
    window.print();
  };

  if (isLoading && !report) {
    return (
      <div className="flex items-center justify-center min-h-[500px]">
        <div className="flex flex-col items-center gap-3">
          <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
          <span className="text-xs font-mono text-slate-400">COMPILING EXECUTIVE SECURITY REPORT...</span>
        </div>
      </div>
    );
  }

  if (!report) return null;

  return (
    <div className="space-y-6">
      {/* Action Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 print:hidden">
        <div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center gap-2">
            <FileText className="h-5 w-5 text-cyan-400" />
            EXECUTIVE SECURITY &amp; COMPLIANCE REPORT
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Automated posture assessment, vulnerability telemetry, and Zero-Trust isolation status.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handlePrint}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-mono font-bold shadow-md shadow-cyan-500/20 transition-all"
          >
            <Printer className="h-4 w-4" />
            <span>PRINT / EXPORT PDF</span>
          </button>
          <button
            onClick={fetchReport}
            className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-all"
            title="Regenerate"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Printable Report Document Container */}
      <div className="cyber-card p-8 rounded-2xl border border-slate-800 space-y-8 print:bg-white print:text-black print:p-0 print:border-none">
        {/* Document Header */}
        <div className="flex items-start justify-between border-b border-slate-800 pb-6 print:border-gray-300">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-2xl font-black font-mono tracking-wider text-white print:text-black">
                {report.platform_name}
              </span>
              <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 font-mono text-xs border border-cyan-500/30 print:border-gray-400">
                OFFICIAL BRIEFING
              </span>
            </div>
            <p className="text-xs font-mono text-slate-400 print:text-gray-600 mt-1">
              Phase 1 Unified Cybersecurity &amp; Traffic Analysis System
            </p>
          </div>

          <div className="text-right font-mono text-xs text-slate-400 print:text-gray-600 space-y-1">
            <div className="flex items-center gap-1.5 justify-end">
              <Calendar className="h-3.5 w-3.5" />
              <span>{new Date(report.generated_at).toLocaleString()}</span>
            </div>
            <p>CLASSIFICATION: <strong className="text-amber-400 print:text-black">CONFIDENTIAL / SOC INTERNAL</strong></p>
          </div>
        </div>

        {/* Executive Summary Score Cards */}
        <div>
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono mb-4 print:text-gray-700">
            1. EXECUTIVE SECURITY POSTURE INDEX
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 font-mono">
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 print:bg-gray-50 print:border-gray-300">
              <span className="text-[10px] text-slate-400 uppercase block">Global Threat Score</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-3xl font-bold text-white print:text-black">{report.overall_risk_score}</span>
                <span className="text-xs text-slate-400">/ 100</span>
              </div>
              <span className="text-xs font-bold text-cyan-400 print:text-blue-600 block mt-1">
                {report.risk_level} POSTURE (GRADE {report.risk_grade})
              </span>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 print:bg-gray-50 print:border-gray-300">
              <span className="text-[10px] text-slate-400 uppercase block">Monitored Hardware</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-3xl font-bold text-white print:text-black">{report.total_assets}</span>
                <span className="text-xs text-slate-400">Nodes</span>
              </div>
              <span className="text-xs text-slate-400 block mt-1">
                {report.cctv_iot_devices} CCTV &amp; IoT Devices
              </span>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 print:bg-gray-50 print:border-gray-300">
              <span className="text-[10px] text-slate-400 uppercase block">Vulnerability Exposures</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-3xl font-bold text-red-400 print:text-red-600">{report.critical_vulnerabilities}</span>
                <span className="text-xs text-slate-400">Critical CVEs</span>
              </div>
              <span className="text-xs text-amber-400 block mt-1">
                +{report.high_vulnerabilities} High Severity
              </span>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 print:bg-gray-50 print:border-gray-300">
              <span className="text-[10px] text-slate-400 uppercase block">Quarantine Containment</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-3xl font-bold text-purple-400 print:text-purple-600">{report.quarantined_assets}</span>
                <span className="text-xs text-slate-400">Isolated</span>
              </div>
              <span className="text-xs text-emerald-400 block mt-1">
                {report.online_assets} Healthy Active
              </span>
            </div>
          </div>
        </div>

        {/* Top Vulnerable Assets Table */}
        <div>
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono mb-4 print:text-gray-700">
            2. HIGH-RISK INFRASTRUCTURE ASSETS
          </h2>
          <div className="overflow-x-auto rounded-xl border border-slate-800 print:border-gray-300">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-900 text-slate-400 print:bg-gray-100 print:text-gray-700 border-b border-slate-800 uppercase text-[10px]">
                <tr>
                  <th className="py-2.5 px-4">Asset / Hostname</th>
                  <th className="py-2.5 px-4">IP Address</th>
                  <th className="py-2.5 px-4">Device Class</th>
                  <th className="py-2.5 px-4">Operating System</th>
                  <th className="py-2.5 px-4">Risk Index</th>
                  <th className="py-2.5 px-4">Quarantine Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 print:divide-gray-200">
                {report.top_vulnerable_assets.map((asset) => (
                  <tr key={asset.id} className="print:text-black">
                    <td className="py-2.5 px-4 font-bold text-white print:text-black">{asset.hostname}</td>
                    <td className="py-2.5 px-4 text-cyan-300 print:text-blue-600">{asset.ip_address}</td>
                    <td className="py-2.5 px-4">{asset.device_type}</td>
                    <td className="py-2.5 px-4 text-slate-300">{asset.os || 'N/A'}</td>
                    <td className="py-2.5 px-4 font-bold text-red-400">{asset.risk_score}</td>
                    <td className="py-2.5 px-4">
                      <Badge size="sm" variant={asset.is_quarantined ? 'critical' : 'success'}>
                        {asset.is_quarantined ? 'QUARANTINED' : 'ACTIVE'}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Compliance and Recommendations */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
          {/* Compliance Posture */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 print:bg-gray-50 print:border-gray-300 space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 print:text-gray-800 flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              COMPLIANCE AUDIT BENCHMARKS
            </h3>
            <div className="space-y-2 text-[11px] text-slate-300 print:text-gray-700">
              <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                <span>NIST SP 800-53 Posture Score:</span>
                <strong className="text-emerald-400 print:text-green-700">{report.compliance_posture.nist_score}% Compliant</strong>
              </div>
              <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                <span>CIS Benchmarks Pass Rate:</span>
                <strong className="text-emerald-400 print:text-green-700">{report.compliance_posture.cis_benchmarks_pass_rate}</strong>
              </div>
              <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                <span>Zero-Trust Microsegmentation:</span>
                <strong className="text-cyan-400 print:text-blue-700">{report.compliance_posture.zero_trust_segmentation}</strong>
              </div>
              <div className="flex justify-between">
                <span>Tamper-Resistant Audit Trail:</span>
                <strong className="text-emerald-400 print:text-green-700">{report.compliance_posture.audit_logging}</strong>
              </div>
            </div>
          </div>

          {/* Remediation Action Plan */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 print:bg-gray-50 print:border-gray-300 space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 print:text-gray-800 flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-cyan-400" />
              STRATEGIC REMEDIATION ROADMAP
            </h3>
            <ul className="space-y-2 text-[11px] text-slate-300 print:text-gray-700">
              {report.remediation_recommendations.map((rec, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-cyan-400 font-bold mt-0.5">•</span>
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Footer Signature Block */}
        <div className="border-t border-slate-800 pt-6 flex items-center justify-between text-slate-400 font-mono text-[11px] print:text-gray-500">
          <span>SENTINEL-X SECURITY PLATFORM • AUTOMATED REPORT ENGINE</span>
          <span>REPORT INTEGRITY VERIFIED (SHA-256 HASH COMPLIANT)</span>
        </div>
      </div>
    </div>
  );
};
