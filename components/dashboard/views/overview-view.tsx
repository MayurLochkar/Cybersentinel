"use client";
import React from "react";
import {
  Bell,
  AlertOctagon,
  AlertTriangle,
  BrainCircuit,
  FileCheck2,
  TrendingUp,
  Activity,
  ArrowUpRight,
  ShieldCheck,
  Server,
  Zap,
} from "lucide-react";
import { useEffect, useState } from "react";
import { CYBER_DATA, Incident } from "@/data/cyberData";
import { cn } from "@/lib/utils";
import { fetchDashboardSummary, fetchAlerts, ApiDashboardSummary, ApiAlert } from "@/lib/api";

export function OverviewView({
  onSelectIncident,
  onNavigateTab,
}: {
  onSelectIncident: (incident: Incident) => void;
  onNavigateTab: (tab: string) => void;
}) {
  const { kpis: defaultKpis, attackDistribution, riskDistribution, weeklyActivity, recentIncidents: defaultIncidents, liveActivityFeed } =
    CYBER_DATA;

  const [liveKpis, setLiveKpis] = useState<ApiDashboardSummary | null>(null);
  const [liveAlerts, setLiveAlerts] = useState<ApiAlert[]>([]);
  const [backendConnected, setBackendConnected] = useState<boolean | null>(null);

  useEffect(() => {
    let isMounted = true;

    async function loadBackendData() {
      try {
        const [summary, alerts] = await Promise.all([
          fetchDashboardSummary(),
          fetchAlerts(),
        ]);
        if (isMounted) {
          setLiveKpis(summary);
          setLiveAlerts(alerts);
          setBackendConnected(true);
        }
      } catch (err) {
        if (isMounted) {
          setBackendConnected(false);
        }
      }
    }

    loadBackendData();
    const interval = setInterval(loadBackendData, 10000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Use live data if connected, otherwise fallback to static prototype data
  const totalAlertsCount = liveKpis ? liveKpis.total_alerts : defaultKpis.totalAlerts;
  const criticalCount = liveKpis ? liveKpis.critical : defaultKpis.critical;
  const highRiskCount = liveKpis ? liveKpis.high_risk : defaultKpis.highRisk;
  const activeInvestigationsCount = liveKpis ? liveKpis.active_investigations : defaultKpis.activeInvestigations;
  const verifiedEvidenceCount = liveKpis ? liveKpis.verified_evidence : defaultKpis.verifiedEvidence;

  return (
    <div className="space-y-8 pb-12">
      {/* Backend Integration Live Banner */}
      <div className="neu-flat rounded-2xl p-4 border border-white flex flex-wrap items-center justify-between gap-3 bg-gradient-to-r from-blue-50/50 via-white/80 to-cyan-50/50">
        <div className="flex items-center gap-3">
          <div className={cn(
            "w-3 h-3 rounded-full animate-pulse",
            backendConnected ? "bg-emerald-500 ring-4 ring-emerald-100" : backendConnected === false ? "bg-amber-500 ring-4 ring-amber-100" : "bg-blue-500 ring-4 ring-blue-100"
          )} />
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-slate-800">
                Backend Connection:
              </span>
              <span className={cn(
                "text-[10px] font-mono font-bold px-2 py-0.5 rounded-full uppercase",
                backendConnected ? "bg-emerald-100 text-emerald-700" : backendConnected === false ? "bg-amber-100 text-amber-700" : "bg-blue-100 text-blue-700"
              )}>
                {backendConnected ? "Connected (FastAPI + SQLite + ML)" : backendConnected === false ? "Offline (Using Local Fallback)" : "Connecting..."}
              </span>
            </div>
            <p className="text-[11px] text-slate-500">
              {backendConnected
                ? `Syncing live with SQLite DB & Random Forest classifier (${liveAlerts.length} live records)`
                : "Ensure backend is running on http://127.0.0.1:8000"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <span>Target:</span>
          <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-600 font-semibold">127.0.0.1:8000</span>
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* TOTAL ALERTS */}
        <div className="neu-flat rounded-2xl p-5 border border-white flex flex-col justify-between hover:translate-y-[-2px] transition-transform">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold tracking-wider text-slate-500 uppercase">
              Total Alerts
            </span>
            <div className="w-8 h-8 rounded-xl bg-blue-100 text-blue-600 flex items-center justify-center">
              <Bell className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-extrabold text-slate-900 tracking-tight font-mono">
              {totalAlertsCount}
            </div>
            <div className="flex items-center gap-1 text-[10px] font-semibold text-emerald-600 mt-1">
              <TrendingUp className="w-3 h-3" />
              <span>{liveKpis ? "Live SQLite Sync" : defaultKpis.totalAlertsTrend}</span>
            </div>
          </div>
        </div>

        {/* CRITICAL */}
        <div className="neu-flat rounded-2xl p-5 border border-white flex flex-col justify-between hover:translate-y-[-2px] transition-transform">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold tracking-wider text-red-600 uppercase">
              Critical
            </span>
            <div className="w-8 h-8 rounded-xl bg-red-100 text-red-600 flex items-center justify-center">
              <AlertOctagon className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-extrabold text-red-600 tracking-tight font-mono">
              {criticalCount}
            </div>
            <div className="text-[10px] font-semibold text-red-500 mt-1">
              {liveKpis ? "Real-time Severity Filter" : defaultKpis.criticalTrend}
            </div>
          </div>
        </div>

        {/* HIGH RISK */}
        <div className="neu-flat rounded-2xl p-5 border border-white flex flex-col justify-between hover:translate-y-[-2px] transition-transform">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold tracking-wider text-orange-600 uppercase">
              High Risk
            </span>
            <div className="w-8 h-8 rounded-xl bg-orange-100 text-orange-600 flex items-center justify-center">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-extrabold text-orange-600 tracking-tight font-mono">
              {highRiskCount}
            </div>
            <div className="text-[10px] font-semibold text-slate-500 mt-1">
              {liveKpis ? "High/Critical Cumulative" : defaultKpis.highRiskTrend}
            </div>
          </div>
        </div>

        {/* ACTIVE INVESTIGATIONS */}
        <div className="neu-flat rounded-2xl p-5 border border-white flex flex-col justify-between hover:translate-y-[-2px] transition-transform">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold tracking-wider text-blue-600 uppercase">
              Active Investigations
            </span>
            <div className="w-8 h-8 rounded-xl bg-indigo-100 text-indigo-600 flex items-center justify-center">
              <BrainCircuit className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-extrabold text-indigo-600 tracking-tight font-mono">
              {activeInvestigationsCount}
            </div>
            <div className="text-[10px] font-semibold text-indigo-500 mt-1">
              {liveKpis ? "Active In-Flight Matrix" : defaultKpis.activeInvestigationsTrend}
            </div>
          </div>
        </div>

        {/* VERIFIED EVIDENCE */}
        <div className="neu-flat rounded-2xl p-5 border border-white flex flex-col justify-between hover:translate-y-[-2px] transition-transform">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold tracking-wider text-emerald-600 uppercase">
              Verified Evidence
            </span>
            <div className="w-8 h-8 rounded-xl bg-emerald-100 text-emerald-600 flex items-center justify-center">
              <FileCheck2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-extrabold text-emerald-600 tracking-tight font-mono">
              {verifiedEvidenceCount}
            </div>
            <div className="text-[10px] font-semibold text-emerald-600 mt-1">
              {defaultKpis.verifiedEvidenceTrend}
            </div>
          </div>
        </div>
      </div>

      {/* Visual Charts Grid: Attack Distribution (Donut), Risk Distribution, Attack Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* SECTION A — ATTACK DISTRIBUTION */}
        <div className="lg:col-span-4 neu-flat rounded-2xl p-6 border border-white">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Attack Distribution
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">Last 24 Hours</span>
          </div>

          <div className="flex flex-col sm:flex-row items-center gap-6">
            {/* SVG Donut Chart */}
            <div className="relative w-36 h-36 shrink-0 flex items-center justify-center">
              <svg viewBox="0 0 36 36" className="w-full h-full transform -rotate-90">
                {/* Background Ring */}
                <path
                  className="text-slate-200"
                  strokeWidth="4"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                {/* Brute force 32% */}
                <path
                  strokeDasharray="32, 100"
                  className="text-blue-600"
                  strokeWidth="4"
                  strokeLinecap="round"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                {/* DDoS 24% */}
                <path
                  strokeDasharray="24, 100"
                  strokeDashoffset="-32"
                  className="text-red-500"
                  strokeWidth="4"
                  strokeLinecap="round"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                {/* Port Scan 18% */}
                <path
                  strokeDasharray="18, 100"
                  strokeDashoffset="-56"
                  className="text-amber-500"
                  strokeWidth="4"
                  strokeLinecap="round"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                {/* Web Attack 14% */}
                <path
                  strokeDasharray="14, 100"
                  strokeDashoffset="-74"
                  className="text-cyan-500"
                  strokeWidth="4"
                  strokeLinecap="round"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-xl font-extrabold text-slate-800 font-mono">128</span>
                <span className="text-[9px] text-slate-400 font-bold uppercase">Attacks</span>
              </div>
            </div>

            {/* Legend breakdown list */}
            <div className="w-full space-y-2 text-xs">
              {attackDistribution.map((item) => (
                <div key={item.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span
                      className="w-2.5 h-2.5 rounded-full"
                      style={{ backgroundColor: item.color }}
                    />
                    <span className="text-slate-700 font-medium text-[11px]">{item.name}</span>
                  </div>
                  <span className="font-bold text-slate-900 font-mono text-[11px]">
                    {item.percentage}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* SECTION B — RISK DISTRIBUTION */}
        <div className="lg:col-span-4 neu-flat rounded-2xl p-6 border border-white">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Risk Distribution
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">Normalized Index</span>
          </div>

          <div className="space-y-3.5 pt-2">
            {riskDistribution.map((item) => (
              <div key={item.level} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-slate-700">{item.level}</span>
                  <span className="font-mono font-bold text-slate-900">
                    {item.count} incidents ({item.percentage}%)
                  </span>
                </div>
                <div className="h-2 w-full bg-slate-200/80 rounded-full overflow-hidden neu-pressed-sm">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${item.percentage * 1.3}%`,
                      backgroundColor: item.color,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 pt-4 border-t border-slate-200 flex items-center justify-between text-[11px] text-slate-500">
            <span>Critical triage priority</span>
            <button
              onClick={() => onNavigateTab("risk")}
              className="text-blue-600 font-semibold hover:underline flex items-center gap-1"
            >
              <span>View Matrix</span>
              <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* SECTION C — ATTACK ACTIVITY (7 Days) */}
        <div className="lg:col-span-4 neu-flat rounded-2xl p-6 border border-white">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Attack Activity (7 Days)
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">Alert Surge Velocity</span>
          </div>

          {/* Bar chart visualization */}
          <div className="h-44 flex items-end justify-between gap-2 pt-6 pb-2 px-2">
            {weeklyActivity.map((day) => {
              const heightPercent = (day.alerts / 180) * 100;
              return (
                <div key={day.day} className="flex-1 flex flex-col items-center gap-1.5 group">
                  <span className="text-[9px] font-mono text-slate-400 opacity-0 group-hover:opacity-100 transition-opacity">
                    {day.alerts}
                  </span>
                  <div className="w-full bg-slate-200/90 rounded-t-lg h-32 flex items-end overflow-hidden neu-pressed-sm">
                    <div
                      className="w-full bg-gradient-to-t from-blue-600 to-cyan-400 rounded-t-lg transition-all duration-500 group-hover:from-blue-500 group-hover:to-cyan-300"
                      style={{ height: `${heightPercent}%` }}
                    />
                  </div>
                  <span className="text-[10px] font-mono font-bold text-slate-600">{day.day}</span>
                </div>
              );
            })}
          </div>

          <div className="mt-2 pt-3 border-t border-slate-200 flex items-center justify-between text-[11px] text-slate-500">
            <span>Peak: Fri (165 alerts)</span>
            <span className="text-emerald-600 font-semibold">Normalized Baseline</span>
          </div>
        </div>
      </div>

      {/* SECTION D — RECENT INCIDENTS & SECTION E — LIVE ACTIVITY */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* SECTION D: Recent Incidents Table */}
        <div className="lg:col-span-8 neu-flat rounded-2xl p-6 border border-white">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                Recent Incidents
              </h3>
              <p className="text-[11px] text-slate-500">Click row for full AI & Forensic drill-down</p>
            </div>
            <button
              onClick={() => onNavigateTab("alerts")}
              className="text-xs text-blue-600 font-bold hover:underline flex items-center gap-1"
            >
              <span>View All 128 Alerts</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-slate-400 text-[10px] uppercase font-mono tracking-wider">
                  <th className="pb-3 font-semibold">Incident ID</th>
                  <th className="pb-3 font-semibold">Attack Type</th>
                  <th className="pb-3 font-semibold">Source IP</th>
                  <th className="pb-3 font-semibold">Target</th>
                  <th className="pb-3 font-semibold">Severity</th>
                  <th className="pb-3 font-semibold">Confidence</th>
                  <th className="pb-3 font-semibold">Status</th>
                  <th className="pb-3 font-semibold text-right">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/80 font-sans">
                {liveAlerts.length > 0
                  ? liveAlerts.slice(0, 5).map((alert) => {
                      const matched = defaultIncidents.find((i) => i.id === alert.incident_id);
                      const displayIncident: Incident = matched || {
                        id: alert.incident_id,
                        attackType: alert.attack_type,
                        sourceIp: alert.source_ip,
                        target: alert.target || "Network Host",
                        severity: alert.severity,
                        confidence: alert.confidence,
                        status: alert.status,
                        time: "Live Feed",
                        protocol: "TCP",
                        port: 443,
                        detectionTime: alert.created_at,
                        timeline: [
                          { time: "Just now", event: `Alert ${alert.incident_id} registered`, detail: alert.reason },
                        ],
                        aiExplanation: {
                          title: `${alert.attack_type} Pattern Identified`,
                          description: alert.reason || "Autonomous correlation from flow indicators.",
                          indicators: ["CICIDS2017 Flow Metrics", "Signature Anomalies"],
                        },
                        mitre: {
                          tactic: "Initial Access / Impact",
                          technique: alert.attack_type,
                          techniqueId: "T1110",
                          description: alert.reason,
                        },
                        investigation: {
                          status: alert.status,
                          progressSteps: [
                            { name: "Detection", completed: true },
                            { name: "Triage", completed: true },
                            { name: "Evidence Hash", completed: true },
                            { name: "Mitigation", completed: false },
                          ],
                          findings: [alert.reason],
                          relatedActivity: {
                            alertsCount: 1,
                            sourceIpsCount: 1,
                            affectedAssetsCount: 1,
                            suspiciousAuthCount: 0,
                          },
                          summary: alert.reason,
                        },
                        risk: {
                          score: alert.confidence,
                          level: alert.severity,
                          factors: [{ name: "Flow Density", level: alert.severity, score: alert.confidence }],
                          explanation: alert.reason,
                        },
                      };

                      return (
                        <tr
                          key={alert.id}
                          onClick={() => onSelectIncident(displayIncident)}
                          className="hover:bg-white/80 transition-colors cursor-pointer group"
                        >
                          <td className="py-3.5 font-bold font-mono text-blue-600 group-hover:underline flex items-center gap-1.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" title="Live SQLite Record" />
                            {alert.incident_id}
                          </td>
                          <td className="py-3.5 font-semibold text-slate-800">{alert.attack_type}</td>
                          <td className="py-3.5 font-mono text-slate-600">{alert.source_ip}</td>
                          <td className="py-3.5 text-slate-700">{alert.target || "Host"}</td>
                          <td className="py-3.5">
                            <span
                              className={cn(
                                "px-2 py-0.5 rounded-full text-[10px] font-extrabold tracking-wider font-mono",
                                alert.severity === "CRITICAL"
                                  ? "bg-red-100 text-red-700 border border-red-200"
                                  : alert.severity === "HIGH"
                                  ? "bg-orange-100 text-orange-700 border border-orange-200"
                                  : "bg-amber-100 text-amber-700 border border-amber-200"
                              )}
                            >
                              {alert.severity}
                            </span>
                          </td>
                          <td className="py-3.5 font-mono font-bold text-slate-800">
                            {alert.confidence}%
                          </td>
                          <td className="py-3.5">
                            <span
                              className={cn(
                                "px-2 py-0.5 rounded-full text-[10px] font-semibold",
                                alert.status === "Investigating"
                                  ? "bg-blue-100 text-blue-700"
                                  : "bg-slate-200 text-slate-700"
                              )}
                            >
                              {alert.status}
                            </span>
                          </td>
                          <td className="py-3.5 text-right font-mono text-slate-400 text-[11px]">
                            Live
                          </td>
                        </tr>
                      );
                    })
                  : defaultIncidents.map((incident) => (
                      <tr
                        key={incident.id}
                        onClick={() => onSelectIncident(incident)}
                        className="hover:bg-white/80 transition-colors cursor-pointer group"
                      >
                        <td className="py-3.5 font-bold font-mono text-blue-600 group-hover:underline">
                          {incident.id}
                        </td>
                        <td className="py-3.5 font-semibold text-slate-800">{incident.attackType}</td>
                        <td className="py-3.5 font-mono text-slate-600">{incident.sourceIp}</td>
                        <td className="py-3.5 text-slate-700">{incident.target}</td>
                        <td className="py-3.5">
                          <span
                            className={cn(
                              "px-2 py-0.5 rounded-full text-[10px] font-extrabold tracking-wider font-mono",
                              incident.severity === "CRITICAL"
                                ? "bg-red-100 text-red-700 border border-red-200"
                                : incident.severity === "HIGH"
                                ? "bg-orange-100 text-orange-700 border border-orange-200"
                                : "bg-amber-100 text-amber-700 border border-amber-200"
                            )}
                          >
                            {incident.severity}
                          </span>
                        </td>
                        <td className="py-3.5 font-mono font-bold text-slate-800">
                          {incident.confidence}%
                        </td>
                        <td className="py-3.5">
                          <span
                            className={cn(
                              "px-2 py-0.5 rounded-full text-[10px] font-semibold",
                              incident.status === "Investigating"
                                ? "bg-blue-100 text-blue-700"
                                : "bg-slate-200 text-slate-700"
                            )}
                          >
                            {incident.status}
                          </span>
                        </td>
                        <td className="py-3.5 text-right font-mono text-slate-400 text-[11px]">
                          {incident.time}
                        </td>
                      </tr>
                    ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* SECTION E: Live Security Activity Stream */}
        <div className="lg:col-span-4 neu-flat rounded-2xl p-6 border border-white flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
                <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  Live Security Activity
                </h3>
              </div>
              <span className="text-[10px] text-slate-400 font-mono">SOC Stream</span>
            </div>

            <div className="space-y-3.5">
              {liveActivityFeed.map((feed, idx) => (
                <div key={idx} className="flex items-start gap-3 text-xs">
                  <span className="text-[10px] font-mono text-slate-400 shrink-0 mt-0.5">
                    {feed.time}
                  </span>
                  <div className="flex-1 bg-white/70 p-2.5 rounded-xl neu-flat-sm border border-white">
                    <p className="font-medium text-slate-800 leading-snug">{feed.text}</p>
                    <div className="flex items-center gap-2 mt-1">
                      <span
                        className={cn(
                          "text-[9px] font-bold uppercase font-mono px-1.5 py-0.2 rounded",
                          feed.severity === "CRITICAL"
                            ? "bg-red-100 text-red-600"
                            : feed.severity === "HIGH"
                            ? "bg-orange-100 text-orange-600"
                            : feed.severity === "SUCCESS"
                            ? "bg-emerald-100 text-emerald-600"
                            : "bg-blue-100 text-blue-600"
                        )}
                      >
                        {feed.severity}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-slate-200 text-center">
            <span className="text-[11px] text-slate-400 font-mono">
              Autonomous telemetry socket listening on port 9443
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
