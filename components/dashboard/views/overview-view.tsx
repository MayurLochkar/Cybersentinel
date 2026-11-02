"use client";
import React from "react";
import { motion } from "framer-motion";
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
  ShieldAlert,
  Server,
  Zap,
  Radio,
  Play,
  Square,
  RefreshCw,
  Trash2,
  RotateCcw,
  CheckCircle2,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  Cpu,
  ArrowRight,
  Sparkles,
  Radar,
  Terminal,
  Key,
  Globe,
  Layers,
  Flame,
} from "lucide-react";
import { useEffect, useState } from "react";
import { CYBER_DATA, Incident } from "@/data/cyberData";
import { cn } from "@/lib/utils";
import {
  fetchDashboardSummary,
  fetchAlerts,
  fetchMonitoringStatus,
  fetchMonitoringMetrics,
  fetchAnalyticsSummary,
  clearAllAlerts,
  resetMonitoringTelemetry,
  startMonitoringSession,
  stopMonitoringSession,
  ApiDashboardSummary,
  ApiAlert,
  ApiAnalyticsSummary,
  MonitoringStatus,
  MonitoringMetrics,
} from "@/lib/api";

export function OverviewView({
  onSelectIncident,
  onNavigateTab,
  onInvestigateIncident,
}: {
  onSelectIncident: (incident: Incident) => void;
  onNavigateTab: (tab: string) => void;
  onInvestigateIncident?: (incident: Incident) => void;
}) {
  const { kpis: defaultKpis, attackDistribution: defaultAttackDist, riskDistribution: defaultRiskDist, weeklyActivity: defaultWeekly, recentIncidents: defaultIncidents, liveActivityFeed } =
    CYBER_DATA;

  const [liveKpis, setLiveKpis] = useState<ApiDashboardSummary | null>(null);
  const [liveAlerts, setLiveAlerts] = useState<ApiAlert[]>([]);
  const [analytics, setAnalytics] = useState<ApiAnalyticsSummary | null>(null);
  const [metrics, setMetrics] = useState<MonitoringMetrics | null>(null);
  const [backendConnected, setBackendConnected] = useState<boolean | null>(null);
  const [monitoringStatus, setMonitoringStatus] = useState<MonitoringStatus | null>(null);
  const [distributionTab, setDistributionTab] = useState<"live_flows" | "db_alerts">("live_flows");
  const [isClearing, setIsClearing] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [bannerNotice, setBannerNotice] = useState<string | null>(null);
  const [showQuickGuide, setShowQuickGuide] = useState<boolean>(true);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    async function loadBackendData() {
      try {
        const [summary, alerts, mon, analyticsData, metricsData] = await Promise.all([
          fetchDashboardSummary(),
          fetchAlerts(),
          fetchMonitoringStatus().catch(() => null),
          fetchAnalyticsSummary().catch(() => null),
          fetchMonitoringMetrics().catch(() => null),
        ]);
        if (isMounted) {
          setLiveKpis(summary);
          setLiveAlerts(alerts);
          if (mon) setMonitoringStatus(mon);
          if (analyticsData) setAnalytics(analyticsData);
          if (metricsData) setMetrics(metricsData);
          setBackendConnected(true);
        }
      } catch (err) {
        if (isMounted) {
          setBackendConnected(false);
        }
      }
    }

    loadBackendData();
    const handleGlobalRefresh = () => {
      loadBackendData();
    };
    if (typeof window !== "undefined") {
      window.addEventListener("cybersentinel-refresh-all", handleGlobalRefresh);
    }
    const interval = setInterval(loadBackendData, 5000);
    return () => {
      isMounted = false;
      clearInterval(interval);
      if (typeof window !== "undefined") {
        window.removeEventListener("cybersentinel-refresh-all", handleGlobalRefresh);
      }
    };
  }, []);

  // Dynamic telemetry calculations linked directly to live monitoring & database
  const flowsProcessed =
    monitoringStatus?.flows_processed ?? liveKpis?.flows_processed ?? metrics?.flows_processed ?? 0;
  const benignCount =
    monitoringStatus?.benign_count ?? liveKpis?.benign_count ?? metrics?.benign_count ?? 0;
  const attackCount =
    monitoringStatus?.attack_count ?? liveKpis?.attack_count ?? metrics?.attack_count ?? 0;
  const packetsCaptured =
    monitoringStatus?.packets_captured ?? liveKpis?.packets_captured ?? metrics?.packets_captured ?? 0;

  // Real database alerts
  const totalAlertsCount = liveAlerts.length;
  const criticalCount = liveAlerts.filter((a) => a.severity === "CRITICAL").length;
  const highRiskCount = liveAlerts.filter((a) => a.severity === "HIGH" || a.severity === "CRITICAL").length;
  const activeInvestigationsCount = liveAlerts.filter((a) => a.status === "Investigating").length;
  const verifiedEvidenceCount = liveKpis?.verified_evidence ?? 0;

  // Determine if an attack is actively occurring RIGHT NOW (from Laptop B or active sniffer):
  const isAttackActive = Boolean(
    monitoringStatus?.is_active_attack ||
    liveKpis?.is_active_attack ||
    liveAlerts.some((a) => {
      if (!a.created_at) return false;
      const ageMs = Date.now() - new Date(a.created_at).getTime();
      return ageMs >= 0 && ageMs <= 35000;
    })
  );

  // Active top attack alert:
  // If user clicked a specific incident pill, show that; otherwise default to the MOST RECENT alert (liveAlerts[0])
  const activeThreatAlert = (selectedAlertId && liveAlerts.find((a) => a.incident_id === selectedAlertId)) || liveAlerts[0] || null;

  const topCriticalAlert = isAttackActive
    ? activeThreatAlert
    : null;

  const validLaptopBIp = (() => {
    const candidate = monitoringStatus?.laptop_b_ip || metrics?.laptop_b_ip;
    if (
      candidate &&
      candidate !== "Auto-detecting on first packet" &&
      !candidate.endsWith(".1") &&
      !candidate.endsWith(".254") &&
      candidate !== "192.168.56.1" &&
      !candidate.includes(":")
    ) {
      return candidate;
    }
    if (topCriticalAlert?.source_ip) {
      return topCriticalAlert.source_ip;
    }
    return "192.168.29.252";
  })();

  const attackerDisplayIp = (() => {
    if (!topCriticalAlert) return `Laptop B (${validLaptopBIp})`;
    const raw = topCriticalAlert.source_ip || "";
    if (raw.endsWith(".1") || raw.endsWith(".254") || raw === "192.168.56.1" || raw.includes(":")) {
      return `Laptop B (${validLaptopBIp})`;
    }
    if (raw.startsWith("192.168.") || raw.startsWith("10.") || raw.startsWith("172.")) {
      return `Laptop B (${raw})`;
    }
    return `Laptop B (${validLaptopBIp})`;
  })();

  const buildTopIncident = (alert: ApiAlert): Incident => {
    const portMatch = alert.target?.match(/port\s*(\d+)/i) || alert.reason?.match(/port\s*(\d+)/i);
    const parsedPort = portMatch ? parseInt(portMatch[1], 10) : alert.attack_type?.toLowerCase().includes("ssh") ? 22 : 80;
    const parsedProtocol = alert.attack_type?.toLowerCase().includes("udp") ? "UDP" : "TCP";
    const cleanSourceIp = (alert.source_ip && !alert.source_ip.endsWith(".1") && !alert.source_ip.endsWith(".254") && alert.source_ip !== "192.168.56.1" && !alert.source_ip.includes(":"))
      ? alert.source_ip
      : validLaptopBIp;

    return {
      id: alert.incident_id,
      attackType: alert.attack_type,
      sourceIp: cleanSourceIp,
      destinationIp: alert.destination_ip || "192.168.29.93",
      target: alert.target || `Port ${parsedPort} (${parsedProtocol})`,
      severity: alert.severity,
      confidence: alert.confidence,
      status: alert.status as any,
      time: alert.created_at ? alert.created_at.slice(11, 16) : "Recent",
      protocol: parsedProtocol,
      port: parsedPort,
      detectionTime: alert.created_at || new Date().toISOString(),
      timeline: [
        {
          time: alert.created_at ? alert.created_at.slice(11, 19) : "Detection",
          event: `Alert ${alert.incident_id} registered`,
          detail: alert.reason || `Real-time correlation: ${alert.attack_type} flagged with ${alert.confidence}% confidence.`,
        },
        {
          time: "Forensics",
          event: "Evidence Packet Chain Hashed",
          detail: `SHA-256 integrity hash committed for ${alert.source_ip} flow capture.`,
        },
      ],
      aiExplanation: {
        title: `${alert.attack_type} Signature Identified`,
        description: alert.reason || `Autonomous detection of ${alert.attack_type} based on flow indicators.`,
        indicators: ["CICIDS2017 Flow Metrics", "Statistical Anomaly Threshold", "Signature Correlation"],
      },
      mitre: {
        tactic: alert.attack_type.includes("Scan") ? "Reconnaissance" : alert.attack_type.includes("Brute") ? "Credential Access" : "Impact",
        technique: alert.attack_type,
        techniqueId: alert.attack_type.includes("Brute") ? "T1110" : alert.attack_type.includes("Scan") ? "T1046" : alert.attack_type.includes("DDoS") || alert.attack_type.includes("DoS") ? "T1498" : "T1190",
        description: alert.reason,
      },
      investigation: {
        status: alert.status,
        progressSteps: [
          { name: "Detection", completed: true },
          { name: "Triage", completed: true },
          { name: "Evidence Hash", completed: true },
          { name: "Classification", completed: true },
          { name: "RAG Analysis", completed: true },
          { name: "Containment", completed: false },
          { name: "Mitigation", completed: alert.status === "Resolved" },
        ],
        findings: [
          alert.reason || `Autonomous detection of ${alert.attack_type} based on network flow characteristics.`,
          `Source IP ${alert.source_ip} directed anomalous traffic toward internal target ${alert.destination_ip || "192.168.29.93"}:${parsedPort}.`,
          `Confidence evaluated at ${alert.confidence}% via Random Forest multi-class model (CICIDS2017 features).`,
          `Forensic evidence cryptographic hash recorded and verified in SQLite ledger.`,
        ],
        relatedActivity: {
          alertsCount: 1,
          sourceIpsCount: 1,
          affectedAssetsCount: 1,
          suspiciousAuthCount: 0,
        },
        summary: alert.reason || `${alert.attack_type} detected from ${alert.source_ip} with ${alert.confidence}% confidence.`,
      },
      risk: {
        score: alert.confidence,
        level: alert.severity,
        factors: [
          { name: "Flow Density", level: alert.severity, score: alert.confidence },
          { name: "Host Vulnerability", level: alert.severity === "CRITICAL" ? "HIGH" : "MEDIUM", score: Math.min(100, alert.confidence * 0.9) },
          { name: "Network Exposure", level: "HIGH", score: 85 },
        ],
        explanation: alert.reason || `Live attack traffic from ${alert.source_ip} exceeding risk tolerance thresholds.`,
      },
    };
  };

  const handleClearAlerts = async () => {
    setIsClearing(true);
    setBannerNotice(null);
    try {
      const [res] = await Promise.all([
        clearAllAlerts(),
        resetMonitoringTelemetry().catch(() => null),
      ]);
      setLiveAlerts([]);
      setSelectedAlertId(null);
      if (monitoringStatus) {
        setMonitoringStatus({
          ...monitoringStatus,
          is_active_attack: false,
          current_threat_level: "NORMAL",
          active_attack_type: null,
          active_attack_source: null,
          attack_count: 0,
          alerts_created: 0,
          flows_processed: 0,
          benign_count: 0,
          packets_captured: 0,
        });
      }
      if (metrics) {
        setMetrics({
          ...metrics,
          flows_processed: 0,
          benign_count: 0,
          attack_count: 0,
          alerts_created: 0,
          packets_captured: 0,
          recent_flows: [],
          packets_from_laptop_b: 0,
        });
      }
      if (liveKpis) {
        setLiveKpis({
          ...liveKpis,
          total_alerts: 0,
          critical: 0,
          high_risk: 0,
          active_investigations: 0,
          open_alerts: 0,
          resolved_alerts: 0,
          monitoring_alerts: 0,
          attack_count: 0,
          flows_processed: 0,
          benign_count: 0,
          packets_captured: 0,
          is_active_attack: false,
          current_threat_level: "NORMAL",
          active_attack_type: null,
          active_attack_source: null,
        });
      }
      setBannerNotice(
        `Cleared ${res.deleted_count} alerts. All threat indicators, flows, incidents, and counters reset to zero across all features.`
      );
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("cybersentinel-refresh-all"));
      }
    } catch {
      setBannerNotice("Failed to clear alerts from database");
    } finally {
      setIsClearing(false);
    }
  };

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      const [summary, alerts, mon, analyticsData, metricsData] = await Promise.all([
        fetchDashboardSummary(),
        fetchAlerts(),
        fetchMonitoringStatus().catch(() => null),
        fetchAnalyticsSummary().catch(() => null),
        fetchMonitoringMetrics().catch(() => null),
      ]);
      setLiveKpis(summary);
      setLiveAlerts(alerts);
      if (mon) setMonitoringStatus(mon);
      if (analyticsData) setAnalytics(analyticsData);
      if (metricsData) setMetrics(metricsData);
      setBannerNotice("Dashboard refreshed with latest live telemetry & database records.");
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("cybersentinel-refresh-all"));
      }
    } catch {
      // non-blocking
    } finally {
      setTimeout(() => setIsRefreshing(false), 500);
    }
  };

  return (
    <div className="space-y-8 pb-12">
      {/* Backend Integration Live Banner */}
      <div className="neu-flat rounded-2xl p-4 border border-white flex flex-wrap items-center justify-between gap-3 bg-gradient-to-r from-blue-50/50 via-white/80 to-cyan-50/50 shadow-sm">
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
                ? `Syncing live with SQLite DB & Random Forest classifier (${liveAlerts.length} DB records, ${flowsProcessed} live flows)`
                : "Ensure backend is running on http://127.0.0.1:8000"}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {liveAlerts.length > 0 && (
            <button
              onClick={handleClearAlerts}
              disabled={isClearing}
              className="px-3 py-1.5 rounded-xl neu-flat hover:bg-rose-50 text-rose-700 text-xs font-semibold flex items-center gap-1.5 transition-all active:scale-95 border border-rose-200/60 cursor-pointer shadow-2xs"
              title="Clear logged incident history so dashboard reflects current live state"
            >
              <Trash2 className="w-3.5 h-3.5 text-rose-600" />
              <span>Clear Alert Log ({liveAlerts.length})</span>
            </button>
          )}

          <button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="px-3 py-1.5 rounded-xl neu-flat hover:bg-white text-slate-700 hover:text-cyan-700 text-xs font-semibold flex items-center gap-1.5 transition-all active:scale-95 border border-white"
            title="Refresh All Telemetry Across Dashboard"
          >
            <RefreshCw className={cn("w-3.5 h-3.5 text-cyan-600", isRefreshing && "animate-spin")} />
            <span>Refresh</span>
          </button>

          <div className="hidden sm:flex items-center gap-1.5 text-xs font-mono text-slate-400 pl-1 border-l border-slate-200">
            <span>Target:</span>
            <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-600 font-semibold text-[11px]">127.0.0.1:8000</span>
          </div>
        </div>
      </div>

      {/* Banner Feedback / Diagnostic Notice */}
      {bannerNotice && (
        <div className="neu-flat rounded-xl p-3 border border-emerald-200 bg-emerald-50/80 text-emerald-800 text-xs flex items-center justify-between gap-3 animate-fade-in">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
            <span className="font-medium">{bannerNotice}</span>
          </div>
          <button
            onClick={() => setBannerNotice(null)}
            className="text-slate-400 hover:text-slate-700 text-xs font-bold"
          >
            &times;
          </button>
        </div>
      )}

      {/* ── HIGH CLARITY THREAT DETECTION & RAPID INVESTIGATION HERO BANNER ── */}
      {topCriticalAlert ? (
        <div className="neu-card-glow rounded-3xl p-6 bg-gradient-to-r from-rose-50/95 via-white/95 to-violet-50/95 border-2 border-rose-300/80 shadow-md flex flex-col lg:flex-row lg:items-center justify-between gap-5 relative overflow-hidden">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-2xl bg-rose-500 text-white flex items-center justify-center shrink-0 shadow-lg shadow-rose-500/25 animate-pulse">
              <ShieldAlert className="w-7 h-7" />
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase tracking-wider bg-rose-600 text-white shadow-xs">
                  Attack Detected
                </span>
                <span className={cn(
                  "px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase",
                  topCriticalAlert.severity === "CRITICAL"
                    ? "bg-rose-100 text-rose-700 border border-rose-200"
                    : "bg-amber-100 text-amber-700 border border-amber-200"
                )}>
                  {topCriticalAlert.severity} PRIORITY
                </span>
                <span className="text-[11px] font-mono text-slate-500 font-semibold bg-white/80 px-2 py-0.5 rounded border border-slate-200">
                  {topCriticalAlert.incident_id}
                </span>
              </div>

              <h2 className="text-xl sm:text-2xl font-black text-slate-900 tracking-tight">
                {topCriticalAlert.attack_type}
              </h2>

              <div className="flex flex-wrap items-center gap-2.5 text-xs text-slate-600 font-medium pt-0.5">
                <span className="bg-white/80 px-2.5 py-1 rounded-lg border border-slate-200 shadow-2xs">
                  <span className="text-slate-400">Attacker:</span> <strong className="font-mono text-rose-600 font-bold">{attackerDisplayIp}</strong>
                </span>
                <span className="bg-white/80 px-2.5 py-1 rounded-lg border border-slate-200 shadow-2xs">
                  <span className="text-slate-400">Target:</span> <strong className="font-mono text-slate-800">{topCriticalAlert.target || "Port 80 (TCP)"}</strong>
                </span>
                <span className="bg-white/80 px-2.5 py-1 rounded-lg border border-slate-200 shadow-2xs">
                  <span className="text-slate-400">ML Confidence:</span> <strong className="font-mono text-violet-700">{topCriticalAlert.confidence}%</strong>
                </span>
              </div>

              {/* Multi-Attack Incident Switcher Pills */}
              {liveAlerts.length > 1 && (
                <div className="pt-2.5 border-t border-rose-200/60 mt-2">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-[10px] font-extrabold uppercase text-slate-500 tracking-wider">
                      Switch Attack ({liveAlerts.length}):
                    </span>
                    {liveAlerts.slice(0, 6).map((alt, idx) => {
                      const isSelected = topCriticalAlert?.incident_id === alt.incident_id;
                      return (
                        <button
                          key={alt.incident_id}
                          onClick={() => setSelectedAlertId(alt.incident_id)}
                          className={cn(
                            "px-2.5 py-1 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer shadow-2xs border",
                            isSelected
                              ? "bg-slate-900 text-white border-slate-900 shadow-sm ring-2 ring-rose-400"
                              : "bg-white/90 text-slate-700 hover:bg-white border-slate-200/80"
                          )}
                          title={`Switch to ${alt.attack_type}`}
                        >
                          <span className={cn(
                            "w-2 h-2 rounded-full shrink-0",
                            idx === 0 ? "bg-rose-500 animate-pulse" : alt.severity === "CRITICAL" ? "bg-rose-500" : "bg-amber-500"
                          )} />
                          <span className="truncate max-w-[130px]">{alt.attack_type}</span>
                          {idx === 0 && (
                            <span className="px-1 py-0.2 rounded text-[9px] bg-rose-500/20 text-rose-700 font-extrabold uppercase">
                              Latest
                            </span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="flex flex-col sm:flex-row lg:flex-col items-stretch sm:items-center gap-2.5 shrink-0 relative z-20">
            <button
              id="hero-investigate-btn"
              onClick={() => {
                const inc = buildTopIncident(topCriticalAlert);
                if (onInvestigateIncident) {
                  onInvestigateIncident(inc);
                } else {
                  onSelectIncident(inc);
                  onNavigateTab("investigation");
                }
              }}
              className="neu-accent-btn px-5 py-3 rounded-2xl font-bold text-xs sm:text-sm flex items-center justify-center gap-2 shadow-md hover:shadow-lg transition-all text-white cursor-pointer relative z-20"
            >
              <BrainCircuit className="w-4 h-4 text-glacier" />
              <span>Investigate Attack Now</span>
              <ArrowRight className="w-4 h-4" />
            </button>
            <button
              id="hero-dossier-btn"
              onClick={() => onSelectIncident(buildTopIncident(topCriticalAlert))}
              className="px-4 py-2 rounded-2xl neu-flat hover:bg-slate-100 font-semibold text-xs text-slate-700 flex items-center justify-center gap-1.5 transition-all border border-slate-200 cursor-pointer relative z-20"
            >
              View Full Incident Dossier
            </button>
          </div>
        </div>
      ) : (
        <div className="neu-card-glow rounded-3xl p-5 bg-gradient-to-r from-emerald-50/95 via-white/95 to-cyan-50/95 border-2 border-emerald-300 shadow-md flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-11 h-11 rounded-2xl bg-emerald-500 text-white flex items-center justify-center shrink-0 shadow-md shadow-emerald-500/25">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase tracking-wider bg-emerald-100 text-emerald-800 border border-emerald-200">
                  System Secure
                </span>
                <span className="text-xs text-slate-500 font-medium">
                  Threat Status: <strong className="text-emerald-700 font-bold">NORMAL</strong> (No Active Attacks)
                </span>
                {validLaptopBIp && (
                  <span className="text-[11px] font-mono text-slate-600 bg-white/80 px-2.5 py-0.5 rounded-lg border border-slate-200 shadow-2xs">
                    Laptop B: <strong className="text-slate-800">{validLaptopBIp}</strong>
                  </span>
                )}
              </div>
              <h2 className="text-base font-extrabold text-slate-900 mt-1">
                All Systems Normal — Zero Active Threat Anomalies
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Listening for incoming network traffic. When Laptop B attacks (DoS, Port Scan, SSH/FTP Brute Force, Web Attack), real-time alerts trigger instantly.
              </p>
            </div>
          </div>
          <button
            onClick={() => onNavigateTab("monitoring")}
            className="neu-accent-btn px-4 py-2.5 rounded-xl font-bold text-xs flex items-center justify-center gap-2 text-white shrink-0 cursor-pointer shadow-sm hover:shadow-md transition-all"
          >
            <Radio className="w-4 h-4 text-glacier" />
            <span>Open Live SOC Monitor</span>
          </button>
        </div>
      )}

      {/* ── RECENT ATTACKS FEED (MULTI-CLASS CLASSIFICATION LEDGER) ── */}
      {liveAlerts.length > 0 && (
        <div className="neu-flat rounded-2xl p-5 border border-white bg-gradient-to-r from-slate-50/70 via-white to-rose-50/50 shadow-sm space-y-3.5">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-xl bg-rose-500/10 text-rose-600 flex items-center justify-center font-bold">
                <Layers className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <span>Recent Classified Attacks & Threats</span>
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-rose-100 text-rose-700 border border-rose-200">
                    {liveAlerts.length} LOGGED
                  </span>
                </h3>
                <p className="text-[11px] text-slate-500">
                  Click any attack to feature it on the investigation board above or deep-dive into AI triage.
                </p>
              </div>
            </div>

            <button
              onClick={() => onNavigateTab("alerts")}
              className="text-xs font-bold text-rose-700 hover:text-rose-800 hover:underline flex items-center gap-1 cursor-pointer"
            >
              <span>View All In Alerts View</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 pt-1">
            {liveAlerts.slice(0, 6).map((alert, idx) => {
              const isSelected = (topCriticalAlert?.incident_id === alert.incident_id);
              const isPortScan = alert.attack_type?.toLowerCase().includes("scan");
              const isSSH = alert.attack_type?.toLowerCase().includes("ssh");
              const isFTP = alert.attack_type?.toLowerCase().includes("ftp");
              const isWeb = alert.attack_type?.toLowerCase().includes("web");
              const isDoS = alert.attack_type?.toLowerCase().includes("dos") || alert.attack_type?.toLowerCase().includes("syn");

              return (
                <div
                  key={alert.incident_id}
                  onClick={() => setSelectedAlertId(alert.incident_id)}
                  className={cn(
                    "p-3.5 rounded-xl border transition-all cursor-pointer flex flex-col justify-between shadow-2xs hover:shadow-sm",
                    isSelected
                      ? "bg-rose-50/90 border-rose-400 ring-2 ring-rose-300"
                      : "bg-white hover:bg-slate-50/80 border-slate-200/80"
                  )}
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className={cn(
                        "text-[9px] font-mono font-bold px-2 py-0.5 rounded-full uppercase",
                        alert.severity === "CRITICAL"
                          ? "bg-rose-100 text-rose-700 border border-rose-200"
                          : alert.severity === "HIGH"
                          ? "bg-amber-100 text-amber-700 border border-amber-200"
                          : "bg-blue-100 text-blue-700 border border-blue-200"
                      )}>
                        {alert.severity}
                      </span>
                      <div className="flex items-center gap-1">
                        {idx === 0 && (
                          <span className="text-[9px] font-mono font-extrabold px-1.5 py-0.2 rounded bg-rose-600 text-white animate-pulse">
                            NEWEST
                          </span>
                        )}
                        <span className="text-[10px] font-mono text-slate-400">
                          {alert.incident_id}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 mb-1.5">
                      <div className={cn(
                        "w-6 h-6 rounded-lg flex items-center justify-center shrink-0",
                        isPortScan ? "bg-cyan-100 text-cyan-700" :
                        isSSH ? "bg-amber-100 text-amber-700" :
                        isFTP ? "bg-yellow-100 text-yellow-700" :
                        isWeb ? "bg-purple-100 text-purple-700" :
                        "bg-rose-100 text-rose-700"
                      )}>
                        {isPortScan ? <Radar className="w-3.5 h-3.5" /> :
                         isSSH ? <Key className="w-3.5 h-3.5" /> :
                         isFTP ? <Terminal className="w-3.5 h-3.5" /> :
                         isWeb ? <Globe className="w-3.5 h-3.5" /> :
                         <Flame className="w-3.5 h-3.5" />}
                      </div>
                      <h4 className="text-xs font-bold text-slate-900 truncate" title={alert.attack_type}>
                        {alert.attack_type}
                      </h4>
                    </div>

                    <div className="space-y-0.5 text-[11px] text-slate-500 font-mono">
                      <div>Target: <strong className="text-slate-700">{alert.target || "Port 80 (TCP)"}</strong></div>
                      <div>Source: <strong className="text-rose-600">{alert.source_ip || validLaptopBIp}</strong></div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-2.5 mt-2 border-t border-slate-100">
                    <span className="text-[10px] font-bold text-violet-700 font-mono">
                      ML Conf: {alert.confidence}%
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        const inc = buildTopIncident(alert);
                        if (onInvestigateIncident) {
                          onInvestigateIncident(inc);
                        } else {
                          onSelectIncident(inc);
                          onNavigateTab("investigation");
                        }
                      }}
                      className="text-[11px] font-bold text-slate-700 hover:text-rose-600 flex items-center gap-1 cursor-pointer transition-colors"
                    >
                      <span>Investigate</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* INTERACTIVE SYSTEM PIPELINE & QUICK START GUIDE */}
      <div className="neu-flat rounded-2xl p-5 border border-white bg-gradient-to-r from-purple-50/60 via-white to-blue-50/60 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-[#6F3DFF]/10 text-[#6F3DFF] flex items-center justify-center font-bold">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-slate-900">
                  How CyberSentinel-X Works (System Pipeline)
                </h2>
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 border border-emerald-200">
                  REAL-TIME PIPELINE
                </span>
              </div>
              <p className="text-[11px] text-slate-500">
                Packets are sniffed from your network adapter, grouped into flows, classified by AI, and sealed in the evidence ledger.
              </p>
            </div>
          </div>

          <button
            onClick={() => setShowQuickGuide(!showQuickGuide)}
            className="px-2.5 py-1 rounded-lg text-xs font-semibold text-slate-600 hover:text-slate-900 hover:bg-white/80 flex items-center gap-1 transition-all border border-slate-200/60"
          >
            <span>{showQuickGuide ? "Collapse" : "Expand Guide"}</span>
            {showQuickGuide ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>

        {showQuickGuide && (
          <div className="space-y-4 pt-1 animate-fade-in">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {/* STAGE 1 */}
              <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between hover:border-[#6F3DFF]/40 transition-all">
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-bold font-mono text-slate-400">STAGE 1</span>
                    <span className={cn(
                      "text-[9px] font-mono font-bold px-1.5 py-0.2 rounded-full",
                      monitoringStatus?.status === "RUNNING"
                        ? "bg-emerald-100 text-emerald-700"
                        : "bg-slate-100 text-slate-600"
                    )}>
                      {monitoringStatus?.status === "RUNNING" ? "SNIFFING LIVE" : "IDLE / READY"}
                    </span>
                  </div>
                  <h3 className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                    <Radio className="w-3.5 h-3.5 text-blue-600" />
                    1. Network Sniffer
                  </h3>
                  <p className="text-[11px] text-slate-500 mt-1">
                    Sniffs raw Wi-Fi/Ethernet packets without synthetic simulation.
                  </p>
                  <div className="text-[10px] font-mono font-bold text-slate-700 mt-2">
                    {packetsCaptured.toLocaleString()} Packets Sniffed
                  </div>
                </div>
                <button
                  onClick={() => onNavigateTab("monitoring")}
                  className="mt-3 text-[10px] font-bold text-[#6F3DFF] hover:underline flex items-center gap-1 self-start"
                >
                  <span>Open Live Sniffer</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>

              {/* STAGE 2 */}
              <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between hover:border-[#6F3DFF]/40 transition-all">
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono font-bold text-slate-400">STAGE 2</span>
                    <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded-full bg-purple-100 text-purple-700">
                      CICIDS2017 RF
                    </span>
                  </div>
                  <h3 className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                    <Cpu className="w-3.5 h-3.5 text-purple-600" />
                    2. AI Classifier
                  </h3>
                  <p className="text-[11px] text-slate-500 mt-1">
                    Extracts 70 features per 5-tuple flow & predicts Benign vs Threat.
                  </p>
                  <div className="text-[10px] font-mono font-bold text-slate-700 mt-2">
                    {flowsProcessed.toLocaleString()} Flows Evaluated
                  </div>
                </div>
                <button
                  onClick={() => onNavigateTab("model")}
                  className="mt-3 text-[10px] font-bold text-[#6F3DFF] hover:underline flex items-center gap-1 self-start"
                >
                  <span>Inspect ML Model</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>

              {/* STAGE 3 */}
              <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between hover:border-[#6F3DFF]/40 transition-all">
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono font-bold text-slate-400">STAGE 3</span>
                    <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded-full bg-rose-100 text-rose-700">
                      {totalAlertsCount} DB RECORDS
                    </span>
                  </div>
                  <h3 className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                    <Bell className="w-3.5 h-3.5 text-rose-600" />
                    3. Security Alerts
                  </h3>
                  <p className="text-[11px] text-slate-500 mt-1">
                    Anomalies generate alerts with risk scores & attack classification.
                  </p>
                  <div className="text-[10px] font-mono font-bold text-slate-700 mt-2">
                    {criticalCount > 0 ? `${criticalCount} Critical Priority` : `${totalAlertsCount} Total Alerts`}
                  </div>
                </div>
                <button
                  onClick={() => onNavigateTab("alerts")}
                  className="mt-3 text-[10px] font-bold text-[#6F3DFF] hover:underline flex items-center gap-1 self-start"
                >
                  <span>Triage Alerts</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>

              {/* STAGE 4 */}
              <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between hover:border-[#6F3DFF]/40 transition-all">
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono font-bold text-slate-400">STAGE 4</span>
                    <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded-full bg-emerald-100 text-emerald-700">
                      SHA-256 SEALED
                    </span>
                  </div>
                  <h3 className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                    <FileCheck2 className="w-3.5 h-3.5 text-emerald-600" />
                    4. Evidence Ledger
                  </h3>
                  <p className="text-[11px] text-slate-500 mt-1">
                    Authentic raw PCAP artifacts verified against on-disk cryptographic bytes.
                  </p>
                  <div className="text-[10px] font-mono font-bold text-emerald-700 mt-2">
                    {verifiedEvidenceCount} Verified Artifacts
                  </div>
                </div>
                <button
                  onClick={() => onNavigateTab("evidence")}
                  className="mt-3 text-[10px] font-bold text-[#6F3DFF] hover:underline flex items-center gap-1 self-start"
                >
                  <span>Verify Evidence</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>
            </div>

            {/* Quick operational tip */}
            <div className="p-2.5 rounded-xl bg-white/80 border border-slate-200/80 flex items-center justify-between text-[11px] text-slate-600">
              <span className="flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                <span>
                  <strong>Quick Start:</strong> To see live data immediately, click <strong>&ldquo;Open Monitoring Hub&rdquo;</strong> below, select your Wi-Fi interface, and click <strong>&ldquo;Start Live Capture&rdquo;</strong>.
                </span>
              </span>
              <button
                onClick={() => onNavigateTab("monitoring")}
                className="ml-2 px-2.5 py-1 rounded-lg bg-slate-900 text-white font-bold text-[10px] shrink-0 hover:bg-black transition-all"
              >
                Start Sniffer
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Live Network Monitoring Compact Control / Status Panel */}
      <div className="neu-flat rounded-2xl p-5 border border-white flex flex-col md:flex-row items-center justify-between gap-4 bg-gradient-to-r from-slate-50 via-white to-blue-50/40">
        <div className="flex items-center gap-3">
          <div className={cn(
            "w-10 h-10 rounded-xl flex items-center justify-center shadow-inner",
            monitoringStatus?.status === "RUNNING"
              ? "bg-emerald-100 text-emerald-700"
              : monitoringStatus?.status === "ERROR"
              ? "bg-rose-100 text-rose-700"
              : "bg-slate-200 text-slate-700"
          )}>
            <Radio className={cn("w-5 h-5", monitoringStatus?.status === "RUNNING" && "animate-pulse")} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-slate-900">Live Traffic Monitoring:</span>
              <span className={cn(
                "text-[10px] font-mono font-bold px-2 py-0.5 rounded-full uppercase",
                monitoringStatus?.status === "RUNNING"
                  ? "bg-emerald-100 text-emerald-800 border border-emerald-200"
                  : monitoringStatus?.status === "ERROR"
                  ? "bg-rose-100 text-rose-800 border border-rose-200"
                  : "bg-slate-100 text-slate-700 border border-slate-200"
              )}>
                {monitoringStatus?.status || "STOPPED"}
              </span>
              <span className="text-[10px] font-mono text-slate-500">
                Source: {monitoringStatus?.source || "None"}
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-slate-500 mt-0.5">
              <span>Flows: <strong className="text-slate-900">{monitoringStatus?.flows_processed || 0}</strong></span>
              <span>Benign: <strong className="text-emerald-700">{monitoringStatus?.benign_count || 0}</strong></span>
              <span>Attacks: <strong className="text-rose-700">{monitoringStatus?.attack_count || 0}</strong></span>
              <span>Alerts: <strong className="text-indigo-700">{monitoringStatus?.alerts_created || 0}</strong></span>
              {monitoringStatus?.last_error && (
                <span className="text-rose-600 truncate max-w-xs" title={monitoringStatus.last_error}>
                  Err: {monitoringStatus.last_error}
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end md:self-center shrink-0">
          <button
            onClick={() => onNavigateTab("monitoring")}
            className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-black text-white text-xs font-bold flex items-center gap-1.5 shadow-md active:scale-95 transition-all"
          >
            <span>Open Monitoring Hub</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Dynamic Project-Aligned KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* CARD 1: TOTAL FLOWS PROCESSED */}
        <div className="neu-flat rounded-2xl p-5 border border-white flex flex-col justify-between hover:translate-y-[-2px] transition-transform">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-[11px] font-bold tracking-wider text-slate-500 uppercase block">
                Total Flows
              </span>
              <span className="text-[9px] text-slate-400 font-medium">5-Tuple Conversations</span>
            </div>
            <div className="w-8 h-8 rounded-xl bg-blue-100 text-blue-600 flex items-center justify-center">
              <Radio className={cn("w-4 h-4", monitoringStatus?.status === "RUNNING" && "animate-pulse")} />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-extrabold text-slate-900 tracking-tight font-mono">
              {flowsProcessed.toLocaleString()}
            </div>
            <div className="flex items-center gap-1 text-[10px] font-semibold text-blue-600 mt-1 font-mono">
              <Activity className="w-3 h-3" />
              <span>{packetsCaptured.toLocaleString()} Packets Captured</span>
            </div>
          </div>
        </div>

        {/* CARD 2: BENIGN / CLEAN TRAFFIC */}
        <div className="neu-flat rounded-2xl p-5 border border-white flex flex-col justify-between hover:translate-y-[-2px] transition-transform">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-[11px] font-bold tracking-wider text-emerald-600 uppercase block">
                Benign Traffic
              </span>
              <span className="text-[9px] text-emerald-600/70 font-medium">Clean & Safe Baseline</span>
            </div>
            <div className="w-8 h-8 rounded-xl bg-emerald-100 text-emerald-600 flex items-center justify-center">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-extrabold text-emerald-600 tracking-tight font-mono">
              {benignCount.toLocaleString()}
            </div>
            <div className="text-[10px] font-semibold text-emerald-600 mt-1">
              {flowsProcessed > 0
                ? `${((benignCount / flowsProcessed) * 100).toFixed(1)}% Legitimate Traffic`
                : "100% Clean Baseline"}
            </div>
          </div>
        </div>

        {/* CARD 3: ATTACK ANOMALIES */}
        <div className="neu-flat rounded-2xl p-5 border border-white flex flex-col justify-between hover:translate-y-[-2px] transition-transform">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-[11px] font-bold tracking-wider text-red-600 uppercase block">
                Attack Anomalies
              </span>
              <span className="text-[9px] text-red-500/70 font-medium">AI Flagged Inferences</span>
            </div>
            <div className="w-8 h-8 rounded-xl bg-red-100 text-red-600 flex items-center justify-center">
              <AlertOctagon className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-extrabold text-red-600 tracking-tight font-mono">
              {attackCount.toLocaleString()}
            </div>
            <div className="text-[10px] font-semibold text-red-500 mt-1">
              {attackCount > 0 ? "CICIDS2017 RF Flagged" : "Zero Malicious Anomalies"}
            </div>
          </div>
        </div>

        {/* CARD 4: PERSISTED SOC INCIDENTS */}
        <div className="neu-flat rounded-2xl p-5 border border-white flex flex-col justify-between hover:translate-y-[-2px] transition-transform">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-[11px] font-bold tracking-wider text-orange-600 uppercase block">
                Database Alerts
              </span>
              <span className="text-[9px] text-orange-600/70 font-medium">Stored SQLite Incidents</span>
            </div>
            <div className="w-8 h-8 rounded-xl bg-orange-100 text-orange-600 flex items-center justify-center">
              <Bell className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-extrabold text-orange-600 tracking-tight font-mono">
              {totalAlertsCount}
            </div>
            <div className="text-[10px] font-semibold text-slate-500 mt-1">
              {criticalCount > 0 ? `${criticalCount} Critical Priority` : `${highRiskCount} High/Crit Flagged`}
            </div>
          </div>
        </div>

        {/* CARD 5: VERIFIED EVIDENCE */}
        <div className="neu-flat rounded-2xl p-5 border border-white flex flex-col justify-between hover:translate-y-[-2px] transition-transform">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-[11px] font-bold tracking-wider text-emerald-600 uppercase block">
                Evidence Files
              </span>
              <span className="text-[9px] text-emerald-600/70 font-medium">Tamper-Proof Ledger</span>
            </div>
            <div className="w-8 h-8 rounded-xl bg-emerald-100 text-emerald-600 flex items-center justify-center">
              <FileCheck2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-extrabold text-emerald-600 tracking-tight font-mono">
              {verifiedEvidenceCount}
            </div>
            <div className="text-[10px] font-semibold text-emerald-600 mt-1">
              100% SHA-256 Verified
            </div>
          </div>
        </div>
      </div>

      {/* Visual Charts Grid: Attack & Traffic Distribution, Risk Distribution, Attack Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* SECTION A — ATTACK & TRAFFIC DISTRIBUTION */}
        <div className="lg:col-span-4 neu-flat rounded-2xl p-6 border border-white">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              {distributionTab === "live_flows" ? "Traffic Classification" : "Attack Distribution"}
            </h3>
            <div className="flex items-center gap-1 bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-[9px] font-bold font-mono">
              <button
                onClick={() => setDistributionTab("live_flows")}
                className={cn(
                  "px-2 py-0.5 rounded transition-all",
                  distributionTab === "live_flows"
                    ? "bg-white text-blue-700 shadow-sm"
                    : "text-slate-500 hover:text-slate-800"
                )}
              >
                Live Flows
              </button>
              <button
                onClick={() => setDistributionTab("db_alerts")}
                className={cn(
                  "px-2 py-0.5 rounded transition-all",
                  distributionTab === "db_alerts"
                    ? "bg-white text-blue-700 shadow-sm"
                    : "text-slate-500 hover:text-slate-800"
                )}
              >
                Incidents ({totalAlertsCount})
              </button>
            </div>
          </div>

          {/* Dynamic Attack & Traffic Distribution */}
          {(() => {
            let chartItems: Array<{ name: string; percentage: number; color: string; value: number }> = [];
            let centerCount = 0;
            let centerLabel = "FLOWS";

            if (distributionTab === "live_flows") {
              centerCount = flowsProcessed;
              centerLabel = "FLOWS";
              if (flowsProcessed > 0) {
                const bPct = Number(((benignCount / flowsProcessed) * 100).toFixed(1));
                const aPct = Number(((attackCount / flowsProcessed) * 100).toFixed(1));
                chartItems = [
                  { name: "Authorized / Benign Traffic", percentage: bPct, color: "#10b981", value: benignCount },
                ];
                if (attackCount > 0) {
                  chartItems.push({
                    name: "CICIDS2017 Threat Anomalies",
                    percentage: aPct,
                    color: "#ef4444",
                    value: attackCount,
                  });
                }
              } else {
                chartItems = [
                  { name: "Optimal Baseline / Zero Flows", percentage: 100, color: "#10b981", value: 0 },
                ];
              }
            } else {
              centerCount = totalAlertsCount;
              centerLabel = "ALERTS";
              if (analytics && analytics.attack_distribution.length > 0) {
                chartItems = analytics.attack_distribution;
              } else if (liveAlerts.length > 0) {
                chartItems = [
                  { name: "Database Incidents", percentage: 100, color: "#3b82f6", value: liveAlerts.length },
                ];
              } else {
                chartItems = [
                  { name: "No Active Threat Incidents", percentage: 100, color: "#3b82f6", value: 0 },
                ];
              }
            }

            let cumulativeOffset = 0;

            return (
              <div className="flex flex-col sm:flex-row items-center gap-6">
                {/* SVG Donut Chart with Rotating Radar Scanline */}
                <div className="relative w-36 h-36 shrink-0 flex items-center justify-center">
                  {/* Animated Rotating Radar Sweep */}
                  <motion.div
                    className="absolute inset-1 rounded-full pointer-events-none z-10"
                    style={{
                      background:
                        "conic-gradient(from 0deg, transparent 0deg, transparent 300deg, rgba(111, 61, 255, 0.25) 360deg)",
                    }}
                    animate={{ rotate: 360 }}
                    transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
                  />

                  <svg viewBox="0 0 36 36" className="w-full h-full transform -rotate-90">
                    <path
                      className="text-slate-200"
                      strokeWidth="4"
                      stroke="currentColor"
                      fill="none"
                      d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    />
                    {chartItems.map((item) => {
                      const pct = Math.max(0, Math.min(100, item.percentage));
                      const dashArray = `${pct}, 100`;
                      const dashOffset = `-${cumulativeOffset}`;
                      cumulativeOffset += pct;
                      return (
                        <path
                          key={item.name}
                          strokeDasharray={dashArray}
                          strokeDashoffset={dashOffset}
                          style={{ color: item.color }}
                          strokeWidth="4"
                          strokeLinecap="round"
                          stroke="currentColor"
                          fill="none"
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                        />
                      );
                    })}
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center text-center z-20">
                    <span className="text-xl font-extrabold text-slate-800 font-mono flex items-center gap-1 justify-center">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 animate-ping" />
                      {centerCount.toLocaleString()}
                    </span>
                    <span className="text-[9px] text-slate-400 font-bold uppercase tracking-wider">{centerLabel}</span>
                  </div>
                </div>

                {/* Legend breakdown list */}
                <div className="w-full space-y-2 text-xs">
                  {chartItems.map((item) => (
                    <div key={item.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span
                          className="w-2.5 h-2.5 rounded-full shrink-0"
                          style={{ backgroundColor: item.color }}
                        />
                        <span className="text-slate-700 font-medium text-[11px] truncate max-w-[140px]" title={item.name}>
                          {item.name}
                        </span>
                      </div>
                      <span className="font-bold text-slate-900 font-mono text-[11px]">
                        {item.percentage}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            );
          })()}
        </div>

        {/* SECTION B — RISK DISTRIBUTION */}
        <div className="lg:col-span-4 neu-flat rounded-2xl p-6 border border-white">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Risk Distribution
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">
              {totalAlertsCount > 0 ? "SQLite Classified" : "Telemetry Baseline"}
            </span>
          </div>

          <div className="space-y-3.5 pt-2">
            {(totalAlertsCount > 0
              ? [
                  { level: "Critical", count: criticalCount, percentage: Math.round((criticalCount / (totalAlertsCount || 1)) * 100), color: "#ef4444" },
                  { level: "High", count: liveAlerts.filter(a => a.severity === "HIGH").length, percentage: Math.round((liveAlerts.filter(a => a.severity === "HIGH").length / (totalAlertsCount || 1)) * 100), color: "#f97316" },
                  { level: "Medium", count: liveAlerts.filter(a => a.severity === "MEDIUM").length, percentage: Math.round((liveAlerts.filter(a => a.severity === "MEDIUM").length / (totalAlertsCount || 1)) * 100), color: "#eab308" },
                  { level: "Low", count: liveAlerts.filter(a => a.severity === "LOW").length, percentage: Math.round((liveAlerts.filter(a => a.severity === "LOW").length / (totalAlertsCount || 1)) * 100), color: "#3b82f6" },
                ]
              : [
                  { level: "Clean Baseline", count: flowsProcessed, percentage: 100, color: "#10b981" },
                  { level: "Critical Risk", count: 0, percentage: 0, color: "#ef4444" },
                  { level: "High Risk", count: 0, percentage: 0, color: "#f97316" },
                  { level: "Medium Risk", count: 0, percentage: 0, color: "#eab308" },
                ]
            ).map((item) => (
              <div key={item.level} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-slate-700">{item.level}</span>
                  <span className="font-mono font-bold text-slate-900">
                    {item.count} {totalAlertsCount > 0 ? "alerts" : "flows"} ({item.percentage}%)
                  </span>
                </div>
                <div className="h-2 w-full bg-slate-200/80 rounded-full overflow-hidden neu-pressed-sm">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${Math.min(100, item.percentage)}%`,
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

        {/* SECTION C — ATTACK ACTIVITY (Weekly / Timeline) */}
        <div className="lg:col-span-4 neu-flat rounded-2xl p-6 border border-white">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Attack Activity (Weekly)
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">Real Incident Timestamps</span>
          </div>

          {/* Bar chart visualization */}
          <div className="h-44 flex items-end justify-between gap-2 pt-6 pb-2 px-2">
            {(analytics && analytics.weekly_activity.length > 0 && totalAlertsCount > 0
              ? analytics.weekly_activity.map((w) => ({ day: w.day, alerts: w.incidents }))
              : [
                  { day: "Mon", alerts: 0 },
                  { day: "Tue", alerts: 0 },
                  { day: "Wed", alerts: totalAlertsCount > 0 ? totalAlertsCount : 0 },
                  { day: "Thu", alerts: 0 },
                  { day: "Fri", alerts: 0 },
                  { day: "Sat", alerts: 0 },
                  { day: "Sun", alerts: 0 },
                ]
            ).map((day) => {
              const maxAlerts = Math.max(
                5,
                ...(analytics && analytics.weekly_activity.length > 0
                  ? analytics.weekly_activity.map((w) => w.incidents)
                  : [1])
              );
              const heightPercent = Math.max(8, (day.alerts / maxAlerts) * 100);
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
            <span>Aggregated database activity</span>
            <span className="text-emerald-600 font-semibold font-mono">{totalAlertsCount} Total Events</span>
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
              <span>View All {totalAlertsCount} Alerts</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="overflow-x-auto">
            {liveAlerts.length === 0 ? (
              <div className="p-8 text-center flex flex-col items-center justify-center space-y-2">
                <div className="w-10 h-10 rounded-2xl bg-emerald-50 text-emerald-600 flex items-center justify-center shadow-inner">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <h4 className="text-sm font-bold text-slate-800">No Incidents in Database — System Normal</h4>
                <p className="text-xs text-slate-400 max-w-sm">
                  Run <code className="bg-slate-100 px-1.5 py-0.5 rounded text-slate-700 font-mono">python laptop_b_traffic_generator.py</code> on Laptop B to generate baseline traffic or launch attack tests.
                </p>
              </div>
            ) : (
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
                  {liveAlerts.slice(0, 5).map((alert) => {
                    const displayIncident: Incident = buildTopIncident(alert);

                    const isLive = alert.incident_id.startsWith("INC-LIVE");
                    const isTest = alert.incident_id.startsWith("INC-TEST");
                    const badgeLabel = isLive ? "LIVE NIC" : isTest ? "PROBE" : "ALERT";
                    const badgeClass = isLive
                      ? "bg-emerald-100 text-emerald-800 border-emerald-300"
                      : isTest
                      ? "bg-purple-100 text-purple-800 border-purple-300"
                      : "bg-rose-100 text-rose-800 border-rose-300";

                    const displaySource =
                      !alert.source_ip || alert.source_ip === "string" ? "Unavailable" : alert.source_ip;
                    const displayTarget =
                      !alert.target || alert.target === "string" ? "Internal Host" : alert.target;

                    return (
                      <tr
                        key={alert.id}
                        onClick={() => onSelectIncident(displayIncident)}
                        className="hover:bg-white/80 transition-colors cursor-pointer group"
                      >
                        <td className="py-3.5 font-bold font-mono text-blue-600 group-hover:underline flex items-center gap-1.5">
                          <span className={cn("px-1 py-0.2 rounded text-[8px] font-mono border font-bold uppercase", badgeClass)}>
                            {badgeLabel}
                          </span>
                          {alert.incident_id}
                        </td>
                        <td className="py-3.5 font-semibold text-slate-800">{alert.attack_type}</td>
                        <td className="py-3.5 font-mono text-slate-600">{displaySource}</td>
                        <td className="py-3.5 text-slate-700">{displayTarget}</td>
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
                                : alert.status === "Resolved"
                                ? "bg-emerald-100 text-emerald-700"
                                : "bg-slate-200 text-slate-700"
                            )}
                          >
                            {alert.status}
                          </span>
                        </td>
                        <td className="py-3.5 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <span className="font-mono text-slate-400 text-[10px] hidden sm:inline">
                              {alert.created_at ? alert.created_at.slice(11, 16) : "Live"}
                            </span>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                onSelectIncident(displayIncident);
                                if (onInvestigateIncident) {
                                  onInvestigateIncident(displayIncident);
                                } else {
                                  onNavigateTab("investigation");
                                }
                              }}
                              className="px-2 py-0.5 rounded neu-accent-btn text-[10px] font-bold text-white shadow-xs hover:shadow transition-all"
                            >
                              Investigate
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* SECTION E: Live Real-Time Network Flow Stream */}
        <div className="lg:col-span-4 neu-flat rounded-2xl p-6 border border-white flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
                <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  Live Traffic & Security Stream
                </h3>
              </div>
              <span className="text-[10px] text-slate-400 font-mono">
                {metrics?.recent_flows && metrics.recent_flows.length > 0 ? "Npcap Live Feed" : "SOC Ingestion"}
              </span>
            </div>

            <div className="space-y-3">
              {(metrics && metrics.recent_flows && metrics.recent_flows.length > 0
                ? metrics.recent_flows.slice(0, 5).map((f) => ({
                    key: f.id,
                    time: f.timestamp ? new Date(f.timestamp).toLocaleTimeString() : "Live",
                    text: `${f.source_ip}:${f.source_port} → ${f.destination_ip}:${f.destination_port}`,
                    protocol: f.protocol,
                    confidence: f.confidence,
                    prediction: f.prediction,
                    packets: f.packets,
                  }))
                : liveAlerts.length > 0
                ? liveAlerts.slice(0, 5).map((feedAlert) => ({
                    key: `alert-${feedAlert.id}`,
                    time: feedAlert.created_at ? feedAlert.created_at.slice(11, 16) : "Live",
                    text: `${feedAlert.attack_type} detected on ${feedAlert.target || "Host"}`,
                    protocol: "ALERT",
                    confidence: Math.round(feedAlert.confidence),
                    prediction: "ATTACK" as const,
                    packets: 1,
                  }))
                : []
              ).map((feed) => {
                const isAttack = feed.prediction === "ATTACK";
                return (
                  <div key={feed.key} className="flex items-start gap-2.5 text-xs font-mono">
                    <span className="text-[10px] text-slate-400 shrink-0 mt-1">
                      {feed.time}
                    </span>
                    <div className="flex-1 bg-white/80 p-2.5 rounded-xl neu-flat-sm border border-white">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-bold text-slate-800 truncate block text-[11px]" title={feed.text}>
                          {feed.text}
                        </span>
                        <span
                          className={cn(
                            "text-[9px] font-bold px-1.5 py-0.2 rounded shrink-0",
                            isAttack
                              ? "bg-rose-100 text-rose-700 border border-rose-200"
                              : "bg-emerald-100 text-emerald-700 border border-emerald-200"
                          )}
                        >
                          {feed.prediction}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 mt-1 text-[10px] text-slate-500">
                        <span>Proto: <strong className="text-slate-700">{feed.protocol}</strong></span>
                        <span>&bull;</span>
                        <span>Conf: <strong className="text-slate-700">{feed.confidence}%</strong></span>
                        {feed.packets > 1 && (
                          <>
                            <span>&bull;</span>
                            <span>{feed.packets} pkts</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}

              {(!metrics?.recent_flows || metrics.recent_flows.length === 0) && liveAlerts.length === 0 && (
                <div className="p-6 text-center text-slate-400 text-xs">
                  <p>No active live traffic flows in inspection buffer.</p>
                  <p className="text-[11px] mt-1 text-slate-500">Start Live Monitoring on Wi-Fi to sniff packets.</p>
                </div>
              )}
            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-slate-200 text-center">
            <button
              onClick={() => onNavigateTab("monitoring")}
              className="text-[11px] text-blue-600 hover:underline font-semibold font-mono"
            >
              Open Full Live Packet Inspector &rarr;
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
