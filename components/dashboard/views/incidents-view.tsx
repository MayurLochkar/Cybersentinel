"use client";
import React, { useState, useMemo, useEffect } from "react";
import {
  AlertTriangle,
  Search,
  Filter,
  RefreshCw,
  ExternalLink,
  ChevronRight,
  ShieldAlert,
  BrainCircuit,
  FileText,
  CheckCircle2,
  Clock,
  ArrowRight,
  Activity,
  Layers,
  Copy,
  Check,
  Ban,
  ShieldCheck,
  Eye,
} from "lucide-react";
import { CYBER_DATA, Incident } from "@/data/cyberData";
import { cn } from "@/lib/utils";
import { fetchAlerts, updateAlertStatus, ApiAlert } from "@/lib/api";

export function buildIncidentFromApiAlert(alert: ApiAlert): Incident {
  const portMatch = alert.target?.match(/port\s*(\d+)/i) || alert.reason?.match(/port\s*(\d+)/i);
  const parsedPort = portMatch ? parseInt(portMatch[1], 10) : 8000;
  const parsedProtocol = alert.attack_type?.toLowerCase().includes("udp") ? "UDP" : "TCP";

  return {
    id: alert.incident_id,
    attackType: alert.attack_type,
    sourceIp: alert.source_ip,
    destinationIp: alert.destination_ip || "192.168.29.93",
    target: alert.target || `Port ${parsedPort} (${parsedProtocol})`,
    severity: alert.severity,
    confidence: alert.confidence,
    status: alert.status as any,
    time: alert.created_at ? alert.created_at.slice(11, 16) : "Live",
    protocol: parsedProtocol,
    port: parsedPort,
    detectionTime: alert.created_at || new Date().toISOString(),
    timeline: [
      {
        time: alert.created_at ? alert.created_at.slice(11, 19) : "Detection",
        event: `Live attack ${alert.incident_id} classified as ${alert.attack_type}`,
        detail: alert.reason || `Real-time packet anomaly detected from ${alert.source_ip}.`,
      },
      {
        time: "Forensics",
        event: "Network telemetry correlated",
        detail: `High-rate connection burst identified targeting ${alert.target || `Port ${parsedPort}`}.`,
      },
      {
        time: "SOC Triage",
        event: "Automated alert record published",
        detail: `Logged to SQLite & Forensic Evidence Ledger with SHA-256 seal.`,
      },
    ],
    aiExplanation: {
      title: `Why was ${alert.attack_type} flagged?`,
      description: alert.reason || `Inbound traffic from ${alert.source_ip} exhibited anomalous connection velocity exceeding baseline thresholds.`,
      indicators: [
        `Source IP: ${alert.source_ip}`,
        `Target: ${alert.destination_ip || "192.168.29.93"}:${parsedPort}`,
        `Attack Classification: ${alert.attack_type}`,
        `Model Confidence: ${alert.confidence}%`,
      ],
    },
    mitre: {
      tactic: alert.attack_type?.toLowerCase().includes("scan")
        ? "Discovery"
        : alert.attack_type?.toLowerCase().includes("brute")
        ? "Credential Access"
        : "Impact",
      technique: alert.attack_type?.toLowerCase().includes("scan")
        ? "Network Service Discovery"
        : alert.attack_type?.toLowerCase().includes("brute")
        ? "Brute Force: Network Protocols"
        : "Direct Network Denial of Service",
      techniqueId: alert.attack_type?.toLowerCase().includes("scan")
        ? "T1046"
        : alert.attack_type?.toLowerCase().includes("brute")
        ? "T1110.001"
        : "T1498.001",
      description: alert.reason || "Adversaries execute anomalous traffic bursts targeting services to degrade availability or probe infrastructure.",
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
        alert.reason || `Autonomous detection of ${alert.attack_type}.`,
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
}

export function IncidentsView({
  onSelectIncident,
  onInvestigateIncident,
  onViewReport,
}: {
  onSelectIncident: (incident: Incident) => void;
  onInvestigateIncident: (incident: Incident) => void;
  onViewReport: (incidentId: string) => void;
}) {
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [liveAlerts, setLiveAlerts] = useState<ApiAlert[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [toastMsg, setToastMsg] = useState("");
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [isLiveConnected, setIsLiveConnected] = useState<boolean | null>(null);

  const loadData = async (silent = false) => {
    if (!silent) setIsLoading(true);
    try {
      const data = await fetchAlerts();
      setLiveAlerts(data);
      setIsLiveConnected(true);
    } catch {
      setIsLiveConnected(false);
    } finally {
      if (!silent) setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(() => loadData(true), 4000);
    const handleGlobalRefresh = () => loadData(true);
    if (typeof window !== "undefined") {
      window.addEventListener("cybersentinel-refresh-all", handleGlobalRefresh);
    }
    return () => {
      clearInterval(interval);
      if (typeof window !== "undefined") {
        window.removeEventListener("cybersentinel-refresh-all", handleGlobalRefresh);
      }
    };
  }, []);

  // Map live database incidents - reflects 0 items when cleared
  const incidentsList: Incident[] = useMemo(() => {
    if (isLiveConnected === false && liveAlerts.length === 0) {
      return CYBER_DATA.recentIncidents;
    }
    return liveAlerts.map(buildIncidentFromApiAlert);
  }, [liveAlerts, isLiveConnected]);

  // Filtered incidents
  const filteredIncidents = useMemo(() => {
    return incidentsList.filter((inc) => {
      const q = searchTerm.toLowerCase();
      const matchesSearch =
        !searchTerm ||
        inc.id.toLowerCase().includes(q) ||
        inc.sourceIp.includes(q) ||
        inc.attackType.toLowerCase().includes(q) ||
        (inc.destinationIp && inc.destinationIp.includes(q));

      const matchesSeverity =
        severityFilter === "ALL" || inc.severity === severityFilter;

      const matchesStatus =
        statusFilter === "ALL" || inc.status === statusFilter;

      return matchesSearch && matchesSeverity && matchesStatus;
    });
  }, [incidentsList, searchTerm, severityFilter, statusFilter]);

  // Statistics
  const totalCount = incidentsList.length;
  const criticalCount = incidentsList.filter((i) => i.severity === "CRITICAL").length;
  const investigatingCount = incidentsList.filter((i) => i.status === "Investigating").length;
  const resolvedCount = incidentsList.filter((i) => i.status === "Resolved").length;

  const handleStatusChange = async (inc: Incident, newStatus: "Open" | "Investigating" | "Resolved") => {
    setUpdatingId(inc.id);
    try {
      await updateAlertStatus(inc.id, newStatus);
      setToastMsg(`Status for #${inc.id.replace("INC-", "")} updated to '${newStatus}'.`);
      await loadData(true);
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("cybersentinel-refresh-all"));
      }
    } catch (err: any) {
      setToastMsg(`Failed to update status: ${err.message || err}`);
    } finally {
      setUpdatingId(null);
      setTimeout(() => setToastMsg(""), 3500);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Toast notification */}
      {toastMsg && (
        <div className="p-3 bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs rounded-xl flex items-center gap-2 font-medium shadow-xs">
          <Check className="w-4 h-4 text-emerald-600" />
          <span>{toastMsg}</span>
        </div>
      )}

      {/* Hero Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-rose-500 to-red-600 text-white flex items-center justify-center shadow-md shadow-rose-500/20">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-black text-slate-900 tracking-tight">
                  Incidents Command Center
                </h1>
                <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-200 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                  Live Sync
                </span>
              </div>
              <p className="text-xs text-slate-500 font-medium mt-0.5">
                Real-time triaged network threat dossiers, ML classifications & containment playbooks
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={() => loadData()}
          disabled={isLoading}
          className="px-3.5 py-2 rounded-xl neu-flat hover:bg-white text-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-all active:scale-95 disabled:opacity-50"
        >
          <RefreshCw className={cn("w-3.5 h-3.5 text-blue-600", isLoading && "animate-spin")} />
          <span>{isLoading ? "Syncing..." : "Refresh Incidents"}</span>
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="neu-flat rounded-2xl p-4 border border-white bg-white/70">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
              Total Incidents
            </span>
            <Activity className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-2xl font-black text-slate-900 mt-2 font-mono">{totalCount}</div>
          <p className="text-[10px] text-slate-400 font-medium mt-0.5">Tracked in SQLite Ledger</p>
        </div>

        <div className="neu-flat rounded-2xl p-4 border border-rose-100 bg-gradient-to-br from-rose-50/50 via-white to-white">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-rose-700 uppercase tracking-wider">
              Critical Threats
            </span>
            <div className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping" />
          </div>
          <div className="text-2xl font-black text-rose-600 mt-2 font-mono">{criticalCount}</div>
          <p className="text-[10px] text-rose-500 font-medium mt-0.5">Immediate Triage Priority</p>
        </div>

        <div className="neu-flat rounded-2xl p-4 border border-blue-100 bg-gradient-to-br from-blue-50/50 via-white to-white">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-blue-700 uppercase tracking-wider">
              Under Investigation
            </span>
            <BrainCircuit className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-2xl font-black text-blue-700 mt-2 font-mono">{investigatingCount}</div>
          <p className="text-[10px] text-blue-500 font-medium mt-0.5">Active SOC Analysts / AI</p>
        </div>

        <div className="neu-flat rounded-2xl p-4 border border-emerald-100 bg-gradient-to-br from-emerald-50/50 via-white to-white">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-emerald-700 uppercase tracking-wider">
              Resolved & Remediated
            </span>
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-2xl font-black text-emerald-700 mt-2 font-mono">{resolvedCount}</div>
          <p className="text-[10px] text-emerald-600 font-medium mt-0.5">Threat Contained</p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="neu-flat rounded-2xl p-4 border border-white bg-white/70 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Search */}
          <div className="relative flex-1 min-w-[240px]">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by IP, Incident ID, or Attack Type..."
              className="w-full pl-9 pr-3.5 py-2 text-xs rounded-xl bg-slate-50 border border-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all font-medium"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-xl">
            {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={cn(
                  "px-2.5 py-1 text-[10px] font-bold rounded-lg transition-all",
                  severityFilter === sev
                    ? "bg-white text-slate-900 shadow-xs"
                    : "text-slate-500 hover:text-slate-900"
                )}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-xl">
            {["ALL", "Open", "Investigating", "Resolved"].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={cn(
                  "px-2.5 py-1 text-[10px] font-bold rounded-lg transition-all",
                  statusFilter === st
                    ? "bg-white text-slate-900 shadow-xs"
                    : "text-slate-500 hover:text-slate-900"
                )}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Incidents Feed / Table */}
      <div className="neu-flat rounded-2xl border border-white bg-white/80 overflow-hidden shadow-xs">
        <div className="p-4 border-b border-slate-100 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Active Incident Queue ({filteredIncidents.length})
            </span>
            <span className="text-[10px] text-slate-400 font-mono">
              Showing matching threat records
            </span>
          </div>
        </div>

        {filteredIncidents.length === 0 ? (
          <div className="p-12 text-center">
            <ShieldCheck className="w-10 h-10 text-emerald-500 mx-auto mb-2 opacity-80" />
            <h3 className="text-sm font-bold text-slate-800">No matching incidents found</h3>
            <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
              No incident records match your active filters. Try adjusting your search query or reset filters.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {filteredIncidents.map((inc) => {
              const isLive = inc.id.includes("LIVE") || inc.time === "Live" || inc.time === "Just now";
              const isUpdatingThis = updatingId === inc.id;

              return (
                <div
                  key={inc.id}
                  className="p-4 hover:bg-slate-50/70 transition-all flex flex-col lg:flex-row lg:items-center justify-between gap-4"
                >
                  {/* Left: Incident ID, Severity, Attack Type, & Network flow */}
                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono font-bold text-blue-700 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded-md flex items-center gap-1">
                        #{inc.id.replace("INC-", "")}
                        <button
                          onClick={() => copyToClipboard(inc.id, inc.id)}
                          title="Copy ID"
                          className="hover:text-blue-900 cursor-pointer"
                        >
                          {copiedId === inc.id ? (
                            <Check className="w-3 h-3 text-emerald-600" />
                          ) : (
                            <Copy className="w-3 h-3 text-slate-400" />
                          )}
                        </button>
                      </span>

                      {isLive && (
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-200 animate-pulse">
                          LIVE WIRE
                        </span>
                      )}

                      <span
                        className={cn(
                          "text-[10px] font-extrabold font-mono px-2 py-0.5 rounded-full uppercase",
                          inc.severity === "CRITICAL"
                            ? "bg-red-100 text-red-700 border border-red-200"
                            : inc.severity === "HIGH"
                            ? "bg-orange-100 text-orange-700 border border-orange-200"
                            : "bg-amber-100 text-amber-700 border border-amber-200"
                        )}
                      >
                        {inc.severity}
                      </span>

                      <span
                        className={cn(
                          "text-[10px] font-semibold px-2 py-0.5 rounded-full",
                          inc.status === "Resolved"
                            ? "bg-emerald-100 text-emerald-800"
                            : inc.status === "Investigating"
                            ? "bg-blue-100 text-blue-700"
                            : "bg-slate-200 text-slate-700"
                        )}
                      >
                        {inc.status}
                      </span>

                      <span className="text-[11px] text-slate-400 font-mono">
                        {inc.time}
                      </span>
                    </div>

                    <h3 className="text-sm font-bold text-slate-900 tracking-tight">
                      {inc.attackType} Attack
                    </h3>

                    <div className="flex items-center gap-3 text-xs text-slate-600 flex-wrap font-mono">
                      <span>
                        Src: <strong className="text-slate-800">{inc.sourceIp}</strong>
                      </span>
                      <span>&rarr;</span>
                      <span>
                        Dst: <strong className="text-slate-800">{inc.destinationIp || "192.168.29.93"}:{inc.port || 8000}</strong>
                      </span>
                      <span>&bull;</span>
                      <span>Proto: <strong>{inc.protocol}</strong></span>
                      <span>&bull;</span>
                      <span className="text-cyan-700 font-semibold">
                        ML Conf: {inc.confidence}%
                      </span>
                    </div>
                  </div>

                  {/* Right: Status Changer & Action Buttons */}
                  <div className="flex items-center gap-2 flex-wrap shrink-0">
                    {/* Fast Status Toggles */}
                    <div className="flex items-center bg-slate-100 p-0.5 rounded-xl border border-slate-200/60">
                      <button
                        disabled={isUpdatingThis || inc.status === "Open"}
                        onClick={() => handleStatusChange(inc, "Open")}
                        className={cn(
                          "px-2 py-1 text-[10px] font-bold rounded-lg transition-all",
                          inc.status === "Open"
                            ? "bg-white text-slate-800 shadow-xs"
                            : "text-slate-400 hover:text-slate-700"
                        )}
                      >
                        Open
                      </button>
                      <button
                        disabled={isUpdatingThis || inc.status === "Investigating"}
                        onClick={() => handleStatusChange(inc, "Investigating")}
                        className={cn(
                          "px-2 py-1 text-[10px] font-bold rounded-lg transition-all",
                          inc.status === "Investigating"
                            ? "bg-blue-600 text-white shadow-xs"
                            : "text-slate-400 hover:text-slate-700"
                        )}
                      >
                        Investigate
                      </button>
                      <button
                        disabled={isUpdatingThis || inc.status === "Resolved"}
                        onClick={() => handleStatusChange(inc, "Resolved")}
                        className={cn(
                          "px-2 py-1 text-[10px] font-bold rounded-lg transition-all",
                          inc.status === "Resolved"
                            ? "bg-emerald-600 text-white shadow-xs"
                            : "text-slate-400 hover:text-slate-700"
                        )}
                      >
                        Resolve
                      </button>
                    </div>

                    {/* View Dossier Button */}
                    <button
                      onClick={() => onSelectIncident(inc)}
                      className="px-3.5 py-1.5 rounded-xl neu-flat hover:bg-white text-slate-800 font-bold text-xs flex items-center gap-1.5 transition-all active:scale-95 cursor-pointer shadow-2xs"
                    >
                      <Eye className="w-3.5 h-3.5 text-blue-600" />
                      <span>View Dossier</span>
                    </button>

                    {/* Start AI Investigation */}
                    <button
                      onClick={() => onInvestigateIncident(inc)}
                      className="px-3.5 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs flex items-center gap-1.5 transition-all active:scale-95 shadow-xs cursor-pointer"
                    >
                      <BrainCircuit className="w-3.5 h-3.5" />
                      <span>AI Investigate</span>
                    </button>

                    {/* Forensic Report */}
                    <button
                      onClick={() => onViewReport(inc.id)}
                      className="p-1.5 rounded-xl neu-flat hover:bg-white text-slate-500 hover:text-slate-800 transition-all active:scale-95"
                      title="Generate Forensic Report"
                    >
                      <FileText className="w-4 h-4 text-slate-600" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
