"use client";
import React, { useState, useMemo, useEffect } from "react";
import {
  Search,
  Filter,
  ArrowUpDown,
  ExternalLink,
  ChevronRight,
  ChevronDown,
  ShieldAlert,
  ArrowRight,
  Bell,
  Sparkles,
  Check,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  Ban,
  Sliders,
  Terminal,
  Copy,
  Activity,
  Layers,
} from "lucide-react";
import { CYBER_DATA, Alert, Incident } from "@/data/cyberData";
import { cn } from "@/lib/utils";
import { fetchAlerts, updateAlertStatus, ApiAlert } from "@/lib/api";

export function AlertsView({
  onSelectAlert,
}: {
  onSelectAlert: (alert: Alert) => void;
}) {
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [timeRange, setTimeRange] = useState("ALL");

  const [liveBackendAlerts, setLiveBackendAlerts] = useState<ApiAlert[]>([]);
  const [isLiveConnected, setIsLiveConnected] = useState<boolean | null>(null);

  // Active selected alert for top 3-pillar triage banner
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);
  const [blockedIps, setBlockedIps] = useState<Record<string, boolean>>({});
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [toastMsg, setToastMsg] = useState("");
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);

  const loadAlerts = async () => {
    try {
      const data = await fetchAlerts();
      setLiveBackendAlerts(data);
      setIsLiveConnected(true);
    } catch {
      setIsLiveConnected(false);
    }
  };

  useEffect(() => {
    loadAlerts();
    const interval = setInterval(loadAlerts, 6000);
    return () => clearInterval(interval);
  }, []);

  // Map live database alerts directly from backend SQLite
  const combinedAlerts: Alert[] = useMemo(() => {
    if (isLiveConnected === false && liveBackendAlerts.length === 0) {
      return CYBER_DATA.alertsList;
    }

    return liveBackendAlerts.map((item) => {
      let port = 80;
      let protocol = "TCP";
      if (item.target) {
        const portMatch = item.target.match(/Port\s+(\d+)/i);
        if (portMatch) port = parseInt(portMatch[1], 10);
        const protoMatch = item.target.match(/\((UDP|TCP|ICMP)\)/i);
        if (protoMatch) protocol = protoMatch[1].toUpperCase();
      }

      return {
        id: `ALT-${item.id.toString().padStart(4, "0")}`,
        timestamp: item.created_at?.slice(11, 16) || "Just now",
        sourceIp: !item.source_ip || item.source_ip === "string" ? "192.168.1.185" : item.source_ip,
        destinationIp: !item.destination_ip || item.destination_ip === "string" ? "192.168.1.1" : item.destination_ip,
        attackType: (item.attack_type as any) || "Network Anomaly",
        confidence: item.confidence,
        severity: item.severity,
        status: item.status as any,
        incidentId: item.incident_id,
        port,
        protocol,
        reason: item.reason,
      };
    });
  }, [liveBackendAlerts, isLiveConnected]);

  const filteredAlerts = useMemo(() => {
    return combinedAlerts.filter((alert) => {
      const matchesSearch =
        alert.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        alert.sourceIp.includes(searchTerm) ||
        alert.destinationIp.includes(searchTerm) ||
        alert.attackType.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (alert.incidentId && alert.incidentId.toLowerCase().includes(searchTerm.toLowerCase()));

      const matchesSeverity =
        severityFilter === "ALL" || alert.severity === severityFilter;

      const matchesType = typeFilter === "ALL" || alert.attackType === typeFilter;

      const matchesStatus = statusFilter === "ALL" || alert.status === statusFilter;

      return matchesSearch && matchesSeverity && matchesType && matchesStatus;
    });
  }, [combinedAlerts, searchTerm, severityFilter, typeFilter, statusFilter]);

  // Active alert displayed in top triage cards
  const activeAlert: Alert | undefined = useMemo(() => {
    if (selectedAlertId) {
      const found = combinedAlerts.find((a) => a.id === selectedAlertId);
      if (found) return found;
    }
    return filteredAlerts[0] || combinedAlerts[0];
  }, [selectedAlertId, combinedAlerts, filteredAlerts]);

  const handleStatusChange = async (targetAlert: Alert, newStatus: "Open" | "Investigating" | "Resolved") => {
    const incId = targetAlert.incidentId || targetAlert.id;
    setIsUpdatingStatus(true);
    try {
      await updateAlertStatus(incId, newStatus);
      setToastMsg(`Status for ${incId} updated to '${newStatus}' in SQLite.`);
      await loadAlerts();
    } catch (err: any) {
      setToastMsg(`Failed to update status: ${err.message || err}`);
    } finally {
      setIsUpdatingStatus(false);
      setTimeout(() => setToastMsg(""), 3500);
    }
  };

  const handleToggleBlock = (ip: string) => {
    const isNowBlocked = !blockedIps[ip];
    setBlockedIps((prev) => ({ ...prev, [ip]: isNowBlocked }));
    setToastMsg(
      isNowBlocked
        ? `Firewall rule applied: Inbound traffic from ${ip} BLOCKED.`
        : `Firewall block removed for ${ip}.`
    );
    setTimeout(() => setToastMsg(""), 3500);
  };

  const copyFirewallCommand = (ip: string) => {
    const cmd = `netsh advfirewall firewall add rule name="Block_${ip}" dir=in action=block remoteip=${ip}`;
    navigator.clipboard?.writeText(cmd);
    setCopiedCmd(ip);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Header Explainer Banner */}
      <div className="neu-flat rounded-2xl p-6 border border-white bg-gradient-to-r from-red-50/50 via-white to-purple-50/50 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-2xl bg-rose-100 text-rose-600 flex items-center justify-center shadow-inner shrink-0">
            <Bell className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-full uppercase bg-rose-100 text-rose-800 border border-rose-200">
                Live SOC Triage Center
              </span>
              <span className="text-[11px] font-mono text-slate-500">
                SQLite Real-Time Storage
              </span>
            </div>
            <h1 className="text-xl font-extrabold text-slate-900 tracking-tight mt-1">
              Security Alerts & Forensic Playbook
            </h1>
            <p className="text-xs text-slate-500 mt-0.5 max-w-2xl">
              All ML-classified network anomalies are persisted here. Select any threat event to review its verified summary, root cause, and immediate firewall remediation.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 self-end md:self-center">
          <div className="text-right">
            <span className="text-[10px] font-mono text-slate-400 block uppercase">Total Threats</span>
            <span className="text-2xl font-black font-mono text-slate-900">
              {combinedAlerts.length}
            </span>
          </div>
        </div>
      </div>

      {toastMsg && (
        <div className="p-3 bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs rounded-xl flex items-center gap-2 font-medium shadow-sm">
          <Check className="w-4 h-4 text-emerald-600 shrink-0" />
          <span>{toastMsg}</span>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TOP 3-PILLAR TRIAGE FRAMEWORK: SUMMARY, REASON, SOLUTION (Requirement)     */}
      {/* ========================================================================= */}
      {activeAlert && (
        <div className="neu-flat rounded-2xl p-6 border-2 border-blue-500/20 bg-gradient-to-b from-slate-50/70 via-white to-white space-y-4 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200/80 pb-3">
            <div className="flex items-center gap-2.5">
              <span className="text-xs font-mono font-bold text-blue-600 bg-blue-100 px-2.5 py-0.5 rounded-md">
                ACTIVE FOCUS: {activeAlert.id}
              </span>
              <span className="text-xs font-mono text-slate-500 font-semibold">
                INCIDENT ID: {activeAlert.incidentId || activeAlert.id}
              </span>
              <span
                className={cn(
                  "text-[10px] font-extrabold font-mono px-2 py-0.5 rounded-full uppercase",
                  activeAlert.severity === "CRITICAL"
                    ? "bg-red-100 text-red-700 border border-red-200"
                    : activeAlert.severity === "HIGH"
                    ? "bg-orange-100 text-orange-700 border border-orange-200"
                    : "bg-amber-100 text-amber-700 border border-amber-200"
                )}
              >
                {activeAlert.severity} PRIORITY
              </span>
            </div>

            <button
              onClick={() => onSelectAlert(activeAlert)}
              className="px-3.5 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold flex items-center gap-1.5 shadow transition-all active:scale-95"
            >
              <span>Drill Into AI Investigation</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* PILLAR 1: SUMMARY (क्या हुआ) */}
            <div className="neu-flat rounded-xl p-4 border border-white bg-white/90 space-y-3">
              <div className="flex items-center justify-between border-b border-blue-100 pb-2">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-md bg-blue-100 text-blue-700 font-black text-xs flex items-center justify-center">
                    01
                  </span>
                  <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">
                    Threat Summary (क्या हुआ)
                  </h3>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-50 text-blue-700 font-bold border border-blue-200/50">
                  {activeAlert.attackType}
                </span>
              </div>

              <p className="text-xs text-slate-700 leading-relaxed font-medium">
                Autonomous detection triggered on anomalous network flow from host{" "}
                <span className="font-mono font-bold text-slate-900 bg-slate-100 px-1 py-0.5 rounded">
                  {activeAlert.sourceIp}
                </span>{" "}
                targeting{" "}
                <span className="font-mono font-bold text-slate-900 bg-slate-100 px-1 py-0.5 rounded">
                  {activeAlert.destinationIp}:{activeAlert.port || 80}
                </span>{" "}
                via protocol <span className="font-bold">{activeAlert.protocol || "TCP"}</span>.
              </p>

              <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200/60 text-[11px] font-mono space-y-1">
                <div className="flex justify-between">
                  <span className="text-slate-400">ML Confidence:</span>
                  <span className="font-bold text-cyan-600">{activeAlert.confidence}%</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Target Asset:</span>
                  <span className="font-bold text-slate-700">Port {activeAlert.port || 80} ({activeAlert.protocol || "TCP"})</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Lifecycle Status:</span>
                  <span className="font-bold text-slate-800">{activeAlert.status}</span>
                </div>
              </div>
            </div>

            {/* PILLAR 2: REASON (क्यों & कैसे आया) */}
            <div className="neu-flat rounded-xl p-4 border border-white bg-white/90 space-y-3">
              <div className="flex items-center justify-between border-b border-amber-100 pb-2">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-md bg-amber-100 text-amber-800 font-black text-xs flex items-center justify-center">
                    02
                  </span>
                  <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">
                    Detection Reason (क्यों & कैसे आया)
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-amber-700 font-bold bg-amber-50 px-2 py-0.5 rounded border border-amber-200/50">
                  RF-70 Model
                </span>
              </div>

              {activeAlert.reason ? (
                <div className="p-2.5 bg-amber-50/80 rounded-lg border border-amber-200 text-xs text-amber-900 leading-relaxed font-mono">
                  {activeAlert.reason}
                </div>
              ) : (
                <p className="text-xs text-slate-600 leading-relaxed">
                  Flow telemetry exceeded multi-dimensional standard deviation bounds against benign baseline models.
                </p>
              )}

              <div className="space-y-1.5 text-[11px]">
                <div className="flex items-center gap-2 p-1.5 rounded bg-slate-50 border border-slate-200/60">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                  <span className="text-slate-700 font-medium">High packet burst frequency divergence</span>
                </div>
                <div className="flex items-center gap-2 p-1.5 rounded bg-slate-50 border border-slate-200/60">
                  <Activity className="w-3.5 h-3.5 text-blue-600 shrink-0" />
                  <span className="text-slate-700 font-medium">Asymmetric forward/backward packet ratio</span>
                </div>
              </div>
            </div>

            {/* PILLAR 3: SOLUTION (Solution क्या है) */}
            <div className="neu-flat rounded-xl p-4 border border-white bg-white/90 space-y-3">
              <div className="flex items-center justify-between border-b border-emerald-100 pb-2">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-md bg-emerald-100 text-emerald-800 font-black text-xs flex items-center justify-center">
                    03
                  </span>
                  <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">
                    Actionable Solution (Solution क्या है)
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-emerald-700 font-bold bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200/50">
                  Playbook
                </span>
              </div>

              <div className="space-y-2 text-xs">
                {/* Action 1: 1-Click IP Block */}
                <div className="p-2 bg-slate-50 rounded-lg border border-slate-200 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-800 flex items-center gap-1.5 text-[11px]">
                      <Ban className="w-3.5 h-3.5 text-rose-600" />
                      1. Inbound Firewall Isolation
                    </span>
                    <button
                      onClick={() => handleToggleBlock(activeAlert.sourceIp)}
                      className={cn(
                        "text-[10px] font-bold px-2 py-1 rounded transition-all active:scale-95",
                        blockedIps[activeAlert.sourceIp]
                          ? "bg-emerald-600 text-white"
                          : "bg-rose-600 hover:bg-rose-700 text-white shadow-sm"
                      )}
                    >
                      {blockedIps[activeAlert.sourceIp] ? "Rule Active (Blocked)" : "Apply IP Block"}
                    </button>
                  </div>

                  <div className="flex items-center justify-between bg-slate-900 text-emerald-400 p-1 rounded font-mono text-[9px]">
                    <span className="truncate">netsh advfirewall firewall add rule name="Block_{activeAlert.sourceIp}" dir=in action=block remoteip={activeAlert.sourceIp}</span>
                    <button
                      onClick={() => copyFirewallCommand(activeAlert.sourceIp)}
                      className="ml-1 text-slate-400 hover:text-white"
                      title="Copy PowerShell rule"
                    >
                      {copiedCmd === activeAlert.sourceIp ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Action 2: Mark as Investigating / Resolved */}
                <div className="flex items-center gap-2 pt-0.5">
                  <button
                    disabled={isUpdatingStatus || activeAlert.status === "Investigating"}
                    onClick={() => handleStatusChange(activeAlert, "Investigating")}
                    className="flex-1 py-1.5 rounded-lg neu-flat hover:bg-white text-slate-700 text-[10px] font-bold flex items-center justify-center gap-1 border border-slate-200 transition-all active:scale-95 disabled:opacity-50"
                  >
                    <CheckCircle2 className="w-3 h-3 text-blue-600" />
                    <span>Investigating</span>
                  </button>

                  <button
                    disabled={isUpdatingStatus || activeAlert.status === "Resolved"}
                    onClick={() => handleStatusChange(activeAlert, "Resolved")}
                    className="flex-1 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-[10px] font-bold flex items-center justify-center gap-1 shadow-sm transition-all active:scale-95 disabled:opacity-50"
                  >
                    <Check className="w-3 h-3" />
                    <span>Resolve Incident</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Search & Filter Bar */}
      <div className="neu-flat rounded-2xl p-5 border border-white space-y-4">
        <div className="relative">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by IP address, attack vector, or alert/incident ID (e.g. 192.168.1.185, INC-REAL)..."
            className="w-full pl-10 pr-4 py-2.5 bg-white/90 neu-pressed-sm rounded-xl text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/40 font-mono transition-all"
          />
        </div>

        {/* Filter Controls Row */}
        <div className="flex flex-wrap items-center gap-3 pt-1">
          {/* Severity filter */}
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-[11px] font-semibold text-slate-500">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-white px-2.5 py-1.5 rounded-lg border border-slate-300 text-xs font-semibold text-slate-700 focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Attack Type filter */}
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-[11px] font-semibold text-slate-500">Attack Type:</span>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-white px-2.5 py-1.5 rounded-lg border border-slate-300 text-xs font-semibold text-slate-700 focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Types</option>
              <option value="DDoS High-Burst Attack">DDoS High-Burst</option>
              <option value="DDoS Syn Flood Attack">DDoS Syn Flood</option>
              <option value="Port Scan">Port Scan</option>
              <option value="Brute Force">Brute Force</option>
              <option value="DDoS">DDoS</option>
              <option value="Web Attack">Web Attack</option>
            </select>
          </div>

          {/* Status filter */}
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-[11px] font-semibold text-slate-500">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-white px-2.5 py-1.5 rounded-lg border border-slate-300 text-xs font-semibold text-slate-700 focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Statuses</option>
              <option value="Open">Open</option>
              <option value="Investigating">Investigating</option>
              <option value="Resolved">Resolved</option>
            </select>
          </div>

          {/* Time Range */}
          <div className="flex items-center gap-1.5 text-xs ml-auto">
            <span className="text-[11px] font-semibold text-slate-500">Time:</span>
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="bg-white px-2.5 py-1.5 rounded-lg border border-slate-300 text-xs font-semibold text-slate-700 focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Logs</option>
              <option value="1H">Past 1 Hour</option>
              <option value="TODAY">Today</option>
              <option value="7D">Past 7 Days</option>
            </select>
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="neu-flat rounded-2xl p-6 border border-white">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-3">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Active Threat Events ({filteredAlerts.length} Matches)
            </h3>
            {isLiveConnected && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-100 text-emerald-700 border border-emerald-200">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                Live SQLite ({liveBackendAlerts.length} active)
              </span>
            )}
          </div>
          <span className="text-[10px] text-slate-400 font-mono">
            Click row to select & view 3-pillar triage above
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 text-slate-400 text-[10px] uppercase font-mono tracking-wider">
                <th className="pb-3 font-semibold w-8"></th>
                <th className="pb-3 font-semibold">Alert ID & Time</th>
                <th className="pb-3 font-semibold">Source &rarr; Target</th>
                <th className="pb-3 font-semibold min-w-[260px]">Threat Vector & Reason (क्यों & कैसे आया)</th>
                <th className="pb-3 font-semibold">ML Confidence</th>
                <th className="pb-3 font-semibold">Severity</th>
                <th className="pb-3 font-semibold">Status</th>
                <th className="pb-3 font-semibold text-right min-w-[180px]">Solution (Solution क्या है)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/80 font-sans">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400 font-mono text-xs">
                    No active threat alerts found in the database.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => {
                  const isSelected = activeAlert?.id === alert.id;
                  const isExpanded = expandedAlertId === alert.id;
                  const isBlocked = blockedIps[alert.sourceIp];

                  return (
                    <React.Fragment key={alert.id}>
                      <tr
                        onClick={() => setSelectedAlertId(alert.id)}
                        className={cn(
                          "transition-colors cursor-pointer group",
                          isSelected
                            ? "bg-blue-50/80 font-medium border-l-4 border-blue-600"
                            : "hover:bg-white/80"
                        )}
                      >
                        <td className="py-3.5 pl-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setExpandedAlertId(isExpanded ? null : alert.id);
                              setSelectedAlertId(alert.id);
                            }}
                            className="p-1 rounded hover:bg-slate-200 text-slate-500"
                            title="Expand inline triage details"
                          >
                            {isExpanded ? (
                              <ChevronDown className="w-3.5 h-3.5 text-blue-600" />
                            ) : (
                              <ChevronRight className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </td>

                        <td className="py-3.5">
                          <span className="font-bold font-mono text-blue-600 group-hover:underline block">
                            {alert.id}
                          </span>
                          <span className="font-mono text-slate-400 text-[10px] block">
                            {alert.timestamp}
                          </span>
                        </td>

                        <td className="py-3.5 font-mono">
                          <div className="font-semibold text-slate-800 text-[11px]">
                            {alert.sourceIp}
                          </div>
                          <div className="text-[10px] text-slate-400">
                            &rarr; {alert.destinationIp}:{alert.port || 80}
                          </div>
                        </td>

                        <td className="py-3.5">
                          <div className="font-bold text-slate-900 text-xs flex items-center gap-1.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                            {alert.attackType}
                          </div>
                          <p className="text-[11px] text-slate-600 leading-snug mt-0.5 line-clamp-2 font-sans font-medium">
                            {alert.reason || "Flow packet rate burst diverged abnormally from baseline CICIDS2017 distributions."}
                          </p>
                        </td>

                        <td className="py-3.5 font-mono font-bold text-cyan-700">
                          {alert.confidence}%
                        </td>

                        <td className="py-3.5">
                          <span
                            className={cn(
                              "px-2 py-0.5 rounded-full text-[10px] font-extrabold tracking-wider font-mono",
                              alert.severity === "CRITICAL"
                                ? "bg-red-100 text-red-700 border border-red-200"
                                : alert.severity === "HIGH"
                                ? "bg-orange-100 text-orange-700 border border-orange-200"
                                : alert.severity === "MEDIUM"
                                ? "bg-amber-100 text-amber-700 border border-amber-200"
                                : "bg-emerald-100 text-emerald-700 border border-emerald-200"
                            )}
                          >
                            {alert.severity}
                          </span>
                        </td>

                        <td className="py-3.5">
                          <span
                            className={cn(
                              "px-2 py-0.5 rounded-full text-[10px] font-semibold",
                              alert.status === "Investigating"
                                ? "bg-blue-100 text-blue-700"
                                : alert.status === "Open"
                                ? "bg-amber-100 text-amber-800"
                                : "bg-emerald-100 text-emerald-800"
                            )}
                          >
                            {alert.status}
                          </span>
                        </td>

                        <td className="py-3.5 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleToggleBlock(alert.sourceIp);
                              }}
                              className={cn(
                                "px-2 py-1 rounded text-[10px] font-bold transition-all active:scale-95 flex items-center gap-1",
                                isBlocked
                                  ? "bg-emerald-600 text-white"
                                  : "bg-rose-100 hover:bg-rose-200 text-rose-800 border border-rose-300"
                              )}
                              title="Block Source IP via Firewall"
                            >
                              <Ban className="w-3 h-3" />
                              <span>{isBlocked ? "Blocked" : "Block IP"}</span>
                            </button>

                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                onSelectAlert(alert);
                              }}
                              className="px-2.5 py-1 rounded neu-flat-sm group-hover:bg-blue-600 group-hover:text-white text-[11px] font-bold text-slate-700 transition-colors flex items-center gap-1 shadow-sm"
                            >
                              <span>Investigate</span>
                              <ArrowRight className="w-3 h-3" />
                            </button>
                          </div>
                        </td>
                      </tr>

                      {/* Inline Collapsible Row Drawer */}
                      {isExpanded && (
                        <tr className="bg-slate-100/70 border-b border-slate-200">
                          <td colSpan={10} className="p-4 space-y-3">
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                              <div className="p-3 bg-white rounded-xl border border-slate-200 space-y-1">
                                <span className="font-bold text-slate-800 text-[11px] block">
                                  Summary & Targeting:
                                </span>
                                <p className="text-[11px] text-slate-600 leading-relaxed font-sans">
                                  Attack vector <strong>{alert.attackType}</strong> from <code>{alert.sourceIp}</code> targeting internal asset <code>{alert.destinationIp}:{alert.port || 80}</code> ({alert.protocol || "TCP"}).
                                </p>
                              </div>

                              <div className="p-3 bg-white rounded-xl border border-slate-200 space-y-1">
                                <span className="font-bold text-slate-800 text-[11px] block">
                                  Forensic Detection Reason:
                                </span>
                                <p className="text-[11px] text-slate-600 leading-relaxed font-sans font-mono">
                                  {alert.reason || "Flow packet rate and asymmetric flag ratios diverged significantly from legitimate baseline distributions."}
                                </p>
                              </div>

                              <div className="p-3 bg-white rounded-xl border border-slate-200 space-y-2">
                                <span className="font-bold text-slate-800 text-[11px] block">
                                  Quick Solution Action:
                                </span>
                                <div className="flex items-center gap-2">
                                  <button
                                    onClick={() => handleToggleBlock(alert.sourceIp)}
                                    className={cn(
                                      "text-[10px] font-bold px-2.5 py-1 rounded transition-all",
                                      blockedIps[alert.sourceIp]
                                        ? "bg-emerald-600 text-white"
                                        : "bg-rose-600 hover:bg-rose-700 text-white"
                                    )}
                                  >
                                    {blockedIps[alert.sourceIp] ? "IP Blocked" : "Block IP"}
                                  </button>
                                  <button
                                    onClick={() => onSelectAlert(alert)}
                                    className="text-[10px] font-bold px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-700 text-white transition-all"
                                  >
                                    Full Investigation &rarr;
                                  </button>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
