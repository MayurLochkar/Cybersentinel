"use client";
import React, { useState, useMemo } from "react";
import {
  Search,
  Filter,
  ArrowUpDown,
  ExternalLink,
  ChevronRight,
  ShieldAlert,
  ArrowRight,
} from "lucide-react";
import { CYBER_DATA, Alert, Incident } from "@/data/cyberData";
import { cn } from "@/lib/utils";
import { useEffect } from "react";
import { fetchAlerts, ApiAlert } from "@/lib/api";

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

  useEffect(() => {
    let isMounted = true;
    async function loadAlerts() {
      try {
        const data = await fetchAlerts();
        if (isMounted) {
          setLiveBackendAlerts(data);
          setIsLiveConnected(true);
        }
      } catch {
        if (isMounted) {
          setIsLiveConnected(false);
        }
      }
    }

    loadAlerts();
    const interval = setInterval(loadAlerts, 8000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Merge live database alerts with static alerts
  const combinedAlerts: Alert[] = useMemo(() => {
    if (liveBackendAlerts.length === 0) {
      return CYBER_DATA.alertsList;
    }

    const mappedLive: Alert[] = liveBackendAlerts.map((item) => ({
      id: `ALT-${item.id.toString().padStart(4, "0")}`,
      timestamp: item.created_at?.slice(11, 16) || "Just now",
      sourceIp: item.source_ip,
      destinationIp: item.destination_ip,
      attackType: (item.attack_type as any) || "Brute Force",
      confidence: item.confidence,
      severity: item.severity,
      status: item.status as any,
      incidentId: item.incident_id,
      port: 443,
      protocol: "TCP",
    }));

    // Put live alerts at top, followed by any additional prototypes
    const existingIds = new Set(mappedLive.map((a) => a.incidentId));
    const extra = CYBER_DATA.alertsList.filter((a) => !existingIds.has(a.incidentId));
    return [...mappedLive, ...extra];
  }, [liveBackendAlerts]);

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

  return (
    <div className="space-y-6 pb-12">
      {/* Top Search & Filter Bar */}
      <div className="neu-flat rounded-2xl p-5 border border-white space-y-4">
        {/* Search */}
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by IP address, attack vector, or alert/incident ID (e.g. 185.73.21.10, INC-1024)..."
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
              className="bg-white px-2.5 py-1.5 rounded-lg border border-slate-300 text-xs font-semibold text-slate-700 focus:outline-none"
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
              className="bg-white px-2.5 py-1.5 rounded-lg border border-slate-300 text-xs font-semibold text-slate-700 focus:outline-none"
            >
              <option value="ALL">All Types</option>
              <option value="Brute Force">Brute Force</option>
              <option value="Port Scan">Port Scan</option>
              <option value="DDoS">DDoS</option>
              <option value="Web Attack">Web Attack</option>
              <option value="Botnet">Botnet</option>
              <option value="SQL Injection">SQL Injection</option>
            </select>
          </div>

          {/* Status filter */}
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-[11px] font-semibold text-slate-500">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-white px-2.5 py-1.5 rounded-lg border border-slate-300 text-xs font-semibold text-slate-700 focus:outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="Open">Open</option>
              <option value="Investigating">Investigating</option>
              <option value="Resolved">Resolved</option>
              <option value="Closed">Closed</option>
            </select>
          </div>

          {/* Time Range */}
          <div className="flex items-center gap-1.5 text-xs ml-auto">
            <span className="text-[11px] font-semibold text-slate-500">Time:</span>
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="bg-white px-2.5 py-1.5 rounded-lg border border-slate-300 text-xs font-semibold text-slate-700 focus:outline-none"
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
          <span className="text-[10px] text-slate-400 font-mono">Real-time Telemetry Stream</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 text-slate-400 text-[10px] uppercase font-mono tracking-wider">
                <th className="pb-3 font-semibold">Alert ID</th>
                <th className="pb-3 font-semibold">Timestamp</th>
                <th className="pb-3 font-semibold">Source IP</th>
                <th className="pb-3 font-semibold">Destination IP</th>
                <th className="pb-3 font-semibold">Attack Type</th>
                <th className="pb-3 font-semibold">Confidence</th>
                <th className="pb-3 font-semibold">Severity</th>
                <th className="pb-3 font-semibold">Status</th>
                <th className="pb-3 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/80 font-sans">
              {filteredAlerts.map((alert) => (
                <tr
                  key={alert.id}
                  onClick={() => onSelectAlert(alert)}
                  className="hover:bg-white/80 transition-colors cursor-pointer group"
                >
                  <td className="py-3.5 font-bold font-mono text-blue-600 group-hover:underline">
                    {alert.id}
                  </td>
                  <td className="py-3.5 font-mono text-slate-500 text-[11px]">{alert.timestamp}</td>
                  <td className="py-3.5 font-mono text-slate-800 font-semibold">{alert.sourceIp}</td>
                  <td className="py-3.5 font-mono text-slate-600">{alert.destinationIp}</td>
                  <td className="py-3.5 font-semibold text-slate-800">{alert.attackType}</td>
                  <td className="py-3.5 font-mono font-bold text-slate-800">
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
                          : "bg-slate-200 text-slate-700"
                      )}
                    >
                      {alert.status}
                    </span>
                  </td>
                  <td className="py-3.5 text-right">
                    <button className="px-3 py-1 rounded-lg neu-flat-sm group-hover:bg-blue-600 group-hover:text-white text-[11px] font-semibold text-slate-700 transition-colors flex items-center gap-1 ml-auto">
                      <span>Investigate</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
