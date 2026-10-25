"use client";
import React from "react";
import {
  ShieldAlert,
  LayoutDashboard,
  Bell,
  AlertTriangle,
  Flame,
  BrainCircuit,
  Gauge,
  FileCheck2,
  BarChart3,
  Cpu,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Shield,
  Activity,
  CheckCircle2,
  UserCheck,
  Radio,
} from "lucide-react";
import { cn } from "@/lib/utils";

export type NavTab =
  | "dashboard"
  | "monitoring"
  | "alerts"
  | "incidents"
  | "threat-intel"
  | "investigation"
  | "risk"
  | "evidence"
  | "analytics"
  | "model"
  | "reports"
  | "report-view"
  | "settings";

import { useEffect, useState } from "react";
import { fetchDashboardSummary, ApiDashboardSummary } from "@/lib/api";

export function DashboardSidebar({
  activeTab,
  onSelectTab,
  collapsed,
  setCollapsed,
}: {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  collapsed: boolean;
  setCollapsed: (c: boolean) => void;
}) {
  const [summary, setSummary] = useState<ApiDashboardSummary | null>(null);

  useEffect(() => {
    let isMounted = true;
    async function loadCounts() {
      try {
        const data = await fetchDashboardSummary();
        if (isMounted) setSummary(data);
      } catch {
        // Keep default
      }
    }
    loadCounts();
    const interval = setInterval(loadCounts, 5000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const totalAlertsStr = summary !== null ? String(summary.total_alerts) : "—";
  const critAlertsStr = summary !== null ? `${summary.critical} Crit` : "—";

  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: "monitoring", label: "Live Network Monitoring", icon: <Radio className="w-4 h-4 text-emerald-600" />, badge: "LIVE" },
    { id: "alerts", label: "Alerts", icon: <Bell className="w-4 h-4" />, badge: totalAlertsStr },
    { id: "incidents", label: "Incidents", icon: <AlertTriangle className="w-4 h-4" />, badge: critAlertsStr },
    { id: "threat-intel", label: "Threat Intelligence", icon: <Flame className="w-4 h-4" /> },
    { id: "investigation", label: "AI Investigation", icon: <BrainCircuit className="w-4 h-4" />, highlight: true },
    { id: "risk", label: "Risk Assessment", icon: <Gauge className="w-4 h-4" /> },
    { id: "evidence", label: "Evidence Ledger", icon: <FileCheck2 className="w-4 h-4" /> },
    { id: "analytics", label: "Analytics", icon: <BarChart3 className="w-4 h-4" /> },
    { id: "model", label: "Model Performance", icon: <Cpu className="w-4 h-4" /> },
    { id: "reports", label: "Reports", icon: <FileText className="w-4 h-4" /> },
    { id: "settings", label: "Settings", icon: <Settings className="w-4 h-4" /> },
  ];

  return (
    <aside
      className={cn(
        "h-screen sticky top-0 bg-[#eef3f8] border-r border-slate-300/80 flex flex-col justify-between transition-all duration-300 z-30 select-none shadow-sm",
        collapsed ? "w-20" : "w-64"
      )}
    >
      {/* Brand Header */}
      <div>
        <div className="h-16 flex items-center justify-between px-4 border-b border-slate-200">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="h-9 w-9 shrink-0 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center text-white shadow-md">
              <Shield className="w-5 h-5" />
            </div>
            {!collapsed && (
              <div className="truncate">
                <span className="font-extrabold text-sm text-slate-800 tracking-tight block">
                  CYBERSENTINEL<span className="text-cyan-600">-X</span>
                </span>
                <span className="text-[10px] text-slate-400 font-mono block">AI SOC SUITE</span>
              </div>
            )}
          </div>
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1 rounded-lg hover:bg-slate-200 text-slate-500 hover:text-slate-800 transition-colors"
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation items */}
        <nav className="p-3 space-y-1 overflow-y-auto max-h-[calc(100vh-170px)]">
          {navItems.map((item) => {
            const isActive =
              activeTab === item.id || (item.id === "incidents" && activeTab === "report-view");
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id as NavTab)}
                className={cn(
                  "w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-semibold transition-all group relative",
                  isActive
                    ? "neu-pressed text-blue-700 font-bold shadow-inner"
                    : "text-slate-600 hover:text-slate-900 hover:bg-white/60"
                )}
                title={collapsed ? item.label : undefined}
              >
                <div
                  className={cn(
                    "transition-colors",
                    isActive ? "text-blue-600" : "text-slate-500 group-hover:text-slate-800"
                  )}
                >
                  {item.icon}
                </div>

                {!collapsed && (
                  <div className="flex-1 text-left flex items-center justify-between truncate">
                    <span className="truncate">{item.label}</span>
                    {item.badge && (
                      <span
                        className={cn(
                          "text-[10px] font-bold px-2 py-0.5 rounded-full",
                          item.badge.includes("Crit")
                            ? "bg-red-100 text-red-600 border border-red-200"
                            : "bg-blue-100 text-blue-600 border border-blue-200"
                        )}
                      >
                        {item.badge}
                      </span>
                    )}
                    {item.highlight && !item.badge && (
                      <span className="w-2 h-2 rounded-full bg-cyan-500 animate-ping" />
                    )}
                  </div>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Status & Profile */}
      <div className="p-3 border-t border-slate-200 space-y-3 bg-[#e8eef5]">
        {!collapsed ? (
          <>
            {/* System Status Requirement */}
            <div className="neu-flat-sm rounded-xl p-2.5 bg-white/70 border border-white">
              <div className="text-[10px] text-slate-400 font-mono">SYSTEM STATUS</div>
              <div className="flex items-center gap-1.5 mt-1 text-xs font-bold text-emerald-600">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span>All Systems Operational</span>
              </div>
            </div>

            {/* User Profile Requirement */}
            <div className="flex items-center gap-2.5 px-2 py-1">
              <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-cyan-600 to-blue-600 text-white flex items-center justify-center font-bold text-xs shadow-md">
                SA
              </div>
              <div className="truncate">
                <div className="text-xs font-bold text-slate-800 truncate">Security Analyst</div>
                <div className="text-[10px] text-slate-500 font-mono">Role: Admin / L3</div>
              </div>
            </div>
          </>
        ) : (
          <div className="flex flex-col items-center gap-2 py-1">
            <span className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse" title="Systems Operational" />
            <div className="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center text-xs font-bold">
              SA
            </div>
          </div>
        )}
      </div>
    </aside>
  );
}
