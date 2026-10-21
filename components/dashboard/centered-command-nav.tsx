"use client";
import React from "react";
import {
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
  Sparkles,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { NavTab } from "./sidebar";

interface CenteredCommandNavProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
}

export function CenteredCommandNav({ activeTab, onSelectTab }: CenteredCommandNavProps) {
  const navTabs = [
    { id: "dashboard", label: "Dashboard", icon: <LayoutDashboard className="w-3.5 h-3.5" /> },
    { id: "alerts", label: "Alerts", icon: <Bell className="w-3.5 h-3.5" />, badge: "128" },
    { id: "incidents", label: "Incidents", icon: <AlertTriangle className="w-3.5 h-3.5" />, badge: "3 Crit" },
    { id: "threat-intel", label: "Threat Intel", icon: <Flame className="w-3.5 h-3.5" /> },
    { id: "investigation", label: "AI Investigation", icon: <BrainCircuit className="w-3.5 h-3.5" />, highlight: true },
    { id: "risk", label: "Risk Assessment", icon: <Gauge className="w-3.5 h-3.5" /> },
    { id: "evidence", label: "Evidence Ledger", icon: <FileCheck2 className="w-3.5 h-3.5" />, badge: "SHA-256" },
    { id: "analytics", label: "Analytics", icon: <BarChart3 className="w-3.5 h-3.5" /> },
    { id: "model", label: "Model Metrics", icon: <Cpu className="w-3.5 h-3.5" /> },
    { id: "reports", label: "Reports", icon: <FileText className="w-3.5 h-3.5" /> },
    { id: "settings", label: "Settings", icon: <Settings className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="w-full flex justify-center py-3 px-2 sticky top-[4.5rem] z-30 pointer-events-auto">
      <div className="max-w-6xl w-full mx-auto overflow-x-auto [scrollbar-width:none] py-1 px-2">
        <nav className="flex items-center justify-start lg:justify-center gap-1.5 p-1.5 rounded-full neu-flat bg-[#eef3f8]/95 backdrop-blur-xl border border-white shadow-xl min-w-max mx-auto">
          {navTabs.map((tab) => {
            const isActive =
              activeTab === tab.id || (tab.id === "incidents" && activeTab === "report-view");
            return (
              <button
                key={tab.id}
                onClick={() => onSelectTab(tab.id as NavTab)}
                className={cn(
                  "flex items-center gap-2 px-3.5 py-2 rounded-full text-xs font-semibold transition-all duration-200 select-none whitespace-nowrap active:scale-95",
                  isActive
                    ? "neu-pressed bg-white text-blue-700 font-bold shadow-inner border border-blue-400/40"
                    : "text-slate-600 hover:text-slate-900 hover:bg-white/60"
                )}
              >
                <span className={cn("transition-colors", isActive ? "text-blue-600" : "text-slate-500")}>
                  {tab.icon}
                </span>
                <span>{tab.label}</span>
                {tab.badge && (
                  <span
                    className={cn(
                      "text-[9px] font-mono font-bold px-1.5 py-0.2 rounded-full",
                      tab.badge.includes("Crit")
                        ? "bg-red-100 text-red-600 border border-red-200"
                        : tab.badge === "SHA-256"
                        ? "bg-emerald-100 text-emerald-700 border border-emerald-200"
                        : "bg-blue-100 text-blue-700"
                    )}
                  >
                    {tab.badge}
                  </span>
                )}
                {tab.highlight && !tab.badge && (
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 animate-ping" />
                )}
              </button>
            );
          })}
        </nav>
      </div>
    </div>
  );
}
