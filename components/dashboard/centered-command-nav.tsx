"use client";
import React, { useEffect, useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
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
  Radio,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { NavTab } from "./sidebar";
import { fetchDashboardSummary, ApiDashboardSummary } from "@/lib/api";

interface CenteredCommandNavProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
}

interface NavItem {
  id: string;
  label: string;
  tooltip: string;
  icon: React.ReactNode;
  badge?: string;
  highlight?: boolean;
}

interface NavGroup {
  group: string;
  tabs: NavItem[];
}

export function CenteredCommandNav({ activeTab, onSelectTab }: CenteredCommandNavProps) {
  const [summary, setSummary] = useState<ApiDashboardSummary | null>(null);
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(false);

  const updateScrollButtons = () => {
    const el = scrollContainerRef.current;
    if (!el) return;
    const { scrollLeft, scrollWidth, clientWidth } = el;
    setCanScrollLeft(scrollLeft > 6);
    setCanScrollRight(scrollLeft < scrollWidth - clientWidth - 6);
  };

  useEffect(() => {
    const el = scrollContainerRef.current;
    if (!el) return;

    updateScrollButtons();
    const handleScroll = () => updateScrollButtons();
    const handleResize = () => updateScrollButtons();

    el.addEventListener("scroll", handleScroll, { passive: true });
    window.addEventListener("resize", handleResize);

    // Support mouse wheel horizontal scrolling over the command bar
    const onWheel = (e: WheelEvent) => {
      if (el.scrollWidth > el.clientWidth && Math.abs(e.deltaY) > Math.abs(e.deltaX)) {
        e.preventDefault();
        el.scrollLeft += e.deltaY;
      }
    };
    el.addEventListener("wheel", onWheel, { passive: false });

    return () => {
      el.removeEventListener("scroll", handleScroll);
      window.removeEventListener("resize", handleResize);
      el.removeEventListener("wheel", onWheel);
    };
  }, []);

  // When activeTab changes, scroll it smoothly into view
  useEffect(() => {
    const el = scrollContainerRef.current;
    if (!el) return;
    const activeEl = el.querySelector(`[data-tab-id="${activeTab}"]`) as HTMLElement;
    if (activeEl) {
      activeEl.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" });
    }
    updateScrollButtons();
  }, [activeTab]);

  const scrollByAmount = (distance: number) => {
    if (!scrollContainerRef.current) return;
    scrollContainerRef.current.scrollBy({ left: distance, behavior: "smooth" });
  };

  useEffect(() => {
    let isMounted = true;
    async function loadCounts() {
      try {
        const data = await fetchDashboardSummary();
        if (isMounted) setSummary(data);
      } catch {
        // Keep default or previous
      }
    }
    loadCounts();
    const handleGlobalRefresh = () => {
      loadCounts();
    };
    if (typeof window !== "undefined") {
      window.addEventListener("cybersentinel-refresh-all", handleGlobalRefresh);
    }
    const interval = setInterval(loadCounts, 5000);
    return () => {
      isMounted = false;
      clearInterval(interval);
      if (typeof window !== "undefined") {
        window.removeEventListener("cybersentinel-refresh-all", handleGlobalRefresh);
      }
    };
  }, []);

  const totalAlertsStr = summary !== null && summary.total_alerts > 0 ? String(summary.total_alerts) : undefined;
  const critAlertsStr = summary !== null && summary.critical > 0 ? `${summary.critical} Crit` : summary !== null && summary.high_risk > 0 ? `${summary.high_risk} High` : undefined;

  const navGroups: NavGroup[] = [
    {
      group: "Live Ops",
      tabs: [
        {
          id: "dashboard",
          label: "Dashboard",
          tooltip: "Executive overview & real-time network traffic health",
          icon: <LayoutDashboard className="w-3.5 h-3.5" />,
        },
        {
          id: "monitoring",
          label: "Live Monitor",
          tooltip: "Real-time packet sniffer & flow classifier (Wi-Fi/Ethernet)",
          icon: <Radio className="w-3.5 h-3.5" />,
          badge: "LIVE",
        },
        {
          id: "alerts",
          label: "Alerts",
          tooltip: "AI-flagged attack anomalies & security events",
          icon: <Bell className="w-3.5 h-3.5" />,
          badge: totalAlertsStr,
        },
        {
          id: "incidents",
          label: "Incidents",
          tooltip: "Detailed incident analysis, timeline & 5-tuple forensic dossier",
          icon: <AlertTriangle className="w-3.5 h-3.5" />,
          badge: critAlertsStr,
        },
      ],
    },
    {
      group: "AI & Intel",
      tabs: [
        {
          id: "investigation",
          label: "AI Investigation",
          tooltip: "Automated root-cause analysis & MITRE ATT&CK correlation",
          icon: <BrainCircuit className="w-3.5 h-3.5" />,
          highlight: true,
        },
        {
          id: "threat-intel",
          label: "Threat Intel",
          tooltip: "Global threat intelligence feeds & IP reputation lookup",
          icon: <Flame className="w-3.5 h-3.5" />,
        },
        {
          id: "risk",
          label: "Risk Engine",
          tooltip: "Quantified threat risk scoring & business impact evaluation",
          icon: <Gauge className="w-3.5 h-3.5" />,
        },
      ],
    },
    {
      group: "Forensics & System",
      tabs: [
        {
          id: "evidence",
          label: "Evidence Ledger",
          tooltip: "Cryptographic SHA-256 chain of custody for legal evidence",
          icon: <FileCheck2 className="w-3.5 h-3.5" />,
          badge: "SHA-256",
        },
        {
          id: "analytics",
          label: "Analytics",
          tooltip: "Historical attack distributions & trend analytics",
          icon: <BarChart3 className="w-3.5 h-3.5" />,
        },
        {
          id: "model",
          label: "Model Metrics",
          tooltip: "Random Forest CICIDS2017 ML performance & confusion matrix",
          icon: <Cpu className="w-3.5 h-3.5" />,
        },
        {
          id: "reports",
          label: "Reports",
          tooltip: "Executive & forensic downloadable incident dossiers",
          icon: <FileText className="w-3.5 h-3.5" />,
        },
        {
          id: "settings",
          label: "Settings",
          tooltip: "Configure network adapters, BPF filters & API keys",
          icon: <Settings className="w-3.5 h-3.5" />,
        },
      ],
    },
  ];

  return (
    <div className="w-full flex justify-center py-2 px-2 sticky top-[4.5rem] z-30 pointer-events-auto">
      <div className="relative w-full max-w-[98vw] 2xl:max-w-[1460px] mx-auto flex items-center justify-center">
        {/* Scroll Left Button */}
        {canScrollLeft && (
          <motion.button
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.8 }}
            type="button"
            onClick={() => scrollByAmount(-260)}
            title="Scroll left"
            className="absolute left-1 z-30 h-8 w-8 rounded-full bg-white shadow-lg border border-[#6F3DFF]/30 flex items-center justify-center text-[#6F3DFF] hover:bg-slate-50 hover:scale-105 active:scale-95 cursor-pointer transition-all"
            aria-label="Scroll navigation left"
          >
            <ChevronLeft className="w-4 h-4" />
          </motion.button>
        )}

        <div
          ref={scrollContainerRef}
          className="w-full overflow-x-auto [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden py-1 px-1 scroll-smooth"
        >
          <nav className="flex items-center gap-1 sm:gap-1.5 p-1.5 rounded-full neu-flat bg-[#eef3f8]/95 backdrop-blur-xl border border-[#B7B7B7]/40 shadow-xl min-w-max mx-auto relative">
            {/* Subtle gradient line at bottom */}
            <div className="absolute bottom-0 left-6 right-6 h-[1.5px] bg-gradient-to-r from-transparent via-[#6F3DFF]/30 to-transparent" />

            {navGroups.map((group, groupIdx) => (
              <React.Fragment key={group.group}>
                {groupIdx > 0 && (
                  <div className="h-5 w-[1px] bg-slate-300/80 mx-1 self-center shrink-0" />
                )}
                <div className="flex items-center gap-1">
                  {group.tabs.map((tab) => {
                    const isActive =
                      activeTab === tab.id || (tab.id === "incidents" && activeTab === "report-view");
                    return (
                      <motion.button
                        key={tab.id}
                        data-tab-id={tab.id}
                        onClick={() => onSelectTab(tab.id as NavTab)}
                        title={tab.tooltip}
                        className={cn(
                          "flex items-center gap-1 sm:gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-full text-xs font-semibold transition-all duration-200 select-none whitespace-nowrap relative group shrink-0",
                          isActive
                            ? "bg-white text-[#6F3DFF] font-bold shadow-md border border-[#6F3DFF]/40"
                            : "text-slate-600 hover:text-slate-900 hover:bg-white/60"
                        )}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.97 }}
                      >
                        {/* Active background indicator */}
                        {isActive && (
                          <motion.div
                            layoutId="nav-active-pill"
                            className="absolute inset-0 bg-white rounded-full shadow-md border border-[#6F3DFF]/40"
                            transition={{ type: "spring", stiffness: 350, damping: 30 }}
                            style={{ zIndex: -1 }}
                          />
                        )}

                        <span
                          className={cn(
                            "transition-colors relative z-10",
                            isActive ? "text-[#6F3DFF]" : "text-slate-500 group-hover:text-slate-700"
                          )}
                        >
                          {tab.icon}
                        </span>
                        <span className="relative z-10">{tab.label}</span>

                        {tab.badge && (
                          <span
                            className={cn(
                              "text-[9px] font-mono font-bold px-1.5 py-0.2 rounded-full relative z-10",
                              tab.badge.includes("Crit")
                                ? "bg-red-100 text-red-600 border border-red-200"
                                : tab.badge === "SHA-256"
                                ? "bg-emerald-100 text-emerald-700 border border-emerald-200"
                                : tab.badge === "LIVE"
                                ? "bg-[#BFE9FF] text-[#6F3DFF] border border-[#6F3DFF]/30"
                                : "bg-[#6F3DFF]/10 text-[#6F3DFF] border border-[#6F3DFF]/20"
                            )}
                          >
                            {tab.badge === "LIVE" && (
                              <span className="inline-block w-1 h-1 rounded-full bg-[#6F3DFF] animate-pulse mr-0.5 relative -top-px" />
                            )}
                            {tab.badge}
                          </span>
                        )}

                        {tab.highlight && !tab.badge && (
                          <span className="relative flex h-1.5 w-1.5 z-10">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#6F3DFF] opacity-75" />
                            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-[#6F3DFF]" />
                          </span>
                        )}
                      </motion.button>
                    );
                  })}
                </div>
              </React.Fragment>
            ))}
          </nav>
        </div>

        {/* Scroll Right Button */}
        {canScrollRight && (
          <motion.button
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.8 }}
            type="button"
            onClick={() => scrollByAmount(260)}
            title="Scroll right to view Analytics, Model Metrics, Reports, Settings"
            className="absolute right-1 z-30 h-8 w-8 rounded-full bg-[#6F3DFF] shadow-lg shadow-[#6F3DFF]/30 border border-white/60 flex items-center justify-center text-white hover:bg-[#5b2cd9] hover:scale-105 active:scale-95 cursor-pointer transition-all"
            aria-label="Scroll navigation right"
          >
            <ChevronRight className="w-4 h-4" />
          </motion.button>
        )}
      </div>
    </div>
  );
}
