"use client";
import React, { useState } from "react";
import {
  Search,
  Bell,
  Sparkles,
  Shield,
  ShieldCheck,
  ExternalLink,
  ChevronRight,
  Terminal,
  ArrowLeft,
  UserCheck,
} from "lucide-react";
import { NotificationsPanel } from "./notifications-panel";
import { CYBER_DATA } from "@/data/cyberData";
import { cn } from "@/lib/utils";

export function TopNavbar({
  activeTab,
  onNavigateHome,
  onSelectTab,
}: {
  activeTab: string;
  onNavigateHome: () => void;
  onSelectTab: (tab: any) => void;
}) {
  const [showNotifications, setShowNotifications] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  return (
    <header className="h-20 bg-[#eef3f8]/95 backdrop-blur-xl border-b border-slate-300/80 px-4 sm:px-8 flex items-center justify-between sticky top-0 z-40 shadow-sm">
      {/* Brand & Live Operational Status */}
      <div className="flex items-center gap-3">
        <div className="h-10 w-10 rounded-2xl bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center text-white shadow-md shadow-blue-500/20">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono font-black text-sm text-slate-800 tracking-tight">
              CYBERSENTINEL<span className="text-cyan-600">-X</span>
            </span>
            <span className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-mono font-bold bg-emerald-100 text-emerald-700 border border-emerald-200">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              OPERATIONAL
            </span>
          </div>
          <p className="text-[10px] text-slate-400 font-mono hidden sm:block">
            AI Threat Detection & Forensic Evidence Hub
          </p>
        </div>
      </div>

      {/* Center Search with Shortcut Badge */}
      <div className="hidden md:flex items-center w-80 lg:w-96 relative">
        <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search IP, Hash, MITRE CVE, Incident ID..."
          className="w-full pl-10 pr-16 py-2 bg-white/90 neu-pressed-sm rounded-full text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/40 font-mono transition-all border border-slate-200"
        />
        <span className="absolute right-3 top-1/2 -translate-y-1/2 px-1.5 py-0.5 rounded bg-slate-200 text-slate-500 text-[10px] font-mono select-none">
          Ctrl K
        </span>
      </div>

      {/* Right Actions */}
      <div className="flex items-center gap-2.5">
        {/* Return to Landing Portal */}
        <button
          onClick={onNavigateHome}
          className="px-3.5 py-2 rounded-full neu-flat hover:bg-white text-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-all active:scale-95"
          title="Return to Landing Page"
        >
          <ArrowLeft className="w-3.5 h-3.5 text-blue-600" />
          <span className="hidden sm:inline">Landing Portal</span>
        </button>

        {/* AI Co-Pilot shortcut */}
        <button
          onClick={() => onSelectTab("investigation")}
          className="hidden lg:flex items-center gap-1.5 px-3.5 py-2 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white text-xs font-bold shadow-md shadow-blue-500/20 hover:from-blue-500 hover:to-indigo-500 active:scale-95 transition-all"
        >
          <Sparkles className="w-3.5 h-3.5 text-cyan-300" />
          <span>AI Co-Pilot</span>
        </button>

        {/* Notification Bell */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="w-10 h-10 rounded-full neu-flat hover:bg-white flex items-center justify-center text-slate-600 relative transition-all active:neu-pressed"
            aria-label="Toggle notifications"
          >
            <Bell className="w-4 h-4" />
            <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-red-500 ring-2 ring-white animate-pulse" />
          </button>

          <NotificationsPanel
            isOpen={showNotifications}
            onClose={() => setShowNotifications(false)}
            notifications={CYBER_DATA.notifications}
            onSelectAlert={() => onSelectTab("alerts")}
          />
        </div>

        {/* Analyst Profile Pill */}
        <div
          onClick={() => onSelectTab("settings")}
          className="hidden sm:flex items-center gap-2 px-2.5 py-1.5 rounded-full neu-flat hover:bg-white cursor-pointer transition-all active:scale-95"
          title="Settings & Profile"
        >
          <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-cyan-600 to-blue-600 text-white flex items-center justify-center font-bold text-xs">
            SA
          </div>
          <span className="text-xs font-bold text-slate-800 pr-1">Analyst L3</span>
        </div>
      </div>
    </header>
  );
}
