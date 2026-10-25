"use client";
import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
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
  RefreshCw,
  Command,
  HelpCircle,
} from "lucide-react";
import { NotificationsPanel } from "./notifications-panel";
import { CYBER_DATA } from "@/data/cyberData";
import { cn } from "@/lib/utils";

export function TopNavbar({
  activeTab,
  onNavigateHome,
  onSelectTab,
  onOpenGuide,
}: {
  activeTab: string;
  onNavigateHome: () => void;
  onSelectTab: (tab: any) => void;
  onOpenGuide?: () => void;
}) {
  const [showNotifications, setShowNotifications] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [searchFocused, setSearchFocused] = useState(false);

  const handleRefresh = () => {
    setIsRefreshing(true);
    window.dispatchEvent(new CustomEvent("cybersentinel-refresh-all"));
    setTimeout(() => setIsRefreshing(false), 1000);
  };

  return (
    <header className="h-20 bg-[#eef3f8]/95 backdrop-blur-xl border-b border-[#B7B7B7]/40 px-4 sm:px-8 flex items-center justify-between sticky top-0 z-40 shadow-sm relative overflow-hidden">
      {/* Subtle gradient shimmer at top */}
      <div className="absolute top-0 left-0 right-0 h-[1.5px] bg-gradient-to-r from-transparent via-[#6F3DFF]/35 to-transparent" />

      {/* Brand & Live Operational Status */}
      <div className="flex items-center gap-3">
        <motion.div
          className="h-10 w-10 rounded-2xl bg-gradient-to-tr from-[#6F3DFF] via-[#855bff] to-[#BFE9FF] flex items-center justify-center text-white shadow-md shadow-[#6F3DFF]/25 border border-white/50"
          whileHover={{ rotate: 10, scale: 1.05 }}
          transition={{ type: "spring", stiffness: 300 }}
        >
          <Shield className="w-5 h-5 text-white" />
        </motion.div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono font-black text-sm text-slate-800 tracking-tight">
              CYBERSENTINEL<span className="text-[#6F3DFF]">-X</span>
            </span>
            <span className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-mono font-bold bg-[#BFE9FF] text-[#6F3DFF] border border-[#6F3DFF]/30">
              <span className="relative flex h-1.5 w-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#6F3DFF] opacity-75" />
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-[#6F3DFF]" />
              </span>
              OPERATIONAL
            </span>
          </div>
          <p className="text-[10px] text-slate-500 font-mono hidden sm:block">
            AI Threat Detection & Forensic Evidence Hub
          </p>
        </div>
      </div>

      {/* Center Search with Shortcut Badge */}
      <div className="hidden md:flex items-center w-80 lg:w-96 relative">
        <Search className={cn(
          "w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 transition-colors",
          searchFocused ? "text-[#6F3DFF]" : "text-slate-400"
        )} />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onFocus={() => setSearchFocused(true)}
          onBlur={() => setSearchFocused(false)}
          placeholder="Search IP, Hash, MITRE CVE, Incident ID..."
          className={cn(
            "w-full pl-10 pr-16 py-2.5 bg-white/90 rounded-full text-xs text-slate-800 placeholder-slate-400 focus:outline-none font-mono transition-all border",
            searchFocused
              ? "border-[#6F3DFF]/50 ring-2 ring-[#6F3DFF]/20 shadow-lg shadow-[#6F3DFF]/10"
              : "border-[#B7B7B7]/40 neu-pressed-sm"
          )}
        />
        <span className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-slate-200 text-slate-500 text-[10px] font-mono select-none">
          <Command className="w-2.5 h-2.5" /> K
        </span>
      </div>

      {/* Right Actions */}
      <div className="flex items-center gap-2.5">
        {/* Return to Landing Portal */}
        <motion.button
          onClick={onNavigateHome}
          className="px-3.5 py-2 rounded-full neu-flat hover:bg-white text-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-all active:scale-95 border border-[#B7B7B7]/30"
          title="Return to Landing Page"
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.97 }}
        >
          <ArrowLeft className="w-3.5 h-3.5 text-[#6F3DFF]" />
          <span className="hidden sm:inline">Landing Portal</span>
        </motion.button>

        {/* Quick Guide / How It Works button */}
        {onOpenGuide && (
          <motion.button
            onClick={onOpenGuide}
            className="px-3.5 py-2 rounded-full neu-flat hover:bg-white text-slate-800 text-xs font-bold flex items-center gap-1.5 transition-all active:scale-95 border border-purple-200 bg-purple-50/60 shadow-sm"
            title="Open Interactive Guide & Architecture Walkthrough"
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
          >
            <HelpCircle className="w-3.5 h-3.5 text-[#6F3DFF]" />
            <span className="hidden md:inline">Quick Guide</span>
            <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded-full bg-[#6F3DFF]/10 text-[#6F3DFF]">
              3-Min
            </span>
          </motion.button>
        )}

        {/* AI Co-Pilot shortcut */}
        <motion.button
          onClick={() => onSelectTab("investigation")}
          className="hidden lg:flex items-center gap-1.5 px-3.5 py-2 rounded-full bg-gradient-to-r from-[#6F3DFF] to-[#4e19d9] text-white text-xs font-bold shadow-md shadow-[#6F3DFF]/25 hover:from-[#7c4dff] hover:to-[#5c24e6] active:scale-95 transition-all relative overflow-hidden border border-[#BFE9FF]/30"
          whileHover={{ scale: 1.03 }}
          whileTap={{ scale: 0.97 }}
        >
          <Sparkles className="w-3.5 h-3.5 text-[#BFE9FF]" />
          <span>AI Co-Pilot</span>
          {/* Shimmer effect */}
          <motion.span
            className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent"
            animate={{ x: ["-100%", "200%"] }}
            transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
          />
        </motion.button>

        {/* Global Refresh Button */}
        <motion.button
          onClick={handleRefresh}
          className="w-10 h-10 rounded-full neu-flat hover:bg-white flex items-center justify-center text-slate-600 hover:text-[#6F3DFF] transition-all active:neu-pressed border border-[#B7B7B7]/30"
          title="Refresh All Telemetry & Views Across CyberSentinel"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          <motion.div
            animate={isRefreshing ? { rotate: 360 } : {}}
            transition={{ duration: 0.6, ease: "easeInOut" }}
          >
            <RefreshCw className="w-4 h-4" />
          </motion.div>
        </motion.button>

        {/* Notification Bell */}
        <div className="relative">
          <motion.button
            onClick={() => setShowNotifications(!showNotifications)}
            className="w-10 h-10 rounded-full neu-flat hover:bg-white flex items-center justify-center text-slate-600 relative transition-all active:neu-pressed"
            aria-label="Toggle notifications"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <Bell className="w-4 h-4" />
            <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-red-500 ring-2 ring-[#eef3f8]">
              <span className="absolute inset-0 rounded-full bg-red-500 animate-ping" />
            </span>
          </motion.button>

          <NotificationsPanel
            isOpen={showNotifications}
            onClose={() => setShowNotifications(false)}
            notifications={CYBER_DATA.notifications}
            onSelectAlert={() => onSelectTab("alerts")}
          />
        </div>

        {/* Analyst Profile Pill */}
        <motion.div
          onClick={() => onSelectTab("settings")}
          className="hidden sm:flex items-center gap-2 px-2.5 py-1.5 rounded-full neu-flat hover:bg-white cursor-pointer transition-all active:scale-95"
          title="Settings & Profile"
          whileHover={{ scale: 1.02 }}
        >
          <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-cyan-600 to-blue-600 text-white flex items-center justify-center font-bold text-xs shadow-sm shadow-blue-500/20">
            SA
          </div>
          <span className="text-xs font-bold text-slate-800 pr-1">Analyst L3</span>
        </motion.div>
      </div>
    </header>
  );
}
