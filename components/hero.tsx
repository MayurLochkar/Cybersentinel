"use client";
import React, { useState, useEffect } from "react";
import Image from "next/image";
import { motion } from "framer-motion";
import {
  ArrowUpRight,
  Shield,
  Check,
  Activity,
  Lock,
  Fingerprint,
  Zap,
  Globe,
  Eye,
} from "lucide-react";
import { EncryptedText } from "@/components/ui/encrypted-text";
import { cn } from "@/lib/utils";

const fadeUp = {
  initial: { opacity: 0, y: 28 },
  animate: { opacity: 1, y: 0 },
};

export function Hero({
  onLaunchDashboard,
  onOpenAuth,
}: {
  onLaunchDashboard: () => void;
  onOpenAuth: (tab: "signin" | "signup") => void;
}) {
  const [syncSiem, setSyncSiem] = useState(true);
  const [syncCloud, setSyncCloud] = useState(false);
  const [syncEdr, setSyncEdr] = useState(true);
  const [toastMessage, setToastMessage] = useState("");
  const [scrolled, setScrolled] = useState(false);
  const [threatCount, setThreatCount] = useState(1247);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // Animate threat counter
  useEffect(() => {
    const id = setInterval(() => {
      setThreatCount((prev) => prev + Math.floor(Math.random() * 3));
    }, 2200);
    return () => clearInterval(id);
  }, []);

  const triggerFeedToggle = (
    feed: string,
    current: boolean,
    setter: (val: boolean) => void
  ) => {
    setter(!current);
    setToastMessage(`${feed} ${!current ? "Encrypted & Synced ✓" : "Disconnected"}`);
    setTimeout(() => setToastMessage(""), 2500);
  };

  return (
    <div className="relative w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-32 pb-24 overflow-visible">
      {/* ── Floating Curved Capsule Navbar ─────────────────────── */}
      <motion.header
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
        className={cn(
          "fixed top-4 left-1/2 -translate-x-1/2 z-50 w-[94%] max-w-5xl rounded-full px-5 sm:px-8 py-3 flex items-center justify-between transition-all duration-500",
          scrolled
            ? "neu-flat bg-[#eef3f8]/92 backdrop-blur-2xl border border-white/90 shadow-2xl shadow-slate-300/40"
            : "neu-flat bg-[#eef3f8]/80 backdrop-blur-xl border border-white/80 shadow-xl"
        )}
      >
        {/* Brand */}
        <div className="flex items-center gap-2.5">
          <div className="h-9 w-9 rounded-full bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center text-white shadow-md shadow-blue-500/25">
            <Shield className="w-4 h-4" />
          </div>
          <span className="text-base sm:text-lg font-black text-slate-800 tracking-tight font-mono">
            CYBERSENTINEL<span className="text-cyan-600">-X</span>
          </span>
        </div>

        {/* Center nav */}
        <nav className="hidden lg:flex items-center gap-0.5 bg-slate-200/50 p-1 rounded-full neu-pressed-sm border border-white/60">
          {[
            { href: "#features", label: "Capabilities" },
            { href: "#scenarios", label: "Threat Vectors" },
            { href: "#modules", label: "AI Forensics" },
          ].map((item) => (
            <a
              key={item.href}
              href={item.href}
              className="px-4 py-1.5 rounded-full text-xs font-semibold text-slate-600 hover:bg-white/90 hover:text-blue-600 hover:shadow-sm transition-all duration-200"
            >
              {item.label}
            </a>
          ))}
          <button
            onClick={onLaunchDashboard}
            className="px-4 py-1.5 rounded-full text-xs font-bold text-blue-700 hover:bg-white/90 transition-all duration-200"
          >
            Live SOC ↗
          </button>
        </nav>

        {/* Right CTAs */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => onOpenAuth("signin")}
            className="hidden sm:inline-flex items-center gap-1.5 text-xs font-bold text-slate-700 px-4 py-2 rounded-full neu-flat hover:bg-white transition-all active:scale-95"
          >
            <Lock className="w-3 h-3 text-cyan-600" />
            Sign In
          </button>
          <button
            onClick={onLaunchDashboard}
            className="px-5 py-2.5 rounded-full bg-[#1e2330] hover:bg-slate-900 text-white text-xs font-bold flex items-center gap-2 shadow-lg shadow-slate-900/25 active:scale-95 transition-all border border-slate-700"
          >
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Launch SOC</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </motion.header>

      {/* ── Toast ── */}
      {toastMessage && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="fixed top-20 left-1/2 -translate-x-1/2 z-50 px-4 py-2 rounded-full bg-slate-900/90 text-white text-xs font-mono border border-cyan-500/40 shadow-2xl flex items-center gap-2"
        >
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          <span>{toastMessage}</span>
        </motion.div>
      )}

      {/* ── Ambient Glow ── */}
      <div className="absolute top-16 left-1/2 -translate-x-1/2 w-[750px] h-[380px] bg-gradient-to-r from-blue-400/8 via-cyan-400/14 to-indigo-400/8 blur-[110px] rounded-full pointer-events-none" />

      {/* ── Hero Grid ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center relative z-10">
        {/* Left Column */}
        <motion.div
          variants={fadeUp}
          initial="initial"
          animate="animate"
          transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          className="lg:col-span-6 space-y-6"
        >
          {/* Status badge */}
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.1, duration: 0.5 }}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full neu-flat-sm text-[11px] font-mono font-bold text-slate-700 border border-white/80"
          >
            <span className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse" />
            <span>AUTONOMOUS SOC SUITE // v2.4 OPERATIONAL</span>
          </motion.div>

          {/* Headline */}
          <motion.h1
            variants={fadeUp}
            transition={{ delay: 0.15, duration: 0.7 }}
            className="text-4xl sm:text-5xl lg:text-6xl font-black text-slate-900 tracking-tight leading-[1.12]"
          >
            <EncryptedText
              text="Detect & Investigate"
              className="text-slate-900 tracking-tight"
              interval={20}
              autoReplay={true}
              startDelay={600}
            />
            <br />
            <span className="text-slate-800">cyber threats across</span>
            {" "}
            <span className="bg-clip-text text-transparent bg-gradient-to-r from-blue-600 via-cyan-500 to-indigo-600">
              enterprise assets
            </span>
          </motion.h1>

          {/* Subtext */}
          <motion.p
            variants={fadeUp}
            transition={{ delay: 0.25, duration: 0.6 }}
            className="text-sm md:text-base text-slate-600 leading-relaxed max-w-lg"
          >
            CyberSentinel-X unifies machine learning threat classification,
            autonomous AI forensic investigation, MITRE ATT&CK intelligence
            correlation, and tamper-evident cryptographic evidence ledger
            verification.
          </motion.p>

          {/* CTA buttons */}
          <motion.div
            variants={fadeUp}
            transition={{ delay: 0.3, duration: 0.6 }}
            className="flex flex-wrap items-center gap-4 pt-2"
          >
            <button
              onClick={onLaunchDashboard}
              className="group px-7 py-3.5 rounded-full bg-[#1e2330] hover:bg-black text-white text-xs font-bold flex items-center gap-2.5 shadow-xl shadow-slate-900/30 active:scale-95 transition-all relative overflow-hidden"
            >
              <span className="relative z-10">Explore SOC Console</span>
              <ArrowUpRight className="w-4 h-4 relative z-10 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
              <span className="absolute inset-0 bg-gradient-to-r from-blue-700/20 to-cyan-700/20 opacity-0 group-hover:opacity-100 transition-opacity" />
            </button>

            <button
              onClick={() => onOpenAuth("signup")}
              className="px-6 py-3.5 rounded-full neu-flat hover:bg-white text-slate-800 text-xs font-bold flex items-center gap-2 active:neu-pressed transition-all"
            >
              <Fingerprint className="w-4 h-4 text-blue-600" />
              <span>Create Analyst Account</span>
            </button>
          </motion.div>

          {/* Trust badges */}
          <motion.div
            variants={fadeUp}
            transition={{ delay: 0.4, duration: 0.6 }}
            className="pt-4 flex flex-wrap items-center gap-5 text-xs text-slate-500 font-mono"
          >
            {[
              { text: "MITRE ATT&CK v14.1" },
              { text: "SHA-256 Ledger" },
              { text: "96.4% Accuracy" },
            ].map((badge) => (
              <div key={badge.text} className="flex items-center gap-1.5">
                <Check className="w-4 h-4 text-emerald-600" />
                <span>{badge.text}</span>
              </div>
            ))}
          </motion.div>
        </motion.div>

        {/* Right Column: Visual composition */}
        <motion.div
          initial={{ opacity: 0, x: 30 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3, duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          className="lg:col-span-6 relative flex items-center justify-center min-h-[500px]"
        >
          {/* Main hero card */}
          <div className="relative w-full max-w-md h-[460px] rounded-3xl overflow-hidden shadow-2xl neu-flat border border-white/80 flex items-end justify-center">
            {/* Gradient background */}
            <div className="absolute inset-0 bg-gradient-to-b from-[#6b8fa3] via-[#3a5f7a] to-[#1e3548]" />

            {/* Cyber grid pattern */}
            <div
              className="absolute inset-0 opacity-15"
              style={{
                backgroundImage:
                  "linear-gradient(rgba(6,182,212,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(6,182,212,0.3) 1px, transparent 1px)",
                backgroundSize: "24px 24px",
              }}
            />

            {/* Animated scan line */}
            <motion.div
              className="absolute left-0 right-0 h-px bg-cyan-400/50 pointer-events-none"
              initial={{ top: "0%" }}
              animate={{ top: "100%" }}
              transition={{
                duration: 3,
                repeat: Infinity,
                ease: "linear",
                repeatType: "loop",
              }}
              style={{ boxShadow: "0 0 12px 2px rgba(6,182,212,0.4)" }}
            />

            {/* Radar glow */}
            <div className="absolute top-4 right-4 w-56 h-56 bg-cyan-400/8 rounded-full blur-2xl pointer-events-none" />

            {/* Analyst image */}
            <div className="relative w-72 h-80 z-10">
              <Image
                src="https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?q=80&w=800&auto=format&fit=crop"
                alt="Lead SOC Analyst"
                fill
                sizes="300px"
                className="object-cover object-top"
                style={{ borderRadius: "12px 12px 0 0" }}
              />
            </div>

            {/* Live threat counter overlay */}
            <div className="absolute top-4 left-4 z-20 px-3 py-2 rounded-xl bg-black/60 backdrop-blur-md border border-cyan-500/30 font-mono">
              <div className="text-[9px] text-cyan-400/80 uppercase tracking-wider mb-0.5">Threats Blocked</div>
              <div className="text-lg font-black text-cyan-300" style={{ textShadow: "0 0 12px rgba(6,182,212,0.8)" }}>
                {threatCount.toLocaleString()}
              </div>
            </div>
          </div>

          {/* Floating Card 1: Sync security feeds */}
          <motion.div
            initial={{ opacity: 0, y: -16, rotate: -3 }}
            animate={{ opacity: 1, y: 0, rotate: 0 }}
            transition={{ delay: 0.6, duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
            className="absolute -top-4 right-2 md:right-6 z-20 w-52 bg-white/96 backdrop-blur-md rounded-2xl p-4 neu-flat-sm border border-white shadow-2xl"
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider font-mono">
                Sync security feeds
              </span>
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            </div>
            <div className="space-y-2.5 text-xs">
              {[
                { key: "SIEM", label: "SIEM Gateway", state: syncSiem, setter: setSyncSiem, color: "cyan" },
                { key: "Cloud", label: "CloudTrail", state: syncCloud, setter: setSyncCloud, color: "blue" },
                { key: "EDR", label: "EDR Agents", state: syncEdr, setter: setSyncEdr, color: "indigo" },
              ].map((item) => (
                <div key={item.key} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className={`w-5 h-5 rounded-md bg-${item.color}-100 text-${item.color}-700 flex items-center justify-center text-[10px] font-bold`}>
                      {item.key[0]}
                    </div>
                    <span className="text-slate-700 text-[11px] font-semibold">{item.label}</span>
                  </div>
                  <button
                    onClick={() => triggerFeedToggle(item.label, item.state, item.setter)}
                    className={cn(
                      "w-8 h-4 rounded-full transition-colors relative flex items-center px-0.5",
                      item.state ? "bg-emerald-500" : "bg-slate-300"
                    )}
                  >
                    <span
                      className={cn(
                        "w-3 h-3 rounded-full bg-white transition-transform",
                        item.state && "translate-x-4"
                      )}
                    />
                  </button>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Floating Metrics */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.75, duration: 0.6 }}
            className="absolute top-14 -right-2 md:-right-8 z-20 text-right bg-white/96 backdrop-blur-md px-4 py-2.5 rounded-2xl neu-flat-sm border border-white shadow-lg"
          >
            <div className="text-2xl font-black text-slate-800 tracking-tight font-mono">120+</div>
            <div className="text-[10px] font-semibold text-slate-500 font-mono">Telemetry Feeds</div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.85, duration: 0.6 }}
            className="absolute top-36 -right-2 md:-right-8 z-20 text-right bg-white/96 backdrop-blur-md px-4 py-2.5 rounded-2xl neu-flat-sm border border-white shadow-lg"
          >
            <div className="text-2xl font-black text-slate-800 tracking-tight font-mono">30+</div>
            <div className="text-[10px] font-semibold text-slate-500 font-mono">AI Threat Rules</div>
          </motion.div>

          {/* Evidence locked pill */}
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.95, duration: 0.5, type: "spring" }}
            className="absolute bottom-32 -right-4 z-20"
          >
            <div className="px-4 py-1.5 rounded-full bg-[#f97316] text-white text-[11px] font-bold flex items-center gap-1.5 shadow-xl shadow-orange-500/30">
              <span className="w-2 h-2 rounded-full bg-white animate-ping" />
              <span>Evidence locked</span>
            </div>
          </motion.div>

          {/* Bottom-left: Assigned Analysts */}
          <motion.div
            initial={{ opacity: 0, y: 16, rotate: 2 }}
            animate={{ opacity: 1, y: 0, rotate: 0 }}
            transition={{ delay: 0.7, duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
            className="absolute -bottom-6 -left-4 md:-left-8 z-20 w-56 bg-white/96 backdrop-blur-md rounded-2xl p-4 neu-flat-sm border border-white shadow-2xl"
          >
            <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2.5 font-mono">
              Assigned Analysts
            </div>
            <div className="space-y-2.5">
              {[
                { initials: "21", label: "21 Threat Hunters", sub: "Active 8 days ago", gradient: "from-cyan-500 to-blue-500", isActive: false },
                { initials: "DP", label: "Darcy Patterson", sub: "Active now", gradient: "from-emerald-500 to-teal-500", isActive: true },
                { initials: "AH", label: "Alex Hamilton", sub: "Active 3 days ago", gradient: "from-amber-500 to-orange-500", isActive: false },
              ].map((a) => (
                <div key={a.initials} className="flex items-center gap-2.5">
                  <div className={`w-7 h-7 rounded-full bg-gradient-to-tr ${a.gradient} text-white flex items-center justify-center text-[10px] font-bold font-mono shrink-0`}>
                    {a.initials}
                  </div>
                  <div>
                    <div className="text-xs font-bold text-slate-800">{a.label}</div>
                    <div className={`text-[10px] font-semibold flex items-center gap-1 ${a.isActive ? "text-emerald-600" : "text-slate-400 font-mono"}`}>
                      {a.isActive && <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />}
                      {a.sub}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        </motion.div>
      </div>
    </div>
  );
}
