"use client";
import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  ShieldCheck,
  ArrowUpRight,
  Radio,
  Lock,
  Cpu,
  Globe,
  Database,
  Terminal,
  Clock,
  Sparkles,
  CheckCircle2,
  Send,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";

export function Footer({
  onOpenAuth,
  onNavigate,
}: {
  onOpenAuth?: (tab: "signin" | "signup" | "recovery") => void;
  onNavigate?: (page: string) => void;
}) {
  const [mounted, setMounted] = useState(false);
  const [currentTime, setCurrentTime] = useState("");
  const [emailInput, setEmailInput] = useState("");
  const [subscribed, setSubscribed] = useState(false);

  useEffect(() => {
    setMounted(true);
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(
        `${now.toUTCString().slice(17, 25)} UTC · DEFCON 4 · PATROL ACTIVE`
      );
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  const handleSubscribe = (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailInput.trim()) return;
    setSubscribed(true);
    setTimeout(() => {
      setEmailInput("");
    }, 2500);
  };

  return (
    <footer className="relative bg-[#050810] text-slate-300 pt-20 pb-12 overflow-hidden border-t border-slate-800 selection:bg-[#6F3DFF] selection:text-white">
      {/* Ambient Glow Orbs */}
      <div className="absolute top-0 left-1/4 w-[600px] h-[350px] bg-[#6F3DFF]/[0.10] blur-[140px] rounded-full pointer-events-none" />
      <div className="absolute bottom-0 right-1/4 w-[500px] h-[300px] bg-[#BFE9FF]/[0.08] blur-[120px] rounded-full pointer-events-none" />

      {/* Cyber Grid Background */}
      <div
        className="absolute inset-0 opacity-[0.03] pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(#6F3DFF 1px, transparent 1px), linear-gradient(90deg, #6F3DFF 1px, transparent 1px)",
          backgroundSize: "60px 60px",
        }}
      />

      <div className="max-w-7xl mx-auto px-6 md:px-10 relative z-10">
        {/* Real-Time Sentinel Subsystems Status Ticker */}
        <div className="mb-12 grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3 rounded-2xl bg-slate-900/80 border border-emerald-500/30 flex items-center gap-3">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shrink-0" />
            <div>
              <div className="text-[10px] font-mono font-bold text-emerald-400">CORE ML ENGINE</div>
              <div className="text-[11px] font-mono text-slate-300">Random Forest · 99.8%</div>
            </div>
          </div>

          <div className="p-3 rounded-2xl bg-slate-900/80 border border-blue-500/30 flex items-center gap-3">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-400 animate-pulse shrink-0" />
            <div>
              <div className="text-[10px] font-mono font-bold text-blue-400">PACKET SNIFFER</div>
              <div className="text-[11px] font-mono text-slate-300">Npcap / Scapy · 25GB Stream</div>
            </div>
          </div>

          <div className="p-3 rounded-2xl bg-slate-900/80 border border-purple-500/30 flex items-center gap-3">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-400 animate-pulse shrink-0" />
            <div>
              <div className="text-[10px] font-mono font-bold text-purple-400">EVIDENCE LEDGER</div>
              <div className="text-[11px] font-mono text-slate-300">SHA-256 Tamper-Proof</div>
            </div>
          </div>

          <div className="p-3 rounded-2xl bg-slate-900/80 border border-cyan-500/30 flex items-center gap-3">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse shrink-0" />
            <div>
              <div className="text-[10px] font-mono font-bold text-cyan-400">THREAT INTEL</div>
              <div className="text-[11px] font-mono text-slate-300">MITRE ATT&CK v14.1</div>
            </div>
          </div>
        </div>

        {/* Newsletter & Direct Launch Banner */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="mb-16 p-8 rounded-3xl border border-[#6F3DFF]/40 relative overflow-hidden shadow-2xl"
          style={{
            background:
              "linear-gradient(135deg, rgba(111,61,255,0.15) 0%, rgba(10,15,30,0.92) 50%, rgba(191,233,255,0.08) 100%)",
          }}
        >
          {/* Animated border shimmer */}
          <motion.div
            className="absolute inset-0 rounded-3xl pointer-events-none"
            style={{
              background:
                "linear-gradient(90deg, transparent, rgba(191,233,255,0.3), rgba(111,61,255,0.35), transparent)",
              backgroundSize: "200% 100%",
            }}
            animate={{ backgroundPosition: ["0% 50%", "200% 50%"] }}
            transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
          />

          <div className="relative z-10 flex flex-col lg:flex-row items-center justify-between gap-8">
            <div className="max-w-xl">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#6F3DFF]/20 border border-[#BFE9FF]/30 text-[#BFE9FF] text-xs font-mono font-bold mb-3">
                <Sparkles className="w-3.5 h-3.5" />
                <span>ENTERPRISE SOC INCIDENT DISPATCH</span>
              </div>
              <h3 className="text-xl md:text-2xl font-black text-white tracking-tight">
                Empower your SOC with Autonomous AI Threat Defense
              </h3>
              <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                Connect your network adapters or stream 12+ GB raw PCAPs with zero RAM exhaustion.
                Detect DoS, DDoS, PortScan, and Botnets with 99.8% precision.
              </p>
            </div>

            <div className="flex flex-col sm:flex-row items-center gap-3 w-full lg:w-auto">
              <button
                onClick={() => onNavigate?.("dashboard")}
                className="w-full sm:w-auto px-7 py-3.5 rounded-2xl bg-gradient-to-r from-[#6F3DFF] via-[#855bff] to-[#4e19d9] hover:from-[#7c4dff] hover:to-[#5c24e6] text-white text-xs font-bold flex items-center justify-center gap-2.5 shadow-xl shadow-[#6F3DFF]/30 hover:shadow-[#6F3DFF]/50 transition-all active:scale-95 border border-[#BFE9FF]/40"
              >
                <Radio className="w-4 h-4 text-[#BFE9FF] animate-pulse" />
                <span>Launch Live SOC Console</span>
              </button>

              <button
                onClick={() => onOpenAuth?.("signup")}
                className="w-full sm:w-auto px-6 py-3.5 rounded-2xl border border-slate-700 bg-slate-900/60 hover:bg-slate-800 text-slate-200 text-xs font-bold hover:border-slate-500 transition-all active:scale-95"
              >
                Create Analyst Account
              </button>
            </div>
          </div>
        </motion.div>

        {/* 5-Column Navigation Matrix */}
        <div className="grid grid-cols-2 md:grid-cols-12 gap-8 pb-16 border-b border-slate-800/80">
          {/* Brand Column */}
          <div className="col-span-2 md:col-span-4 space-y-4">
            <div className="flex items-center gap-3">
              <motion.div
                className="w-10 h-10 rounded-2xl bg-gradient-to-tr from-[#6F3DFF] via-[#855bff] to-[#BFE9FF] flex items-center justify-center text-white shadow-lg shadow-[#6F3DFF]/30 border border-white/40"
                whileHover={{ rotate: 12, scale: 1.1 }}
                transition={{ type: "spring", stiffness: 300 }}
              >
                <ShieldCheck className="w-6 h-6 text-white" />
              </motion.div>
              <span className="text-2xl font-black tracking-tight text-white font-mono">
                CyberSentinel<span className="text-[#6F3DFF]">-X</span>
              </span>
            </div>

            <p className="text-xs text-slate-400 max-w-sm leading-relaxed">
              AI-driven framework for cyber threat detection, automated investigation, threat intelligence,
              and tamper-evident forensic evidence integrity.
            </p>

            {/* Live UTC Ticker */}
            {mounted && (
              <div className="flex items-center gap-2 text-[10px] font-mono text-cyan-400 bg-cyan-950/40 px-3 py-1.5 rounded-xl border border-cyan-500/20 w-fit">
                <Clock className="w-3.5 h-3.5 animate-spin" style={{ animationDuration: "12s" }} />
                <span>{currentTime}</span>
              </div>
            )}

            {/* Technology Stack Pills */}
            <div className="flex flex-wrap gap-1.5 pt-1">
              {[
                "Next.js 15",
                "FastAPI",
                "Scapy Engine",
                "Random Forest",
                "SHA-256 Chain",
                "MITRE ATT&CK",
              ].map((tech) => (
                <span
                  key={tech}
                  className="px-2.5 py-1 rounded-lg text-[9px] font-mono font-bold border border-slate-800 text-slate-400 bg-slate-900/80"
                >
                  {tech}
                </span>
              ))}
            </div>
          </div>

          {/* Col 1: SOC Modules */}
          <div className="col-span-1 md:col-span-2 space-y-3">
            <h4 className="text-xs font-mono font-bold text-white uppercase tracking-wider">SOC Modules</h4>
            <ul className="space-y-2 text-xs text-slate-400">
              {[
                { label: "Executive SOC Hub", page: "dashboard" },
                { label: "Live Traffic Sniffer", page: "monitoring" },
                { label: "Alerts Matrix", page: "alerts" },
                { label: "AI Investigation", page: "investigation" },
                { label: "Threat Intelligence", page: "threat-intel" },
                { label: "Evidence Ledger", page: "evidence" },
              ].map((item) => (
                <li key={item.page}>
                  <button
                    onClick={() => onNavigate?.(item.page)}
                    className="hover:text-[#BFE9FF] transition-colors text-left flex items-center gap-1 group"
                  >
                    <span className="text-slate-600 group-hover:text-cyan-400">&gt;</span>
                    <span>{item.label}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>

          {/* Col 2: Threat Matrix */}
          <div className="col-span-1 md:col-span-2 space-y-3">
            <h4 className="text-xs font-mono font-bold text-white uppercase tracking-wider">Attack Classes</h4>
            <ul className="space-y-2 text-xs text-slate-400 font-mono">
              {[
                "DDoS / DoS LOIC",
                "PortScan & Recon",
                "FTP/SSH Brute Force",
                "Web SQL Injection",
                "Infiltration & Bot",
                "Zero-Day Anomaly",
              ].map((atk) => (
                <li key={atk} className="flex items-center gap-1.5 text-slate-400 hover:text-rose-400 transition-colors">
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-500/70" />
                  <span>{atk}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Col 3: Research & Docs */}
          <div className="col-span-1 md:col-span-2 space-y-3">
            <h4 className="text-xs font-mono font-bold text-white uppercase tracking-wider">Standards</h4>
            <ul className="space-y-2 text-xs text-slate-400">
              {[
                { label: "CICIDS2017 Dataset", href: "https://www.unb.ca/cic/datasets/ids-2017.html" },
                { label: "MITRE ATT&CK v14", href: "https://attack.mitre.org" },
                { label: "Npcap Packet Capture", href: "https://npcap.com" },
                { label: "RFC 2131 Protocol", href: "https://datatracker.ietf.org/doc/html/rfc2131" },
              ].map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:text-[#BFE9FF] transition-colors flex items-center gap-1"
                  >
                    <span>{link.label}</span>
                    <ArrowUpRight className="w-3 h-3 opacity-60 text-cyan-400" />
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Col 4: Dispatch Subscriptions */}
          <div className="col-span-1 md:col-span-2 space-y-3">
            <h4 className="text-xs font-mono font-bold text-white uppercase tracking-wider">Intel Dispatch</h4>
            <p className="text-[11px] text-slate-400">
              Subscribe to zero-day CVE advisories & CICIDS heuristic signature updates.
            </p>
            <form onSubmit={handleSubscribe} className="space-y-2">
              <input
                type="email"
                value={emailInput}
                onChange={(e) => setEmailInput(e.target.value)}
                placeholder="analyst@soc.mil"
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
              />
              <button
                type="submit"
                className="w-full py-2 px-3 rounded-xl bg-[#6F3DFF] hover:bg-[#855bff] text-white text-xs font-bold transition-all flex items-center justify-center gap-1.5"
              >
                {subscribed ? (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-300" />
                    <span>Dispatched!</span>
                  </>
                ) : (
                  <>
                    <Send className="w-3.5 h-3.5" />
                    <span>Subscribe</span>
                  </>
                )}
              </button>
            </form>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="pt-8 flex flex-col md:flex-row items-center justify-between gap-4 text-[11px] text-slate-500 font-mono">
          <div className="flex flex-wrap items-center gap-6">
            <div className="flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-[#6F3DFF]" />
              <span>TLS 1.3 / AES-256-GCM</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-[#BFE9FF]" />
              <span>CICIDS2017 ML CLASSIFIER</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5 text-emerald-400" />
              <span>FORENSIC LEDGER SHA-256</span>
            </div>
          </div>

          <div>
            © 2026 CYBERSENTINEL-X PLATFORM · ALL RIGHTS RESERVED
          </div>
        </div>
      </div>

      {/* Giant Embossed Watermark Background */}
      <div className="relative w-full overflow-hidden select-none pointer-events-none mt-12">
        <h1
          className="text-[13vw] font-black tracking-tighter leading-none whitespace-nowrap text-center uppercase font-mono"
          style={{
            background:
              "linear-gradient(180deg, rgba(111,61,255,0.12) 0%, rgba(191,233,255,0.04) 50%, transparent 100%)",
            WebkitBackgroundClip: "text",
            backgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          CyberSentinel-X
        </h1>
      </div>
    </footer>
  );
}
