"use client";
import React, { useState, useRef } from "react";
import { motion, useInView, AnimatePresence } from "framer-motion";
import {
  Cpu,
  BrainCircuit,
  FileCheck2,
  Gauge,
  CheckCircle2,
  ArrowRight,
  Sparkles,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";

const FEATURES = [
  {
    id: "detection",
    title: "ML Threat Detection",
    badge: "RANDOM FOREST v2.4",
    icon: Cpu,
    iconColor: "text-cyan-600",
    iconBg: "bg-cyan-50",
    glowColor: "rgba(6,182,212,0.15)",
    tagline: "Multivariate Flow Analysis with 96.4% Precision",
    description:
      "Continuously evaluates network flow sequences, inter-arrival times, payload entropies, and connection velocity to detect credential stuffing, volumetric reflection floods, and stealthy SYN sweeps before payload detonation.",
    metrics: [
      { label: "Accuracy", value: "96.4%", color: "text-cyan-700" },
      { label: "Recall Rate", value: "94.9%", color: "text-blue-700" },
      { label: "False Positive", value: "3.2%", color: "text-emerald-700" },
    ],
    preview: {
      header: "Live Detection Pipeline",
      sub: "CICIDS2017 & Flow Baseline Engine",
      points: [
        "Zero-day anomaly flagging using decision trees",
        "Automated threshold adaptation based on network baselines",
        "Sub-150ms classification latency on 10Gbps streams",
      ],
      cmd: "detection",
    },
  },
  {
    id: "investigation",
    title: "Autonomous AI Forensics",
    badge: "MITRE ATT&CK v14.1",
    icon: BrainCircuit,
    iconColor: "text-indigo-600",
    iconBg: "bg-indigo-50",
    glowColor: "rgba(99,102,241,0.15)",
    tagline: "Contextual Investigation & Plain-English Explanations",
    description:
      "Bridges the gap between raw alerts and human understanding. Autonomous agentic steps correlate indicators with known adversary tactics (T1110, T1498), assess attack vectors, and formulate immediate tactical remediation advice.",
    metrics: [
      { label: "Investigation Time", value: "< 2 min", color: "text-indigo-700" },
      { label: "MITRE Coverage", value: "100%", color: "text-purple-700" },
      { label: "Findings Clarity", value: "L3 Grade", color: "text-cyan-700" },
    ],
    preview: {
      header: "7-Stage Investigation Matrix",
      sub: "Autonomous Reasoning Co-Pilot",
      points: [
        "Automated alert validation & network baseline comparison",
        "Adversary TTP identification & IOC reputation query",
        "Prescribed remediation steps generated for instant execution",
      ],
      cmd: "investigation",
    },
  },
  {
    id: "evidence",
    title: "Immutable Evidence Ledger",
    badge: "SHA-256 INTEGRITY",
    icon: FileCheck2,
    iconColor: "text-emerald-600",
    iconBg: "bg-emerald-50",
    glowColor: "rgba(16,185,129,0.15)",
    tagline: "Tamper-Evident Chain of Custody for Forensic Artifacts",
    description:
      "Guarantees that raw authentication logs, memory dumps, and PCAP recordings have not been altered or purged. Every artifact is cryptographically hashed at the moment of capture with verifiable runtime verification.",
    metrics: [
      { label: "Hash Match", value: "100%", color: "text-emerald-700" },
      { label: "Ledger Blocks", value: "4 Verified", color: "text-teal-700" },
      { label: "Integrity Checks", value: "Continuous", color: "text-green-700" },
    ],
    preview: {
      header: "Cryptographic Proof of Authenticity",
      sub: "Court-Admissible Forensic Integrity",
      points: [
        "Real-time SHA-256 runtime comparison against ledger records",
        "Zero tolerance for bit-rot or malicious tampering",
        "Instant export of verifiable evidence certificates",
      ],
      cmd: "evidence",
    },
  },
  {
    id: "risk",
    title: "Quantified Risk Engine",
    badge: "DYNAMIC SCORING",
    icon: Gauge,
    iconColor: "text-orange-600",
    iconBg: "bg-orange-50",
    glowColor: "rgba(249,115,22,0.15)",
    tagline: "Context-Aware 0-100 Risk Prioritization",
    description:
      "Eliminates alert fatigue by synthesizing attack severity, classifier confidence, asset criticality, and external threat intelligence into a single, actionable score to direct tier-1 and tier-2 analyst triage where it matters most.",
    metrics: [
      { label: "Risk Scale", value: "0-100", color: "text-orange-700" },
      { label: "Factors", value: "6 Vectors", color: "text-amber-700" },
      { label: "Triage Speed", value: "4.8×", color: "text-red-700" },
    ],
    preview: {
      header: "Multi-Factor Scoring Matrix",
      sub: "Normalized Threat Weighting",
      points: [
        "Weighted criticality for crown-jewel authentication servers",
        "Model confidence weighting preventing low-certainty alarms",
        "Dynamic SLA elevation for recurring adversary source IPs",
      ],
      cmd: "risk",
    },
  },
];

export function FeaturesSection({
  onLaunchConsole,
}: {
  onLaunchConsole: () => void;
}) {
  const [activeTab, setActiveTab] = useState(0);
  const sectionRef = useRef<HTMLElement>(null);
  const isInView = useInView(sectionRef, { once: true, margin: "-80px" });

  const current = FEATURES[activeTab];
  const Icon = current.icon;

  return (
    <section
      ref={sectionRef}
      id="features"
      className="py-28 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative"
    >
      {/* Ambient background glow */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[900px] h-[400px] bg-gradient-to-r from-blue-100/60 via-cyan-100/40 to-indigo-100/60 blur-[100px] rounded-full" />
      </div>

      {/* Section Header */}
      <motion.div
        initial={{ opacity: 0, y: 24 }}
        animate={isInView ? { opacity: 1, y: 0 } : {}}
        transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
        className="text-center max-w-3xl mx-auto mb-16 space-y-3"
      >
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full neu-flat-sm text-[11px] font-mono font-bold text-blue-600 border border-white">
          <Sparkles className="w-3.5 h-3.5" />
          <span>CYBERSENTINEL-X CORE ARCHITECTURE</span>
        </div>
        <h2 className="text-3xl md:text-5xl font-black text-slate-900 tracking-tight">
          Next-Generation{" "}
          <span className="bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-cyan-500">
            Defense Pillars
          </span>
        </h2>
        <p className="text-xs sm:text-sm text-slate-600 leading-relaxed max-w-xl mx-auto">
          Explore the modular technology stack designed to empower modern Security
          Operations Centers with autonomous speed and forensic certainty.
        </p>
      </motion.div>

      {/* Tab pills */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={isInView ? { opacity: 1, y: 0 } : {}}
        transition={{ delay: 0.15, duration: 0.6 }}
        className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-8"
      >
        {FEATURES.map((feat, idx) => {
          const FeatIcon = feat.icon;
          return (
            <motion.button
              key={feat.id}
              onClick={() => setActiveTab(idx)}
              whileHover={{ y: -2, scale: 1.01 }}
              whileTap={{ scale: 0.98 }}
              className={cn(
                "p-4 rounded-2xl text-left transition-all duration-300 border flex flex-col justify-between min-h-[110px] relative overflow-hidden",
                activeTab === idx
                  ? "neu-pressed bg-white text-blue-700 border-blue-300/60 shadow-inner"
                  : "neu-flat hover:bg-white text-slate-700 border-white/80"
              )}
            >
              {/* Active indicator dot */}
              {activeTab === idx && (
                <motion.div
                  layoutId="active-tab-indicator"
                  className="absolute top-3 right-3 w-2 h-2 rounded-full bg-blue-500"
                  style={{ boxShadow: "0 0 8px rgba(59,130,246,0.7)" }}
                />
              )}
              <div className="flex items-center gap-3">
                <div className={cn("p-2 rounded-xl neu-flat-sm", feat.iconBg)}>
                  <FeatIcon className={cn("w-4 h-4", feat.iconColor)} />
                </div>
              </div>
              <div>
                <div className="font-extrabold text-xs sm:text-sm tracking-tight text-slate-800 mt-2">
                  {feat.title}
                </div>
                <div className="text-[9px] font-mono text-slate-500 font-semibold mt-0.5">
                  {feat.badge}
                </div>
              </div>
            </motion.button>
          );
        })}
      </motion.div>

      {/* Main showcase card */}
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 16, scale: 0.99 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -10, scale: 0.99 }}
          transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
          className="neu-flat rounded-3xl p-6 md:p-10 border border-white bg-white/80 shadow-xl relative overflow-hidden"
        >
          {/* Ambient glow based on active tab */}
          <div
            className="absolute inset-0 pointer-events-none rounded-3xl"
            style={{
              background: `radial-gradient(ellipse at top right, ${current.glowColor} 0%, transparent 60%)`,
            }}
          />

          <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
            {/* Left: Text */}
            <div className="lg:col-span-7 space-y-6">
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Icon className={cn("w-5 h-5", current.iconColor)} />
                  <span className={cn("text-xs font-mono font-bold uppercase tracking-wider", current.iconColor)}>
                    {current.badge}
                  </span>
                </div>
                <h3 className="text-2xl md:text-3xl font-extrabold text-slate-900 tracking-tight">
                  {current.tagline}
                </h3>
                <p className="text-xs sm:text-sm text-slate-600 leading-relaxed pt-1">
                  {current.description}
                </p>
              </div>

              {/* Metrics */}
              <div className="grid grid-cols-3 gap-3">
                {current.metrics.map((m, i) => (
                  <motion.div
                    key={m.label}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.07 }}
                    className="neu-flat-sm rounded-xl p-3.5 bg-white/90 border border-white"
                  >
                    <div className={cn("text-xl sm:text-2xl font-black font-mono tracking-tight", m.color)}>
                      {m.value}
                    </div>
                    <div className="text-[10px] text-slate-500 font-mono uppercase mt-0.5">
                      {m.label}
                    </div>
                  </motion.div>
                ))}
              </div>

              <button
                onClick={onLaunchConsole}
                className="group px-6 py-3 rounded-full bg-[#1e2330] hover:bg-black text-white text-xs font-bold flex items-center gap-2 shadow-lg shadow-slate-900/20 active:scale-95 transition-all"
              >
                <span>Launch in Live SOC Console</span>
                <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
              </button>
            </div>

            {/* Right: Dark preview terminal */}
            <div className="lg:col-span-5 bg-gradient-to-br from-slate-900 via-[#0d1627] to-[#070d18] rounded-2xl p-6 border border-slate-700/80 text-white shadow-2xl relative overflow-hidden font-mono text-xs space-y-4">
              {/* Ambient glow */}
              <div
                className="absolute top-0 right-0 w-32 h-32 rounded-full blur-3xl pointer-events-none"
                style={{ background: current.glowColor }}
              />

              {/* Header */}
              <div className="relative flex items-center justify-between border-b border-slate-700/80 pb-3">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
                  <span className="text-[11px] font-bold text-slate-200">
                    {current.preview.header}
                  </span>
                </div>
                <span className="text-[9px] text-emerald-400 bg-emerald-950/70 px-2 py-0.5 rounded border border-emerald-500/30">
                  ACTIVE
                </span>
              </div>

              <div className="text-[10px] text-slate-400">
                SUB-SYSTEM: {current.preview.sub}
              </div>

              {/* Points */}
              <div className="space-y-3">
                {current.preview.points.map((pt, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.1 + i * 0.08 }}
                    className="flex items-start gap-2.5 text-slate-200"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                    <span className="text-[11px] leading-relaxed">{pt}</span>
                  </motion.div>
                ))}
              </div>

              {/* Terminal cmd */}
              <div className="p-3 bg-black/60 rounded-xl border border-slate-800 space-y-1 text-[10px]">
                <div className="text-cyan-400">
                  $ cybersentinel-x core-check --module {current.preview.cmd}
                </div>
                <div className="text-emerald-400">
                  ✓ Cryptographic checksum matched (0x8F91)
                </div>
                <div className="text-slate-300">
                  ✓ Real-time telemetry feed latency: 12ms
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </AnimatePresence>
    </section>
  );
}
