"use client";
import React, { useState, useEffect, useRef } from "react";
import Image from "next/image";
import { motion, useMotionValue, useTransform, useInView } from "framer-motion";
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
  Cpu,
  Radio,
  ShieldCheck,
} from "lucide-react";
import { EncryptedText } from "@/components/ui/encrypted-text";
import { cn } from "@/lib/utils";

const fadeUp = {
  initial: { opacity: 0, y: 28 },
  animate: { opacity: 1, y: 0 },
};

/* ── Animated stat counter ── */
function AnimatedCounter({ end, duration = 2000, suffix = "" }: { end: number; duration?: number; suffix?: string }) {
  const [count, setCount] = useState(0);
  const ref = useRef<HTMLSpanElement>(null);
  const isInView = useInView(ref, { once: true });

  useEffect(() => {
    if (!isInView) return;
    const startTime = Date.now();
    const timer = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
      setCount(Math.floor(eased * end));
      if (progress >= 1) clearInterval(timer);
    }, 16);
    return () => clearInterval(timer);
  }, [isInView, end, duration]);

  return <span ref={ref}>{count.toLocaleString()}{suffix}</span>;
}

/* ── Floating particle dots ── */
function FloatingDot({ delay, x, y, color = "#BFE9FF" }: { delay: number; x: string; y: string; color?: string }) {
  return (
    <motion.div
      className="absolute w-1.5 h-1.5 rounded-full pointer-events-none"
      style={{ left: x, top: y, backgroundColor: color, boxShadow: `0 0 10px ${color}` }}
      animate={{
        y: [0, -18, 0, 18, 0],
        opacity: [0.25, 0.8, 0.25],
      }}
      transition={{
        duration: 5 + Math.random() * 3,
        delay,
        repeat: Infinity,
        ease: "easeInOut",
      }}
    />
  );
}

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

  const heroRef = useRef<HTMLDivElement>(null);
  const mouseX = useMotionValue(0);
  const mouseY = useMotionValue(0);

  const gradientX = useTransform(mouseX, [0, 1], ["30%", "70%"]);
  const gradientY = useTransform(mouseY, [0, 1], ["30%", "70%"]);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // Mouse parallax for background gradient
  useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      mouseX.set(e.clientX / window.innerWidth);
      mouseY.set(e.clientY / window.innerHeight);
    };
    window.addEventListener("mousemove", onMouseMove);
    return () => window.removeEventListener("mousemove", onMouseMove);
  }, [mouseX, mouseY]);

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
    <div ref={heroRef} className="relative w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-32 pb-24 overflow-visible">
      {/* ── Floating Curved Capsule Navbar ─────────────────────── */}
      <motion.header
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
        className={cn(
          "fixed top-4 left-1/2 -translate-x-1/2 z-50 w-[94%] max-w-5xl rounded-full px-5 sm:px-8 py-3 flex items-center justify-between transition-all duration-500",
          scrolled
            ? "glass-premium shadow-2xl shadow-slate-300/40"
            : "neu-flat bg-[#eef3f8]/80 backdrop-blur-xl border border-white/80 shadow-xl"
        )}
      >
        {/* Brand */}
        <div className="flex items-center gap-2.5">
          <motion.div
            className="h-9 w-9 rounded-full bg-gradient-to-tr from-[#6F3DFF] via-[#855bff] to-[#BFE9FF] flex items-center justify-center text-white shadow-md shadow-[#6F3DFF]/30 border border-white/50"
            whileHover={{ scale: 1.1, rotate: 10 }}
            transition={{ type: "spring", stiffness: 300 }}
          >
            <Shield className="w-4 h-4 text-white" />
          </motion.div>
          <span className="text-base sm:text-lg font-black text-slate-800 tracking-tight font-mono">
            CYBERSENTINEL<span className="text-[#6F3DFF]">-X</span>
          </span>
        </div>

        {/* Center nav */}
        <nav className="hidden lg:flex items-center gap-0.5 bg-slate-200/50 p-1 rounded-full neu-pressed-sm border border-[#B7B7B7]/40">
          {[
            { href: "#features", label: "Capabilities" },
            { href: "#scenarios", label: "Threat Vectors" },
            { href: "#modules", label: "AI Forensics" },
          ].map((item) => (
            <a
              key={item.href}
              href={item.href}
              className="px-4 py-1.5 rounded-full text-xs font-semibold text-slate-600 hover:bg-white/90 hover:text-[#6F3DFF] hover:shadow-sm transition-all duration-200 neon-underline"
            >
              {item.label}
            </a>
          ))}
          <button
            onClick={onLaunchDashboard}
            className="px-4 py-1.5 rounded-full text-xs font-bold text-[#6F3DFF] hover:bg-white/90 transition-all duration-200 flex items-center gap-1"
          >
            Live SOC <span className="text-[#BFE9FF] bg-[#6F3DFF] text-[9px] px-1.5 py-0.5 rounded-full">LIVE</span>
          </button>
        </nav>

        {/* Right CTAs */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => onOpenAuth("signin")}
            className="hidden sm:inline-flex items-center gap-1.5 text-xs font-bold text-slate-700 px-4 py-2 rounded-full neu-flat hover:bg-white transition-all active:scale-95 border border-[#B7B7B7]/30"
          >
            <Lock className="w-3 h-3 text-[#6F3DFF]" />
            Sign In
          </button>
          <motion.button
            onClick={onLaunchDashboard}
            className="px-5 py-2.5 rounded-full bg-gradient-to-r from-[#6F3DFF] to-[#4e19d9] hover:from-[#7c4dff] hover:to-[#5c24e6] text-white text-xs font-bold flex items-center gap-2 shadow-lg shadow-[#6F3DFF]/30 active:scale-95 transition-all border border-[#BFE9FF]/30 relative overflow-hidden"
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.97 }}
          >
            <span className="w-2 h-2 rounded-full bg-[#BFE9FF] animate-pulse shadow-sm shadow-[#BFE9FF]" />
            <span>Launch SOC</span>
            <ArrowUpRight className="w-3.5 h-3.5 text-[#BFE9FF]" />
            {/* Subtle shimmer on hover */}
            <motion.span
              className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent"
              initial={{ x: "-100%" }}
              whileHover={{ x: "100%" }}
              transition={{ duration: 0.6 }}
            />
          </motion.button>
        </div>
      </motion.header>

      {/* ── Toast ── */}
      {toastMessage && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="fixed top-20 left-1/2 -translate-x-1/2 z-50 px-4 py-2 rounded-full bg-slate-900/90 text-white text-xs font-mono border border-[#BFE9FF]/40 shadow-2xl flex items-center gap-2"
        >
          <Activity className="w-3.5 h-3.5 text-[#BFE9FF]" />
          <span>{toastMessage}</span>
        </motion.div>
      )}

      {/* ── Enhanced Ambient Glow (moves with mouse) ── */}
      <motion.div
        className="absolute top-16 left-1/2 -translate-x-1/2 w-[850px] h-[450px] rounded-full pointer-events-none"
        style={{
          background: "radial-gradient(ellipse, rgba(111,61,255,0.18) 0%, rgba(191,233,255,0.14) 35%, rgba(183,183,183,0.05) 60%, transparent 75%)",
          filter: "blur(90px)",
        }}
      />

      {/* Floating ambient particles */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        {Array.from({ length: 14 }).map((_, i) => (
          <FloatingDot
            key={i}
            delay={i * 0.35}
            x={`${8 + ((i * 13) % 84)}%`}
            y={`${12 + ((i * 17) % 76)}%`}
            color={i % 3 === 0 ? "#6F3DFF" : i % 3 === 1 ? "#BFE9FF" : "#B7B7B7"}
          />
        ))}
      </div>

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
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full neu-flat-sm text-[11px] font-mono font-bold text-slate-700 border border-[#B7B7B7]/40 shimmer-border"
          >
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#6F3DFF] opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-[#6F3DFF]" />
            </span>
            <span>AUTONOMOUS SOC SUITE // v2.4 OPERATIONAL</span>
            <span className="px-1.5 py-0.5 rounded bg-[#BFE9FF] text-[#6F3DFF] text-[9px] font-mono font-black">ACTIVE</span>
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
            <span className="text-slate-800">cyber threats across</span>{" "}
            <span className="cyber-gradient-text">
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
            <motion.button
              onClick={onLaunchDashboard}
              className="group px-7 py-3.5 rounded-full bg-gradient-to-r from-[#6F3DFF] via-[#5c2ae8] to-[#4e19d9] hover:from-[#7c4dff] hover:to-[#5c24e6] text-white text-xs font-bold flex items-center gap-2.5 shadow-xl shadow-[#6F3DFF]/35 active:scale-95 transition-all relative overflow-hidden border border-[#BFE9FF]/40"
              whileHover={{ scale: 1.03, boxShadow: "0 0 32px rgba(111,61,255,0.45)" }}
              whileTap={{ scale: 0.97 }}
            >
              <span className="relative z-10 tracking-wide">Explore SOC Console</span>
              <ArrowUpRight className="w-4 h-4 relative z-10 text-[#BFE9FF] group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
              <motion.span
                className="absolute inset-0 bg-gradient-to-r from-transparent via-[#BFE9FF]/20 to-transparent"
                initial={{ opacity: 0 }}
                whileHover={{ opacity: 1 }}
                transition={{ duration: 0.3 }}
              />
            </motion.button>

            <motion.button
              onClick={() => onOpenAuth("signup")}
              className="px-6 py-3.5 rounded-full neu-flat hover:bg-white text-slate-800 text-xs font-bold flex items-center gap-2 active:neu-pressed transition-all border border-[#B7B7B7]/40"
              whileHover={{ scale: 1.02, y: -2 }}
              whileTap={{ scale: 0.97 }}
            >
              <Fingerprint className="w-4 h-4 text-[#6F3DFF]" />
              <span>Create Analyst Account</span>
            </motion.button>
          </motion.div>

          {/* Live stats row */}
          <motion.div
            variants={fadeUp}
            transition={{ delay: 0.4, duration: 0.6 }}
            className="pt-4 grid grid-cols-3 gap-3"
          >
            {[
              { value: 96.4, suffix: "%", label: "ML Accuracy", color: "text-[#6F3DFF]" },
              { value: 150, suffix: "ms", label: "Detection Speed", color: "text-[#2563eb]" },
              { value: 14, suffix: "+", label: "MITRE Techniques", color: "text-[#6F3DFF]" },
            ].map((stat) => (
              <div key={stat.label} className="text-center p-3 rounded-2xl neu-flat-sm border border-[#B7B7B7]/30 hover:border-[#BFE9FF]/60 transition-colors">
                <div className={cn("text-xl font-black font-mono tabular-nums", stat.color)}>
                  <AnimatedCounter end={stat.value} suffix={stat.suffix} />
                </div>
                <div className="text-[9px] text-[#64748b] font-mono uppercase mt-0.5">{stat.label}</div>
              </div>
            ))}
          </motion.div>

          {/* Trust badges */}
          <motion.div
            variants={fadeUp}
            transition={{ delay: 0.45, duration: 0.6 }}
            className="pt-2 flex flex-wrap items-center gap-5 text-xs text-slate-500 font-mono"
          >
            {[
              { text: "MITRE ATT&CK v14.1", icon: ShieldCheck, color: "text-[#6F3DFF]" },
              { text: "SHA-256 Ledger", icon: Lock, color: "text-[#0ea5e9]" },
              { text: "Scapy/Npcap Active", icon: Radio, color: "text-[#10b981]" },
            ].map((badge) => (
              <div key={badge.text} className="flex items-center gap-1.5">
                <badge.icon className={cn("w-3.5 h-3.5", badge.color)} />
                <span className="text-[#475569]">{badge.text}</span>
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
          <motion.div
            className="relative w-full max-w-md h-[460px] rounded-3xl overflow-hidden shadow-2xl neu-flat border border-[#B7B7B7]/40 flex items-end justify-center"
            whileHover={{ scale: 1.01, rotateY: 2 }}
            transition={{ type: "spring", stiffness: 200 }}
          >
            {/* Gradient background with deep ultraviolet to slate tones */}
            <div className="absolute inset-0 bg-gradient-to-b from-[#2a1b4e] via-[#1a233a] to-[#0c1222]" />

            {/* Cyber grid pattern */}
            <div
              className="absolute inset-0 opacity-20"
              style={{
                backgroundImage:
                  "linear-gradient(rgba(191,233,255,0.25) 1px, transparent 1px), linear-gradient(90deg, rgba(111,61,255,0.25) 1px, transparent 1px)",
                backgroundSize: "24px 24px",
              }}
            />

            {/* Animated scan line with Glacier Blue glow */}
            <motion.div
              className="absolute left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-[#BFE9FF] to-transparent pointer-events-none"
              initial={{ top: "0%" }}
              animate={{ top: "100%" }}
              transition={{
                duration: 3,
                repeat: Infinity,
                ease: "linear",
                repeatType: "loop",
              }}
              style={{ boxShadow: "0 0 16px 2px rgba(191,233,255,0.8)" }}
            />

            {/* Radar glow */}
            <div className="absolute top-4 right-4 w-56 h-56 bg-[#6F3DFF]/20 rounded-full blur-3xl pointer-events-none" />

            {/* Analyst image */}
            <div className="relative w-72 h-80 z-10">
              <Image
                src="https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?q=80&w=800&auto=format&fit=crop"
                alt="Lead SOC Analyst"
                fill
                priority
                loading="eager"
                sizes="300px"
                className="object-cover object-top"
                style={{ borderRadius: "12px 12px 0 0" }}
              />
            </div>

            {/* Live threat counter overlay */}
            <motion.div
              className="absolute top-4 left-4 z-20 px-3.5 py-2.5 rounded-xl bg-black/75 backdrop-blur-md border border-[#BFE9FF]/40 font-mono shadow-xl shadow-black/40"
              whileHover={{ scale: 1.05 }}
            >
              <div className="text-[9px] text-[#BFE9FF] uppercase tracking-wider mb-0.5 flex items-center gap-1.5 font-bold">
                <span className="w-1.5 h-1.5 rounded-full bg-[#6F3DFF] animate-pulse shadow-sm shadow-[#6F3DFF]" />
                Threats Blocked
              </div>
              <div className="text-lg font-black text-white" style={{ textShadow: "0 0 16px rgba(191,233,255,0.9)" }}>
                {threatCount.toLocaleString()}
              </div>
            </motion.div>

            {/* Bottom gradient overlay */}
            <div className="absolute bottom-0 left-0 right-0 h-24 bg-gradient-to-t from-[#0c1222] to-transparent z-[5]" />
          </motion.div>

          {/* Floating Card 1: Sync security feeds */}
          <motion.div
            initial={{ opacity: 0, y: -16, rotate: -3 }}
            animate={{ opacity: 1, y: 0, rotate: 0 }}
            transition={{ delay: 0.6, duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
            className="absolute -top-4 right-2 md:right-6 z-20 w-52 bg-white/96 backdrop-blur-md rounded-2xl p-4 neu-flat-sm border border-white shadow-2xl dash-card"
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider font-mono">
                Sync security feeds
              </span>
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-500 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
              </span>
            </div>
            <div className="space-y-2.5 text-xs">
              {[
                { key: "SIEM", label: "SIEM Gateway", state: syncSiem, setter: setSyncSiem, gradient: "from-[#6F3DFF] to-[#4e19d9]" },
                { key: "Cloud", label: "CloudTrail", state: syncCloud, setter: setSyncCloud, gradient: "from-[#0284c7] to-[#0369a1]" },
                { key: "EDR", label: "EDR Agents", state: syncEdr, setter: setSyncEdr, gradient: "from-[#6F3DFF] to-[#8b5cf6]" },
              ].map((item) => (
                <div key={item.key} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className={`w-5 h-5 rounded-md bg-gradient-to-tr ${item.gradient} text-white flex items-center justify-center text-[9px] font-bold shadow-sm`}>
                      {item.key[0]}
                    </div>
                    <span className="text-slate-700 text-[11px] font-semibold">{item.label}</span>
                  </div>
                  <button
                    onClick={() => triggerFeedToggle(item.label, item.state, item.setter)}
                    className={cn(
                      "w-8 h-4 rounded-full transition-all duration-300 relative flex items-center px-0.5",
                      item.state ? "bg-[#6F3DFF] shadow-sm shadow-[#6F3DFF]/40" : "bg-[#B7B7B7]/50"
                    )}
                  >
                    <motion.span
                      className="w-3 h-3 rounded-full bg-white shadow-sm"
                      animate={{ x: item.state ? 16 : 0 }}
                      transition={{ type: "spring", stiffness: 500, damping: 30 }}
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
            className="absolute top-14 -right-2 md:-right-8 z-20 text-right bg-white/96 backdrop-blur-md px-4 py-2.5 rounded-2xl neu-flat-sm border border-[#B7B7B7]/40 shadow-lg dash-card"
          >
            <div className="text-2xl font-black text-[#6F3DFF] tracking-tight font-mono">
              <AnimatedCounter end={120} suffix="+" />
            </div>
            <div className="text-[10px] font-semibold text-slate-500 font-mono">Telemetry Feeds</div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.85, duration: 0.6 }}
            className="absolute top-36 -right-2 md:-right-8 z-20 text-right bg-white/96 backdrop-blur-md px-4 py-2.5 rounded-2xl neu-flat-sm border border-[#B7B7B7]/40 shadow-lg dash-card"
          >
            <div className="text-2xl font-black text-[#2563eb] tracking-tight font-mono">
              <AnimatedCounter end={30} suffix="+" />
            </div>
            <div className="text-[10px] font-semibold text-slate-500 font-mono">AI Threat Rules</div>
          </motion.div>

          {/* Evidence locked pill */}
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.95, duration: 0.5, type: "spring" }}
            className="absolute bottom-32 -right-4 z-20"
          >
            <motion.div
              className="px-4 py-1.5 rounded-full bg-gradient-to-r from-[#6F3DFF] to-[#BFE9FF] text-white text-[11px] font-bold flex items-center gap-1.5 shadow-xl shadow-[#6F3DFF]/30 border border-white/50"
              whileHover={{ scale: 1.05 }}
            >
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-white opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-white" />
              </span>
              <span className="drop-shadow-sm font-mono tracking-tight">Ledger Verified</span>
            </motion.div>
          </motion.div>

          {/* Bottom-left: Assigned Analysts */}
          <motion.div
            initial={{ opacity: 0, y: 16, rotate: 2 }}
            animate={{ opacity: 1, y: 0, rotate: 0 }}
            transition={{ delay: 0.7, duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
            className="absolute -bottom-6 -left-4 md:-left-8 z-20 w-56 bg-white/96 backdrop-blur-md rounded-2xl p-4 neu-flat-sm border border-[#B7B7B7]/40 shadow-2xl dash-card"
          >
            <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2.5 font-mono">
              Assigned Analysts
            </div>
            <div className="space-y-2.5">
              {[
                { initials: "21", label: "21 Threat Hunters", sub: "Active 8 days ago", gradient: "from-[#6F3DFF] to-[#4e19d9]", isActive: false },
                { initials: "DP", label: "Darcy Patterson", sub: "Active now", gradient: "from-[#6F3DFF] via-[#855bff] to-[#BFE9FF]", isActive: true },
                { initials: "AH", label: "Alex Hamilton", sub: "Active 3 days ago", gradient: "from-[#64748b] to-[#475569]", isActive: false },
              ].map((a) => (
                <div key={a.initials} className="flex items-center gap-2.5">
                  <div className={`w-7 h-7 rounded-full bg-gradient-to-tr ${a.gradient} text-white flex items-center justify-center text-[10px] font-bold font-mono shrink-0 shadow-sm`}>
                    {a.initials}
                  </div>
                  <div>
                    <div className="text-xs font-bold text-slate-800">{a.label}</div>
                    <div className="text-[10px] text-slate-500 flex items-center gap-1 font-mono">
                      {a.isActive && <span className="w-1.5 h-1.5 rounded-full bg-[#6F3DFF] inline-block animate-pulse" />}
                      <span>{a.sub}</span>
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
