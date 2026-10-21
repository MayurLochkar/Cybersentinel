"use client";
import React, { useState } from "react";
import {
  ShieldCheck,
  Lock,
  Mail,
  User,
  Eye,
  EyeOff,
  Building,
  KeyRound,
  CheckCircle2,
  X,
  ArrowRight,
  Shield,
  Cpu,
  Fingerprint,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";

export function AuthModal({
  isOpen,
  onClose,
  initialTab = "signin",
  onLoginSuccess,
}: {
  isOpen: boolean;
  onClose: () => void;
  initialTab?: "signin" | "signup" | "recovery";
  onLoginSuccess?: () => void;
}) {
  const [activeTab, setActiveTab] = useState<"signin" | "signup" | "recovery">(initialTab);
  const [showPassword, setShowPassword] = useState(false);
  const [isCaptchaChecked, setIsCaptchaChecked] = useState(true);
  const [isAgreed, setIsAgreed] = useState(true);

  // Form states
  const [email, setEmail] = useState("analyst.jordan@cybersentinel.ai");
  const [password, setPassword] = useState("Sentinel2026@Secure!");
  const [username, setUsername] = useState("JordanB_SOC");
  const [department, setDepartment] = useState("Incident Response Team");
  const [token, setToken] = useState("AUTH-SEC-9921-X");
  const [statusMsg, setStatusMsg] = useState("");

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setStatusMsg("Authenticating security credentials...");
    setTimeout(() => {
      setStatusMsg("✓ Clearance verified. Redirecting to SOC Console...");
      setTimeout(() => {
        onLoginSuccess?.();
        onClose();
      }, 700);
    }, 800);
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-md">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          transition={{ duration: 0.25 }}
          className="relative w-full max-w-4xl bg-gradient-to-br from-[#f3f7fb] via-[#eaf0f8] to-[#dce6f2] rounded-3xl neu-flat border border-white/90 p-6 md:p-10 overflow-hidden shadow-2xl"
        >
          {/* Close button */}
          <button
            onClick={onClose}
            className="absolute top-5 right-5 h-9 w-9 rounded-full neu-flat flex items-center justify-center text-slate-500 hover:text-slate-800 hover:bg-white transition-all z-20"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
            {/* Left Auth Form Card (Matching screenshots 3 & 4) */}
            <div className="lg:col-span-6 bg-white/90 rounded-2xl p-6 md:p-7 neu-flat-sm border border-white shadow-xl">
              {/* Pill Tabs */}
              <div className="grid grid-cols-3 gap-1 bg-[#eef3f8] p-1.5 rounded-xl neu-pressed-sm mb-6 text-xs font-semibold text-slate-600">
                <button
                  type="button"
                  onClick={() => setActiveTab("signin")}
                  className={cn(
                    "py-2 rounded-lg transition-all text-center",
                    activeTab === "signin"
                      ? "bg-white text-blue-600 shadow-sm font-bold"
                      : "hover:text-slate-900"
                  )}
                >
                  Sign In
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab("signup")}
                  className={cn(
                    "py-2 rounded-lg transition-all text-center",
                    activeTab === "signup"
                      ? "bg-white text-blue-600 shadow-sm font-bold"
                      : "hover:text-slate-900"
                  )}
                >
                  Sign Up
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab("recovery")}
                  className={cn(
                    "py-2 rounded-lg transition-all text-center",
                    activeTab === "recovery"
                      ? "bg-white text-blue-600 shadow-sm font-bold"
                      : "hover:text-slate-900"
                  )}
                >
                  Recovery
                </button>
              </div>

              {/* Brand Logo & Title */}
              <div className="flex items-center gap-2.5 mb-5">
                <div className="h-8 w-8 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center text-white shadow-sm">
                  <Shield className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-xl font-bold text-slate-800">
                    {activeTab === "signin"
                      ? "Sign In"
                      : activeTab === "signup"
                      ? "Create SOC Profile"
                      : "Reset Clearance"}
                  </h3>
                  <p className="text-[11px] text-slate-500">CyberSentinel-X Enterprise Node</p>
                </div>
              </div>

              <form onSubmit={handleSubmit} className="space-y-3.5">
                {activeTab === "signup" && (
                  <div>
                    <label className="text-[11px] font-semibold text-slate-700 block mb-1">
                      Analyst Handle
                    </label>
                    <div className="relative">
                      <User className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                      <input
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="e.g. JordanB_SOC"
                        required
                        className="w-full pl-10 pr-4 py-2.5 bg-[#f5f8fc] rounded-xl text-xs text-slate-800 border border-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all shadow-inner"
                      />
                    </div>
                  </div>
                )}

                <div>
                  <label className="text-[11px] font-semibold text-slate-700 block mb-1">
                    {activeTab === "signin" ? "Login / Email" : "Enterprise Email"}
                  </label>
                  <div className="relative">
                    <Mail className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="analyst.jordan@cybersentinel.ai"
                      required
                      className="w-full pl-10 pr-4 py-2.5 bg-[#f5f8fc] rounded-xl text-xs text-slate-800 border border-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all shadow-inner"
                    />
                  </div>
                </div>

                {activeTab === "signup" && (
                  <div>
                    <label className="text-[11px] font-semibold text-slate-700 block mb-1">
                      Unit / Department
                    </label>
                    <div className="relative">
                      <Building className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                      <select
                        value={department}
                        onChange={(e) => setDepartment(e.target.value)}
                        className="w-full pl-10 pr-4 py-2.5 bg-[#f5f8fc] rounded-xl text-xs text-slate-800 border border-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all shadow-inner"
                      >
                        <option>Incident Response Team</option>
                        <option>Threat Hunting & Intel</option>
                        <option>Security Operations Center</option>
                        <option>Forensic & Evidence Unit</option>
                      </select>
                    </div>
                  </div>
                )}

                {activeTab !== "recovery" && (
                  <div>
                    <label className="text-[11px] font-semibold text-slate-700 block mb-1">
                      Clearance Password
                    </label>
                    <div className="relative">
                      <Lock className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                      <input
                        type={showPassword ? "text" : "password"}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="••••••••••••"
                        required
                        className="w-full pl-10 pr-10 py-2.5 bg-[#f5f8fc] rounded-xl text-xs text-slate-800 border border-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all shadow-inner font-mono"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-700"
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                )}

                {/* reCAPTCHA Mockup (Exact element from Screenshot 3 & 4) */}
                <div className="bg-[#f7f9fc] border border-slate-300/80 rounded-xl p-3 flex items-center justify-between shadow-inner">
                  <label className="flex items-center gap-2.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={isCaptchaChecked}
                      onChange={(e) => setIsCaptchaChecked(e.target.checked)}
                      className="w-5 h-5 rounded border-slate-300 text-blue-600 focus:ring-blue-500 cursor-pointer"
                    />
                    <span className="text-xs text-slate-700 font-medium">I&apos;m not a robot</span>
                  </label>
                  <div className="flex flex-col items-center text-[8px] text-slate-400 font-sans">
                    <div className="w-6 h-6 rounded-full border-2 border-dashed border-blue-500 flex items-center justify-center">
                      <Fingerprint className="w-3.5 h-3.5 text-blue-600" />
                    </div>
                    <span>reCAPTCHA</span>
                    <span>Privacy · Terms</span>
                  </div>
                </div>

                {/* Terms agreement */}
                <label className="flex items-center gap-2 cursor-pointer text-[11px] text-slate-600">
                  <input
                    type="checkbox"
                    checked={isAgreed}
                    onChange={(e) => setIsAgreed(e.target.checked)}
                    className="w-4 h-4 text-blue-600 rounded border-slate-300"
                  />
                  <span>
                    I agree to CyberSentinel-X{" "}
                    <span className="text-blue-600 underline font-medium">Terms of security use</span>
                  </span>
                </label>

                {statusMsg && (
                  <div className="text-xs p-2 rounded-lg bg-blue-50 text-blue-700 border border-blue-200 font-mono">
                    {statusMsg}
                  </div>
                )}

                {/* Gradient Submit Button */}
                <button
                  type="submit"
                  className="w-full py-3 px-4 rounded-xl text-white font-semibold text-xs uppercase tracking-wider bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 shadow-lg shadow-blue-500/25 transition-all transform active:scale-[0.99] flex items-center justify-center gap-2"
                >
                  <span>
                    {activeTab === "signin"
                      ? "Sign In to SOC Console"
                      : activeTab === "signup"
                      ? "Create Analyst Credentials"
                      : "Send Reset Link"}
                  </span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </form>
            </div>

            {/* Right Graphic Panel (Matching screenshot 3 & 4 isometric illustration) */}
            <div className="lg:col-span-6 flex flex-col items-center justify-center text-center p-4">
              {/* Brand Header */}
              <div className="w-16 h-16 rounded-2xl bg-white neu-flat flex items-center justify-center text-blue-600 mb-4 shadow-lg border border-white">
                <ShieldCheck className="w-9 h-9" />
              </div>
              <h2 className="text-2xl md:text-3xl font-extrabold text-slate-800 tracking-tight leading-snug">
                Welcome to the CyberSentinel-X <br />
                <span className="bg-clip-text text-transparent bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600">
                  Security Terminal
                </span>
              </h2>
              <p className="text-xs text-slate-500 max-w-sm mt-2">
                Real-time AI threat forensics, cryptographic evidence integrity & MITRE ATT&CK correlation.
              </p>

              {/* 3D Isometric Cyber SOC Illustration */}
              <div className="relative w-full max-w-sm h-64 mt-4 flex items-center justify-center">
                {/* Holographic glowing rings */}
                <div className="absolute w-56 h-36 bg-cyan-400/20 blur-3xl rounded-full pointer-events-none" />

                {/* Isometric Platform SVG graphic */}
                <svg
                  viewBox="0 0 400 300"
                  className="w-full h-full drop-shadow-2xl"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  {/* Isometric base grid */}
                  <path
                    d="M200 40 L360 130 L200 220 L40 130 Z"
                    fill="#e1ecf8"
                    stroke="#b4cce8"
                    strokeWidth="2"
                  />
                  <path
                    d="M40 130 L200 220 L200 250 L40 160 Z"
                    fill="#c8dbef"
                  />
                  <path
                    d="M360 130 L200 220 L200 250 L360 160 Z"
                    fill="#b0c8e4"
                  />

                  {/* Upward Growth Arrow (Like in screenshot) */}
                  <path
                    d="M170 190 L270 90 L260 70 L310 65 L305 115 L285 105 L185 205 Z"
                    fill="url(#arrowGrad)"
                    filter="drop-shadow(0 4px 8px rgba(14,165,233,0.4))"
                  />

                  {/* Isometric Server Monoliths */}
                  <g transform="translate(240, 100)">
                    <path d="M20 0 L40 12 L20 24 L0 12 Z" fill="#93c5fd" />
                    <path d="M0 12 L20 24 L20 70 L0 58 Z" fill="#60a5fa" />
                    <path d="M40 12 L20 24 L20 70 L40 58 Z" fill="#3b82f6" />
                  </g>
                  <g transform="translate(270, 75)">
                    <path d="M20 0 L40 12 L20 24 L0 12 Z" fill="#bfdbfe" />
                    <path d="M0 12 L20 24 L20 90 L0 78 Z" fill="#93c5fd" />
                    <path d="M40 12 L20 24 L20 90 L40 78 Z" fill="#60a5fa" />
                  </g>

                  {/* Main Command Monitor Screen Display */}
                  <g transform="translate(100, 95)">
                    <polygon
                      points="10,20 120,5 120,95 10,110"
                      fill="#0f172a"
                      stroke="#38bdf8"
                      strokeWidth="2"
                    />
                    <polygon
                      points="15,25 115,12 115,90 15,103"
                      fill="#0369a1"
                      opacity="0.85"
                    />
                    {/* Screen waveform */}
                    <path
                      d="M20 70 Q 40 40, 60 65 T 110 50"
                      stroke="#38bdf8"
                      strokeWidth="3"
                      fill="none"
                    />
                    <circle cx="60" cy="65" r="4" fill="#22c55e" />
                    <circle cx="95" cy="55" r="4" fill="#eab308" />
                  </g>

                  {/* Analyst avatar 1 (Left) */}
                  <g transform="translate(70, 130)">
                    <circle cx="20" cy="15" r="9" fill="#fcd34d" />
                    <path d="M10 25 L30 25 L35 70 L5 70 Z" fill="#2563eb" />
                    <path d="M12 70 L12 95 L18 95 L18 70 Z" fill="#1e293b" />
                    <path d="M22 70 L22 95 L28 95 L28 70 Z" fill="#1e293b" />
                  </g>

                  {/* Analyst avatar 2 (Right) */}
                  <g transform="translate(225, 125)">
                    <circle cx="20" cy="15" r="9" fill="#fbcfe8" />
                    <path d="M10 25 L30 25 L35 65 L5 65 Z" fill="#0284c7" />
                    <path d="M12 65 L12 95 L18 95 L18 65 Z" fill="#1e293b" />
                    <path d="M22 65 L22 95 L28 95 L28 65 Z" fill="#1e293b" />
                    {/* Tablet held */}
                    <polygon points="5,45 15,42 15,60 5,63" fill="#38bdf8" />
                  </g>

                  <defs>
                    <linearGradient id="arrowGrad" x1="0%" y1="100%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="#0284c7" />
                      <stop offset="100%" stopColor="#06b6d4" />
                    </linearGradient>
                  </defs>
                </svg>
              </div>

              {/* Status footer inside panel */}
              <div className="flex items-center gap-2 mt-2 px-3 py-1 bg-white/70 rounded-full neu-flat-sm text-[10px] text-slate-600">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span>Encrypted TLS 1.3 Channel Active</span>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
