"use client";
import React from "react";
import { ShieldCheck, ArrowUpRight } from "lucide-react";

export function Footer({
  onOpenAuth,
  onNavigate,
}: {
  onOpenAuth?: (tab: "signin" | "signup" | "recovery") => void;
  onNavigate?: (page: string) => void;
}) {
  return (
    <footer className="relative bg-[#070b13] text-slate-300 pt-20 pb-12 overflow-hidden border-t border-slate-800">
      {/* Top Footer Content */}
      <div className="max-w-7xl mx-auto px-6 md:px-10 relative z-10">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-10 pb-16 border-b border-slate-800/80">
          {/* Brand Col */}
          <div className="md:col-span-4 space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-cyan-500/20">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <span className="text-2xl font-bold tracking-tight text-white">
                CyberSentinel<span className="text-cyan-400">-X</span>
              </span>
            </div>
            <p className="text-xs text-slate-400 max-w-sm leading-relaxed">
              AI-driven cyber threat detection, autonomous investigation, and immutable evidence integrity platform built for next-generation Security Operations Centers.
            </p>
            <p className="text-xs text-slate-500 pt-2">
              © copyright CyberSentinel-X 2026. All rights reserved.
            </p>
          </div>

          {/* Column 1: Pages */}
          <div className="md:col-span-2 space-y-3">
            <h4 className="text-sm font-semibold text-white tracking-wider">Pages</h4>
            <ul className="space-y-2 text-xs text-slate-400">
              <li>
                <button
                  onClick={() => onNavigate?.("dashboard")}
                  className="hover:text-cyan-400 transition-colors text-left"
                >
                  SOC Dashboard
                </button>
              </li>
              <li>
                <button
                  onClick={() => onNavigate?.("alerts")}
                  className="hover:text-cyan-400 transition-colors text-left"
                >
                  Alerts Matrix
                </button>
              </li>
              <li>
                <button
                  onClick={() => onNavigate?.("investigation")}
                  className="hover:text-cyan-400 transition-colors text-left"
                >
                  AI Investigation
                </button>
              </li>
              <li>
                <button
                  onClick={() => onNavigate?.("evidence")}
                  className="hover:text-cyan-400 transition-colors text-left"
                >
                  Evidence Ledger
                </button>
              </li>
              <li>
                <button
                  onClick={() => onNavigate?.("analytics")}
                  className="hover:text-cyan-400 transition-colors text-left"
                >
                  Analytics & Reports
                </button>
              </li>
            </ul>
          </div>

          {/* Column 2: Socials */}
          <div className="md:col-span-2 space-y-3">
            <h4 className="text-sm font-semibold text-white tracking-wider">Socials</h4>
            <ul className="space-y-2 text-xs text-slate-400">
              <li>
                <a href="#github" className="hover:text-cyan-400 transition-colors flex items-center gap-1">
                  GitHub <ArrowUpRight className="w-3 h-3 opacity-60" />
                </a>
              </li>
              <li>
                <a href="#twitter" className="hover:text-cyan-400 transition-colors flex items-center gap-1">
                  Twitter / X <ArrowUpRight className="w-3 h-3 opacity-60" />
                </a>
              </li>
              <li>
                <a href="#linkedin" className="hover:text-cyan-400 transition-colors flex items-center gap-1">
                  LinkedIn <ArrowUpRight className="w-3 h-3 opacity-60" />
                </a>
              </li>
              <li>
                <a href="#discord" className="hover:text-cyan-400 transition-colors flex items-center gap-1">
                  SOC Discord <ArrowUpRight className="w-3 h-3 opacity-60" />
                </a>
              </li>
            </ul>
          </div>

          {/* Column 3: Legal */}
          <div className="md:col-span-2 space-y-3">
            <h4 className="text-sm font-semibold text-white tracking-wider">Legal</h4>
            <ul className="space-y-2 text-xs text-slate-400">
              <li>
                <a href="#privacy" className="hover:text-cyan-400 transition-colors">
                  Privacy Policy
                </a>
              </li>
              <li>
                <a href="#terms" className="hover:text-cyan-400 transition-colors">
                  Terms of Service
                </a>
              </li>
              <li>
                <a href="#security" className="hover:text-cyan-400 transition-colors">
                  Security Whitepaper
                </a>
              </li>
              <li>
                <a href="#cookies" className="hover:text-cyan-400 transition-colors">
                  Cookie Policy
                </a>
              </li>
            </ul>
          </div>

          {/* Column 4: Register */}
          <div className="md:col-span-2 space-y-3">
            <h4 className="text-sm font-semibold text-white tracking-wider">Register</h4>
            <ul className="space-y-2 text-xs text-slate-400">
              <li>
                <button
                  onClick={() => onOpenAuth?.("signup")}
                  className="hover:text-cyan-400 transition-colors text-left"
                >
                  Sign Up
                </button>
              </li>
              <li>
                <button
                  onClick={() => onOpenAuth?.("signin")}
                  className="hover:text-cyan-400 transition-colors text-left"
                >
                  Login
                </button>
              </li>
              <li>
                <button
                  onClick={() => onOpenAuth?.("recovery")}
                  className="hover:text-cyan-400 transition-colors text-left"
                >
                  Forgot Password
                </button>
              </li>
              <li>
                <span className="inline-block mt-2 px-2.5 py-0.5 rounded-full text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  ● Gateway 100% Operational
                </span>
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* Giant Embossed Watermark Background (Exact DevStudio Footer element from Screenshot 2) */}
      <div className="relative w-full overflow-hidden select-none pointer-events-none mt-10 md:mt-16">
        <h1 className="text-[14vw] font-extrabold text-slate-800/20 tracking-tighter leading-none whitespace-nowrap text-center uppercase font-mono drop-shadow-sm">
          CyberSentinel-X
        </h1>
      </div>
    </footer>
  );
}
