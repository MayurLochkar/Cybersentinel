"use client";
import React from "react";
import { Gauge, ShieldAlert, AlertTriangle, CheckCircle, Info, ArrowRight } from "lucide-react";
import { CYBER_DATA } from "@/data/cyberData";
import { cn } from "@/lib/utils";

export function RiskView({
  onNavigateTab,
}: {
  onNavigateTab: (tab: string) => void;
}) {
  const incident = CYBER_DATA.recentIncidents[0]; // INC-1024
  const { score, level, factors, explanation } = incident.risk;

  return (
    <div className="space-y-6 pb-12">
      {/* Top Main Risk Gauge Card (Requirement 8) */}
      <div className="neu-flat rounded-2xl p-6 md:p-8 border border-white">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-8 items-center">
          {/* Circular Gauge */}
          <div className="md:col-span-4 flex flex-col items-center justify-center">
            <div className="relative w-48 h-48 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                {/* Background Ring */}
                <circle
                  cx="50"
                  cy="50"
                  r="42"
                  stroke="#e2e8f0"
                  strokeWidth="8"
                  fill="transparent"
                />
                {/* Score Arc */}
                <circle
                  cx="50"
                  cy="50"
                  r="42"
                  stroke="#ea580c"
                  strokeWidth="8"
                  strokeDasharray="264"
                  strokeDashoffset={264 - (264 * score) / 100}
                  strokeLinecap="round"
                  fill="transparent"
                  className="transition-all duration-1000 ease-out"
                />
              </svg>

              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-4xl font-black text-slate-900 font-mono tracking-tight">
                  {score}
                </span>
                <span className="text-xs font-bold text-slate-400 font-mono uppercase">
                  out of 100
                </span>
                <span className="mt-1 px-2.5 py-0.5 rounded-full text-[10px] font-extrabold bg-orange-100 text-orange-700 border border-orange-200">
                  {level} RISK
                </span>
              </div>
            </div>
          </div>

          {/* Explanation & Summary */}
          <div className="md:col-span-8 space-y-4">
            <div>
              <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                RISK EVALUATION ENGINE
              </span>
              <h2 className="text-2xl font-black text-slate-900 tracking-tight mt-0.5">
                Quantified Incident Risk: INC-1024
              </h2>
            </div>

            {/* RISK EXPLANATION (Requirement 8) */}
            <div className="p-4 bg-white/90 rounded-xl neu-flat-sm border border-white">
              <p className="text-xs text-slate-700 leading-relaxed">
                &ldquo;{explanation}&rdquo;
              </p>
            </div>

            {/* RISK LEVELS Legend (Requirement 8) */}
            <div>
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-2 font-mono">
                Risk Classification Spectrum
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                <div className="p-2 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-center">
                  <div className="font-bold">LOW</div>
                  <div className="text-[10px] text-emerald-600 font-mono">0 - 39</div>
                </div>
                <div className="p-2 rounded-xl bg-amber-50 border border-amber-200 text-amber-800 text-center">
                  <div className="font-bold">MEDIUM</div>
                  <div className="text-[10px] text-amber-600 font-mono">40 - 69</div>
                </div>
                <div className="p-2 rounded-xl bg-orange-100 border border-orange-300 text-orange-900 text-center ring-2 ring-orange-500/40 font-bold">
                  <div>HIGH (Active)</div>
                  <div className="text-[10px] text-orange-700 font-mono">70 - 89</div>
                </div>
                <div className="p-2 rounded-xl bg-red-50 border border-red-200 text-red-800 text-center">
                  <div className="font-bold">CRITICAL</div>
                  <div className="text-[10px] text-red-600 font-mono">90 - 100</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* RISK FACTORS Horizontal Progress Bars (Requirement 8) */}
      <div className="neu-flat rounded-2xl p-6 border border-white space-y-5">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
            Risk Factor Weighting & Breakdown
          </h3>
          <span className="text-[10px] text-slate-400 font-mono">6 Composite Vectors</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {factors.map((factor) => (
            <div key={factor.name} className="space-y-1.5 p-3 bg-white/70 rounded-xl neu-flat-sm border border-white">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-slate-800">{factor.name}</span>
                <div className="flex items-center gap-2">
                  <span
                    className={cn(
                      "text-[10px] font-extrabold px-2 py-0.5 rounded-full font-mono",
                      factor.level === "HIGH"
                        ? "bg-orange-100 text-orange-700"
                        : "bg-blue-100 text-blue-700"
                    )}
                  >
                    {factor.level}
                  </span>
                  <span className="font-mono font-bold text-slate-800">{factor.score}%</span>
                </div>
              </div>

              {/* Horizontal Progress Bar */}
              <div className="h-2 w-full bg-slate-200 rounded-full overflow-hidden neu-pressed-sm">
                <div
                  className={cn(
                    "h-full rounded-full transition-all duration-700",
                    factor.level === "HIGH" ? "bg-orange-500" : "bg-blue-500"
                  )}
                  style={{ width: `${factor.score}%` }}
                />
              </div>
            </div>
          ))}
        </div>

        <div className="pt-4 border-t border-slate-200 flex justify-end">
          <button
            onClick={() => onNavigateTab("evidence")}
            className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold flex items-center gap-2 transition-all shadow-md shadow-blue-500/20"
          >
            <span>Inspect Cryptographic Evidence Ledger</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
