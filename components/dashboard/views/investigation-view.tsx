"use client";
import React from "react";
import {
  BrainCircuit,
  CheckCircle2,
  AlertCircle,
  Network,
  ShieldCheck,
  Server,
  FileText,
  ArrowRight,
  Activity,
  Layers,
  Sparkles,
} from "lucide-react";
import { Incident } from "@/data/cyberData";
import { cn } from "@/lib/utils";

export function InvestigationView({
  incident,
  onGenerateReport,
  onNavigateTab,
}: {
  incident: Incident;
  onGenerateReport: () => void;
  onNavigateTab: (tab: string) => void;
}) {
  const inv = incident.investigation;

  return (
    <div className="space-y-6 pb-12">
      {/* Top Header Card with Stepper */}
      <div className="neu-flat rounded-2xl p-6 border border-white space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-100 text-indigo-600 flex items-center justify-center shadow-inner">
              <BrainCircuit className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold text-blue-600">
                  INCIDENT: {incident.id}
                </span>
                <span className="text-[10px] font-bold bg-emerald-100 text-emerald-700 px-2.5 py-0.5 rounded-full">
                  {inv.status}
                </span>
              </div>
              <h2 className="text-xl font-extrabold text-slate-900 tracking-tight mt-0.5">
                Autonomous AI Investigation Matrix
              </h2>
            </div>
          </div>

          <button
            onClick={onGenerateReport}
            className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold flex items-center gap-2 shadow-lg shadow-blue-500/20 active:scale-95 transition-all"
          >
            <FileText className="w-4 h-4" />
            <span>Generate Investigation Report</span>
          </button>
        </div>

        {/* 7-Step Visual Progress Stepper (Requirement 6) */}
        <div>
          <h4 className="text-[11px] font-bold text-slate-400 uppercase font-mono tracking-wider mb-4">
            Investigation Lifecycle Progress
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
            {inv.progressSteps.map((step, idx) => (
              <div
                key={idx}
                className={cn(
                  "p-3 rounded-xl border text-left transition-all flex flex-col justify-between min-h-[72px]",
                  step.completed
                    ? "bg-white/90 border-emerald-300 neu-flat-sm"
                    : "bg-slate-100/50 border-slate-200 opacity-60"
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono font-bold text-slate-400">0{idx + 1}</span>
                  <CheckCircle2
                    className={cn(
                      "w-4 h-4",
                      step.completed ? "text-emerald-600" : "text-slate-300"
                    )}
                  />
                </div>
                <span className="text-[11px] font-semibold text-slate-800 leading-snug mt-2">
                  {step.name}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Grid: Investigation Findings & Related Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* INVESTIGATION FINDINGS (Requirement 6) */}
        <div className="lg:col-span-8 neu-flat rounded-2xl p-6 border border-white space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Forensic Findings & Corroborated Facts
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">4 Verified Observations</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {inv.findings.map((finding, idx) => (
              <div
                key={idx}
                className="p-4 bg-white/90 rounded-xl neu-flat-sm border border-white hover:translate-y-[-1px] transition-transform"
              >
                <div className="flex items-center gap-2 mb-2">
                  <span className="w-2 h-2 rounded-full bg-blue-600" />
                  <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">
                    Forensic Observation #{idx + 1}
                  </span>
                </div>
                <p className="text-xs font-semibold text-slate-800 leading-relaxed">
                  {finding}
                </p>
              </div>
            ))}
          </div>

          {/* AI SUMMARY (Requirement 6) */}
          <div className="mt-6 p-5 bg-white/80 rounded-2xl neu-pressed-sm border border-slate-200/60 space-y-2">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-cyan-600" />
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                Autonomous AI Synthesis
              </h4>
            </div>
            <p className="text-xs text-slate-700 leading-relaxed font-sans italic">
              &ldquo;{inv.summary}&rdquo;
            </p>
          </div>
        </div>

        {/* RELATED ACTIVITY (Requirement 6) */}
        <div className="lg:col-span-4 neu-flat rounded-2xl p-6 border border-white space-y-5 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-4">
              Correlated Attack Activity
            </h3>

            <div className="space-y-3">
              <div
                onClick={() => onNavigateTab("alerts")}
                className="p-3 bg-white/80 rounded-xl neu-flat-sm flex items-center justify-between cursor-pointer hover:bg-white transition-colors"
              >
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center font-bold text-xs">
                    {inv.relatedActivity.alertsCount}
                  </div>
                  <span className="text-xs font-semibold text-slate-800">Related Alerts</span>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-400" />
              </div>

              <div
                onClick={() => onNavigateTab("threat-intel")}
                className="p-3 bg-white/80 rounded-xl neu-flat-sm flex items-center justify-between cursor-pointer hover:bg-white transition-colors"
              >
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-orange-100 text-orange-600 flex items-center justify-center font-bold text-xs">
                    {inv.relatedActivity.sourceIpsCount}
                  </div>
                  <span className="text-xs font-semibold text-slate-800">Related Source IPs</span>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-400" />
              </div>

              <div className="p-3 bg-white/80 rounded-xl neu-flat-sm flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-emerald-100 text-emerald-600 flex items-center justify-center font-bold text-xs">
                    {inv.relatedActivity.affectedAssetsCount}
                  </div>
                  <span className="text-xs font-semibold text-slate-800">Affected Asset</span>
                </div>
                <span className="text-[10px] font-mono text-slate-500">Auth Server</span>
              </div>

              <div className="p-3 bg-white/80 rounded-xl neu-flat-sm flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-red-100 text-red-600 flex items-center justify-center font-bold text-xs">
                    {inv.relatedActivity.suspiciousAuthCount}
                  </div>
                  <span className="text-xs font-semibold text-slate-800">Suspicious Auth Events</span>
                </div>
                <span className="text-[10px] font-mono text-red-600 font-bold">500 req/min</span>
              </div>
            </div>
          </div>

          <button
            onClick={() => onNavigateTab("risk")}
            className="w-full py-2.5 rounded-xl neu-flat hover:bg-white text-xs font-bold text-blue-600 flex items-center justify-center gap-1.5 transition-all"
          >
            <span>Proceed to Risk Assessment</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}
