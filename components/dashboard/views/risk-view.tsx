"use client";
import React, { useState, useEffect } from "react";
import { Gauge, ShieldAlert, AlertTriangle, CheckCircle, Info, ArrowRight, Layers } from "lucide-react";
import { CYBER_DATA } from "@/data/cyberData";
import { cn } from "@/lib/utils";
import { fetchRiskSummary, ApiRiskSummary, ApiIncidentRisk } from "@/lib/api";

export function RiskView({
  onNavigateTab,
}: {
  onNavigateTab: (tab: string) => void;
}) {
  const [riskData, setRiskData] = useState<ApiRiskSummary | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    async function loadRisk() {
      try {
        const data = await fetchRiskSummary();
        if (isMounted) {
          setRiskData(data);
          if (data.incidents.length > 0 && !selectedIncidentId) {
            setSelectedIncidentId(data.incidents[0].incident_id);
          }
        }
      } catch {
        // Fallback handled below
      } finally {
        if (isMounted) setLoading(false);
      }
    }
    loadRisk();
  }, [selectedIncidentId]);

  // Selected incident risk, or fallback to prototype
  const selectedIncident =
    riskData?.incidents.find((i) => i.incident_id === selectedIncidentId) ||
    riskData?.incidents[0];

  const defaultIncident = CYBER_DATA.recentIncidents[0];
  const score = selectedIncident ? selectedIncident.calculated_risk_score : defaultIncident.risk.score;
  const level = selectedIncident ? selectedIncident.risk_level : defaultIncident.risk.level;
  const factors = selectedIncident ? selectedIncident.factors : defaultIncident.risk.factors;
  const explanation = selectedIncident ? selectedIncident.explanation : defaultIncident.risk.explanation;
  const formula = riskData?.scoring_formula || "0.45 * ThreatSeverity + 0.35 * MLConfidence + 0.20 * AssetCriticality";

  return (
    <div className="space-y-6 pb-12">
      {/* Top Header Card */}
      <div className="neu-flat rounded-2xl p-6 md:p-8 border border-white">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-8 items-center">
          {/* Circular Gauge */}
          <div className="md:col-span-4 flex flex-col items-center justify-center">
            <div className="relative w-48 h-48 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                <circle
                  cx="50"
                  cy="50"
                  r="42"
                  stroke="#e2e8f0"
                  strokeWidth="8"
                  fill="transparent"
                />
                <circle
                  cx="50"
                  cy="50"
                  r="42"
                  stroke={level === "CRITICAL" ? "#ef4444" : level === "HIGH" ? "#ea580c" : level === "MEDIUM" ? "#eab308" : "#3b82f6"}
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
                <span className={cn(
                  "mt-1 px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase border",
                  level === "CRITICAL"
                    ? "bg-red-100 text-red-700 border-red-200"
                    : level === "HIGH"
                    ? "bg-orange-100 text-orange-700 border-orange-200"
                    : level === "MEDIUM"
                    ? "bg-amber-100 text-amber-700 border-amber-200"
                    : "bg-blue-100 text-blue-700 border-blue-200"
                )}>
                  {level} RISK
                </span>
              </div>
            </div>
          </div>

          {/* Explanation & Summary */}
          <div className="md:col-span-8 space-y-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                  DETERMINISTIC SOC RISK ENGINE
                </span>
                <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 border border-emerald-200">
                  SQLite Live Data
                </span>
              </div>
              <h2 className="text-2xl font-black text-slate-900 tracking-tight mt-0.5">
                Quantified Incident Risk: {selectedIncident?.incident_id || "INC-1024"}
              </h2>
            </div>

            {/* Formula Banner */}
            <div className="p-3 bg-blue-50/70 border border-blue-200/80 rounded-xl text-xs font-mono text-blue-900 flex items-center justify-between">
              <span className="font-bold">Scoring Formula:</span>
              <span className="text-[11px] text-blue-700">{formula}</span>
            </div>

            {/* Risk Explanation */}
            <div className="p-4 bg-white/90 rounded-xl neu-flat-sm border border-white">
              <p className="text-xs text-slate-700 leading-relaxed font-sans">
                &ldquo;{explanation}&rdquo;
              </p>
            </div>

            {/* Classification Spectrum */}
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
                <div className="p-2 rounded-xl bg-orange-50 border border-orange-200 text-orange-900 text-center">
                  <div className="font-bold">HIGH</div>
                  <div className="text-[10px] text-orange-700 font-mono">70 - 84</div>
                </div>
                <div className="p-2 rounded-xl bg-red-50 border border-red-200 text-red-800 text-center">
                  <div className="font-bold">CRITICAL</div>
                  <div className="text-[10px] text-red-600 font-mono">85 - 100</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Incident Selection Strip */}
      {riskData && riskData.incidents.length > 0 && (
        <div className="neu-flat rounded-2xl p-5 border border-white space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Select Incident to Evaluate ({riskData.incidents.length} Records)
            </h3>
            <span className="text-[11px] font-mono text-slate-400">
              Overall Fleet Risk: <strong className="text-slate-800">{riskData.overall_score}</strong> ({riskData.overall_level})
            </span>
          </div>
          <div className="flex items-center gap-2 overflow-x-auto pb-1">
            {riskData.incidents.map((inc) => {
              const isSelected = (selectedIncident?.incident_id || "") === inc.incident_id;
              return (
                <button
                  key={inc.incident_id}
                  onClick={() => setSelectedIncidentId(inc.incident_id)}
                  className={cn(
                    "px-3 py-2 rounded-xl text-xs font-mono transition-all shrink-0 flex items-center gap-2 border",
                    isSelected
                      ? "bg-blue-600 text-white border-blue-700 shadow-md"
                      : "bg-white/80 hover:bg-white text-slate-700 border-slate-200 neu-flat-sm"
                  )}
                >
                  <span className="font-bold">{inc.incident_id}</span>
                  <span
                    className={cn(
                      "text-[9px] px-1.5 py-0.2 rounded font-extrabold uppercase",
                      isSelected
                        ? "bg-white/20 text-white"
                        : inc.risk_level === "CRITICAL"
                        ? "bg-red-100 text-red-700"
                        : inc.risk_level === "HIGH"
                        ? "bg-orange-100 text-orange-700"
                        : "bg-amber-100 text-amber-700"
                    )}
                  >
                    {inc.calculated_risk_score}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Risk Factors Breakdown */}
      <div className="neu-flat rounded-2xl p-6 border border-white space-y-5">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
            Risk Factor Weighting & Breakdown ({selectedIncident?.incident_id || "Active Incident"})
          </h3>
          <span className="text-[10px] text-slate-400 font-mono">Weighted Rule Factors</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {factors.map((factor) => (
            <div key={factor.name} className="space-y-1.5 p-3.5 bg-white/70 rounded-xl neu-flat-sm border border-white">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-slate-800">{factor.name}</span>
                <div className="flex items-center gap-2">
                  <span
                    className={cn(
                      "text-[10px] font-extrabold px-2 py-0.5 rounded-full font-mono uppercase",
                      factor.level === "CRITICAL"
                        ? "bg-red-100 text-red-700"
                        : factor.level === "HIGH"
                        ? "bg-orange-100 text-orange-700"
                        : "bg-blue-100 text-blue-700"
                    )}
                  >
                    {factor.level}
                  </span>
                  <span className="font-mono font-bold text-slate-800">{factor.score}</span>
                </div>
              </div>

              <div className="h-2 w-full bg-slate-200 rounded-full overflow-hidden neu-pressed-sm">
                <div
                  className={cn(
                    "h-full rounded-full transition-all duration-700",
                    factor.level === "CRITICAL"
                      ? "bg-red-500"
                      : factor.level === "HIGH"
                      ? "bg-orange-500"
                      : "bg-blue-500"
                  )}
                  style={{ width: `${Math.min(100, factor.score)}%` }}
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
