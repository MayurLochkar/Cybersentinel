"use client";
import React, { useState, useEffect } from "react";
import {
  Search,
  Flame,
  Globe,
  ShieldAlert,
  Layers,
  Hash,
  ExternalLink,
  MapPin,
  Clock,
  Server,
  ArrowRight,
  ShieldCheck,
  AlertTriangle,
} from "lucide-react";
import { CYBER_DATA } from "@/data/cyberData";
import { MitreModal } from "../mitre-modal";
import { fetchThreatIntelLookup, ApiThreatIntelResult } from "@/lib/api";
import { cn } from "@/lib/utils";

export function ThreatIntelView() {
  const [searchQuery, setSearchQuery] = useState("185.73.21.10");
  const [showMitreModal, setShowMitreModal] = useState(false);
  const [intelData, setIntelData] = useState<ApiThreatIntelResult | null>(null);
  const [loading, setLoading] = useState(false);

  const performLookup = async (q: string) => {
    if (!q.trim()) return;
    setLoading(true);
    try {
      const data = await fetchThreatIntelLookup(q.trim());
      setIntelData(data);
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    performLookup("185.73.21.10");
  }, []);

  const defaultIntel = CYBER_DATA.threatIntelligence;
  const primaryTechnique =
    intelData?.mitre_techniques && intelData.mitre_techniques.length > 0
      ? intelData.mitre_techniques[0]
      : {
          attack_type: "Brute Force",
          tactic: "Credential Access",
          technique_id: "T1110",
          technique_name: "Brute Force",
          description: defaultIntel.mitre.description,
          mitigation: "M1036 - Account Use Policies, M1032 - Multi-factor Authentication",
        };

  return (
    <div className="space-y-6 pb-12">
      {/* Search Bar */}
      <div className="neu-flat rounded-2xl p-5 border border-white space-y-3">
        <div className="flex items-center justify-between">
          <label className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block font-mono">
            Query Local Threat Matrix & MITRE ATT&CK Matrix
          </label>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
            Offline Deterministic SOC Mode
          </span>
        </div>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && performLookup(searchQuery)}
              placeholder="Search IP, incident ID, or attack vector (e.g. 185.73.21.10, INC-1024, Port Scan)..."
              className="w-full pl-10 pr-4 py-2.5 bg-white/90 neu-pressed-sm rounded-xl text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/40 font-mono transition-all"
            />
          </div>
          <button
            onClick={() => performLookup(searchQuery)}
            disabled={loading}
            className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold font-mono transition-all disabled:opacity-50"
          >
            {loading ? "Searching..." : "Lookup"}
          </button>
        </div>
      </div>

      {/* Main Threat Intelligence Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Threat Indicator Card */}
        <div className="lg:col-span-6 neu-flat rounded-2xl p-6 border border-white space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-xl bg-orange-100 text-orange-600 flex items-center justify-center font-bold">
                <Flame className="w-5 h-5" />
              </div>
              <div>
                <span className="text-[10px] font-mono text-slate-400 uppercase">QUERY TARGET</span>
                <h3 className="text-xl font-black text-slate-900 font-mono tracking-tight">
                  {intelData?.query || searchQuery}
                </h3>
              </div>
            </div>
            <span
              className={cn(
                "px-3 py-1 rounded-full text-[10px] font-extrabold tracking-wider border font-mono uppercase",
                (intelData?.reputation_level || defaultIntel.status) === "MALICIOUS"
                  ? "bg-red-100 text-red-700 border-red-200"
                  : (intelData?.reputation_level || defaultIntel.status) === "SUSPICIOUS"
                  ? "bg-orange-100 text-orange-700 border-orange-200"
                  : "bg-blue-100 text-blue-700 border-blue-200"
              )}
            >
              {intelData?.reputation_level || defaultIntel.status}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
              <span className="text-[10px] text-slate-400 font-mono block">MATCHED ALERTS</span>
              <span className="text-xs font-bold text-slate-800 font-mono">
                {intelData?.matched_incidents_count ?? 1} in SQLite
              </span>
            </div>
            <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
              <span className="text-[10px] text-slate-400 font-mono block">THREAT SCORE</span>
              <span className="text-xs font-bold text-orange-600 font-mono">
                {intelData?.reputation_score ?? 92}/100
              </span>
            </div>
            <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
              <span className="text-[10px] text-slate-400 font-mono block">ATTACK PATTERN</span>
              <span className="text-xs font-bold text-blue-600 truncate block">
                {primaryTechnique.attack_type}
              </span>
            </div>
          </div>

          <div className="space-y-2 bg-white/80 p-4 rounded-xl neu-flat-sm border border-white text-xs">
            <div className="flex items-center justify-between py-1 border-b border-slate-100">
              <span className="text-slate-500 font-medium">Data Pipeline Origin:</span>
              <span className="font-semibold text-slate-800">CyberSentinel-X Forensic Store</span>
            </div>
            <div className="flex items-center justify-between py-1 border-b border-slate-100">
              <span className="text-slate-500 font-medium">Correlated MITRE Technique:</span>
              <span className="font-mono text-slate-800">{primaryTechnique.technique_id} - {primaryTechnique.technique_name}</span>
            </div>
            <div className="flex items-center justify-between py-1">
              <span className="text-slate-500 font-medium">Recommended Mitigation:</span>
              <span className="text-slate-700 text-[11px] truncate max-w-[280px]" title={primaryTechnique.mitigation}>
                {primaryTechnique.mitigation}
              </span>
            </div>
          </div>

          {/* Matched Incidents in Database */}
          {intelData && intelData.matched_incidents.length > 0 && (
            <div className="space-y-2 pt-2">
              <h4 className="text-[11px] font-bold text-slate-700 uppercase font-mono">
                Correlated Database Records ({intelData.matched_incidents.length})
              </h4>
              <div className="space-y-1.5 max-h-44 overflow-y-auto pr-1">
                {intelData.matched_incidents.map((m) => (
                  <div
                    key={m.incident_id}
                    className="p-2.5 rounded-lg bg-white/90 border border-slate-200 flex items-center justify-between text-xs font-mono"
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-blue-600">{m.incident_id}</span>
                      <span className="text-slate-600 font-sans">{m.attack_type}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-slate-500">{m.target}</span>
                      <span className={cn(
                        "text-[9px] px-1.5 py-0.2 rounded font-bold uppercase",
                        m.severity === "CRITICAL" ? "bg-red-100 text-red-700" : "bg-orange-100 text-orange-700"
                      )}>
                        {m.severity}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* MITRE ATT&CK Mapping Card */}
        <div className="lg:col-span-6 space-y-6">
          <div className="neu-flat rounded-2xl p-6 border border-white space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-orange-600" />
                <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  MITRE ATT&CK Matrix Correlation
                </h3>
              </div>
              <button
                onClick={() => setShowMitreModal(true)}
                className="text-[11px] font-semibold text-blue-600 hover:underline flex items-center gap-1"
              >
                <span>Full Details</span>
                <ExternalLink className="w-3 h-3" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-[10px] text-slate-400 font-mono block">TACTIC</span>
                <span className="font-bold text-slate-800">{primaryTechnique.tactic}</span>
              </div>
              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-[10px] text-slate-400 font-mono block">TECHNIQUE</span>
                <span className="font-bold text-orange-600 font-mono">
                  {primaryTechnique.technique_id} - {primaryTechnique.technique_name}
                </span>
              </div>
            </div>

            <p className="text-xs text-slate-600 leading-relaxed bg-white/70 p-3 rounded-xl neu-flat-sm border border-white">
              {primaryTechnique.description}
            </p>
          </div>

          <div className="neu-flat rounded-2xl p-6 border border-white space-y-3">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-2">
              Defense Countermeasures
            </h3>
            <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm text-xs space-y-2">
              <p className="text-slate-700 leading-relaxed">
                <strong>Mitigation Guidance:</strong> {primaryTechnique.mitigation}
              </p>
              <div className="pt-2 border-t border-slate-200/60 flex items-center justify-between text-[11px] font-mono text-slate-500">
                <span>SOC Policy: Strict Ingress Filtering</span>
                <span className="text-emerald-600 font-semibold">Active Enforcement</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <MitreModal
        isOpen={showMitreModal}
        onClose={() => setShowMitreModal(false)}
        techniqueId={primaryTechnique.technique_id}
        techniqueName={primaryTechnique.technique_name}
        tactic={primaryTechnique.tactic}
      />
    </div>
  );
}
