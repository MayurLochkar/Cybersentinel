"use client";
import React, { useState } from "react";
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
} from "lucide-react";
import { CYBER_DATA } from "@/data/cyberData";
import { MitreModal } from "../mitre-modal";

export function ThreatIntelView() {
  const [searchQuery, setSearchQuery] = useState("185.73.21.10");
  const [showMitreModal, setShowMitreModal] = useState(false);
  const intel = CYBER_DATA.threatIntelligence;

  return (
    <div className="space-y-6 pb-12">
      {/* Search Bar (Requirement 7) */}
      <div className="neu-flat rounded-2xl p-5 border border-white">
        <label className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block mb-2 font-mono">
          Query Global Threat Intelligence Database
        </label>
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search IP / Domain / SHA-256 Hash / Attack Type (e.g. 185.73.21.10, example-threat.net)..."
            className="w-full pl-10 pr-4 py-2.5 bg-white/90 neu-pressed-sm rounded-xl text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/40 font-mono transition-all"
          />
        </div>
      </div>

      {/* Main Threat Intelligence Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* THREAT INDICATOR CARD (Requirement 7) */}
        <div className="lg:col-span-6 neu-flat rounded-2xl p-6 border border-white space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-xl bg-orange-100 text-orange-600 flex items-center justify-center font-bold">
                <Flame className="w-5 h-5" />
              </div>
              <div>
                <span className="text-[10px] font-mono text-slate-400 uppercase">THREAT INDICATOR</span>
                <h3 className="text-xl font-black text-slate-900 font-mono tracking-tight">
                  {intel.indicator}
                </h3>
              </div>
            </div>
            <span className="px-3 py-1 rounded-full text-[10px] font-extrabold tracking-wider bg-red-100 text-red-700 border border-red-200">
              {intel.status.toUpperCase()}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
              <span className="text-[10px] text-slate-400 font-mono block">TYPE</span>
              <span className="text-xs font-bold text-slate-800">{intel.type}</span>
            </div>
            <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
              <span className="text-[10px] text-slate-400 font-mono block">RISK</span>
              <span className="text-xs font-bold text-orange-600">{intel.risk}</span>
            </div>
            <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
              <span className="text-[10px] text-slate-400 font-mono block">STATUS</span>
              <span className="text-xs font-bold text-red-600">{intel.status}</span>
            </div>
            <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
              <span className="text-[10px] text-slate-400 font-mono block">ATTACK TYPE</span>
              <span className="text-xs font-bold text-blue-600">{intel.relatedAttack}</span>
            </div>
          </div>

          <div className="space-y-2 bg-white/80 p-4 rounded-xl neu-flat-sm border border-white text-xs">
            <div className="flex items-center justify-between py-1 border-b border-slate-100">
              <span className="text-slate-500 font-medium">Geolocation Origin:</span>
              <span className="font-semibold text-slate-800">{intel.country}</span>
            </div>
            <div className="flex items-center justify-between py-1 border-b border-slate-100">
              <span className="text-slate-500 font-medium">Network ASN:</span>
              <span className="font-mono text-slate-800">{intel.asn}</span>
            </div>
            <div className="flex items-center justify-between py-1">
              <span className="text-slate-500 font-medium">Composite Threat Index:</span>
              <span className="font-mono font-bold text-orange-600">{intel.reputationScore}</span>
            </div>
          </div>
        </div>

        {/* MITRE ATT&CK MAPPING & RELATED INDICATORS (Requirement 7) */}
        <div className="lg:col-span-6 space-y-6">
          {/* MITRE ATT&CK MAPPING */}
          <div className="neu-flat rounded-2xl p-6 border border-white space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-orange-600" />
                <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  MITRE ATT&CK Mapping
                </h3>
              </div>
              <button
                onClick={() => setShowMitreModal(true)}
                className="text-[11px] font-semibold text-blue-600 hover:underline flex items-center gap-1"
              >
                <span>Details</span>
                <ExternalLink className="w-3 h-3" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-[10px] text-slate-400 font-mono block">TACTIC</span>
                <span className="font-bold text-slate-800">{intel.mitre.tactic}</span>
              </div>
              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-[10px] text-slate-400 font-mono block">TECHNIQUE</span>
                <span className="font-bold text-orange-600 font-mono">{intel.mitre.technique}</span>
              </div>
            </div>

            <p className="text-xs text-slate-600 leading-relaxed bg-white/70 p-3 rounded-xl neu-flat-sm border border-white">
              {intel.mitre.description}
            </p>
          </div>

          {/* RELATED INDICATORS (Requirement 7) */}
          <div className="neu-flat rounded-2xl p-6 border border-white space-y-3">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-2">
              Correlated Artifacts & IOCs
            </h3>

            <div className="space-y-2 text-xs">
              <div className="p-2.5 bg-white/80 rounded-xl neu-pressed-sm flex items-center justify-between">
                <span className="text-slate-400 font-mono text-[10px]">SOURCE IP</span>
                <span className="font-mono font-bold text-slate-800">
                  {intel.relatedIndicators.sourceIp}
                </span>
              </div>

              <div className="p-2.5 bg-white/80 rounded-xl neu-pressed-sm flex items-center justify-between">
                <span className="text-slate-400 font-mono text-[10px]">RELATED DOMAIN</span>
                <span className="font-mono font-bold text-blue-600">
                  {intel.relatedIndicators.relatedDomain}
                </span>
              </div>

              <div className="p-2.5 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-slate-400 font-mono text-[10px] block mb-1">
                  MALICIOUS PAYLOAD HASH (SHA-256)
                </span>
                <span className="font-mono text-[11px] text-slate-700 break-all select-all">
                  {intel.relatedIndicators.hash}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <MitreModal
        isOpen={showMitreModal}
        onClose={() => setShowMitreModal(false)}
        techniqueId="T1110"
        techniqueName="Brute Force"
        tactic="Credential Access"
      />
    </div>
  );
}
