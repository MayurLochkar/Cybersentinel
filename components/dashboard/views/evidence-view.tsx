"use client";
import React, { useState } from "react";
import {
  FileCheck2,
  ShieldCheck,
  CheckCircle2,
  Lock,
  ExternalLink,
  Search,
  FileCode,
  ArrowUpRight,
  Database,
} from "lucide-react";
import { CYBER_DATA, EvidenceItem } from "@/data/cyberData";
import { EvidenceModal } from "../evidence-modal";
import { cn } from "@/lib/utils";

export function EvidenceView() {
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceItem | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");

  const filteredEvidence = CYBER_DATA.evidenceLedger.filter(
    (ev) =>
      ev.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.fileName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.incidentId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.sha256.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleRowClick = (item: EvidenceItem) => {
    setSelectedEvidence(item);
    setShowModal(true);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner with Verification Proof */}
      <div className="neu-flat rounded-2xl p-6 border border-white flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-emerald-100 text-emerald-600 flex items-center justify-center shadow-inner">
            <ShieldCheck className="w-7 h-7" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-emerald-700 bg-emerald-100 px-2.5 py-0.5 rounded-full uppercase">
                Tamper-Evident Ledger Active
              </span>
              <span className="text-[11px] text-slate-400 font-mono">SHA-256 Engine</span>
            </div>
            <h2 className="text-xl font-extrabold text-slate-900 tracking-tight mt-1">
              Cryptographic Evidence Chain
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Forensic packet captures and authentication logs hashed at time of incident detection.
            </p>
          </div>
        </div>

        <div className="text-right shrink-0">
          <span className="text-[10px] text-slate-400 font-mono block">INTEGRITY ASSURANCE</span>
          <span className="text-2xl font-black text-emerald-600 font-mono">100% VERIFIED</span>
          <span className="text-[10px] text-slate-400 block font-mono">Zero Tamper Detections</span>
        </div>
      </div>

      {/* Table Section (Requirement 9) */}
      <div className="neu-flat rounded-2xl p-6 border border-white space-y-4">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Immutable Artifact Ledger
            </h3>
            <p className="text-[11px] text-slate-500">
              Click any evidence row to compare stored hash against live cryptographic runtime digest
            </p>
          </div>

          <div className="w-full sm:w-72 relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search file name or hash..."
              className="w-full pl-10 pr-4 py-2 bg-white/90 neu-pressed-sm rounded-xl text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/40 font-mono transition-all"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 text-slate-400 text-[10px] uppercase font-mono tracking-wider">
                <th className="pb-3 font-semibold">Evidence ID</th>
                <th className="pb-3 font-semibold">File Name</th>
                <th className="pb-3 font-semibold">Incident</th>
                <th className="pb-3 font-semibold">SHA-256 Hash</th>
                <th className="pb-3 font-semibold">Blockchain Status</th>
                <th className="pb-3 font-semibold">Verification Status</th>
                <th className="pb-3 font-semibold text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/80 font-sans">
              {filteredEvidence.map((ev) => (
                <tr
                  key={ev.id}
                  onClick={() => handleRowClick(ev)}
                  className="hover:bg-white/80 transition-colors cursor-pointer group"
                >
                  <td className="py-3.5 font-bold font-mono text-blue-600 group-hover:underline">
                    {ev.id}
                  </td>
                  <td className="py-3.5 font-mono text-slate-800 font-semibold flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-slate-400" />
                    <span>{ev.fileName}</span>
                  </td>
                  <td className="py-3.5 font-mono text-slate-600">{ev.incidentId}</td>
                  <td className="py-3.5 font-mono text-slate-500 text-[11px]">
                    {ev.sha256.slice(0, 10)}...{ev.sha256.slice(-8)}
                  </td>
                  <td className="py-3.5">
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-blue-100 text-blue-700">
                      {ev.blockchainStatus}
                    </span>
                  </td>
                  <td className="py-3.5">
                    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-extrabold font-mono bg-emerald-100 text-emerald-700 border border-emerald-200">
                      <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                      <span>{ev.verificationStatus}</span>
                    </span>
                  </td>
                  <td className="py-3.5 text-right font-mono text-slate-400 text-[11px]">
                    {ev.timestamp}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <EvidenceModal
        isOpen={showModal}
        onClose={() => setShowModal(false)}
        evidence={selectedEvidence}
      />
    </div>
  );
}
