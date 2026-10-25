"use client";
import React, { useState, useEffect } from "react";
import {
  FileCheck2,
  ShieldCheck,
  CheckCircle2,
  AlertOctagon,
  AlertTriangle,
  Lock,
  ExternalLink,
  Search,
  FileCode,
  ArrowUpRight,
  Database,
  RefreshCw,
} from "lucide-react";
import { CYBER_DATA, EvidenceItem } from "@/data/cyberData";
import { EvidenceModal } from "../evidence-modal";
import { fetchEvidenceList, ApiEvidenceItem } from "@/lib/api";
import { cn } from "@/lib/utils";

export function EvidenceView() {
  const [evidenceList, setEvidenceList] = useState<ApiEvidenceItem[]>([]);
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceItem | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [loading, setLoading] = useState(true);

  async function loadEvidence() {
    setLoading(true);
    try {
      const data = await fetchEvidenceList();
      setEvidenceList(data);
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadEvidence();
  }, []);

  // Map backend items to UI
  const displayItems =
    evidenceList.length > 0
      ? evidenceList.map((item) => ({
          id: item.id,
          fileName: item.file_name,
          incidentId: item.incident_id,
          sha256: item.stored_hash,
          storedHash: item.stored_hash,
          fileSize: item.file_size,
          blockchainStatus: item.blockchain_status,
          verificationStatus: item.verification_status,
          timestamp: item.timestamp,
          recordedBlock: item.recorded_block || "#0x8F91A204C",
        }))
      : CYBER_DATA.evidenceLedger;

  const filteredEvidence = displayItems.filter(
    (ev) =>
      ev.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.fileName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.incidentId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.sha256.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const verifiedCount = displayItems.filter((e) => e.verificationStatus === "VERIFIED").length;
  const tamperedCount = displayItems.filter((e) => e.verificationStatus === "TAMPERED").length;
  const verifiedPercentage = displayItems.length > 0 ? Math.round((verifiedCount / displayItems.length) * 100) : 0;

  const handleRowClick = (item: any) => {
    setSelectedEvidence(item);
    setShowModal(true);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner with Verification Proof */}
      <div className="neu-flat rounded-2xl p-6 border border-white flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="flex items-center gap-4">
          <div className={cn(
            "w-12 h-12 rounded-2xl flex items-center justify-center shadow-inner",
            tamperedCount > 0 ? "bg-amber-100 text-amber-700" : "bg-emerald-100 text-emerald-600"
          )}>
            <ShieldCheck className="w-7 h-7" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className={cn(
                "text-xs font-bold px-2.5 py-0.5 rounded-full uppercase",
                tamperedCount > 0
                  ? "bg-amber-100 text-amber-800 border border-amber-200"
                  : "bg-emerald-100 text-emerald-700 border border-emerald-200"
              )}>
                {tamperedCount > 0 ? "Tamper Detected in Ledger" : "Tamper-Evident Ledger Active"}
              </span>
              <span className="text-[11px] text-slate-400 font-mono">Live SHA-256 Engine</span>
            </div>
            <h2 className="text-xl font-extrabold text-slate-900 tracking-tight mt-1">
              Cryptographic Evidence Chain
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Forensic packet captures, authentication logs, and probe artifacts verified against genuine disk bytes.
            </p>
          </div>
        </div>

        <div className="text-right shrink-0">
          <span className="text-[10px] text-slate-400 font-mono block">INTEGRITY ASSURANCE</span>
          <span className={cn(
            "text-2xl font-black font-mono",
            tamperedCount > 0 ? "text-amber-600" : "text-emerald-600"
          )}>
            {verifiedPercentage}% VERIFIED
          </span>
          <span className="text-[10px] text-slate-400 block font-mono">
            {tamperedCount > 0 ? `${tamperedCount} Tampered / Test Violation` : "Zero Tamper Detections"}
          </span>
        </div>
      </div>

      {/* Table Section */}
      <div className="neu-flat rounded-2xl p-6 border border-white space-y-4">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Immutable Artifact Ledger ({displayItems.length} Artifacts)
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
              {filteredEvidence.map((ev) => {
                const isVerified = ev.verificationStatus === "VERIFIED";
                const isTampered = ev.verificationStatus === "TAMPERED";
                return (
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
                    <td className="py-3.5 font-mono text-slate-500 text-[11px]" title={ev.sha256}>
                      {ev.sha256.slice(0, 10)}...{ev.sha256.slice(-8)}
                    </td>
                    <td className="py-3.5">
                      <span className={cn(
                        "px-2 py-0.5 rounded-full text-[10px] font-semibold",
                        ev.blockchainStatus === "Recorded" ? "bg-blue-100 text-blue-700" : "bg-slate-200 text-slate-600"
                      )}>
                        {ev.blockchainStatus}
                      </span>
                    </td>
                    <td className="py-3.5">
                      <span
                        className={cn(
                          "inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-extrabold font-mono border",
                          isVerified
                            ? "bg-emerald-100 text-emerald-700 border-emerald-200"
                            : isTampered
                            ? "bg-rose-100 text-rose-700 border-rose-300 animate-pulse"
                            : "bg-amber-100 text-amber-700 border-amber-200"
                        )}
                      >
                        {isVerified ? (
                          <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                        ) : isTampered ? (
                          <AlertOctagon className="w-3 h-3 text-rose-600" />
                        ) : (
                          <AlertTriangle className="w-3 h-3 text-amber-600" />
                        )}
                        <span>{ev.verificationStatus}</span>
                      </span>
                    </td>
                    <td className="py-3.5 text-right font-mono text-slate-400 text-[11px]">
                      {ev.timestamp}
                    </td>
                  </tr>
                );
              })}
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
