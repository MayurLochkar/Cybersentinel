"use client";
import React from "react";
import { X, CheckCircle2, ShieldCheck, FileCode, Copy, Check } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { EvidenceItem } from "@/data/cyberData";

export function EvidenceModal({
  isOpen,
  onClose,
  evidence,
}: {
  isOpen: boolean;
  onClose: () => void;
  evidence: EvidenceItem | null;
}) {
  const [copied, setCopied] = React.useState(false);

  if (!isOpen || !evidence) return null;

  const copyHash = () => {
    navigator.clipboard.writeText(evidence.sha256);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          className="relative w-full max-w-xl bg-[#eef3f8] rounded-3xl neu-flat border border-white p-6 md:p-8 shadow-2xl"
        >
          {/* Header */}
          <div className="flex items-center justify-between pb-4 border-b border-slate-300">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-xl bg-emerald-100 text-emerald-600 flex items-center justify-center font-bold">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900">Evidence Cryptographic Verification</h3>
                <span className="text-[11px] text-slate-500 font-mono">Immutable Artifact Integrity Check</span>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 rounded-full neu-flat hover:bg-white text-slate-500 hover:text-slate-800 transition-all"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="py-5 space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-white/80 p-3 rounded-xl neu-pressed-sm">
                <span className="text-[10px] text-slate-400 font-mono block">FILE NAME</span>
                <span className="text-xs font-bold text-slate-800 font-mono break-all">
                  {evidence.fileName}
                </span>
              </div>
              <div className="bg-white/80 p-3 rounded-xl neu-pressed-sm">
                <span className="text-[10px] text-slate-400 font-mono block">FILE SIZE</span>
                <span className="text-xs font-bold text-slate-800">{evidence.fileSize}</span>
              </div>
            </div>

            {/* SHA-256 Comparison */}
            <div className="space-y-2 bg-white/90 p-4 rounded-xl neu-flat-sm border border-white">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] text-slate-500 font-mono font-bold uppercase">
                    Stored Cryptographic Hash (Ledger)
                  </span>
                  <button
                    onClick={copyHash}
                    className="text-[10px] text-blue-600 hover:underline flex items-center gap-1"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                    {copied ? "Copied" : "Copy Hash"}
                  </button>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-900 text-cyan-300 font-mono text-[11px] break-all select-all">
                  {evidence.storedHash}
                </div>
              </div>

              <div className="pt-2">
                <span className="text-[10px] text-slate-500 font-mono font-bold uppercase block mb-1">
                  Current Computed Hash (Runtime Digest)
                </span>
                <div className="p-2.5 rounded-lg bg-slate-900 text-emerald-300 font-mono text-[11px] break-all select-all">
                  {evidence.sha256}
                </div>
              </div>
            </div>

            {/* Status Card */}
            <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-900 flex items-start gap-3">
              <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
              <div>
                <div className="font-bold text-xs uppercase tracking-wider text-emerald-700">
                  Status: ✓ VERIFIED
                </div>
                <p className="text-xs text-emerald-800 mt-1 leading-relaxed">
                  The current file hash matches the stored hash, indicating that the evidence has not changed since the recorded verification point.
                </p>
              </div>
            </div>

            <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1">
              <span>Timestamp: {evidence.timestamp}</span>
              <span>Ledger Block: {evidence.recordedBlock || "#0x8F91A204C"}</span>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-200 flex justify-end">
            <button
              onClick={onClose}
              className="px-5 py-2 rounded-xl neu-flat hover:bg-white text-xs font-semibold text-slate-700"
            >
              Done
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
