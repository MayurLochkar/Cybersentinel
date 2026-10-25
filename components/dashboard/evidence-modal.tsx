"use client";
import React, { useState, useEffect } from "react";
import { X, CheckCircle2, AlertOctagon, AlertTriangle, ShieldCheck, FileCode, Copy, Check, RefreshCw } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { EvidenceItem } from "@/data/cyberData";
import { verifyEvidenceHash, ApiEvidenceVerifyResult } from "@/lib/api";
import { cn } from "@/lib/utils";

export function EvidenceModal({
  isOpen,
  onClose,
  evidence,
}: {
  isOpen: boolean;
  onClose: () => void;
  evidence: EvidenceItem | null;
}) {
  const [copied, setCopied] = useState(false);
  const [verifyResult, setVerifyResult] = useState<ApiEvidenceVerifyResult | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  useEffect(() => {
    if (!isOpen || !evidence) {
      setVerifyResult(null);
      return;
    }

    const currentEv = evidence;
    let isMounted = true;
    async function performLiveVerification() {
      setIsVerifying(true);
      try {
        const result = await verifyEvidenceHash(currentEv.id);
        if (isMounted) setVerifyResult(result);
      } catch (err: any) {
        if (isMounted) {
          setVerifyResult({
            evidence_id: currentEv.id,
            file_name: currentEv.fileName,
            stored_hash: currentEv.storedHash || currentEv.sha256,
            current_hash: "VERIFICATION_ERROR",
            verification_status: "ERROR",
            message: `Backend verification endpoint error: ${err.message || err}`,
            timestamp: new Date().toISOString(),
          });
        }
      } finally {
        if (isMounted) setIsVerifying(false);
      }
    }

    performLiveVerification();
    return () => {
      isMounted = false;
    };
  }, [isOpen, evidence]);

  if (!isOpen || !evidence) return null;

  const currentDisplayHash = verifyResult ? verifyResult.current_hash : evidence.sha256;
  const storedDisplayHash = verifyResult ? verifyResult.stored_hash : evidence.storedHash || evidence.sha256;
  const status = verifyResult ? verifyResult.verification_status : evidence.verificationStatus;

  const copyHash = (hashText: string) => {
    navigator.clipboard.writeText(hashText);
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
              <div className={cn(
                "w-9 h-9 rounded-xl flex items-center justify-center font-bold",
                status === "VERIFIED" ? "bg-emerald-100 text-emerald-600" : status === "TAMPERED" ? "bg-rose-100 text-rose-600" : "bg-amber-100 text-amber-600"
              )}>
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900">Live SHA-256 Evidence Verification</h3>
                <span className="text-[11px] text-slate-500 font-mono">
                  {isVerifying ? "Hashing disk bytes in real-time..." : "Disk Artifact Digest vs Forensic Ledger"}
                </span>
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
                    Stored Cryptographic Hash (Ledger Catalog)
                  </span>
                  <button
                    onClick={() => copyHash(storedDisplayHash)}
                    className="text-[10px] text-blue-600 hover:underline flex items-center gap-1"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                    <span>{copied ? "Copied" : "Copy Hash"}</span>
                  </button>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-900 text-cyan-300 font-mono text-[11px] break-all select-all">
                  {storedDisplayHash}
                </div>
              </div>

              <div className="pt-2">
                <span className="text-[10px] text-slate-500 font-mono font-bold uppercase block mb-1">
                  Current Computed Hash (Live SHA-256 over Disk Bytes)
                </span>
                <div className={cn(
                  "p-2.5 rounded-lg font-mono text-[11px] break-all select-all",
                  status === "VERIFIED"
                    ? "bg-slate-900 text-emerald-300"
                    : status === "TAMPERED"
                    ? "bg-rose-950 text-rose-300 ring-2 ring-rose-500"
                    : "bg-slate-900 text-amber-300"
                )}>
                  {isVerifying ? "Computing SHA-256..." : currentDisplayHash}
                </div>
              </div>
            </div>

            {/* Status Card */}
            {status === "VERIFIED" ? (
              <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-900 flex items-start gap-3">
                <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold text-xs uppercase tracking-wider text-emerald-700">
                    Status: ✓ VERIFIED (INTEGRITY CONFIRMED)
                  </div>
                  <p className="text-xs text-emerald-800 mt-1 leading-relaxed">
                    {verifyResult?.message ||
                      "The current file hash matches the stored hash, proving zero modification or corruption since evidence acquisition."}
                  </p>
                </div>
              </div>
            ) : status === "TAMPERED" ? (
              <div className="p-4 rounded-xl bg-rose-50 border border-rose-300 text-rose-900 flex items-start gap-3">
                <AlertOctagon className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold text-xs uppercase tracking-wider text-rose-700">
                    Status: ⚠ TAMPERED (INTEGRITY VIOLATION)
                  </div>
                  <p className="text-xs text-rose-800 mt-1 leading-relaxed">
                    {verifyResult?.message ||
                      "INTEGRITY VIOLATION: Current SHA-256 hash does not match recorded catalog hash. File bytes have been modified or corrupted."}
                  </p>
                </div>
              </div>
            ) : (
              <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold text-xs uppercase tracking-wider text-amber-700">
                    Status: ⚠ {status}
                  </div>
                  <p className="text-xs text-amber-800 mt-1 leading-relaxed">
                    {verifyResult?.message || "Artifact could not be verified against disk storage."}
                  </p>
                </div>
              </div>
            )}

            <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1">
              <span>Verified: {verifyResult?.timestamp ? verifyResult.timestamp.slice(0, 19).replace("T", " ") + " UTC" : evidence.timestamp}</span>
              <span>Ledger Block: {evidence.recordedBlock || "#0x8F91A204C"}</span>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-200 flex justify-end">
            <button
              onClick={onClose}
              className="px-5 py-2 rounded-xl neu-flat hover:bg-white text-xs font-semibold text-slate-700 active:scale-95 transition-all"
            >
              Done
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
