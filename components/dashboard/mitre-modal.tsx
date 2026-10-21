"use client";
import React from "react";
import { X, ShieldAlert, ExternalLink, CheckCircle, Terminal, Layers } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

export function MitreModal({
  isOpen,
  onClose,
  techniqueId = "T1110",
  techniqueName = "Brute Force",
  tactic = "Credential Access",
}: {
  isOpen: boolean;
  onClose: () => void;
  techniqueId?: string;
  techniqueName?: string;
  tactic?: string;
}) {
  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          className="relative w-full max-w-2xl bg-[#eef3f8] rounded-3xl neu-flat border border-white p-6 md:p-8 shadow-2xl"
        >
          <div className="flex items-center justify-between pb-4 border-b border-slate-300">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-orange-100 text-orange-600 flex items-center justify-center font-bold text-xs">
                <Layers className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900">MITRE ATT&CK Matrix Intelligence</h3>
                <span className="text-[11px] text-slate-500 font-mono">Enterprise Framework v14.1</span>
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
                <span className="text-[10px] text-slate-400 font-mono block">TACTIC</span>
                <span className="text-sm font-bold text-slate-800">{tactic} (TA0006)</span>
              </div>
              <div className="bg-white/80 p-3 rounded-xl neu-pressed-sm">
                <span className="text-[10px] text-slate-400 font-mono block">TECHNIQUE ID</span>
                <span className="text-sm font-bold text-blue-600 font-mono">{techniqueId} — {techniqueName}</span>
              </div>
            </div>

            <div className="bg-white/90 p-4 rounded-xl neu-flat-sm border border-white">
              <h4 className="font-bold text-slate-800 mb-1">Adversary Behavior Pattern</h4>
              <p className="text-slate-600 leading-relaxed">
                Adversaries may attempt to gain access to accounts through repeated authentication attempts. Password Guessing or Credential Stuffing entails systematically submitting passwords against target usernames until authentication succeeds.
              </p>
            </div>

            <div className="space-y-2">
              <h4 className="font-bold text-slate-800">Autonomous Mitigation Actions</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <div className="p-2.5 rounded-lg bg-emerald-50 text-emerald-800 border border-emerald-200 flex items-center gap-2">
                  <CheckCircle className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                  <span>M1036: Account lockout threshold applied</span>
                </div>
                <div className="p-2.5 rounded-lg bg-emerald-50 text-emerald-800 border border-emerald-200 flex items-center gap-2">
                  <CheckCircle className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                  <span>M1032: Multi-factor challenge enforced</span>
                </div>
                <div className="p-2.5 rounded-lg bg-emerald-50 text-emerald-800 border border-emerald-200 flex items-center gap-2">
                  <CheckCircle className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                  <span>M1037: Ephemeral IP rate-limiting active</span>
                </div>
                <div className="p-2.5 rounded-lg bg-emerald-50 text-emerald-800 border border-emerald-200 flex items-center gap-2">
                  <CheckCircle className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                  <span>M1018: Threat feed hash quarantined</span>
                </div>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-200 flex justify-end gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-xl neu-flat hover:bg-white text-xs font-semibold text-slate-700"
            >
              Close
            </button>
            <a
              href="https://attack.mitre.org/techniques/T1110/"
              target="_blank"
              rel="noreferrer"
              className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1.5 shadow-md shadow-blue-500/25"
            >
              <span>View on MITRE ATT&CK</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
