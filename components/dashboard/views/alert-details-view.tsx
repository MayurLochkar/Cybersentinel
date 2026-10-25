"use client";
import React, { useState } from "react";
import {
  ShieldAlert,
  Clock,
  Network,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  FileText,
  BrainCircuit,
  ArrowRight,
  ArrowLeft,
  Sparkles,
  Layers,
  Check,
  ShieldCheck,
  Ban,
  Sliders,
  Terminal,
  Info,
  Copy,
} from "lucide-react";
import { Incident } from "@/data/cyberData";
import { MitreModal } from "../mitre-modal";
import { cn } from "@/lib/utils";

import { updateAlertStatus } from "@/lib/api";

export function AlertDetailsView({
  incident,
  onStartInvestigation,
  onGenerateReport,
  onBack,
}: {
  incident: Incident;
  onStartInvestigation: () => void;
  onGenerateReport: () => void;
  onBack: () => void;
}) {
  const [showMitreModal, setShowMitreModal] = useState(false);
  const [currentStatus, setCurrentStatus] = useState<string>(incident.status);
  const [toastMsg, setToastMsg] = useState("");
  const [isUpdating, setIsUpdating] = useState(false);
  const [isBlocked, setIsBlocked] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const handleUpdateStatus = async (newStatus: "Open" | "Investigating" | "Resolved") => {
    setIsUpdating(true);
    try {
      await updateAlertStatus(incident.id, newStatus);
      setCurrentStatus(newStatus);
      setToastMsg(`Status updated to '${newStatus}' and persisted in SQLite.`);
    } catch (err: any) {
      setToastMsg(`Status update error: ${err.message || err}`);
    } finally {
      setIsUpdating(false);
      setTimeout(() => setToastMsg(""), 3500);
    }
  };

  const displayDestIp = incident.destinationIp || "10.0.0.21";

  return (
    <div className="space-y-6 pb-12">
      {/* Back button & Incident Headline Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-2 rounded-xl neu-flat hover:bg-white text-slate-600 transition-all active:scale-95"
            title="Back to alerts"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-blue-600 bg-blue-100/70 px-2 py-0.5 rounded-md">
                INCIDENT #{incident.id.replace("INC-", "")}
              </span>
              <span
                className={cn(
                  "text-[10px] font-extrabold font-mono px-2 py-0.5 rounded-full uppercase",
                  incident.severity === "CRITICAL"
                    ? "bg-red-100 text-red-700 border border-red-200"
                    : incident.severity === "HIGH"
                    ? "bg-orange-100 text-orange-700 border border-orange-200"
                    : "bg-amber-100 text-amber-700 border border-amber-200"
                )}
              >
                {incident.severity}
              </span>
              <span
                className={cn(
                  "text-[10px] font-semibold px-2 py-0.5 rounded-full",
                  currentStatus === "Resolved"
                    ? "bg-emerald-100 text-emerald-800"
                    : currentStatus === "Investigating"
                    ? "bg-blue-100 text-blue-700"
                    : "bg-slate-200 text-slate-700"
                )}
              >
                {currentStatus}
              </span>
            </div>
            <h2 className="text-2xl font-black text-slate-900 tracking-tight mt-1">
              {incident.attackType} Attack
            </h2>
          </div>
        </div>

        {/* Action Buttons (Requirement 5) */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={onStartInvestigation}
            className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white text-xs font-bold flex items-center gap-2 shadow-lg shadow-blue-500/20 active:scale-95 transition-all"
          >
            <BrainCircuit className="w-4 h-4" />
            <span>Start AI Investigation</span>
          </button>

          {currentStatus !== "Investigating" && (
            <button
              disabled={isUpdating}
              onClick={() => handleUpdateStatus("Investigating")}
              className="px-4 py-2.5 rounded-xl neu-flat hover:bg-white text-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-all active:scale-95 disabled:opacity-50"
            >
              <CheckCircle2 className="w-4 h-4 text-blue-600" />
              <span>Mark as Investigating</span>
            </button>
          )}

          {currentStatus !== "Resolved" && (
            <button
              disabled={isUpdating}
              onClick={() => handleUpdateStatus("Resolved")}
              className="px-4 py-2.5 rounded-xl neu-flat hover:bg-white text-emerald-800 text-xs font-semibold flex items-center gap-1.5 transition-all active:scale-95 disabled:opacity-50"
            >
              <Check className="w-4 h-4 text-emerald-600" />
              <span>Resolve Incident</span>
            </button>
          )}

          <button
            onClick={onGenerateReport}
            className="px-4 py-2.5 rounded-xl neu-flat hover:bg-white text-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-all active:scale-95"
          >
            <FileText className="w-4 h-4 text-blue-600" />
            <span>Generate Report</span>
          </button>
        </div>
      </div>

      {toastMsg && (
        <div className="p-3 bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs rounded-xl flex items-center gap-2 font-medium">
          <Check className="w-4 h-4 text-emerald-600" />
          <span>{toastMsg}</span>
        </div>
      )}

      {/* Metadata Telemetry Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="neu-flat-sm rounded-xl p-3.5 bg-white/70 border border-white">
          <span className="text-[10px] text-slate-400 font-mono block">SOURCE IP</span>
          <span className="text-xs font-bold font-mono text-slate-800">{incident.sourceIp}</span>
        </div>
        <div className="neu-flat-sm rounded-xl p-3.5 bg-white/70 border border-white">
          <span className="text-[10px] text-slate-400 font-mono block">DESTINATION IP</span>
          <span className="text-xs font-bold font-mono text-slate-800">{displayDestIp}</span>
        </div>
        <div className="neu-flat-sm rounded-xl p-3.5 bg-white/70 border border-white">
          <span className="text-[10px] text-slate-400 font-mono block">PROTOCOL</span>
          <span className="text-xs font-bold font-mono text-slate-800">{incident.protocol}</span>
        </div>
        <div className="neu-flat-sm rounded-xl p-3.5 bg-white/70 border border-white">
          <span className="text-[10px] text-slate-400 font-mono block">DEST PORT</span>
          <span className="text-xs font-bold font-mono text-slate-800">{incident.port}</span>
        </div>
        <div className="neu-flat-sm rounded-xl p-3.5 bg-white/70 border border-white">
          <span className="text-[10px] text-slate-400 font-mono block">MODEL CONFIDENCE</span>
          <span className="text-xs font-bold font-mono text-cyan-600">{incident.confidence}%</span>
        </div>
        <div className="neu-flat-sm rounded-xl p-3.5 bg-white/70 border border-white">
          <span className="text-[10px] text-slate-400 font-mono block">DETECTION TIME</span>
          <span className="text-xs font-bold font-mono text-slate-800">{incident.detectionTime}</span>
        </div>
      </div>


      {/* 3-PILLAR TRIAGE SECTION: SUMMARY, REASON, SOLUTION */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* PILLAR 1: SUMMARY (क्या हुआ) */}
        <div className="neu-flat rounded-2xl p-5 border border-white bg-gradient-to-b from-blue-50/40 via-white to-white space-y-3.5">
          <div className="flex items-center justify-between border-b border-blue-100 pb-2.5">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-blue-100 text-blue-700 flex items-center justify-center font-bold text-xs">
                01
              </div>
              <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">
                Threat Summary (क्या हुआ)
              </h3>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 font-bold">
              {incident.attackType}
            </span>
          </div>

          <p className="text-xs text-slate-700 leading-relaxed font-medium">
            CyberSentinel-X detected malicious network telemetry originating from host{" "}
            <span className="font-mono font-bold text-slate-900 bg-slate-100 px-1 py-0.5 rounded">
              {incident.sourceIp}
            </span>{" "}
            targeting{" "}
            <span className="font-mono font-bold text-slate-900 bg-slate-100 px-1 py-0.5 rounded">
              {displayDestIp}:{incident.port}
            </span>{" "}
            via protocol <span className="font-bold">{incident.protocol}</span>.
          </p>

          <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/60 text-[11px] space-y-1.5 font-mono">
            <div className="flex justify-between">
              <span className="text-slate-400">IMPACT LEVEL:</span>
              <span className="font-bold text-rose-600">{incident.severity} RISK</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">ML CONFIDENCE:</span>
              <span className="font-bold text-cyan-600">{incident.confidence}% evaluated</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">CURRENT STATUS:</span>
              <span className="font-bold text-slate-700">{currentStatus}</span>
            </div>
          </div>
        </div>

        {/* PILLAR 2: REASON (क्यों और कैसे आया) */}
        <div className="neu-flat rounded-2xl p-5 border border-white bg-gradient-to-b from-amber-50/40 via-white to-white space-y-3.5">
          <div className="flex items-center justify-between border-b border-amber-100 pb-2.5">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-amber-100 text-amber-800 flex items-center justify-center font-bold text-xs">
                02
              </div>
              <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">
                Detection Reason (क्यों & कैसे आया)
              </h3>
            </div>
            <span className="text-[10px] font-mono text-amber-700 font-bold bg-amber-50 px-2 py-0.5 rounded">
              Random Forest RF-70
            </span>
          </div>

          <p className="text-xs text-slate-600 leading-relaxed">
            The flow diverged from legitimate baseline traffic across multiple CICIDS2017 feature dimensions:
          </p>

          <div className="space-y-2 text-xs">
            <div className="flex items-start gap-2 p-2 rounded-lg bg-white border border-amber-200/50">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold text-slate-800 block text-[11px]">Packet Rate Burst Anomaly</span>
                <span className="text-[10px] text-slate-500">Flow Packets/s exceeded standard 99th percentile threshold.</span>
              </div>
            </div>

            <div className="flex items-start gap-2 p-2 rounded-lg bg-white border border-amber-200/50">
              <Network className="w-3.5 h-3.5 text-amber-600 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold text-slate-800 block text-[11px]">Asymmetric Flow Ratio</span>
                <span className="text-[10px] text-slate-500">Unbalanced forward vs backward response typical of probes or floods.</span>
              </div>
            </div>

            <div className="flex items-start gap-2 p-2 rounded-lg bg-white border border-amber-200/50">
              <Cpu className="w-3.5 h-3.5 text-amber-600 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold text-slate-800 block text-[11px]">Automated Flag Distribution</span>
                <span className="text-[10px] text-slate-500">TCP control flags matched signature for {incident.attackType}.</span>
              </div>
            </div>
          </div>
        </div>

        {/* PILLAR 3: SOLUTION (इसका Solution क्या है) */}
        <div className="neu-flat rounded-2xl p-5 border border-white bg-gradient-to-b from-emerald-50/40 via-white to-white space-y-3.5">
          <div className="flex items-center justify-between border-b border-emerald-100 pb-2.5">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-emerald-100 text-emerald-800 flex items-center justify-center font-bold text-xs">
                03
              </div>
              <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">
                Actionable Solution (Solution क्या है)
              </h3>
            </div>
            <span className="text-[10px] font-mono text-emerald-700 font-bold bg-emerald-50 px-2 py-0.5 rounded">
              Playbook
            </span>
          </div>

          <div className="space-y-2.5 text-xs">
            {/* Action 1: IP Block */}
            <div className="p-2.5 bg-white rounded-xl border border-slate-200 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-800 flex items-center gap-1.5 text-[11px]">
                  <Ban className="w-3.5 h-3.5 text-rose-600" />
                  1. Firewall Inbound Block
                </span>
                <button
                  onClick={() => {
                    setIsBlocked(!isBlocked);
                    setToastMsg(
                      !isBlocked
                        ? `Firewall rule applied: Inbound traffic from ${incident.sourceIp} BLOCKED.`
                        : `Firewall block removed for ${incident.sourceIp}.`
                    );
                    setTimeout(() => setToastMsg(""), 3500);
                  }}
                  className={cn(
                    "text-[10px] font-bold px-2 py-1 rounded-lg transition-all active:scale-95",
                    isBlocked
                      ? "bg-emerald-600 text-white"
                      : "bg-rose-600 hover:bg-rose-700 text-white"
                  )}
                >
                  {isBlocked ? "Rule Active (Blocked)" : "Apply IP Block"}
                </button>
              </div>
              <div className="flex items-center justify-between bg-slate-900 text-emerald-400 p-1.5 rounded font-mono text-[9px]">
                <span className="truncate">netsh advfirewall firewall add rule name="Block_{incident.sourceIp}" dir=in action=block remoteip={incident.sourceIp}</span>
                <button
                  onClick={() => {
                    navigator.clipboard?.writeText(`netsh advfirewall firewall add rule name="Block_${incident.sourceIp}" dir=in action=block remoteip=${incident.sourceIp}`);
                    setCopiedCmd(true);
                    setTimeout(() => setCopiedCmd(false), 2000);
                  }}
                  className="ml-1 text-slate-400 hover:text-white"
                  title="Copy PowerShell command"
                >
                  {copiedCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
            </div>

            {/* Action 2: Rate Limiting */}
            <div className="p-2.5 bg-white rounded-xl border border-slate-200">
              <span className="font-bold text-slate-800 flex items-center gap-1.5 text-[11px]">
                <Sliders className="w-3.5 h-3.5 text-blue-600" />
                2. Port & Rate Limiting Policy
              </span>
              <p className="text-[10px] text-slate-500 mt-1 leading-snug">
                Cap connections on Port {incident.port} to 50 req/min and drop TCP SYN packets without cookie verification.
              </p>
            </div>

            {/* Action 3: Incident Containment */}
            <div className="p-2.5 bg-white rounded-xl border border-slate-200">
              <span className="font-bold text-slate-800 flex items-center gap-1.5 text-[11px]">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                3. Triage & Incident Lifecycle
              </span>
              <div className="flex items-center gap-2 mt-1.5">
                <button
                  disabled={isUpdating || currentStatus === "Resolved"}
                  onClick={() => handleUpdateStatus("Resolved")}
                  className="flex-1 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-[10px] flex items-center justify-center gap-1 transition-all active:scale-95 disabled:opacity-50"
                >
                  <Check className="w-3 h-3" />
                  <span>Mark as Remediated</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Analysis Sections */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Attack Timeline & MITRE ATT&CK Context */}
        <div className="lg:col-span-6 space-y-6">
          {/* ATTACK TIMELINE (Requirement 5) */}
          <div className="neu-flat rounded-2xl p-6 border border-white">
            <div className="flex items-center gap-2 mb-5">
              <Clock className="w-4 h-4 text-blue-600" />
              <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                Attack Timeline
              </h3>
            </div>

            <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-300">
              {incident.timeline.map((item, idx) => (
                <div key={idx} className="relative group">
                  {/* Timeline dot */}
                  <div className="absolute -left-[25px] top-1 w-3.5 h-3.5 rounded-full bg-white border-2 border-blue-600 shadow-sm" />
                  <div className="text-[11px] font-mono font-bold text-blue-600">{item.time}</div>
                  <h4 className="text-xs font-bold text-slate-800 mt-0.5">{item.event}</h4>
                  {item.detail && (
                    <p className="text-[11px] text-slate-500 mt-0.5 leading-relaxed">
                      {item.detail}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* MITRE ATT&CK CONTEXT (Requirement 5) */}
          <div className="neu-flat rounded-2xl p-6 border border-white">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-orange-600" />
                <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  MITRE ATT&CK Context
                </h3>
              </div>
              <span className="text-[10px] text-slate-400 font-mono">v14 Mapping</span>
            </div>

            <div className="grid grid-cols-2 gap-3 mb-4">
              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-[10px] text-slate-400 font-mono block">TACTIC</span>
                <span className="text-xs font-bold text-slate-800">{incident.mitre.tactic}</span>
              </div>
              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-[10px] text-slate-400 font-mono block">TECHNIQUE</span>
                <span className="text-xs font-bold text-orange-600 font-mono">
                  {incident.mitre.technique} ({incident.mitre.techniqueId})
                </span>
              </div>
            </div>

            <p className="text-xs text-slate-600 leading-relaxed mb-4">
              {incident.mitre.description}
            </p>

            <button
              onClick={() => setShowMitreModal(true)}
              className="w-full py-2.5 rounded-xl neu-flat hover:bg-white text-xs font-semibold text-slate-700 flex items-center justify-center gap-1.5 transition-all active:scale-95"
            >
              <span>View Technique Details</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Right Column: AI ANALYSIS Card */}
        <div className="lg:col-span-6 space-y-6">
          {/* AI ANALYSIS Card (Requirement 5) */}
          <div className="neu-flat rounded-2xl p-6 border border-white space-y-5 bg-gradient-to-br from-white/90 to-[#eef3f8]">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-cyan-100 text-cyan-600 flex items-center justify-center">
                <Sparkles className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  AI Forensic Analysis
                </h3>
                <span className="text-[10px] text-slate-400 font-mono">Autonomous Reasoning Co-Pilot</span>
              </div>
            </div>

            <div className="p-4 bg-white rounded-xl neu-flat-sm border border-slate-100 space-y-2">
              <h4 className="text-sm font-bold text-slate-800">
                {incident.aiExplanation.title}
              </h4>
              <p className="text-xs text-slate-600 leading-relaxed">
                &ldquo;{incident.aiExplanation.description}&rdquo;
              </p>
            </div>

            <div>
              <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider mb-3">
                Detection Indicators
              </h4>
              <div className="space-y-2 text-xs">
                {incident.aiExplanation.indicators.map((indicator, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-2.5 p-2.5 bg-white/70 rounded-xl neu-pressed-sm border border-slate-200/40"
                  >
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                    <span className="font-medium text-slate-700">{indicator}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-2">
              <button
                onClick={onStartInvestigation}
                className="w-full py-3 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold flex items-center justify-center gap-2 shadow-md shadow-blue-500/25 transition-all"
              >
                <span>Drill Deeper into AI Investigation</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </div>

      <MitreModal
        isOpen={showMitreModal}
        onClose={() => setShowMitreModal(false)}
        techniqueId={incident.mitre.techniqueId}
        techniqueName={incident.mitre.technique}
        tactic={incident.mitre.tactic}
      />
    </div>
  );
}
