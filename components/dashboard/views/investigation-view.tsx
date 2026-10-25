"use client";
import React, { useState } from "react";
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
  Bot,
  Send,
  Terminal,
  Copy,
  Check,
  ShieldAlert,
  HelpCircle,
  Cpu,
} from "lucide-react";
import { Incident } from "@/data/cyberData";
import { cn } from "@/lib/utils";
import {
  investigateIncidentWithAI,
  chatWithAICopilot,
  ApiAIInvestigationResponse,
} from "@/lib/api";

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

  // AI & RAG Copilot State
  const [aiReport, setAiReport] = useState<ApiAIInvestigationResponse | null>(null);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [copiedRule, setCopiedRule] = useState(false);
  const [copilotQuery, setCopilotQuery] = useState("");
  const [isChatLoading, setIsChatLoading] = useState(false);
  const [chatHistory, setChatHistory] = useState<
    Array<{ role: "user" | "copilot"; content: string; technique?: string }>
  >([]);

  // Trigger RAG & LangChain Investigation
  const handleRunAiInvestigation = async () => {
    setIsAiLoading(true);
    try {
      const res = await investigateIncidentWithAI({
        incident_id: incident.id,
        attack_type: incident.attackType,
        source_ip: incident.sourceIp,
        destination_ip: incident.destinationIp || "10.0.0.1",
        confidence: incident.risk.score,
        reason: incident.investigation.summary,
      });
      setAiReport(res);
    } catch (err) {
      console.error("AI Investigation failed:", err);
    } finally {
      setIsAiLoading(false);
    }
  };

  // Submit Copilot Query
  const handleSendCopilotQuery = async (queryText?: string) => {
    const text = (queryText || copilotQuery).trim();
    if (!text || isChatLoading) return;

    const userMessage = { role: "user" as const, content: text };
    setChatHistory((prev) => [...prev, userMessage]);
    setCopilotQuery("");
    setIsChatLoading(true);

    try {
      const res = await chatWithAICopilot(text, incident.id, {
        attack_type: incident.attackType,
        source_ip: incident.sourceIp,
        destination_ip: incident.destinationIp,
      });
      setChatHistory((prev) => [
        ...prev,
        {
          role: "copilot",
          content: res.response,
          technique: res.rag_technique,
        },
      ]);
    } catch (err) {
      setChatHistory((prev) => [
        ...prev,
        {
          role: "copilot",
          content:
            "Unable to contact AI Copilot service. Please ensure the backend is running.",
        },
      ]);
    } finally {
      setIsChatLoading(false);
    }
  };

  const handleCopySnort = (rule: string) => {
    navigator.clipboard.writeText(rule);
    setCopiedRule(true);
    setTimeout(() => setCopiedRule(false), 2000);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Header Card with Stepper */}
      <div className="neu-flat rounded-2xl p-6 border border-white space-y-6">
        {/* Scope and Provider Status Banner */}
        <div className="p-3 bg-gradient-to-r from-blue-50 to-indigo-50/80 border border-blue-200/80 rounded-xl text-xs text-blue-900 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-6 h-6 rounded-lg bg-blue-600 text-white flex items-center justify-center">
              <Sparkles className="w-3.5 h-3.5" />
            </div>
            <span>
              <strong>RAG & LangChain Multi-Provider SOC Copilot:</strong> Grounded in MITRE ATT&CK &amp; NIST SP 800-61 incident response playbooks.
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono px-2.5 py-1 rounded bg-white text-blue-700 border border-blue-200 shadow-sm flex items-center gap-1.5 font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              RAG Vector Index: ONLINE
            </span>
          </div>
        </div>

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
                Deterministic Forensic Investigation Matrix
              </h2>
            </div>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            <button
              onClick={handleRunAiInvestigation}
              disabled={isAiLoading}
              className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-700 hover:to-cyan-700 text-white text-xs font-bold flex items-center gap-2 shadow-lg shadow-indigo-500/20 active:scale-95 transition-all disabled:opacity-50"
            >
              <Bot className={cn("w-4 h-4", isAiLoading && "animate-spin")} />
              <span>
                {isAiLoading
                  ? "Synthesizing with RAG..."
                  : "Run RAG & LangChain Synthesis"}
              </span>
            </button>

            <button
              onClick={onGenerateReport}
              className="px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold flex items-center gap-2 shadow-lg shadow-blue-500/20 active:scale-95 transition-all"
            >
              <FileText className="w-4 h-4" />
              <span>Generate Full Report</span>
            </button>
          </div>
        </div>

        {/* 7-Step Visual Progress Stepper */}
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

      {/* RAG & LangChain AI Copilot Dynamic Insight Box (when triggered) */}
      {aiReport && (
        <div className="neu-flat rounded-2xl p-6 border-2 border-indigo-200/80 bg-gradient-to-br from-white via-indigo-50/20 to-cyan-50/20 space-y-5 animate-in fade-in duration-300">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-indigo-100 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500 to-cyan-500 text-white flex items-center justify-center shadow-md">
                <Sparkles className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-extrabold text-slate-900">
                    AI Forensic Synthesis (RAG Augmented)
                  </h3>
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-indigo-100 text-indigo-700">
                    {aiReport.model_provider}
                  </span>
                </div>
                <p className="text-[11px] text-slate-500">
                  Grounded in {aiReport.rag_citations.join(" • ")}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold px-3 py-1 bg-white text-indigo-700 rounded-lg border border-indigo-200 shadow-sm">
                {aiReport.attack_classification.technique_id} — {aiReport.attack_classification.technique_name}
              </span>
            </div>
          </div>

          <div className="p-4 bg-white/90 rounded-xl border border-indigo-100 shadow-sm text-xs text-slate-800 leading-relaxed font-sans">
            <strong className="text-indigo-900 block mb-1">Executive Forensic Assessment:</strong>
            {aiReport.executive_summary}
          </div>

          {/* Containment Playbook & Snort Rule */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-white/90 rounded-xl border border-slate-200/80 space-y-2.5">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-800 uppercase tracking-wider">
                <ShieldAlert className="w-4 h-4 text-amber-600" />
                <span>NIST SP 800-61 Containment Checklist</span>
              </div>
              <ul className="space-y-2 text-xs text-slate-700">
                {aiReport.containment_playbook.map((step, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                    <span>{step}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="p-4 bg-slate-900 text-slate-200 rounded-xl border border-slate-800 space-y-2.5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2 text-xs font-mono font-bold text-cyan-400">
                    <Terminal className="w-4 h-4" />
                    <span>Auto-Generated Snort / Suricata Rule</span>
                  </div>
                  <button
                    onClick={() => handleCopySnort(aiReport.snort_defense_rule)}
                    className="text-[10px] font-mono px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center gap-1 border border-slate-700 transition-colors"
                  >
                    {copiedRule ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Copy Rule</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="text-[11px] font-mono bg-black/60 p-3 rounded-lg text-emerald-400 overflow-x-auto whitespace-pre-wrap leading-relaxed border border-slate-800">
                  {aiReport.snort_defense_rule}
                </pre>
              </div>
              <span className="text-[10px] text-slate-400">
                Deploy to <code>/etc/snort/rules/local.rules</code> or Suricata IDS engine.
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Grid: Investigation Findings & Related Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* INVESTIGATION FINDINGS */}
        <div className="lg:col-span-8 neu-flat rounded-2xl p-6 border border-white space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Forensic Findings &amp; Corroborated Facts
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

          {/* AI SUMMARY */}
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

          {/* Interactive SOC Copilot Q&A */}
          <div className="mt-6 p-5 bg-white/90 rounded-2xl neu-flat-sm border border-slate-200/70 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Bot className="w-4 h-4 text-indigo-600" />
                <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  Ask CyberSentinel Copilot (RAG Chat)
                </h4>
              </div>
              <span className="text-[10px] font-mono text-slate-400">
                Grounds queries in live incident context
              </span>
            </div>

            {/* Quick Suggestions */}
            <div className="flex flex-wrap gap-2">
              {[
                "How do I block this in iptables?",
                "What are the indicators of this attack?",
                "Draft an executive incident briefing",
              ].map((suggestion, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSendCopilotQuery(suggestion)}
                  className="px-2.5 py-1 text-[11px] rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200/60 transition-colors"
                >
                  {suggestion}
                </button>
              ))}
            </div>

            {/* Chat History */}
            {chatHistory.length > 0 && (
              <div className="space-y-3 max-h-60 overflow-y-auto p-3 bg-slate-50/70 rounded-xl border border-slate-200/50">
                {chatHistory.map((msg, i) => (
                  <div
                    key={i}
                    className={cn(
                      "p-3 rounded-xl text-xs leading-relaxed",
                      msg.role === "user"
                        ? "bg-blue-600 text-white ml-auto max-w-[85%]"
                        : "bg-white text-slate-800 border border-slate-200/80 mr-auto max-w-[90%] shadow-sm"
                    )}
                  >
                    <div className="flex items-center gap-1.5 font-bold mb-1 opacity-75 text-[10px]">
                      {msg.role === "user" ? "SOC Analyst" : "CyberSentinel AI Copilot"}
                    </div>
                    <div className="whitespace-pre-wrap font-sans">{msg.content}</div>
                  </div>
                ))}
              </div>
            )}

            {/* Input Bar */}
            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="Ask about attack mitigation, forensic signatures, firewall syntax..."
                value={copilotQuery}
                onChange={(e) => setCopilotQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSendCopilotQuery()}
                className="flex-1 px-4 py-2.5 rounded-xl border border-slate-200 text-xs bg-slate-50/60 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20"
              />
              <button
                onClick={() => handleSendCopilotQuery()}
                disabled={isChatLoading || !copilotQuery.trim()}
                className="px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold flex items-center gap-1.5 shadow-md shadow-blue-500/20 active:scale-95 disabled:opacity-40 transition-all"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Ask</span>
              </button>
            </div>
          </div>
        </div>

        {/* RELATED ACTIVITY */}
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
            className="w-full py-2.5 rounded-xl neu-flat hover:bg-white text-xs font-bold text-blue-600 flex items-center justify-center gap-1.5 transition-all mt-4"
          >
            <span>Proceed to Risk Assessment</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}
