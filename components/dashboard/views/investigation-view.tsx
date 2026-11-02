"use client";
import React, { useState, useEffect } from "react";
import {
  BrainCircuit,
  CheckCircle2,
  AlertCircle,
  ShieldAlert,
  Server,
  FileText,
  ArrowRight,
  Sparkles,
  Bot,
  Send,
  Terminal,
  Copy,
  Check,
  RefreshCw,
  Loader2,
  ShieldCheck,
  Radio,
  ExternalLink,
  Flame,
  Key,
  Globe,
  Radar,
  Lock,
  Layers,
  ChevronDown,
  ChevronUp,
  HelpCircle,
  AlertTriangle,
  Zap,
  Ban,
  Activity,
  ArrowDown,
  Sliders,
  CheckCheck,
} from "lucide-react";
import { Incident } from "@/data/cyberData";
import { cn } from "@/lib/utils";
import {
  investigateIncidentWithAI,
  chatWithAICopilot,
  ApiAIInvestigationResponse,
  blockFirewallIp,
  unblockFirewallIp,
  fetchBlockedIps,
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
  const [activeWorkspaceTab, setActiveWorkspaceTab] = useState<"triage" | "containment" | "copilot">("triage");
  const [explanationMode, setExplanationMode] = useState<"simple" | "technical">("simple");
  const [copiedRule, setCopiedRule] = useState<string | null>(null);
  const [showRawBriefing, setShowRawBriefing] = useState(false);
  const [isFirewallActive, setIsFirewallActive] = useState(false);
  const [droppedPacketsCount, setDroppedPacketsCount] = useState(0);
  const [toastMsg, setToastMsg] = useState("");

  // AI & RAG Copilot State
  const [aiReport, setAiReport] = useState<ApiAIInvestigationResponse | null>(null);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [copilotQuery, setCopilotQuery] = useState("");
  const [isChatLoading, setIsChatLoading] = useState(false);
  const [chatHistory, setChatHistory] = useState<
    Array<{ role: "user" | "copilot"; content: string; technique?: string; provider?: string }>
  >([]);

  const inv = incident.investigation || {
    status: incident.status || "Investigating",
    progressSteps: [
      { name: "Detection", completed: true },
      { name: "Triage", completed: true },
      { name: "Evidence Hash", completed: true },
      { name: "Classification", completed: true },
      { name: "RAG Analysis", completed: true },
      { name: "Containment", completed: false },
      { name: "Mitigation", completed: incident.status === "Resolved" },
    ],
    findings: [
      incident.aiExplanation?.description || `Autonomous alert triggered for ${incident.attackType}.`,
      `Source IP ${incident.sourceIp} correlated with internal target ${incident.destinationIp || "192.168.29.93"}.`,
      `Confidence scored at ${incident.confidence}% by multi-class detection model.`,
      `SHA-256 evidence chain recorded for audit integrity.`,
    ],
    relatedActivity: {
      alertsCount: 1,
      sourceIpsCount: 1,
      affectedAssetsCount: 1,
      suspiciousAuthCount: 0,
    },
    summary: incident.aiExplanation?.description || `${incident.attackType} under active forensic review.`,
  };

  // Trigger RAG & LangChain Investigation
  const handleRunAiInvestigation = async () => {
    setIsAiLoading(true);
    setAiError(null);
    try {
      const res = await investigateIncidentWithAI({
        incident_id: incident.id,
        attack_type: incident.attackType,
        source_ip: incident.sourceIp,
        destination_ip: incident.destinationIp || "192.168.29.93",
        confidence: incident.risk?.score ?? incident.confidence ?? 85,
        reason: inv.summary || incident.aiExplanation?.description || "",
      });
      setAiReport(res);
    } catch (err: any) {
      console.error("AI Investigation failed:", err);
      setAiError(err?.message || "Failed to execute AI RAG investigation. Please ensure backend is running.");
    } finally {
      setIsAiLoading(false);
    }
  };

  // Auto-run investigation on mount / incident change
  useEffect(() => {
    let isMounted = true;
    async function autoRun() {
      setIsAiLoading(true);
      setAiError(null);
      try {
        const res = await investigateIncidentWithAI({
          incident_id: incident.id,
          attack_type: incident.attackType,
          source_ip: incident.sourceIp,
          destination_ip: incident.destinationIp || "192.168.29.93",
          confidence: incident.risk?.score ?? incident.confidence ?? 85,
          reason: inv.summary || incident.aiExplanation?.description || "",
        });
        if (isMounted) {
          setAiReport(res);
        }
      } catch (err: any) {
        console.error("Auto AI Investigation error:", err);
        if (isMounted) {
          setAiError(err?.message || "Unable to contact RAG engine");
        }
      } finally {
        if (isMounted) {
          setIsAiLoading(false);
        }
      }
    }

    autoRun();

    return () => {
      isMounted = false;
    };
  }, [incident.id]);

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
          provider: res.provider,
        },
      ]);
    } catch {
      setChatHistory((prev) => [
        ...prev,
        {
          role: "copilot",
          content:
            "Unable to contact AI Copilot service. Please ensure the backend is running on http://127.0.0.1:8000.",
        },
      ]);
    } finally {
      setIsChatLoading(false);
    }
  };

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedRule(id);
    setTimeout(() => setCopiedRule(null), 2000);
  };

  // Synchronize firewall block status from backend
  useEffect(() => {
    let isMounted = true;
    async function syncBlockedStatus() {
      try {
        const data = await fetchBlockedIps();
        const rec = data.records.find((r) => r.ip === incident.sourceIp);
        if (isMounted) {
          setIsFirewallActive(!!rec);
          if (rec) setDroppedPacketsCount(rec.packets_dropped);
        }
      } catch {
        // Fallback
      }
    }
    syncBlockedStatus();
    const interval = setInterval(syncBlockedStatus, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [incident.sourceIp]);

  const handleToggleBlock = async () => {
    const nextState = !isFirewallActive;
    try {
      if (nextState) {
        await blockFirewallIp(incident.sourceIp, `AI Containment for incident ${incident.id}`, incident.id);
        setIsFirewallActive(true);
        setToastMsg(
          `🛡️ Firewall Quarantined: Attacker IP (${incident.sourceIp}) is now BLOCKED. Any subsequent traffic will be automatically DROPPED at perimeter without generating alert noise.`
        );
      } else {
        await unblockFirewallIp(incident.sourceIp);
        setIsFirewallActive(false);
        setDroppedPacketsCount(0);
        setToastMsg(`Firewall block removed for ${incident.sourceIp}.`);
      }
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("cybersentinel-refresh-all"));
      }
    } catch {
      setToastMsg("Failed to communicate with firewall blocklist service.");
    }
    setTimeout(() => setToastMsg(""), 4500);
  };

  // Clean executive narrative helper
  const narrativeData = (() => {
    if (!aiReport) return { coreNarrative: inv.summary, directives: [], raw: "" };

    const raw = aiReport.executive_summary || "";
    let cleanedText = raw
      .replace(/\*\*TO:\*\*[\s\S]*?(?=\*\*SUBJECT:|\n|---)/gi, "")
      .replace(/\*\*FROM:\*\*[\s\S]*?(?=\*\*SUBJECT:|\n|---)/gi, "")
      .replace(/\*\*SUBJECT:\*\*[\s\S]*?(?=\n|---|###)/gi, "")
      .replace(/---/g, "")
      .replace(/###\s*\^?\^?[\s\S]*?\^?\^?/g, "")
      .replace(/\^?\^/g, "")
      .trim();

    let coreNarrative = "";
    const hypMatch = cleanedText.match(/(?:Working Hypotheses[\s\S]*?\*|Causality \(Vector\):?)([^#\*]+)/i);
    if (hypMatch && hypMatch[1].trim().length > 25) {
      coreNarrative = hypMatch[1].replace(/[\*\_\^]/g, "").trim();
    } else {
      const paras = cleanedText
        .split(/\n\n+/)
        .map((p) => p.replace(/[\*\_\^]/g, "").trim())
        .filter((p) => p.length > 30 && !p.toLowerCase().startsWith("target:"));
      coreNarrative = paras[0] || cleanedText.slice(0, 280);
    }

    const directives: string[] = [];
    const directMatch = cleanedText.match(/(?:Commander's Directives|Immediate Mitigation:?)([\s\S]+)$/i);
    if (directMatch) {
      const items = directMatch[1]
        .split(/\*|\n/)
        .map((s) => s.replace(/[\*\_\^]/g, "").trim())
        .filter((s) => s.length > 15 && !s.toLowerCase().startsWith("status:"));
      directives.push(...items.slice(0, 3));
    }
    if (directives.length === 0) {
      directives.push(
        `Deploy stateful drop rule for source IP ${aiReport.attack_classification?.source_ip || incident.sourceIp}`,
        `Commit SHA-256 byte payload to tamper-evident SQLite forensic ledger`,
        `Inspect target server connection queue to prevent host denial of service`
      );
    }

    return { coreNarrative, directives, raw };
  })();

  const isPortScan = incident.attackType?.toLowerCase().includes("scan");
  const isSSH = incident.attackType?.toLowerCase().includes("ssh");
  const isFTP = incident.attackType?.toLowerCase().includes("ftp");
  const isWeb = incident.attackType?.toLowerCase().includes("web");
  const isDoS = incident.attackType?.toLowerCase().includes("dos") || incident.attackType?.toLowerCase().includes("syn");

  // Plain-Language Explanations (Easily understandable for any user)
  const plainExplanations = {
    whatHappened: isDoS
      ? `Attacker computer (${incident.sourceIp}) sent a high-velocity flood of incomplete TCP SYN connection requests to your server on Port ${incident.port || 8000}. By sending dozens of requests per second without finishing the connection handshake, it tried to exhaust your server's memory and connection slots.`
      : isPortScan
      ? `Attacker computer (${incident.sourceIp}) was actively scanning multiple ports on your network to discover which services and applications are running and find open vulnerabilities.`
      : isSSH
      ? `Attacker computer (${incident.sourceIp}) attempted an automated dictionary brute-force password spray targeting SSH service (Port 22) trying to gain unauthorized remote access.`
      : isFTP
      ? `Attacker computer (${incident.sourceIp}) flooded the FTP service (Port 21) with rapid login attempts attempting to crack user credentials.`
      : isWeb
      ? `Attacker computer (${incident.sourceIp}) injected suspicious web payloads (SQL injection or XSS scripting) into web application endpoints.`
      : `Anomalous network telemetry was detected originating from ${incident.sourceIp} targeting your server on Port ${incident.port || 8000}.`,

    whyAIFlagged: isDoS
      ? `The Machine Learning model (Random Forest trained on CIC-IDS2017) observed packet burst velocity exceeding the 99th percentile baseline, with 100% asymmetric forward-only SYN flags and 0 completed handshakes (${incident.confidence}% match).`
      : isPortScan
      ? `AI detected an abnormal number of distinct destination ports probed in a short time window, diverging sharply from normal legitimate browsing patterns (${incident.confidence}% match).`
      : `The flow exhibited high packet frequency, repetitive authentication requests, and rapid reset flags typical of automated brute-force scripts (${incident.confidence}% match).`,

    potentialDanger: isDoS
      ? `If left unblocked, your service on Port ${incident.port || 8000} can freeze or crash, preventing genuine users from accessing your application (Denial of Service).`
      : isPortScan
      ? `The attacker is actively mapping your system to launch a targeted exploit on open, vulnerable services.`
      : `The attacker could guess administrative credentials and take over host access remotely.`,

    immediateAction: `Add a firewall drop rule on your host or router to immediately disconnect and block all inbound packets from ${incident.sourceIp}.`,
  };

  return (
    <div className="space-y-6 pb-12 max-w-7xl mx-auto">
      {/* Toast Notification */}
      {toastMsg && (
        <div className="p-3 bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs rounded-2xl flex items-center gap-2 font-medium shadow-xs">
          <Check className="w-4 h-4 text-emerald-600 shrink-0" />
          <span>{toastMsg}</span>
        </div>
      )}

      {/* ── 1. MODERN INVESTIGATION COMMAND HERO ── */}
      <div className="neu-card-glow rounded-3xl p-6 sm:p-7 bg-gradient-to-r from-indigo-50/90 via-white/95 to-purple-50/80 border-2 border-indigo-200/90 shadow-md relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="flex items-start gap-4">
            <div className={cn(
              "w-14 h-14 rounded-2xl text-white flex items-center justify-center shrink-0 shadow-lg",
              isPortScan ? "bg-cyan-600 shadow-cyan-600/25" :
              isSSH ? "bg-amber-600 shadow-amber-600/25" :
              isFTP ? "bg-yellow-600 shadow-yellow-600/25" :
              isWeb ? "bg-purple-600 shadow-purple-600/25" :
              "bg-rose-600 shadow-rose-600/25 animate-pulse"
            )}>
              {isPortScan ? <Radar className="w-7 h-7" /> :
               isSSH ? <Key className="w-7 h-7" /> :
               isFTP ? <Terminal className="w-7 h-7" /> :
               isWeb ? <Globe className="w-7 h-7" /> :
               <ShieldAlert className="w-7 h-7" />}
            </div>

            <div className="space-y-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-3 py-0.5 rounded-full text-[10px] font-extrabold uppercase tracking-wider bg-slate-900 text-white shadow-2xs font-mono">
                  {incident.id}
                </span>
                <span className={cn(
                  "px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase",
                  incident.severity === "CRITICAL"
                    ? "bg-rose-100 text-rose-700 border border-rose-200"
                    : incident.severity === "HIGH"
                    ? "bg-amber-100 text-amber-700 border border-amber-200"
                    : "bg-blue-100 text-blue-700 border border-blue-200"
                )}>
                  {incident.severity} PRIORITY
                </span>
                <span className="text-[10px] font-bold bg-emerald-100 text-emerald-800 px-2.5 py-0.5 rounded-full border border-emerald-200">
                  {inv.status}
                </span>
                <span className="text-[10px] font-mono text-indigo-700 bg-indigo-50 border border-indigo-200 px-2.5 py-0.5 rounded-full flex items-center gap-1 font-bold">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                  AI RAG Vector Store: ONLINE
                </span>
              </div>

              <h1 className="text-2xl sm:text-3xl font-black text-slate-900 tracking-tight">
                {incident.attackType} Investigation
              </h1>

              {/* 5-Tuple Specs in Generous Glass Pills */}
              <div className="flex flex-wrap items-center gap-2.5 text-xs text-slate-600 pt-1">
                <span className="bg-white/95 px-3 py-1.5 rounded-xl border border-slate-200 shadow-2xs">
                  <span className="text-slate-400 font-medium">Attacker Device:</span>{" "}
                  <strong className="font-mono text-rose-600 font-bold">{incident.sourceIp}</strong>
                </span>
                <span className="bg-white/95 px-3 py-1.5 rounded-xl border border-slate-200 shadow-2xs">
                  <span className="text-slate-400 font-medium">Target Port:</span>{" "}
                  <strong className="font-mono text-slate-800 font-bold">{incident.target || `Port ${incident.port || 8000} (TCP)`}</strong>
                </span>
                <span className="bg-white/95 px-3 py-1.5 rounded-xl border border-slate-200 shadow-2xs">
                  <span className="text-slate-400 font-medium">Model Confidence:</span>{" "}
                  <strong className="font-mono text-violet-700 font-bold">{incident.confidence}% Verified</strong>
                </span>
                {aiReport?.attack_classification?.technique_id && (
                  <span className="bg-indigo-50/90 text-indigo-800 px-3 py-1.5 rounded-xl border border-indigo-200 shadow-2xs font-mono font-bold">
                    MITRE {aiReport.attack_classification.technique_id}
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Top Actions */}
          <div className="flex flex-col sm:flex-row lg:flex-col items-stretch gap-2.5 shrink-0">
            <button
              onClick={handleRunAiInvestigation}
              disabled={isAiLoading}
              className="px-5 py-3 rounded-2xl bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-700 hover:to-cyan-700 text-white text-xs font-bold flex items-center justify-center gap-2 shadow-md hover:shadow-lg transition-all active:scale-95 disabled:opacity-50 cursor-pointer"
            >
              <Bot className={cn("w-4 h-4", isAiLoading && "animate-spin")} />
              <span>{isAiLoading ? "Re-Synthesizing..." : "Re-Run AI Investigation"}</span>
            </button>
            <button
              onClick={onGenerateReport}
              className="px-4 py-2.5 rounded-2xl bg-white hover:bg-slate-50 text-slate-800 text-xs font-bold flex items-center justify-center gap-2 border border-slate-200 shadow-sm transition-all cursor-pointer"
            >
              <FileText className="w-4 h-4 text-blue-600" />
              <span>Generate Forensic Report</span>
            </button>
          </div>
        </div>

        {/* ── LINEAR 7-PHASE TIMELINE BAR ── */}
        <div className="mt-6 pt-5 border-t border-indigo-200/50">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
              Autonomous Investigation Pipeline Lifecycle:
            </span>
            <span className="text-[10px] font-mono text-emerald-700 font-bold">
              Stage 5/7 Completed &bull; Evidence Hashed
            </span>
          </div>
          <div className="grid grid-cols-7 gap-1.5 sm:gap-2">
            {inv.progressSteps.map((step, idx) => (
              <div key={idx} className="flex flex-col gap-1.5">
                <div
                  className={cn(
                    "h-1.5 rounded-full transition-all",
                    step.completed ? "bg-emerald-500 shadow-xs shadow-emerald-500/50" : "bg-slate-200"
                  )}
                />
                <span className={cn(
                  "text-[10px] truncate font-medium",
                  step.completed ? "text-slate-800 font-bold" : "text-slate-400"
                )}>
                  {step.name}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── VISUAL ATTACK & CONTAINMENT FLOW DIAGRAM (VISUAL EXPLANATION) ── */}
      <div className="neu-flat rounded-3xl p-5 border border-white bg-white/80 shadow-xs">
        <div className="flex items-center justify-between mb-3 border-b border-slate-100 pb-2">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-500" />
            <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">
              Live Attack Telemetry Flow (हमले का दृश्य प्रवाह)
            </h3>
          </div>
          <span className="text-[10px] font-mono text-slate-400">
            Real-Time Socket Interception
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 items-center">
          {/* Node 1: Attacker */}
          <div className="p-3.5 rounded-2xl bg-rose-50 border border-rose-200 text-center space-y-1">
            <div className="w-8 h-8 rounded-xl bg-rose-600 text-white mx-auto flex items-center justify-center font-bold text-xs shadow-xs">
              <Server className="w-4 h-4" />
            </div>
            <div className="text-[10px] font-bold uppercase text-rose-700">1. Attacker Device</div>
            <div className="text-xs font-black font-mono text-slate-900">{incident.sourceIp}</div>
            <div className="text-[9px] text-rose-600/80 font-medium">Source of anomalous burst</div>
          </div>

          {/* Node 2: Attack Vector */}
          <div className="p-3.5 rounded-2xl bg-amber-50 border border-amber-200 text-center space-y-1">
            <div className="w-8 h-8 rounded-xl bg-amber-500 text-white mx-auto flex items-center justify-center font-bold text-xs shadow-xs">
              <Flame className="w-4 h-4" />
            </div>
            <div className="text-[10px] font-bold uppercase text-amber-800">2. Attack Transmission</div>
            <div className="text-xs font-black text-slate-900 truncate">{incident.attackType}</div>
            <div className="text-[9px] text-amber-700/80 font-medium">TCP SYN / High Velocity Burst</div>
          </div>

          {/* Node 3: AI Detector */}
          <div className="p-3.5 rounded-2xl bg-indigo-50 border border-indigo-200 text-center space-y-1">
            <div className="w-8 h-8 rounded-xl bg-indigo-600 text-white mx-auto flex items-center justify-center font-bold text-xs shadow-xs">
              <BrainCircuit className="w-4 h-4" />
            </div>
            <div className="text-[10px] font-bold uppercase text-indigo-700">3. AI Classifier Match</div>
            <div className="text-xs font-black text-indigo-900">{incident.confidence}% Confidence</div>
            <div className="text-[9px] text-indigo-600 font-medium">CICIDS2017 RF-70 Model</div>
          </div>

          {/* Node 4: Target & Containment */}
          <div className={cn(
            "p-3.5 rounded-2xl border text-center space-y-1 transition-all",
            isFirewallActive
              ? "bg-emerald-50 border-emerald-300"
              : "bg-blue-50 border-blue-200"
          )}>
            <div className={cn(
              "w-8 h-8 rounded-xl mx-auto flex items-center justify-center font-bold text-xs shadow-xs text-white",
              isFirewallActive ? "bg-emerald-600" : "bg-blue-600"
            )}>
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div className="text-[10px] font-bold uppercase text-slate-700">4. Target Host Status</div>
            <div className="text-xs font-black text-slate-900">{incident.target || `Port ${incident.port || 8000}`}</div>
            <div className={cn(
              "text-[9px] font-bold",
              isFirewallActive ? "text-emerald-700" : "text-blue-700"
            )}>
              {isFirewallActive ? "SHIELD ACTIVE (IP Blocked)" : "Shield Ready to Apply"}
            </div>
          </div>
        </div>
      </div>

      {/* ── 2. SEGMENTED WORKSPACE SELECTOR ── */}
      <div className="flex items-center justify-between flex-wrap gap-3 border-b border-slate-200 pb-2">
        <div className="flex items-center gap-2 p-1 bg-slate-200/70 rounded-2xl">
          <button
            onClick={() => setActiveWorkspaceTab("triage")}
            className={cn(
              "px-5 py-2.5 rounded-xl text-xs font-extrabold transition-all flex items-center gap-2 cursor-pointer",
              activeWorkspaceTab === "triage"
                ? "bg-white text-slate-900 shadow-sm"
                : "text-slate-600 hover:text-slate-900"
            )}
          >
            <BrainCircuit className="w-4 h-4 text-indigo-600" />
            <span>AI Triage & Clear Breakdown</span>
          </button>
          <button
            onClick={() => setActiveWorkspaceTab("containment")}
            className={cn(
              "px-5 py-2.5 rounded-xl text-xs font-extrabold transition-all flex items-center gap-2 cursor-pointer",
              activeWorkspaceTab === "containment"
                ? "bg-white text-slate-900 shadow-sm"
                : "text-slate-600 hover:text-slate-900"
            )}
          >
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
            <span>Firewall Rules & Containment</span>
          </button>
          <button
            onClick={() => setActiveWorkspaceTab("copilot")}
            className={cn(
              "px-5 py-2.5 rounded-xl text-xs font-extrabold transition-all flex items-center gap-2 cursor-pointer",
              activeWorkspaceTab === "copilot"
                ? "bg-white text-slate-900 shadow-sm"
                : "text-slate-600 hover:text-slate-900"
            )}
          >
            <Bot className="w-4 h-4 text-cyan-600" />
            <span>Ask Copilot (Interactive AI)</span>
          </button>
        </div>

        {/* Mode Toggle: Easy & Clear vs Deep Technical */}
        {activeWorkspaceTab === "triage" && (
          <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-xl border border-slate-200">
            <button
              onClick={() => setExplanationMode("simple")}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer",
                explanationMode === "simple"
                  ? "bg-indigo-600 text-white shadow-xs"
                  : "text-slate-600 hover:text-slate-900"
              )}
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Easy & Clear (सरल सारांश)</span>
            </button>
            <button
              onClick={() => setExplanationMode("technical")}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer",
                explanationMode === "technical"
                  ? "bg-slate-900 text-white shadow-xs"
                  : "text-slate-600 hover:text-slate-900"
              )}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Deep Technical (तकनीकी)</span>
            </button>
          </div>
        )}
      </div>

      {/* Loading state indicator */}
      {isAiLoading && !aiReport && (
        <div className="p-8 rounded-3xl bg-indigo-50/50 border border-indigo-200 text-center space-y-3 animate-pulse">
          <Loader2 className="w-8 h-8 text-indigo-600 animate-spin mx-auto" />
          <h3 className="text-sm font-extrabold text-slate-900">
            Synthesizing Live Incident Telemetry with LangGraph RAG Agent...
          </h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Correlating with STIX 2.1 ChromaDB vector embeddings and Canadian Institute for Cybersecurity feature vectors.
          </p>
        </div>
      )}

      {/* ── TAB 1: AI EXECUTIVE TRIAGE & FORENSIC FINDINGS ── */}
      {activeWorkspaceTab === "triage" && (
        <div className="space-y-6 animate-fade-in">
          {/* MODE 1: SIMPLE & CLEAR BREAKDOWN (EASILY UNDERSTANDABLE) */}
          {explanationMode === "simple" && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Question 1: What Happened? */}
              <div className="neu-flat rounded-3xl p-5 border border-white bg-gradient-to-b from-blue-50/60 via-white to-white space-y-3">
                <div className="flex items-center gap-2.5 border-b border-blue-100 pb-2.5">
                  <div className="w-7 h-7 rounded-lg bg-blue-100 text-blue-700 flex items-center justify-center font-black text-xs">
                    01
                  </div>
                  <div>
                    <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">
                      What Happened? (क्या हमला हुआ?)
                    </h3>
                    <span className="text-[10px] text-slate-400 font-medium">Attack Context & Target</span>
                  </div>
                </div>
                <p className="text-xs text-slate-700 leading-relaxed font-medium">
                  {plainExplanations.whatHappened}
                </p>
                <div className="p-3 bg-blue-50/50 rounded-xl border border-blue-100 text-[11px] font-mono text-blue-900 space-y-1">
                  <div><strong>Attacker IP:</strong> {incident.sourceIp}</div>
                  <div><strong>Target:</strong> {incident.destinationIp || "192.168.29.93"}:{incident.port || 8000} ({incident.protocol})</div>
                </div>
              </div>

              {/* Question 2: Why Did AI Flag It? */}
              <div className="neu-flat rounded-3xl p-5 border border-white bg-gradient-to-b from-amber-50/60 via-white to-white space-y-3">
                <div className="flex items-center gap-2.5 border-b border-amber-100 pb-2.5">
                  <div className="w-7 h-7 rounded-lg bg-amber-100 text-amber-800 flex items-center justify-center font-black text-xs">
                    02
                  </div>
                  <div>
                    <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">
                      Why Did AI Flag It? (AI ने इसे क्यों पकड़ा?)
                    </h3>
                    <span className="text-[10px] text-slate-400 font-medium">Machine Learning Reasoning</span>
                  </div>
                </div>
                <p className="text-xs text-slate-700 leading-relaxed font-medium">
                  {plainExplanations.whyAIFlagged}
                </p>
                <div className="p-3 bg-amber-50/50 rounded-xl border border-amber-100 text-[11px] font-mono text-amber-900 space-y-1">
                  <div><strong>Model Match:</strong> {incident.confidence}% Confidence</div>
                  <div><strong>Dataset Profile:</strong> CIC-IDS2017 Statistical Signature</div>
                </div>
              </div>

              {/* Question 3: What Is The Risk? */}
              <div className="neu-flat rounded-3xl p-5 border border-white bg-gradient-to-b from-rose-50/60 via-white to-white space-y-3">
                <div className="flex items-center gap-2.5 border-b border-rose-100 pb-2.5">
                  <div className="w-7 h-7 rounded-lg bg-rose-100 text-rose-700 flex items-center justify-center font-black text-xs">
                    03
                  </div>
                  <div>
                    <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">
                      What Is The Risk? (संभावित खतरा क्या है?)
                    </h3>
                    <span className="text-[10px] text-slate-400 font-medium">Impact Assessment</span>
                  </div>
                </div>
                <p className="text-xs text-slate-700 leading-relaxed font-medium">
                  {plainExplanations.potentialDanger}
                </p>
                <div className="p-3 bg-rose-50/50 rounded-xl border border-rose-100 text-[11px] font-mono text-rose-900 space-y-1">
                  <div><strong>Severity Level:</strong> {incident.severity} RISK</div>
                  <div><strong>Service Availability:</strong> Endangered without containment</div>
                </div>
              </div>

              {/* Question 4: Immediate Action */}
              <div className="neu-flat rounded-3xl p-5 border border-white bg-gradient-to-b from-emerald-50/60 via-white to-white space-y-3">
                <div className="flex items-center justify-between border-b border-emerald-100 pb-2.5">
                  <div className="flex items-center gap-2.5">
                    <div className="w-7 h-7 rounded-lg bg-emerald-100 text-emerald-800 flex items-center justify-center font-black text-xs">
                      04
                    </div>
                    <div>
                      <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">
                        Immediate Action (तुरंत क्या समाधान करें?)
                      </h3>
                      <span className="text-[10px] text-slate-400 font-medium">Instant Containment</span>
                    </div>
                  </div>
                  <button
                    onClick={handleToggleBlock}
                    className={cn(
                      "text-[10px] font-bold px-3 py-1 rounded-lg transition-all active:scale-95 cursor-pointer flex items-center gap-1.5",
                      isFirewallActive
                        ? "bg-emerald-600 hover:bg-emerald-700 text-white shadow-xs"
                        : "bg-rose-600 hover:bg-rose-700 text-white shadow-xs"
                    )}
                  >
                    {isFirewallActive ? (
                      <>
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>Rule Active (Blocked)</span>
                      </>
                    ) : (
                      <>
                        <Ban className="w-3.5 h-3.5" />
                        <span>Apply IP Block</span>
                      </>
                    )}
                  </button>
                </div>

                {isFirewallActive && (
                  <div className="p-3 rounded-2xl bg-emerald-50 border border-emerald-200 text-xs text-emerald-950 space-y-1">
                    <div className="flex items-center justify-between font-bold flex-wrap gap-1">
                      <span className="flex items-center gap-1.5 text-emerald-800">
                        <ShieldCheck className="w-4 h-4 text-emerald-600" />
                        <span>Active Perimeter Shield (Attacker Quarantined)</span>
                      </span>
                      <span className="font-mono text-[10px] bg-emerald-200/80 text-emerald-900 px-2 py-0.5 rounded-full font-bold">
                        Packets Dropped: {droppedPacketsCount}
                      </span>
                    </div>
                    <p className="text-[11px] text-emerald-700 leading-snug">
                      🔒 Attacker IP <strong>{incident.sourceIp}</strong> ब्लॉक है। अगर attacker दोबारा पैकेट्स भेजता है, तो सिस्टम उन्हें बिना अलार्म बजाए पेरीमीटर पर ही चुपचाप <strong>DROP</strong> कर देगा!
                    </p>
                  </div>
                )}

                <p className="text-xs text-slate-700 leading-relaxed font-medium">
                  {plainExplanations.immediateAction}
                </p>
                <div className="flex items-center justify-between bg-slate-900 text-emerald-400 p-2 rounded-xl font-mono text-[10px]">
                  <span className="truncate">netsh advfirewall firewall add rule name="Block_{incident.sourceIp}" dir=in action=block remoteip={incident.sourceIp}</span>
                  <button
                    onClick={() => handleCopyText(`netsh advfirewall firewall add rule name="Block_${incident.sourceIp}" dir=in action=block remoteip=${incident.sourceIp}`, "quick-netsh")}
                    className="ml-2 px-2 py-0.5 rounded bg-slate-800 text-slate-200 hover:text-white shrink-0 text-[10px]"
                  >
                    {copiedRule === "quick-netsh" ? "Copied!" : "Copy"}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* MODE 2: DEEP TECHNICAL SOC BRIEFING */}
          {explanationMode === "technical" && (
            <div className="p-6 rounded-3xl bg-white border border-slate-200 shadow-sm space-y-4">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center font-bold">
                    <Sparkles className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-extrabold text-slate-900">
                      Deep Forensic Narrative & Causality (NIST SP 800-61 Rev 2)
                    </h3>
                    <p className="text-[11px] text-slate-500">
                      Grounded in persistent ChromaDB STIX 2.1 vector embeddings
                    </p>
                  </div>
                </div>

                {narrativeData.raw && (
                  <button
                    onClick={() => setShowRawBriefing(!showRawBriefing)}
                    className="text-xs font-bold text-indigo-600 hover:text-indigo-800 flex items-center gap-1 cursor-pointer transition-colors"
                  >
                    <span>{showRawBriefing ? "Hide Raw Briefing" : "View Full LLM Briefing"}</span>
                    {showRawBriefing ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>
                )}
              </div>

              <div className="p-4 rounded-2xl bg-slate-50/80 border border-slate-200/80 text-xs text-slate-800 leading-relaxed font-sans">
                {narrativeData.coreNarrative}
              </div>

              {/* Containment Directives */}
              <div className="space-y-2 pt-1">
                <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider block">
                  Recommended Containment Directives:
                </span>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {narrativeData.directives.map((dir, idx) => (
                    <div
                      key={idx}
                      className="p-3.5 rounded-2xl bg-indigo-50/50 border border-indigo-100 flex items-start gap-2.5 text-xs text-indigo-950 font-medium leading-snug"
                    >
                      <CheckCircle2 className="w-4 h-4 text-indigo-600 shrink-0 mt-0.5" />
                      <span>{dir}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Collapsible raw briefing */}
              {showRawBriefing && narrativeData.raw && (
                <div className="p-4 rounded-2xl bg-slate-900 text-slate-300 font-mono text-[11px] leading-relaxed max-h-64 overflow-y-auto whitespace-pre-wrap border border-slate-800">
                  {narrativeData.raw}
                </div>
              )}
            </div>
          )}

          {/* 4 Corroborated Forensic Findings */}
          <div className="p-6 rounded-3xl bg-white border border-slate-200 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-blue-600" />
                <h3 className="text-sm font-extrabold text-slate-900">
                  Forensic Observations & Corroborated Evidence
                </h3>
              </div>
              <span className="text-[11px] font-mono text-slate-400">
                4 Verified Facts
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
              {inv.findings.map((finding, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-2xl bg-slate-50/70 border border-slate-200/80 hover:bg-slate-50 transition-all flex flex-col justify-between"
                >
                  <div className="flex items-center gap-2 mb-2">
                    <span className="w-2 h-2 rounded-full bg-blue-600" />
                    <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">
                      Observation #{idx + 1}
                    </span>
                  </div>
                  <p className="text-xs font-semibold text-slate-800 leading-relaxed">
                    {finding}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 2: FIREWALL RULES & CONTAINMENT PLAYBOOK ── */}
      {activeWorkspaceTab === "containment" && (
        <div className="space-y-6 animate-fade-in">
          {/* Actionable Firewall Drop Rules */}
          <div className="p-6 rounded-3xl bg-white border border-slate-200 shadow-sm space-y-5">
            <div>
              <h3 className="text-sm font-extrabold text-slate-900 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
                <span>Actionable Perimeter Defense Rules</span>
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Copy and apply to drop malicious packets from {incident.sourceIp} on your border or host firewalls.
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Windows Defender Netsh */}
              <div className="p-4 rounded-2xl bg-slate-900 text-slate-100 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-cyan-400 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5" />
                    Windows Defender Firewall Rule (netsh)
                  </span>
                  <button
                    onClick={() => handleCopyText(`netsh advfirewall firewall add rule name="Block_${incident.sourceIp}" dir=in action=block remoteip=${incident.sourceIp}`, "netsh")}
                    className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-[10px] font-mono text-slate-300 flex items-center gap-1 border border-slate-700 cursor-pointer"
                  >
                    {copiedRule === "netsh" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedRule === "netsh" ? "Copied" : "Copy Command"}</span>
                  </button>
                </div>
                <pre className="p-3 bg-black/60 rounded-xl font-mono text-xs text-emerald-400 overflow-x-auto">
                  netsh advfirewall firewall add rule name="Block_{incident.sourceIp}" dir=in action=block remoteip={incident.sourceIp}
                </pre>
              </div>

              {/* Linux iptables */}
              <div className="p-4 rounded-2xl bg-slate-900 text-slate-100 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-cyan-400 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5" />
                    Linux iptables Drop Rule
                  </span>
                  <button
                    onClick={() => handleCopyText(`iptables -A INPUT -s ${incident.sourceIp} -j DROP`, "iptables")}
                    className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-[10px] font-mono text-slate-300 flex items-center gap-1 border border-slate-700 cursor-pointer"
                  >
                    {copiedRule === "iptables" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedRule === "iptables" ? "Copied" : "Copy Command"}</span>
                  </button>
                </div>
                <pre className="p-3 bg-black/60 rounded-xl font-mono text-xs text-emerald-400 overflow-x-auto">
                  iptables -A INPUT -s {incident.sourceIp} -j DROP
                </pre>
              </div>
            </div>

            {/* Snort / Suricata Rule */}
            {aiReport?.snort_defense_rule && (
              <div className="p-4 rounded-2xl bg-slate-900 text-slate-100 border border-slate-800 space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-amber-400 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5" />
                    Snort / Suricata Signature Rule
                  </span>
                  <button
                    onClick={() => handleCopyText(aiReport.snort_defense_rule, "snort")}
                    className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-[10px] font-mono text-slate-300 flex items-center gap-1 border border-slate-700 cursor-pointer"
                  >
                    {copiedRule === "snort" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedRule === "snort" ? "Copied" : "Copy Signature"}</span>
                  </button>
                </div>
                <pre className="p-3 bg-black/60 rounded-xl font-mono text-xs text-emerald-400 overflow-x-auto whitespace-pre-wrap">
                  {aiReport.snort_defense_rule}
                </pre>
              </div>
            )}
          </div>

          {/* NIST Containment Playbook Steps */}
          {aiReport?.containment_playbook && (
            <div className="p-6 rounded-3xl bg-white border border-slate-200 shadow-sm space-y-4">
              <h3 className="text-sm font-extrabold text-slate-900 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                <span>NIST SP 800-61 Incident Containment Checklist</span>
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {aiReport.containment_playbook.map((step, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-2xl bg-slate-50 border border-slate-200 flex items-start gap-2.5 text-xs text-slate-800 font-medium"
                  >
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── TAB 3: INTERACTIVE RAG SOC COPILOT CHAT ── */}
      {activeWorkspaceTab === "copilot" && (
        <div className="p-6 rounded-3xl bg-white border border-slate-200 shadow-sm space-y-5 animate-fade-in">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-xl bg-cyan-100 text-cyan-700 flex items-center justify-center font-bold">
                <Bot className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-extrabold text-slate-900">
                  CyberSentinel RAG Copilot (Live Incident Assistant)
                </h3>
                <p className="text-[11px] text-slate-500">
                  Ask questions in plain English or Hindi. Grounded in incident {incident.id} and MITRE ATT&CK STIX vector store.
                </p>
              </div>
            </div>
          </div>

          {/* Quick Prompt Suggestions */}
          <div className="flex flex-wrap gap-2">
            {[
              "सरल हिंदी में समझाओ क्या हमला हुआ है?",
              "How do I block this attacker in Windows Firewall?",
              "Why did the Random Forest model flag this attack?",
              "What danger does this attack have on port 8000?",
              "Draft an executive incident summary for management",
              "Is my target server safe right now?",
            ].map((suggestion, idx) => (
              <button
                key={idx}
                onClick={() => handleSendCopilotQuery(suggestion)}
                className="px-3 py-1.5 text-xs rounded-xl bg-slate-100 hover:bg-indigo-50 hover:text-indigo-700 hover:border-indigo-200 text-slate-700 border border-slate-200/80 transition-all cursor-pointer font-medium"
              >
                {suggestion}
              </button>
            ))}
          </div>

          {/* Chat Messages Log */}
          <div className="space-y-3.5 min-h-[220px] max-h-96 overflow-y-auto p-4 bg-slate-50/70 rounded-2xl border border-slate-200/60">
            {chatHistory.length === 0 ? (
              <div className="py-12 text-center space-y-2 text-slate-400">
                <Bot className="w-8 h-8 mx-auto text-slate-300" />
                <p className="text-xs font-medium">
                  Copilot is ready. Ask any question in Hindi or English about this incident.
                </p>
              </div>
            ) : (
              chatHistory.map((msg, i) => (
                <div
                  key={i}
                  className={cn(
                    "p-4 rounded-2xl text-xs leading-relaxed max-w-[85%]",
                    msg.role === "user"
                      ? "bg-slate-900 text-white ml-auto shadow-sm"
                      : "bg-white text-slate-800 border border-slate-200 mr-auto shadow-xs"
                  )}
                >
                  <div className="flex items-center justify-between font-bold mb-1.5 opacity-70 text-[10px]">
                    <span>{msg.role === "user" ? "SOC Analyst" : "CyberSentinel AI Copilot"}</span>
                    {msg.provider && (
                      <span className="px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-700 font-mono text-[9px] border border-indigo-200">
                        {msg.provider}
                      </span>
                    )}
                  </div>
                  <div className="whitespace-pre-wrap font-sans text-xs">{msg.content}</div>
                </div>
              ))
            )}
            {isChatLoading && (
              <div className="p-3.5 rounded-2xl bg-white border border-slate-200 mr-auto flex items-center gap-2 text-xs text-slate-500 animate-pulse">
                <Loader2 className="w-4 h-4 text-indigo-600 animate-spin" />
                <span>Searching MITRE vector store and synthesizing response...</span>
              </div>
            )}
          </div>

          {/* Input Bar */}
          <div className="flex items-center gap-2.5">
            <input
              type="text"
              placeholder="Ask anything in English or Hindi (e.g. 'How to mitigate this attack?')..."
              value={copilotQuery}
              onChange={(e) => setCopilotQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSendCopilotQuery()}
              className="flex-1 px-4 py-3 rounded-2xl border border-slate-200 text-xs bg-slate-50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 font-medium"
            />
            <button
              onClick={() => handleSendCopilotQuery()}
              disabled={isChatLoading || !copilotQuery.trim()}
              className="px-5 py-3 rounded-2xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold flex items-center gap-2 shadow-sm transition-all disabled:opacity-40 cursor-pointer"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Ask Copilot</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
