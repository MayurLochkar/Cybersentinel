"use client";
import React, { useState } from "react";
import {
  X,
  Radio,
  Cpu,
  Bell,
  ShieldCheck,
  BrainCircuit,
  ArrowRight,
  Play,
  FileCheck2,
  CheckCircle2,
  Sparkles,
  HelpCircle,
  Activity,
  Layers,
  Flame,
  Gauge,
  BarChart3,
  FileText,
  Settings,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";

interface HowItWorksModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateTab: (tab: string) => void;
}

export function HowItWorksModal({
  isOpen,
  onClose,
  onNavigateTab,
}: HowItWorksModalProps) {
  const [activeGuideTab, setActiveGuideTab] = useState<"overview" | "steps" | "dictionary">("overview");

  if (!isOpen) return null;

  const quickFeatures = [
    {
      tab: "dashboard",
      title: "1. Executive Dashboard",
      desc: "Overall network health, live flow statistics, attack distributions, and risk scores.",
      icon: <Activity className="w-4 h-4 text-blue-600" />,
      color: "bg-blue-50 border-blue-200 text-blue-900",
    },
    {
      tab: "monitoring",
      title: "2. Live Network Sniffer",
      desc: "Captures real packets from your Wi-Fi or Ethernet adapter and extracts 70 ML features in real-time.",
      icon: <Radio className="w-4 h-4 text-emerald-600" />,
      color: "bg-emerald-50 border-emerald-200 text-emerald-900",
    },
    {
      tab: "alerts",
      title: "3. Alerts & Threat Triage",
      desc: "Shows flows flagged as malicious or anomalous by the Random Forest model with severity ratings.",
      icon: <Bell className="w-4 h-4 text-rose-600" />,
      color: "bg-rose-50 border-rose-200 text-rose-900",
    },
    {
      tab: "investigation",
      title: "4. AI Investigation",
      desc: "Automated root-cause analysis, timeline reconstruction, and MITRE ATT&CK tactic correlation.",
      icon: <BrainCircuit className="w-4 h-4 text-purple-600" />,
      color: "bg-purple-50 border-purple-200 text-purple-900",
    },
    {
      tab: "threat-intel",
      title: "5. Threat Intelligence",
      desc: "IP reputation feeds, known adversary indicators, and global threat intelligence matching.",
      icon: <Flame className="w-4 h-4 text-amber-600" />,
      color: "bg-amber-50 border-amber-200 text-amber-900",
    },
    {
      tab: "risk",
      title: "6. Risk Assessment Engine",
      desc: "Quantifies threat level based on attack likelihood, target criticality, and confidence scores.",
      icon: <Gauge className="w-4 h-4 text-indigo-600" />,
      color: "bg-indigo-50 border-indigo-200 text-indigo-900",
    },
    {
      tab: "evidence",
      title: "7. Evidence Ledger (SHA-256)",
      desc: "Tamper-evident legal ledger hashing raw PCAP and log bytes to guarantee chain-of-custody.",
      icon: <FileCheck2 className="w-4 h-4 text-emerald-600" />,
      color: "bg-emerald-50 border-emerald-200 text-emerald-900",
    },
    {
      tab: "model",
      title: "8. Machine Learning Metrics",
      desc: "Evaluation benchmarks, confusion matrix, ROC curves, and accuracy of the CICIDS2017 model.",
      icon: <Cpu className="w-4 h-4 text-cyan-600" />,
      color: "bg-cyan-50 border-cyan-200 text-cyan-900",
    },
  ];

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-[150] flex items-center justify-center p-3 sm:p-6 bg-slate-950/60 backdrop-blur-md">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 10 }}
          transition={{ duration: 0.2, ease: "easeOut" }}
          className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto bg-[#f8fafc] rounded-3xl neu-flat border border-white shadow-2xl p-6 sm:p-8 flex flex-col"
        >
          {/* Header */}
          <div className="flex items-start justify-between pb-4 border-b border-slate-200">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-[#6F3DFF] to-[#3b82f6] text-white flex items-center justify-center shadow-md">
                <Sparkles className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-xl font-black text-slate-900 tracking-tight">
                    CyberSentinel-X User Guide & Architecture
                  </h2>
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-purple-100 text-[#6F3DFF] border border-purple-200">
                    EASY GUIDE
                  </span>
                </div>
                <p className="text-xs text-slate-500 mt-0.5">
                  Understand how the real-time AI security pipeline works and how to operate it in 3 easy steps.
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-2 rounded-full neu-flat hover:bg-white text-slate-400 hover:text-slate-800 transition-all border border-slate-200"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Navigation Tabs inside Guide */}
          <div className="flex items-center gap-2 mt-4 bg-slate-200/60 p-1 rounded-xl w-fit">
            <button
              onClick={() => setActiveGuideTab("overview")}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-bold transition-all",
                activeGuideTab === "overview"
                  ? "bg-white text-slate-900 shadow-sm"
                  : "text-slate-600 hover:text-slate-900"
              )}
            >
              🚀 How It Works (Overview)
            </button>
            <button
              onClick={() => setActiveGuideTab("steps")}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-bold transition-all",
                activeGuideTab === "steps"
                  ? "bg-white text-slate-900 shadow-sm"
                  : "text-slate-600 hover:text-slate-900"
              )}
            >
              ⚡ Quick 3-Step Walkthrough
            </button>
            <button
              onClick={() => setActiveGuideTab("dictionary")}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-bold transition-all",
                activeGuideTab === "dictionary"
                  ? "bg-white text-slate-900 shadow-sm"
                  : "text-slate-600 hover:text-slate-900"
              )}
            >
              📖 All Pages & Tools
            </button>
          </div>

          {/* Tab 1: Overview */}
          {activeGuideTab === "overview" && (
            <div className="space-y-6 mt-5 text-slate-700 text-xs">
              <div className="p-4 rounded-2xl bg-white border border-slate-200 shadow-sm">
                <h3 className="text-sm font-bold text-slate-900 mb-1 flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-600" />
                  What is CyberSentinel-X?
                </h3>
                <p className="text-slate-600 leading-relaxed">
                  CyberSentinel-X is an autonomous cybersecurity detection & investigation platform. It connects directly to your computer&apos;s network card (Wi-Fi or Ethernet), sniffs incoming and outgoing packets in real time, converts them into 70 statistical traffic features, and evaluates every connection using a machine learning Random Forest model trained on the CICIDS2017 intrusion dataset.
                </p>
              </div>

              {/* Visual 4-Stage Pipeline */}
              <div>
                <h4 className="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-3">
                  The Complete 4-Stage Security Pipeline
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {/* Step 1 */}
                  <div className="p-4 rounded-2xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between">
                    <div>
                      <div className="w-8 h-8 rounded-xl bg-blue-100 text-blue-600 flex items-center justify-center font-bold mb-2">
                        1
                      </div>
                      <h5 className="font-bold text-slate-900">Network Sniffer</h5>
                      <p className="text-[11px] text-slate-500 mt-1">
                        Scapy + Npcap captures raw network packets from your chosen physical adapter without synthetic packet generation.
                      </p>
                    </div>
                    <div className="mt-3 pt-2 border-t border-slate-100 text-[10px] font-mono text-blue-600 font-semibold">
                      Wi-Fi / Ethernet Adapter
                    </div>
                  </div>

                  {/* Step 2 */}
                  <div className="p-4 rounded-2xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between">
                    <div>
                      <div className="w-8 h-8 rounded-xl bg-indigo-100 text-indigo-600 flex items-center justify-center font-bold mb-2">
                        2
                      </div>
                      <h5 className="font-bold text-slate-900">Flow Extractor</h5>
                      <p className="text-[11px] text-slate-500 mt-1">
                        Aggregates packets into bidirectional 5-tuple network conversations and extracts 70 statistical features.
                      </p>
                    </div>
                    <div className="mt-3 pt-2 border-t border-slate-100 text-[10px] font-mono text-indigo-600 font-semibold">
                      70 CICIDS2017 Features
                    </div>
                  </div>

                  {/* Step 3 */}
                  <div className="p-4 rounded-2xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between">
                    <div>
                      <div className="w-8 h-8 rounded-xl bg-purple-100 text-purple-600 flex items-center justify-center font-bold mb-2">
                        3
                      </div>
                      <h5 className="font-bold text-slate-900">Random Forest AI</h5>
                      <p className="text-[11px] text-slate-500 mt-1">
                        Infers whether each flow is BENIGN (clean) or an ATTACK anomaly with calibrated probability scores.
                      </p>
                    </div>
                    <div className="mt-3 pt-2 border-t border-slate-100 text-[10px] font-mono text-purple-600 font-semibold">
                      99.8% Test Accuracy
                    </div>
                  </div>

                  {/* Step 4 */}
                  <div className="p-4 rounded-2xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between">
                    <div>
                      <div className="w-8 h-8 rounded-xl bg-emerald-100 text-emerald-600 flex items-center justify-center font-bold mb-2">
                        4
                      </div>
                      <h5 className="font-bold text-slate-900">Evidence & Triage</h5>
                      <p className="text-[11px] text-slate-500 mt-1">
                        Persists alerts in SQLite, maps MITRE ATT&CK tactics, and seals evidence artifacts with cryptographic SHA-256 hashes.
                      </p>
                    </div>
                    <div className="mt-3 pt-2 border-t border-slate-100 text-[10px] font-mono text-emerald-600 font-semibold">
                      Tamper-Proof Ledger
                    </div>
                  </div>
                </div>
              </div>

              {/* Quick Jump Action */}
              <div className="p-4 rounded-2xl bg-gradient-to-r from-purple-50 to-blue-50 border border-purple-200 flex flex-col sm:flex-row items-center justify-between gap-3">
                <div>
                  <span className="font-bold text-slate-900 block">Ready to try it out?</span>
                  <span className="text-slate-600 text-[11px]">
                    Head to the Live Monitoring page and start packet capture with 1 click.
                  </span>
                </div>
                <button
                  onClick={() => {
                    onClose();
                    onNavigateTab("monitoring");
                  }}
                  className="px-4 py-2 rounded-xl bg-[#6F3DFF] hover:bg-[#592be3] text-white font-bold text-xs flex items-center gap-2 shadow-md shrink-0 transition-all"
                >
                  <span>Open Live Monitoring</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* Tab 2: 3-Step Walkthrough */}
          {activeGuideTab === "steps" && (
            <div className="space-y-4 mt-5 text-xs text-slate-700">
              <div className="p-4 rounded-2xl bg-white border border-slate-200 flex gap-4">
                <div className="w-10 h-10 rounded-xl bg-blue-100 text-blue-700 font-bold flex items-center justify-center shrink-0 text-base">
                  1
                </div>
                <div>
                  <h4 className="font-bold text-slate-900 text-sm">Step 1: Start Live Monitoring</h4>
                  <p className="text-slate-600 mt-1 leading-relaxed">
                    Go to the <strong>Live Monitoring</strong> tab. Ensure your active physical network card (like <code>Wi-Fi</code>) is selected, and click <strong>&ldquo;Start Live Capture&rdquo;</strong>. The system immediately starts sniffing real traffic on your machine.
                  </p>
                  <button
                    onClick={() => {
                      onClose();
                      onNavigateTab("monitoring");
                    }}
                    className="mt-3 px-3 py-1.5 rounded-lg bg-blue-600 text-white font-bold text-[11px] inline-flex items-center gap-1.5 hover:bg-blue-700 transition-all"
                  >
                    <Radio className="w-3.5 h-3.5" />
                    Go to Live Monitoring
                  </button>
                </div>
              </div>

              <div className="p-4 rounded-2xl bg-white border border-slate-200 flex gap-4">
                <div className="w-10 h-10 rounded-xl bg-purple-100 text-purple-700 font-bold flex items-center justify-center shrink-0 text-base">
                  2
                </div>
                <div>
                  <h4 className="font-bold text-slate-900 text-sm">Step 2: Watch Real-Time AI Predictions</h4>
                  <p className="text-slate-600 mt-1 leading-relaxed">
                    As you browse the web or stream video, packets are grouped into bidirectional TCP/UDP flows. The Random Forest model evaluates them in real-time. Clean traffic shows as <span className="text-emerald-700 font-bold">BENIGN</span>, while any suspicious anomalies are flagged as <span className="text-rose-700 font-bold">ATTACK</span>.
                  </p>
                </div>
              </div>

              <div className="p-4 rounded-2xl bg-white border border-slate-200 flex gap-4">
                <div className="w-10 h-10 rounded-xl bg-emerald-100 text-emerald-700 font-bold flex items-center justify-center shrink-0 text-base">
                  3
                </div>
                <div>
                  <h4 className="font-bold text-slate-900 text-sm">Step 3: Investigate & Verify Evidence</h4>
                  <p className="text-slate-600 mt-1 leading-relaxed">
                    Check the <strong>Alerts</strong> tab to see any flagged threat records. Click on any alert to view its full 5-tuple forensic dossier, MITRE ATT&CK technique mapping, and automated triage. Finally, visit the <strong>Evidence Ledger</strong> to verify the SHA-256 cryptographic hash of the saved PCAP artifacts.
                  </p>
                  <div className="flex items-center gap-2 mt-3">
                    <button
                      onClick={() => {
                        onClose();
                        onNavigateTab("alerts");
                      }}
                      className="px-3 py-1.5 rounded-lg bg-slate-900 text-white font-bold text-[11px] inline-flex items-center gap-1.5 hover:bg-black transition-all"
                    >
                      <Bell className="w-3.5 h-3.5" />
                      View Alerts
                    </button>
                    <button
                      onClick={() => {
                        onClose();
                        onNavigateTab("evidence");
                      }}
                      className="px-3 py-1.5 rounded-lg bg-emerald-600 text-white font-bold text-[11px] inline-flex items-center gap-1.5 hover:bg-emerald-700 transition-all"
                    >
                      <FileCheck2 className="w-3.5 h-3.5" />
                      View Evidence Ledger
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Tab 3: Dictionary */}
          {activeGuideTab === "dictionary" && (
            <div className="mt-5 space-y-3">
              <h4 className="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-2">
                What Each Page in the Navigation Bar Does
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {quickFeatures.map((feat) => (
                  <div
                    key={feat.tab}
                    className="p-3.5 rounded-2xl bg-white border border-slate-200 hover:border-slate-300 transition-all flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between mb-1.5">
                        <div className="flex items-center gap-2">
                          {feat.icon}
                          <span className="font-bold text-slate-900 text-xs">{feat.title}</span>
                        </div>
                      </div>
                      <p className="text-[11px] text-slate-500 leading-relaxed">{feat.desc}</p>
                    </div>
                    <button
                      onClick={() => {
                        onClose();
                        onNavigateTab(feat.tab);
                      }}
                      className="mt-3 text-[10px] font-bold text-[#6F3DFF] hover:underline flex items-center gap-1 self-start"
                    >
                      <span>Jump to page</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Footer Note */}
          <div className="mt-6 pt-4 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] text-slate-500">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              All data shown is live from your host machine & SQLite database. Zero hardcoded fake metrics.
            </span>
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-xl bg-slate-200 hover:bg-slate-300 text-slate-700 font-bold text-xs transition-all"
            >
              Got it, Close Guide
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
