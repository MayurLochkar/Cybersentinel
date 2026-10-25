"use client";
import React, { useState, useEffect, useRef } from "react";
import {
  Radio,
  Play,
  Square,
  UploadCloud,
  FileCheck2,
  AlertTriangle,
  ShieldCheck,
  CheckCircle2,
  RefreshCw,
  Activity,
  Sparkles,
  ChevronRight,
  RotateCcw,
  History,
  Trash2,
  Clock,
  Database,
  Layers,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  fetchMonitoringStatus,
  fetchMonitoringMetrics,
  fetchMonitoringInterfaces,
  startMonitoringSession,
  stopMonitoringSession,
  uploadPcapFile,
  ingestSamplePcap,
  ingestLocalPcapFile,
  fetchPcapProgress,
  stopPcapIngestion,
  resetMonitoringTelemetry,
  fetchMonitoringHistory,
  clearMonitoringHistory,
  MonitoringStatus,
  MonitoringMetrics,
  NetworkInterfaceInfo,
  RecentFlow,
  PcapUploadResponse,
  PcapProgressResponse,
  SessionHistoryItem,
} from "@/lib/api";

const DEFAULT_HOST_INTERFACES: NetworkInterfaceInfo[] = [
  {
    id: "wifi-host",
    name: "Wi-Fi",
    description: "Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter",
    ip: "192.168.29.93",
    mac: "c0:35:32:58:3b:47",
    is_loopback: false,
  },
  {
    id: "ethernet-host",
    name: "Ethernet 2",
    description: "Host Ethernet Adapter",
    ip: "192.168.56.1",
    mac: "0a:00:27:00:00:13",
    is_loopback: false,
  },
  {
    id: "loopback-host",
    name: "Software Loopback Interface",
    description: "Local Software Loopback",
    ip: "127.0.0.1",
    mac: "00:00:00:00:00:00",
    is_loopback: true,
  },
];

interface MonitoringViewProps {
  onNavigateTab?: (tab: string) => void;
}

export function MonitoringView({ onNavigateTab }: MonitoringViewProps) {
  const [status, setStatus] = useState<MonitoringStatus | null>(null);
  const [metrics, setMetrics] = useState<MonitoringMetrics | null>(null);
  const [interfaces, setInterfaces] = useState<NetworkInterfaceInfo[]>(DEFAULT_HOST_INTERFACES);
  const [pcapLiveCapable, setPcapLiveCapable] = useState<boolean>(false);

  const [selectedInterface, setSelectedInterface] = useState<string>("Wi-Fi");
  const [bpfFilter, setBpfFilter] = useState<string>("");
  const [activeControlTab, setActiveControlTab] = useState<"pcap" | "live">("live");
  const [liveCaptureMode, setLiveCaptureMode] = useState<"real" | "demo">("real");

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [uploadLoading, setUploadLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [pcapResult, setPcapResult] = useState<PcapUploadResponse | null>(null);
  const [localPcapPath, setLocalPcapPath] = useState<string>("");
  const [localMaxPackets, setLocalMaxPackets] = useState<number | null>(50000);
  const [pcapProgress, setPcapProgress] = useState<PcapProgressResponse | null>(null);
  const [pcapSubTab, setPcapSubTab] = useState<"upload" | "local_disk">("upload");

  const [selectedFlowForModal, setSelectedFlowForModal] = useState<RecentFlow | null>(null);
  const [flowFilter, setFlowFilter] = useState<"all" | "attack" | "benign">("all");

  // History & Reset states
  const [historyList, setHistoryList] = useState<SessionHistoryItem[]>([]);
  const [historyFilter, setHistoryFilter] = useState<"all" | "live" | "pcap" | "reset">("all");
  const [historyLoading, setHistoryLoading] = useState<boolean>(false);
  const [resetConfirmOpen, setResetConfirmOpen] = useState<boolean>(false);
  const [isResetting, setIsResetting] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const loadHistory = async () => {
    try {
      setHistoryLoading(true);
      const hist = await fetchMonitoringHistory();
      setHistoryList(hist);
    } catch {
      // non-blocking
    } finally {
      setHistoryLoading(false);
    }
  };

  // Poll backend monitoring status, metrics, and session history
  const loadData = async (broadcastGlobal = false) => {
    try {
      const [statusRes, metricsRes, ifacesRes, histRes] = await Promise.all([
        fetchMonitoringStatus(),
        fetchMonitoringMetrics(),
        fetchMonitoringInterfaces(),
        fetchMonitoringHistory().catch(() => []),
      ]);

      setStatus(statusRes);
      setMetrics(metricsRes);
      setHistoryList(histRes);

      if (ifacesRes && ifacesRes.interfaces && ifacesRes.interfaces.length > 0) {
        setInterfaces(ifacesRes.interfaces);
        setPcapLiveCapable(ifacesRes.pcap_available);

        if (!selectedInterface || !ifacesRes.interfaces.some((i) => i.name === selectedInterface)) {
          const active = ifacesRes.interfaces.find(
            (i) => i.name === "Wi-Fi" || (i.ip && !i.ip.startsWith("169.254") && i.ip !== "Not Assigned")
          ) || ifacesRes.interfaces[0];
          if (active) setSelectedInterface(active.name);
        }
      }
      setErrorMessage(null);

      if (broadcastGlobal && typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("cybersentinel-refresh-all"));
      }
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to communicate with monitoring backend");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    let isMounted = true;
    const fetchInitial = async () => {
      try {
        const [statusRes, metricsRes, ifacesRes, histRes] = await Promise.all([
          fetchMonitoringStatus(),
          fetchMonitoringMetrics(),
          fetchMonitoringInterfaces(),
          fetchMonitoringHistory().catch(() => []),
        ]);
        if (!isMounted) return;
        setStatus(statusRes);
        setMetrics(metricsRes);
        setHistoryList(histRes);
        if (ifacesRes && ifacesRes.interfaces && ifacesRes.interfaces.length > 0) {
          setInterfaces(ifacesRes.interfaces);
          setPcapLiveCapable(ifacesRes.pcap_available);
          if (!selectedInterface || !ifacesRes.interfaces.some((i) => i.name === selectedInterface)) {
            const active = ifacesRes.interfaces.find(
              (i) => i.name === "Wi-Fi" || (i.ip && !i.ip.startsWith("169.254") && i.ip !== "Not Assigned")
            ) || ifacesRes.interfaces[0];
            if (active) setSelectedInterface(active.name);
          }
        }
        setErrorMessage(null);
      } catch (err: unknown) {
        if (!isMounted) return;
        setErrorMessage(err instanceof Error ? err.message : "Failed to communicate with monitoring backend");
      } finally {
        if (isMounted) setIsLoading(false);
      }
    };

    fetchInitial();
    const interval = setInterval(fetchInitial, 3500);

    const handleGlobalRefresh = () => {
      loadData(false);
    };
    if (typeof window !== "undefined") {
      window.addEventListener("cybersentinel-refresh-all", handleGlobalRefresh);
    }

    return () => {
      isMounted = false;
      clearInterval(interval);
      if (typeof window !== "undefined") {
        window.removeEventListener("cybersentinel-refresh-all", handleGlobalRefresh);
      }
    };
  }, [selectedInterface]);

  const handleResetCounters = async () => {
    setIsResetting(true);
    setErrorMessage(null);
    try {
      const res = await resetMonitoringTelemetry();
      // Zero local counters immediately
      setMetrics({
        status: res.status,
        mode: res.mode,
        source: res.source,
        errors_count: 0,
        packets_captured: 0,
        flows_processed: 0,
        benign_count: 0,
        attack_count: 0,
        alerts_created: 0,
        capture_mode: res.capture_mode,
        recent_flows: [],
      });
      setStatus((prev) =>
        prev
          ? {
              ...prev,
              packets_captured: 0,
              flows_processed: 0,
              benign_count: 0,
              attack_count: 0,
              alerts_created: 0,
            }
          : null
      );
      setSuccessMessage(res.message || "All telemetry metrics & active flow counts reset to 0.");
      await loadHistory();

      // Broadcast global refresh to all other components
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("cybersentinel-refresh-all"));
      }
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to reset telemetry counters");
    } finally {
      setIsResetting(false);
      setResetConfirmOpen(false);
    }
  };

  const handleClearHistory = async () => {
    try {
      await clearMonitoringHistory();
      setHistoryList([]);
      setSuccessMessage("Capture session ledger cleared successfully.");
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to clear session history");
    }
  };

  const handleStartLive = async () => {
    setActionLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);
    try {
      const res = await startMonitoringSession(selectedInterface, bpfFilter, liveCaptureMode);
      setSuccessMessage(
        `Monitoring started in ${res.capture_mode?.toUpperCase() || liveCaptureMode.toUpperCase()} mode on ${res.source}`
      );
      await loadData();
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to start live capture");
    } finally {
      setActionLoading(false);
    }
  };

  const handleStopLive = async () => {
    setActionLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);
    try {
      const res = await stopMonitoringSession();
      setSuccessMessage(res.message);
      await loadData();
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to stop monitoring");
    } finally {
      setActionLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploadLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);
    setPcapResult(null);

    try {
      const result = await uploadPcapFile(file);
      setPcapResult(result);
      setSuccessMessage(
        `PCAP analyzed: ${result.flows_extracted} flows processed (${result.attack_flows} attacks, ${result.benign_flows} benign, ${result.alerts_created} alerts generated).`
      );
      await loadData();
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to ingest PCAP capture");
    } finally {
      setUploadLoading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const handleLoadSamplePcap = async () => {
    setUploadLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);
    setPcapResult(null);

    try {
      const result = await ingestSamplePcap();
      setPcapResult(result);
      setSuccessMessage(
        `Authorized test capture analyzed: ${result.flows_extracted} flows ingested in ${result.elapsed_seconds}s!`
      );
      await loadData();
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to analyze sample PCAP");
    } finally {
      setUploadLoading(false);
    }
  };

  // Poll real-time progress while PCAP ingestion is running
  useEffect(() => {
    let timer: NodeJS.Timeout | null = null;
    if (uploadLoading) {
      const pollProgress = async () => {
        try {
          const prog = await fetchPcapProgress();
          setPcapProgress(prog);
        } catch {
          // ignore transient poll error
        }
      };
      pollProgress();
      timer = setInterval(pollProgress, 500);
    } else {
      if (timer) clearInterval(timer);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [uploadLoading]);

  const handleLocalFileIngest = async () => {
    const rawPath = localPcapPath.trim();
    if (!rawPath) {
      setErrorMessage("Please enter a valid local PCAP file path (e.g. C:\\Datasets\\capture.pcap).");
      return;
    }
    // Automatically strip quotes if path was pasted from 'Copy as Path'
    const cleanPath = rawPath.replace(/^["']|["']$/g, "").trim();

    setUploadLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);
    setPcapResult(null);

    try {
      const result = await ingestLocalPcapFile(cleanPath, localMaxPackets);
      setPcapResult(result);
      setSuccessMessage(
        `PCAP analyzed: ${result.flows_extracted} flows processed (${result.attack_flows} attacks, ${result.benign_flows} benign, ${result.alerts_created} alerts generated in ${result.elapsed_seconds}s).`
      );
      await loadData();
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to ingest local PCAP file");
    } finally {
      setUploadLoading(false);
    }
  };

  const handleStopPcap = async () => {
    try {
      await stopPcapIngestion();
      setSuccessMessage("PCAP stream stopped cleanly.");
      await loadData();
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to stop PCAP stream");
    } finally {
      setUploadLoading(false);
    }
  };

  const isRunning = status?.status === "RUNNING";
  const isStarting = status?.status === "STARTING";
  const isError = status?.status === "ERROR";

  const flowsList = metrics?.recent_flows || [];
  const filteredFlows = flowsList.filter((f) => {
    if (flowFilter === "attack") return f.prediction === "ATTACK";
    if (flowFilter === "benign") return f.prediction === "BENIGN";
    return true;
  });

  const liveHistoryCount = historyList.filter((h) => h.session_type === "LIVE_MONITORING").length;
  const pcapHistoryCount = historyList.filter((h) => h.session_type === "PCAP_INGESTION").length;
  const resetHistoryCount = historyList.filter((h) => h.session_type === "TELEMETRY_RESET").length;

  const filteredHistory = historyList.filter((item) => {
    if (historyFilter === "live") return item.session_type === "LIVE_MONITORING";
    if (historyFilter === "pcap") return item.session_type === "PCAP_INGESTION";
    if (historyFilter === "reset") return item.session_type === "TELEMETRY_RESET";
    return true;
  });

  return (
    <div className="space-y-6 pb-12">
      {/* Top Status & Controls Header Banner */}
      <div className="neu-flat rounded-2xl p-6 border border-white flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 shadow-sm">
        <div className="flex items-center gap-4">
          <div
            className={cn(
              "w-14 h-14 rounded-2xl flex items-center justify-center shadow-inner transition-colors",
              isRunning
                ? "bg-emerald-100 text-emerald-700 shadow-emerald-500/20"
                : isError
                ? "bg-rose-100 text-rose-700 shadow-rose-500/20"
                : isStarting
                ? "bg-amber-100 text-amber-700 shadow-amber-500/20"
                : "bg-slate-200 text-slate-700 shadow-slate-500/10"
            )}
          >
            <Radio className={cn("w-7 h-7", isRunning && "animate-pulse")} />
          </div>

          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={cn(
                  "text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-full uppercase tracking-wider",
                  isRunning
                    ? "bg-emerald-100 text-emerald-800 border border-emerald-300 flex items-center gap-1.5"
                    : isError
                    ? "bg-rose-100 text-rose-800 border border-rose-300"
                    : isStarting
                    ? "bg-amber-100 text-amber-800 border border-amber-300"
                    : "bg-slate-100 text-slate-700 border border-slate-300"
                )}
              >
                {isRunning && <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />}
                {status?.status || "STOPPED"}
              </span>

              <span className="text-[11px] font-mono text-slate-500">
                Mode: {status?.mode || "NONE"} &bull; Source: {status?.source || "None"}
              </span>

              {status?.capture_mode === "real" && (
                <span className="text-[10px] font-mono font-bold bg-emerald-600 text-white px-2 py-0.5 rounded-full flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
                  REAL LIVE CAPTURE
                </span>
              )}
              {status?.capture_mode === "demo" && (
                <span className="text-[10px] font-mono font-bold bg-amber-500 text-slate-950 px-2 py-0.5 rounded-full">
                  DEMO / SIMULATED
                </span>
              )}
              {status?.capture_mode === "pcap_file" && (
                <span className="text-[10px] font-mono font-bold bg-blue-600 text-white px-2 py-0.5 rounded-full">
                  PCAP FILE
                </span>
              )}

              {pcapLiveCapable ? (
                <span className="text-[10px] font-mono bg-emerald-50 text-emerald-700 border border-emerald-200 px-2 py-0.5 rounded-full">
                  Npcap Driver: Active
                </span>
              ) : (
                <span className="text-[10px] font-mono bg-amber-50 text-amber-700 border border-amber-200 px-2 py-0.5 rounded-full">
                  Npcap Driver: Not Detected
                </span>
              )}

              <span className="text-[10px] font-mono text-slate-600 bg-slate-100 px-2 py-0.5 rounded-full border border-slate-200">
                {metrics?.packets_captured ?? status?.packets_captured ?? 0} pkts
              </span>
            </div>

            <h1 className="text-xl md:text-2xl font-black text-slate-900 tracking-tight mt-1">
              Live Network Traffic Sniffer & ML Classifier
            </h1>
            <p className="text-xs text-slate-500 mt-0.5 max-w-2xl">
              Sniffs genuine packets from your Wi-Fi/Ethernet adapter, calculates 70 statistical features, and evaluates threats in real-time.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 shrink-0 self-end lg:self-center">
          <button
            onClick={() => loadData(true)}
            disabled={isLoading}
            className="px-3.5 py-2.5 rounded-xl neu-flat hover:bg-white text-slate-700 hover:text-cyan-700 text-xs font-bold flex items-center gap-2 transition-all active:scale-95 border border-white shadow-sm"
            title="Refresh All Telemetry Across Whole Application"
          >
            <RefreshCw className={cn("w-4 h-4 text-cyan-600", isLoading && "animate-spin")} />
            <span>Refresh All</span>
          </button>

          <button
            onClick={() => setResetConfirmOpen(true)}
            disabled={isResetting}
            className="px-3.5 py-2.5 rounded-xl neu-flat hover:bg-rose-50 text-rose-700 hover:text-rose-800 text-xs font-bold flex items-center gap-2 transition-all active:scale-95 border border-rose-200/80 shadow-sm"
            title="Zero Out All Telemetry Counters (0) & Clear Active Cache"
          >
            <RotateCcw className={cn("w-4 h-4 text-rose-600", isResetting && "animate-spin")} />
            <span>Reset to 0</span>
          </button>
        </div>
      </div>

      {/* QUICK OPERATIONAL GUIDE (3 SIMPLE STEPS) */}
      <div className="neu-flat rounded-2xl p-4 border border-white bg-gradient-to-r from-blue-50/70 via-white to-purple-50/70 shadow-sm">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-bold text-slate-800 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-[#6F3DFF]" />
            Quick 3-Step Guide: How to Sniff & Classify Traffic
          </span>
          <span className="text-[10px] font-mono font-bold text-slate-500 bg-white px-2 py-0.5 rounded-full border border-slate-200">
            EASY STEPS
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="p-2.5 rounded-xl bg-white border border-slate-200 shadow-sm flex items-start gap-2.5">
            <span className="w-6 h-6 rounded-lg bg-blue-100 text-blue-700 font-bold flex items-center justify-center shrink-0 text-xs">
              1
            </span>
            <div>
              <span className="font-bold text-slate-900 block">Select Network Interface</span>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Under Ingestion Controller, choose <strong>Live NIC</strong> and select your active card (e.g. <code>Wi-Fi</code>).
              </p>
            </div>
          </div>

          <div className="p-2.5 rounded-xl bg-white border border-slate-200 shadow-sm flex items-start gap-2.5">
            <span className="w-6 h-6 rounded-lg bg-purple-100 text-purple-700 font-bold flex items-center justify-center shrink-0 text-xs">
              2
            </span>
            <div>
              <span className="font-bold text-slate-900 block">Click &quot;Start Live Capture&quot;</span>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Press the green button to start packet sniffing. Status badge changes to 🟢 <strong>RUNNING</strong>.
              </p>
            </div>
          </div>

          <div className="p-2.5 rounded-xl bg-white border border-slate-200 shadow-sm flex items-start gap-2.5">
            <span className="w-6 h-6 rounded-lg bg-emerald-100 text-emerald-700 font-bold flex items-center justify-center shrink-0 text-xs">
              3
            </span>
            <div>
              <span className="font-bold text-slate-900 block">Watch Live AI Classifications</span>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Browse any website—flows appear below in the Live Feed classified as <strong>BENIGN</strong> or <strong>ATTACK</strong>.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Notifications / Errors */}
      {errorMessage && (
        <div className="neu-flat rounded-xl p-4 border border-rose-200 bg-rose-50/70 text-rose-800 flex items-start justify-between gap-3 animate-fade-in">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
            <div className="text-xs">
              <span className="font-bold block text-rose-900">Ingestion Alert / Diagnostics:</span>
              <p className="mt-0.5 leading-relaxed">
                {errorMessage === "Failed to fetch"
                  ? "Cannot connect to the FastAPI backend server on port 8000. Ensure the backend server is running with 'python -m uvicorn main:app --port 8000'."
                  : errorMessage}
              </p>
            </div>
          </div>
          <button
            onClick={() => setErrorMessage(null)}
            className="text-slate-400 hover:text-rose-700 text-sm font-bold p-1 leading-none"
            title="Dismiss error"
          >
            &times;
          </button>
        </div>
      )}

      {successMessage && (
        <div className="neu-flat rounded-xl p-4 border border-emerald-200 bg-emerald-50/70 text-emerald-800 flex items-start justify-between gap-3 animate-fade-in">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
            <div className="text-xs">
              <span className="font-bold block text-emerald-900">Operation Successful:</span>
              <p className="mt-0.5 leading-relaxed">{successMessage}</p>
            </div>
          </div>
          <button
            onClick={() => setSuccessMessage(null)}
            className="text-slate-400 hover:text-emerald-700 text-sm font-bold p-1 leading-none"
            title="Dismiss notice"
          >
            &times;
          </button>
        </div>
      )}

      {/* 4 Telemetry Counter Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="neu-flat rounded-2xl p-5 border border-white relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider">TOTAL FLOWS PROCESSED</span>
            <Activity className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-3xl font-black text-slate-900 font-mono mt-2">
            {metrics?.flows_processed ?? status?.flows_processed ?? 0}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 flex items-center gap-1">
            <span>Aggregated 5-Tuple Flows</span>
          </div>
        </div>

        <div className="neu-flat rounded-2xl p-5 border border-white relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider">BENIGN TRAFFIC</span>
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-3xl font-black text-emerald-600 font-mono mt-2">
            {metrics?.benign_count ?? status?.benign_count ?? 0}
          </div>
          <div className="text-[11px] text-emerald-700 mt-1 flex items-center gap-1">
            <span>
              {metrics?.flows_processed
                ? `${Math.round(((metrics.benign_count || 0) / metrics.flows_processed) * 100)}% of flows`
                : "Safe Traffic Streams"}
            </span>
          </div>
        </div>

        <div className="neu-flat rounded-2xl p-5 border border-white relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider">ATTACK ANOMALIES</span>
            <AlertTriangle className="w-4 h-4 text-rose-600" />
          </div>
          <div className="text-3xl font-black text-rose-600 font-mono mt-2">
            {metrics?.attack_count ?? status?.attack_count ?? 0}
          </div>
          <div className="text-[11px] text-rose-700 mt-1">
            <span>CICIDS2017 Random Forest Hits</span>
          </div>
        </div>

        <div className="neu-flat rounded-2xl p-5 border border-white relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider">SOC ALERTS GENERATED</span>
            <FileCheck2 className="w-4 h-4 text-indigo-600" />
          </div>
          <div className="text-3xl font-black text-indigo-600 font-mono mt-2">
            {metrics?.alerts_created ?? status?.alerts_created ?? 0}
          </div>
          <div className="text-[11px] text-indigo-700 mt-1 flex items-center justify-between">
            <span>Deduplicated in SQLite</span>
            {onNavigateTab && (
              <button
                onClick={() => onNavigateTab("alerts")}
                className="text-[10px] font-bold text-indigo-800 hover:underline flex items-center gap-0.5"
              >
                <span>View</span>
                <ChevronRight className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Main Ingestion & Controls Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Capture Controller (2 Tabs) */}
        <div className="neu-flat rounded-2xl p-6 border border-white space-y-5 lg:col-span-1 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-200/80 pb-3">
              <div>
                <h2 className="text-sm font-extrabold text-slate-900 tracking-tight">
                  Ingestion Controller
                </h2>
                <p className="text-[11px] text-slate-500">Configure capture source & pipeline</p>
              </div>

              {/* Pill Switcher */}
              <div className="flex p-0.5 rounded-full bg-slate-200/80 neu-pressed-sm">
                <button
                  onClick={() => setActiveControlTab("pcap")}
                  className={cn(
                    "px-3 py-1 rounded-full text-[11px] font-bold transition-all",
                    activeControlTab === "pcap"
                      ? "bg-white text-blue-700 shadow-sm"
                      : "text-slate-600 hover:text-slate-900"
                  )}
                >
                  PCAP File
                </button>
                <button
                  onClick={() => setActiveControlTab("live")}
                  className={cn(
                    "px-3 py-1 rounded-full text-[11px] font-bold transition-all",
                    activeControlTab === "live"
                      ? "bg-white text-blue-700 shadow-sm"
                      : "text-slate-600 hover:text-slate-900"
                  )}
                >
                  Live NIC
                </button>
              </div>
            </div>

            {/* TAB 1: PCAP Ingestion */}
            {activeControlTab === "pcap" && (
              <div className="space-y-4 pt-4">
                <div className="text-xs text-slate-600 leading-relaxed">
                  Ingest and analyze PCAP / PCAPNG packet captures (<span className="font-mono font-bold">up to 25 GB</span>) using CyberSentinel's streaming pipeline with zero memory exhaustion.
                </div>

                {/* Sub-mode selector: Upload vs Local Path */}
                <div className="flex p-0.5 rounded-xl bg-slate-200/90 neu-pressed-sm text-xs font-bold">
                  <button
                    onClick={() => setPcapSubTab("upload")}
                    className={cn(
                      "flex-1 py-1.5 rounded-lg transition-all text-center",
                      pcapSubTab === "upload"
                        ? "bg-white text-blue-700 shadow-sm"
                        : "text-slate-600 hover:text-slate-900"
                    )}
                  >
                    File Upload (Up to 25 GB)
                  </button>
                  <button
                    onClick={() => setPcapSubTab("local_disk")}
                    className={cn(
                      "flex-1 py-1.5 rounded-lg transition-all text-center",
                      pcapSubTab === "local_disk"
                        ? "bg-white text-blue-700 shadow-sm"
                        : "text-slate-600 hover:text-slate-900"
                    )}
                  >
                    Local File Path (Zero-Copy 12 GB)
                  </button>
                </div>

                {/* SUB-TAB A: File Upload */}
                {pcapSubTab === "upload" && (
                  <div className="space-y-3">
                    {/* Hidden File Input */}
                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={handleFileUpload}
                      accept=".pcap,.pcapng,.cap"
                      className="hidden"
                    />

                    {/* Dropzone Container */}
                    <div
                      onClick={() => fileInputRef.current?.click()}
                      className="border-2 border-dashed border-slate-300 hover:border-blue-500 hover:bg-blue-50/30 rounded-2xl p-5 text-center cursor-pointer transition-all neu-pressed-sm flex flex-col items-center justify-center gap-2"
                    >
                      <div className="w-10 h-10 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center">
                        <UploadCloud className="w-5 h-5" />
                      </div>
                      <div>
                        <span className="text-xs font-bold text-slate-800 block">
                          Click to select PCAP file
                        </span>
                        <span className="text-[10px] text-slate-400 block mt-0.5">
                          Streaming Scapy reader &bull; Supports multi-gigabyte captures
                        </span>
                      </div>
                    </div>

                    <div className="flex flex-col gap-2">
                      <button
                        onClick={() => fileInputRef.current?.click()}
                        disabled={uploadLoading}
                        className="w-full py-2 px-3 rounded-xl neu-flat text-xs font-bold text-slate-800 hover:text-blue-700 hover:bg-white transition-all active:scale-95 border border-white flex items-center justify-center gap-2"
                      >
                        <UploadCloud className="w-4 h-4 text-blue-600" />
                        <span>{uploadLoading ? "Streaming PCAP..." : "Select PCAP from Computer"}</span>
                      </button>

                      <button
                        onClick={handleLoadSamplePcap}
                        disabled={uploadLoading}
                        className="w-full py-2 px-3 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 text-white text-xs font-bold shadow-md shadow-blue-500/20 hover:from-blue-700 hover:to-cyan-700 transition-all active:scale-95 flex items-center justify-center gap-2"
                      >
                        <Sparkles className="w-4 h-4 text-cyan-200" />
                        <span>Load & Ingest Authorized Test PCAP</span>
                      </button>
                    </div>
                  </div>
                )}

                {/* SUB-TAB B: Local Disk Path */}
                {pcapSubTab === "local_disk" && (
                  <div className="space-y-3 bg-white/70 p-3 rounded-xl border border-slate-200 text-xs">
                    <div>
                      <label className="text-[11px] font-bold text-slate-800 flex items-center gap-1.5 mb-1">
                        <Database className="w-3.5 h-3.5 text-blue-600" />
                        <span>Local Disk File Path (12 GB+ Direct Stream):</span>
                      </label>
                      <input
                        type="text"
                        value={localPcapPath}
                        onChange={(e) => setLocalPcapPath(e.target.value)}
                        placeholder="e.g. C:\Datasets\traffic.pcap or C:\Users\lochk\Downloads\capture.pcap"
                        className="w-full px-3 py-2 rounded-xl bg-white border border-slate-300 text-xs font-mono text-slate-900 shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 placeholder:text-slate-400"
                      />
                      <span className="text-[10px] text-slate-400 block mt-1">
                        Streams directly from SSD at full speed with 0 MB HTTP transfer delay.
                      </span>
                    </div>

                    <div>
                      <label className="text-[11px] font-bold text-slate-800 flex items-center gap-1.5 mb-1">
                        <Activity className="w-3.5 h-3.5 text-blue-600" />
                        <span>Packet Limit / Sampling Profile:</span>
                      </label>
                      <select
                        value={localMaxPackets === null ? "all" : localMaxPackets.toString()}
                        onChange={(e) => {
                          const val = e.target.value;
                          setLocalMaxPackets(val === "all" ? null : parseInt(val, 10));
                        }}
                        className="w-full px-3 py-2 rounded-xl bg-white border border-slate-300 text-xs font-mono text-slate-900 shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
                      >
                        <option value="all">Full File (All Packets — Complete 12 GB Ingestion)</option>
                        <option value="100000">Fast Profiling: First 100,000 Packets (Recommended)</option>
                        <option value="50000">Quick Audit: First 50,000 Packets</option>
                        <option value="10000">Micro Sample: First 10,000 Packets</option>
                      </select>
                    </div>

                    <button
                      onClick={handleLocalFileIngest}
                      disabled={uploadLoading || !localPcapPath.trim()}
                      className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-blue-600 via-indigo-600 to-cyan-600 text-white text-xs font-bold shadow-md shadow-blue-500/20 hover:from-blue-700 hover:to-cyan-700 transition-all active:scale-95 flex items-center justify-center gap-2 disabled:opacity-50"
                    >
                      <Activity className={cn("w-4 h-4 text-cyan-200", uploadLoading && "animate-spin")} />
                      <span>{uploadLoading ? "Streaming & Classifying PCAP..." : "Stream & Ingest Local PCAP"}</span>
                    </button>
                  </div>
                )}

                {/* Real-time Streaming Progress HUD */}
                {uploadLoading && pcapProgress && (
                  <div className="p-3 bg-gradient-to-r from-blue-900/90 to-slate-900 text-white rounded-xl shadow-lg border border-blue-500/30 font-mono text-[11px] space-y-2">
                    <div className="flex items-center justify-between border-b border-blue-400/20 pb-1.5">
                      <span className="flex items-center gap-1.5 text-cyan-300 font-bold">
                        <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                        STREAMING PCAP TELEMETRY
                      </span>
                      <span className="text-[10px] text-cyan-200/80">
                        {pcapProgress.file_size_mb ? `${pcapProgress.file_size_mb} MB` : "Active Stream"}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[10px]">
                      <div>Packets Sniffed: <span className="font-bold text-white">{pcapProgress.packets_read.toLocaleString()}</span></div>
                      <div>Speed: <span className="font-bold text-cyan-300">{pcapProgress.current_rate_pps.toLocaleString()} pkts/s</span></div>
                      <div>Flows Formed: <span className="font-bold text-white">{pcapProgress.flows_extracted.toLocaleString()}</span></div>
                      <div>Attacks Detected: <span className="font-bold text-rose-400">{pcapProgress.attack_flows.toLocaleString()}</span></div>
                    </div>

                    <div className="text-[9px] text-slate-400 pt-0.5 flex justify-between items-center">
                      <span>Elapsed: {pcapProgress.elapsed_seconds}s (Zero-RAM Stream)</span>
                      <button
                        onClick={handleStopPcap}
                        className="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white font-sans font-bold text-[10px] flex items-center gap-1 shadow transition-all active:scale-95 cursor-pointer"
                        title="Cancel PCAP streaming"
                      >
                        <Square className="w-2.5 h-2.5 fill-current" />
                        <span>Stop Ingestion</span>
                      </button>
                    </div>
                  </div>
                )}

                {/* Completed Analysis Summary */}
                {pcapResult && !uploadLoading && (
                  <div className="p-3 bg-white/95 rounded-xl neu-pressed-sm text-[11px] font-mono space-y-1 text-slate-700 border border-slate-200 shadow-sm">
                    <div className="font-bold text-slate-900 border-b border-slate-200 pb-1 flex items-center justify-between">
                      <span>Analysis Summary: {pcapResult.filename}</span>
                      {pcapResult.file_size_mb && (
                        <span className="text-[10px] text-blue-600 bg-blue-50 px-1.5 py-0.5 rounded">
                          {pcapResult.file_size_mb} MB
                        </span>
                      )}
                    </div>
                    {pcapResult.packets_processed !== undefined && (
                      <div>Packets Streamed: <span className="font-bold text-slate-900">{pcapResult.packets_processed.toLocaleString()}</span></div>
                    )}
                    <div>Flows Extracted: <span className="font-bold text-slate-900">{pcapResult.flows_extracted.toLocaleString()}</span></div>
                    <div className="text-emerald-700">Benign Traffic: <span className="font-bold">{pcapResult.benign_flows.toLocaleString()}</span></div>
                    <div className="text-rose-700">Attacks Detected: <span className="font-bold">{pcapResult.attack_flows.toLocaleString()}</span></div>
                    <div className="text-indigo-700">Alerts Created: <span className="font-bold">{pcapResult.alerts_created.toLocaleString()}</span></div>
                    <div className="text-slate-400 text-[10px] pt-0.5">Processing Time: {pcapResult.elapsed_seconds}s</div>
                  </div>
                )}
              </div>
            )}

            {/* TAB 2: Live Interface Adapter */}
            {activeControlTab === "live" && (
              <div className="space-y-4 pt-4">
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-[11px] font-bold text-slate-800 flex items-center gap-1.5">
                      <Activity className="w-3.5 h-3.5 text-blue-600" />
                      <span>Select Authorized Network Interface:</span>
                    </label>
                    <span className="text-[10px] font-mono font-bold bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full">
                      {interfaces.length} Detected
                    </span>
                  </div>

                  <select
                    value={selectedInterface}
                    onChange={(e) => setSelectedInterface(e.target.value)}
                    disabled={isRunning || actionLoading}
                    className="w-full px-3 py-2.5 rounded-xl bg-white border border-slate-300 text-xs font-mono font-bold text-slate-800 shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer disabled:opacity-50"
                  >
                    {interfaces.map((iface) => {
                      const icon = iface.is_loopback ? "🔄" : iface.name.toLowerCase().includes("wi-fi") ? "📶" : "🔌";
                      return (
                        <option key={iface.id || iface.name} value={iface.name} className="py-1 text-slate-900 font-mono">
                          {icon} {iface.name} {iface.ip !== "Not Assigned" ? `[${iface.ip}]` : ""} — {iface.description}
                        </option>
                      );
                    })}
                  </select>

                  {/* Selected Interface Details Card */}
                  {(() => {
                    const activeIface = interfaces.find((i) => i.name === selectedInterface) || interfaces[0];
                    if (!activeIface) return null;
                    return (
                      <div className="mt-2.5 p-3 rounded-xl bg-white/90 border border-slate-200/90 neu-pressed-sm text-[11px] font-mono space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-slate-400 text-[10px]">ADAPTER HARDWARE</span>
                          <span className={cn(
                            "px-2 py-0.2 rounded-full text-[9px] font-bold uppercase",
                            activeIface.is_loopback ? "bg-purple-100 text-purple-700" : "bg-blue-100 text-blue-700"
                          )}>
                            {activeIface.is_loopback ? "Loopback" : "Hardware NIC"}
                          </span>
                        </div>
                        <div className="font-bold text-slate-800 text-xs truncate" title={activeIface.description}>
                          {activeIface.description}
                        </div>
                        <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-100 text-[10px]">
                          <div>
                            <span className="text-slate-400 block">IP ADDRESS:</span>
                            <span className="text-emerald-700 font-bold">{activeIface.ip || "Not Assigned"}</span>
                          </div>
                          <div>
                            <span className="text-slate-400 block">PHYSICAL MAC:</span>
                            <span className="text-slate-700 font-bold truncate block">{activeIface.mac || "N/A"}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })()}
                </div>

                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">
                    BPF Capture Filter (Optional):
                  </label>
                  <input
                    type="text"
                    value={bpfFilter}
                    onChange={(e) => setBpfFilter(e.target.value)}
                    disabled={isRunning || actionLoading}
                    placeholder="e.g. tcp or udp, port 80"
                    className="w-full p-2.5 rounded-xl bg-white border border-slate-300 text-xs font-mono text-slate-800 shadow-inner focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                  />
                </div>

                {/* Engine Mode Toggle */}
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">
                    Capture Engine Mode:
                  </label>
                  <div className="grid grid-cols-2 gap-2 p-1 rounded-xl bg-slate-200/70 neu-pressed-sm">
                    <button
                      type="button"
                      disabled={isRunning || actionLoading}
                      onClick={() => setLiveCaptureMode("real")}
                      className={cn(
                        "py-2 px-2.5 rounded-lg text-[11px] font-bold transition-all text-center flex flex-col items-center justify-center gap-0.5",
                        liveCaptureMode === "real"
                          ? "bg-white text-emerald-800 shadow-sm border border-emerald-200/60"
                          : "text-slate-600 hover:text-slate-900"
                      )}
                    >
                      <span className="flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                        Real Live NIC
                      </span>
                      <span className="text-[9px] font-normal text-slate-500">Npcap Wire Capture</span>
                    </button>
                    <button
                      type="button"
                      disabled={isRunning || actionLoading}
                      onClick={() => setLiveCaptureMode("demo")}
                      className={cn(
                        "py-2 px-2.5 rounded-lg text-[11px] font-bold transition-all text-center flex flex-col items-center justify-center gap-0.5",
                        liveCaptureMode === "demo"
                          ? "bg-white text-amber-800 shadow-sm border border-amber-200/60"
                          : "text-slate-600 hover:text-slate-900"
                      )}
                    >
                      <span className="flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                        Demo Mode
                      </span>
                      <span className="text-[9px] font-normal text-slate-500">In-Memory Simulated</span>
                    </button>
                  </div>
                </div>

                {!pcapLiveCapable && liveCaptureMode === "real" && (
                  <div className="p-3 bg-amber-50/80 rounded-xl neu-pressed-sm border border-amber-200 text-amber-900 text-[11px] leading-relaxed">
                    <span className="font-bold block text-amber-950 mb-0.5">Windows Npcap Driver Notice:</span>
                    Live raw sniffing on Windows requires Npcap (https://npcap.com) installed with WinPcap API-compatible mode enabled. If not installed, switch to Demo Mode or use PCAP Ingestion.
                  </div>
                )}

                <div className="pt-2 flex items-center gap-3">
                  {!isRunning ? (
                    <button
                      onClick={handleStartLive}
                      disabled={actionLoading}
                      className={cn(
                        "flex-1 py-3 px-4 rounded-xl text-white text-xs font-bold shadow-lg active:scale-95 transition-all flex items-center justify-center gap-2 disabled:opacity-50",
                        liveCaptureMode === "real"
                          ? "bg-emerald-600 hover:bg-emerald-700 shadow-emerald-600/20"
                          : "bg-amber-600 hover:bg-amber-700 shadow-amber-600/20 text-slate-950"
                      )}
                    >
                      <Play className="w-4 h-4 fill-current" />
                      <span>
                        {actionLoading
                          ? "Starting..."
                          : liveCaptureMode === "real"
                          ? "Start Real Live NIC Capture"
                          : "Start Simulated Demo Traffic"}
                      </span>
                    </button>
                  ) : (
                    <button
                      onClick={handleStopLive}
                      disabled={actionLoading}
                      className="flex-1 py-3 px-4 rounded-xl bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold shadow-lg shadow-rose-600/20 active:scale-95 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                    >
                      <Square className="w-4 h-4 fill-current" />
                      <span>{actionLoading ? "Stopping..." : "Stop Monitoring"}</span>
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="p-3 bg-slate-100/80 rounded-xl neu-pressed-sm text-[11px] text-slate-600 border border-slate-200 mt-4">
            <span className="font-bold text-slate-800 block font-mono text-[10px]">OPERATIONAL SAFETY POLICY:</span>
            Zero simulated synthetic streams. Every flow classification corresponds to actual network packet captures evaluated by the CICIDS2017 classifier.
          </div>
        </div>

        {/* Right Columns: Real-Time Flow Telemetry Stream Table */}
        <div className="neu-flat rounded-2xl p-6 border border-white space-y-4 lg:col-span-2 flex flex-col justify-between">
          <div>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200/80 pb-3">
              <div>
                <h2 className="text-sm font-extrabold text-slate-900 tracking-tight flex items-center gap-2">
                  <span>Real-Time Network Flow Stream</span>
                  <span className="w-2 h-2 rounded-full bg-cyan-500 animate-ping" />
                </h2>
                <p className="text-[11px] text-slate-500 flex flex-wrap items-center gap-2">
                  <span>Last {filteredFlows.length} classified flows ({metrics?.flows_processed || 0} total)</span>
                  {isRunning && (
                    <span className="text-[10px] font-mono text-cyan-700 bg-cyan-50 px-2 py-0.5 rounded-full border border-cyan-200">
                      In Aggregator: {metrics?.active_flows_in_memory ?? 0} &bull; Dupes Prevented: {metrics?.duplicates_prevented ?? 0}
                    </span>
                  )}
                </p>
              </div>

              {/* Filter Buttons */}
              <div className="flex items-center gap-1.5 self-start sm:self-center">
                <button
                  onClick={() => setFlowFilter("all")}
                  className={cn(
                    "px-2.5 py-1 rounded-full text-[10px] font-mono font-bold transition-all",
                    flowFilter === "all" ? "bg-slate-900 text-white" : "bg-slate-200 text-slate-600"
                  )}
                >
                  All ({flowsList.length})
                </button>
                <button
                  onClick={() => setFlowFilter("attack")}
                  className={cn(
                    "px-2.5 py-1 rounded-full text-[10px] font-mono font-bold transition-all",
                    flowFilter === "attack" ? "bg-rose-600 text-white" : "bg-rose-100 text-rose-700"
                  )}
                >
                  Attacks ({flowsList.filter((f) => f.prediction === "ATTACK").length})
                </button>
                <button
                  onClick={() => setFlowFilter("benign")}
                  className={cn(
                    "px-2.5 py-1 rounded-full text-[10px] font-mono font-bold transition-all",
                    flowFilter === "benign" ? "bg-emerald-600 text-white" : "bg-emerald-100 text-emerald-700"
                  )}
                >
                  Benign ({flowsList.filter((f) => f.prediction === "BENIGN").length})
                </button>
              </div>
            </div>

            {/* Table Container */}
            <div className="overflow-x-auto [scrollbar-width:thin] max-h-[420px] overflow-y-auto mt-3">
              {filteredFlows.length === 0 ? (
                <div className="py-12 text-center text-slate-400">
                  <Activity className="w-8 h-8 mx-auto mb-2 opacity-40" />
                  <p className="text-xs font-semibold">No flow telemetry recorded yet</p>
                  <p className="text-[11px] text-slate-400 mt-1">
                    Upload an authorized PCAP file or start live monitoring to begin classification.
                  </p>
                </div>
              ) : (
                <table className="w-full text-left text-[11px]">
                  <thead>
                    <tr className="text-slate-400 border-b border-slate-200 font-mono text-[10px]">
                      <th className="py-2 px-2 font-bold uppercase">Time</th>
                      <th className="py-2 px-2 font-bold uppercase">Source &bull; Destination</th>
                      <th className="py-2 px-2 font-bold uppercase">Proto</th>
                      <th className="py-2 px-2 font-bold uppercase">Packets/Bytes</th>
                      <th className="py-2 px-2 font-bold uppercase">ML Result</th>
                      <th className="py-2 px-2 font-bold uppercase text-right">Confidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {filteredFlows.map((flow) => {
                      const isAttack = flow.prediction === "ATTACK";
                      return (
                        <tr
                          key={flow.id}
                          onClick={() => setSelectedFlowForModal(flow)}
                          className="hover:bg-blue-50/50 cursor-pointer transition-colors group"
                        >
                          <td className="py-2.5 px-2 font-mono text-slate-500 whitespace-nowrap">
                            {new Date(flow.timestamp).toLocaleTimeString()}
                          </td>
                          <td className="py-2.5 px-2 font-mono">
                            <div className="text-slate-900 font-semibold">
                              {flow.source_ip}:{flow.source_port}
                            </div>
                            <div className="text-slate-500 text-[10px]">
                              &rarr; {flow.destination_ip}:{flow.destination_port}
                            </div>
                          </td>
                          <td className="py-2.5 px-2 font-mono font-bold text-slate-700">
                            {flow.protocol}
                          </td>
                          <td className="py-2.5 px-2 font-mono text-slate-600">
                            <span>{flow.packets} pkts</span>
                            <span className="text-[10px] text-slate-400 block">
                              {flow.bytes} B ({flow.duration_ms}ms)
                            </span>
                          </td>
                          <td className="py-2.5 px-2">
                            <span
                              className={cn(
                                "px-2 py-0.5 rounded-full text-[10px] font-mono font-bold inline-flex items-center gap-1",
                                isAttack
                                  ? "bg-rose-100 text-rose-700 border border-rose-200"
                                  : "bg-emerald-100 text-emerald-700 border border-emerald-200"
                              )}
                            >
                              {flow.prediction}
                            </span>
                            {flow.alert_id && (
                              <span className="text-[9px] font-mono text-rose-600 block mt-0.5 font-bold">
                                {flow.alert_id}
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 px-2 text-right font-mono font-bold">
                            <span className={isAttack ? "text-rose-600" : "text-emerald-600"}>
                              {flow.confidence}%
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-200/80 flex items-center justify-between text-[11px] text-slate-500">
            <span>Click any flow record above to inspect full 5-tuple forensic metadata.</span>
            <span className="font-mono text-[10px]">CICIDS2017 Model: Random Forest</span>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* BOTTOM HISTORY LEDGER & SESSION AUDIT TRAIL */}
      {/* ========================================================================= */}
      <div className="neu-flat rounded-2xl p-6 border border-white space-y-5 shadow-sm">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-200/80 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-indigo-100 text-indigo-700 flex items-center justify-center shadow-inner">
              <History className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-black text-slate-900 tracking-tight">
                  Capture Session & Telemetry History Ledger
                </h2>
                <span className="text-[10px] font-mono font-bold bg-indigo-50 text-indigo-700 border border-indigo-200 px-2 py-0.5 rounded-full">
                  {historyList.length} Sessions Logged
                </span>
              </div>
              <p className="text-xs text-slate-500">
                Persistent audit history of all live NIC captures, PCAP file ingestions, and zero-counter telemetry resets.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto justify-between sm:justify-end">
            <button
              onClick={loadHistory}
              disabled={historyLoading}
              className="px-3 py-1.5 rounded-xl neu-flat hover:bg-white text-slate-600 hover:text-slate-900 text-xs font-semibold flex items-center gap-1.5 transition-all active:scale-95 border border-white"
              title="Refresh Session History"
            >
              <RefreshCw className={cn("w-3.5 h-3.5 text-indigo-600", historyLoading && "animate-spin")} />
              <span>Refresh History</span>
            </button>

            {historyList.length > 0 && (
              <button
                onClick={handleClearHistory}
                className="px-3 py-1.5 rounded-xl neu-flat hover:bg-rose-50 text-rose-600 hover:text-rose-700 text-xs font-semibold flex items-center gap-1.5 transition-all active:scale-95 border border-rose-200/60"
                title="Clear all recorded session history"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear History</span>
              </button>
            )}
          </div>
        </div>

        {/* Filter Navigation Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-1.5 p-1 rounded-xl bg-slate-200/50 neu-pressed-sm border border-slate-200/60">
            <button
              onClick={() => setHistoryFilter("all")}
              className={cn(
                "px-3 py-1 rounded-lg text-xs font-bold transition-all",
                historyFilter === "all"
                  ? "bg-white text-slate-900 shadow-sm"
                  : "text-slate-600 hover:text-slate-900"
              )}
            >
              All History ({historyList.length})
            </button>
            <button
              onClick={() => setHistoryFilter("live")}
              className={cn(
                "px-3 py-1 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5",
                historyFilter === "live"
                  ? "bg-white text-emerald-700 shadow-sm"
                  : "text-slate-600 hover:text-slate-900"
              )}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              Live NIC ({liveHistoryCount})
            </button>
            <button
              onClick={() => setHistoryFilter("pcap")}
              className={cn(
                "px-3 py-1 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5",
                historyFilter === "pcap"
                  ? "bg-white text-blue-700 shadow-sm"
                  : "text-slate-600 hover:text-slate-900"
              )}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
              PCAP Ingestions ({pcapHistoryCount})
            </button>
            <button
              onClick={() => setHistoryFilter("reset")}
              className={cn(
                "px-3 py-1 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5",
                historyFilter === "reset"
                  ? "bg-white text-rose-700 shadow-sm"
                  : "text-slate-600 hover:text-slate-900"
              )}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
              Telemetry Resets ({resetHistoryCount})
            </button>
          </div>

          <div className="text-[11px] font-mono text-slate-500 flex items-center gap-2">
            <Database className="w-3.5 h-3.5 text-slate-400" />
            <span>Audit trail auto-updates on live runs, file uploads, and resets.</span>
          </div>
        </div>

        {/* History Table */}
        <div className="overflow-x-auto rounded-xl border border-slate-200/80 bg-white/70 shadow-inner">
          {filteredHistory.length === 0 ? (
            <div className="p-10 text-center flex flex-col items-center justify-center space-y-2">
              <div className="w-12 h-12 rounded-2xl neu-flat flex items-center justify-center text-slate-400">
                <History className="w-6 h-6" />
              </div>
              <h3 className="text-sm font-bold text-slate-700">No session history records found</h3>
              <p className="text-xs text-slate-400 max-w-md">
                {historyFilter === "all"
                  ? "No capture sessions or resets recorded yet. Start a Live NIC capture or analyze a PCAP file to start building the history ledger."
                  : `No records found matching the "${historyFilter.toUpperCase()}" filter category.`}
              </p>
            </div>
          ) : (
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-100/80 font-mono text-[10px] uppercase text-slate-500 tracking-wider">
                  <th className="py-2.5 px-4 font-bold">Session ID / Type</th>
                  <th className="py-2.5 px-4 font-bold">Source / Adapter</th>
                  <th className="py-2.5 px-4 font-bold">Started &bull; Duration</th>
                  <th className="py-2.5 px-4 font-bold">Packets</th>
                  <th className="py-2.5 px-4 font-bold">Flows (Benign / Attack)</th>
                  <th className="py-2.5 px-4 font-bold">SOC Alerts</th>
                  <th className="py-2.5 px-4 font-bold text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                {filteredHistory.map((item) => {
                  const isLive = item.session_type === "LIVE_MONITORING";
                  const isPcap = item.session_type === "PCAP_INGESTION";
                  const isReset = item.session_type === "TELEMETRY_RESET";

                  return (
                    <tr
                      key={item.session_id}
                      className="hover:bg-blue-50/40 transition-colors"
                    >
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <span
                            className={cn(
                              "w-2 h-2 rounded-full shrink-0",
                              isLive
                                ? "bg-emerald-500"
                                : isPcap
                                ? "bg-blue-500"
                                : "bg-rose-500"
                            )}
                          />
                          <div>
                            <span className="font-bold text-slate-800 block">
                              {item.session_id}
                            </span>
                            <span
                              className={cn(
                                "text-[9px] font-bold uppercase px-1.5 py-0.2 rounded inline-block mt-0.5",
                                isLive
                                  ? "bg-emerald-100 text-emerald-800 border border-emerald-200"
                                  : isPcap
                                  ? "bg-blue-100 text-blue-800 border border-blue-200"
                                  : "bg-rose-100 text-rose-800 border border-rose-200"
                              )}
                            >
                              {item.session_type.replace(/_/g, " ")}
                            </span>
                          </div>
                        </div>
                      </td>

                      <td className="py-3 px-4 font-semibold text-slate-700">
                        <span className="truncate block max-w-[200px]" title={item.source}>
                          {item.source}
                        </span>
                      </td>

                      <td className="py-3 px-4 text-slate-600">
                        <div className="flex flex-col">
                          <span>{new Date(item.started_at).toLocaleTimeString()}</span>
                          <span className="text-[10px] text-slate-400">
                            {item.duration_seconds !== null && item.duration_seconds !== undefined
                              ? `${item.duration_seconds.toFixed(1)}s elapsed`
                              : item.status === "RUNNING"
                              ? "In progress..."
                              : "Instant milestone"}
                          </span>
                        </div>
                      </td>

                      <td className="py-3 px-4 font-bold text-slate-800">
                        {item.packets_captured.toLocaleString()}
                      </td>

                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1.5">
                          <span className="font-black text-slate-900">
                            {item.flows_processed.toLocaleString()}
                          </span>
                          <span className="text-[10px] text-slate-400">
                            ({item.benign_count.toLocaleString()} benign &bull;{" "}
                            <span
                              className={cn(
                                item.attack_count > 0 ? "text-rose-600 font-bold" : "text-slate-400"
                              )}
                            >
                              {item.attack_count} attacks
                            </span>
                            )
                          </span>
                        </div>
                      </td>

                      <td className="py-3 px-4">
                        <span
                          className={cn(
                            "px-2 py-0.5 rounded-full text-[10px] font-bold font-mono",
                            item.alerts_created > 0
                              ? "bg-rose-100 text-rose-700 border border-rose-200"
                              : "bg-slate-100 text-slate-600"
                          )}
                        >
                          {item.alerts_created} Alerts
                        </span>
                      </td>

                      <td className="py-3 px-4 text-right">
                        <span
                          className={cn(
                            "px-2.5 py-1 rounded-full text-[10px] font-bold uppercase",
                            item.status === "RUNNING"
                              ? "bg-emerald-100 text-emerald-800 border border-emerald-300 animate-pulse"
                              : item.status === "COMPLETED"
                              ? "bg-slate-100 text-slate-700 border border-slate-300"
                              : item.status === "COUNTERS_ZEROED"
                              ? "bg-amber-100 text-amber-800 border border-amber-300"
                              : "bg-slate-100 text-slate-700"
                          )}
                        >
                          {item.status.replace(/_/g, " ")}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Confirmation Modal for Reset Telemetry (Zero Counters) */}
      {resetConfirmOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="neu-flat rounded-3xl p-6 bg-[#eef3f8] border border-white max-w-md w-full shadow-2xl space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-2xl bg-rose-100 text-rose-600 flex items-center justify-center shadow-inner shrink-0">
                <RotateCcw className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-black text-slate-900">
                  Reset Telemetry Counters to 0?
                </h3>
                <span className="text-[11px] text-slate-500 font-mono">
                  Zero out live flow and packet statistics
                </span>
              </div>
            </div>

            <p className="text-xs text-slate-600 leading-relaxed bg-white/60 p-3 rounded-xl border border-slate-200">
              This action will reset <strong>Total Flows</strong>, <strong>Benign Traffic</strong>, <strong>Attack Anomalies</strong>, and <strong>SOC Alerts</strong> back to <span className="font-bold text-rose-600">0</span>. It also clears the active flow cache and records a milestone entry in the history ledger below.
            </p>

            <div className="flex items-center justify-end gap-2.5 pt-2">
              <button
                onClick={() => setResetConfirmOpen(false)}
                className="px-4 py-2 rounded-xl neu-flat text-xs font-bold text-slate-600 hover:text-slate-900 transition-all"
              >
                Cancel
              </button>
              <button
                onClick={handleResetCounters}
                disabled={isResetting}
                className="px-4 py-2 rounded-xl bg-rose-600 text-white text-xs font-bold hover:bg-rose-700 shadow-md shadow-rose-600/20 flex items-center gap-1.5 transition-all active:scale-95"
              >
                {isResetting ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <RotateCcw className="w-3.5 h-3.5" />
                )}
                Confirm Reset to 0
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Detailed Flow Telemetry Inspection */}
      {selectedFlowForModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="neu-flat rounded-3xl p-6 bg-[#eef3f8] border border-white max-w-xl w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <div>
                <span className="text-[10px] font-mono font-bold uppercase text-slate-400">
                  Network Flow Telemetry Record
                </span>
                <h3 className="text-lg font-black text-slate-900">
                  {selectedFlowForModal.source_ip}:{selectedFlowForModal.source_port} &rarr; {selectedFlowForModal.destination_ip}:{selectedFlowForModal.destination_port}
                </h3>
              </div>
              <button
                onClick={() => setSelectedFlowForModal(null)}
                className="w-8 h-8 rounded-full neu-flat flex items-center justify-center text-slate-500 hover:text-slate-900 text-sm font-bold"
              >
                &times;
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-slate-400 block text-[10px]">CLASSIFICATION</span>
                <span
                  className={cn(
                    "text-sm font-black",
                    selectedFlowForModal.prediction === "ATTACK" ? "text-rose-600" : "text-emerald-600"
                  )}
                >
                  {selectedFlowForModal.prediction} ({selectedFlowForModal.confidence}%)
                </span>
              </div>

              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-slate-400 block text-[10px]">CAPTURE ORIGIN</span>
                <span className="text-xs font-bold text-slate-800 uppercase flex items-center gap-1.5 mt-0.5">
                  <span
                    className={cn(
                      "w-2 h-2 rounded-full",
                      selectedFlowForModal.capture_origin === "npcap_live_nic"
                        ? "bg-emerald-500"
                        : selectedFlowForModal.capture_origin === "pcap_file"
                        ? "bg-blue-500"
                        : "bg-amber-500"
                    )}
                  />
                  {selectedFlowForModal.capture_origin === "npcap_live_nic"
                    ? "Npcap Live NIC"
                    : selectedFlowForModal.capture_origin === "pcap_file"
                    ? "PCAP Ingested"
                    : "Simulated Demo"}
                </span>
              </div>

              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-slate-400 block text-[10px]">INTERFACE / ADAPTER</span>
                <span className="font-bold text-slate-800 truncate block">
                  {selectedFlowForModal.interface || selectedFlowForModal.mode || "Host Adapter"}
                </span>
              </div>

              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-slate-400 block text-[10px]">FLOW TEARDOWN REASON</span>
                <span className="font-bold text-slate-800 capitalize">
                  {selectedFlowForModal.close_reason ? selectedFlowForModal.close_reason.replace(/_/g, " ") : "Completed"}
                </span>
              </div>

              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-slate-400 block text-[10px]">FIRST PACKET CAPTURED</span>
                <span className="font-semibold text-slate-700 text-[11px]">
                  {selectedFlowForModal.packet_start_time
                    ? new Date(selectedFlowForModal.packet_start_time).toLocaleTimeString()
                    : new Date(selectedFlowForModal.timestamp).toLocaleTimeString()}
                </span>
              </div>

              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-slate-400 block text-[10px]">LAST PACKET CAPTURED</span>
                <span className="font-semibold text-slate-700 text-[11px]">
                  {selectedFlowForModal.packet_end_time
                    ? new Date(selectedFlowForModal.packet_end_time).toLocaleTimeString()
                    : new Date(selectedFlowForModal.timestamp).toLocaleTimeString()}
                </span>
              </div>

              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-slate-400 block text-[10px]">PROTOCOL</span>
                <span className="font-bold text-slate-800">{selectedFlowForModal.protocol}</span>
              </div>

              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-slate-400 block text-[10px]">DURATION</span>
                <span className="font-bold text-slate-800">{selectedFlowForModal.duration_ms} ms</span>
              </div>

              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-slate-400 block text-[10px]">PACKET VOLUME</span>
                <span className="font-bold text-slate-800">{selectedFlowForModal.packets} packets</span>
              </div>

              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-slate-400 block text-[10px]">BYTE COUNT</span>
                <span className="font-bold text-slate-800">{selectedFlowForModal.bytes} bytes</span>
              </div>
            </div>

            {/* TRIAGE GUIDANCE IF ATTACK DETECTED */}
            {selectedFlowForModal.prediction === "ATTACK" ? (
              <div className="space-y-2.5 pt-1">
                <div className="p-3 bg-rose-50 border border-rose-200 rounded-xl space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-rose-900 flex items-center gap-1.5 text-[11px]">
                      <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
                      Threat Summary (क्या हुआ): Network Attack Anomaly
                    </span>
                    <span className="text-[10px] font-mono font-bold bg-rose-200/80 text-rose-800 px-2 py-0.5 rounded">
                      {selectedFlowForModal.confidence}% Confidence
                    </span>
                  </div>
                  <p className="text-[11px] text-rose-800 leading-relaxed font-sans">
                    Malicious flow detected from <strong>{selectedFlowForModal.source_ip}</strong> targeting port <strong>{selectedFlowForModal.destination_port}</strong>.
                    Telemetry matched trained CICIDS2017 attack signatures.
                  </p>
                </div>

                <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl space-y-1.5 text-xs">
                  <span className="font-bold text-amber-900 flex items-center gap-1.5 text-[11px]">
                    <Activity className="w-3.5 h-3.5 text-amber-600" />
                    Detection Reason (क्यों & कैसे आया):
                  </span>
                  <ul className="list-disc pl-4 text-[10px] text-amber-800 space-y-0.5 font-sans">
                    <li>Flow rate: <strong>{selectedFlowForModal.packets} packets</strong> / <strong>{selectedFlowForModal.bytes} bytes</strong> over {selectedFlowForModal.duration_ms}ms.</li>
                    <li>Asymmetric packet transmission characteristic of automated probe/flood tools.</li>
                    <li>Multi-feature vector classified as ATTACK by Random Forest (70 flow features).</li>
                  </ul>
                </div>

                <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl space-y-2 text-xs">
                  <span className="font-bold text-emerald-900 flex items-center gap-1.5 text-[11px]">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                    Recommended Solution (Solution क्या है):
                  </span>
                  <div className="text-[10px] text-emerald-800 space-y-1 font-sans">
                    <p>1. <strong>Firewall Drop:</strong> Block inbound packets from <code className="bg-emerald-100 px-1 rounded font-mono font-bold">{selectedFlowForModal.source_ip}</code>.</p>
                    <p>2. <strong>Port Hardening:</strong> Inspect services bound to port <code className="bg-emerald-100 px-1 rounded font-mono font-bold">{selectedFlowForModal.destination_port}</code>.</p>
                  </div>
                </div>

                {selectedFlowForModal.alert_id && (
                  <div className="flex items-center justify-between p-2.5 bg-slate-100 rounded-xl border border-slate-200 text-xs font-mono">
                    <span className="text-slate-600 text-[10px]">SQLite Incident: <strong className="text-slate-900">{selectedFlowForModal.alert_id}</strong></span>
                    <button
                      onClick={() => {
                        setSelectedFlowForModal(null);
                        onNavigateTab?.("alerts");
                      }}
                      className="text-[10px] font-bold text-blue-600 hover:text-blue-800 flex items-center gap-1 font-sans"
                    >
                      <span>Open in Alerts &rarr;</span>
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-3 bg-emerald-50 rounded-xl border border-emerald-200 text-emerald-800 text-xs font-mono">
                <span className="font-bold block flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                  BENIGN Traffic Verified
                </span>
                <span className="text-[10px] text-emerald-700 mt-0.5 block font-sans">
                  This flow matches normal baseline operating parameters. No defensive action needed.
                </span>
              </div>
            )}

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedFlowForModal(null)}
                className="px-5 py-2 rounded-xl bg-slate-900 text-white text-xs font-bold hover:bg-black transition-all"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
