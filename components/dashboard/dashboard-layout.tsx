"use client";
import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { TopNavbar } from "./top-navbar";
import { CenteredCommandNav } from "./centered-command-nav";
import { NavTab } from "./sidebar";
import { OverviewView } from "./views/overview-view";
import { AlertsView } from "./views/alerts-view";
import { AlertDetailsView } from "./views/alert-details-view";
import { InvestigationView } from "./views/investigation-view";
import { ThreatIntelView } from "./views/threat-intel-view";
import { RiskView } from "./views/risk-view";
import { EvidenceView } from "./views/evidence-view";
import { AnalyticsView } from "./views/analytics-view";
import { ModelPerformanceView } from "./views/model-performance-view";
import { ReportsView } from "./views/reports-view";
import { ReportDetailView } from "./views/report-view";
import { SettingsView } from "./views/settings-view";
import { MonitoringView } from "./views/monitoring-view";
import { IncidentsView } from "./views/incidents-view";
import { HowItWorksModal } from "./how-it-works-modal";
import { CyberCursor } from "@/components/ui/cyber-cursor";
import { GsapScrollTriggerProvider } from "@/components/ui/gsap-scroll-trigger";
import { CYBER_DATA, Incident, Alert } from "@/data/cyberData";
import { fetchAlerts, ApiAlert } from "@/lib/api";

function buildIncidentFromApiAlert(alert: ApiAlert): Incident {
  const portMatch = alert.target?.match(/port\s*(\d+)/i) || alert.reason?.match(/port\s*(\d+)/i);
  const parsedPort = portMatch ? parseInt(portMatch[1], 10) : 8000;
  const parsedProtocol = alert.attack_type?.toLowerCase().includes("udp") ? "UDP" : "TCP";

  return {
    id: alert.incident_id,
    attackType: alert.attack_type,
    sourceIp: alert.source_ip,
    destinationIp: alert.destination_ip || "192.168.29.93",
    target: alert.target || `Port ${parsedPort} (${parsedProtocol})`,
    severity: alert.severity,
    confidence: alert.confidence,
    status: alert.status as any,
    time: alert.created_at ? alert.created_at.slice(11, 16) : "Live",
    protocol: parsedProtocol,
    port: parsedPort,
    detectionTime: alert.created_at || new Date().toISOString(),
    timeline: [
      {
        time: alert.created_at ? alert.created_at.slice(11, 19) : "Detection",
        event: `Live attack ${alert.incident_id} classified as ${alert.attack_type}`,
        detail: alert.reason || `Real-time packet anomaly detected from ${alert.source_ip}.`,
      },
      {
        time: "Forensics",
        event: "Network telemetry correlated",
        detail: `High-rate connection burst identified targeting ${alert.target}.`,
      },
      {
        time: "SOC Triage",
        event: "Automated alert record published",
        detail: `Logged to SQLite & Forensic Evidence Ledger with SHA-256 seal.`,
      },
    ],
    aiExplanation: {
      title: `Why was ${alert.attack_type} flagged?`,
      description: alert.reason || `Inbound traffic from ${alert.source_ip} exhibited anomalous connection velocity exceeding baseline thresholds.`,
      indicators: [
        `Source IP: ${alert.source_ip}`,
        `Target: ${alert.destination_ip || "192.168.29.93"}:${parsedPort}`,
        `Attack Classification: ${alert.attack_type}`,
        `Model Confidence: ${alert.confidence}%`,
      ],
    },
    mitre: {
      tactic: "Impact",
      technique: "Direct Network Denial of Service",
      techniqueId: "T1498.001",
      description: "Adversaries may perform TCP SYN floods targeting service ports to exhaust the connection backlog state.",
    },
    investigation: {
      status: alert.status,
      progressSteps: [
        { name: "Detection", completed: true },
        { name: "Triage", completed: true },
        { name: "Evidence Hash", completed: true },
        { name: "Classification", completed: true },
        { name: "RAG Analysis", completed: true },
        { name: "Containment", completed: false },
        { name: "Mitigation", completed: alert.status === "Resolved" },
      ],
      findings: [
        alert.reason || `Autonomous detection of ${alert.attack_type}.`,
        `Source IP ${alert.source_ip} directed anomalous traffic toward internal target ${alert.destination_ip || "192.168.29.93"}:${parsedPort}.`,
        `Confidence evaluated at ${alert.confidence}% via Random Forest multi-class model (CICIDS2017 features).`,
        `Forensic evidence cryptographic hash recorded and verified in SQLite ledger.`,
      ],
      relatedActivity: {
        alertsCount: 1,
        sourceIpsCount: 1,
        affectedAssetsCount: 1,
        suspiciousAuthCount: 0,
      },
      summary: alert.reason || `${alert.attack_type} detected from ${alert.source_ip} with ${alert.confidence}% confidence.`,
    },
    risk: {
      score: alert.confidence,
      level: alert.severity,
      factors: [
        { name: "Flow Density", level: alert.severity, score: alert.confidence },
        { name: "Host Vulnerability", level: alert.severity === "CRITICAL" ? "HIGH" : "MEDIUM", score: Math.min(100, alert.confidence * 0.9) },
        { name: "Network Exposure", level: "HIGH", score: 85 },
      ],
      explanation: alert.reason || `Live attack traffic from ${alert.source_ip} exceeding risk tolerance thresholds.`,
    },
  };
}

export function DashboardLayout({
  onReturnToHome,
  initialTab = "dashboard",
}: {
  onReturnToHome: () => void;
  initialTab?: NavTab;
}) {
  const [activeTab, setActiveTab] = useState<NavTab>(initialTab);
  const [showHowItWorks, setShowHowItWorks] = useState<boolean>(false);
  const [selectedIncident, setSelectedIncident] = useState<Incident>(
    CYBER_DATA.recentIncidents[0]
  );
  const [reportIncidentId, setReportIncidentId] = useState("INC-1024");

  useEffect(() => {
    let isMounted = true;
    async function loadLatestAlertIncident() {
      try {
        const alerts = await fetchAlerts();
        if (isMounted && alerts.length > 0) {
          const prioritized =
            alerts.find((a) => a.severity === "CRITICAL") ||
            alerts.find((a) => a.severity === "HIGH") ||
            alerts.find((a) => !a.destination_ip?.startsWith("224.") && !a.destination_ip?.startsWith("239.")) ||
            alerts[0];
          setSelectedIncident(buildIncidentFromApiAlert(prioritized));
          setReportIncidentId(prioritized.incident_id);
        }
      } catch {
        // non-blocking
      }
    }
    loadLatestAlertIncident();
    const handleGlobalRefresh = () => {
      loadLatestAlertIncident();
    };
    if (typeof window !== "undefined") {
      window.addEventListener("cybersentinel-refresh-all", handleGlobalRefresh);
    }
    return () => {
      isMounted = false;
      if (typeof window !== "undefined") {
        window.removeEventListener("cybersentinel-refresh-all", handleGlobalRefresh);
      }
    };
  }, []);

  const [incidentSubView, setIncidentSubView] = useState<"list" | "detail">("list");

  const handleSelectTab = (tab: NavTab) => {
    setActiveTab(tab);
    if (tab === "incidents") {
      setIncidentSubView("list");
    }
  };

  // Interaction Flow Helper: Dashboard -> Alert -> Alert Details -> AI Investigation -> etc.
  const handleSelectIncident = (incident: Incident) => {
    setSelectedIncident(incident);
    setIncidentSubView("detail");
    setActiveTab("incidents");
  };

  const handleInvestigateIncident = (incident: Incident) => {
    setSelectedIncident(incident);
    setActiveTab("investigation");
  };

  const handleInvestigateAlert = (alert: Alert) => {
    handleSelectAlert(alert);
    setActiveTab("investigation");
  };

  const handleSelectAlert = (alert: Alert) => {
    const matched = CYBER_DATA.recentIncidents.find(
      (i) => i.id === alert.incidentId || i.id === alert.id
    );
    if (matched) {
      setSelectedIncident({
        ...matched,
        destinationIp: alert.destinationIp || (matched as any).destinationIp || "10.0.0.21",
        status: alert.status as any,
        aiExplanation: {
          ...matched.aiExplanation,
          description: alert.reason || matched.aiExplanation.description,
        },
      });
    } else {
      const realReason =
        alert.reason ||
        `Real-time Network Telemetry: Inbound ${alert.protocol || "TCP"} traffic from ${alert.sourceIp} to ${alert.destinationIp || "internal host"}:${alert.port || 80} evaluated as ${alert.attackType} by Random Forest classifier with ${alert.confidence}% confidence.`;

      setSelectedIncident({
        id: alert.incidentId || alert.id,
        attackType: alert.attackType,
        sourceIp: alert.sourceIp,
        destinationIp: alert.destinationIp,
        target: alert.destinationIp ? `Port ${alert.port || 80} (${alert.protocol || "TCP"})` : "Network Host",
        severity: alert.severity,
        confidence: alert.confidence,
        status: alert.status as any,
        time: alert.timestamp || "Recent",
        protocol: alert.protocol || "TCP",
        port: alert.port || 80,
        detectionTime: new Date().toISOString(),
        timeline: [
          {
            time: alert.timestamp || "Detection",
            event: `Alert ${alert.incidentId || alert.id} classified as ${alert.attackType}`,
            detail: realReason,
          },
        ],
        aiExplanation: {
          title: `${alert.attackType} Threat Detected`,
          description: realReason,
          indicators: [
            "CICIDS2017 70-Feature Matrix Evaluation",
            "Packet Rate Burst Anomaly Divergence",
            "Asymmetric SYN/ACK Flag Distribution",
          ],
        },
        mitre: {
          tactic: alert.attackType.includes("Brute")
            ? "Credential Access"
            : alert.attackType.includes("Scan")
            ? "Discovery"
            : "Impact",
          technique: alert.attackType,
          techniqueId: alert.attackType.includes("Brute")
            ? "T1110"
            : alert.attackType.includes("Scan")
            ? "T1046"
            : "T1498",
          description: realReason,
        },
        investigation: {
          status: alert.status,
          progressSteps: [
            { name: "Detection", completed: true },
            { name: "Triage", completed: true },
            { name: "Evidence Hash", completed: true },
            { name: "Classification", completed: true },
            { name: "RAG Analysis", completed: true },
            { name: "Containment", completed: false },
            { name: "Mitigation", completed: alert.status === "Resolved" },
          ],
          findings: [
            realReason,
            `Model confidence evaluated at ${alert.confidence}% by Random Forest Classifier.`,
            `Target host is ${alert.destinationIp || "Internal Host"} on Port ${alert.port || 80} (${alert.protocol || "TCP"}).`,
            `Threat severity evaluated as ${alert.severity} priority based on automated SOC triage matrix.`,
          ],
          relatedActivity: {
            alertsCount: 1,
            sourceIpsCount: 1,
            affectedAssetsCount: 1,
            suspiciousAuthCount: 0,
          },
          summary: realReason,
        },
        risk: {
          score: alert.confidence,
          level: alert.severity,
          factors: [
            { name: "Threat Severity", level: alert.severity, score: alert.confidence },
            { name: "ML Confidence", level: alert.severity, score: alert.confidence },
            { name: "Asset Criticality", level: "HIGH", score: 85 },
          ],
          explanation: `Automated risk scoring based on ${alert.severity} severity and ${alert.confidence}% model confidence.`,
        },
      });
    }
    setIncidentSubView("detail");
    setActiveTab("incidents");
  };

  const handleViewReport = (incId: string) => {
    setReportIncidentId(incId);
    setActiveTab("report-view");
  };

  return (
    <div className="min-h-screen bg-[#eef3f8] flex flex-col selection:bg-cyan-200 selection:text-cyan-900 relative">
      {/* High-Tech Tactical SOC Cyber Cursor */}
      <CyberCursor />

      {/* Subtle ambient background effects */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div className="absolute top-0 right-1/4 w-[600px] h-[400px] bg-cyan-500/[0.02] blur-[150px] rounded-full" />
        <div className="absolute bottom-1/4 left-1/4 w-[500px] h-[350px] bg-indigo-500/[0.02] blur-[120px] rounded-full" />
      </div>

      {/* Top Main Navigation Header */}
      <TopNavbar
        activeTab={activeTab}
        onNavigateHome={onReturnToHome}
        onSelectTab={handleSelectTab}
        onOpenGuide={() => setShowHowItWorks(true)}
      />

      {/* Interactive Architecture & Quick Guide Modal */}
      <HowItWorksModal
        isOpen={showHowItWorks}
        onClose={() => setShowHowItWorks(false)}
        onNavigateTab={(tab) => {
          setShowHowItWorks(false);
          handleSelectTab(tab as NavTab);
        }}
      />

      {/* Centered Floating Command Bar */}
      <CenteredCommandNav
        activeTab={activeTab}
        onSelectTab={handleSelectTab}
      />

      {/* Main Full-Width Content Container */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-4 pb-16 min-w-0 relative z-10">
        <AnimatePresence mode="wait">
          <motion.div
            key={`${activeTab}-${incidentSubView}`}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
          >
            <GsapScrollTriggerProvider>
              {activeTab === "dashboard" && (
                <OverviewView
                  onSelectIncident={handleSelectIncident}
                  onInvestigateIncident={handleInvestigateIncident}
                  onNavigateTab={(tab) => handleSelectTab(tab as NavTab)}
                />
              )}

              {activeTab === "monitoring" && (
                <MonitoringView onNavigateTab={(tab) => handleSelectTab(tab as NavTab)} />
              )}

              {activeTab === "alerts" && (
                <AlertsView
                  onSelectAlert={handleSelectAlert}
                  onInvestigateAlert={handleInvestigateAlert}
                />
              )}

              {activeTab === "incidents" && incidentSubView === "list" && (
                <IncidentsView
                  onSelectIncident={(inc) => {
                    setSelectedIncident(inc);
                    setIncidentSubView("detail");
                  }}
                  onInvestigateIncident={(inc) => {
                    setSelectedIncident(inc);
                    setActiveTab("investigation");
                  }}
                  onViewReport={(incId) => handleViewReport(incId)}
                />
              )}

              {activeTab === "incidents" && incidentSubView === "detail" && (
                <AlertDetailsView
                  incident={selectedIncident}
                  onStartInvestigation={() => setActiveTab("investigation")}
                  onGenerateReport={() => handleViewReport(selectedIncident.id)}
                  onBack={() => setIncidentSubView("list")}
                />
              )}

              {activeTab === "threat-intel" && <ThreatIntelView />}

              {activeTab === "investigation" && (
                <InvestigationView
                  incident={selectedIncident}
                  onGenerateReport={() => handleViewReport(selectedIncident.id)}
                  onNavigateTab={(tab) => setActiveTab(tab as NavTab)}
                />
              )}

              {activeTab === "risk" && (
                <RiskView onNavigateTab={(tab) => setActiveTab(tab as NavTab)} />
              )}

              {activeTab === "evidence" && <EvidenceView />}

              {activeTab === "analytics" && <AnalyticsView />}

              {activeTab === "model" && <ModelPerformanceView />}

              {activeTab === "reports" && (
                <ReportsView onViewReport={handleViewReport} />
              )}

              {activeTab === "report-view" && (
                <ReportDetailView
                  incidentId={reportIncidentId}
                  onBack={() => setActiveTab("reports")}
                />
              )}

              {activeTab === "settings" && <SettingsView />}
            </GsapScrollTriggerProvider>
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}
