"use client";
import React, { useState } from "react";
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
import { HowItWorksModal } from "./how-it-works-modal";
import { CyberCursor } from "@/components/ui/cyber-cursor";
import { CYBER_DATA, Incident, Alert } from "@/data/cyberData";

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

  // Interaction Flow Helper: Dashboard -> Alert -> Alert Details -> AI Investigation -> etc.
  const handleSelectIncident = (incident: Incident) => {
    setSelectedIncident(incident);
    setActiveTab("incidents");
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
            { name: "Remediation", completed: alert.status === "Resolved" },
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
        onSelectTab={setActiveTab}
        onOpenGuide={() => setShowHowItWorks(true)}
      />

      {/* Interactive Architecture & Quick Guide Modal */}
      <HowItWorksModal
        isOpen={showHowItWorks}
        onClose={() => setShowHowItWorks(false)}
        onNavigateTab={(tab) => {
          setShowHowItWorks(false);
          setActiveTab(tab as NavTab);
        }}
      />

      {/* Centered Floating Command Bar */}
      <CenteredCommandNav
        activeTab={activeTab}
        onSelectTab={setActiveTab}
      />

      {/* Main Full-Width Content Container */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-4 pb-16 min-w-0 relative z-10">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
          >
            {activeTab === "dashboard" && (
              <OverviewView
                onSelectIncident={handleSelectIncident}
                onNavigateTab={(tab) => setActiveTab(tab as NavTab)}
              />
            )}

            {activeTab === "monitoring" && (
              <MonitoringView onNavigateTab={(tab) => setActiveTab(tab as NavTab)} />
            )}

            {activeTab === "alerts" && (
              <AlertsView onSelectAlert={handleSelectAlert} />
            )}

            {activeTab === "incidents" && (
              <AlertDetailsView
                incident={selectedIncident}
                onStartInvestigation={() => setActiveTab("investigation")}
                onGenerateReport={() => handleViewReport(selectedIncident.id)}
                onBack={() => setActiveTab("alerts")}
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
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}
