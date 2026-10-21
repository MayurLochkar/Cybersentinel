"use client";
import React, { useState } from "react";
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
import { CYBER_DATA, Incident, Alert } from "@/data/cyberData";

export function DashboardLayout({
  onReturnToHome,
}: {
  onReturnToHome: () => void;
}) {
  const [activeTab, setActiveTab] = useState<NavTab>("dashboard");
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
    const matched =
      CYBER_DATA.recentIncidents.find((i) => i.id === alert.incidentId) ||
      CYBER_DATA.recentIncidents[0];
    setSelectedIncident(matched);
    setActiveTab("incidents");
  };

  const handleViewReport = (incId: string) => {
    setReportIncidentId(incId);
    setActiveTab("report-view");
  };

  return (
    <div className="min-h-screen bg-[#eef3f8] flex flex-col selection:bg-cyan-200 selection:text-cyan-900">
      {/* Top Main Navigation Header */}
      <TopNavbar
        activeTab={activeTab}
        onNavigateHome={onReturnToHome}
        onSelectTab={setActiveTab}
      />

      {/* Centered Floating Command Bar (Removed side bar & centered in middle) */}
      <CenteredCommandNav
        activeTab={activeTab}
        onSelectTab={setActiveTab}
      />

      {/* Main Full-Width Content Container */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-4 pb-16 min-w-0">
        {activeTab === "dashboard" && (
          <OverviewView
            onSelectIncident={handleSelectIncident}
            onNavigateTab={(tab) => setActiveTab(tab as NavTab)}
          />
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
      </main>
    </div>
  );
}
