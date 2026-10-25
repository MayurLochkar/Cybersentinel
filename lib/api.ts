export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export interface ApiAlert {
  id: number;
  incident_id: string;
  attack_type: string;
  source_ip: string;
  destination_ip: string;
  target: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  confidence: number;
  status: "Open" | "Investigating" | "Resolved";
  reason: string;
  created_at: string;
}

export interface ApiDashboardSummary {
  total_alerts: number;
  critical: number;
  high_risk: number;
  active_investigations: number;
  open_alerts?: number;
  resolved_alerts?: number;
  verified_evidence: number;
  data_source: string;
  monitoring_status?: string;
  capture_mode?: string;
  source?: string;
  flows_processed?: number;
  packets_captured?: number;
  benign_count?: number;
  attack_count?: number;
  monitoring_alerts?: number;
}


export interface PredictResponse {
  prediction: "BENIGN" | "ATTACK";
  confidence_percent: number;
  probabilities_percent: {
    BENIGN: number;
    ATTACK: number;
  };
  model: string;
  note: string;
}

export interface PredictRequest {
  features: Record<string, number>;
}

/**
 * Fetch health status of backend
 */
export async function fetchHealth(): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE_URL}/api/health`, { cache: "no-store" });
  if (!res.ok) throw new Error("Backend service unavailable");
  return res.json();
}

/**
 * Fetch dashboard summary counters directly from SQLite backend
 */
export async function fetchDashboardSummary(): Promise<ApiDashboardSummary> {
  const res = await fetch(`${API_BASE_URL}/api/dashboard/summary`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch dashboard summary");
  return res.json();
}

/**
 * Fetch all alerts from backend database
 */
export async function fetchAlerts(): Promise<ApiAlert[]> {
  const res = await fetch(`${API_BASE_URL}/api/alerts`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch alerts from backend");
  return res.json();
}

/**
 * Fetch single alert by incident_id
 */
export async function fetchAlertById(incidentId: string): Promise<ApiAlert> {
  const res = await fetch(`${API_BASE_URL}/api/alerts/${encodeURIComponent(incidentId)}`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`Alert ${incidentId} not found`);
  return res.json();
}

/**
 * Create new alert
 */
export async function createAlert(alertData: Omit<ApiAlert, "id">): Promise<ApiAlert> {
  const res = await fetch(`${API_BASE_URL}/api/alerts`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(alertData),
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Failed to create alert: ${errorText}`);
  }
  return res.json();
}

/**
 * Update alert status
 */
export async function updateAlertStatus(
  incidentId: string,
  status: "Open" | "Investigating" | "Resolved"
): Promise<ApiAlert> {
  const res = await fetch(`${API_BASE_URL}/api/alerts/${encodeURIComponent(incidentId)}/status`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Failed to update status: ${errorText}`);
  }
  return res.json();
}

/**
 * Clears all persistent alerts from SQLite database
 */
export async function clearAllAlerts(): Promise<{ status: string; deleted_count: number }> {
  const res = await fetch(`${API_BASE_URL}/api/alerts/clear`, {
    method: "POST",
  });
  if (!res.ok) throw new Error("Failed to clear alerts");
  return res.json();
}

/**
 * Seeds demo baseline alerts in database
 */
export async function seedDemoAlerts(): Promise<{ status: string; total_alerts: number }> {
  const res = await fetch(`${API_BASE_URL}/api/alerts/seed-demo`, {
    method: "POST",
  });
  if (!res.ok) throw new Error("Failed to seed demo alerts");
  return res.json();
}

/**
 * Predict network traffic classification using real Random Forest model
 */
export async function predictTraffic(features: Record<string, number>): Promise<PredictResponse> {
  const res = await fetch(`${API_BASE_URL}/api/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ features }),
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Prediction error: ${errorText}`);
  }
  return res.json();
}

export interface MonitoringStatus {
  status: "STOPPED" | "STARTING" | "RUNNING" | "ERROR";
  mode: "NONE" | "LIVE" | "PCAP";
  capture_mode?: "real" | "demo" | "pcap_file" | "idle";
  pcap_live_capable: boolean;
  is_running?: boolean;
  source: string;
  selected_interface?: string;
  started_at: string | null;
  last_activity: string | null;
  packets_captured?: number;
  flows_processed: number;
  benign_count: number;
  attack_count: number;
  alerts_created: number;
  alerts_generated?: number;
  active_flows_in_memory?: number;
  duplicates_prevented?: number;
  errors_count: number;
  last_error: string | null;
  message?: string;
}

export interface RecentFlow {
  id: string;
  timestamp: string;
  packet_start_time?: string;
  packet_end_time?: string;
  packet_start_epoch?: number;
  packet_end_epoch?: number;
  capture_origin?: string;
  interface?: string;
  close_reason?: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  packets: number;
  bytes: number;
  duration_ms: number;
  prediction: "BENIGN" | "ATTACK";
  confidence: number;
  probabilities: Record<string, number>;
  alert_id: string | null;
  mode: string;
}

export interface MonitoringMetrics {
  status: string;
  mode: string;
  capture_mode?: string;
  source: string;
  selected_interface?: string;
  packets_captured?: number;
  flows_processed: number;
  benign_count: number;
  attack_count: number;
  alerts_created: number;
  alerts_generated?: number;
  active_flows_in_memory?: number;
  duplicates_prevented?: number;
  errors_count: number;
  recent_flows: RecentFlow[];
}

export interface NetworkInterfaceInfo {
  id: string;
  name: string;
  description: string;
  ip: string;
  mac: string;
  is_loopback: boolean;
}

export interface MonitoringInterfacesResponse {
  pcap_available: boolean;
  interfaces: NetworkInterfaceInfo[];
}

export interface PcapUploadResponse {
  status: string;
  filename: string;
  file_size_mb?: number;
  packets_processed?: number;
  flows_extracted: number;
  benign_flows: number;
  attack_flows: number;
  alerts_created: number;
  elapsed_seconds: number;
}

export interface PcapProgressResponse {
  status: "idle" | "streaming" | "processing" | "completed" | "error";
  filename: string;
  file_size_mb: number;
  packets_read: number;
  flows_extracted: number;
  attack_flows: number;
  benign_flows: number;
  alerts_created: number;
  elapsed_seconds: number;
  current_rate_pps: number;
  error?: string | null;
}

/**
 * Fetch current live monitoring status
 */
export async function fetchMonitoringStatus(): Promise<MonitoringStatus> {
  const res = await fetch(`${API_BASE_URL}/api/monitoring/status`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch monitoring status");
  return res.json();
}

/**
 * Fetch telemetry metrics and real-time recent flows
 */
export async function fetchMonitoringMetrics(): Promise<MonitoringMetrics> {
  const res = await fetch(`${API_BASE_URL}/api/monitoring/metrics`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch monitoring metrics");
  return res.json();
}

/**
 * Enumerate host network interfaces and Npcap driver availability
 */
export async function fetchMonitoringInterfaces(): Promise<MonitoringInterfacesResponse> {
  const res = await fetch(`${API_BASE_URL}/api/monitoring/interfaces`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch network interfaces");
  return res.json();
}

/**
 * Explicitly start an authorized live monitoring session
 */
export async function startMonitoringSession(
  interfaceName?: string,
  bpfFilter?: string,
  mode: "real" | "demo" = "real"
): Promise<{ status: string; source: string; started_at: string; capture_mode?: string; selected_interface?: string }> {
  const res = await fetch(`${API_BASE_URL}/api/monitoring/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      interface: interfaceName || null,
      bpf_filter: bpfFilter || null,
      mode,
    }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errorData.detail || "Failed to start monitoring session");
  }
  return res.json();
}

/**
 * Cleanly halt the live monitoring session
 */
export async function stopMonitoringSession(): Promise<{
  status: string;
  message: string;
  flows_processed: number;
  alerts_created: number;
}> {
  const res = await fetch(`${API_BASE_URL}/api/monitoring/stop`, {
    method: "POST",
  });
  if (!res.ok) throw new Error("Failed to stop monitoring session");
  return res.json();
}

export interface SessionHistoryItem {
  session_id: string;
  session_type: string;
  type?: string;
  source: string;
  interface?: string;
  started_at: string;
  ended_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
  packets_captured: number;
  flows_processed: number;
  benign_count: number;
  attack_count: number;
  alerts_created: number;
  status: string;
}

/**
 * Resets all live telemetry counters and flow inspection buffers back to 0.
 */
export async function resetMonitoringTelemetry(): Promise<MonitoringStatus> {
  const res = await fetch(`${API_BASE_URL}/api/monitoring/reset`, {
    method: "POST",
  });
  if (!res.ok) throw new Error("Failed to reset monitoring telemetry");
  return res.json();
}

/**
 * Fetches the complete ledger of past capture sessions and PCAP uploads.
 */
export async function fetchMonitoringHistory(): Promise<SessionHistoryItem[]> {
  const res = await fetch(`${API_BASE_URL}/api/monitoring/history`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch monitoring history");
  const data = await res.json();
  const list = Array.isArray(data) ? data : data.history || [];
  return list.map((item: any) => ({
    session_id: item.session_id,
    session_type: item.session_type || item.type || "LIVE_MONITORING",
    type: item.type || item.session_type || "LIVE_MONITORING",
    source: item.source || "Network Adapter",
    interface: item.interface || item.source || "Wi-Fi",
    started_at: item.started_at || new Date().toISOString(),
    ended_at: item.ended_at || null,
    completed_at: item.completed_at || item.ended_at || null,
    duration_seconds:
      typeof item.duration_seconds === "number"
        ? item.duration_seconds
        : item.ended_at && item.started_at
        ? Math.max(0, (new Date(item.ended_at).getTime() - new Date(item.started_at).getTime()) / 1000)
        : null,
    packets_captured: Number(item.packets_captured || 0),
    flows_processed: Number(item.flows_processed || 0),
    benign_count:
      typeof item.benign_count === "number"
        ? item.benign_count
        : Math.max(0, Number(item.flows_processed || 0) - Number(item.attack_count || 0)),
    attack_count: Number(item.attack_count || 0),
    alerts_created: Number(item.alerts_created || item.attack_count || 0),
    status: item.status || "COMPLETED",
  }));
}

/**
 * Clears the session history log.
 */
export async function clearMonitoringHistory(): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_BASE_URL}/api/monitoring/history/clear`, {
    method: "POST",
  });
  if (!res.ok) throw new Error("Failed to clear monitoring history");
  return res.json();
}


/**
 * Upload an authorized PCAP or PCAPNG capture file for flow extraction & ML inference
 */
export async function uploadPcapFile(file: File): Promise<PcapUploadResponse> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE_URL}/api/monitoring/pcap`, {
    method: "POST",
    body: formData,
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errorData.detail || "PCAP analysis failed");
  }
  return res.json();
}

/**
 * Ingest the built-in authorized sample PCAP directly on backend
 */
export async function ingestSamplePcap(): Promise<PcapUploadResponse> {
  const pcapBlobRes = await fetch(`${API_BASE_URL}/api/monitoring/sample-pcap`);
  if (!pcapBlobRes.ok) throw new Error("Failed to download sample PCAP");
  const blob = await pcapBlobRes.blob();
  const file = new File([blob], "cybersentinel_authorized_sample.pcap", {
    type: "application/vnd.tcpdump.pcap",
  });
  return uploadPcapFile(file);
}

/**
 * Ingest an authorized PCAP file directly from a local disk path (ideal for 12+ GB captures)
 */
export async function ingestLocalPcapFile(
  filePath: string,
  maxPackets?: number | null,
  flowTimeout: number = 30.0
): Promise<PcapUploadResponse> {
  const res = await fetch(`${API_BASE_URL}/api/monitoring/pcap/local`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      file_path: filePath,
      max_packets: maxPackets ?? null,
      flow_timeout: flowTimeout,
    }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errorData.detail || "Local PCAP analysis failed");
  }
  return res.json();
}

/**
 * Fetch real-time progress for PCAP packet parsing and flow classification
 */
export async function fetchPcapProgress(): Promise<PcapProgressResponse> {
  const res = await fetch(`${API_BASE_URL}/api/monitoring/pcap/progress`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch PCAP progress");
  return res.json();
}

/**
 * Abort active PCAP streaming ingestion immediately
 */
export async function stopPcapIngestion(): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_BASE_URL}/api/monitoring/pcap/stop`, {
    method: "POST",
  });
  if (!res.ok) throw new Error("Failed to stop PCAP ingestion");
  return res.json();
}

// ============================================================================
// Forensic Evidence Ledger
// ============================================================================

export interface ApiEvidenceItem {
  id: string;
  file_name: string;
  incident_id: string;
  stored_hash: string;
  file_size: string;
  blockchain_status: "Recorded" | "Pending";
  verification_status: "VERIFIED" | "TAMPERED" | "MISSING" | "ERROR";
  timestamp: string;
  recorded_block?: string | null;
}

export interface ApiEvidenceVerifyResult {
  evidence_id: string;
  file_name: string;
  stored_hash: string;
  current_hash: string;
  verification_status: "VERIFIED" | "TAMPERED" | "MISSING" | "ERROR";
  message: string;
  timestamp: string;
}

export async function fetchEvidenceList(): Promise<ApiEvidenceItem[]> {
  const res = await fetch(`${API_BASE_URL}/api/evidence`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch forensic evidence ledger");
  return res.json();
}

export async function verifyEvidenceHash(
  evidenceId: string
): Promise<ApiEvidenceVerifyResult> {
  const res = await fetch(`${API_BASE_URL}/api/evidence/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ evidence_id: evidenceId }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errorData.detail || "Failed to verify evidence hash");
  }
  return res.json();
}

// ============================================================================
// Real-time Analytics Summary
// ============================================================================

export interface ApiAnalyticsSummary {
  total_alerts: number;
  attack_distribution: Array<{
    name: string;
    value: number;
    percentage: number;
    color: string;
  }>;
  risk_distribution: Array<{
    name: string;
    value: number;
    color: string;
  }>;
  weekly_activity: Array<{
    day: string;
    incidents: number;
  }>;
  top_source_ips: Array<{
    ip: string;
    count: number;
  }>;
  top_targets: Array<{
    target: string;
    count: number;
  }>;
  status_pipeline: {
    Open: number;
    Investigating: number;
    Resolved: number;
  };
}

export async function fetchAnalyticsSummary(): Promise<ApiAnalyticsSummary> {
  const res = await fetch(`${API_BASE_URL}/api/analytics/summary`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch analytics summary");
  return res.json();
}

// ============================================================================
// Rule-Based Explainable Incident Risk
// ============================================================================

export interface RiskFactor {
  name: string;
  level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  score: number;
}

export interface ApiIncidentRisk {
  incident_id: string;
  attack_type: string;
  severity: string;
  confidence: number;
  calculated_risk_score: number;
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  factors: RiskFactor[];
  explanation: string;
}

export interface ApiRiskSummary {
  overall_score: number;
  overall_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  scoring_formula: string;
  incidents: ApiIncidentRisk[];
}

export async function fetchRiskSummary(): Promise<ApiRiskSummary> {
  const res = await fetch(`${API_BASE_URL}/api/risk/summary`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch risk assessment summary");
  return res.json();
}

// ============================================================================
// Local Threat Intel Matrix & MITRE ATT&CK Correlation
// ============================================================================

export interface ApiThreatIntelResult {
  query: string;
  matched_incidents_count: number;
  reputation_score: number;
  reputation_level: string;
  mitre_techniques: Array<{
    attack_type: string;
    tactic: string;
    technique_id: string;
    technique_name: string;
    description: string;
    mitigation: string;
  }>;
  matched_incidents: Array<{
    incident_id: string;
    attack_type: string;
    severity: string;
    source_ip: string;
    target: string;
    status: string;
    timestamp: string;
  }>;
  intel_source: string;
}

export async function fetchThreatIntelLookup(
  query: string
): Promise<ApiThreatIntelResult> {
  const res = await fetch(
    `${API_BASE_URL}/api/threat-intel/lookup?query=${encodeURIComponent(query)}`,
    { cache: "no-store" }
  );
  if (!res.ok) throw new Error("Failed to lookup threat intelligence");
  return res.json();
}

// ============================================================================
// RAG & LangChain AI Incident Copilot
// ============================================================================

export interface ApiAIInvestigationResponse {
  incident_id: string;
  executive_summary: string;
  attack_classification: {
    attack_type: string;
    technique_id: string;
    technique_name: string;
    tactics: string[];
    confidence_percent: number;
    source_ip: string;
    destination_ip: string;
  };
  retrieved_mitre_context: Array<{
    id: string;
    technique_id: string;
    technique_name: string;
    tactics: string[];
    description: string;
    mitigation: string[];
    snort_rule?: string;
  }>;
  forensic_hypothesis: string;
  containment_playbook: string[];
  snort_defense_rule: string;
  rag_citations: string[];
  model_provider: string;
  timestamp: string;
}

export interface ApiAICopilotChatResponse {
  query: string;
  response: string;
  retrieved_context: Array<any>;
  rag_technique: string;
  timestamp: string;
  provider: string;
}

export async function investigateIncidentWithAI(req: {
  incident_id: string;
  attack_type?: string;
  source_ip?: string;
  destination_ip?: string;
  confidence?: number;
  reason?: string;
}): Promise<ApiAIInvestigationResponse> {
  const res = await fetch(`${API_BASE_URL}/api/ai/investigate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) throw new Error("Failed to execute AI RAG investigation");
  return res.json();
}

export async function chatWithAICopilot(
  query: string,
  incidentId?: string,
  context?: Record<string, any>
): Promise<ApiAICopilotChatResponse> {
  const res = await fetch(`${API_BASE_URL}/api/ai/copilot-chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query, incident_id: incidentId, context }),
  });
  if (!res.ok) throw new Error("Failed to communicate with AI Copilot");
  return res.json();
}

export async function fetchAIKnowledgeStats(): Promise<{
  indexed_techniques_count: number;
  techniques: Array<{ id: string; name: string; tactics: string[] }>;
  active_provider: string;
  rag_status: string;
  supported_providers: string[];
}> {
  const res = await fetch(`${API_BASE_URL}/api/ai/knowledge-stats`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch AI knowledge stats");
  return res.json();
}


