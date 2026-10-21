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
  verified_evidence: number;
  data_source: string;
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
