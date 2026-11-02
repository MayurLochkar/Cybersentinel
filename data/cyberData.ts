export interface Alert {
  id: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  attackType: "Brute Force" | "DDoS" | "Port Scan" | "Web Attack" | "Botnet" | "SQL Injection";
  confidence: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: "Open" | "Investigating" | "Resolved" | "Closed";
  incidentId?: string;
  port?: number;
  protocol?: string;
  reason?: string;
}

export interface Incident {
  id: string;
  attackType: string;
  sourceIp: string;
  destinationIp?: string;
  target: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  confidence: number;
  status: "Investigating" | "Open" | "Resolved";
  time: string;
  protocol: string;
  port: number;
  detectionTime: string;
  timeline: { time: string; event: string; detail?: string }[];
  aiExplanation: {
    title: string;
    description: string;
    indicators: string[];
  };
  mitre: {
    tactic: string;
    technique: string;
    techniqueId: string;
    description: string;
  };
  investigation: {
    status: string;
    progressSteps: { name: string; completed: boolean }[];
    findings: string[];
    relatedActivity: {
      alertsCount: number;
      sourceIpsCount: number;
      affectedAssetsCount: number;
      suspiciousAuthCount: number;
    };
    summary: string;
  };
  risk: {
    score: number;
    level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    factors: { name: string; level: "HIGH" | "MEDIUM" | "LOW" | "CRITICAL"; score: number }[];
    explanation: string;
  };
  evidenceFile?: string;
}

export interface EvidenceItem {
  id: string;
  fileName: string;
  incidentId: string;
  sha256: string;
  storedHash: string;
  fileSize: string;
  blockchainStatus: "Recorded" | "Pending";
  verificationStatus: "VERIFIED" | "MISMATCH";
  timestamp: string;
  recordedBlock?: string;
}

export interface ReportItem {
  id: string;
  incidentId: string;
  title: string;
  attackType: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  generatedDate: string;
  analyst: string;
  summary: string;
}

export const CYBER_DATA = {
  kpis: {
    totalAlerts: 128,
    totalAlertsTrend: "+14% vs yesterday",
    critical: 3,
    criticalTrend: "+1 new in last 20m",
    highRisk: 7,
    highRiskTrend: "Stable",
    activeInvestigations: 5,
    activeInvestigationsTrend: "2 automated, 3 analyst",
    verifiedEvidence: 24,
    verifiedEvidenceTrend: "100% SHA-256 integrity",
  },
  attackDistribution: [
    { name: "Brute Force", percentage: 32, count: 41, color: "#2563eb" },
    { name: "DDoS", percentage: 24, count: 31, color: "#ef4444" },
    { name: "Port Scan", percentage: 18, count: 23, color: "#f59e0b" },
    { name: "Web Attack", percentage: 14, count: 18, color: "#0ea5e9" },
    { name: "Botnet", percentage: 7, count: 9, color: "#8b5cf6" },
    { name: "Other", percentage: 5, count: 6, color: "#64748b" },
  ],
  riskDistribution: [
    { level: "Critical", count: 3, color: "#ef4444", percentage: 2.3 },
    { level: "High", count: 7, color: "#f97316", percentage: 5.5 },
    { level: "Medium", count: 28, color: "#f59e0b", percentage: 21.8 },
    { level: "Low", count: 90, color: "#10b981", percentage: 70.4 },
  ],
  weeklyActivity: [
    { day: "Mon", alerts: 84, critical: 1 },
    { day: "Tue", alerts: 112, critical: 2 },
    { day: "Wed", alerts: 96, critical: 0 },
    { day: "Thu", alerts: 142, critical: 4 },
    { day: "Fri", alerts: 165, critical: 3 },
    { day: "Sat", alerts: 98, critical: 1 },
    { day: "Sun", alerts: 128, critical: 3 },
  ],
  liveActivityFeed: [
    { time: "Live", text: "Single-Source DoS (SYN Flood) detected from Laptop B (192.168.29.252)", type: "threat", severity: "CRITICAL" },
    { time: "Just now", text: "AI Investigation completed for INC-LIVE-10311117-C1FD68", type: "ai", severity: "INFO" },
    { time: "2 min ago", text: "Evidence hash verified: telemetry_inc_live_10311117_c1fd68.json", type: "evidence", severity: "SUCCESS" },
    { time: "5 min ago", text: "Port 8000 (TCP) ingress connection burst flagged by ML classifier", type: "threat", severity: "CRITICAL" },
    { time: "12 min ago", text: "Model active: Random Forest 96.4% multi-class confidence", type: "system", severity: "INFO" },
    { time: "20 min ago", text: "Real-time network telemetry synchronized with host 192.168.29.93", type: "system", severity: "INFO" },
  ],
  recentIncidents: [
    {
      id: "INC-LIVE-10311117-C1FD68",
      attackType: "Single-Source DoS (SYN Flood / Connection Exhaustion)",
      sourceIp: "192.168.29.252",
      destinationIp: "192.168.29.93",
      target: "Port 8000 (TCP)",
      severity: "CRITICAL" as const,
      confidence: 96,
      status: "Open" as const,
      time: "Just now",
      protocol: "TCP",
      port: 8000,
      detectionTime: "Live",
      timeline: [
        { time: "Live", event: "TCP SYN burst initiated", detail: "Originating from Laptop B (192.168.29.252) targeting port 8000 on host 192.168.29.93" },
        { time: "Live", event: "Connection velocity exceeded baseline", detail: "Exceeded 40 pkts/sec threshold across single destination port 8000" },
        { time: "Live", event: "ML Classifier triggered for Single-Source DoS", detail: "Random Forest multi-class model confirmed SYN flood with 96% confidence" },
        { time: "Live", event: "Cryptographic Evidence Generated", detail: "Recorded SHA-256 telemetry snapshot to tamper-evident ledger" },
        { time: "Live", event: "SOC Automated Triage Dispatched", detail: "Critical alert flagged with firewall containment recommendation" },
      ],
      aiExplanation: {
        title: "Why was Single-Source DoS flagged?",
        description:
          "Inbound network traffic from Laptop B (192.168.29.252) exhibited an anomalous high-velocity TCP SYN burst targeting service port 8000 on host 192.168.29.93. The connection rate exceeded baseline thresholds with incomplete handshakes, characteristic of connection starvation / SYN flood.",
        indicators: [
          "Source IP: 192.168.29.252 (Laptop B)",
          "Target: 192.168.29.93:8000 (Port 8000 TCP)",
          "Connection burst: 40 pkts/s velocity",
          "Incomplete TCP SYN handshakes",
          "Model confidence: 96%",
        ],
      },
      mitre: {
        tactic: "Impact",
        technique: "Direct Network Denial of Service (SYN Flood)",
        techniqueId: "T1498.001",
        description: "Adversaries execute rapid TCP SYN bursts targeting service ports to exhaust the host socket backlog and connection capacity.",
      },
      investigation: {
        status: "Investigation Completed",
        progressSteps: [
          { name: "Alert validated", completed: true },
          { name: "Network behaviour analysed", completed: true },
          { name: "Threat intelligence retrieved", completed: true },
          { name: "MITRE ATT&CK mapping completed", completed: true },
          { name: "Historical activity reviewed", completed: true },
          { name: "Risk assessed", completed: true },
          { name: "Recommendations generated", completed: true },
        ],
        findings: [
          "Finding 1: High-velocity TCP SYN burst from Laptop B (192.168.29.252).",
          "Finding 2: Traffic targeted service port 8000 on host 192.168.29.93 without completing 3-way handshakes.",
          "Finding 3: Behavior matches Single-Source DoS (SYN Flood / Connection Exhaustion) signature.",
          "Finding 4: Forensic evidence hash recorded with SHA-256 seal in tamper-evident ledger.",
        ],
        relatedActivity: {
          alertsCount: 1,
          sourceIpsCount: 1,
          affectedAssetsCount: 1,
          suspiciousAuthCount: 0,
        },
        summary:
          "Critical Single-Source DoS attack detected from Laptop B (192.168.29.252) targeting port 8000 on host 192.168.29.93 with 96% model confidence.",
      },
      risk: {
        score: 96,
        level: "CRITICAL" as const,
        factors: [
          { name: "Attack Severity", level: "CRITICAL" as const, score: 95 },
          { name: "Model Confidence", level: "HIGH" as const, score: 96 },
          { name: "Flow Density", level: "CRITICAL" as const, score: 92 },
          { name: "Asset Criticality", level: "HIGH" as const, score: 85 },
          { name: "Threat Intelligence", level: "HIGH" as const, score: 90 },
          { name: "Evidence Confidence", level: "HIGH" as const, score: 98 },
        ],
        explanation:
          "Risk evaluated as CRITICAL due to active Single-Source DoS (SYN Flood) targeting service availability on port 8000 from Laptop B (192.168.29.252).",
      },
      evidenceFile: "telemetry_inc_live_10311117_c1fd68.json",
    },
    {
      id: "INC-1023",
      attackType: "Port Scan",
      sourceIp: "45.91.22.17",
      target: "Web Server",
      severity: "MEDIUM" as const,
      confidence: 91,
      status: "Open" as const,
      time: "8 min ago",
      protocol: "TCP/SYN",
      port: 80,
      detectionTime: "12:35 PM",
      timeline: [
        { time: "12:32 PM", event: "SYN packet sweep across ports 1-1024" },
        { time: "12:34 PM", event: "Banner grabbing detected on port 22 and 80" },
        { time: "12:35 PM", event: "ML Classifier triggered for Network Reconnaissance" },
      ],
      aiExplanation: {
        title: "Reconnaissance Fingerprint Detected",
        description: "Source 45.91.22.17 sequentially scanned 1,024 TCP ports using fragmented SYN packets to evade stateless inspection.",
        indicators: ["Port sequencing sequence", "TCP flag anomalies", "Unregistered ASN source"],
      },
      mitre: {
        tactic: "Reconnaissance",
        technique: "Network Service Discovery",
        techniqueId: "T1046",
        description: "Adversaries may attempt to get a listing of services running on hosts by scanning network ports.",
      },
      investigation: {
        status: "Triage in Progress",
        progressSteps: [
          { name: "Alert validated", completed: true },
          { name: "Network behaviour analysed", completed: true },
          { name: "Threat intelligence retrieved", completed: true },
          { name: "MITRE ATT&CK mapping completed", completed: true },
          { name: "Historical activity reviewed", completed: false },
          { name: "Risk assessed", completed: false },
          { name: "Recommendations generated", completed: false },
        ],
        findings: [
          "Finding 1: Port scan covered 1024 ports within 3 minutes.",
          "Finding 2: Originating from hosting provider known for scanning nodes.",
        ],
        relatedActivity: {
          alertsCount: 2,
          sourceIpsCount: 1,
          affectedAssetsCount: 1,
          suspiciousAuthCount: 0,
        },
        summary: "Automated scan probing exposed web endpoints and SSH management ports without payload penetration.",
      },
      risk: {
        score: 58,
        level: "MEDIUM" as const,
        factors: [
          { name: "Attack Severity", level: "MEDIUM" as const, score: 55 },
          { name: "Model Confidence", level: "HIGH" as const, score: 91 },
          { name: "Attack Frequency", level: "MEDIUM" as const, score: 60 },
          { name: "Asset Criticality", level: "MEDIUM" as const, score: 65 },
          { name: "Threat Intelligence", level: "MEDIUM" as const, score: 50 },
          { name: "Evidence Confidence", level: "HIGH" as const, score: 90 },
        ],
        explanation: "Medium risk as probe was deflected by edge firewall with zero authentication access.",
      },
      evidenceFile: "honeypot_telemetry.log",
    },
    {
      id: "INC-1022",
      attackType: "DDoS",
      sourceIp: "103.44.18.91",
      target: "API Gateway",
      severity: "CRITICAL" as const,
      confidence: 98,
      status: "Investigating" as const,
      time: "12 min ago",
      protocol: "UDP Flood",
      port: 443,
      detectionTime: "12:24 PM",
      timeline: [
        { time: "12:20 PM", event: "Traffic surge exceeds 40 Gbps across 8 distributed clusters" },
        { time: "12:22 PM", event: "Rate limit threshold breached on ingress gateway" },
        { time: "12:24 PM", event: "Automatic mitigation scrub rule activated" },
      ],
      aiExplanation: {
        title: "Volumetric DDoS Attack in Progress",
        description: "Distributed amplification flood saturating upstream bandwidth through reflection vectors.",
        indicators: ["UDP packet reflection", "Spike from 800+ source IPs", "CPU load > 94% on gateway"],
      },
      mitre: {
        tactic: "Impact",
        technique: "Network Denial of Service",
        techniqueId: "T1498",
        description: "Adversaries may perform Network DoS attacks to degrade or block the availability of services.",
      },
      investigation: {
        status: "Mitigation Engaged",
        progressSteps: [
          { name: "Alert validated", completed: true },
          { name: "Network behaviour analysed", completed: true },
          { name: "Threat intelligence retrieved", completed: true },
          { name: "MITRE ATT&CK mapping completed", completed: true },
          { name: "Historical activity reviewed", completed: true },
          { name: "Risk assessed", completed: true },
          { name: "Recommendations generated", completed: true },
        ],
        findings: [
          "Finding 1: Traffic amplification factor is 38x standard UDP queries.",
          "Finding 2: Primary target is public API authorization endpoint.",
        ],
        relatedActivity: {
          alertsCount: 14,
          sourceIpsCount: 180,
          affectedAssetsCount: 2,
          suspiciousAuthCount: 0,
        },
        summary: "Major volumetric disruption effort mitigated by BGP scrubbing center and edge geoblocking.",
      },
      risk: {
        score: 96,
        level: "CRITICAL" as const,
        factors: [
          { name: "Attack Severity", level: "CRITICAL" as const, score: 98 },
          { name: "Model Confidence", level: "HIGH" as const, score: 98 },
          { name: "Attack Frequency", level: "CRITICAL" as const, score: 95 },
          { name: "Asset Criticality", level: "CRITICAL" as const, score: 99 },
          { name: "Threat Intelligence", level: "HIGH" as const, score: 88 },
          { name: "Evidence Confidence", level: "HIGH" as const, score: 96 },
        ],
        explanation: "Critical due to direct danger to public customer availability and API latency SLAs.",
      },
      evidenceFile: "network_capture.pcap",
    },
  ],
  alertsList: [
    {
      id: "ALT-0010",
      timestamp: "Live",
      sourceIp: "192.168.29.252",
      destinationIp: "192.168.29.93",
      attackType: "Single-Source DoS" as any,
      confidence: 96.4,
      severity: "CRITICAL" as const,
      status: "Open" as const,
      incidentId: "INC-LIVE-10311117-C1FD68",
      port: 8000,
      protocol: "TCP",
      reason: "Authorized Live Ingestion: Connection velocity 40 pkts/s exceeded baseline. Subtype: Single-Source DoS (SYN Flood / Connection Exhaustion).",
    },
    {
      id: "ALT-1023",
      timestamp: "12:39 PM",
      sourceIp: "45.91.22.17",
      destinationIp: "10.0.0.15",
      attackType: "Port Scan" as const,
      confidence: 91.7,
      severity: "MEDIUM" as const,
      status: "Open" as const,
      incidentId: "INC-1023",
      port: 80,
      protocol: "TCP",
    },
    {
      id: "ALT-1022",
      timestamp: "12:35 PM",
      sourceIp: "103.44.18.91",
      destinationIp: "10.0.0.8",
      attackType: "DDoS" as const,
      confidence: 98.1,
      severity: "CRITICAL" as const,
      status: "Investigating" as const,
      incidentId: "INC-1022",
      port: 443,
      protocol: "UDP",
    },
    {
      id: "ALT-1021",
      timestamp: "12:18 PM",
      sourceIp: "192.241.206.12",
      destinationIp: "10.0.0.4",
      attackType: "Web Attack" as const,
      confidence: 89.4,
      severity: "MEDIUM" as const,
      status: "Investigating" as const,
      port: 8080,
      protocol: "HTTP",
    },
    {
      id: "ALT-1020",
      timestamp: "11:55 AM",
      sourceIp: "82.102.23.4",
      destinationIp: "10.0.0.21",
      attackType: "Brute Force" as const,
      confidence: 92.0,
      severity: "HIGH" as const,
      status: "Resolved" as const,
      port: 22,
      protocol: "SSH",
    },
    {
      id: "ALT-1019",
      timestamp: "11:32 AM",
      sourceIp: "198.51.100.44",
      destinationIp: "10.0.0.99",
      attackType: "Botnet" as const,
      confidence: 96.5,
      severity: "CRITICAL" as const,
      status: "Closed" as const,
      port: 6667,
      protocol: "IRC/TCP",
    },
    {
      id: "ALT-1018",
      timestamp: "10:14 AM",
      sourceIp: "172.67.180.2",
      destinationIp: "10.0.0.12",
      attackType: "SQL Injection" as const,
      confidence: 88.3,
      severity: "HIGH" as const,
      status: "Resolved" as const,
      port: 3306,
      protocol: "MySQL",
    },
    {
      id: "ALT-1017",
      timestamp: "09:45 AM",
      sourceIp: "194.26.29.112",
      destinationIp: "10.0.0.15",
      attackType: "Port Scan" as const,
      confidence: 87.0,
      severity: "LOW" as const,
      status: "Closed" as const,
      port: 80,
      protocol: "TCP",
    },
  ],
  threatIntelligence: {
    indicator: "192.168.29.252",
    type: "IPv4 Address (LAN Host - Laptop B)",
    risk: "Critical",
    status: "Malicious",
    relatedAttack: "Single-Source DoS (SYN Flood / Connection Exhaustion)",
    country: "Local Subnet (192.168.29.0/24)",
    asn: "Private Wi-Fi Subnet",
    reputationScore: "96/100 Threat Index",
    mitre: {
      tactic: "Impact",
      technique: "T1498.001 — Direct Network Denial of Service (SYN Flood)",
      description: "Adversaries execute rapid TCP SYN bursts targeting service ports to exhaust the host socket backlog and connection capacity.",
    },
    relatedIndicators: {
      sourceIp: "192.168.29.252",
      relatedDomain: "laptop-b.local",
      hash: "c41dfca26fc0f988e421212cab718563fc89a5ebea2416a51921cb6b2bc3f51c",
      dnsRecord: "laptop-b-traffic-generator",
      firstSeen: "2026-10-31 11:15:00",
      lastSeen: "2026-10-31 11:39:53",
    },
  },
  evidenceLedger: [
    {
      id: "EV-LIVE-239C",
      fileName: "telemetry_inc_live_10311117_c1fd68.json",
      incidentId: "INC-LIVE-10311117-C1FD68",
      sha256: "c41dfca26fc0f988e421212cab718563fc89a5ebea2416a51921cb6b2bc3f51c",
      storedHash: "c41dfca26fc0f988e421212cab718563fc89a5ebea2416a51921cb6b2bc3f51c",
      fileSize: "389 B",
      blockchainStatus: "Recorded" as const,
      verificationStatus: "VERIFIED" as const,
      timestamp: "Live Recorded",
      recordedBlock: "#0xAA483C743",
    },
    {
      id: "EV-002",
      fileName: "network_capture.pcap",
      incidentId: "INC-1022",
      sha256: "71a82bc99401fec7d03a11928374be210d4891172a39bca022fa",
      storedHash: "71a82bc99401fec7d03a11928374be210d4891172a39bca022fa",
      fileSize: "48.2 MB",
      blockchainStatus: "Recorded" as const,
      verificationStatus: "VERIFIED" as const,
      timestamp: "12:46 PM",
      recordedBlock: "#0x8F91A198B",
    },
    {
      id: "EV-003",
      fileName: "honeypot_telemetry.log",
      incidentId: "INC-1023",
      sha256: "4c9018e21ba092817d663fe01a2c918239a018bcdef72101aa01",
      storedHash: "4c9018e21ba092817d663fe01a2c918239a018bcdef72101aa01",
      fileSize: "1.1 MB",
      blockchainStatus: "Recorded" as const,
      verificationStatus: "VERIFIED" as const,
      timestamp: "12:36 PM",
      recordedBlock: "#0x8F91A172D",
    },
    {
      id: "EV-004",
      fileName: "kernel_audit_telemetry.bin",
      incidentId: "INC-1019",
      sha256: "d301ab9827c1029384756bf019283471029384756192837402aa",
      storedHash: "d301ab9827c1029384756bf019283471029384756192837402aa",
      fileSize: "14.9 MB",
      blockchainStatus: "Recorded" as const,
      verificationStatus: "VERIFIED" as const,
      timestamp: "11:35 AM",
      recordedBlock: "#0x8F91A099E",
    },
  ],
  modelPerformance: {
    modelName: "Random Forest Classifier",
    accuracy: 96.4,
    precision: 95.8,
    recall: 94.9,
    f1Score: 95.3,
    fpr: 3.2,
    confusionMatrix: [
      { actual: "Brute Force", predictedBruteForce: 94, predictedDDoS: 2, predictedScan: 1, predictedOther: 3 },
      { actual: "DDoS", predictedBruteForce: 1, predictedDDoS: 98, predictedScan: 0, predictedOther: 1 },
      { actual: "Port Scan", predictedBruteForce: 2, predictedDDoS: 0, predictedScan: 92, predictedOther: 6 },
      { actual: "Benign", predictedBruteForce: 1, predictedDDoS: 1, predictedScan: 1, predictedOther: 97 },
    ],
    classificationBreakdown: [
      { attackType: "Brute Force", precision: 95.4, recall: 94.0, f1: 94.7, support: 1420 },
      { attackType: "DDoS", precision: 98.2, recall: 98.0, f1: 98.1, support: 3100 },
      { attackType: "Port Scan", precision: 92.8, recall: 91.5, f1: 92.1, support: 950 },
      { attackType: "Web Attack", precision: 89.6, recall: 90.2, f1: 89.9, support: 620 },
      { attackType: "Botnet", precision: 94.1, recall: 93.8, f1: 93.9, support: 410 },
      { attackType: "Benign Traffic", precision: 99.1, recall: 98.9, f1: 99.0, support: 18450 },
    ],
  },
  reports: [
    {
      id: "REP-2026-001",
      incidentId: "INC-LIVE-10311117-C1FD68",
      title: "Laptop B Single-Source DoS Investigation Report",
      attackType: "Single-Source DoS (SYN Flood / Connection Exhaustion)",
      severity: "CRITICAL" as const,
      generatedDate: "Today, Live",
      analyst: "Lead SOC Investigator",
      summary: "High volume TCP SYN connection burst originating from Laptop B (192.168.29.252) targeting port 8000 on host 192.168.29.93.",
    },
    {
      id: "REP-2026-002",
      incidentId: "INC-1022",
      title: "DDoS Volumetric Scrubbing Report",
      attackType: "DDoS",
      severity: "CRITICAL" as const,
      generatedDate: "Today, 12:40 PM",
      analyst: "Network Defense Team",
      summary: "Distributed denial of service scrubbed via edge rate limiting and geo-fencing.",
    },
    {
      id: "REP-2026-003",
      incidentId: "INC-1018",
      title: "Port Scan & Probe Assessment",
      attackType: "Port Scan",
      severity: "MEDIUM" as const,
      generatedDate: "Yesterday, 04:30 PM",
      analyst: "Threat Intel Analyst",
      summary: "Host discovery scan blocked at perimeter firewall with zero data compromise.",
    },
  ],
  notifications: [
    { id: "notif-1", title: "Critical DoS SYN Flood from 192.168.29.252", time: "Just now", severity: "critical", read: false },
    { id: "notif-2", title: "Target port 8000 socket backlog defended", time: "2 minutes ago", severity: "high", read: false },
    { id: "notif-3", title: "AI investigation completed for INC-LIVE-10311117-C1FD68", time: "5 minutes ago", severity: "info", read: true },
    { id: "notif-4", title: "Evidence hash verified: telemetry_inc_live_10311117_c1fd68.json", time: "10 minutes ago", severity: "success", read: true },
  ],
};
