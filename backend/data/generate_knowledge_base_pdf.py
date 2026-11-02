"""
Script to generate the authentic 5-page CyberSentinel-X Operational Knowledge Base PDF.
Includes standard operational guidance, section headings, and precise pagination.
"""

from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib import colors

data_dir = Path(__file__).resolve().parent
pdf_path = data_dir / "CyberSentinelX_RAG_Knowledge_Base_v1.pdf"

def generate_pdf():
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=12
    )
    h1_style = ParagraphStyle(
        'SecHeader',
        parent=styles['Heading2'],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1e3a8a'),
        spaceAfter=8,
        spaceBefore=12
    )
    body_style = ParagraphStyle(
        'SecBody',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#334155'),
        spaceAfter=8
    )
    bullet_style = ParagraphStyle(
        'BulletStyle',
        parent=styles['Normal'],
        fontSize=9.5,
        leading=13,
        leftIndent=15,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=4
    )

    story = []

    # PAGE 1: Section 1
    story.append(Paragraph("CYBERSENTINEL-X SECURITY OPERATIONS MANUAL", title_style))
    story.append(Paragraph("DOCUMENT VERSION: v1.0 | CLASSIFICATION: SOC OPERATIONAL GUIDANCE", body_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph("SECTION 1: FALSE-POSITIVE ANALYSIS & PROTOCOL DEVIATION HANDLING", h1_style))
    story.append(Paragraph("In modern enterprise networks, statistical anomaly detection engines frequently observe traffic patterns that diverge from baseline distributions without representing malicious adversarial intent. The CyberSentinel-X False-Positive Analysis Protocol establishes structured triage criteria to prevent alert fatigue.", body_style))
    story.append(Paragraph("<b>Key Protocol Deviation Vectors:</b>", body_style))
    story.append(Paragraph("• <b>RFC 2131 / RFC 3046 DHCP Option 82 Anomalies:</b> Relay agent information sub-options inserted by network switches or routers can trigger false-positive alerts if classified strictly against standard IP flow models. Such packets must be classified as Network Protocol Anomalies with severity LOW, rather than high-severity malicious exploit attempts.", bullet_style))
    story.append(Paragraph("• <b>Scheduled Enterprise Maintenance & Database Backups:</b> High-throughput intra-datacenter transfers (e.g., Veeam, rsync, NFS replication) routinely display sudden spikes in Flow Bytes/s and Total Length of Fwd Packets. SOC analysts must correlate alert timestamps against the enterprise change management calendar prior to initiating containment.", bullet_style))
    story.append(Paragraph("• <b>ML Confidence Score Interpretation:</b> Predictions returned by the Random Forest classifier with confidence below 80% or with high entropy across probability distributions must be tagged as 'EVALUATING' and cross-referenced with secondary telemetry before generating an automated incident report.", bullet_style))
    story.append(Paragraph("• <b>Asymmetric Routing & Straggler Packets:</b> TCP teardowns with delayed FIN-ACK packets following connection resets must be gracefully absorbed by the flow aggregator without spinning up duplicate flow records or false alarms.", bullet_style))
    story.append(PageBreak())

    # PAGE 2: Section 2
    story.append(Paragraph("SECTION 2: MACHINE LEARNING EXPLAINABILITY & FEATURE ATTRIBUTION", h1_style))
    story.append(Paragraph("CyberSentinel-X utilizes a validated Random Forest classifier trained on 70 statistical bidirectional flow features derived from the CIC-IDS2017 benchmark dataset. To maintain analytical transparency, every prediction is accompanied by both global feature importances and local flow feature attributions.", body_style))
    story.append(Paragraph("<b>Global Feature Hierarchy (Gini Importance Ranking):</b>", body_style))
    story.append(Paragraph("• <b>Destination Port (Rank 1, Importance: 0.0688):</b> Primary discriminator for service targeting, separating administrative ports (22 SSH, 21 FTP) under brute-force Patator campaigns from standard HTTP/HTTPS browsing.", bullet_style))
    story.append(Paragraph("• <b>Average Packet Size (Rank 2, Importance: 0.0668):</b> Distinguishes automated brute-force attempts with fixed payload sizes from variable interactive user sessions.", bullet_style))
    story.append(Paragraph("• <b>Init_Win_bytes_forward (Rank 3, Importance: 0.0656):</b> Reflects client TCP stack characteristics; unusual initial TCP window sizes frequently identify scripted attack tooling such as Hydra, Medusa, or custom python socket scripts.", bullet_style))
    story.append(Paragraph("• <b>Packet Length Variance (Rank 4, Importance: 0.0447):</b> High variance indicates mixed multi-stage transfers, while zero or near-zero variance indicates repetitive probe loops or SYN floods.", bullet_style))
    story.append(Paragraph("<b>Local Feature Attribution & Explainability Principles:</b>", body_style))
    story.append(Paragraph("Local attribution scores measure the contribution of observed flow features toward shifting model output away from the benign base rate. High attribution scores explain model rationale but do not prove attacker attribution or causal identity.", body_style))
    story.append(Paragraph("Analysts must review top contributing features alongside packet hex streams to verify that anomalies correspond to genuine malicious protocol headers rather than benign transmission artifacts.", body_style))
    story.append(PageBreak())

    # PAGE 3: Section 3
    story.append(Paragraph("SECTION 3: SOC INCIDENT RESPONSE LIFECYCLE & CONTAINMENT FRAMEWORK", h1_style))
    story.append(Paragraph("CyberSentinel-X aligns with the NIST SP 800-61 Rev. 2 Computer Security Incident Handling Guide across four primary phases: Preparation, Detection & Analysis, Containment, Eradication & Recovery, and Post-Incident Activity.", body_style))
    story.append(Paragraph("<b>Non-Destructive Containment Protocol:</b>", body_style))
    story.append(Paragraph("• <b>Analyst Approval Gate:</b> Autonomous systems must never unilaterally sever production connections, modify core routing tables, or block network subnets without verified human approval. All automated playbooks generate 'suggested' actions requiring explicit analyst confirmation.", bullet_style))
    story.append(Paragraph("• <b>Perimeter Firewall Rate-Limiting & DROP Rules:</b> For verified external brute-force source IPs (e.g. 185.73.21.10), analysts apply targeted ingress DROP rules at edge firewalls (iptables -I INPUT -s &lt;IP&gt; -j DROP) rather than wide subnet null-routing.", bullet_style))
    story.append(Paragraph("• <b>Target Host Isolation & Credential Revocation:</b> Internal hosts exhibiting post-exploitation lateral movement or C2 traffic must be logically isolated via VLAN quarantine. Associated session tokens and service accounts must be revoked immediately.", bullet_style))
    story.append(Paragraph("• <b>Recovery & Telemetry Validation:</b> Following eradication, target assets undergo continuous 24-hour enhanced monitoring to detect persistence mechanisms or secondary backdoors before full service restoration.", body_style))
    story.append(PageBreak())

    # PAGE 4: Section 4
    story.append(Paragraph("SECTION 4: FORENSIC EVIDENCE INTEGRITY & CRYPTOGRAPHIC CHAIN OF CUSTODY", h1_style))
    story.append(Paragraph("Digital evidence collected during network intrusion investigations must meet strict legal and technical standards for admissibility and non-repudiation. CyberSentinel-X implements an automated SHA-256 Forensic Evidence Ledger.", body_style))
    story.append(Paragraph("<b>Evidence Custody Standards:</b>", body_style))
    story.append(Paragraph("• <b>Cryptographic Hashing:</b> Every raw PCAP slice, authentication log snippet, and memory artifact is hashed with SHA-256 immediately upon disk capture and registered in the immutable catalog ledger.", bullet_style))
    story.append(Paragraph("• <b>Tamper Detection & Verification:</b> On-demand verification recalculates the SHA-256 byte digest across disk storage. Any modification of recorded bytes immediately flags the artifact status as 'TAMPERED', generating an urgent forensic violation alert.", bullet_style))
    story.append(Paragraph("• <b>Traceable Artifact Association:</b> Every alert and investigation report preserves direct foreign-key references to supporting evidence IDs (e.g., EV-001, EV-002), including file path, byte length, capture timestamp, and recording block.", bullet_style))
    story.append(Paragraph("• <b>Missing Evidence Handling:</b> If an evidentiary file is unlinked, renamed, or purged from storage, the system explicitly returns status 'MISSING' with a detailed explanation rather than fabricating missing bytes.", body_style))
    story.append(PageBreak())

    # PAGE 5: Section 5
    story.append(Paragraph("SECTION 5: LANGGRAPH AGENTIC SOC INVESTIGATION ARCHITECTURE", h1_style))
    story.append(Paragraph("The CyberSentinel-X investigation engine is powered by a deterministic, bounded LangGraph StateGraph comprising 9 specialized analytical nodes designed for evidence grounding and hallucination prevention.", body_style))
    story.append(Paragraph("<b>Graph Node Execution Sequence:</b>", body_style))
    story.append(Paragraph("1. <b>Validate Request:</b> Rejects malformed input, empty strings, and illegal parameter injections with schema-enforced HTTP 422 errors.", bullet_style))
    story.append(Paragraph("2. <b>Fetch Telemetry:</b> Pulls real alert records, packet counts, IP addresses, and correlated flows from SQLite.", bullet_style))
    story.append(Paragraph("3. <b>Gather Evidence:</b> Re-hashes associated forensic artifacts on disk to verify cryptographic SHA-256 chain of custody.", bullet_style))
    story.append(Paragraph("4. <b>Retrieve MITRE RAG:</b> Queries persistent ChromaDB to retrieve relevant Enterprise ATT&CK techniques, NIST playbooks, and Knowledge Base guidelines.", bullet_style))
    story.append(Paragraph("5. <b>Correlate Hypotheses:</b> Contrasts competing explanations: Adversary Campaign (high likelihood) vs Benign Protocol Variance (low likelihood).", bullet_style))
    story.append(Paragraph("6. <b>Calculate Risk:</b> Computes deterministic risk scores using the formula: 0.45 * ThreatSeverity + 0.35 * MLConfidence + 0.20 * AssetCriticality.", bullet_style))
    story.append(Paragraph("7. <b>Generate Recommendations:</b> Proposes actionable containment, isolation, forensic preservation, and hardening steps labeled as 'suggested'.", bullet_style))
    story.append(Paragraph("8. <b>Synthesize Findings:</b> Formulates structured executive summaries grounded in observed packet evidence and source citations.", bullet_style))
    story.append(Paragraph("9. <b>Persist Report:</b> Commits the final investigation record into the SQLite database for permanent audit compliance.", bullet_style))
    story.append(Paragraph("<b>Separation of Fact and Hypothesis:</b>", body_style))
    story.append(Paragraph("The agentic engine explicitly separates directly observed network facts (IPs, ports, packet counts, timestamps) from AI-generated hypotheses (attack motives, threat actor attribution, potential exfiltration). Unsupported claims without evidentiary backing are strictly barred from the final persisted report.", body_style))

    doc.build(story)
    print(f"Successfully generated PDF knowledge base at: {pdf_path} ({pdf_path.stat().st_size} bytes)")

if __name__ == "__main__":
    generate_pdf()
