import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from rag_service import rag_service

print("Testing MITRE STIX Ingestion...")
res = rag_service.ingest_official_stix()
print("Ingestion result:", res)

queries = [
    "SSH brute force authentication password attempts",
    "Volumetric SYN flood network denial of service",
    "Port scan reconnaissance Nmap probe",
    "DNS tunneling command and control",
]

for q in queries:
    print(f"\nQuery: '{q}'")
    docs = rag_service.retrieve(q, top_k=2)
    for d in docs:
        tid = d.get("technique_id")
        tname = d.get("technique_name")
        sim = d.get("similarity_score")
        url = d.get("url")
        print(f"  -> [{tid}] {tname} (similarity: {sim}) | {url}")

print("\nRAG Health Stats:")
print(rag_service.get_health_stats())
