# CIC-IDS2017 PCAP Provenance & Validation Record

- **Dataset**: Canadian Institute for Cybersecurity — Intrusion Detection Evaluation Dataset (CIC-IDS2017)
- **Source PCAP Path**: `C:\Users\lochk\Downloads\Tuesday-WorkingHours.pcap`
- **Source File Size**: 11,048,283,608 bytes (10.28 GB)
- **Source Format**: PCAP-NG (`\x0a\x0d\x0d\x0a`)
- **Activity Profile**: Tuesday Working Hours (FTP-Patator, SSH-Patator brute-force attacks and benign normal operations)

## Bounded Sample Details

- **Sample File Path**: `backend/ml/data/cicids2017_tuesday_sample.pcap`
- **Packet Count**: 2,000 genuine packets extracted sequentially from packet 0 to 1,999
- **Extraction Timestamp**: 2026-10-26T09:26:00Z
- **Output File Size**: 718,602 bytes
- **SHA-256 Checksum**: `27e0e62ae0bfc64cf1a9d9e7dafae1cd80be6f17c24d63d6ccd1cde1dd1a7003`
- **Integrity Notice**: Every packet in this sample was extracted directly from the genuine downloaded `Tuesday-WorkingHours.pcap`. It is NOT synthetic data.
- **Safety Boundary**: Created as a bounded offline extraction to allow reliable, non-exhaustive testing, flow validation, and regression verification without saturating RAM or disk I/O.
