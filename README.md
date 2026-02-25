# AI SOC Zeek Pipeline

## Overview
AI-driven SOC pipeline that:
- Parses normalized Zeek logs
- Detects port scans and data exfiltration using time correlation
- Generates SOC alerts with automated response playbooks
- Builds a unified dataset for AI/ML clustering

## Features
- Time-window detection using ts
- Multi-log normalization (conn, dns, http → unified)
- Human-readable SOC playbooks
- SIEM-ready architecture

## Run
python3 ai_soc.py

## Future Work
- MITRE ATT&CK mapping
- K-Means clustering for anomaly detection
- Real-time log streaming
- SIEM integration
