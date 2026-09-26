# SOC Analyst Portfolio — Odo Ikenna Jones

Security Operations Analyst · Detection Engineering · Alert Triage & Investigation

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ikenna%20Odo-0A66C2?logo=linkedin&logoColor=white)](https://linkedin.com/in/ikenna-odo-2101a6333/)

Hands-on security operations work from a self-built home lab: writing and validating
detection rules against MITRE ATT&CK techniques, and triaging alerts end-to-end the way
a Tier 1/Tier 2 analyst would — alert to evidence to verdict to recommendation.

Everything here is my own work, reproduced from lab telemetry. No production or client data.

---

## What's in this repository

| Project | What it demonstrates |
|---|---|
| [**Detection Engineering — T1059.001 PowerShell**](detection-engineering/T1059-powershell/) | Writing a custom Wazuh rule against Sysmon telemetry, troubleshooting a silent detection failure, and validating with Atomic Red Team |
| [**SOC Case Reports**](soc-case-reports/) | Full alert investigations: phishing triage and a correlated DNS exfiltration attack |

---

## Lab environment

| Component | Detail |
|---|---|
| SIEM | Wazuh (manager + Windows agent) |
| Endpoint telemetry | Sysmon (Windows 10) |
| Adversary emulation | Atomic Red Team |
| Framework | MITRE ATT&CK |
| Enrichment | VirusTotal, Base64 decoding, DNS/domain analysis |

---

## Skills evidenced

**Detection engineering** — custom rule authoring (Wazuh XML), decoder/rule-group mapping,
MITRE ATT&CK mapping, detection validation through adversary emulation, telemetry gap analysis.

**Alert triage & investigation** — parent/child process analysis, command-line analysis,
Base64 decoding, alert correlation across events by PID/host/domain, domain reputation checks,
phishing analysis (sender, content, technical indicators), verdict writing and containment
recommendations.

**Tooling** — Wazuh, Sysmon, Atomic Red Team, PowerShell, Windows Event Log, VirusTotal.

---

## Roadmap

Detection coverage is being built out technique by technique:

- [x] T1016 — System Network Configuration Discovery
- [x] T1059.001 — Command and Scripting Interpreter: PowerShell
- [ ] T1003 — OS Credential Dumping (in progress)
- [ ] T1082 — System Information Discovery

---

## Contact

**Odo Ikenna Jones** — Security Operations Analyst
LinkedIn: https://linkedin.com/in/ikenna-odo-2101a6333/
