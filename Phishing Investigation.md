# 🎣 Phishing Email Investigation — SOC-2026-001

**Role:** Junior / L1 SOC Analyst  
**Environment:** Windows + Sysmon + Wazuh  
**Classification:** Benign controlled security simulation

## Overview

This project demonstrates an end-to-end SOC investigation of a simulated phishing scenario.

**Investigation chain:**

`Phishing Email → Attachment → File Creation → Execution → Sysmon → Wazuh → MITRE ATT&CK → SOC Verdict`

No real malware or real compromise was involved. All activity was intentionally generated in a controlled lab.

## Objectives

- Investigate a simulated phishing email
- Hash and identify artifacts
- Investigate a simulated attachment
- Confirm file creation
- Determine whether the attachment was executed
- Analyze process and parent/child relationships
- Correlate Wazuh and Sysmon telemetry
- Map observed behavior to MITRE ATT&CK
- Produce a professional SOC disposition

## Lab Tools

| Tool | Purpose |
|---|---|
| Windows | Investigation endpoint |
| Sysmon | Process creation telemetry |
| Wazuh Agent | Endpoint telemetry |
| Wazuh Manager / Discover | Centralized investigation |
| PowerShell | Controlled lab activity |
| MITRE ATT&CK | Technique mapping |

## Investigation Flow

```text
Simulated Phishing Email
          ↓
   Simulated Attachment
          ↓
      File Creation
          ↓
     Wazuh FIM Alert
          ↓
   Deliberate Execution
          ↓
   Sysmon Event ID 1
          ↓
   Process Correlation
          ↓
     Wazuh Discover
          ↓
   MITRE ATT&CK Mapping
          ↓
     SOC Disposition
```

## Key Evidence

### 1. Simulated phishing email

```text
C:\SOC-Lab\phishing-email.txt
```

SHA-256:

```text
D46BB1CB3A4CEF960C7D206B527563DD88F349FC984FEDEFCC32C30047345B5
```

The message was a controlled training artifact.

### 2. Simulated attachment

```text
C:\SOC-Lab\invoice_attachment.cmd
```

Wazuh File Integrity Monitoring detected creation of the simulated attachment.

**Important SOC distinction:** file creation does not automatically prove execution, so the investigation continued into process telemetry.

### 3. Execution evidence

Sysmon **Event ID 1 — Process Create** recorded `cmd.exe` with a command line containing:

```text
C:\SOC-Lab\invoice_attachment.cmd
```

This confirmed deliberate execution of the simulated attachment.

### 4. Process relationship

```text
powershell.exe
      |
      +-- cmd.exe
              |
              +-- invoice_attachment.cmd
```

The parent/child relationship provided useful endpoint context.

## MITRE ATT&CK Mapping

| Simulated / observed behavior | Technique |
|---|---|
| Phishing scenario | **T1566 — Phishing** |
| Simulated attachment | **T1566.001 — Spearphishing Attachment** |
| Simulated link | **T1566.002 — Spearphishing Link** |
| PowerShell activity | **T1059.001 — PowerShell** |
| `cmd.exe` activity | **T1059.003 — Windows Command Shell** |

These mappings describe the controlled behaviors observed in the lab and do not claim a real attacker compromise.

## SOC Analyst Assessment

### Was the file created?

**Yes.** Wazuh FIM confirmed creation of the simulated attachment.

### Was it executed?

**Yes.** Sysmon Event ID 1 recorded `cmd.exe` executing the `.cmd` file.

### What launched it?

**PowerShell** was identified as the parent process.

### Was the activity malicious?

**No malicious compromise was established.**

The activity was intentionally generated for training. No persistence, credential theft, lateral movement, or command-and-control activity was demonstrated.

## Configuration Finding

During the investigation, a duplicate Sysmon event-channel configuration was identified between the local Wazuh agent configuration and shared configuration.

This was treated as a **telemetry/configuration issue**, not evidence of compromise.

## SOC Workflow Demonstrated

```text
DETECT
  ↓
TRIAGE
  ↓
COLLECT EVIDENCE
  ↓
CORRELATE Wazuh + Sysmon
  ↓
VALIDATE EXECUTION
  ↓
MAP MITRE ATT&CK
  ↓
CLASSIFY
  ↓
DOCUMENT
```

## Skills Demonstrated

- Phishing alert triage
- Email artifact analysis
- SHA-256 hashing
- Windows endpoint investigation
- Wazuh SIEM investigation
- Wazuh File Integrity Monitoring
- Sysmon Event ID 1 analysis
- Process analysis
- Parent/child process analysis
- Command-line analysis
- Event correlation
- MITRE ATT&CK mapping
- Incident classification
- SOC documentation
- Detection/telemetry troubleshooting

## Evidence Screenshots

Place sanitized screenshots in the `evidence/` folder:

1. Phishing email
2. File hash
3. Wazuh FIM alert
4. Sysmon Event ID 1
5. Process relationship
6. Wazuh Discover correlation
7. Final verdict

**Before publishing:** remove your username, local IP addresses, computer name, and other personal identifiers.

## Final Verdict

**CASE CLOSED — BENIGN CONTROLLED PHISHING SIMULATION**

This project demonstrates a complete beginner-level SOC workflow:

**Detection → Triage → Evidence Collection → Correlation → Validation → MITRE ATT&CK → Classification → Documentation**
