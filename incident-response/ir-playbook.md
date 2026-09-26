# Incident Response Playbook — Suspicious PowerShell Execution & Phishing-Initiated Execution

**Prepared by:** Odo Ikenna Jones
**Environment:** Home SOC Lab — Wazuh SIEM, Sysmon-instrumented Windows endpoint
**Framework:** Based on NIST SP 800-61 (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned)

## Purpose

This playbook defines the standard response procedure for two related incident types observed and validated in this SOC lab:

1. **Scenario A — Phishing-Initiated Execution** (an Office application spawning PowerShell as a result of a malicious attachment)
2. **Scenario B — Standalone Suspicious PowerShell Execution** (PowerShell activity detected with no confirmed phishing vector)

Both scenarios share the same underlying response lifecycle but differ in identification triggers and initial scoping questions, so each is documented separately below.

---

## 1. Preparation

**Tools required:**

- Wazuh Manager / Wazuh Discover (SIEM, alerting, log search)
- Sysmon (Event ID 1 – Process Creation, Event ID 3 – Network Connection, Event ID 11 – File Create)
- Wazuh File Integrity Monitoring (FIM)
- VirusTotal (hash and domain reputation lookups)
- Atomic Red Team (detection validation)
- CyberChef (command-line/Base64 decoding)

**Standing requirements:**

- Sysmon must be correctly configured to log Process Create events (see Lessons Learned — this has been a recurring failure point in this environment and should be the first thing verified during any investigation, not assumed).
- Detection rules must be validated against the correct `if_group` and telemetry source before relying on them in a live alert.

**Roles:**

- Tier 1 Analyst: initial triage, evidence gathering
- Escalation path: Incident Response lead (for confirmed malicious activity requiring containment decisions)

---

## 2. Identification

### Scenario A — Phishing-Initiated Execution

**Trigger:** An alert or manual review showing an Office application (WINWORD.EXE, EXCEL.EXE, OUTLOOK.EXE) as the **parent process** of `powershell.exe` or `cmd.exe`.

**Initial questions:**

- Is this parent-child relationship expected on this host? (Almost never — treat as high-confidence suspicious by default.)
- What is the full command line of the child process? Does it contain `-enc`, `-nop`, `-w hidden`, or other obfuscation/stealth flags?
- Can the originating email/attachment be located (sender, subject, attachment name/hash)?

**Reference case:** SOC-2026-001 (Simulated Phishing, .cmd Execution) — confirmed `powershell.exe → cmd.exe → invoice_attachment.cmd`, validated via Wazuh FIM (file creation) and Sysmon Event ID 1 (execution), correctly treating creation and execution as separate evidentiary questions.

### Scenario B — Standalone Suspicious PowerShell Execution

**Trigger:** A Wazuh/Sysmon alert showing `powershell.exe` execution with no known-legitimate parent process or business justification, and no confirmed phishing vector.

**Initial questions:**

- What is the parent process? (If it is also `powershell.exe`, confirm whether this is expected admin/scripting activity or a nested/relaunched shell — a pattern worth scrutiny.)
- What is the full command line? Does it read/write files, contact the network, or simply perform local actions?
- What is the process integrity level? (High integrity is a signal worth investigating, not proof of malicious intent on its own.)
- What is the SHA-256 hash of the PowerShell executable/script, and does it match a known-good baseline?

**Reference case:** SOC Malware Investigation Lab (Controlled PowerShell Simulation) — `powershell.exe` observed writing a local file via `Set-Content`, parent process also `powershell.exe`, High integrity, SHA-256 hash captured for reference. Investigation confirmed benign only after reviewing image path, command line, parent process, integrity level, and hash — not from the alert alone. Notably, a search for the corresponding Sysmon Event ID 11 (FileCreate) returned no result, demonstrating that telemetry completeness must be verified rather than assumed during identification.

---

## 3. Containment

**Short-term (both scenarios):**

- If command-line analysis reveals obfuscation (`-enc`), a download cradle (`IEX`, `DownloadString`, `Invoke-WebRequest` to an external IP), or any confirmed malicious indicator, isolate the host immediately via EDR/Wazuh active response or network isolation — do not wait to complete full analysis before containing an actively executing threat.
- If the activity is ambiguous (e.g., Scenario B with no immediately obvious malicious indicator), continue investigation before containment, but avoid closing the alert until command line, hash, and network activity have all been reviewed.

**Long-term:**

- Block confirmed malicious sending domains, IPs, or file hashes at the email gateway / firewall / EDR level.
- Preserve the host in its current state (no wipe/reimage) until evidence collection is complete, to maintain chain of custody.

---

## 4. Eradication

- Remove the malicious file/attachment and any dropped payloads.
- Terminate any still-running malicious processes.
- If credentials may have been exposed (e.g., in a phishing scenario with a credential-harvesting component), reset affected credentials.
- Confirm no persistence mechanism (scheduled task, registry run key, startup item) was established.

---

## 5. Recovery

- Restore the host to normal operation only after confirming no residual malicious artifacts remain.
- Re-enable normal user access.
- Monitor the host for a defined period post-incident for signs of reinfection or renewed C2 contact.

---

## 6. Lessons Learned

- **PowerShell is a legitimate administrative tool and must never be classified as malicious by name alone.** Classification must always be based on parent process, command line, and context — demonstrated directly in the Malware Investigation Lab, where PowerShell activity was correctly assessed as benign only after full review.
- **File creation and file execution are separate investigative questions requiring independent evidence** — confirmed in both SOC-2026-001 and the Malware Investigation Lab, where FIM alone was insufficient to prove execution, and Sysmon Event ID 1 alone was reviewed alongside it.
- **Telemetry availability must be verified, not assumed.** Both this playbook's Scenario B reference case (missing Event ID 11) and earlier detection engineering work (T1059 rule troubleshooting, where Sysmon was found not to be logging Process Create events at all) confirm that a "no results" search outcome can mean either "nothing happened" or "the telemetry wasn't collected" — these must be distinguished before drawing a conclusion.
- **High integrity level and elevated execution context are investigative signals, not proof of malicious intent.**
- **Correlate rather than triage alerts in isolation** — demonstrated in Case Report 2 (DNS Exfiltration), where two alerts were only understood as a single ongoing attack once correlated by process ID and destination domain.
- **MITRE ATT&CK mappings must be grounded in observed evidence**, and simulated or training activity must be clearly labeled as such, never presented as a genuine compromise.

---

## Appendix: MITRE ATT&CK Coverage

| Technique | Name | Scenario |
|---|---|---|
| T1566.001 | Spearphishing Attachment | A |
| T1566.002 | Spearphishing Link | A |
| T1204.002 | User Execution: Malicious File | A |
| T1059.001 | PowerShell | A, B |
| T1059.003 | Windows Command Shell | A |
