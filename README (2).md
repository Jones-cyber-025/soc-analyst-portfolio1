# Detection Engineering — T1059.001: Command and Scripting Interpreter (PowerShell)

| | |
|---|---|
| **Technique** | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| **Tactic** | Execution |
| **Tools** | Sysmon, Wazuh SIEM, Atomic Red Team |
| **Environment** | Home lab — Windows 10 endpoint, Wazuh manager |
| **Analyst** | Odo Ikenna Jones |
| **Status** | Detection live and validated (rule 100130) |

> A PDF version of this write-up is included: [`T1059_PowerShell_Detection_Writeup.pdf`](T1059_PowerShell_Detection_Writeup.pdf)

---

## Objective

Detect adversarial use of PowerShell for command execution — a technique heavily abused in
real-world intrusions for payload execution, credential-theft tooling (e.g. Mimikatz), and
living-off-the-land attacks.

---

## Detection logic

A custom Wazuh rule flags any process creation event where the process image is
`powershell.exe`, based on Sysmon Event ID 1 telemetry.

```xml
<group name="mitre,t1059,execution">
  <rule id="100130" level="5">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell.exe</field>
    <description>T1059 PowerShell execution detected</description>
    <mitre><id>T1059</id></mitre>
  </rule>
</group>
```

Full rule file: [`rules/local_rules.xml`](rules/local_rules.xml)

---

## Challenges & troubleshooting

### 1. Sysmon wasn't logging process creation at all

Initial testing showed zero Event ID 1 hits in Wazuh despite PowerShell running successfully
on the monitored endpoint. Inspecting the live Sysmon configuration confirmed the gap:

```powershell
sysmon64 -c | Select-String -Pattern "ProcessCreate" -Context 0,5
```

No `ProcessCreate` block existed in the active config — Sysmon was only capturing file
creation (Event ID 11) and DNS query filtering events. Resolved by deploying a configuration
that explicitly enables process creation logging:

```powershell
sysmon64 -c C:\add-processcreate.xml
```

Verified the fix by confirming `data.win.system.eventID: 1` events began appearing in
Wazuh Discover.

### 2. Rule group mismatch

After enabling Event ID 1 logging, the custom rule still did not fire. Inspecting a raw
Event ID 1 hit in Wazuh Discover revealed the actual decoder-assigned rule group was
`sysmon_eid1_detections`, not `sysmon_event1` as initially assumed. Correcting the
`<if_group>` value resolved the mismatch and allowed rule 100130 to fire as expected.

---

## Validation

Atomic Red Team was used to simulate real PowerShell-based execution on the monitored endpoint:

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

Detection confirmed by querying Wazuh Discover for `rule.id: 100130`:

| Field | Value |
|---|---|
| `rule.id` | 100130 |
| `rule.groups` | mitre, t1059, execution |
| `rule.mitre.id` | T1059 |
| `rule.mitre.tactic` | Execution |
| `rule.mitre.technique` | Command and Scripting Interpreter |

---

## Evidence

**Wazuh Discover — rule.id 100130 returning no results (pre-fix)**

![Wazuh Discover returning no results](screenshots/01-wazuh-no-results-prefix.png)

*Figure 1. Initial query against the custom rule returned no hits, prompting investigation
into the telemetry pipeline.*

**Sysmon config missing ProcessCreate logging**

![Sysmon config missing ProcessCreate](screenshots/02-sysmon-missing-processcreate.png)

*Figure 2. Searching the live Sysmon configuration for a ProcessCreate block returned nothing,
confirming Event ID 1 was never being generated.*

**Sysmon configuration updated successfully**

![Sysmon configuration updated](screenshots/03-sysmon-config-updated.png)

*Figure 3. Applying a corrected Sysmon configuration file enabling ProcessCreate logging.*

**Event ID 1 now reaching Wazuh**

![Event ID 1 in Wazuh](screenshots/04-eventid1-reaching-wazuh.png)

*Figure 4. After the Sysmon fix, Process Create (Event ID 1) events began appearing in Wazuh.*

**Root cause of rule mismatch identified**

![Rule group mismatch](screenshots/05-rule-group-mismatch.png)

*Figure 5. Inspecting a raw Event ID 1 hit revealed the actual rule group was
`sysmon_eid1_detections`, not `sysmon_event1` as originally configured.*

**Successful detection — rule 100130 firing**

![Rule 100130 firing](screenshots/06-rule-100130-firing.png)

*Figure 6. After correcting the `if_group` value and restarting the Wazuh manager, rule 100130
fired successfully with correct MITRE ATT&CK mapping (T1059, Execution, Command and Scripting
Interpreter).*

---

## Key takeaway

Detection rules are only as good as the telemetry feeding them. A correctly written rule can
silently fail if the underlying data source isn't configured to emit the expected events —
always verify raw telemetry before assuming a rule's logic is at fault.

---

## Tuning notes

Rule 100130 as written fires on **all** PowerShell process creation, which is intentionally
broad for lab validation and would be noisy in production. Production hardening would layer on
command-line context — encoded commands (`-enc`), download cradles, hidden window style,
unusual parent processes (Office, browsers) — and reserve the high-severity level for those.
