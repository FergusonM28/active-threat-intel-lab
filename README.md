# Active Threat Intel Lab
Hands-on CTI &amp; SOC lab that turns real, current cybersecurity threats into MITRE ATT&amp;CK-mapped detections, Splunk/KQL queries, and Tier 1 SOC investigation playbooks.

# SentinelForge: Active Threat Intelligence & SOC Detection Lab

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Focus](https://img.shields.io/badge/focus-SOC%20%7C%20CTI%20%7C%20Detection%20Engineering-blue)
![Tools](https://img.shields.io/badge/tools-Splunk%20%7C%20KQL%20%7C%20MITRE%20ATT%26CK-orange)
![License](https://img.shields.io/badge/license-Educational%2FResearch-lightgrey)

A hands-on Cyber Threat Intelligence (CTI) and Security Operations Center (SOC) lab where I track real, currently active cybersecurity threats and turn them into working detections, investigation playbooks, and incident response documentation.

This isn't a news clippings folder. Every entry answers one question:

> **"How would a SOC actually detect, investigate, and respond to this threat?"**

---

## Why This Project Exists

I built this lab to practice, and prove, the day-to-day skills of a SOC / Cybersecurity Analyst: reading threat intel, mapping attacker behavior to MITRE ATT&CK, writing detection logic in Splunk and KQL, and running a triage-to-containment investigation the way a Tier 1/2 analyst would in a live SOC. Everything here is built from publicly available threat reporting and documented in a repeatable, analyst-style format.

---

## Table of Contents

- [What This Project Demonstrates](#what-this-project-demonstrates)
- [Project Objectives](#project-objectives)
- [Threat Intelligence Sources](#threat-intelligence-sources)
- [Threat Landscape Dashboard](#threat-landscape-dashboard)
- [SOC Investigation Workflow](#soc-investigation-workflow)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Detection Engineering](#detection-engineering)
- [Example Investigation: Phishing Campaign](#example-investigation-phishing-campaign)
- [Repository Structure](#repository-structure)
- [Monthly Research Process](#monthly-research-process)
- [Skills Demonstrated](#skills-demonstrated)
- [Tools & Technologies](#tools--technologies)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)

---

## What This Project Demonstrates

- Ability to research and interpret real-world threat intelligence from trusted industry sources
- Ability to translate raw intel into actionable SIEM detection logic (Splunk + KQL)
- Understanding of attacker Tactics, Techniques, and Procedures (TTPs) mapped to MITRE ATT&CK
- A repeatable Tier 1 SOC analyst investigation workflow, from alert to containment
- Clear, analyst-grade technical documentation that a hiring manager or SOC lead can review

---

## Project Objectives

**Threat Intelligence**
- Track newly reported cybersecurity threats
- Research threat actors and campaigns
- Monitor actively exploited vulnerabilities
- Identify common attack vectors
- Collect and validate Indicators of Compromise (IOCs)
- Analyze attacker behavior and TTPs

**SOC Detection**
- Convert threat intelligence into detection opportunities
- Build Splunk searches
- Build KQL queries
- Identify relevant Windows/Sysmon events
- Identify authentication and network telemetry
- Map detections back to MITRE ATT&CK techniques

**Incident Investigation**

For selected threats, I simulate the full workflow of a Tier 1 SOC Analyst:

1. Alert received
2. Triage and validate
3. Determine scope
4. Investigate SIEM and endpoint telemetry
5. Identify malicious indicators
6. Contain the threat
7. Escalate when necessary
8. Document findings

---

## Threat Intelligence Sources

Research is based on publicly available intelligence from sources including:

- CISA
- MITRE ATT&CK
- Microsoft Threat Intelligence
- Mandiant
- CrowdStrike
- Palo Alto Networks Unit 42
- Cisco Talos
- Google Threat Intelligence
- FBI/CISA cybersecurity advisories
- Vendor security advisories
- CVE / NVD vulnerability data

Each threat entry cites its original source and publication date.

---

## Threat Landscape Dashboard

Every reporting period tracks threats across the following fields:

| Category | Tracked Information |
|---|---|
| Threat Actor | Group/campaign name |
| Threat Type | Ransomware, phishing, malware, etc. |
| Initial Access | Phishing, valid accounts, exploitation, etc. |
| Target | Industry/technology affected |
| MITRE ATT&CK | Relevant techniques |
| CVEs | Exploited vulnerabilities |
| IOCs | IPs, domains, hashes, URLs |
| Detection | SIEM/EDR detection opportunities |
| Mitigation | Recommended defensive actions |
| Source | Intelligence report |
| Date | Date reported/observed |

---

## SOC Investigation Workflow

Each selected threat is run through a structured investigation process:

**1. Triage & Validate**
- What triggered the alert?
- Which user/device is involved?
- What is the severity?
- Is the activity expected?
- Is the indicator linked to known malicious activity?

**2. Scope the Impact**
- How many users were affected?
- How many endpoints were affected?
- Were multiple IPs involved?
- Are there related alerts?

**3. Investigate**

Telemetry reviewed includes:
- Windows Event Logs
- Sysmon
- Authentication logs
- DNS logs
- Firewall logs
- VPN logs
- Proxy logs
- EDR
- Email security logs
- SIEM data

**4. Identify Indicators**
- Malicious IPs, domains, URLs
- File hashes
- Email addresses
- Suspicious processes and command-line activity
- User accounts and hostnames

**5. Containment**
- Disable or lock compromised accounts
- Revoke active sessions
- Reset credentials
- Block malicious IPs/domains
- Isolate affected endpoints
- Remove malicious email
- Escalate confirmed incidents

**6. Document & Escalate**
- Timeline
- Affected assets and accounts
- IOCs
- Investigation findings
- Actions taken
- Detection logic
- Recommended next steps

---

## MITRE ATT&CK Mapping

Observed activity is mapped to MITRE ATT&CK, for example:

| Tactic | Technique | Example |
|---|---|---|
| Initial Access | T1566.001 | Spearphishing Attachment |
| Initial Access | T1566.002 | Spearphishing Link |
| Persistence | T1053 | Scheduled Task/Job |
| Credential Access | T1056 | Input Capture |
| Credential Access | T1555 | Credentials from Password Stores |
| Defense Evasion | T1070 | Indicator Removal |
| Execution | T1059 | Command and Scripting Interpreter |
| Discovery | T1087 | Account Discovery |
| Lateral Movement | T1021 | Remote Services |
| Command & Control | T1071 | Web Protocols |

Techniques are determined from the behavior documented in each threat report, not assumed.

---

## Detection Engineering

The core of this project: converting threat intelligence into working SIEM detection logic.

**Example Splunk Detection: Brute Force / Password Spraying**

```spl
index=windows
(EventCode=4625 OR EventCode=4624)
| stats count values(src_ip) as source_ips
    by user
| where count >= 10
| sort - count
```

*Investigation Question:* Are there repeated failed authentication attempts that could indicate password spraying or brute-force activity?

**Example KQL Detection: Suspicious Sign-In Failures**

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts=count(),
            IPAddresses=make_set(IPAddress)
    by UserPrincipalName
| where FailedAttempts >= 10
| order by FailedAttempts desc
```

*Investigation Question:* Are users experiencing an unusual number of failed authentication attempts from potentially suspicious sources?

---

## Example Investigation: Phishing Campaign

**Scenario:** A threat intelligence report identifies a phishing campaign targeting corporate users. The SOC receives an alert for a suspicious email containing a credential-harvesting URL.

**Email Analysis**
- Review sender address and Reply-To mismatch
- Review email headers
- Check SPF/DKIM/DMARC
- Inspect URLs and attachments
- Check domain reputation

**Threat Intelligence Cross-Check**
- Domain and IP reputation lookups
- URL intelligence
- Compare against known campaign indicators and threat feeds

**SIEM Investigation**
- Other recipients of the email
- URL click activity
- Authentication activity, failed logins, impossible travel, MFA anomalies

**Endpoint Investigation**
- Browser activity
- Suspicious processes and PowerShell execution
- Credential-related activity and persistence mechanisms
- Additional network connections

**Response (if confirmed malicious)**
1. Remove the phishing email
2. Block malicious URLs/domains
3. Reset compromised credentials
4. Revoke active sessions
5. Investigate affected endpoints
6. Search for additional affected users
7. Escalate per incident response procedures

---

## Repository Structure

```
SentinelForge/
│
├── README.md
│
├── Threat-Reports/
│   ├── 2026-09/
│   │   ├── threat-01.md
│   │   ├── threat-02.md
│   │   └── threat-03.md
│   │
│   └── 2026-10/
│       └── ...
│
├── Detection-Rules/
│   ├── Splunk/
│   │   ├── brute-force.conf
│   │   ├── phishing.conf
│   │   └── suspicious-powershell.conf
│   │
│   └── KQL/
│       ├── authentication.kql
│       ├── phishing.kql
│       └── suspicious-process.kql
│
├── IOCs/
│   ├── IPs.csv
│   ├── Domains.csv
│   ├── Hashes.csv
│   └── URLs.csv
│
├── MITRE/
│   └── attack-mapping.md
│
├── Reports/
│   ├── Monthly-Threat-Landscape/
│   └── SOC-Investigation-Reports/
│
└── Screenshots/
    ├── Splunk/
    └── KQL/
```

---

## Monthly Research Process

1. **Research** newly reported threat actors, malware, ransomware campaigns, phishing campaigns, exploited vulnerabilities, cloud attacks, and credential attacks
2. **Analyze** attack vector, target, TTPs, MITRE ATT&CK techniques, IOCs, and potential business impact
3. **Detect** by building Splunk searches, KQL queries, IOC searches, and endpoint detection opportunities
4. **Investigate** using realistic SOC scenarios based on the threat
5. **Document** and publish a threat summary, investigation findings, detection logic, mitigations, and sources

---

## Skills Demonstrated

- Cyber Threat Intelligence (CTI)
- SOC Operations
- SIEM Investigation (Splunk, Microsoft Sentinel)
- KQL and SPL query writing
- Microsoft Defender concepts
- MITRE ATT&CK mapping
- IOC analysis
- Threat actor research
- Phishing analysis
- Authentication log analysis
- Windows Event Logs and Sysmon
- Incident response
- Detection engineering
- Threat hunting
- Security documentation and technical reporting

---

## Tools & Technologies

| Tool | Purpose |
|---|---|
| Splunk | SIEM investigation and detection |
| Microsoft Sentinel | Cloud SIEM / KQL investigations |
| Microsoft Defender | Endpoint/security telemetry |
| MITRE ATT&CK | TTP mapping |
| VirusTotal | IOC investigation |
| URLScan | URL analysis |
| Wireshark | Network traffic analysis |
| Sysmon | Windows endpoint telemetry |
| Python | Automation and data processing |
| GitHub | Documentation and version control |

---

## Roadmap

- [ ] Automated threat-feed ingestion
- [ ] Python-based IOC enrichment
- [ ] Automated MITRE ATT&CK mapping
- [ ] Splunk dashboards
- [ ] Microsoft Sentinel workbooks
- [ ] Automated CVE monitoring
- [ ] Threat-intelligence API integration
- [ ] IOC deduplication
- [ ] Threat severity categorization
- [ ] Monthly threat landscape reports
- [ ] Automated GitHub updates

---

## Disclaimer

This project is built for educational and defensive cybersecurity purposes only. Threat intelligence and IOCs evolve constantly, so indicators documented here should be validated against current intelligence before any production use. Any attack simulations referenced in this project are conducted strictly in controlled lab environments.

---

## About This Project

I maintain this lab to build and demonstrate practical SOC analyst skills by continuously connecting current, real-world cybersecurity threats to detection, investigation, and response work. It is updated on an ongoing basis as new threats, vulnerabilities, and defensive techniques emerge.

**Focus:** Threat Intelligence -> MITRE ATT&CK -> Detection -> Investigation -> Response
