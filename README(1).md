# Sea Turtle APT — Threat Intelligence Report
### DNS Hijacking Campaign Analysis | MITRE ATT&CK Mapped | MISP Investigated

---

![Threat Level](https://img.shields.io/badge/Threat%20Level-HIGH-red?style=for-the-badge)
![Classification](https://img.shields.io/badge/Classification-TLP%3A%20WHITE-white?style=for-the-badge&labelColor=grey)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-G1041-blue?style=for-the-badge)
![MISP](https://img.shields.io/badge/MISP%20Event-1869-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active%20Threat-critical?style=for-the-badge)

---

## Table of Contents

- [Overview](#overview)
- [Threat Actor Profile](#threat-actor-profile)
- [Investigation Methodology](#investigation-methodology)
- [MITRE ATT&CK TTPs](#mitre-attck-ttps)
- [Indicators of Compromise](#indicators-of-compromise-iocs)
- [DNS Hijacking Kill Chain](#dns-hijacking-kill-chain)
- [Defensive Recommendations](#defensive-recommendations)
- [References](#references)
- [Author](#author)

---

## Overview

This repository contains a **threat intelligence executive report** profiling **Sea Turtle (APT-C-28)**, a state-sponsored Advanced Persistent Threat group conducting DNS hijacking campaigns against government, military, and intelligence organisations across the MENA region and beyond.

> **Important:** Sea Turtle attacks DNS infrastructure — not individual endpoints. This means traditional perimeter security controls (firewalls, IDS/IPS) are largely ineffective. The attack occurs *before* traffic ever reaches the target organisation.

### Key Findings at a Glance

| Field | Details |
|---|---|
| **Threat Actor** | Sea Turtle |
| **Also Known As** | Teal Kurma, Silicon, Cosmic Wolf, APT-C-28 |
| **Suspected Origin** | Turkey (state-nexus) |
| **Active Since** | 2017 (publicly disclosed April 2019) |
| **Threat Level** | HIGH |
| **Primary Motivation** | Espionage / Intelligence Collection |
| **Organisations Compromised** | 40+ across 13 countries |
| **MISP Event ID** | 1869 |
| **MITRE ATT&CK Group** | G1041 |

---

## Threat Actor Profile

Sea Turtle is a sophisticated, state-backed hacking group that specifically targets **DNS infrastructure** rather than attacking individual host systems. By compromising registrars, ISPs, and DNS providers, the group silently redirects legitimate traffic through actor-controlled Man-in-the-Middle (MITM) nodes to harvest credentials and intelligence.

### What Makes Sea Turtle Unique

- Attacks DNS infrastructure — not individual endpoints
- Silent interception — victims remain completely unaware
- Wide geographic reach — 40+ organisations across 13 countries
- Operational resilience — continued operations after public exposure in 2019
- State-backed — resources and protection beyond typical threat actors

### Geographic and Sector Targeting

**Regions:**

| Region | Countries |
|---|---|
| Middle East | Turkey, Iraq, Syria, Lebanon, Jordan, Kuwait, UAE, Saudi Arabia |
| North Africa | Egypt, Libya |
| Mediterranean | Greece, Cyprus |
| South Asia | Pakistan |

**Primary Target Sectors:**
- National Security and Intelligence Agencies
- Government Ministries and Departments
- Military Organisations
- Internet Service Providers (ISPs) and DNS Registrars
- Telecommunications Companies
- Energy and Oil & Gas Sector
- Think Tanks and Research Organisations

---

## Investigation Methodology

This intelligence profile was developed using a structured **MISP (Malware Information Sharing Platform)** investigation workflow.

```
MISP Event ID   : 1869
MISP Event UUID : 4b79f6b1-f69c-483b-9d24-6e20039f5e96
Source Event    : 187 (CUDESO, 2019-07-09)
Source UUID     : 5d26d766-5d64-4dc1-b8b2-0904c0a8ab16
IOC Count       : 15 verified indicators
TTP Count       : 9 MITRE ATT&CK techniques mapped
```

### Investigation Steps

| Step | Action | Outcome |
|---|---|---|
| 1 | Searched MISP for Sea Turtle IOCs | Discovered CUDESO feed (Event 187, dated 2019-07-09) |
| 2 | Created APT profile event (Event 1869) | Titled: *APT Profile — Sea Turtle DNS Hijacking Campaign* |
| 3 | Applied threat actor taxonomy | Tag: `misp-galaxy:threat-actor='Sea Turtle'` — Cluster ID 81836 |
| 4 | Merged verified IOCs | 15 IOCs from Event 187 merged via MISP merge functionality |
| 5 | Documented TTPs | 9 MITRE ATT&CK techniques linked via Galaxy relationships |
| 6 | Authored intelligence report | Structured report in MISP Event Reports module |
| 7 | Published and exported | Exported in **STIX 2 format** for community sharing |

---

## MITRE ATT&CK TTPs

All TTPs are mapped to [MITRE ATT&CK Group G1041](https://attack.mitre.org/groups/G1041/).

| ATT&CK ID | Technique | Tactic | Description |
|---|---|---|---|
| [T1557](https://attack.mitre.org/techniques/T1557/) | Adversary-in-the-Middle | Credential Access | Intercepts DNS traffic between victims and legitimate sites to steal credentials |
| [T1583.002](https://attack.mitre.org/techniques/T1583/002/) | DNS Server | Resource Development | Acquires rogue DNS servers to silently redirect victim traffic |
| [T1588.004](https://attack.mitre.org/techniques/T1588/004/) | Digital Certificates | Resource Development | Obtains valid SSL/TLS certs for actor-controlled domains to appear legitimate |
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | Initial Access | Exploits VPN and remote access services for initial access |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access | Exploits vulnerabilities in internet-facing systems |
| [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Archive via Utility | Collection | Compresses collected data before exfiltration |
| [T1070.002](https://attack.mitre.org/techniques/T1070/002/) | Clear Linux Logs | Defense Evasion | Removes intrusion evidence to hinder forensic investigation |
| [T1074.002](https://attack.mitre.org/techniques/T1074/002/) | Remote Data Staging | Collection | Stages collected data on compromised infrastructure before exfiltration |
| [T1114.001](https://attack.mitre.org/techniques/T1114/001/) | Local Email Collection | Collection | Collects emails from compromised mail servers for intelligence gathering |

---

## Indicators of Compromise (IOCs)

> All IOCs verified via **MISP Event 187** (Source: CUDESO, UUID: `5d26d766-5d64-4dc1-b8b2-0904c0a8ab16`). All indicators are flagged for IDS detection. Block immediately at perimeter firewall and DNS resolver level.

### Operational Node IP Addresses

| IP Address | Type | Role | Recommended Action |
|---|---|---|---|
| `185.64.105.100` | ip-dst | Primary attack coordination node | BLOCK + ALERT |
| `178.17.167.51` | ip-dst | Secondary attack coordination node | BLOCK + ALERT |
| `95.179.131.225` | ip-dst | MITM — Traffic interception server | BLOCK + ALERT |
| `140.82.58.253` | ip-dst | MITM — Traffic interception server | BLOCK + ALERT |
| `95.179.156.61` | ip-dst | MITM — Traffic interception server | BLOCK + ALERT |
| `196.29.187.100` | ip-dst | MITM — Traffic interception server | BLOCK + ALERT |
| `188.226.192.35` | ip-dst | MITM — Traffic interception server | BLOCK + ALERT |
| `45.32.100.62` | ip-dst | Hosted malicious nameserver | BLOCK + ALERT |

### Actor-Controlled DNS Infrastructure

| Hostname | Role | Recommended Action |
|---|---|---|
| `ns1.rootdnservers.com` | Actor-controlled rogue nameserver | BLOCK at DNS resolver + firewall |
| `ns2.rootdnservers.com` | Actor-controlled rogue nameserver | BLOCK at DNS resolver + firewall |
| `ns1.intersecdns.com` | Actor-controlled rogue nameserver | BLOCK at DNS resolver + firewall |
| `ns2.intersecdns.com` | Actor-controlled rogue nameserver | BLOCK at DNS resolver + firewall |

### SIEM Detection Queries (Splunk)

**Detect IOC IP addresses in network traffic:**
```spl
index=network sourcetype=firewall
dest_ip IN ("185.64.105.100","178.17.167.51","95.179.131.225","140.82.58.253",
            "95.179.156.61","196.29.187.100","188.226.192.35","45.32.100.62")
| table _time, src_ip, dest_ip, action
```

**Detect rogue DNS nameserver queries:**
```spl
index=dns sourcetype=dns
query IN ("rootdnservers.com","intersecdns.com")
| table _time, src_ip, query, answer
```

**Detect anomalous DNS A record changes:**
```spl
index=dns sourcetype=dns query_type=A
| stats count by query, answer
| where count < 3
| sort - count
```

---

## DNS Hijacking Kill Chain

Sea Turtle employs a sophisticated 7-stage kill chain. Understanding each stage is critical for detection and response planning.

```
+----+----------------------+--------------------------------------------+
|    | PHASE                | TECHNICAL ACTION                           |
+----+----------------------+--------------------------------------------+
| 1  | Reconnaissance       | Identify targets and their DNS registrars  |
| 2  | Initial Access       | Compromise registrar via exploits or       |
|    |                      | stolen credentials                         |
| 3  | DNS Modification     | Change DNS A records to actor-controlled   |
|    |                      | IP addresses                               |
| 4  | Cert Acquisition     | Obtain valid SSL/TLS certs to avoid        |
|    |                      | browser warnings                           |
| 5  | Traffic Interception | Victim traffic silently redirected through |
|    |                      | MITM nodes                                 |
| 6  | Credential Theft     | VPN, email and web app credentials         |
|    |                      | captured at MITM node                      |
| 7  | Restore Records      | DNS records quietly restored to avoid      |
|    |                      | detection and complicate forensics         |
+----+----------------------+--------------------------------------------+
```

> **Critical Note:** Traditional security controls (firewalls, IDS/IPS, endpoint security) are **ineffective** against DNS hijacking. The attack occurs at the infrastructure level — before traffic reaches the target organisation. Even organisations with strong internal security postures can be compromised through their DNS provider.

---

## Defensive Recommendations

### Immediate Actions (0-48 Hours)

- [ ] Block all identified IP addresses and DNS hostnames at perimeter firewall and DNS resolver level
- [ ] Ingest all 15 IOCs into SIEM, EDR, and IDS/IPS for immediate alerting
- [ ] Conduct emergency audit of DNS registrar account access — check for unauthorised changes
- [ ] Verify all DNS A records match expected values across all organisational domains
- [ ] Verify SSL/TLS certificates are issued by expected and trusted Certificate Authorities
- [ ] Deploy SIEM detection queries (see above) for immediate threat hunting

### Medium-Term Actions (1-4 Weeks)

- [ ] Enable MFA on all DNS registrar and hosting provider accounts
- [ ] Deploy automated DNS monitoring with alerting on any record changes
- [ ] Restrict access to DNS management portals — implement least privilege
- [ ] Implement Certificate Transparency log monitoring for unauthorised certificate issuance
- [ ] Conduct full threat hunt using IOCs across network logs, SIEM, and EDR telemetry
- [ ] Establish emergency response relationship with DNS registrar

### Long-Term Strategic Actions

- [ ] Implement DNSSEC on all organisational domains
- [ ] Develop and test a DNS hijacking-specific incident response playbook
- [ ] Conduct regular tabletop exercises simulating DNS hijacking scenarios
- [ ] Join threat intelligence sharing communities (MISP, ISACs)
- [ ] Include DNS provider security posture in vendor risk assessment programme
- [ ] Monitor Certificate Transparency via [crt.sh](https://crt.sh) or equivalent

---

## References

| Source | Reference |
|---|---|
| Cisco Talos | [DNS Hijacking Abuses Trust In Core Internet Service (April 2019)](https://blog.talosintelligence.com/2019/04/sea-turtle-cyberspionage/) |
| Cisco Talos | [Sea Turtle Keeps on Swimming, Finds New Victims (July 2019)](https://blog.talosintelligence.com/2019/07/sea-turtle-keeps-on-swimming.html) |
| MITRE ATT&CK | [Group G1041 — Sea Turtle](https://attack.mitre.org/groups/G1041/) |
| MISP Project | Threat Actor Galaxy — Sea Turtle Cluster ID 81836 |
| MISP Event 187 | Sea Turtle IOCs (Source: CUDESO, 2019-07-09) |
| FBI / CISA | Advisory on DNS Infrastructure Tampering |

---

## Author

**Philip Ufuah**
ISC2 CC Cybersecurity SOC Analyst | AMDARI
February 24, 2026

---

## Disclaimer

This report was produced using verified threat intelligence data from authoritative public sources including MISP, Cisco Talos, MITRE ATT&CK, the FBI, and CISA. All IOCs have been validated against known Sea Turtle infrastructure. Recipients are encouraged to integrate the provided IOCs into their security monitoring tools and share relevant sightings back to the intelligence community.

This document is classified **TLP: WHITE** — unrestricted distribution is permitted.
