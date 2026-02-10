# Phishing Email Investigation Lab

## Overview

This project simulates a SOC Level-1 phishing investigation workflow.  
A real phishing email sample was analyzed to identify malicious indicators, perform threat intelligence enrichment, classify the incident, and document response actions.

The objective is to demonstrate practical blue-team skills including email header analysis, IOC extraction, and incident reporting.

---

## Tools Used

- VirusTotal  
- AbuseIPDB  
- WHOIS  
- Manual Email Header Analysis  
- Text Editor  

---

## Investigation Workflow

1. Collected phishing email sample (.eml)
2. Extracted email headers and sender details
3. Identified phishing indicators
4. Extracted Indicators of Compromise (IOC)
5. Performed threat intelligence enrichment
6. Classified incident using MITRE ATT&CK
7. Created SOC-style incident report

---

## Key Findings

- SPF authentication failed
- Spoofed sender domain detected
- Reply-To address redirected to Gmail
- Russian relay infrastructure identified
- Scam content requesting sensitive information
- Classified as Advance Fee Fraud (419 Scam)

---

## MITRE ATT&CK Mapping

- T1566 – Phishing

---

## Repository Structure
phishing-email-investigation/
├── README.md
├── setup-instructions.md
├── incident-report.md
├── header-analysis.txt
├── ioc.txt
├── threat-intel.txt
├── incident-classification.txt
└── screenshots/



---

## Skills Demonstrated

- Phishing Detection
- Email Header Analysis
- IOC Extraction
- Threat Intelligence
- Incident Classification
- SOC Documentation

---

## Author

Niladri Biswas  
Cyber Security Intern | SOC Analyst Trainee








