#  HTTP Log Analysis & Threat Detection Using Splunk

##  Project Overview
This project demonstrates how to analyze HTTP traffic using Splunk and Zeek-style JSON logs to detect anomalies, errors, and potential cyber threats.

It simulates real-world SOC (Security Operations Center) use cases for monitoring and investigating web traffic.

---

##  Objectives
- Ingest HTTP logs into Splunk
- Detect client-side (4xx) and server-side (5xx) errors
- Identify suspicious User-Agents and URIs
- Detect large file transfers (data exfiltration)
- Perform log analysis using SPL queries

---

##  Tools & Technologies
- Splunk Enterprise
- SPL (Search Processing Language)
- Zeek HTTP Logs (JSON)

---

##  Dataset Information
The dataset contains:
- Source IP (id.orig_h)
- Destination IP (id.resp_h)
- HTTP Method (GET, POST, etc.)
- URI (requested resource)
- Status Codes (200, 404, 500, etc.)
- User-Agent
- Response Body Length

Example log:{ "id.orig_h": "10.0.0.49", "uri": "/index.html", "status_code": 200 }

---

##  Implementation Steps

### 1. Data Ingestion
- Uploaded JSON logs into Splunk
- Configured Source Type: JSON
- Created index: http_lab

### 2. Verification
index=http_lab | head 5


---

##  SPL Queries

###  Top Active Source IPs
index=http_lab| stats count by id.orig_h| sort -count| head 10


###  Detect Server Errors (5xx)
index=http_lab status_code>=500 status_code<600| stats count as server_errors


###  Suspicious User Agents
index=http_lab user_agent IN ("sqlmap", "curl", "python-requests")| stats count by user_agent


###  Large File Transfers (>500KB)
index=http_lab resp_body_len>500000| table id.orig_h uri resp_body_len| sort -resp_body_len


---

##  Dashboard
Designed a Splunk dashboard to visualize:

- Top active IPs
- HTTP status trends
- Suspicious user agents
- Large file transfers

---

## Security Insights
- Detected automated tools like sqlmap and curl
- Identified abnormal HTTP behavior
- Observed potential data exfiltration patterns
- Detected suspicious access attempts

---

##  Project Files
- HTTP Project Report (PDF)
- HTTP Logs Dataset (JSON)

---

##  Future Enhancements
- Add alert rules for anomalies
- Integrate threat intelligence feeds
- Enhance dashboard visualization

---

##  Author
Shreedhar Teradal  
Aspiring Cybersecurity Analyst
