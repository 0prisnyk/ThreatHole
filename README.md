# **ThreatHole**  
## **AI-assisted DNS Security Monitoring and Response using Pi-hole and Splunk**  
  
## Project Description  
**ThreatHole** is a research and educational cybersecurity project that transforms a home network into a **micro-SOC (Security Operations Center)** with elements of **SIEM, SOAR, and AI**.  
It integrates:  
* **Pi-hole** – DNS sinkhole and DNS logging sensor.  
* **Splunk Enterprise** – analytics, dashboards, alerts, and data enrichment.  
* **Splunk Universal Forwarder** – log collection from Pi-hole into Splunk.  
* **Threat Intelligence feeds** – PhishTank, URLhaus, Suspicious TLDs.  
* **Pi-hole API** – block/unblock domains and enable/disable filtering from Splunk.  
* **AI module (Ollama + LLM)** – Explain, Report, and Advise functions for SOC analysis.  
The project provides a complete **detect → triage → respond** workflow for DNS security monitoring.  
  
## Requirements  
* **Pi-hole** installed on Raspberry Pi (tested on Raspberry Pi 3b).  
* **Splunk Enterprise** (indexer & search head).  
* **Splunk Universal Forwarder** installed on Pi-hole host.  
* **Ollama** installed locally with an LLM model (e.g., **nous-hermes2:latest**).  
  
## Dashboard Structure  
The ThreatHole Splunk dashboard includes the following:  
* KPI metrics (single-value with trends): Total Queries, Allowed, Blocked, Clean, Suspicious, Malicious.
<img width="2542" height="280" alt="image" src="https://github.com/user-attachments/assets/7e6f8e36-ba55-404d-a30b-20ed3766fefe" />

* Statistical visualizations (pie & bar charts):  
    * Allowed vs Blocked  
    * Active Clients  
    * TI Statuses (Clean/Suspicious/Malicious)  
    * Query Types  
    * Reply Types  
    * TI statuses per Client (stacked bar)
 
<img width="2538" height="457" alt="image" src="https://github.com/user-attachments/assets/496a5103-8735-4f79-8b77-5b0b33ce3aa1" />
<img width="2537" height="465" alt="image" src="https://github.com/user-attachments/assets/bf28b392-62ad-41f8-9513-c5269d1cfa04" />

* Time-based charts:  
    * Timechart by TI statuses  
    * Timechart by Clients  
    * Anomaly Detection with drill-down (queries outside ±2σ).

<img width="2543" height="328" alt="image" src="https://github.com/user-attachments/assets/8d7231f5-f51f-433f-a713-d4cbae11a213" />
<img width="2537" height="474" alt="image" src="https://github.com/user-attachments/assets/4d28d8a5-2833-45b0-abb4-75af9aa79403" />

* Interesting Domains table: suspicious TLDs, malicious and suspicious domains by TI, blocked domains per client.

<img width="2539" height="604" alt="image" src="https://github.com/user-attachments/assets/0d234e1e-ae3e-4939-b1ef-f1a448ddcb07" />
  
* Detailed Logs table (color-coded).

<img width="2541" height="492" alt="image" src="https://github.com/user-attachments/assets/2b0c7651-f768-4a7e-b199-00db27ac17df" />

* Active Response controls: block/unblock domains, enable/disable Pi-hole, API response tables.

<img width="2535" height="363" alt="image" src="https://github.com/user-attachments/assets/6484c03d-476c-4f3a-8d14-3320401531ef" />

* Ask AI panel: Explain, Report, Advise with AI output table.

<img width="2538" height="485" alt="image" src="https://github.com/user-attachments/assets/6b802602-9c8d-4caf-9f41-969753eaf21f" />

## How to Reproduce  
### Step 1: Log Forwarding from Pi-hole  
1. Export script: create */opt/pihole_ftl_export.sh* on Raspberry Pi  
2. Make it executable  
3. Cron job (run every minute)  
4. Add Splunk Forwarder *inputs.conf* on Pi-hole *(/opt/splunkforwarder/etc/system/local/inputs.conf)*  
  
After that you should see raw events in Splunk.  
  
### Step 2: Field Extractions & Automatic Lookups  
1. Create a delimiter-based field extraction with source key “_raw” to extract fields:  
    * "timestamp"  
    * "type_id"  
    * "status_id"  
    * "client"  
    * "domain"  
    * "forward"  
    * "reply_type_id"  
    * "additional_info"  
2. Upload CSV lookup files into Splunk:  
    * *pihole_type.csv* → query types (A, AAAA, TXT…).  
    * *pihole_status.csv* → allowed/blocked status.  
    * *pihole_reply_type.csv* → reply type (NXDOMAIN, IP, CNAME).  
3. Configure Automatic Lookups in Splunk Web for sourcetype *pihole:ftl*.  
  
### Step 3: Calculated Fields  
Readable timestamp:  
* strftime(timestamp, "%Y-%m-%d %H:%M:%S")  
TLD extraction:  
* lower(replace(domain,"^.*(\\.[^\\.]+)$","\\1"))  
  
### **Step 4: Automatic TI Lookups**  
Upload lookup CSVs:  
* *TI_phishtank.csv*  
* *TI_urlhaus.csv*  
* *suspicious_TLDs.csv*  
Create automatic lookups:  
* pihole:ftl : LOOKUP-Automatic_TI_URLhaus: TI_URLhaus domain AS domain OUTPUTNEW in_TI_URLhaus  
* pihole:ftl : LOOKUP-Automatic_TI_phishtank: TI_phishtank domain AS domain OUTPUTNEW in_TI_phishtank  
* pihole:ftl : LOOKUP-Automatic_suspicious_TLDs: suspicious_TLDs tld AS tld OUTPUTNEW suspicious_TLD  
  
### Step 5: Event Types  
Create Event types based on TI lookups:  
* Clean: index=pihole sourcetype=pihole:ftl NOT (in_TI_phishtank="true" OR in_TI_URLhaus="true")  
* Suspicious: index=pihole sourcetype=pihole:ftl (in_TI_phishtank="true" AND NOT in_TI_URLhaus="true") OR (in_TI_URLhaus="true" AND NOT in_TI_phishtank="true")  
* Malicious: index=pihole sourcetype=pihole:ftl in_TI_phishtank="true" AND in_TI_URLhaus="true"  
  
### Step 6: Macro “*pihole_ftl*”  
Create macro for a cleaner searches:  
* *pihole_ftl*: index=pihole sourcetype=pihole:ftl | table timestamp type action status client domain forward reply_type eventtype suspicious_TLD  
  
### **Step 7: Import “threathole_pihole” App**  
Purpose: This app integrates Pi-hole Active Response into Splunk. It provides the **pihole** custom command, which communicates with the Pi-hole API. With it, you can:  
* Block domains (action=block domain=example.com).  
* Unblock domains.  
* Enable/disable Pi-hole filtering.  
* Get status from Pi-hole.  
Installation:  
1. Copy the provided folder *threathole_pihole *into Splunk’s app directory  
2. Restart Splunk  
3. The command “*| pihole*” will now be available in searches and dashboards.  
  
### **Step 8: Import “threathole_ai” App**  
Purpose: This app integrates AI SOC Assistant into Splunk. It provides the **ai** custom command, which connects to your local Ollama LLM. The command has three modes:  
* Explain → human-readable explanation of DNS logs.  
* Report → SOC report (summary, statistics, recommendations).  
* Advise → actionable recommendation (block/whitelist/investigate).  
Installation:  
1. Copy the provided folder *threathole_ai* into Splunk’s app directory  
2. Restart Splunk  
3. The command “*| ai*” will now be available in searches and dashboards.  
  
### **Step 9: Import Dashboard**  
1. Exported JSON  
	The dashboard JSON is saved in repo as *ThreatHole.json* (already built with all KPIs, charts, anomaly detection, active response, and AI panel).  
2. Import into Splunk Web  
    * Go to Splunk Web → Dashboards → Create New Dashboard → Import from JSON.  
    * Paste or upload the *ThreatHole.json*.  
    * Save.  
3. Result  
You’ll see a full interactive SOC-style dashboard with:  
    * KPI cards  
    * Charts and time-series  
    * Anomaly detection  
    * Interesting domains table  
    * Detailed logs  
    * Active response buttons  
    * AI assistant panel  
