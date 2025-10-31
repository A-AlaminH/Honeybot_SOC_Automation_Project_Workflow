[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)]([https://linkedin.com/in/your-profile])
[![Email](https://img.shields.io/badge/Email-Contact%20Me-green?logo=gmail&logoColor=white)](mailto:a.alaminhussain@proton.me)
[![Version](https://img.shields.io/badge/Version-1.0.0-brightyellow)](README.md)
# Honeybot SOC Automation Project (Wazuh SIEM + n8n + AbuseIPDB)

## Project Overview
---
<img width="1414" height="740" alt="Workflow Automation screenshot" src="https://github.com/user-attachments/assets/5f38c5bb-9118-4829-8eb0-3ab4358c5306" />

This personal cybersecurity project demonstrates a fully automated security response workflow by integrating Wazuh (security information and event management) with n8n (workflow automation) to detect, investigate, and respond to threats in real-time. The system identifies suspicious authentication attempts and RDP logins by correlating Wazuh alerts with threat intelligence data, automatically enriches them with AbuseIPDB reputation information, and triggers immediate containment actions including network isolation and multi-channel alerting.


```markdown

⚠️ Disclaimer

> This project is a proof-of-concept for educational use.  
> Not intended for production deployment.  
> Use responsibly and at your own risk.
```


---

## Prerequisites & Environment Requirements

### Infrastructure

- **Wazuh Server**: Wazuh 4.13.1 OVA (freely available from [Wazuh downloads](https://www.wazuh.com/downloads/))
- **Windows Agent Machine**: Windows Server 2022 VM with Wazuh agent installed
- **n8n Instance**: Self-hosted n8n ([installation guide](https://docs.n8n.io/hosting/installation/docker/))
- **Network Connectivity**: Both VMs on same network; if external access needed, configure public RDP port with VPN/bastion host

### Required External Services & Credentials

**Telegram Bot** (for alerts and de-isolation commands)
- Create bot via BotFather on Telegram
- Obtain: Bot Token, Chat ID

**Google Cloud Platform** (for threat data storage)
- Create Google Cloud project
- Enable Google Sheets API and Google Drive API
- Create Service Account with JSON key file
- Share the following sheets with service account email:
  - Threat Data sheet (for storing/updating compromised IPs)
  - IP Whitelist sheet (for approved IPs to bypass isolation)
- [Google Cloud setup guide](https://cloud.google.com/docs/authentication/application-default-credentials)

**AbuseIPDB** (for IP reputation lookup)
- Create account at [abuseipdb.com](https://www.abuseipdb.com/)
- Obtain API Key

**Slack** (optional, for team notifications)
- Create Slack workspace/app
- Generate Bot Token
- Obtain Channel ID

**ServiceNow** (optional, for incident management)
- Create ServiceNow developer instance
- Configure credentials for API access

**C-LiveResponse Isolation Module**
- Download from [C-LiveResponse GitHub](https://github.com/mitzep0x1/C-LiveResponse)
- Extract `isolation.exe` to `C:\Program Files\ossec-agent\active-response\bin\` on Windows Server 2022
- Executable will be invoked by active response rules

---

## Project Workflow Architecture

### Flow 1: Main Detection & Response (Triggered by Wazuh Alerts)

1. **Wazuh Alert Reception** → Alert triggers via webhook when Rule ID 60204 or 92653 detected
2. **Field Extraction** → Extract attacker IP, rule name, agent details, timestamp, severity, logon type
3. **AbuseIPDB Lookup** → Query attacker IP for reputation score and historical abuse reports
4. **Conditional Routing** (Switch Node):
   - **Rule 60204 (Multiple Failed Logins)**:
     - Query Threat Data sheet for existing IP records
     - Merge Wazuh alert + AbuseIPDB data using JavaScript node
     - Check if IP already exists in sheet (via "IP Already Exists" field)
     - **If exists** → Update existing row with new alert data
     - **If new** → Append new row to Threat Data sheet
   
   - **Rule 92653 (Successful RDP Login)**:
     - Check IP_Whitelist sheet for approved IPs
     - **If in whitelist** → Log and stop (no action needed)
     - **If not in whitelist**:
       - Request Wazuh JWT token via Wazuh API credentials
       - Send isolation command (`isolate`) to target agent
       - Alert Telegram bot with isolation details
       - Alert Slack channel
       - Create incident in ServiceNow

### Flow 2: De-isolation Response (Manual or Bot Trigger)

1. **Trigger Source**: Telegram bot receives `/release` command OR manual workflow trigger
2. **Verify Chat ID**: Confirm command from authorized user
3. **Obtain JWT Token** → Authenticate with Wazuh API
4. **Send Release Command** → Call Wazuh active response with `release` parameter
5. **Confirm Action** → Notify via Telegram, Slack, ServiceNow

### Flow 3: Scheduled Threat Report (Default: Every 4 Hours)

1. **Cron Trigger** → Fires on schedule
2. **Fetch Data** → Retrieve all rows from Threat Data sheet
3. **Format Report** → JavaScript node transforms data into readable summary (IP, attack count, highest severity, timestamps)
4. **Send Alerts** → Distribute formatted report to Telegram, Slack, ServiceNow

---

## Configuration & Setup

### 1. Wazuh Server Configuration

**File**: `/var/ossec/etc/ossec.conf` (on Wazuh manager)

Add the following n8n integrations to handle alerts:

```xml
<!-- n8n webhook integration for production alerts -->
<integration>
  <name>shuffle</name>
  <hook_url>http://YOUR_N8N_SERVER_IP:5678/webhook/wazuh-alerts</hook_url>
  <rule_id>60204,92653</rule_id>
  <alert_format>json</alert_format>
</integration>

<!-- n8n webhook integration for testing -->
<integration>
  <name>shuffle</name>
  <hook_url>http://YOUR_N8N_SERVER_IP:5678/webhook-test/wazuh-alerts</hook_url>
  <rule_id>60204,92653</rule_id>
  <alert_format>json</alert_format>
</integration>

<!-- Active Response command for network isolation -->
<command>
  <name>isolation</name>
  <executable>isolation.exe</executable>
  <timeout_allowed>no</timeout_allowed>
</command>
```

**Replace `YOUR_N8N_SERVER_IP`** with the IP address where n8n is running.

**Note on Detection Rules**: Rule IDs 60204 (Multiple authentication failures) and 92653 (Successful RDP login) are **built-in Wazuh rules** and require no custom configuration.

[Wazuh Manager Configuration Reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html)

### 2. Windows Server 2022 Agent Configuration

**File**: `C:\Program Files (x86)\ossec-agent\ossec.conf`

Ensure Windows EventLog monitoring is enabled:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventlog</log_format>
</localfile>
```

Verify agent is enrolled in Wazuh manager and showing "Active" status in Wazuh dashboard.

[Wazuh Windows Agent Guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)

### 3. n8n Workflow Configuration

Import the provided `Wazuh_Honeybot_Public.json` workflow into n8n:

1. Go to n8n dashboard → Click **Import** → Upload JSON file
2. Review and update the following nodes with your credentials/IDs:

#### Node: "AbuseIPDB Lookup"
- **Credential**: Select or create "Header Auth account"
- **Header**: Set `Key` field to your AbuseIPDB API Key
- Verify query parameters extract `attackerIP` from Wazuh alert correctly

#### Node: "Sheet Lookup" (Threat Data)
- **Service Account Credential**: Upload your Google Service Account JSON key
- **Document ID**: Set to your Threat Data Google Sheet ID
- **Sheet Name**: Select "Sheet1" (or your designated sheet)
- Verify column name for lookup: `attackerIP`

#### Node: "Update Row" (Threat Data)
- **Document ID**: Same Threat Data sheet ID
- **Sheet Name**: Same sheet
- Ensure all fields map to corresponding Google Sheet columns

#### Node: "Append Row" (Threat Data)
- **Document ID**: Same Threat Data sheet ID
- **Sheet Name**: Same sheet
- Map fields in order they appear in sheet header

#### Node: "Get row from Whitelist"
- **Document ID**: Set to your IP_Whitelist Google Sheet ID
- **Sheet Name**: Select sheet containing whitelist
- Lookup column: `attackerIP`

#### Node: "Wazuh JWT Token"
- **URL**: `http://YOUR_WAZUH_SERVER_IP:55000/security/user/authenticate`
- **Headers**:
  - `Content-Type: application/json`
  - `Authorization: Basic YOUR_BASE64_ENCODED_CREDENTIALS`
- **Body**: Include Wazuh API credentials

#### Node: "Isolation Request"
- **URL**: `http://YOUR_WAZUH_SERVER_IP:55000/active-response?agents_list=AGENT_ID`
- Extract JWT token from previous node
- Pass `command=isolate` or `command=release` based on flow

#### Node: "Alert Telegram"
- **Bot Token**: Your Telegram bot token
- **Chat ID**: Your personal Telegram chat ID to receive alerts
  - To find your Chat ID:
    1. Send any message to your bot
    2. Call: `https://api.telegram.org/botYOUR_BOT_TOKEN/getUpdates`
    3. Extract `chat.id` from response JSON

#### Node: "Bot De-isolation Trigger"
- **Bot Token**: Same as above
- **Allowed Chat ID**: Restrict trigger to your Chat ID only
- Configure `/release` command parameters

#### Node: "Slack Notification"
- **Credential**: Create Slack app with bot token
- **Channel**: Set to target Slack channel ID
- Message formatting configurable in node

#### Node: "ServiceNow Incident"
- **Credential**: ServiceNow instance URL, username, password
- **Table Name**: `incident`
- Map fields: short_description, description, priority, assignment_group

#### Node: "Scheduled Report"
- **Cron Expression**: Default `0 */4 * * *` (every 4 hours)
- Modify cron pattern as needed ([cron reference](https://crontab.guru/))

---

## Technical Skills Demonstrated

This project showcases the following SOC Level 1 and Level 2 competencies:

- **SIEM Administration**: Configuring Wazuh server, agent deployment, rule tuning, alert ingestion
- **Threat Intelligence Integration**: Leveraging external threat databases (AbuseIPDB) for IP reputation scoring
- **Workflow Automation**: Designing and implementing multi-stage alert response processes with n8n
- **API Integration**: Authentication (JWT), HTTP requests, webhook handling, third-party service connectivity
- **Data Management**: Google Sheets integration for persistent threat tracking, data normalization, deduplication
- **Incident Response**: Automated containment (network isolation), alerting, escalation workflows
- **Scripting**: JavaScript for data transformation, merging heterogeneous data sources, conditional logic
- **Communication**: Multi-channel notifications (Telegram, Slack, ServiceNow) for cross-team visibility
- **Active Response**: Endpoint isolation/remediation using C-LiveResponse module
- **Security Best Practices**: Credential management, role-based access, audit trails, data retention policies

---

## Installation & Deployment Guide

### Step 1: Deploy Virtual Machines

- Download Wazuh 4.13.1 OVA from [Wazuh downloads](https://www.wazuh.com/downloads/)
- Deploy via VMware/VirtualBox
- Deploy Windows Server 2022 VM on same network
- Note IP addresses for both VMs

### Step 2: Install & Configure Wazuh Agent

On Windows Server 2022:
1. Download Wazuh agent installer from manager: `https://WAZUH_SERVER_IP/downloads/`
2. Run installer with agent enrollment
3. Start agent service: `net start wazuhsvc`
4. Verify agent status in Wazuh dashboard

### Step 3: Deploy n8n

Using Docker (recommended):

```bash
docker run -it --rm \
  -p 5678:5678 \
  -v n8n_data:/home/node/.n8n \
  n8nio/n8n
```

Or follow [n8n self-hosted guide](https://docs.n8n.io/hosting/installation/docker/)

### Step 4: Configure Google Cloud & ServiceAccount

1. Create GCP project at [console.cloud.google.com](https://console.cloud.google.com)
2. Enable APIs: Google Sheets API, Google Drive API
3. Create Service Account, download JSON key
4. Create Threat Data and IP_Whitelist Google Sheets
5. Share both sheets with service account email (format: `SERVICE_ACCOUNT@PROJECT.iam.gserviceaccount.com`)

### Step 5: Import n8n Workflow

1. In n8n, click **Import** → Select `Wazuh_Honeybot_Public.json`
2. Configure credentials as outlined in "Configuration & Setup" section
3. Test webhook connections
4. Activate workflow

### Step 6: Deploy Isolation Module

On Windows Server 2022:

1. Download [C-LiveResponse repository](https://github.com/mitzep0x1/C-LiveResponse)
2. Extract `isolation.exe` to: `C:\Program Files\ossec-agent\active-response\bin\`
3. Verify permissions: isolation.exe should be executable by SYSTEM account
4. Verify Wazuh active response can invoke: `"C:\Program Files\ossec-agent\active-response\bin\isolation.exe"`

[C-LiveResponse Documentation](https://github.com/mitzep0x1/C-LiveResponse/blob/main/docs/endpoint/isolation.md)

### Step 7: Update Wazuh Configuration & Test

1. Update `/var/ossec/etc/ossec.conf` with n8n webhook URLs (use IP from Step 3)
2. Restart Wazuh manager: `systemctl restart wazuh-manager`
3. Test alert delivery: Generate failed login attempts on Windows Server
4. Monitor n8n execution for successful webhook delivery

---

## Screenshots 
<img width="1440" height="660" alt="piechart" src="https://github.com/user-attachments/assets/0f4be106-39b1-4213-a861-78e5e278cf47" />
<img width="671" height="680" alt="telegram alert" src="https://github.com/user-attachments/assets/fc9d4111-a86f-4ab7-9062-82d9a6a97440" />
<img width="673" height="664" alt="telegram report" src="https://github.com/user-attachments/assets/820d9e87-8e6d-4dde-acab-0dd5c9cae89e" />
<img width="1440" height="660" alt="piechart" src="https://github.com/user-attachments/assets/8b7bba8e-a158-4955-8f13-485bb6ba1502" />


---

## Stuck? Check These Resources

**Official Documentation:**
- [Wazuh User Manual](https://documentation.wazuh.com/current/index.html)
- [Wazuh Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)
- [n8n Documentation](https://docs.n8n.io/)
- [n8n Community](https://community.n8n.io/)

**API References:**
- [AbuseIPDB API Docs](https://docs.abuseipdb.com/)
- [Google Sheets API](https://developers.google.com/sheets/api)
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [Slack API](https://api.slack.com/)
- [ServiceNow REST API](https://developer.servicenow.com/dev.do#!/reference/api/tokyo/rest)

**Security & Best Practices:**
- [NIST Incident Response Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [Wazuh Security Hardening](https://documentation.wazuh.com/current/deployment-options/docker/container-hardening.html)
- [n8n Security Practices](https://docs.n8n.io/hosting/configuration/security/)

**Troubleshooting:**
- Webhook not receiving alerts? Verify firewall allows port 5678 and n8n server IP in ossec.conf matches actual IP
- AbuseIPDB returning errors? Check API key in HTTP header auth credential and rate limits
- Google Sheets permission denied? Ensure service account email has Editor access to both sheets
- Isolation.exe not executing? Verify file permissions on Windows agent and Wazuh active response logs

---

## Repository Structure

```
wazuh-honeybot/
├── README.md                          # This file
├── workflows/
│   └── Wazuh_Honeybot_Public.json   # n8n workflow (sanitized, placeholders for IDs)
├── config/
│   ├── ossec.conf.sample             # Wazuh manager config snippet
│   └── windows-agent.conf.sample     # Windows agent config snippet
├── sheets/
│   ├── Threat_Data_Template.csv      # Template for Threat Data sheet
│   └── IP_Whitelist_Template.csv     # Template for IP Whitelist sheet
└── docs/
    └── SETUP.md                       # Detailed setup guide
```

---

## License

This project is provided as-is for educational purposes. Use at your own risk in your lab environment.

## Author Notes

Built as a personal security automation project to demonstrate SOC fundamentals including alert correlation, threat intelligence integration, and automated response orchestration. Feedback and improvements welcome!
