# ThreatLens TIP 🛡️

<div align="center">

![ThreatLens](https://img.shields.io/badge/ThreatLens-TIP-00d4ff?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**An AI-Powered Threat Intelligence Platform built for automated SOC environments.**

*Part of the ThreatLens Security Automation Pipeline project.*

</div>

---

## 📌 Overview

ThreatLens TIP is a **proprietary Threat Intelligence Platform** that aggregates security intelligence from multiple sources into a single unified API. Designed to integrate seamlessly with n8n automation workflows and Wazuh SIEM as part of a full Security Operations Center (SOC) pipeline.

Instead of querying multiple threat intelligence APIs separately inside your automation workflow, ThreatLens TIP acts as a **single intelligence endpoint** — you send one request, and get a complete threat analysis back.

---

## 🏗️ Architecture

```
Wazuh SIEM (Alerts)
      ↓
n8n Automation Workflow
      ↓
ThreatLens TIP API ← You are here
      ↓        ↓        ↓
 Source 1   Source 2   Source 3   (+ Custom Sources)
      ↓
Unified Threat Response
      ↓
Severity Score + Recommendation
      ↓
Auto-Block / Investigate / Monitor
```

---

## ✨ Features

- 🔍 **IP & Domain Analysis** — Supports both IPv4 addresses and domain names
- 📊 **Full Raw API Results** — Returns complete unfiltered responses from all intelligence sources
- 🧮 **Severity Scoring** — Calculates threat score (0-100) and assigns LOW / MEDIUM / HIGH / CRITICAL
- 🚫 **Malicious DB** — Local blacklist that auto-blocks known bad targets instantly
- ⚡ **Auto-Block** — HIGH/CRITICAL targets automatically added to local blacklist
- 🔌 **Custom Sources** — Add any REST API as an intelligence source from the admin panel
- 🕵️ **Hidden Admin Panel** — Accessible only via secret URL parameter
- 📜 **Lookup History** — All queries logged with full results
- 🔗 **n8n Ready** — Single endpoint integration with any automation workflow
- 🎨 **Dark Dashboard** — Professional cybersecurity-themed UI

---

## 🚀 Quick Start

### Requirements
- Python 3.10+
- pip

### Windows (One Click)
```
Double-click setup.bat
```

### Manual
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Then open `frontend/index.html` in your browser.

---

## ⚙️ Configuration

### 1. Open Admin Panel
```
frontend/index.html?admin=threatlens2024
```

### 2. Add Your API Keys
Go to **API Keys** tab and enter your keys for the configured intelligence sources.

### 3. Add Custom Sources (Optional)
Go to **Custom Sources** tab:
- **Name**: Any label (e.g. GreyNoise)
- **Endpoint**: URL with `{ip}` or `{target}` placeholder
- **Header**: API key header name
- **API Key**: Your key

Example — GreyNoise:
```
Endpoint: https://api.greynoise.io/v3/community/{ip}
Header:   key
```

---

## 🔌 n8n Integration

In your n8n workflow, add an **HTTP Request** node:

```
Method:  POST
URL:     http://localhost:8000/analyze/ip
Body:    {"ip": "{{ $json.body.data.srcip }}"}
```

### Response Format
```json
{
  "target": "1.2.3.4",
  "type": "ip",
  "timestamp": "2026-01-01T00:00:00",
  "source": "ThreatLens Intelligence",
  "severity": "HIGH",
  "recommendation": "Block",
  "auto_blocked": true,
  "threat_score": 75,
  "indicators": ["5 malicious detections", "80% abuse confidence"],
  "network_info": {
    "country": "CN",
    "organization": "Example ISP",
    "open_ports": [22, 80, 443]
  },
  "virustotal": { ... },
  "abuseipdb": { ... },
  "shodan": { ... },
  "custom_sources": { ... }
}
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze/ip` | Analyze IP or Domain |
| `POST` | `/analyze/domain` | Alias for analyze/ip |
| `GET` | `/history` | Get all lookup history |
| `GET` | `/history/{id}` | Get detailed result by ID |
| `GET` | `/admin/settings` | Get API keys (admin only) |
| `POST` | `/admin/settings` | Save API keys (admin only) |
| `GET` | `/admin/sources` | List custom sources (admin only) |
| `POST` | `/admin/sources` | Add custom source (admin only) |
| `DELETE` | `/admin/sources/{id}` | Delete custom source (admin only) |
| `GET` | `/admin/malicious` | List blacklisted targets (admin only) |
| `POST` | `/admin/malicious` | Add to blacklist (admin only) |
| `DELETE` | `/admin/malicious/{id}` | Remove from blacklist (admin only) |

> Admin endpoints require `x-admin-key` header.

---

## 📁 Project Structure

```
threatlens-tip/
├── backend/
│   ├── main.py              # FastAPI server + all endpoints
│   └── requirements.txt     # Python dependencies
├── frontend/
│   └── index.html           # Full dashboard (HTML/CSS/JS)
├── setup.bat                # Windows one-click startup
└── README.md
```

---

## 🔒 Security Notes

- API keys are stored in a local SQLite database (`threatlens.db`) — never in code
- The `threatlens.db` file is excluded from git via `.gitignore`
- Admin panel is hidden and requires a secret URL parameter
- All admin API endpoints require a secret header key
- No API documentation exposed (`/docs` and `/redoc` disabled)

---

## 🧩 Part of ThreatLens SOC Pipeline

This TIP is one component of the full **ThreatLens Security Automation Pipeline**:

```
1. Ingestion     → Wazuh SIEM + EDR
2. Normalize     → n8n Code Node
3. Enrich        → ThreatLens TIP  ← This repo
4. AI Assess     → Claude AI
5. Decision      → IF Node (autoContain)
6. Response      → Block IP / Isolate Host / Revoke Tokens
7. Notify        → Slack SOC Alert + Jira Ticket
8. Report        → Google Sheets Audit Log
```

---

## 👥 Team

**ThreatLens** — University Security Automation Project

---

## 📄 License

MIT License — Free to use and modify.
