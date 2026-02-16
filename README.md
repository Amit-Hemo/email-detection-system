# Email Detection System

A modular phishing detection system consisting of a **FastAPI backend** and a **Gmail Add-on**. It uses deterministic heuristic rules to identify suspicious emails and classify them as Safe, Suspicious, or Phishing.

## 🧠 Overview

The system is designed to provide real-time security insights directly within the Gmail interface. It parses email headers and body content, extracts key features (URLs, sender info, language patterns), and runs them through classification models, more on that below.

## 🚀 Quick Start

You can try the Email Detection System directly in your Gmail without setting up any local server. The Add-on is configured to use our **hosted production backend**.

### Prerequisites

- A Google Account (Gmail).

### Installation (Test Deployment)

1.  Go to [Google Apps Script](https://script.google.com/).
2.  Click **New Project**.
3.  Copy the content of `gmail_adds_on/Code.gs` into the script editor.
4.  Replace the `appsscript.json` file:
    - In the editor, go to **Project Settings** (gear icon).
    - Check "Show 'appsscript.json' manifest file in editor".
    - Copy the content of `gmail_adds_on/appsscript.json` into the editor.
5.  Click **Deploy** > **Test deployments**.
6.  Click **Install**.
7.  Open Gmail, click on any email, and you should see the **Email Detection System** blue box icon in the side panel.

> [!IMPORTANT]
> **Cold Start Delay**: The production API is hosted on Render's free tier. If the service hasn't been used recently, the first scan may take **30-60 seconds** to wake up the server. Subsequent scans will be nearly instantaneous. To avoid this, a background scheduled job is run every 14 minutes to keep the server warm. 
---

## 🧠 How the Detection Model Works

The detection engine (`HeuristicModel`) evaluates emails based on several categories of rules:

### 1. Header & Sender Analysis

- **Suspicious TLDs**: Detects senders from high-risk domains (e.g., `.ru`, `.xyz`, `.top`).
- **Display Name Mismatch**: Flags cases where the display name (e.g., "PayPal Support") contains an email address that doesn't match the actual sender address.

### 2. URL & Link Safety

- **IP-based URLs**: Flags links that use an IP address instead of a domain name (common in phishing).
- **Phishing Patterns**: Scans for known malicious keywords in URLs like `paypal-secure`, `apple-id-verify`, or `bank-login`.
- **Link Density**: Flags emails with an unusually high number of external links.

### 3. Content & Psychology

- **Urgency Keywords**: Detects pressure tactics using words like `urgent`, `verify account`, `locked`, and `unauthorized`.
- **Subject Analysis**: Flags subjects with excessive uppercase characters, often used in scam lures.

### 4. Classification Logic

- **Phishing**: Triggered by any **High Severity** rule failure.
- **Suspicious**: Triggered by **2 or more Medium Severity** rule failures.
- **Safe**: The default state when no significant threats are identified.

---

## 🏗️ Developer Guide & Local Setup

If you want to modify the detection logic or run your own instance of the API, follow these steps.

### Backend (FastAPI)

The backend is built with Python 3.12 and managed using `uv`.

**Local Setup:**

```bash
# Install dependencies
uv sync

# Run the API
uv run uvicorn api:app --app-dir src
```

**Docker Setup:**

```bash
docker compose up --build
```

The local API will be available at [http://localhost:8000](http://localhost:8000).

### CI/CD Pipeline

- **Linting & Formatting Checks**: via `ruff`.
- **Unit Testing**: via `pytest` to ensure core detection logic remains robust.
- **Dockerization**: Automatically builds and pushes a container image to the GitHub Container Registry (GHCR).
- **Auto-Deployment**: On every push to `main`, the system is automatically deployed to Render.

---

## 📋 API Documentation

Interactive API documentation (Swagger UI) is available at:

- **Local**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Production**: [https://email-detection-system-latest.onrender.com/docs](https://email-detection-system-latest.onrender.com/docs)

### `POST /api/v1/analyze`

Analyzes an email for phishing threats.

**Request Body:**

```json
{
  "subject": "Urgent: Action Required",
  "sender": "Security <security@verify-paypal.xyz>",
  "body": "Your account has been locked. Click here: http://192.168.1.1/login"
}
```

---

## ⚠️ Limitations & Future Improvements

### Current Limitations

- **Heuristics Only**: The current model is deterministic and can be bypassed by sophisticated attackers who avoid known patterns.
- **No Attachment Scanning**: Currently does not scan attachments for malware or macros.

### Roadmap

- [ ] **ML Integration**: Implement a Random Forest or BERT-based classifier for better detection of zero-day phishing.
- [ ] **Strengthen Heuristics**: Classification accuracy can be improved by adding more rules.
- [ ] **URL Sandboxing**: Integrate with an external service to check links in real-time.
- [ ] **Blocklist Sync**: Automatically sync with global domain blocklists.
- [ ] **Improved UI**: Add more detailed explanations of _why_ an email was flagged directly in the Gmail UI.
- [ ] **Cache**: Implement a cache to store results of previous scans.
- [ ] **Rate Limiting**: Implement rate limiting to prevent abuse.
