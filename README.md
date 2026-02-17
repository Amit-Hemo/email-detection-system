# Email Detection System

A modular phishing detection system combining **Machine Learning** and **Heuristic Rules** to provide intelligent email threat analysis. Features a **[FastAPI](https://fastapi.tiangolo.com/)** backend and **Gmail Add-on** that work together to classify emails as Safe, Suspicious, or Phishing in real-time.

## 🧠 Overview

The system provides real-time security insights directly within the Gmail interface using a **hybrid approach**:

1. **Machine Learning Model**: A TF-IDF + Logistic Regression classifier trained on 82,000+ emails (98% accuracy)
2. **Heuristic Rules**: Deterministic pattern matching for known phishing indicators
3. **Smart Resolver**: Intelligently combines both models for optimal detection

---

## 🚀 Quick Start (Gmail Add-on)

Try the Email Detection System directly in your Gmail - no setup required!

### Prerequisites

- A Google Account (Gmail)

### Installation

1. Go to [Google Apps Script](https://script.google.com/)
2. Click **New Project**
3. Copy the content of `gmail_adds_on/Code.gs` into the script editor
4. Replace the `appsscript.json` file:
   - In the editor, go to **Project Settings** (gear icon)
   - Check "Show 'appsscript.json' manifest file in editor"
   - Copy the content of `gmail_adds_on/appsscript.json` into the editor
5. Click **Deploy** > **Test deployments**
6. Click **Install**
7. Open Gmail, click on any email, and you should see the **Email Detection System** icon in the side panel

> [!IMPORTANT]
> **Cold Start Delay**: The production API is hosted on [Render's](https://render.com) free tier. If the service hasn't been used recently, it is because of a cold start, and the first scan may take **30-60 seconds** to wake up the server. Subsequent scans will be nearly instantaneous. However, you probably won't experience this issue since there is a background task that pings the API every 14 minutes to keep it warm.

---

## 🧠 How It Works

### The Hybrid Detection System

The system uses a **three-stage intelligent pipeline**:

```
Email Input → Feature Extraction → [ML Model + Heuristic Rules] → Smart Decision → Result
```

### Stage 1: Feature Extraction

Automatically extracts key information from emails:
- Sender details (email address, domain, display name)
- All URLs and links
- Subject line patterns
- Body content and language

### Stage 2: Dual Model Analysis

**Machine Learning Model**:
- Analyzes text patterns using trained AI
- Detects subtle phishing language and structure
- Trained on 82,486 emails - [Phishing Email Dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset/data?select=phishing_email.csv)
- 98% accuracy on test data
- For more details, read the research notebook [here](ml/notebooks/experiments.ipynb)

**Heuristic Rules Engine**:
- Checks for known red flags:
  - ⚠️ Suspicious domains (`.ru`, `.xyz`, `.top`, `.work`, etc.)
  - ⚠️ IP addresses in URLs instead of domain names
  - ⚠️ Sender name doesn't match email address
  - ⚠️ Urgent/threatening language ("account locked", "verify now")
  - ⚠️ Known phishing URL patterns
  - ⚠️ Excessive uppercase text or too many links

### Stage 3: Smart Decision Making

The **Hybrid Resolver** intelligently combines both models:

1. **Emergency Override**: If heuristics detect extreme danger (score ≥ 90%), immediately flag as PHISHING
2. **Balanced Decision**: Otherwise, combines both models (40% heuristics + 60% ML) for nuanced classification
3. **Graceful Fallback**: If ML model is unavailable, relies purely on heuristics

**Final Classification**:
- 🟢 **SAFE** (< 40% confidence): No significant threats detected
- 🟡 **SUSPICIOUS** (40-75% confidence): Some warning signs present
- 🔴 **PHISHING** (≥ 75% confidence): High likelihood of phishing attempt

---

## 📊 Example Results

### Example 1: Obvious Phishing Attack
```
Subject: URGENT ACTION REQUIRED
Sender: attacker@evil.ru
Body: Click: http://1.1.1.1/paypal-secure
```
**Result**: 🔴 **PHISHING** (90% confidence)
- Multiple critical red flags detected immediately

### Example 2: Subtle Phishing Attempt
```
Subject: Your account update
Sender: support@service-company.work
Body: We've updated our terms. Please verify your account.
```
**Result**: 🟡 **SUSPICIOUS** (64% confidence)
- ML model recognizes phishing language patterns
- Suspicious domain TLD

### Example 3: Legitimate Email
```
Subject: Meeting tomorrow
Sender: colleague@company.com
Body: Confirming our 2pm meeting to discuss the project.
```
**Result**: 🟢 **SAFE** (9% confidence)
- No red flags, normal communication pattern

---

## 🔧 API Usage

The system provides a REST API for programmatic access.

### Endpoint

**Production**: `https://email-detection-system-latest.onrender.com/api/v1/analyze`

**Local** (see Developer Setup below): `http://localhost:8000/api/v1/analyze`

### Request Example

```bash
curl -X POST https://email-detection-system-latest.onrender.com/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Urgent: Verify your account",
    "sender": "security@verify-paypal.xyz",
    "body": "Your account has been locked. Click here: http://192.168.1.1/login"
  }'
```

### Response Example

```json
{
  "classification": "Phishing",
  "confidence_score": 95.5
}
```

**Response Fields**:
- `classification`: `"Safe"`, `"Suspicious"`, or `"Phishing"`
- `confidence_score`: Percentage (0-100) - higher values indicate stronger confidence in phishing classification

### Interactive Documentation

Explore the API interactively:
- **Production**: [https://email-detection-system-latest.onrender.com/docs](https://email-detection-system-latest.onrender.com/docs)
- **Local**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 💻 Developer Setup

Want to modify the system or run your own instance?

### Local Development

**Requirements**: Python 3.12+

```bash
# Clone the repository
git clone https://github.com/Amit-Hemo/email-detection-system
cd email-detection-system

# Install dependencies (using uv)
uv sync

# Run the API server
uv run uvicorn api:app --app-dir src

# Run tests
uv run pytest tests/ -v
```

The API will be available at `http://localhost:8000`

### Docker Setup

```bash
# Build and run
docker compose up --build
```

### Testing

The system has comprehensive test coverage covering:
- Models (availability, preprocessing, classification)
- Hybrid resolver (edge cases, boundary conditions, model disagreements)
- End-to-end detection pipeline

```bash
uv run pytest tests/ -v
```

### CI/CD Pipeline

- **Linting checks**: Automated via [ruff](https://docs.astral.sh/ruff/)
- **Testing**: Automated via [pytest](https://pytest.org/)
- **Deployment**: Auto-deploys to [Render](https://render.com/) on push to `main`

---

## 📈 Performance & Accuracy

### ML Model Metrics
- **Accuracy**: 98%
- **Precision**: 98%
- **Recall**: 98%
- **Training Dataset**: 82,486 emails (balanced)
- **Model**: TF-IDF vectorization + Logistic Regression

### System Performance
- **Response Time**: < 100ms (typical)
- **Model Inference**: < 50ms
- **Reliability**: Graceful fallback if ML unavailable

---

## ⚠️ Limitations

- **Training Data**: ML model trained on older emails, may not catch all modern phishing techniques
- **No Attachment Scanning**: Does not analyze email attachments
- **Static Weights**: Resolver uses fixed weights (could be dynamically adjusted)
- **Limited URL Analysis**: No real-time URL reputation/sandboxing checks

---

## 🗺️ Roadmap

- [ ] Advanced ML models (BERT, DistilBERT) for better context understanding
- [ ] Adaptive weights based on confidence levels
- [ ] Real-time URL sandboxing integration
- [ ] Domain blocklist synchronization
- [ ] Attachment scanning support
- [ ] Enhanced Gmail UI with detailed threat explanations
- [ ] Performance optimization with caching
- [ ] API rate limiting

---

## 🛠️ Built With

- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [scikit-learn](https://scikit-learn.org/) - Machine learning library
- [Pydantic](https://docs.pydantic.dev/) - Data validation
- [pytest](https://pytest.org/) - Testing framework
- [uv](https://docs.astral.sh/uv/) - Fast Python package manager
- [Render](https://render.com/) - Cloud deployment platform

---

## 📄 License

This project is open source and available for educational and research purposes.

---

## 🤝 Contributing

Contributions are welcome! Please ensure:
- All tests pass
- Code follows [ruff](https://docs.astral.sh/ruff/) style guidelines
- New features include tests
- Documentation is updated
