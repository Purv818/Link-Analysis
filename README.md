# AI Link Threat Analyzer

A production-ready, portfolio-quality web application that uses **Machine Learning** and **static URL feature analysis** to classify URLs as Safe, Suspicious, Phishing, or Malicious — and explains why.

---

## Problem Statement

Phishing and malicious URLs are the entry point for the majority of cyberattacks. Existing browser-based warnings rely on centralised blocklists that can be slow to update. This project demonstrates how a pure **feature-engineering + ML pipeline** can perform fast, offline, static threat assessment with explainable results — without ever visiting the target URL.

---

## Features

| Feature | Description |
|---|---|
| URL Scanner | Enter any URL and get an instant ML prediction |
| Risk Score | 0–100 numeric risk score with Low / Medium / High / Critical levels |
| Confidence | Model's confidence in its prediction (%) |
| Explainability | Plain-English explanation of why the URL was flagged |
| Dashboard | Aggregate statistics, charts, and recent scans |
| Scan History | Searchable, filterable paginated history |
| Batch Scanner | Scan up to 20 URLs at once |
| CSV Export | Download scan history as CSV |
| Premium Animations | Particle canvas, cinematic loader, result reveal, scroll animations |
| Feature Contributions | Model-internal importance scores per scan |
| Scan Details | Full feature breakdown for each historical scan |
| REST API | JSON API for integration with other tools |
| Secure by design | Input sanitisation, parameterised queries, rate limiting, no URL execution |

---

## Architecture

```
Browser / API Client
       │
       ▼
  Flask App (app.py)
       │
       ├── Feature Extraction (src/feature_extraction.py)
       │       └── 32 static URL features, no network requests
       │
       ├── ML Prediction (src/predict.py)
       │       └── Loads trained model + feature config from models/
       │
       ├── Explainability (src/explain.py)
       │       └── Feature importance / SHAP / rule-based flags
       │
       └── SQLite Database (database/db_init.py)
               └── Stores all scan results
```

---

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3, Bootstrap 5, Bootstrap Icons, Chart.js |
| Backend | Python 3.11, Flask 3.0 |
| ML / Data Science | scikit-learn, XGBoost, pandas, NumPy, matplotlib, seaborn |
| Explainability | Feature importance + rule-based flags (SHAP optional) |
| Persistence | SQLite via Python `sqlite3` |
| Model serialisation | joblib |

---

## Project Structure

```
link-analysis-ai/
│
├── app.py                         # Flask application
├── requirements.txt               # Python dependencies
├── README.md
│
├── data/
│   └── urls.csv                   # Labelled URL dataset
│
├── models/
│   ├── link_detection_model.pkl   # Trained classifier (created by train_model.py)
│   └── feature_config.pkl         # Feature names + label mapping
│
├── notebooks/
│   └── link_analysis_model.ipynb  # End-to-end ML development notebook
│
├── src/
│   ├── __init__.py
│   ├── feature_extraction.py      # URL → 32 numeric features
│   ├── preprocessing.py           # Dataset loading + train/test split
│   ├── train_model.py             # Train, evaluate, select, save models
│   ├── predict.py                 # Inference: URL → prediction dict
│   └── explain.py                 # Explainability layer
│
├── templates/
│   ├── base.html                  # Shared layout, nav, footer
│   ├── index.html                 # Scanner homepage
│   ├── dashboard.html             # Statistics + charts
│   ├── history.html               # Scan history
│   └── details.html               # Single scan detail view
│
├── static/
│   ├── css/style.css              # Cybersecurity dark theme
│   ├── js/app.js                  # Frontend logic
│   └── reports/                   # Auto-generated training charts (PNG)
│
└── database/
    ├── db_init.py                 # SQLite schema + all data-access functions
    └── scans.db                   # SQLite database (auto-created)
```

---

## Dataset

The dataset `data/urls.csv` contains 280+ labelled URLs across four categories:

| Label | Description | Examples |
|---|---|---|
| `safe` | Legitimate, well-known websites | google.com, wikipedia.org, github.com |
| `suspicious` | Unusual patterns, shorteners, dubious domains | bit.ly links, newly registered domains |
| `phishing` | Credential-theft and impersonation | fake PayPal/Apple/bank login pages |
| `malicious` | Malware distribution, exploits, C2 servers | drive-by downloads, ransomware hosts |

**To extend the dataset**, add rows to `data/urls.csv` with `url` and `label` columns, then retrain.

For production use, consider integrating large public datasets such as:
- [PhishTank](https://www.phishtank.com/) — phishing URLs
- [OpenPhish](https://openphish.com/) — phishing feeds
- [Alexa / Tranco](https://tranco-list.eu/) — legitimate domains
- [URLhaus](https://urlhaus.abuse.ch/) — malware URLs

---

## Feature Engineering

**34 static features** are extracted from each URL string without making any network requests:

| # | Feature | Group | Description |
|---|---|---|---|
| 1 | `url_length` | Structural | Total character length of the URL |
| 2 | `domain_length` | Structural | Length of the hostname |
| 3 | `path_length` | Structural | Length of the URL path |
| 4 | `query_length` | Structural | Length of the query string |
| 5 | `num_dots` | Structural | Count of `.` characters |
| 6 | `num_slashes` | Structural | Count of `/` characters |
| 7 | `num_hyphens` | Structural | Count of `-` characters |
| 8 | `num_underscores` | Structural | Count of `_` characters |
| 9 | `num_digits` | Structural | Count of digit characters |
| 10 | `num_special_chars` | Structural | Count of non-standard characters |
| 11 | `num_query_params` | Structural | Number of `key=value` query parameters |
| 12 | `num_subdomains` | Structural | Number of subdomain levels |
| 13 | `uses_https` | Protocol | 1 if scheme is `https` |
| 14 | `uses_http` | Protocol | 1 if scheme is `http` |
| 15 | `has_ip_address` | Suspicious | 1 if host is an IPv4 address |
| 16 | `has_at_symbol` | Suspicious | 1 if `@` present in netloc |
| 17 | `has_hex_chars` | Suspicious | 1 if >3 percent-encoded or hex sequences |
| 18 | `suspicious_kw_count` | Suspicious | Count of matched suspicious keywords |
| 19 | `has_suspicious_tld` | Suspicious | 1 if TLD is on the abuse list |
| 20 | `is_url_shortener` | Suspicious | 1 if host is a known URL shortener |
| 21 | `excessive_subdomains` | Suspicious | 1 if subdomain count ≥ 4 |
| 22 | `has_login_keyword` | Suspicious | 1 if URL contains login-related words |
| 23 | `has_verify_keyword` | Suspicious | 1 if URL contains verify/confirm words |
| 24 | `has_account_keyword` | Suspicious | 1 if URL contains account/billing words |
| 25 | `has_password_keyword` | Suspicious | 1 if URL contains password/credential words |
| 26 | `has_double_slash_path` | Suspicious | 1 if path contains `//` |
| 27 | `has_multiple_at` | Suspicious | 1 if more than one `@` in URL |
| 28 | `domain_entropy` | Domain Quality | Shannon entropy of domain characters |
| 29 | `digit_ratio_domain` | Domain Quality | Fraction of digits in domain name |
| 30 | `path_depth` | Structural | Number of path segments |
| 31 | `has_fragment` | Navigation | 1 if URL contains a `#` fragment |
| 32 | `has_non_standard_port` | Protocol | 1 if port is not 80/443/8080/8443 |
| 33 | `has_redirect_param` | Navigation | 1 if query contains a redirect parameter |
| 34 | `has_malware_keyword` | Malware/C2 | 1 if URL contains a malware/C2-specific keyword (ransomware, botnet, beacon, exploit, etc.) |

---

## ML Algorithms

| Model | Rationale |
|---|---|
| Logistic Regression | Linear baseline; fast and interpretable |
| Decision Tree | Fully explainable; good for rule discovery |
| Random Forest | Robust ensemble; handles non-linearity well |
| Gradient Boosting | Strong sequential learner; high accuracy |
| XGBoost | Optimised gradient boosting (if installed) |

### Current Model Performance (Random Forest — 690-sample dataset)

| Metric | Score |
|---|---|
| Accuracy | **88.4%** |
| F1-Score | **88.3%** |
| ROC-AUC | **96.8%** |
| Malicious F1 | **98%** |
| Phishing F1 | **79%** |
| Safe F1 | **99%** |

### Model Selection

Models are **not** selected purely by accuracy. A composite score is used:

```
composite = 0.45 × F1 + 0.30 × ROC-AUC + 0.25 × Recall
```

This prioritises recall (catching real threats) alongside overall quality.

---

## Evaluation Metrics

| Metric | Why it matters |
|---|---|
| **Accuracy** | Overall correctness |
| **Precision** | Of URLs flagged as threats, how many actually were? |
| **Recall** | Of actual threats, how many did we catch? (most critical) |
| **F1-Score** | Harmonic mean of precision and recall |
| **ROC-AUC** | Model's ability to rank threat probability |
| **Confusion Matrix** | Shows exact class-level errors |

---

## Installation

### Prerequisites
- Python 3.9 or higher
- pip

### Steps

```bash
# 1. Clone or download the project
cd link-analysis-ai

# 2. Create a virtual environment (recommended)
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## How to Train the Model

```bash
# From the project root directory
python -m src.train_model
```

This will:
1. Load and clean `data/urls.csv`
2. Extract 34 features from every URL
3. Train all classifiers and evaluate them on a held-out test set
4. Print a model comparison report
5. Save the best model to `models/link_detection_model.pkl`
6. Save the feature configuration to `models/feature_config.pkl`
7. Generate training charts in `static/reports/`

---

## How to Run the Application

```bash
# Ensure the model is trained first, then:
python app.py
```

Open your browser at: **http://localhost:5000**

---

## API Documentation

### POST /api/analyze

Analyse a URL and return a prediction.

**Request**
```json
POST /api/analyze
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Response**
```json
{
  "scan_id": 42,
  "url": "https://example.com",
  "prediction": "SAFE",
  "risk_score": 12,
  "risk_level": "Low Risk",
  "confidence": 0.91,
  "probabilities": {
    "safe": 0.91,
    "suspicious": 0.06,
    "phishing": 0.02,
    "malicious": 0.01
  },
  "features": { "url_length": 19, "uses_https": 1, "..." : "..." },
  "explanation": ["HTTPS protocol in use", "No suspicious keywords detected"],
  "model_name": "Random Forest",
  "disclaimer": "This is an automated ML prediction..."
}
```

### POST /api/analyze/batch

Scan up to 20 URLs at once.

```json
POST /api/analyze/batch
{ "urls": ["https://example.com", "http://evil.xyz/phish"] }
```

Returns `{ "count": 2, "results": [...] }` in the same order as the input.
Rate limit: **5 requests/minute**.

### GET /api/health

```
GET /api/health
```

Returns `{ "status": "ok", "model_ready": true, "timestamp": "..." }`.
Returns HTTP 503 if the model is not trained.

### GET /api/history

```
GET /api/history?limit=50&offset=0&filter=PHISHING&q=paypal
```

| Parameter | Default | Description |
|---|---|---|
| `limit` | 50 | Max records to return (max 200) |
| `offset` | 0 | Pagination offset |
| `filter` | — | SAFE / SUSPICIOUS / PHISHING / MALICIOUS |
| `q` | — | URL substring search |

### GET /api/stats

Returns aggregate dashboard statistics (totals, risk buckets, scans by day).

### GET /api/scan/\<id\>

Returns the full record for a single scan by its integer ID.

### GET /api/export/csv

```
GET /api/export/csv?filter=PHISHING&q=paypal
```

Downloads matching scans as a CSV file (up to 5,000 rows).
Rate limit: **10 requests/hour**.

### GET /api/features

Returns documentation for all 34 URL features used by the model.

### GET /api/explain/\<id\>

Returns the explainability breakdown for a stored scan — feature contributions with
importance scores, direction (increases/decreases risk), and the explanation method used.

```
GET /api/explain/42
{ "scan_id": 42, "prediction": "MALICIOUS", "explain_method": "tree_importance",
  "contributions": [{"feature":"has_malware_keyword","value":1,"importance":0.082,...}],
  "flags": ["URL contains a malware/C2-associated keyword", ...] }
```

---

## Security Notes

This application is designed for **static URL analysis only**:

- **No URLs are visited or executed** — all analysis is on the URL string itself
- **No network requests** are made to the submitted URL
- **SQL injection** is prevented via parameterised queries throughout
- **XSS** is prevented via server-side escaping (`escHtml` in JS, Jinja2 auto-escaping in HTML)
- **Rate limiting** is applied to the `/api/analyze` endpoint (30 requests/minute)
- **Input validation** rejects empty, malformed, and oversized URLs

---

## Known Limitations

1. **Training dataset size** — 690 URLs covers the main patterns well for a portfolio demo. A production system would use millions of labelled samples from sources like PhishTank and URLhaus.
2. **Static analysis only** — the model cannot detect threats that rely on page content, JavaScript behaviour, or server-side redirects.
3. **No real-time threat intel** — the model is not connected to live blocklists or threat feeds.
4. **Class imbalance** — the dataset has unequal class distribution; `class_weight='balanced'` partially mitigates this.
5. **Feature coverage** — domain age, WHOIS data, and SSL certificate details are not included (would require network calls).
6. **Not a security guarantee** — predictions are probabilistic. Always treat results as a risk indicator, not a verdict.

---

## Future Improvements

- Larger, curated dataset (PhishTank + URLhaus integration)
- NLP features: character n-grams, word2vec on URL tokens
- Domain WHOIS / age lookup (opt-in, rate-limited)
- Real-time threat intelligence API integration
- Browser extension for on-page URL checking
- ~~Batch URL scanning~~ **Done** (up to 20 URLs via API + UI)
- ~~CSV report export~~ **Done** (`/api/export/csv`)
- PDF report generation
- Continuous model retraining pipeline
- Anomaly detection for zero-day URLs
- Email URL extraction and analysis
- QR code URL decoding and analysis

---

## License

This project is created for educational and portfolio purposes.
