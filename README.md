# NetScan — Metadata-Only Network Intrusion Detection System

A **near real-time, metadata-only NIDS** for college / campus networks.  
Captures flows every 15–30 s, extracts per-device features, runs **rule-based + unsupervised ML anomaly detection**, optionally escalates to **Google Gemini** for semantic classification, and surfaces results through a **web dashboard + notifications**.

> **Privacy first:** Only packet headers (IPs, ports, timestamps, sizes) are analysed — **no payload data is captured or stored**.

---

## Architecture

```
Capture Layer ──► Feature Extraction ──► Hybrid Detection ──► AI Reasoner (Gemini)
     │                                        │                      │
     └────────── Database ◄───────────────────┴──────────────────────┘
                    │
              Admin Dashboard  ◄──  Alerts  ──►  Email / Telegram
```

| Component | Location | Purpose |
|-----------|----------|---------|
| **Capture** | `app/capture/` | Reads NIC with scapy, groups into flows |
| **Features** | `app/features/` | Converts flows to per-device feature vectors (sliding window) |
| **Detection** | `app/detection/` | Rule engine + IsolationForest ML, hybrid scoring |
| **AI Reasoner** | `app/ai_reasoner/` | Gemini API integration for uncertain detections |
| **Alerts** | `app/alerts/` | Persistence, console / email / Telegram notifications |
| **API & Dashboard** | `app/api/` + `templates/` | FastAPI + Bootstrap/Chart.js admin UI |
| **Database** | `app/db/` | SQLAlchemy models (SQLite dev / Postgres prod) |
| **Config** | `config/` | YAML configs for rules, thresholds, Gemini, logging |

---

## Quick Start

### 1. Clone & Install

```bash
git clone <repo-url> netscan
cd netscan
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac
pip install -r requirements.txt
```

### 2. Start the API Server & Dashboard

```bash
python cli.py api
```

Open **http://localhost:8000** in your browser.

### 3. Run the Live Pipeline

```bash
python cli.py capture --mode scapy --interface Wi-Fi
```

Every ~10 s a window of traffic is analysed and alerts appear in the console and dashboard.

### 4. Run with Real Traffic

```bash
python cli.py capture --mode scapy --interface eth0
```

### 5. All-in-One Live Monitor
```bash
python cli.py live --interface Wi-Fi
```

---

## Configuration

All tunable parameters are in `config/app_config.yaml`:

| Key | Default | Description |
|-----|---------|-------------|
| `app.window_seconds` | 20 | Analysis window length |
| `app.slide_seconds` | 10 | Window slide interval |
| `detection.rule_weight` | 0.65 | Weight of rule score in hybrid |
| `detection.ml_weight` | 0.35 | Weight of ML score in hybrid |
| `detection.block_threshold` | 0.90 | Risk ≥ this → block decision |
| `detection.alert_threshold` | 0.70 | Risk ≥ this → monitor decision |
| `detection.ai_review_low/high` | 0.55 / 0.80 | Gray-zone → escalate to Gemini |
| `gemini.enabled` | false | Enable Gemini AI reasoning |
| `gemini.model` | gemini-2.0-flash | Gemini model to call |

### Enable Gemini

1. Set `gemini.enabled: true` in `config/app_config.yaml`.
2. Export your API key: `set GEMINI_API_KEY=<your-key>`.

### Rules

Edit `config/rules.yaml` to add/modify VPN ports, torrent ports, restricted domain keywords, and fan-out thresholds.

---

## ML Model Training

1. Capture several hours of **normal** traffic.
2. Open `models/train_notebook.ipynb` and run all cells.
3. The notebook trains an `IsolationForest` and saves `models/isolation_forest.pkl`.
4. Restart the pipeline — the model loads automatically.

See `models/ml_config.yaml` for hyperparameters.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard (HTML) |
| `GET` | `/health` | System health check |
| `GET` | `/alerts` | List alerts (JSON), filterable by `status`, `severity`, `src_ip` |
| `GET` | `/alerts/stats` | Aggregate alert statistics |
| `GET` | `/alerts/{id}` | Alert detail with detection scores + AI assessment |
| `PATCH` | `/alerts/{id}` | Update alert status (`open` → `acknowledged` → `resolved`) |
| `GET` | `/alert/{id}` | Alert detail page (HTML) |
| `GET` | `/devices` | List tracked devices |
| `GET` | `/devices/{ip}` | Device detail with recent detections & alerts |
| `GET` | `/devices/summary/all` | Per-device risk summary |

---

## Testing

```bash
pytest tests/ -v
```

Tests cover capture parsing, feature extraction, rule engine, ML scoring, AI reasoner (mocked), and API endpoints.

---

## Database Schema

| Table | Purpose |
|-------|---------|
| `devices` | Known IPs, MACs, hostnames, owners |
| `network_features` | Per-device per-window feature snapshots |
| `detections` | Rule + ML scores, decisions |
| `ai_assessments` | Gemini responses (threat type, severity, explanation) |
| `alerts` | Admin-facing alerts with status lifecycle |

See `app/db/schema.sql` for the full DDL.

---

## Demo Plan (College Evaluation)

1. **Architecture Overview** (2–3 min) — show the diagram above.
2. **Live Monitoring** (5–7 min):
   - Open dashboard → note empty state.
   - Start VPN on test client → VPN alert appears within 20–30 s.
   - Visit gambling site → gambling alert.
   - Start torrent → high-severity torrent alert.
3. **AI Explainability** (2–3 min) — click an AI-assisted alert, show Gemini's JSON explanation.
4. **Technical Deep Dive** (optional) — DB schema, feature code, prompt template.

---

## Project Structure

```
netscan/
  app/
    config.py                   # AppConfig loader
    capture/                    # Packet capture & flow aggregation
    features/                   # Feature extraction & sliding window
    detection/                  # Rules + ML + hybrid detector
    ai_reasoner/                # Gemini API client & prompt builder
    alerts/                     # Alert manager & notifier
    api/                        # FastAPI routes & dashboard
    db/                         # SQLAlchemy models & session
    utils/                      # Logging, time, IP, config helpers
  templates/                    # Jinja2 HTML templates
  static/                       # CSS / JS assets
  models/                       # Trained ML models & notebook
  scripts/                      # CLI entry points
  tests/                        # pytest test suite
  config/                       # YAML configuration files
  requirements.txt
  README.md
```

---

## License

MIT — see individual file headers for details.