# Web Threat Early Warning

Realtime early-warning pipeline for suspicious web traffic. The current implementation focuses on web monitoring from access logs and keeps the runtime path simple enough to demo locally or deploy as host services.

```text
Nginx access.log
  -> web_accesslog_to_events.py
  -> events.jsonl
  -> web_events_to_n8n.py
  -> Scoring API (/score)
  -> SQLite alert history + n8n webhook
```

## Goals

- Detect abnormal or attack-like web behavior from access-log telemetry.
- Score each aggregated flow with a LightGBM model.
- Emit `ALERT` only when policy thresholds are met, reducing noise before forwarding to n8n/Telegram.
- Keep training, inference, and deployment code reproducible for portfolio review.

## Main Components

- `feature_pipeline.py`: normalizes feature names and maps model feature profiles.
- `inference_service.py`: FastAPI scoring API with `/health`, `/score`, and `/alerts`.
- `web_accesslog_to_events.py`: tails access logs and emits windowed JSONL flow events.
- `web_events_to_n8n.py`: scores events, stores alerts, and forwards alert payloads.
- `train_flowfeatures_binary.py`: trains a binary model from `flowFeatures.csv`.
- `train_combined_binary.py`: trains a combined web/flow feature profile.
- `compare_models.py`: offline benchmark runner for multiple algorithms.
- `n8n/*.workflow.json`: n8n workflows for alert routing/correlation.
- `deploy/`: systemd units, env examples, install scripts, and healthcheck.

## Install

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r web_early_warning/requirements.txt
```

## Run The Scoring API

```bash
uvicorn web_early_warning.inference_service:app --host 127.0.0.1 --port 8000
```

Check runtime state:

```bash
curl -s http://127.0.0.1:8000/health
python3 -m web_early_warning.self_check
```

The API reads `BUNDLE_PATH` when set. Without it, it looks for:

```text
web_early_warning/model_out_flowfeatures/lgbm_combined_flow_web_60_webattack.joblib
```

## Run The Local Web Demo

Start the lab:

```bash
cd security-demo-lab
docker compose up -d
```

Run the parser against the lab access log:

```bash
WEB_ACCESS_LOG_PATH=security-demo-lab/logs/nginx/access.log \
WEB_EVENTS_PATH=security-demo-lab/logs/web/events.jsonl \
python3 -m web_early_warning.web_accesslog_to_events --verbose
```

Run the collector in another terminal:

```bash
WEB_EVENTS_PATH=security-demo-lab/logs/web/events.jsonl \
SCORE_URL=http://127.0.0.1:8000/score \
N8N_WEBHOOK=http://127.0.0.1:5678/webhook/web-ingest \
ALERTS_DB_PATH=security-demo-lab/logs/web/alerts.db \
python3 -m web_early_warning.web_events_to_n8n --verbose
```

View recent persisted alerts:

```bash
bash show_alerts.sh security-demo-lab/logs/web/alerts.db 20
curl -s "http://127.0.0.1:8000/alerts?limit=20"
```

## systemd Deployment

The install scripts render service files using the current repository path and the invoking sudo user:

```bash
sudo bash web_early_warning/deploy/install_scoring_systemd.sh
sudo bash web_early_warning/deploy/install_web_log_parser_systemd.sh
sudo bash web_early_warning/deploy/install_web_collector_systemd.sh
```

Edit the generated env files under `/etc`:

- `/etc/web_early_warning_scoring.env`
- `/etc/web_early_warning_web_log_parser.env`
- `/etc/web_early_warning_web_collector.env`

Then restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart web_early_warning_scoring.service
sudo systemctl restart web_early_warning_web_log_parser.service
sudo systemctl restart web_early_warning_web_collector.service
```

Healthcheck:

```bash
CHECK_SURICATA=0 web_early_warning/deploy/healthcheck_realtime.sh
```

## n8n Workflows

Importable workflows:

- `web_early_warning/n8n/BTLPY_Web_Early_Warning.workflow.json`
- `web_early_warning/n8n/BTLPY_Web_LLM_Correlation.workflow.json`

Use production webhook URLs (`/webhook/...`) only after the workflow is saved and active. Test URLs (`/webhook-test/...`) work only while executing the workflow from the editor.

## Public Repository Notes

- Do not commit raw traffic captures, private logs, SQLite alert history, or large datasets.
- Do not commit private webhook URLs, Telegram tokens, API keys, or n8n credentials.
- Model `.joblib` files are ignored by default; publish them separately only when you are allowed to share the trained artifact.
- Keep benchmark CSVs or summarized reports when they help reviewers understand model quality without exposing private data.

