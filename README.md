# Web Threat Early Warning

Machine-learning pipeline for early warning of suspicious web traffic from Nginx access logs. The project is designed as a local, reproducible security demo: traffic is generated against OWASP Juice Shop, converted into flow-like features, scored by a FastAPI LightGBM service, and forwarded to n8n for alerting.

## Highlights

- Parses Nginx/Apache combined logs or JSON access logs into windowed web-flow events.
- Scores events through a FastAPI inference API with configurable alert policy.
- Persists alerts to SQLite and can forward only actionable alerts to an n8n webhook.
- Includes Docker lab assets for safe local testing with OWASP Juice Shop.
- Includes training and benchmarking scripts for comparing classical ML models.

## Architecture

```text
Nginx access.log
  -> web_accesslog_to_events.py
  -> events.jsonl
  -> web_events_to_n8n.py
  -> FastAPI /score
  -> SQLite alerts.db + n8n webhook
  -> Telegram or other SOC notification channel
```

## Repository Layout

```text
web_early_warning/
  inference_service.py          FastAPI scoring API
  web_accesslog_to_events.py    Access-log parser and flow-window aggregator
  web_events_to_n8n.py          Collector, scorer, alert persistence, webhook forwarder
  feature_pipeline.py           Feature normalization/profile mapping
  train_*.py                    Training pipelines
  compare_models.py             Offline model comparison
  deploy/                       systemd units, env examples, healthcheck
  n8n/                          Importable n8n workflows

security-demo-lab/
  docker-compose.yml            OWASP Juice Shop behind Nginx
  nginx/default.conf            Demo reverse-proxy logging config
```

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r web_early_warning/requirements.txt
uvicorn web_early_warning.inference_service:app --host 127.0.0.1 --port 8000
```

In another terminal:

```bash
curl -s http://127.0.0.1:8000/health
python3 -m web_early_warning.self_check
```

By default, the API expects a local model bundle at:

```text
web_early_warning/model_out_flowfeatures/lgbm_combined_flow_web_60_webattack.joblib
```

Model bundles and datasets are intentionally ignored by Git because they can be large or environment-specific. For a public portfolio repository, publish the code, workflows, benchmark summaries, and instructions; attach model/data artifacts separately only when licensing and size are appropriate.

## Local Demo Lab

```bash
cd security-demo-lab
docker compose up -d
```

The lab exposes OWASP Juice Shop through Nginx at `http://localhost:3000`. The Nginx access log can be consumed by `web_accesslog_to_events.py`.

## Safety Scope

This repository is for defensive monitoring, education, and authorized lab testing. Do not point the demo collector at systems you do not own or have permission to test.

## What This Shows Employers

- Practical log parsing and feature engineering for web-security telemetry.
- End-to-end ML inference service design with operational health checks.
- Alert filtering and integration with an automation platform.
- Reproducible local lab setup and deployment scripts.

