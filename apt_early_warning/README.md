# APT Early Warning

He thong canh bao som APT dua tren ML flow features, toi uu cho web monitoring:

`access.log -> web_accesslog_to_events -> web_events_to_n8n -> /score -> n8n -> Telegram`

Model hien tai:
- Bundle: `apt_early_warning/model_out_flowfeatures/lgbm_flowfeatures_web_rich_v2.joblib`
- Profile: `web_monitor_rich_v2`
- So dac trung: 18
- Muc tieu: phat hien bat thuong/APT tren luong truy cap web

## 1) Kien truc

### Luong khuyen nghi (web-only)
1. `web_accesslog_to_events.py` tail access log va gom theo cua so thoi gian thanh flow-like event.
2. `web_events_to_n8n.py` doc JSONL events, goi `/score`.
3. Chi khi `decision=ALERT` moi forward sang n8n webhook.
4. n8n workflow xu ly canh bao (Telegram/LLM correlation tuy chon).

## 2) Cau truc thu muc quan trong

- `train_flowfeatures_binary.py`: train model binary Benign/APT tu `flowFeatures.csv`.
- `feature_pipeline.py`: mapping + feature profile (`web_monitor_rich_v2`, `web_realtime_v1`, `legacy7`).
- `inference_service.py`: FastAPI `/health`, `/score`.
- `web_accesslog_to_events.py`: parser access log -> events JSONL.
- `web_events_to_n8n.py`: collector events -> score -> n8n.
- `deploy/`: systemd units + env examples + scripts install + healthcheck.
- `n8n/`: workflow JSONs.

## 3) Cai dat nhanh

```bash
cd /home/sealorl/BTLPY
python3 -m venv .venv
source .venv/bin/activate
pip install -r apt_early_warning/requirements.txt
```

## 4) Train model

### 4.1 Train profile rich cho web monitoring (khuyen nghi)

```bash
python3 apt_early_warning/train_flowfeatures_binary.py \
  --csv flowFeatures.csv \
  --feature-profile web_monitor_rich_v2 \
  --out apt_early_warning/model_out_flowfeatures/lgbm_flowfeatures_web_rich_v2.joblib
```

### 4.2 Train profile 7 dac trung (tuong thich cao)

```bash
python3 apt_early_warning/train_flowfeatures_binary.py \
  --csv flowFeatures.csv \
  --feature-profile web_realtime_v1 \
  --out apt_early_warning/model_out_flowfeatures/lgbm_flowfeatures_binary.joblib
```

## 5) Chay scoring API

```bash
uvicorn apt_early_warning.inference_service:app --host 0.0.0.0 --port 8000
```

Kiem tra:

```bash
curl -s http://127.0.0.1:8000/health
curl -s "http://127.0.0.1:8000/alerts?limit=20"
```

Smoke test:

```bash
python3 -m apt_early_warning.self_check
```

## 6) Van hanh web-only bang systemd (khuyen nghi)

### 6.1 Cai services

```bash
cd /home/sealorl/BTLPY
sudo bash apt_early_warning/deploy/install_scoring_systemd.sh
sudo bash apt_early_warning/deploy/install_web_log_parser_systemd.sh
sudo bash apt_early_warning/deploy/install_web_collector_systemd.sh
```

### 6.2 Cau hinh env

Scoring:

```bash
sudo cp apt_early_warning/deploy/scoring.env.example /etc/apt_early_warning_scoring.env
sudo nano /etc/apt_early_warning_scoring.env
```

Dat:

```env
BUNDLE_PATH=/home/sealorl/BTLPY/apt_early_warning/model_out_flowfeatures/lgbm_flowfeatures_web_rich_v2.joblib
ALERT_LABELS=APT
ALERT_MIN_CONF_HIGH_IMPACT=0.50
ALERT_MIN_CONF_NON_BENIGN=0.50
```

Web log parser:

```bash
sudo cp apt_early_warning/deploy/web_log_parser.env.example /etc/apt_early_warning_web_log_parser.env
sudo nano /etc/apt_early_warning_web_log_parser.env
```

Web collector:

```bash
sudo cp apt_early_warning/deploy/web_collector.env.example /etc/apt_early_warning_web_collector.env
sudo nano /etc/apt_early_warning_web_collector.env
```

Mau collector env:

```env
WEB_EVENTS_PATH=/home/sealorl/BTLPY/security-demo-lab/logs/apt/events.jsonl
SCORE_URL=http://127.0.0.1:8000/score
N8N_WEBHOOK=http://127.0.0.1:5678/webhook/apt-ingest
ALERTS_DB_PATH=/home/sealorl/BTLPY/security-demo-lab/logs/apt/alerts.db
VERBOSE=1
```

Restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart apt_early_warning_scoring.service
sudo systemctl restart apt_early_warning_web_log_parser.service
sudo systemctl restart apt_early_warning_web_collector.service
```

Status:

```bash
systemctl status apt_early_warning_scoring.service --no-pager
systemctl status apt_early_warning_web_log_parser.service --no-pager
systemctl status apt_early_warning_web_collector.service --no-pager
```

## 7) Healthcheck

Web-only:

```bash
/home/sealorl/BTLPY/apt_early_warning/deploy/healthcheck_realtime.sh
```

## 8) n8n workflows

Thu muc: `apt_early_warning/n8n/`

File workflow chinh:
- `BTLPY_APT_Early_Warning.workflow.json` (`/webhook/apt-ingest`)
- `BTLPY_APT_Early_Warning_Binary.workflow.json` (`/webhook/apt-ingest-binary`)
- `BTLPY_APT_ML_First.workflow.json` (`/webhook/apt-ingest-ml`)
- `BTLPY_APT_LLM_Correlation_FIXED.workflow.json` (`/webhook/apt-ingest-llm-fixed`)

Luu y quan trong:
- Production URL (`/webhook/...`) chi hoat dong khi workflow da `Save + Active`.
- Test URL dung `/webhook-test/...` khi dang mo editor workflow.

## 9) Payload test nhanh

Da co script:

```bash
bash /home/sealorl/BTLPY/payloads_test_curl.sh score
bash /home/sealorl/BTLPY/payloads_test_curl.sh ingest
bash /home/sealorl/BTLPY/payloads_test_curl.sh llm
bash /home/sealorl/BTLPY/payloads_test_curl.sh llm3
```

## 10) Theo doi realtime

```bash
sudo journalctl -u apt_early_warning_web_log_parser.service -f
sudo journalctl -u apt_early_warning_web_collector.service -f
tail -f /home/sealorl/BTLPY/security-demo-lab/logs/apt/events.jsonl
bash /home/sealorl/BTLPY/show_alerts.sh
```

## 11) Troubleshooting nhanh

### 11.1 Webhook 404
- Nguyen nhan: workflow chua `Active` hoac sai path.
- Cach xu ly: `Save + Active`, doi chieu dung endpoint (`apt-ingest`, `apt-ingest-llm-fixed`, ...).

### 11.2 Collector chi ra `NO_ALERT`
- Thuong do traffic hien tai benh tinh (benign).
- Tao traffic test manh hon hoac tam giam threshold alert de demo.

### 11.3 Node Function n8n loi `getWorkflowStaticData is not defined`
- Dung expression dung: `$getWorkflowStaticData('global')`
- Khong dung `getWorkflowStaticData(...)` khong co dau `$`.

## 12) Khong bat buoc database

Phien ban hien tai khong can DB de chay realtime:
- Input: access log / events JSONL
- Processing: scoring API + collector
- Output: n8n + Telegram

Chi can DB neu muon dashboard lich su, truy van bao cao, thong ke dai han.

## 13) Lenh demo nhanh (web-only)

```bash
cd /home/sealorl/BTLPY/security-demo-lab
docker compose up -d

cd /home/sealorl/BTLPY
/home/sealorl/BTLPY/apt_early_warning/deploy/healthcheck_realtime.sh

bash /home/sealorl/BTLPY/payloads_test_curl.sh ingest
```

Neu can tai lieu thao tac day du hon, xem file goc:
- `/home/sealorl/BTLPY/huong_dan.txt`
- `/home/sealorl/BTLPY/in4.txt`
