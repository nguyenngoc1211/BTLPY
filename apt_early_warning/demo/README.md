# Demo (FastAPI /score + n8n webhook)

Mục tiêu: demo end-to-end luồng `Webhook -> /score -> decision`.

## 0) Chuẩn bị (host)

```bash
cd /home/sealorl/BTLPY
python3 -m venv .venv
source .venv/bin/activate
pip install -r apt_early_warning/requirements.txt
```

## Option A: Chạy scoring API trên host + n8n Docker

### 1) Chạy scoring API (host)

```bash
export BUNDLE_PATH=apt_early_warning/model_out_flowfeatures/lgbm_flowfeatures_web_rich_v2.joblib
uvicorn apt_early_warning.inference_service:app --host 0.0.0.0 --port 8000
```

Kiểm tra:

```bash
curl -s http://localhost:8000/health | jq
```

### 2) Chạy n8n (Docker)

```bash
docker compose -f apt_early_warning/demo/n8n-compose.yml up -d
```

Mở UI: `http://localhost:5678`

### 3) Import workflow mẫu

- Trong n8n: `Workflows -> Import from File`
- Chọn 1 trong các workflow:
  - Demo đơn giản (trả JSON score): `apt_early_warning/demo/workflow_apt_demo.json`
- Activate workflow

Workflow này:
- Nhận `POST /webhook/apt-ingest`
- Forward `body` sang `http://host.docker.internal:8000/score`
- Trả response về caller (để demo dễ quan sát)

### 4) Gửi payload demo

```bash
python3 -m apt_early_warning.demo.send_sample --url http://localhost:5678/webhook/apt-ingest
```

Test nhánh ALERT (force):

```bash
python3 -m apt_early_warning.demo.send_sample --url http://localhost:5678/webhook/apt-ingest --force-alert
```

## Option B (khuyến nghị cho demo): 1 lệnh chạy cả n8n + scoring trong Docker

Chạy:

```bash
docker compose -f apt_early_warning/demo/compose.demo.yml up -d --build
```

Hoặc chạy nhanh bằng script:

```bash
bash apt_early_warning/demo/run_demo_compose.sh
```

Kiểm tra API:

```bash
curl -s http://localhost:8000/health | jq
```

Import workflow:

- Trong n8n: `Workflows -> Import from File`
- Chọn 1 trong các workflow:
  - Demo đơn giản (trả JSON score): `apt_early_warning/demo/workflow_apt_demo_compose.json`
- Activate workflow

Gửi payload demo vẫn như Option A:

```bash
python3 -m apt_early_warning.demo.send_sample --url http://localhost:5678/webhook/apt-ingest
```

## Option C: Replay "gần thực tế" từ `flowFeatures.csv` (không dùng force-alert)

Sinh kịch bản replay JSONL:

```bash
python3 apt_early_warning/demo/replay_realistic.py \
  --csv flowFeatures.csv \
  --out-jsonl apt_early_warning/demo/scenario_replay.jsonl \
  --campaigns 1 \
  --baseline-window 30 \
  --phase-size 20
```

Replay trực tiếp vào webhook n8n:

```bash
python3 apt_early_warning/demo/replay_realistic.py \
  --csv flowFeatures.csv \
  --out-jsonl apt_early_warning/demo/scenario_replay.jsonl \
  --campaigns 1 \
  --baseline-window 30 \
  --phase-size 20 \
  --url http://localhost:5678/webhook/apt-ingest \
  --delay-ms 150
```

Ghi chú:
- Script chia các mẫu `APT` thành 3 pha theo cường độ tín hiệu (`low/medium/high`) và trộn xen kẽ traffic `Benign`.
- `force_alert=false` mặc định để tránh tín hiệu kiểm thử lộ.
