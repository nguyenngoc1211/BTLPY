# Security Demo Lab (Docker)

Lab này dùng để demo an toàn trên máy local bằng OWASP Juice Shop.

## Yêu cầu

- Docker
- Docker Compose (plugin `docker compose`)

## Chạy lab

```bash
cd security-demo-lab
docker compose up -d
```

Mở trình duyệt: http://localhost:3000

## Nhúng ML Cảnh Báo (web-only, không dùng Suricata)

Luồng: `nginx access.log -> web_accesslog_to_events -> /score -> n8n`.

### 1) Cài service parser/collector (chạy 1 lần)

```bash
cd ..
sudo bash web_early_warning/deploy/install_scoring_systemd.sh
sudo bash web_early_warning/deploy/install_web_log_parser_systemd.sh
sudo bash web_early_warning/deploy/install_web_collector_systemd.sh
```

### 2) Cấu hình bridge cho lab này

```bash
cd security-demo-lab
sudo bash setup_ml_web_bridge.sh
```

### 3) Chạy demo

```bash
cd security-demo-lab
docker compose up -d
```

Mở web và tạo traffic: `http://localhost:3000`

### 4) Theo dõi log cảnh báo

```bash
sudo journalctl -u web_early_warning_web_log_parser.service -f
sudo journalctl -u web_early_warning_web_collector.service -f
```

Healthcheck web-only:

```bash
CHECK_SURICATA=0 \
COLLECTOR_SERVICE=web_early_warning_web_collector.service \
../web_early_warning/deploy/healthcheck_realtime.sh
```

## Kiểm tra trạng thái

```bash
docker compose ps
```

## Xem log

```bash
docker compose logs -f juice-shop
```

## Dừng lab

```bash
docker compose down
```

## Xóa sạch container + volume mạng demo

```bash
docker compose down --volumes --remove-orphans
```

## Lưu ý an toàn

- Chỉ chạy trong môi trường lab/local.
- Không trỏ demo này vào hệ thống production.
- Chỉ dùng cho mục đích đào tạo và kiểm thử được cấp phép.
