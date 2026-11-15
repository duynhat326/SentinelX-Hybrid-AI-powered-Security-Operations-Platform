# SentinelX — Checklist

Quy tắc: một mục chỉ được tick `[x]` khi (1) code xong, (2) test/lệnh xác nhận đã chạy và pass, (3) tài liệu liên quan đã cập nhật. Mỗi mục ghi rõ **Xác nhận bằng** gì. Số liệu đánh giá chỉ lấy từ lần chạy thật.

Cách dùng: làm xong một chức năng → chạy lệnh xác nhận → tick → commit.

---

## M1 — Lát cắt dọc đầu tiên (HOÀN THÀNH)
- [x] Cấu hình kiểm tra lúc khởi động — *Xác nhận:* app không chạy nếu thiếu/ngắn `SENTINELX_API_KEY`
- [x] Chuẩn hóa sshd auth + Sysmon EventID 1, che secret — *Xác nhận:* `pytest tests/test_normalize.py`
- [x] Lưu event idempotent (hash chống trùng) — *Xác nhận:* test `duplicate`, smoke test Docker
- [x] Rule SX-001 (SSH brute-force), SX-002 (PowerShell đáng ngờ) — *Xác nhận:* `pytest tests/test_api.py`
- [x] API `/health`, `POST /api/v1/events`, `GET /api/v1/alerts` + API key — *Xác nhận:* 401 không key, smoke test
- [x] 11 test pass trên SQLite và PostgreSQL 17; ruff, mypy sạch
- [x] Docker Compose chạy, db + backend healthy, backend non-root

---

## M1.5 — Sửa lỗi và nền tảng (CÒN 1 MỤC)
- [x] **Sửa race tạo alert song song** (advisory lock theo host trên Postgres)
  - *Xác nhận:* `test_concurrent_ingest_one_alert` pass 13/13 lần chạy trên Postgres; smoke test Compose 8 request song song → 8×200, 1 alert
- [x] **Sửa lỗi log đến sai thứ tự** (rule SX-001 xét cửa sổ hai phía) — lỗi phát hiện thêm trong lúc làm
  - *Xác nhận:* `test_out_of_order_arrival_still_alerts_with_full_evidence`
- [x] `docs/architecture.md` — sơ đồ Mermaid 5 lớp + luồng ingest, đánh dấu phần chưa làm
- [x] `docs/database-schema.md` — ER diagram, ràng buộc, bảng dự kiến
- [x] Thêm `graphify-out/`, `.codegraph/`, `.claude/` vào `.gitignore`
- [x] Rate limiting `POST /api/v1/events` (mặc định 600/phút/IP, cấu hình `SENTINELX_RATE_LIMIT_PER_MINUTE`)
  - *Xác nhận:* `test_rate_limit_returns_429`
- [x] GitHub Actions (`.github/workflows/ci.yml`): pytest SQLite + Postgres, ruff, mypy
  - *Đã viết, YAML hợp lệ, chưa chạy trên GitHub.* Tick khi CI xanh trên PR

## M2 — Migration và nguồn dữ liệu (nhánh `feat/m2-migrations-wazuh`) — XONG, chờ bạn review
- [x] Alembic + migration `0001` thay `create_all`
  - *Xác nhận:* `alembic upgrade head` → `downgrade base` → `upgrade head` + `alembic check` sạch trên Postgres 17; `test_migrations.py` so khớp migration với model (đã thử cố tình làm lệch schema, test phát hiện được); container Compose tự chạy migration khi khởi động
- [x] Bảng `assets` (hostname duy nhất, criticality 1–5, mặc định 3) + `security_events.asset_id`; tạo tự động ở lần đầu thấy host — *Xác nhận:* `test_asset_created_once_per_host`, smoke test Compose
- [x] Bảng `detection_rules` đồng bộ metadata từ code lúc khởi động, `enabled` do vận hành quyết định + `GET /api/v1/rules` — *Xác nhận:* `test_rules_listed_and_disabling_stops_alerts`
- [x] Sysmon event 3 (kết nối mạng), 12/13 (registry) — *Xác nhận:* fixture `tests/fixtures/sysmon_*.json`, `test_sysmon_*`
- [x] Đầu vào Wazuh alert JSON (`source: "wazuh"`, bọc Sysmon hoặc dòng sshd) — *Xác nhận:* `test_wazuh_*`, smoke test Compose (SX-002 kích hoạt qua Wazuh)
- [x] Cột `src_port`, `dst_ip`, `dst_port`, `registry_key`, `registry_value` cho event
- [x] Cập nhật `docs/database-schema.md`
- [x] **Sửa lỗi M1 phát hiện thêm:** secret ở cuối giá trị trong JSON làm hỏng JSON → event Sysmon bị từ chối 422 (mất event). Nay parse JSON trước rồi mới che từng giá trị. *Xác nhận:* `test_secret_in_json_payload_is_redacted_and_event_accepted`
- [ ] Công cụ đẩy alert Wazuh sang API (integration script) — *chưa làm*, hiện chỉ có định dạng nhận; cân nhắc ở M8/lab

## M3 — Bộ rule phát hiện (đủ 5–8 rule)
- [ ] SX-003 Tạo tài khoản đáng ngờ
- [ ] SX-004 Dấu hiệu leo thang đặc quyền
- [ ] SX-005 Registry Run key persistence (T1547.001)
- [ ] SX-006 Kết nối ra ngoài bất thường
- [ ] SX-007 Quan hệ process cha–con bất thường
- [ ] SX-008 Thất bại nhiều lần rồi thành công
- [ ] Mỗi rule có: metadata (severity, MITRE, tham chiếu), fixture lành tính + độc hại, test TP/FP
- [ ] Rule bật/tắt được qua cấu hình — *Xác nhận:* test rule tắt không sinh alert
- [ ] Alert dedup theo **cửa sổ thời gian** (thay vì mãi mãi)
- [ ] Bộ fixture gán nhãn lành tính/độc hại (mục tiêu 100–200 mẫu)
- [ ] `docs/detection-rules.md` mô tả từng rule, false positive dự kiến

## M4 — Correlation, incident, risk engine
- [ ] Gom alert thành incident theo host/user/IP/process trong cửa sổ thời gian
- [ ] Chống tạo incident trùng — *Xác nhận:* test idempotent
- [ ] Timeline bằng chứng của incident (`incident_alerts`, `incident_evidence`)
- [ ] Risk score 0–100 xác định (0.4·severity + 0.3·correlation + 0.2·TI + 0.1·asset), cấu hình được
- [ ] Xử lý dữ liệu thiếu (TI chưa có) và ghi chú giới hạn hiệu chuẩn
- [ ] API: danh sách incident, chi tiết + timeline
- [ ] Test: cửa sổ thời gian, gộp incident, công thức risk

## M5 — AI điều tra (LLM chỉ giải thích)
- [ ] Nhà cung cấp LLM cấu hình được + **mock LLM** cho test/offline
- [ ] LangGraph có giới hạn: Triage → Investigation
- [ ] Đầu ra kiểm tra bằng Pydantic; mọi nhận định trích dẫn event/evidence ID
- [ ] Bảng `agent_runs` lưu mỗi lần chạy
- [ ] Hệ thống vẫn phát hiện và chấm điểm khi LLM tắt — *Xác nhận:* test với LLM không khả dụng
- [ ] Test prompt injection: nội dung log là dữ liệu, tool call trái phép bị từ chối và ghi audit
- [ ] Test claim không có bằng chứng bị loại (unsupported-claim)
- [ ] Không đưa secret vào prompt — *Xác nhận:* test redaction trước khi gửi LLM

## M6 — Threat intel, phản ứng, phân quyền
- [ ] RBAC: bảng users/roles, đăng nhập, thay API key chung
- [ ] `audit_logs` cho mọi thao tác nhạy cảm
- [ ] Bảng IOC cục bộ + cache
- [ ] Adapter VirusTotal / AbuseIPDB (tùy chọn): timeout, rate limit, cảnh báo riêng tư trước khi gửi ngoài, không bịa dữ liệu
- [ ] Threat Intel Agent
- [ ] Response Agent chỉ **đề xuất** (kiểu dữ liệu chặt, allowlist hành động), mặc định dry-run
- [ ] Luồng duyệt: người duyệt + kiểm tra quyền + idempotency + audit + hướng dẫn rollback
- [ ] Test: chặn hành động trái phép đạt 100%, audit đủ 100% hành động phản ứng

## M7 — Dashboard React + TypeScript
- [ ] Khung dự án `frontend/` + client API
- [ ] Trang tổng quan, danh sách alert, incident + timeline
- [ ] Bản đồ MITRE, threat intel, hàng chờ duyệt, agent runs, audit logs
- [ ] Test frontend; chạy được qua Docker Compose

## M8 — Kịch bản demo, đánh giá, phát hành
- [ ] A: SSH brute-force → 1 incident
- [ ] B: PowerShell đáng ngờ (dữ liệu giả lành tính) + ngữ cảnh process cha–con
- [ ] C: Registry persistence trong VM Windows cô lập, có bước dọn dẹp
- [ ] D: Chuỗi tấn công nhiều giai đoạn, nhãn "synthetic" rõ ràng
- [ ] E: Prompt injection bị chặn
- [ ] Mỗi kịch bản có: kết quả phát hiện kỳ vọng, false positive dự kiến, dọn dẹp, test khẳng định
- [ ] `docs/evaluation.md`: precision/recall/F1, MITRE mapping, so sánh 3 cấu hình (rule / rule+correlation / +AI) với số đo thật
- [ ] `docs/threat-model.md`
- [ ] README đầy đủ, ảnh chụp màn hình, kịch bản demo ngắn
- [ ] Sao lưu/khôi phục database được ghi lại

## Tùy chọn (tuần 9–12)
- [ ] Threat Hunting Agent · Suricata · RAG knowledge base · thêm kịch bản/benchmark
