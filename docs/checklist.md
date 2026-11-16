# SentinelX - Checklist

Quy tắc: một mục chỉ được tick `[x]` khi (1) code xong, (2) test/lệnh xác nhận đã chạy và pass, (3) tài liệu liên quan đã cập nhật. Mỗi mục ghi rõ **Xác nhận bằng** gì. Số liệu đánh giá chỉ lấy từ lần chạy thật.

Cách dùng: làm xong một chức năng → chạy lệnh xác nhận → tick → commit.

---

## M1 - Lát cắt dọc đầu tiên (HOÀN THÀNH)
- [x] Cấu hình kiểm tra lúc khởi động - *Xác nhận:* app không chạy nếu thiếu/ngắn `SENTINELX_API_KEY`
- [x] Chuẩn hóa sshd auth + Sysmon EventID 1, che secret - *Xác nhận:* `pytest tests/test_normalize.py`
- [x] Lưu event idempotent (hash chống trùng) - *Xác nhận:* test `duplicate`, smoke test Docker
- [x] Rule SX-001 (SSH brute-force), SX-002 (PowerShell đáng ngờ) - *Xác nhận:* `pytest tests/test_api.py`
- [x] API `/health`, `POST /api/v1/events`, `GET /api/v1/alerts` + API key - *Xác nhận:* 401 không key, smoke test
- [x] 11 test pass trên SQLite và PostgreSQL 17; ruff, mypy sạch
- [x] Docker Compose chạy, db + backend healthy, backend non-root

---

## M1.5 - Sửa lỗi và nền tảng (CÒN 1 MỤC)
- [x] **Sửa race tạo alert song song** (advisory lock theo host trên Postgres)
  - *Xác nhận:* `test_concurrent_ingest_one_alert` pass 13/13 lần chạy trên Postgres; smoke test Compose 8 request song song → 8×200, 1 alert
- [x] **Sửa lỗi log đến sai thứ tự** (rule SX-001 xét cửa sổ hai phía) - lỗi phát hiện thêm trong lúc làm
  - *Xác nhận:* `test_out_of_order_arrival_still_alerts_with_full_evidence`
- [x] `docs/architecture.md` - sơ đồ Mermaid 5 lớp + luồng ingest, đánh dấu phần chưa làm
- [x] `docs/database-schema.md` - ER diagram, ràng buộc, bảng dự kiến
- [x] Thêm `graphify-out/`, `.codegraph/`, `.claude/` vào `.gitignore`
- [x] Rate limiting `POST /api/v1/events` (mặc định 600/phút/IP, cấu hình `SENTINELX_RATE_LIMIT_PER_MINUTE`)
  - *Xác nhận:* `test_rate_limit_returns_429`
- [x] GitHub Actions (`.github/workflows/ci.yml`): pytest SQLite + Postgres, ruff, mypy
  - *Đã viết, YAML hợp lệ, chưa chạy trên GitHub.* Tick khi CI xanh trên PR

## M2 - Migration và nguồn dữ liệu (nhánh `feat/m2-migrations-wazuh`) - XONG, chờ bạn review
- [x] Alembic + migration `0001` thay `create_all`
  - *Xác nhận:* `alembic upgrade head` → `downgrade base` → `upgrade head` + `alembic check` sạch trên Postgres 17; `test_migrations.py` so khớp migration với model (đã thử cố tình làm lệch schema, test phát hiện được); container Compose tự chạy migration khi khởi động
- [x] Bảng `assets` (hostname duy nhất, criticality 1–5, mặc định 3) + `security_events.asset_id`; tạo tự động ở lần đầu thấy host - *Xác nhận:* `test_asset_created_once_per_host`, smoke test Compose
- [x] Bảng `detection_rules` đồng bộ metadata từ code lúc khởi động, `enabled` do vận hành quyết định + `GET /api/v1/rules` - *Xác nhận:* `test_rules_listed_and_disabling_stops_alerts`
- [x] Sysmon event 3 (kết nối mạng), 12/13 (registry) - *Xác nhận:* fixture `tests/fixtures/sysmon_*.json`, `test_sysmon_*`
- [x] Đầu vào Wazuh alert JSON (`source: "wazuh"`, bọc Sysmon hoặc dòng sshd) - *Xác nhận:* `test_wazuh_*`, smoke test Compose (SX-002 kích hoạt qua Wazuh)
- [x] Cột `src_port`, `dst_ip`, `dst_port`, `registry_key`, `registry_value` cho event
- [x] Cập nhật `docs/database-schema.md`
- [x] **Sửa lỗi M1 phát hiện thêm:** secret ở cuối giá trị trong JSON làm hỏng JSON → event Sysmon bị từ chối 422 (mất event). Nay parse JSON trước rồi mới che từng giá trị. *Xác nhận:* `test_secret_in_json_payload_is_redacted_and_event_accepted`
- [ ] Công cụ đẩy alert Wazuh sang API (integration script) - *chưa làm*, hiện chỉ có định dạng nhận; cân nhắc ở M8/lab

## M3 — Bộ rule phát hiện (đủ 5–8 rule) — XONG, chờ bạn review (nhánh `feat/m3-detection-rules`)
- [x] SX-003 Tạo tài khoản local từ command line
- [x] SX-004 Thêm tài khoản vào nhóm Administrators
- [x] SX-005 Registry Run key persistence (T1547.001)
- [x] SX-006 Script host/LOLBin kết nối ra địa chỉ bên ngoài
- [x] SX-007 Office sinh ra shell/script host (quan hệ process cha–con)
- [x] SX-008 Thất bại nhiều lần rồi thành công (T1110 + T1078)
- [x] Mỗi rule có metadata (severity, MITRE, tham chiếu), case độc hại + lành tính, test — *Xác nhận:* `test_every_corpus_case_behaves_as_labeled`, `test_rule_metadata_and_docs`
- [x] Rule bật/tắt được — *Xác nhận:* `test_disabling_a_rule_stops_its_alerts` chạy cho cả 8 rule (đổi bằng SQL, chưa có API)
- [x] Alert dedup theo **cửa sổ thời gian** (thay vì mãi mãi) + cột `first_event_at`/`last_event_at`, migration `0002` có backfill — *Xác nhận:* `test_windowing.py`, `test_0002_backfills_alert_time_bounds_from_evidence`, Compose lên `0002`
- [x] Bộ corpus gán nhãn: **149 case** (80 độc hại, 69 lành tính, 294 event, 13 known gap) trong `backend/tests/corpus/`
- [x] `docs/detection-rules.md` mô tả từng rule, false positive dự kiến, known gap, bảng precision/recall
- [ ] *Ghi chú, không phải việc phải làm:* precision 1.00 / recall 0.75–0.91 là số **hồi quy trên dữ liệu tổng hợp do cùng một người viết**, không phải đánh giá thật. Recall dưới 0.85 ở SX-001/002/003/004/006 do các known gap cố ý. Đánh giá thật nằm ở M8

## M4 — Correlation, incident, risk engine — XONG, chờ bạn review (nhánh `feat/m4-correlation-risk`)
- [x] Gom alert thành incident theo host / IP (nguồn hoặc đích) / user / process trong cửa sổ thời gian (`correlation_window_seconds`, mặc định 3600 s) — *Xác nhận:* `test_same_attacker_ip_links_hosts`, `test_user_link_*`, `test_unusual_process_path_links_but_system_binary_does_not`, `test_alerts_far_apart_in_time_are_separate_incidents`
- [x] Chống tạo incident trùng — *Xác nhận:* `test_same_alert_activity_is_idempotent`; `incident_alerts.alert_id` là khóa chính (mỗi alert tối đa 1 incident)
- [x] Alert nối hai incident thì gộp lại; alert đến sai thứ tự vẫn gộp đúng — *Xác nhận:* `test_bridging_alert_merges_two_incidents`, `test_out_of_order_alert_arrival_*`
- [x] Timeline bằng chứng của incident — *Xác nhận:* `test_timeline_is_ordered_cited_and_capped`. **Quyết định:** không tạo bảng `incident_evidence` riêng, timeline suy ra từ `incident_alerts` + `alert_events` (không thể lệch dữ liệu)
- [x] Risk score 0–100 xác định (0.4·severity + 0.3·correlation + 0.2·TI + 0.1·asset), trọng số cấu hình được và bắt buộc tổng bằng 1 — *Xác nhận:* `tests/test_risk.py` (20 test, tính tay các ví dụ)
- [x] Xử lý dữ liệu thiếu (chưa có TI): bỏ thành phần đó và chuẩn hóa lại trọng số, không coi là 0; ghi chú giới hạn hiệu chuẩn trong `docs/correlation-and-risk.md`
- [x] API: `GET /api/v1/incidents`, `GET /api/v1/incidents/{id}` (risk_breakdown, entities, alerts kèm lý do gom, timeline); `incident_id` trong `/api/v1/alerts`
- [x] Chống race khi nhiều host tạo alert cùng lúc — *Xác nhận:* `test_concurrent_alerts_from_one_attacker_make_one_incident` (8 host đồng thời qua barrier); đã kiểm tra test **fail 4/5 lần khi tắt lock** và pass 5/5 khi bật
- [x] Backfill alert cũ chưa có incident khi khởi động — *Xác nhận:* `test_backfill_*`, và trong Compose: xóa bảng incident, restart, 2 incident + 4 liên kết được dựng lại
- [x] Migration `0003` — *Xác nhận:* `test_upgrade_matches_models_and_downgrade_is_clean` chạy trên Postgres
- [ ] *Ghi chú, không phải việc phải làm:* trọng số, thang điểm và danh sách user/đường dẫn "chung chung" là **ước lượng chưa hiệu chuẩn**. Cần incident gán nhãn từ lab (M8) mới đánh giá được độ đúng của điểm
- [ ] Chưa có API đóng incident / đổi criticality của asset (cần RBAC và audit, M6); hiện đổi bằng SQL

## Sửa lỗi từ /security-review toàn repo (nhánh `fix/security-review-findings`) — XONG, chờ bạn review
- [x] **Vuln 1 (High): username chứa `from <ip> port N` làm sai IP nguồn SSH** → kẻ tấn công đổi IP giả mỗi lần thử để né SX-001/SX-008 và đổ tội cho IP vô can. Sửa: regex neo cuối dòng, `.+` tham lam nuốt phần trước `from <ip> port N ssh2` thật. *Xác nhận:* `test_injected_username_cannot_change_source_ip_or_outcome`, `test_username_injection_does_not_evade_the_bruteforce_rule` (đã thấy fail trước khi sửa)
- [x] **Vuln 2 (Medium): event có trường quá dài bị bỏ bằng HTTP 500 trên Postgres** (đường dẫn process > 512 ký tự né mọi rule Windows). Sửa: `process_name`/`parent_process_name` thành `TEXT` (migration `0004`), `user` cắt còn 255, `host` > 255 trả 422 rõ ràng, `group_key` cắt 255, `DataError` của DB thành 422. *Xác nhận:* `tests/test_security.py` trên Postgres (đã fail trước khi sửa), smoke test Compose
- [ ] *Chưa làm:* `redact()` bỏ sót dạng không có `=`/`:` (ví dụ `-p mật_khẩu`); mức hardening, chưa phải lỗ hổng cụ thể

## M5 - AI điều tra (LLM chỉ giải thích) - phần mã XONG, còn thiếu adapter LLM thật
- [~] Nhà cung cấp LLM cấu hình được (`SENTINELX_LLM_PROVIDER=none|mock`, Compose truyền biến này) + **mock LLM**; **chưa có adapter LLM thật** (giao diện `LLM.complete(system, user, timeout)` đã sẵn)
- [x] Triage → Investigation là **LangGraph** có giới hạn: 2 node nối thẳng, đúng 2 lời gọi model, không vòng lặp (`recursion_limit` 10). *Xác nhận:* `test_the_workflow_is_a_fixed_two_step_graph_with_two_model_calls`
- [x] Đầu ra kiểm tra bằng Pydantic; mọi nhận định trích dẫn **alert/event id** (id của incident không được tính là bằng chứng). *Xác nhận:* `test_unsupported_claims_are_dropped_and_the_incident_id_is_not_evidence` (đã thử phá mã: test fail)
- [x] Đầu ra có `confidence`, `uncertainties`, `likely_techniques` (phải là technique rule đã gán cho incident và có trích dẫn), `scope` host/user/IP **suy ra từ incident, không lấy từ model**. *Xác nhận:* `test_techniques_*`, `test_scope_is_derived_*`
- [x] Provenance và đo lường mỗi run: `provider`, `model`, `prompt_version`, `input_sha256`, `duration_ms` (migration `0006`). *Xác nhận:* `test_run_is_stored_with_cited_claims_scope_and_provenance`, migration giữ nguyên run cũ trên Postgres
- [x] Bảng `agent_runs` lưu mỗi lần chạy
- [x] Hệ thống vẫn phát hiện và chấm điểm khi LLM tắt - *Xác nhận:* `test_ai_off_still_detects_and_scores_and_investigate_is_503`, Compose mặc định `none` trả 503
- [x] Test prompt injection: nội dung log là dữ liệu, tool call trái phép bị từ chối và ghi audit; **mọi** dạng tool call (quá dài, không phải object, quá nhiều, không phải list) đều được ghi trong giới hạn mà không làm hỏng run
- [x] Test claim không có bằng chứng bị loại (unsupported-claim)
- [x] Không đưa secret vào prompt - *Xác nhận:* test redaction trước khi gửi LLM
- [x] Lỗi không rò rỉ: `error` chỉ chứa tên lớp exception hoặc đường dẫn schema, không có thông điệp của provider (có thể chứa khóa API) hay nội dung model. *Xác nhận:* `test_failures_are_recorded_without_leaking_provider_or_model_text`
- [x] Chi phí/độ bền: rate limit riêng cho `POST /investigate` (mặc định 10/phút/IP), `timeout` truyền cho provider (mặc định 30 s), văn bản tư vấn bị cắt chứ không làm fail run
- [ ] Adapter LLM thật (Ollama hoặc API) — cần khi muốn dùng thật; phải tự áp `timeout`, và cân nhắc cảnh báo riêng tư khi gửi dữ liệu ra ngoài
- [ ] Đánh giá chất lượng AI (evidence accuracy, hallucination) với dữ liệu lab — thuộc M8; hiện chỉ kiểm tra được *id có tồn tại*, chưa kiểm tra *câu có đúng*

## M6 - Threat intel, phản ứng, phân quyền (làm theo 3 lát cắt, mỗi lát một PR)

### 6A - RBAC và audit log — XONG, chờ bạn review (nhánh `feat/m6a-rbac-audit`)
- [x] RBAC: bảng `users`, `auth_tokens`, 4 vai trò cố định (viewer, analyst, approver, admin) + vai trò `service` cho API key dùng chung; đăng nhập bằng mật khẩu (scrypt) ra bearer token chỉ lưu hash. *Xác nhận:* `tests/test_auth.py` (14 test)
  - API key dùng chung **vẫn còn** cho collector (`ingest`) và client cũ nhưng không thể đề xuất/duyệt/quản trị; người dùng đăng nhập bằng token. Chưa "thay hẳn" key vì collector cần một credential máy
- [x] Tạo admin đầu tiên bằng CLI (`python -m app.manage create-user`), mật khẩu không nằm trên dòng lệnh
- [x] **Mỗi route khai báo quyền cần có**; test chạy *mọi route* với *mọi loại người gọi* (ẩn danh, token sai, service, 4 vai trò) và fail nếu có route thiếu khai báo. *Xác nhận:* `tests/test_authz_matrix.py`; đã thử phá 5 chỗ (bỏ check quyền, không commit audit, thêm route không khai báo, bearer sai rơi về API key, cấp thừa quyền) và test fail mỗi lần
- [x] `audit_logs`: đăng nhập thành công/thất bại, đăng xuất, tạo/sửa user, **mọi lần bị từ chối quyền của người đã xác thực** (khớp 100% trong test ma trận), mỗi lần chạy AI investigate; không có route nào sửa/xóa audit
- [x] Mật khẩu/token không bao giờ vào audit hay response — *Xác nhận:* `test_passwords_and_tokens_never_reach_audit_logs_or_responses`
- [ ] Audit log của **hành động phản ứng** — thuộc lát 6C
- [ ] *Chưa làm (ghi trong `docs/security-model.md`):* audit bất biến ở mức database, khóa tài khoản, đổi mật khẩu qua API, MFA

### 6B - Threat intel — chưa làm
- [ ] Bảng IOC cục bộ + cache
- [ ] Adapter VirusTotal / AbuseIPDB (tùy chọn): timeout, rate limit, cảnh báo riêng tư trước khi gửi ngoài, không bịa dữ liệu
- [ ] Threat Intel Agent; đưa điểm TI vào risk score

### 6C - Phản ứng có duyệt — chưa làm
- [ ] Response Agent chỉ **đề xuất** (kiểu dữ liệu chặt, allowlist hành động), mặc định dry-run
- [ ] Luồng duyệt: người duyệt + kiểm tra quyền + idempotency + audit + hướng dẫn rollback
- [ ] Test: chặn hành động trái phép đạt 100%, audit đủ 100% hành động phản ứng

## M7 - Dashboard React + TypeScript
- [ ] Khung dự án `frontend/` + client API
- [ ] Trang tổng quan, danh sách alert, incident + timeline
- [ ] Bản đồ MITRE, threat intel, hàng chờ duyệt, agent runs, audit logs
- [ ] Test frontend; chạy được qua Docker Compose

## M8 - Kịch bản demo, đánh giá, phát hành
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
