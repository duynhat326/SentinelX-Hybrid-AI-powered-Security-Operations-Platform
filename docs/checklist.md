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
- [x] Audit log của **hành động phản ứng** — xong ở lát 6C
- [ ] *Chưa làm (ghi trong `docs/security-model.md`):* audit bất biến ở mức database, khóa tài khoản, đổi mật khẩu qua API, MFA

### 6B - Threat intel — XONG, chờ bạn review (nhánh `feat/m6b-threat-intel`)
- [x] Bảng `iocs` (IOC cục bộ `manual` + cache của provider có `expires_at`); chuẩn hóa chỉ báo IP/domain/SHA-256 và từ chối mọi thứ có thể làm sai URL provider. *Xác nhận:* `test_indicators_are_normalized`, `test_anything_that_could_alter_a_provider_url_is_rejected`, `test_manual_ioc_lifecycle_*`
- [x] Adapter VirusTotal và AbuseIPDB: timeout, rate limit riêng mỗi provider, không theo redirect, lỗi/sai định dạng → `unavailable` và **không lưu gì**; VirusTotal 404 là `not_found`, không phải "sạch". *Xác nhận:* 10 kịch bản lỗi trong `test_provider_failures_*`, `test_unknown_to_virustotal_*`, `test_each_provider_has_its_own_rate_limit_*`
- [x] **Cảnh báo riêng tư trước khi gửi ra ngoài:** mặc định tắt (`SENTINELX_TI_EXTERNAL_ENABLED=false`) + mỗi request phải có `confirm_external=true` (không có thì 409 kèm cảnh báo và không gửi gì) + chỉ địa chỉ public được gửi; mỗi lần gọi ngoài được audit (ai, provider, chỉ báo, kết quả; không có khóa). *Xác nhận:* `test_external_*`, `test_private_reserved_*`, `test_a_confirmed_lookup_*`, `test_secrets_never_appear_*`
- [x] Không bịa dữ liệu và không chép chữ của provider (summary dựng từ con số). *Xác nhận:* `test_provider_text_never_reaches_*`
- [x] Threat Intel Agent = `POST /api/v1/incidents/{id}/enrich` (code xác định, không cần LLM): tra IP của incident (tối đa 10), lấy từ bảng/cache trước
- [x] Điểm TI vào risk score: điểm cao nhất còn hạn của các IP trong incident; **không có verdict = thiếu (chuẩn hóa lại), verdict 0 = "đã kiểm tra, sạch" và hạ điểm**; thêm/xóa IOC chấm lại ngay các incident đang mở; `GET incident` có `intel`. *Xác nhận:* `test_stored_intelligence_moves_the_risk_score_*` (44 → 55 → 44 → 35), `test_an_incident_without_any_address_*`
- [x] Quyền: `enrich` (analyst+), `manage_iocs` (approver, admin); ma trận phân quyền phủ 5 route mới. Migration `0008`
- [x] Đã phá 11 chỗ (bỏ xác nhận, gửi IP private, bỏ công tắc, 404 thành sạch, chép chữ provider, theo redirect, ghi khóa vào audit, bỏ audit, thiếu thành 0 hai kiểu, bỏ rate limit) và test fail mỗi lần
- [ ] **Chưa gọi API thật của VirusTotal/AbuseIPDB**: adapter theo tài liệu công khai, chỉ test bằng transport giả. Cần thử với khóa tạm trước khi tin vào định dạng phản hồi
- [ ] *Chưa làm:* dữ liệu MITRE ATT&CK cục bộ, nhập feed IOC, làm mới định kỳ; `risk_score` đã lưu có thể cũ cho tới lần tính lại kế tiếp khi một verdict hết hạn

### 6C - Phản ứng có duyệt — XONG, chờ bạn review (nhánh `feat/m6c-response-actions`)
- [x] Hành động **có kiểu, allowlist là một union** (blocklist cục bộ, yêu cầu chặn IP, yêu cầu cô lập host, báo cáo); không loại nào mang lệnh/URL, trường lạ bị từ chối. *Xác nhận:* `test_only_typed_allowlisted_actions_are_accepted` (14 dạng body xấu)
- [x] Chỉ hai loại có thể chạy thật (blocklist cục bộ, báo cáo) và vẫn nằm trong SentinelX; chặn firewall và cô lập host **chỉ mô phỏng**. Công tắc `SENTINELX_RESPONSE_REAL_ACTIONS_ENABLED` mặc định tắt: duyệt = **dry-run** (`result.would`)
- [x] Policy kiểm tra lúc đề xuất **và lại lúc duyệt**: địa chỉ phải public, phải nằm trong bằng chứng của incident, không thuộc danh sách bảo vệ (`SENTINELX_PROTECTED_IPS`, gõ sai thì không khởi động), chưa bị chặn; host phải thuộc incident và là asset đã biết
- [x] Duyệt cần quyền `approve` + **người khác** người đề xuất **và người đã yêu cầu gợi ý** (cột `triggered_by`: không ai tự duyệt thứ mình đã bảo agent đưa ra); duyệt/từ chối/rollback đều lặp lại an toàn; khóa hàng khi quyết định; `Idempotency-Key` (cùng khóa khác nội dung = 409; replay sau khi policy đổi vẫn trả bản gốc)
- [x] Rollback blocklist (hủy kích hoạt, cho phép đề xuất lại); loại khác trả `rollback_guidance`
- [x] **Audit đủ 100%:** mỗi chuyển trạng thái và mỗi lần từ chối đúng số dòng audit. *Xác nhận:* `test_each_state_change_and_refusal_leaves_exactly_the_audit_rows_it_should` (19 bước, mỗi bước kiểm số dòng chính xác)
- [x] **Chặn trái phép 100% trong bộ test đã định nghĩa:** ma trận phân quyền phủ 8 route mới; test từ chối cho từng loại vi phạm (tự duyệt, người yêu cầu gợi ý duyệt, analyst duyệt, real khi tắt công tắc, real cho loại chỉ mô phỏng, policy đổi sau khi đề xuất)
- [x] Response Agent: chế độ policy (xác định, không cần LLM) và chế độ AI: đầu ra model là **không tin cậy**, phải khớp allowlist (còn lại bị bỏ và đếm), qua cùng policy (địa chỉ/host ngoài incident bị từ chối, kể cả khi log bảo model làm vậy); chỉ tạo **đề xuất**, không bao giờ chạy. *Xác nhận:* `test_model_proposals_are_untrusted_*`, `test_log_text_that_tries_to_steer_the_agent_*`
- [x] An toàn khi chạy song song (Postgres): 6 người duyệt cùng lúc → thực thi đúng 1 lần; 6 đề xuất cùng khóa → 1 dòng. Đã **phá khóa hàng và xử lý trùng khóa: test fail 3/3**, giữ nguyên thì pass 3/3 (bản đầu của test chưa chứng minh gì nên đã viết lại với cửa sổ race được mở rộng)
- [x] Gộp incident chuyển hành động và run AI sang incident còn lại (FK `RESTRICT` chặn xóa incident đang có hành động). Migration `0009`
- [x] Đã phá 16 chỗ (bỏ bốn-mắt, chỉ chặn người đề xuất, bỏ công tắc, firewall chạy thật, không kiểm policy lúc duyệt, bỏ policy lúc đề xuất, cho trường lạ, bỏ audit khi duyệt, không commit lúc từ chối, bỏ rollback, quên chuyển hành động khi gộp, duyệt hai lần, báo cáo không escape, bỏ idempotency, bỏ khóa hàng, bỏ xử lý trùng khóa) và test fail mỗi lần
- [ ] **Chưa chạy với firewall, EDR hay hệ thống ticket thật**: blocklist chỉ là dữ liệu, SentinelX không chặn lưu lượng. Bốn-mắt so sánh tên tài khoản (hai tài khoản của một người vượt được)
- [ ] *Chưa làm:* kết nối firewall/EDR (nếu làm phải là loại hành động mới trong allowlist, mô phỏng trước), UI duyệt (M7), hết hạn cho đề xuất treo

## M7 - Dashboard React + TypeScript — XONG, chờ bạn review (nhánh `feat/m7-dashboard`)
- [x] Khung `frontend/` (Vite, React 19, TypeScript strict, không thư viện UI/biểu đồ) + client API có kiểu; đăng nhập bằng bearer token, phiên hết hạn đưa về trang đăng nhập. *Xác nhận:* `src/__tests__/api.test.ts`, `app.test.tsx`
- [x] Trang tổng quan (số liệu **chính xác** từ endpoint `/api/v1/overview` mới, biểu đồ có ghi số, không chỉ màu), danh sách alert, incident + trang chi tiết (phân tích điểm risk, thực thể, TI, lý do gom alert, **timeline bằng chứng** kèm số alert trích dẫn)
- [x] Bản đồ MITRE theo tactic (chỉ đặt tên cho các technique mà rule gán, còn lại hiện là "Unmapped", không đoán). *Xác nhận:* `mitre.test.ts`
- [x] Threat intel (bảng IOC, tra cứu, thêm/xóa IOC), hàng chờ duyệt, agent runs (`/api/v1/agent-runs` mới), audit log (chỉ admin)
- [x] Giao diện **ẩn điều khiển theo quyền** (quyền lấy từ `/api/v1/auth/me`, không sao chép bảng quyền) nhưng server vẫn quyết định. *Xác nhận:* test cho viewer, analyst, approver
- [x] **Xác nhận trước khi gửi ra ngoài** (hộp thoại cảnh báo của server; hủy thì không gửi gì), "Run for real" mặc định không tick, `Idempotency-Key` mỗi form
- [x] Chống XSS: không dùng `dangerouslySetInnerHTML`; nội dung log thù địch hiện thành chữ (test); báo cáo hiện trong `<pre>`
- [x] Test frontend: 27 test (Vitest + Testing Library); `tsc --strict` và build sạch. Đã phá 11 chỗ (hiện mọi điều khiển cho mọi vai trò, gửi TI không hỏi, render HTML, tick sẵn "real", key mới mỗi lần, không phát hiện hết phiên, token vào localStorage, từ chối không cần lý do, MITRE tự đặt tên, router nhận id sai, link audit cho mọi người) và test fail mỗi lần
- [x] Chạy được qua Docker Compose: nginx không root (uid 101), CSP chặt, proxy `/api`, job CI cho frontend. Đã kiểm tra trên trình duyệt thật với dữ liệu mẫu: đăng nhập, tổng quan, chi tiết incident, duyệt dry-run, MITRE, bố cục điện thoại không tràn ngang, console không lỗi dưới CSP, header `X-Forwarded-For` giả bị bỏ qua
- [x] Ảnh chụp màn hình trong `docs/screenshots/` (dữ liệu lab mẫu), tài liệu `docs/dashboard.md`
- [ ] **Chưa kiểm tra với trình đọc màn hình** và chưa kiểm tra trên trình duyệt khác ngoài trình duyệt trong app; không phải kiểm toán accessibility
- [ ] *Chưa làm:* ESLint, phân trang (danh sách giới hạn 200), cập nhật trực tiếp (phải tải lại), token trong HttpOnly cookie (cần backend hỗ trợ), quản lý người dùng trong giao diện (dùng CLI/API)

## M8 - Kịch bản demo, đánh giá, phát hành
- [x] A: SSH brute-force → 1 incident (`lab/scenarios`, `test_scenarios.py`)
- [x] B: PowerShell đáng ngờ (dữ liệu giả lành tính) + ngữ cảnh process cha–con
- [x] C: Registry persistence: fixture đã có test; *các bước trên VM Windows thật (kèm dọn dẹp `reg delete`) đã ghi trong `lab/scenarios/README.md` nhưng chưa chạy*
- [x] D: Chuỗi tấn công nhiều giai đoạn, nhãn "synthetic" rõ ràng (cần rule mới SX-009 + Sysmon event 11, migration 0010)
- [x] E: Prompt injection bị chặn (cần provider lab `mock-adversarial`; rủi ro còn lại được ghi rõ trong README kịch bản)
- [x] Mỗi kịch bản có: kết quả phát hiện kỳ vọng, false positive dự kiến, dọn dẹp, test khẳng định
- [ ] `docs/evaluation.md`: precision/recall/F1, MITRE mapping, so sánh 3 cấu hình (rule / rule+correlation / +AI) với số đo thật
- [ ] `docs/threat-model.md`
- [ ] README đầy đủ, ảnh chụp màn hình, kịch bản demo ngắn
- [ ] Sao lưu/khôi phục database được ghi lại

## Tùy chọn (tuần 9–12)
- [ ] Threat Hunting Agent · Suricata · RAG knowledge base · thêm kịch bản/benchmark
