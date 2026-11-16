# Quy trình test từ đầu đến cuối

Một tài liệu duy nhất cho mọi việc kiểm tra SentinelX, theo thứ tự từ rẻ đến đắt. Mỗi bước có **kết quả mong đợi**; các con số là kết quả thật của lần chạy gần nhất với dữ liệu trong repo (có thể lệch vài đơn vị nếu bạn đổi dữ liệu). Nếu một bước không ra như mô tả, dừng ở đó và xem mục "Khi có sự cố".

Mọi dữ liệu đều **tổng hợp** (host, người dùng, địa chỉ giả hoặc thuộc dải tài liệu RFC 5737). Không có gì thực thi lệnh tấn công và không gửi gì ra Internet.

| Giai đoạn | Cần Docker | Thời gian | Mục đích |
|---|:-:|---|---|
| 1. Tự động: backend, frontend | không | ~1 phút | hồi quy toàn bộ logic |
| 2. Tự động: PostgreSQL | có (1 container) | ~2,5 phút | hành vi chỉ khác trên Postgres (khóa, đồng thời) |
| 3. Dựng stack và tạo người dùng | có | ~5 phút lần đầu | hệ thống chạy thật |
| 4. Dashboard theo từng vai trò (dữ liệu mẫu) | có | ~20 phút | quyền hạn, bốn mắt, dry-run, audit |
| 5. Hành động thật, blocklist, rollback | có | ~10 phút | công tắc an toàn |
| 6. Kịch bản A–E (stack sạch) | có | ~5 phút | phát hiện, gom incident, prompt injection |
| 7. Đánh giá (evaluation) | không | ~2 phút | tái tạo số liệu trong `evaluation.md` |
| 8. Sao lưu và khôi phục | có | ~5 phút | dữ liệu không mất |
| 9. Kiểm tra bảo mật nhanh | có | ~5 phút | header, 401/403, giới hạn tốc độ |
| 10. Demo 5 phút | có | 5 phút | trình bày |

## 0. Cần có
- Docker (đang chạy) và `docker compose`; `openssl` và `python3`.
- `uv` (backend) và Node 22 trở lên (frontend), cho giai đoạn 1 và 2.
- Cổng `8080` (dashboard) và `8000` (API, chỉ mở trên loopback) phải trống.

## 1. Test tự động (không cần Docker)
```bash
cd backend
uv sync
uv run ruff check .                       # All checks passed
uv run mypy app                           # Success: no issues found
uv run pytest -q                          # 226 passed, 5 skipped (5 test cần PostgreSQL)
cd ../frontend
npm ci && npm run typecheck && npm test && npm run build     # 27 test pass, build thành công
```
Những test này kiểm tra những thứ không bấm tay được: luồng xác nhận trước khi gửi ra ngoài, lỗi nhà cung cấp (timeout, 429, sai định dạng), quyền của **mọi** route, log chứa HTML hoặc chỉ dẫn tấn công model, bộ corpus 171 case của 9 rule (`backend/tests/corpus/`) và 10 test kịch bản A–E (`tests/test_scenarios.py`).

## 2. Test trên PostgreSQL
Chạy cả các test chỉ có nghĩa trên Postgres (nhiều người duyệt cùng lúc chỉ thực thi một lần, khóa tương quan, `DataError`):
```bash
docker run -d --name sx-pg -e POSTGRES_PASSWORD=pgtest -e POSTGRES_DB=sx -p 55432:5432 postgres:17-alpine
cd backend
SENTINELX_TEST_DATABASE_URL=postgresql+psycopg://postgres:pgtest@localhost:55432/sx uv run pytest -q   # 231 passed
```
Giữ container này cho giai đoạn 7; xóa ở cuối bằng `docker rm -f sx-pg`.

## 3. Dựng stack và tạo người dùng
Từ thư mục gốc repo. Nếu đã có stack cũ chứa dữ liệu bạn không cần, `docker compose down -v` trước (**xóa database**).
```bash
cp .env.example .env
sed -i "s/^SENTINELX_API_KEY=.*/SENTINELX_API_KEY=$(openssl rand -hex 24)/; s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 12)/" .env
sed -i "s/^SENTINELX_LLM_PROVIDER=.*/SENTINELX_LLM_PROVIDER=mock/" .env     # AI giả lập, để thử phần điều tra AI
docker compose up --build -d
docker compose ps
```
**Mong đợi:** sau 20–60 giây `db`, `backend`, `frontend` đều `healthy` (lần build đầu mất vài phút). `curl -s localhost:8000/health` trả `{"status":"ok"}`; <http://localhost:8080> hiện trang đăng nhập tối của SentinelX.

Không có tài khoản mặc định. Tạo năm tài khoản dùng chung một mật khẩu thử nghiệm do bạn chọn (tối thiểu 12 ký tự; chỉ cho lab cục bộ này):
```bash
read -r -s -p 'Chọn mật khẩu thử nghiệm: ' PW; echo
for u in "admin1 admin" "appr1 approver" "appr2 approver" "ana1 analyst" "view1 viewer"; do
  set -- $u; echo "$PW" | docker compose exec -T backend .venv/bin/python -m app.manage create-user $1 $2 --password-stdin
done
```
**Mong đợi:** năm dòng `ok`. Cần **hai** approver để thử quy tắc "người khác duyệt".

| Tài khoản | Vai trò | Được làm gì |
|---|---|---|
| `view1` | viewer | chỉ xem |
| `ana1` | analyst | xem, đề xuất hành động, tra cứu threat intel, chạy điều tra AI |
| `appr1`, `appr2` | approver | như analyst, thêm duyệt, từ chối, rollback và ghi IOC |
| `admin1` | admin | như approver, thêm đọc audit log và quản lý người dùng |

## 4. Dashboard theo từng vai trò (dữ liệu mẫu)
```bash
export SENTINELX_API_KEY=$(grep '^SENTINELX_API_KEY=' .env | cut -d= -f2)
python3 lab/seed_demo.py
```
**Mong đợi:** `Sent 20 synthetic events. Alerts raised: SX-001 x2, SX-002 x1, SX-003 x1, SX-004 x1, SX-005 x1, SX-006 x1, SX-007 x1, SX-008 x1`. Ba kịch bản: **A** dò mật khẩu SSH từ `203.0.113.50` vào `web01` và `db01` rồi đăng nhập thành công; **B** Word mở `cmd` và PowerShell mã hóa trên `ws-fin-02`; **C** tài khoản admin mới, Run key và `mshta` gọi ra ngoài trên `win10-lab`. Chạy **một lần** (chạy lại thêm một bộ event nữa). **Đừng chạy giai đoạn 6 trên stack đã nạp dữ liệu mẫu**: các kịch bản cần stack sạch (xem giai đoạn 6).

Đăng nhập tại <http://localhost:8080> (tab ẩn danh giúp đổi tài khoản dễ hơn; "Sign out" ở góc phải). Giao diện có chế độ sáng và tối theo hệ điều hành; font SF Compact chỉ hiện nếu thư mục `frontend/public/fonts/` có trên máy bạn khi build, nếu không dashboard dùng font hệ thống (vẫn đúng chức năng).

### 4.1 Viewer (`view1`): chỉ xem
1. **Overview:** hero tối "SentinelX" với bốn bước Detect, Investigate, Understand, Respond; bên dưới `20` events ingested, `3` open incidents, `0` actions awaiting approval, `0` blocklisted addresses. "Alerts by severity": critical 1, high 6, medium 2, low 0 (con số ghi bên cạnh thanh, không chỉ màu).
2. **Incidents:** ba incident theo risk: **81** high (`win10-lab`, 4 alerts), **69** critical (`db01`, `web01`, 3 alerts), **56** high (`ws-fin-02`, 2 alerts).
3. Mở incident **69 critical**: bảng "How the risk score is made" (threat intel `unknown`, "not used": thiếu thì bị bỏ chứ không tính là 0), "Involved" (host, IP, MITRE T1078 và T1110), bảng Alerts với cột "Grouped because" (`seed`, rồi `ip:203.0.113.50`: hai host gộp vì cùng địa chỉ tấn công), **Timeline** 14 event (mỗi dòng ghi "cited by N alert(s)").
4. **MITRE:** technique chia theo tactic (T1110 dưới Credential Access, T1078 dưới nhiều tactic).
5. **Quyền hạn:** trang incident **không** có "Propose an action", "Run AI investigation" hay "Look up this incident's addresses"; menu không có "Audit log".

### 4.2 Analyst (`ana1`): đề xuất, không duyệt
1. Incident **69 critical** → "Response actions" → **Suggest (policy)**. **Mong đợi:** "2 proposed, 0 already proposed, 0 refused by policy" (*Add to blocklist* `203.0.113.50` và *Generate report*, do `policy` yêu cầu, "asked for by user:ana1").
2. Incident **81 high** → **Suggest (policy)**: 2 proposed (blocklist `198.51.100.7` và report) và **1 refused by policy**: `10.0.0.5: the address is not public ...`.
3. "Propose an action" → *Add to blocklist*, gõ lý do, **Propose** → `proposed`. Bấm thêm lần nữa **không** tạo bản thứ hai (cùng `Idempotency-Key`).
4. **Run AI investigation:** `mock/mock-1 · ok · confidence low`, kết luận có trích dẫn id và dòng "Advisory only. 0 claim(s) dropped...". Nếu `.env` không bật `mock` sẽ thấy "AI investigation is disabled (SENTINELX_LLM_PROVIDER=none)": đúng hành vi.
5. **Suggest (AI):** "0 proposed" (mock không đề xuất gì).
6. **Quyền hạn:** hành động `proposed` **không** có nút Approve/Reject; trang Threat intel có "Look up an indicator" nhưng **không** có "Add to the local IOC table". Trang **Approvals** liệt kê các đề xuất đang chờ.

### 4.3 Approver (`appr1`): duyệt, bốn mắt
1. **Approvals** → mở một đề xuất blocklist. Ô "Run for real" **không tick sẵn**.
2. **Bốn mắt:** tự đề xuất một *Generate report* rồi **Approve (dry run)** chính đề xuất đó. **Mong đợi:** lỗi `a different person must approve: nobody approves a proposal they made or asked for`. Cũng áp dụng cho đề xuất mà bạn *nhờ policy hoặc AI tạo ra*.
3. **Dry-run:** **Approve (dry run)** đề xuất blocklist của `ana1` → `simulated`, nhãn `dry run`; "Show what happened" → `Would: add 203.0.113.50 to the local blocklist`. Overview vẫn `0 blocklisted addresses`.
4. **Chạy thật khi công tắc tắt:** tick "Run for real" → **Approve and run** → `real actions are disabled (SENTINELX_RESPONSE_REAL_ACTIONS_ENABLED=false): approve as a dry run`; đề xuất vẫn `proposed`.
5. **Từ chối:** **Reject** bị khóa tới khi gõ lý do; gõ rồi bấm → `rejected`.
6. **Threat intel:** thêm IOC `203.0.113.50`, score `90`. Incident **69 critical**: risk **69 → 73**, dòng threat intel giờ là `90` và được dùng. Xóa IOC (Remove) thì về 69.
7. Tra cứu `203.0.113.50` → `found` (nguồn `manual`); `10.0.0.5` hoặc `8.8.8.8` → `not_found` (chưa cấu hình nhà cung cấp nào).

### 4.4 Admin (`admin1`): audit
**Audit log** (chỉ admin thấy). Lọc `Outcome = denied` để xem mọi lần bị từ chối, `Action = response.approve` cho lịch sử duyệt. **Mong đợi:** `auth.login`, `user.create`, `response.suggest`, `response.propose`, `response.approve` (cả `ok` và `denied`), `ioc.create`, `agent.investigate`, và `authz.denied` mỗi lần bấm thứ không được phép. Mật khẩu và token **không bao giờ** xuất hiện trong cột Detail.

## 5. Hành động thật, blocklist và rollback
Mặc định duyệt chỉ mô phỏng. Bật hiệu lực thật (chỉ trong SentinelX: một dòng blocklist hoặc một báo cáo; **không** có gì chặn lưu lượng, còn chặn firewall và cô lập host luôn chỉ là mô phỏng):
```bash
sed -i "s/^SENTINELX_RESPONSE_REAL_ACTIONS_ENABLED=.*/SENTINELX_RESPONSE_REAL_ACTIONS_ENABLED=true/" .env
docker compose up -d        # tạo lại backend với cấu hình mới
```
1. `ana1` đề xuất **mới** *Add to blocklist* `203.0.113.50` ở incident 69 (đề xuất đã duyệt dry-run **không** nâng cấp được thành thật; phải đề xuất lại).
2. `appr2` tick "Run for real" → **Approve and run** → `executed`; Overview `1 blocklisted addresses`.
3. Đề xuất cùng địa chỉ lần nữa → từ chối `the address is already on the blocklist`.
4. *Isolate host* với "Run for real" → `request_host_isolation can only be simulated` (dry-run thì được).
5. *Generate report* với "Run for real" → `executed`; "Show what happened" hiện báo cáo markdown trong khung `<pre>`.
6. Đề xuất blocklist đã `executed` → **Roll back** → `rolled_back`; Overview `0 blocklisted`.
7. Rollback một hành động chỉ mới `simulated` → `there is nothing to roll back automatically` kèm "It was approved as a dry run, so nothing was changed...".

**Địa chỉ được bảo vệ (tùy chọn):** đặt `SENTINELX_PROTECTED_IPS=203.0.113.0/24`, `docker compose up -d`, đề xuất blocklist `203.0.113.50` → `the address is on the protected list`.

## 6. Kịch bản A–E (stack sạch)
Năm kịch bản tổng hợp, mỗi cái có host và địa chỉ riêng. Chúng **không** gộp với nhau, nhưng có thể bị gộp với dữ liệu mẫu hoặc với lần chạy trước (cùng người dùng, địa chỉ, cửa sổ thời gian), và chạy lại làm cộng dồn số lần thất bại. Vì vậy: **stack sạch, chạy một lần**.
```bash
docker compose down -v
sed -i "s/^SENTINELX_LLM_PROVIDER=.*/SENTINELX_LLM_PROVIDER=mock-adversarial/" .env   # chỉ cho kịch bản E; model giả này nghe theo prompt injection
docker compose up -d --build
# tạo lại người dùng như giai đoạn 3 nếu muốn xem trên dashboard
python3 lab/scenarios/run.py all --check
```
**Mong đợi:** mỗi kịch bản in `[PASS]` cho từng kỳ vọng (phát hiện đúng tập rule, baseline lành tính không tạo alert, một incident đúng host, đúng MITRE); D thêm `risk score 94`; E thêm ba dòng về công cụ bị từ chối (`delete_incident`, `run_shell`, `<invalid>`), 5 claim/technique bị loại, `scope` lấy từ incident và severity, risk, status không đổi. Tổng cộng 25 dòng `[PASS]`, không có `[FAIL]`. Mở dashboard xem incident của D (nhiều alert, hai host `jump01` và `ws-d01`, timeline 10 event) và của E (rồi **Suggest (AI)**: không tạo gì). Chi tiết từng kịch bản, false positive dự kiến và dọn dẹp: [lab/scenarios/README.md](../lab/scenarios/README.md). Xong thì đặt lại `SENTINELX_LLM_PROVIDER=mock` (hoặc `none`).

## 7. Đánh giá (tái tạo số liệu)
Dữ liệu tổng hợp do chính tác giả viết: đây là phép đo hồi quy và thiết kế, không phải độ chính xác thực tế ([evaluation.md](evaluation.md)).
```bash
cd backend
uv run python -m evaluation.run                 # detection, campaigns, guardrails; ghi docs/evaluation-results.json
```
**Mong đợi:** precision 1.00, recall 0.83 trên 171 case; 63 episode, 117 alert gom thành 63 incident; AUROC 0.55 → 0.72; guardrail: 0 đề xuất độc hại được tạo, 0 incident bị đổi. Ba phần đầu cho **đúng cùng số** mỗi lần (seed cố định). Phần `system` cần server đang chạy và phụ thuộc máy:
```bash
uv run python -m evaluation.run --only system --live http://127.0.0.1:8000 --key "$SENTINELX_API_KEY"
```
(Với Compose, tăng `SENTINELX_RATE_LIMIT_PER_MINUTE` trước khi đo, nếu không 1.000 request sẽ chạm giới hạn 600/phút.) Lệnh sẽ ghi đè phần tương ứng trong `docs/evaluation-results.json`: dùng `git diff` để xem, `git checkout` để hoàn lại nếu không muốn giữ.

## 8. Sao lưu và khôi phục
Làm theo [operations.md](operations.md): `pg_dump`, khôi phục vào database mới, so số dòng `security_events`, `alerts`, `incidents`. **Mong đợi:** số dòng bằng nhau; `docker compose exec backend .venv/bin/alembic current` (trên bản khôi phục) báo head `0010`.

## 9. Kiểm tra bảo mật nhanh
```bash
curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/api/v1/overview            # 401: chưa đăng nhập
curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/api/v1/users \
  -H "X-API-Key: $SENTINELX_API_KEY"                                                # 403: khóa dùng chung không quản trị được
curl -sI localhost:8080/ | grep -iE 'content-security|x-frame|x-content-type'      # có CSP, DENY, nosniff
curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/api/v1/auth/login \
  -H 'content-type: application/json' -H 'X-Forwarded-For: 6.6.6.6' \
  -d '{"username":"nobody1","password":"wrong wrong wrong"}'                        # 401; header giả không được tin (audit ghi IP thật)
```
Gửi liên tiếp hơn 10 lần đăng nhập sai trong một phút thì lần thứ 11 trả `429`. Đề xuất một "lệnh" bị từ chối vì không loại hành động nào mang lệnh: đăng nhập `ana1`, lấy token, gửi `{"type":"run_shell","command":"id"}` tới `/api/v1/incidents/<id>/response-actions` → `422`.

## 10. Demo 5 phút
1. **Nạp và định hướng (30 s).** Stack sạch, `python3 lab/seed_demo.py`, đăng nhập. Overview cho số đếm chính xác, alert và incident theo severity, incident rủi ro cao nhất. Nói: *"Chưa có mô hình ngôn ngữ nào được dùng."*
2. **Một câu chuyện, không phải tám alert (60 s).** Mở incident 69 (đăng nhập SSH sau nhiều lần thất bại): chỉ vào *Grouped because* (`ip:203.0.113.50`), timeline từ lần thất bại đầu đến lần thành công, bảng risk (threat intel "unknown, not used", không bao giờ "clean"). Nếu muốn nhấn mạnh chuỗi nhiều giai đoạn, dùng stack sạch và `python3 lab/scenarios/run.py D` (giai đoạn 6).
3. **MITRE (20 s).** Technique theo tactic, chỉ những cái rule gán.
4. **Phản ứng cần hai người (60 s).** Analyst *Suggest (policy)*; cùng người đó thử duyệt: bị từ chối; approver duyệt: **dry run** ghi rõ *would*. Admin mở audit log: mọi bước và mọi lần từ chối đều có.
5. **AI giải thích (45 s).** *Run AI investigation*: mỗi kết luận trích dẫn id bằng chứng, có confidence và uncertainties. Nói: *"Nó không đổi được điểm số và không hành động được."*
6. **Prompt injection (60 s, model giả).** Với `mock-adversarial`: `python3 lab/scenarios/run.py E --check`. Các lời gọi công cụ bị từ chối và ghi lại, claim vô căn cứ bị loại, severity và risk không đổi, *Suggest (AI)* không tạo gì. Nói thẳng về rủi ro còn lại: một claim trích dẫn bằng chứng thật nhưng chứa lời độc hại vẫn hiện như lời khuyên, và người dùng không được làm theo.
7. **Kết (15 s).** [evaluation.md](evaluation.md): dữ liệu tổng hợp, cái gì đã và chưa đo.

## 11. Những gì không thể test ở đây
- **VirusTotal và AbuseIPDB thật.** Cần khóa thật, `SENTINELX_TI_EXTERNAL_ENABLED=true` và xác nhận mỗi lần tra cứu. **Cảnh báo:** làm vậy gửi địa chỉ, miền hoặc hash bạn đang điều tra cho bên thứ ba, và adapter **chưa từng chạy với dịch vụ thật** (chỉ test với HTTP giả). Luồng "xác nhận trước khi gửi" được test tự động (giai đoạn 1).
- **LLM thật** (chưa có adapter), **firewall, EDR hoặc ticket thật** (chưa có; blocklist chỉ là dữ liệu).
- **Kịch bản C trên VM Windows thật** (các bước nằm trong `lab/scenarios/README.md`, chưa chạy).
- Trình đọc màn hình, các trình duyệt khác, độ tương phản chữ trên nền tối bằng công cụ.

## 12. Dọn dẹp
```bash
docker compose down -v        # xóa cả database
docker rm -f sx-pg            # container test Postgres (giai đoạn 2)
```

## Khi có sự cố
| Hiện tượng | Nguyên nhân thường gặp | Cách xử lý |
|---|---|---|
| `service "backend" is not running` ngay sau `up` | backend chờ database khỏe | chờ 20–60 giây, `docker compose ps` |
| Backend lỗi xác thực database sau khi đổi `POSTGRES_PASSWORD` | volume cũ giữ mật khẩu cũ | `docker compose down -v` rồi `up` lại (xóa dữ liệu) |
| Đăng nhập bị `429` | quá 10 lần/phút | chờ một phút |
| Dashboard trắng hoặc lỗi mạng | backend chưa healthy | `docker compose logs backend` |
| `seed_demo.py` hoặc `run.py`: `Set SENTINELX_API_KEY first` | chưa `export` khóa | chạy lại lệnh `export` ở giai đoạn 4 |
| Kịch bản báo `[FAIL]` | stack không sạch, chạy lần hai, hoặc E thiếu `mock-adversarial` | `docker compose down -v`, đặt đúng provider, chạy lại một lần |
| Cổng 8080 hoặc 8000 đã bị dùng | dịch vụ khác | tắt nó hoặc đổi cổng trong `docker-compose.yml` |
| "AI investigation is disabled" | `SENTINELX_LLM_PROVIDER=none` | đặt `mock` rồi `docker compose up -d` |
| Dashboard không có font SF | `frontend/public/fonts/` không có khi build | bình thường; chép font vào rồi `docker compose up -d --build frontend` |
