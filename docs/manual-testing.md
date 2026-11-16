# Hướng dẫn test từ đầu đến cuối

Hướng dẫn này đi từ máy trống đến một hệ thống chạy đủ: dựng stack, tạo người dùng, nạp dữ liệu mẫu, đi qua dashboard theo từng vai trò, thử hành động phản ứng (dry-run rồi chạy thật), AI (mock) và threat intelligence, rồi chạy bộ test tự động. Mỗi bước có **kết quả mong đợi**; các con số bên dưới là kết quả thật của một lần chạy với dữ liệu mẫu trong repo (có thể lệch vài đơn vị nếu bạn đổi dữ liệu).

Mọi thứ dùng dữ liệu **tổng hợp** (host, user, địa chỉ giả hoặc thuộc dải tài liệu RFC 5737). Không có gì thực thi lệnh tấn công và không gửi gì ra Internet.

## 0. Cần có
- Docker (đang chạy) và `docker compose`. Cần `openssl` và `python3` (có sẵn trên hầu hết Linux/macOS).
- Chỉ để chạy test tự động: `uv` (backend) và Node 22 trở lên (frontend).
- Các cổng `8080` (dashboard) và `8000` (API, chỉ mở trên loopback) phải trống.

## 1. Dựng hệ thống
Từ thư mục gốc repo:
```bash
cp .env.example .env
sed -i "s/^SENTINELX_API_KEY=.*/SENTINELX_API_KEY=$(openssl rand -hex 24)/; s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 12)/" .env
sed -i "s/^SENTINELX_LLM_PROVIDER=.*/SENTINELX_LLM_PROVIDER=mock/" .env
```
Dòng thứ ba bật AI **giả lập** (mock) để thử phần điều tra AI; bỏ nó nếu không cần. Rồi:
```bash
docker compose up --build -d
docker compose ps
```
**Mong đợi:** sau khoảng 20–60 giây cả `db`, `backend`, `frontend` đều `healthy`. Lần build đầu mất vài phút vì tải image.
```bash
curl -s localhost:8000/health        # {"status":"ok"}
```
Mở <http://localhost:8080>: thấy trang đăng nhập SentinelX.

## 2. Tạo người dùng
Không có tài khoản mặc định. Tạo năm tài khoản dùng chung một mật khẩu thử nghiệm do bạn chọn (tối thiểu 12 ký tự; chỉ dùng cho lab cục bộ này, đừng dùng mật khẩu thật):
```bash
read -r -s -p 'Chọn mật khẩu thử nghiệm: ' PW; echo
for u in "admin1 admin" "appr1 approver" "appr2 approver" "ana1 analyst" "view1 viewer"; do
  set -- $u; echo "$PW" | docker compose exec -T backend .venv/bin/python -m app.manage create-user $1 $2 --password-stdin
done
```
**Mong đợi:** năm dòng `ok`. Cần **hai** approver (`appr1`, `appr2`) để thử quy tắc "người khác duyệt".

| Tài khoản | Vai trò | Được làm gì |
|---|---|---|
| `view1` | viewer | chỉ xem |
| `ana1` | analyst | xem, đề xuất hành động, tra cứu threat intel, chạy điều tra AI |
| `appr1`, `appr2` | approver | như analyst, thêm duyệt/từ chối/rollback và ghi IOC |
| `admin1` | admin | như approver, thêm đọc audit log và quản lý người dùng |

## 3. Nạp dữ liệu mẫu
```bash
export SENTINELX_API_KEY=$(grep '^SENTINELX_API_KEY=' .env | cut -d= -f2)
python3 lab/seed_demo.py
```
**Mong đợi:**
```
Sent 20 synthetic events. Alerts raised: SX-001 x2, SX-002 x1, SX-003 x1, SX-004 x1, SX-005 x1, SX-006 x1, SX-007 x1, SX-008 x1
```
Ba kịch bản: **A** dò mật khẩu SSH từ `203.0.113.50` vào `web01` và `db01` rồi một lần đăng nhập thành công; **B** Word mở `cmd` và PowerShell mã hóa trên `ws-fin-02`; **C** tài khoản admin cục bộ mới, Run key và `mshta` gọi ra ngoài trên `win10-lab`. Chạy **một lần** trên stack mới (chạy lại sẽ thêm một bộ event nữa).

## 4. Đi qua dashboard theo từng vai trò
Đăng nhập tại <http://localhost:8080> bằng tên tài khoản ở bảng trên và mật khẩu bạn đã chọn (tab riêng tư/ẩn danh giúp đổi tài khoản dễ hơn; "Sign out" ở góc phải).

### 4.1 Viewer (`view1`): chỉ xem
1. **Overview:** `20` events ingested, `3` open incidents, `0` actions awaiting approval, `0` blocklisted addresses. Biểu đồ "Alerts by severity": critical 1, high 6, medium 2, low 0 (con số ghi bên cạnh thanh, không chỉ màu). "Open incidents by severity": critical 1, high 2.
2. **Incidents:** ba incident, xếp theo risk: **81** high (`win10-lab`, 4 alerts), **69** critical (`db01`, `web01`, 3 alerts), **56** high (`ws-fin-02`, 2 alerts).
3. Mở incident **69 critical** (hai incident còn lại có timeline 4 và 2 event; cột "Grouped because" của chúng là `user:carol` và `user:dave`). Kiểm tra: bảng "How the risk score is made" (threat intel hiện `unknown`, "not used": thiếu thì bị bỏ chứ không tính là 0), "Involved" (host, IP, MITRE T1078 và T1110), bảng Alerts với cột "Grouped because" (`seed`, rồi `ip:203.0.113.50`: hai host được gộp vì cùng địa chỉ tấn công), **Timeline** (14 event: 7 + 6 lần thất bại và 1 lần thành công; mỗi dòng ghi "cited by N alert(s)").
4. **MITRE:** các technique chia theo tactic (ví dụ T1110 Brute Force dưới Credential Access, T1078 xuất hiện dưới nhiều tactic).
5. **Quyền hạn:** trong trang incident **không** có ô "Propose an action", nút "Run AI investigation" hay "Look up this incident's addresses". Menu không có "Audit log".

### 4.2 Analyst (`ana1`): đề xuất, nhưng không duyệt
1. Mở incident **69 critical**. Cuộn tới "Response actions" → bấm **Suggest (policy)**. **Mong đợi:** "2 proposed, 0 already proposed, 0 refused by policy": gồm *Add to blocklist* `203.0.113.50` và *Generate report*, cả hai do `policy` yêu cầu, "asked for by user:ana1".
2. Mở incident **81 high** (win10-lab) → **Suggest (policy)**. **Mong đợi:** 2 proposed (blocklist `198.51.100.7` và report) và **1 refused by policy**: `10.0.0.5: the address is not public ...`. Policy chỉ cho đề xuất địa chỉ công khai và nằm trong bằng chứng của incident.
3. Thử đề xuất sai: ở "Propose an action" chọn *Add to blocklist* và gõ lý do, bấm **Propose** → thành công (trạng thái `proposed`). Bấm **Propose** thêm lần nữa **không** tạo bản thứ hai (cùng `Idempotency-Key`).
4. Bấm **Run AI investigation**. **Mong đợi:** một dòng `mock/mock-1 · ok · confidence low`; mở ra thấy kết luận có trích dẫn id và dòng "Advisory only. 0 claim(s) dropped...". Nếu bạn không bật `mock` trong `.env`, bạn sẽ thấy lỗi "AI investigation is disabled (SENTINELX_LLM_PROVIDER=none)": đó là hành vi đúng.
5. Bấm **Suggest (AI)**. **Mong đợi:** "0 proposed": mock không đề xuất gì (AI thật mới đề xuất; mọi đề xuất của AI đều bị kiểm tra như của người).
6. **Quyền hạn:** các hành động `proposed` **không** có nút Approve/Reject (analyst không có quyền `approve`). Trang **Threat intel** có ô "Look up an indicator" nhưng **không** có "Add to the local IOC table".
7. **Hàng chờ:** trang **Approvals** liệt kê các đề xuất đang chờ.

### 4.3 Approver (`appr1`): duyệt, bốn mắt
1. Trang **Approvals**: các đề xuất của analyst đang chờ. Mở một đề xuất blocklist. Ô "Run for real" **không tick sẵn**.
2. **Bốn mắt:** ở incident **69 critical**, tự đề xuất một hành động (ví dụ *Generate report*) rồi bấm **Approve (dry run)** trên đề xuất của chính bạn. **Mong đợi:** lỗi đỏ `a different person must approve: nobody approves a proposal they made or asked for`. Điều tương tự áp dụng cho đề xuất mà bạn *nhờ policy hoặc AI tạo ra*.
3. **Dry-run:** bấm **Approve (dry run)** trên đề xuất blocklist do `ana1` tạo. **Mong đợi:** trạng thái `simulated`, nhãn `dry run`; bấm "Show what happened" → `Would: add 203.0.113.50 to the local blocklist`. Trang Overview vẫn ghi `0 blocklisted addresses`: dry-run không thay đổi gì.
4. **Chạy thật khi công tắc tắt:** với một đề xuất khác, tick "Run for real" rồi **Approve and run**. **Mong đợi:** `real actions are disabled (SENTINELX_RESPONSE_REAL_ACTIONS_ENABLED=false): approve as a dry run`, và đề xuất vẫn `proposed`.
5. **Từ chối:** nút **Reject** bị khóa cho tới khi bạn gõ lý do; gõ rồi bấm → trạng thái `rejected`.
6. **Threat intel:** trang Threat intel có thêm "Add to the local IOC table". Thêm `203.0.113.50`, score `90`, lý do bất kỳ. Quay lại incident **69 critical**: risk tăng **69 → 73**, dòng threat intel giờ là `90` và được dùng; mục "Threat intelligence" liệt kê `203.0.113.50 scored 90/100 by manual`. Xóa IOC (nút Remove) thì risk trở về 69.
7. Tra cứu: ở trang Threat intel nhập `203.0.113.50` → `found`, nguồn `manual`. Nhập `10.0.0.5` hoặc `8.8.8.8` → `not_found` (đúng: chưa cấu hình nhà cung cấp nào nên không có nguồn nào để hỏi).

### 4.4 Admin (`admin1`): audit
Trang **Audit log** (chỉ admin thấy). Lọc `Outcome = denied` để xem mọi lần bị từ chối, `Action = response.approve` để xem lịch sử duyệt. **Mong đợi** sau các bước trên: các dòng `auth.login`, `user.create`, `response.suggest`, `response.propose`, `response.approve` (cả `ok` và `denied`), `response.execute`, `ioc.create`, `agent.investigate`, và `authz.denied` mỗi lần có người bấm thứ họ không được phép. Mật khẩu và token **không bao giờ** xuất hiện trong cột Detail.

## 5. Hành động thật, blocklist và rollback
Mặc định duyệt chỉ là mô phỏng. Bật hiệu lực thật (chỉ trong SentinelX: một dòng blocklist hoặc một báo cáo; **không** có gì chặn lưu lượng, và chặn firewall/cô lập host luôn chỉ là mô phỏng):
```bash
sed -i "s/^SENTINELX_RESPONSE_REAL_ACTIONS_ENABLED=.*/SENTINELX_RESPONSE_REAL_ACTIONS_ENABLED=true/" .env
docker compose up -d        # tạo lại backend với cấu hình mới
```
1. `ana1` đề xuất **mới** *Add to blocklist* `203.0.113.50` ở incident 69 (đề xuất đã duyệt dry-run **không** nâng cấp được thành chạy thật; phải đề xuất lại).
2. `appr2` tick "Run for real" → **Approve and run**. **Mong đợi:** `executed`; Overview: `1 blocklisted addresses`.
3. Đề xuất blocklist cùng địa chỉ lần nữa → bị từ chối: `the address is already on the blocklist`.
4. Đề xuất *Isolate host* và duyệt với "Run for real" → `request_host_isolation can only be simulated` (duyệt dry-run thì được).
5. Duyệt *Generate report* với "Run for real" → `executed`; "Show what happened" hiện báo cáo markdown (khoảng 40 dòng) trong khung `<pre>`.
6. Ở đề xuất blocklist đã `executed`, bấm **Roll back (remove from blocklist)** → `rolled_back`; Overview về `0 blocklisted`. Có thể đề xuất lại địa chỉ đó.
7. Rollback một hành động chỉ mới `simulated` → báo `there is nothing to roll back automatically` kèm "It was approved as a dry run, so nothing was changed...".

**Danh sách địa chỉ được bảo vệ (tùy chọn):** đặt `SENTINELX_PROTECTED_IPS=203.0.113.0/24` trong `.env`, `docker compose up -d`, rồi đề xuất blocklist `203.0.113.50` → bị từ chối `the address is on the protected list`.

## 6. Kiểm tra nhanh bằng dòng lệnh
```bash
curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/api/v1/overview            # 401: chưa đăng nhập
curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/api/v1/users \
  -H "X-API-Key: $SENTINELX_API_KEY"                                                # 403: API key dùng chung không quản trị được
curl -sI localhost:8080/ | grep -iE 'content-security|x-frame|x-content-type'      # có Content-Security-Policy, DENY, nosniff
curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/api/v1/auth/login \
  -H 'content-type: application/json' -H 'X-Forwarded-For: 6.6.6.6' \
  -d '{"username":"nobody1","password":"wrong wrong wrong"}'                        # 401; header giả không được tin (audit ghi IP thật)
```
Giới hạn đăng nhập: gửi liên tiếp hơn 10 lần đăng nhập sai trong một phút thì lần thứ 11 trở đi trả `429`.

Đề xuất một "lệnh" bị từ chối vì không có loại hành động nào mang lệnh:
```bash
curl -s localhost:8080/api/v1/auth/login -H 'content-type: application/json' -d "{\"username\":\"ana1\",\"password\":\"$PW\"}"   # lấy token
# dùng token trong header Authorization: Bearer <token>, gửi {"type":"run_shell","command":"id"} tới
# /api/v1/incidents/<id>/response-actions  ->  422
```

## 7. Những gì không thể test thủ công ở đây
- **VirusTotal và AbuseIPDB thật.** Muốn thử cần khóa API thật, bật `SENTINELX_TI_EXTERNAL_ENABLED=true` và mỗi lần tra cứu phải xác nhận. **Cảnh báo:** làm vậy gửi địa chỉ/miền/hash bạn đang điều tra cho bên thứ ba, và các adapter **chưa từng được chạy với dịch vụ thật** (chỉ test với HTTP giả). Luồng "xác nhận trước khi gửi" được test tự động (xem mục 8), không cần khóa thật.
- **LLM thật.** Chưa có adapter nào; `mock` là bản giả lập offline.
- **Firewall/EDR/ticket thật.** Chưa có; blocklist chỉ là dữ liệu.
- Trình đọc màn hình và các trình duyệt khác chưa được thử.

## 8. Test tự động
Backend (SQLite, không cần Docker):
```bash
cd backend && uv sync && uv run pytest -q          # 214 passed, 5 skipped
```
Backend trên PostgreSQL (cần Docker; chạy cả các test chạy song song, mất khoảng 2 phút):
```bash
docker run -d --name sx-pg -e POSTGRES_PASSWORD=pgtest -e POSTGRES_DB=sx -p 55432:5432 postgres:17-alpine
SENTINELX_TEST_DATABASE_URL=postgresql+psycopg://postgres:pgtest@localhost:55432/sx uv run pytest -q   # 219 passed
docker rm -f sx-pg
```
Frontend:
```bash
cd frontend && npm ci && npm run typecheck && npm test && npm run build     # 27 passed
```
Nên chú ý các test này vì chúng là thứ duy nhất kiểm tra những tình huống không bấm tay được: luồng xác nhận trước khi gửi ra ngoài, lỗi provider (timeout, 429, sai định dạng), 6 người duyệt cùng lúc chỉ thực thi một lần, log chứa mã HTML/chỉ dẫn tấn công model. Bộ corpus 149 case của các rule nằm ở `backend/tests/corpus/`.

## 9. Dọn dẹp
```bash
docker compose down -v      # xóa cả dữ liệu (database)
```

## 10. Khi có sự cố
| Hiện tượng | Nguyên nhân thường gặp | Cách xử lý |
|---|---|---|
| `service "backend" is not running` ngay sau `up` | backend chờ database khỏe nên chưa chạy kịp | chờ 20–60 giây, `docker compose ps` |
| Backend báo lỗi xác thực database sau khi đổi `POSTGRES_PASSWORD` | volume cũ giữ mật khẩu cũ | `docker compose down -v` rồi `up` lại (xóa dữ liệu) |
| Đăng nhập bị `429` | quá 10 lần/phút | chờ một phút |
| Dashboard trắng hoặc báo lỗi mạng | backend chưa healthy | `docker compose logs backend` |
| `seed_demo.py`: `Set SENTINELX_API_KEY first` | chưa `export` khóa | chạy lại lệnh `export` ở mục 3 |
| Cổng 8080/8000 đã bị dùng | dịch vụ khác | tắt dịch vụ đó hoặc đổi cổng trong `docker-compose.yml` |
| Thấy "AI investigation is disabled" | `SENTINELX_LLM_PROVIDER=none` | đặt `mock` trong `.env` rồi `docker compose up -d` |
