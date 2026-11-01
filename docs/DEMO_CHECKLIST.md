# PRIVACYGUARD: CHECKLIST CHUẨN BỊ VÀ THỰC HIỆN QUAY VIDEO DEMO

Tài liệu này cung cấp danh sách kiểm tra từng bước dành cho người quay video demo 5 phút, nhằm đảm bảo quy trình ghi hình diễn ra mượt mà, ổn định và không làm ảnh hưởng đến cơ sở dữ liệu kiểm chuẩn của dự án.

---

## 1. GIAI ĐOẠN 1: TRƯỚC KHI QUAY (PRE-RECORDING)

### 1.1. Dọn dẹp ứng dụng và tiến trình nền
- [ ] Đóng toàn bộ các tab trình duyệt cũ đang mở cổng `8501`, `8765`, `8443`.
- [ ] Tắt toàn bộ các tiến trình Python nền cũ (Streamlit, Tray App, Leaker cũ):
  ```powershell
  # Kiểm tra và dừng tiến trình Streamlit cũ nếu có
  Get-Process streamlit -ErrorAction SilentlyContinue | Stop-Process -Force
  ```
- [ ] Kiểm tra cổng `8765`, `8443`, và `8501` đang ở trạng thái rảnh:
  ```powershell
  Get-NetTCPConnection -LocalPort 8501, 8765, 8443 -ErrorAction SilentlyContinue
  ```
  *(Nếu không có dòng nào xuất hiện tức là cổng hoàn toàn rảnh).*

### 1.2. Môi trường hiển thị và quay màn hình
- [ ] **Độ phân giải**: Đặt màn hình chính ở độ phân giải tiêu chuẩn `1920 x 1080` (Full HD), tỷ lệ hiển thị `100%`.
- [ ] **Cỡ chữ**: Tăng cỡ chữ trong VS Code và trình duyệt lên `110% – 120%` (Ctrl + +) để người xem video có thể đọc rõ từng dòng code và chỉ số.
- [ ] **Tắt thông báo Windows**: Bật chế độ **Focus Assist** (hoặc **Do Not Disturb**) trên Windows 10 để tránh các pop-up thông báo cá nhân, email, Zalo, Teams xuất hiện bất ngờ khi đang quay.
- [ ] **Âm thanh & Micro**: Kiểm tra micro thử giọng trước 10 giây để đảm bảo âm lượng to, rõ ràng, không bị rè hoặc có tiếng ồn quạt máy.

### 1.3. Sao lưu cơ sở dữ liệu và xác thực Preflight
- [ ] Tạo bản sao lưu an toàn cho cơ sở dữ liệu chuẩn:
  ```powershell
  Copy-Item "data\privacyguard.db" "data\privacyguard.db.bak_demo"
  ```
- [ ] Chạy script kiểm tra điều kiện tiên quyết (Preflight):
  ```powershell
  # Chạy trong PowerShell với quyền Administrator
  .\scripts\demo_preflight.ps1
  ```
  *(Xác nhận toàn bộ 6 hạng mục đều báo màu xanh `[PASS]`).*
- [ ] Xuất gói bằng chứng kiểm chứng mới nhất:
  ```powershell
  .\.venv\Scripts\python.exe scripts\export_demo_evidence.py
  ```

### 1.4. (Tùy chọn) Chuẩn bị nếu muốn Live Demo kích hoạt tấn công
> [!CAUTION]
> **QUY TẮC BẮT BUỘC**: Tuyệt đối **KHÔNG ĐƯỢC CHẠY** kịch bản tấn công trực tiếp trên tệp cơ sở dữ liệu chuẩn `data/privacyguard.db` vì sẽ làm sai lệch bộ 8 cảnh báo gốc (#170–#177).

- [ ] Nếu cần quay phân cảnh kích hoạt tấn công thời gian thực (Live Attack), phải sao chép DB chuẩn ra tệp tạm `data/demo.db`:
  ```powershell
  Copy-Item "data\privacyguard.db" "data\demo.db"
  ```
- [ ] Khi chạy kịch bản, **CHỈ DÙNG** lệnh chỉ định rõ `--db data\demo.db`:
  ```powershell
  # Chạy trên data/demo.db (KHÔNG dùng run_phase3_mitre.ps1 vì script đó trỏ vào DB chuẩn)
  .\.venv\Scripts\python.exe scripts\run_mitre_scenarios.py --db data\demo.db --port 8765 --alt-port 8443
  ```

---

## 2. GIAI ĐOẠN 2: TRONG KHI QUAY (DURING RECORDING)

- [ ] **Bám sát kịch bản thời gian**:
  - `0:00 – 0:30`: Mở đầu & vấn đề rò rỉ dữ liệu.
  - `0:30 – 1:30`: Kiến trúc Sysmon ETW & 5 cổng Hard Gates.
  - `1:30 – 2:30`: Báo cáo Benign Workload (121.94 phút, 0/1.000 windows).  
    *Nhớ đọc đúng câu bắt buộc*: *"0/1.000 windows trong 121.94 phút; toàn bộ benign bị lọc ở gate 0.5/2, nên final decision layer chưa được benign traffic kiểm chứng."*
  - `2:30 – 4:00`: Trực quan hóa 3 cảnh báo MITRE #175, #176, #177 và nút chặn tường lửa 1-click.
  - `4:00 – 4:30`: Đối soát kỹ thuật (`bytes_diff = 0`, 100% authentic Sysmon, manifest hash).
  - `4:30 – 5:00`: Minh bạch giới hạn hệ thống (Localhost, T1048 DNS gap) & lời chào Q&A.
- [ ] **Bảo vệ quyền riêng tư**:
  - Tuyệt đối không mở các thư mục cá nhân thật (`Desktop`, `Downloads`, `Documents`, `C:\Users\...`).
  - Mọi thao tác tệp chỉ thực hiện trong `data/FakeDocuments`.
- [ ] **Thao tác chuột**:
  - Di chuyển chuột dứt khoát, chậm rãi; không lắc hoặc rê chuột liên tục gây rối mắt.
  - Khi nói về số liệu nào, trỏ hoặc bôi đen nhẹ vùng số liệu đó 1–2 giây để người xem chú ý.
- [ ] **Phương án dự phòng (Fallback)**:
  - Nếu Dashboard bị chậm hoặc không mở được, ngay lập tức chuyển sang mở tệp [`results/MITRE_REPORT.md`](../results/MITRE_REPORT.md) và [`results/demo_export/manifest.json`](../results/demo_export/manifest.json) trên VS Code để tiếp tục thuyết minh liền mạch.

---

## 3. GIAI ĐOẠN 3: SAU KHI QUAY (POST-RECORDING)

- [ ] Tắt dashboard hoặc các dịch vụ Streamlit đang chạy nền:
  ```powershell
  Get-Process streamlit -ErrorAction SilentlyContinue | Stop-Process -Force
  ```
- [ ] Nếu đã tạo `data/demo.db` cho live demo, hãy xóa tệp này để tránh nhầm lẫn:
  ```powershell
  Remove-Item "data\demo.db" -ErrorAction SilentlyContinue
  Remove-Item "data\demo.db*" -ErrorAction SilentlyContinue
  ```
- [ ] Kiểm tra và xác nhận cơ sở dữ liệu chuẩn `data/privacyguard.db` vẫn nguyên vẹn 100% với đúng 8 cảnh báo (#170–#177):
  ```powershell
  .\.venv\Scripts\python.exe -c "import sqlite3; conn = sqlite3.connect('file:data/privacyguard.db?mode=ro', uri=True); ids = [r[0] for r in conn.execute('SELECT id FROM alerts ORDER BY id ASC').fetchall()]; print('Alerts in DB:', ids); assert ids == [170, 171, 172, 173, 174, 175, 176, 177], 'Mismatch!'; print('[OK] Database completely intact!')"
  ```
- [ ] Chạy lại bộ kiểm thử để đảm bảo 91 test tiếp tục PASS:
  ```powershell
  .\.venv\Scripts\python.exe -m pytest -q
  ```
- [ ] Xóa bản sao lưu tạm `data\privacyguard.db.bak_demo` nếu không còn nhu cầu sử dụng:
  ```powershell
  Remove-Item "data\privacyguard.db.bak_demo" -ErrorAction SilentlyContinue
  ```
