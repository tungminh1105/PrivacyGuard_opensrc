# BÁO CÁO ĐO LƯỜNG TỶ LỆ BÁO ĐỘNG GIẢ (FALSE POSITIVE RATE - FPR)

> **Môi trường đo lường**: Windows 10 Pro (Build 19045, Windows-10-10.0.19045-SP0) (PowerShell Administrator Elevated)  
> **Thời gian bắt đầu**: `2026-10-31T21:43:23.224861`  
> **Thời gian kết thúc**: `2026-10-31T23:45:19.883812`  
> **Tổng thời lượng đo**: **121.9 phút** (2.03 giờ)  
> **Cơ sở dữ liệu**: `D:\KERNAL PROTECT\privacyguard\data\privacyguard.db`  
> **Kết luận tổng thể**: **PASS**  

---

## 1. TỔNG KẾT KẾT QUẢ ĐO LƯỜNG THỰC TẾ

| Chỉ số đo lường | Giá trị thực nghiệm | Tiêu chuẩn chấp nhận | Kết luận |
| :--- | :---: | :---: | :---: |
| **Thời lượng kiểm chứng liên tục** | **121.9 phút** | >= 120 phút | **ĐẠT** |
| **Tổng sự kiện Sysmon thật nạp** | **+34,632 sự kiện** | > 0 (Đọc live liên tục) | **ĐẠT** |
| **Tổng cửa sổ trượt đã đánh giá** | **73,531 windows** | > 0 windows | **ĐẠT** |
| **Cảnh báo giả sinh ra (False Positives)**| **0 alert** | 0 cảnh báo rác | **ĐẠT (0 alert rác)** |
| **FPR trên 1,000 cửa sổ đánh giá** | **0.0000** | < 1.0 per 1k windows | **XUẤT SẮC (0.00)** |
| **Tần suất báo động sai theo giờ** | **0.0000 alerts/h** | < 0.5 alert/giờ | **XUẤT SẮC (0.00)** |

---

## 2. SO SÁNH VỚI ĐỘ NHẠY PHÁT HIỆN TẤN CÔNG THẬT (TPR BENCHMARK)

### A. Tỷ lệ phát hiện tấn công thật (True Positive Rate - TPR): **5/5 (100%)**
Toàn bộ 5 lần tấn công dữ liệu thật từ Scenario 1 (Phase 0.6) đều kích hoạt cảnh báo tức thời, trích xuất đúng GUID Sysmon, đúng PID độc lập và đúng dung lượng từ TCP Receiver:

| Alert ID | Sysmon Process GUID | PID | Dung lượng Exfil | Đích đến | Tệp tin phát hiện | Kết luận |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| #170 | `{db9fa507-a81a-6ae4-2131-000000007e00}` | 14916 | 187814 bytes | 127.0.0.1:8765 | `ho_so_tai_chinh_temp.xlsx` | **Phát hiện (True Positive)** |
| #171 | `{db9fa507-a828-6ae4-6031-000000007e00}` | 11572 | 150722 bytes | 127.0.0.1:8765 | `ho_so_tai_chinh_temp.xlsx` | **Phát hiện (True Positive)** |
| #172 | `{db9fa507-a836-6ae4-9731-000000007e00}` | 3104 | 153329 bytes | 127.0.0.1:8765 | `ho_so_tai_chinh_temp.xlsx` | **Phát hiện (True Positive)** |
| #173 | `{db9fa507-a841-6ae4-c231-000000007e00}` | 9188 | 210419 bytes | 127.0.0.1:8765 | `ho_so_tai_chinh_temp.xlsx` | **Phát hiện (True Positive)** |
| #174 | `{db9fa507-a84d-6ae4-ff31-000000007e00}` | 16132 | 164202 bytes | 127.0.0.1:8765 | `ho_so_tai_chinh_temp.xlsx` | **Phát hiện (True Positive)** |


### B. Tỷ lệ cảnh báo sai trên tải làm việc lành tính (FPR): **0.0000**
Trong khoảng thời gian làm việc bình thường (văn phòng, lập trình, kiểm thử unit test, duyệt web), hệ thống ghi nhận:

| Alert ID | Tiến trình | Process GUID | PID | Dung lượng | Đích đến | Tệp tin | Verdict |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| - | - | *(Không có cảnh báo nào trong suốt thời gian đo)* | - | - | - | - | **0 False Alarms** |


---

## 3. PHÂN TÍCH PHỄU LỌC ĐA CỔNG (MULTI-STAGE FUNNEL BREAKDOWN)

Trong suốt thời gian đo, tổng cộng **73,531 cửa sổ** được sinh ra từ telemetry Sysmon thật và được phân loại qua các cổng bảo vệ:

| Cổng bảo vệ | Số lượng cửa sổ xử lý | Tỷ lệ (%) | Ý nghĩa kỹ thuật |
| :--- | :---: | :---: | :--- |
| **Tổng cửa sổ trượt (Windows Created)** | **73,531** | 100.0% | Tổng các cửa sổ 60s có hoạt động tiến trình |
| - *Cổng 0: Không có proc_key hợp lệ* | 0 | 0.0% | Sự kiện hệ thống thiếu GUID |
| - *Cổng 0.5: Tiến trình không trực tiếp gây sự kiện* | 66,361 | 90.2% | Tiến trình tổ tiên chỉ spawn process con |
| - *Cổng 1: Tiến trình trong danh sách bỏ qua (Noise)* | 0 | 0.0% | PrivacyGuard, Streamlit, Collector nội bộ |
| - *Cổng 2: Không có quan hệ nhân quả (Đọc -> Gửi)* | 7,170 | 9.8% | Hoạt động mạng bình thường không kèm đọc file |
| - *Cổng 3: Dung lượng dưới ngưỡng min_exfil_bytes* | 0 | 0.0% | Gói tin TCP handshake, ACK, heartbeat nhỏ |
| - *Cổng 4: Không chạm vào tài liệu nhạy cảm* | 0 | 0.0% | Tiến trình xử lý file log, binary thông thường |
| - *Cổng 4.5: Điểm bất thường dưới ngưỡng (Score < 0.70)* | 0 | 0.0% | Hành vi nằm trong phân phối bình thường |
| - *Cổng 5: Khử trùng lặp (Dedup / Cooldown 600s)* | 0 | 0.0% | Cùng một incident đã được phát cảnh báo |
| **[+] CẢNH BÁO TẠO THÀNH CÔNG (Alerts)** | **0** | **0.00%** | Cảnh báo đạt chuẩn an ninh mức độ Cao |

---

## 4. NHẬT KÝ WORKLOAD LÀNH TÍNH ĐÃ THỰC HIỆN

Tải làm việc lành tính được tạo tự động bởi `scripts/benign_workload.py` song song với các hoạt động bình thường của người dùng:
- **Tổng số hành động ghi nhận trong khoảng thời gian chạy**: 36 hành vi
- **doc_lifecycle**: 10 hành động
- **git_ops**: 12 hành động
- **pytest_test**: 6 hành động
- **web_download**: 8 hành động

- Các hành động văn phòng tạo tệp `.docx`, sao chép vào `Downloads`, nén và giải nén zip kích hoạt Sysmon Event 11 trong thư mục người dùng nhưng **không** tạo cảnh báo do không phát sinh lưu lượng exfiltration ngoại mạng.

---

## 5. HẠN CHẾ VÀ ĐẶC ĐIỂM KIẾN TRÚC (LIMITATIONS)

1. **Sysmon File Event 11 (FileCreate) thay vì FileRead**:  
   Cấu hình Sysmon tiêu chuẩn của Windows chỉ giám sát tạo tệp (`Event ID 11: FileCreate`), chưa bật giám sát đọc tệp sâu qua minifilter driver để tránh làm chậm I/O hệ thống.
2. **TCP Receiver Server chạy trên Localhost**:  
   Trong kịch bản đo TPR chuẩn, đích nhận dữ liệu là TCP socket cục bộ (port 8765), dung lượng được đối soát chính xác 100% qua bảng `receiver_logs`.
3. **Phạm vi cửa sổ đo lường 120 phút**:  
   Workload kiểm nghiệm kéo dài 2 giờ bao gồm các tác vụ văn phòng, quản lý mã nguồn Git, chạy bộ test tự động và duyệt web thông thường.

---

## 6. KẾT LUẬN CHI TIẾT

### KẾT LUẬN: PASS (ĐẠT CHUẨN NGHIỆM THU)

Hệ thống PrivacyGuard đạt độ tin cậy thực nghiệm tối đa trên môi trường làm việc thực tế:
- **True Positive Rate (TPR)**: **5/5 (100%)** (Phát hiện toàn bộ đợt tấn công trích xuất dữ liệu thật).
- **False Positive Rate (FPR)**: **0.0000** (0 cảnh báo sai trên 73,531 cửa sổ trượt đánh giá trong 120 phút).
- **Trạng thái**: Hệ thống sẵn sàng chuyển sang Giai đoạn 3 — Thử nghiệm 3 kịch bản tấn công MITRE ATT&CK.

