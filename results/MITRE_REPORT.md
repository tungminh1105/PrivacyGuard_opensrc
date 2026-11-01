# BÁO CÁO KIỂM CHỨNG 3 KỊCH BẢN MITRE ATT&CK & ĐO LƯỜNG TPR (PHASE 3)

> **Môi trường thử nghiệm**: Windows 10 Pro (Build 19045, Windows-10-10.0.19045-SP0) (PowerShell Administrator Elevated)  
> **Thời gian bắt đầu**: `2026-11-01T23:42:58.652346`  
> **Thời gian kết thúc**: `2026-11-01T23:43:17.313824`  
> **Cơ sở dữ liệu**: `D:\KERNAL PROTECT\privacyguard\data\privacyguard.db`  
> **Kết luận tổng thể**: **PASS** (TPR: **3/3 (100.0%)**)  

---

## 1. MỤC TIÊU VÀ PHẠM VI KIỂM CHỨNG

Phase 3 thực hiện kiểm chứng khả năng phát hiện của PrivacyGuard đối với 3 kỹ thuật đánh cắp dữ liệu chuẩn MITRE ATT&CK trên luồng telemetry Sysmon thật (không giả lập, không injection synthetic events):
1. **T1560.001 (Archive via Utility)**: Nén tài liệu nhạy cảm vào tệp lưu trữ ZIP trực tiếp trong bộ nhớ (in-memory) và gửi ra ngoài (không tạo tệp nén trên đĩa).
2. **T1041 (Exfiltration Over C2 Channel)**: Rò rỉ hàng loạt (bulk binary exfiltration) trực tiếp qua kênh TCP nhị phân tới cổng máy chủ nhận.
3. **T1567 (Exfiltration Over Web Service - flow level)**: Gửi luồng dữ liệu nhạy cảm qua kết nối mạng (net_connect) kèm lưu lượng byte lớn tới cổng web service thay thế (8443) theo mô hình flow-level (không giải mã / parsing HTTP payload).

> [!NOTE]
> **Kỹ thuật T1048 (Exfiltration Over Alternative Protocol / DNS)**:
> Hiện tại `config.yaml` của PrivacyGuard chỉ thu thập Sysmon Event ID 1, 3, 5, 11; sự kiện truy vấn DNS (Event ID 22) chưa được kích hoạt trong pipeline. Do đó, T1048 được ghi nhận là khoảng trống giám sát (coverage gap) cho giai đoạn phát triển tiếp theo, không thực hiện giả mạo trong Phase 3.

---

## 2. PHƯƠNG PHÁP THỰC NGHIỆM VÀ ĐỊNH NGHĨA TPR

- **Nguồn Telemetry**: 100% Microsoft Sysmon Event Log thật (Event 11: FileCreate, Event 3: NetworkConnect) qua user-mode EventStore.
- **Tiến trình độc lập**: Mỗi kịch bản được thực thi bởi một tiến trình con riêng biệt (`simulator/mitre_payload.py`) để sinh ra Process GUID (`proc_key`) và PID độc lập.
- **Đối soát Receiver**: TCP Receiver Server chạy trên `127.0.0.1` ghi nhận chính xác từng byte nhận được vào bảng `receiver_logs` để đối soát sai số với evidence (`abs(diff) <= 1`).
- **Định nghĩa TPR (True Positive Rate)**:
  - Một kịch bản chỉ được tính là **Detected & Valid** khi thỏa mãn toàn bộ 15 tiêu chí an ninh (GUID hợp lệ, PID khớp, 100% Sysmon, đúng cổng đích, đúng dung lượng, score >= 0.70).
  - $$\text{TPR} = \frac{\text{Số kịch bản phát hiện hợp lệ}}{\text{Tổng số kịch bản thử nghiệm}} = \frac{3}{3}$$

---

## 3. THÔNG SỐ ĐỐI SOÁT BASELINE TRƯỚC VÀ SAU RUN

| Chỉ số hệ thống | Trước khi chạy (Baseline) | Sau khi chạy (Final) | Chênh lệch thực tế |
| :--- | :---: | :---: | :---: |
| **Tổng số cảnh báo (Alerts)** | 5 (Max ID: 174) | 8 (Max ID: 177) | **+3 alerts mới** |
| **Tổng số sự kiện (Events)** | 260,207 | 260,384 | +177 events |
| **Bản ghi nhận gói (Receiver Logs)** | 163 | 166 | +3 logs |
| **Bản ghi chẩn đoán (Scan Stats)** | 180 | 183 | +3 scans |

- Cảnh báo tham chiếu Phase 0.6 (#170–#174): **Giữ nguyên vẹn 100% (Không bị ghi đè hay xóa)**.
- Sự kiện `source != 'sysmon'`: **0 sự kiện** (Tuyệt đối không có synthetic event).

---

## 4. KẾT QUẢ KIỂM CHỨNG 3 KỊCH BẢN (TPR BENCHMARK)

| Kỹ thuật | Tên kỹ thuật | Alert ID | Process GUID | PID | Bytes Gửi | Receiver Bytes | Diff | Sensitive Files | Cổng đích | Điểm Rủi Ro | Độ Trễ (s) | Kết Luận |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `T1560.001` | Archive via Utility | #175 | `{db9fa507-6c12-6ae7-4f2a-000000008200}` | 10904 | 8636 | 8636 | 0 | 2 | `127.0.0.1:8765` | 1.00 | 5.00s | **DETECTED (1/1)** |
| `T1041` | Exfiltration Over C2 Channel | #176 | `{db9fa507-6c18-6ae7-632a-000000008200}` | 1172 | 12426 | 12426 | 0 | 3 | `127.0.0.1:8765` | 1.00 | 5.00s | **DETECTED (1/1)** |
| `T1567` | Exfiltration Over Web Service (flow-level) | #177 | `{db9fa507-6c1f-6ae7-7d2a-000000008200}` | 24772 | 8412 | 8412 | 0 | 2 | `127.0.0.1:8443` | 1.00 | 5.00s | **DETECTED (1/1)** |


---

## 5. PHÂN TÍCH PHỄU LỌC TỪNG KỊCH BẢN (SCAN STATS FUNNEL)

| Kỹ thuật | Windows Created | Not Direct Actor | No Causal Flow | Bytes < Min | No Sensitive | Score < Thresh | Duplicate | Alerts Created |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `T1560.001` | 10 | 7 | 2 | 0 | 0 | 0 | 0 | **1** |
| `T1041` | 45 | 38 | 5 | 0 | 0 | 0 | 1 | **1** |
| `T1567` | 88 | 72 | 12 | 0 | 0 | 0 | 3 | **1** |


---

## 6. CHI TIẾT CẢNH BÁO MỚI PHÁT SINH

| Alert ID | Process GUID | PID | Bytes | Đích đến | Score | Severity | Tệp tin phát hiện |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| #175 | `{db9fa507-6c12-6ae7-4f2a-000000008200}` | 10904 | 8636 | `127.0.0.1:8765` | 1.00 | Cao | `D:\KERNAL PROTECT\privacyguard\data\Fake...` |
| #176 | `{db9fa507-6c18-6ae7-632a-000000008200}` | 1172 | 12426 | `127.0.0.1:8765` | 1.00 | Cao | `D:\KERNAL PROTECT\privacyguard\data\Fake...` |
| #177 | `{db9fa507-6c1f-6ae7-7d2a-000000008200}` | 24772 | 8412 | `127.0.0.1:8443` | 1.00 | Cao | `D:\KERNAL PROTECT\privacyguard\data\Fake...` |


---

## 7. ĐÁNH GIÁ TỶ LỆ PHÁT HIỆN & PHÂN TÍCH FALSE NEGATIVES

- **True Positive Rate (TPR)**: **3/3 (100.0%)**
- Không có false negative nào ghi nhận (3/3 kịch bản đều kích hoạt cảnh báo hợp lệ).


---

## 8. PHẠM VI BAO PHỦ MITRE ATT&CK (COVERAGE MATRIX)

| Mã MITRE | Tên Kỹ Thuật | Trạng Thái Giám Sát | Cơ Chế Phát Hiện |
| :--- | :--- | :---: | :--- |
| **T1560.001** | Archive via Utility | **COVERED** | Tương quan chuỗi nhân quả: file_create tài liệu nhạy cảm $\to$ nén ZIP trực tiếp trong bộ nhớ (in-memory, không tạo tệp trên đĩa) $\to$ net_connect ngoại mạng. |
| **T1041** | Exfiltration Over C2 | **COVERED** | Phát hiện rò rỉ trực tiếp qua socket TCP (bulk binary exfiltration): nhận diện luồng truyền byte lớn tới máy chủ sau khi truy cập tài liệu nhạy cảm (được phát hiện độc lập, ghi nhận độ trễ). |
| **T1567** | Exfiltration Over Web Service | **COVERED (Flow-level)** | Tương quan luồng mạng (flow-level): net_connect + dung lượng byte lớn (byte volume) tới cổng dịch vụ thay thế (8443) gắn liền với tập tài liệu nhạy cảm, không phải giải mã/phân tích sâu HTTP payload. |
| **T1048** | Exfiltration Over Alternative Protocol | **NOT COVERED** | Cấu hình Sysmon hiện tại chưa kích hoạt thu thập DNS Query (Event 22). |

---

## 9. HẠN CHẾ VÀ ĐẶC ĐIỂM KIẾN TRÚC (LIMITATIONS)

1. **Thử nghiệm trên Localhost Socket**: Địa chỉ nhận dữ liệu gắn trên loopback `127.0.0.1` thay vì hạ tầng máy chủ C2 / Cloud thực tế bên ngoài mạng.
2. **Nén ZIP trong bộ nhớ (in-memory)**: Tệp nén ZIP được tạo hoàn toàn trong bộ nhớ (không tạo tệp nén trung gian trên đĩa). PrivacyGuard phát hiện dựa trên tương quan chuỗi nhân quả của tiến trình (truy cập tài liệu nhạy cảm $\to$ gửi gói dữ liệu ngoại mạng) mà không cần kiểm tra hay giải mã nội dung bên trong ZIP stream.
3. **Phân tích ở tầng Flow-Level đối với T1567**: Nhận diện tương quan dựa trên sự kiện net_connect và dung lượng byte truyền (byte volume), không sử dụng MITM proxy hay giải mã/parsing nội dung HTTP payload.
4. **Không đo lại FPR trong Phase 3**: FPR đã được đo đạc và nghiệm thu độc lập tại Phase 2 (0/1,000 windows trong 121.94 phút).
## 10. KIỂM SOÁT TÍNH TOÀN VẸN (INTEGRITY AUDIT)

- **Detection Core Hash**:
  - `config.yaml`: `e20df170d37b8b96bcf50dfaba648a82ca479246b4c8e0205e5caee2bef20a63`
  - `core/guard_service.py`: `5c5dc050fe9f213973c914fc4f8349423d500242149292bbd4af1d4e40517159`
  - `core/features.py`: `3d2eaec8f799d5c8e4e137197ea0044fb9e05afff674a81c33cab5779117d571`
  - `core/explain.py`: `144d9b80515a83fcab209131532855256058857dbb1b7be9b784896a9061a7f0`
- `git diff -- core config.yaml`: **Rỗng 100% (Không sửa bất kỳ dòng mã detection hay ngưỡng bảo vệ nào)**.
- Bản ghi tấn công tham chiếu Phase 0.6 (#170–#174): **Nguyên vẹn**.
- Sự kiện Sysmon: **100% authentic, 0 synthetic**.

---

## 11. KHẢ NĂNG TÁI LẬP (REPRODUCIBILITY)

Để tái lập toàn bộ quy trình kiểm chứng 3 kịch bản:
```powershell
# PowerShell với quyền Administrator
cd "D:\KERNAL PROTECT\privacyguard"
.\.venv\Scripts\python.exe scripts\run_mitre_scenarios.py --db data\privacyguard.db --port 8765 --alt-port 8443
```

---

## 12. KẾT LUẬN

Hệ thống PrivacyGuard hoàn thành kiểm chứng Giai đoạn 3:
- **Kết quả**: **PASS**
- **TPR**: **3/3 (100.0%)** trên 3 kỹ thuật MITRE ATT&CK bằng telemetry Sysmon thật.
