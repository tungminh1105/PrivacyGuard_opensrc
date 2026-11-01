# PRIVACYGUARD: KỊCH BẢN VIDEO DEMO ĐÁNH GIÁ HỆ THỐNG (5 PHÚT)

> **Mục tiêu**: Hướng dẫn quay video thuyết trình và kiểm chứng sản phẩm PrivacyGuard trong đúng 5 phút (300 giây).  
> **Cam kết an toàn**: Chỉ sử dụng địa chỉ loopback nội bộ `127.0.0.1` và thư mục tệp giả lập an toàn `data/FakeDocuments`. Tuyệt đối không xâm phạm, đọc hay phát tán dữ liệu thật của người dùng.  
> **Nguyên tắc khoa học**: Không tuyên bố "FPR = 0%" một cách chung chung. Phải nêu chính xác: *"0/1.000 windows trong 121.94 phút; toàn bộ benign bị lọc ở gate 0.5/2, nên final decision layer chưa được benign traffic kiểm chứng."*

---

## 1. BẢNG PHÂN BỔ THỜI GIAN VÀ THAO TÁC TỔNG QUAN

| Mốc Thời Gian | Phân Đoạn Thuyết Trình | Thao Tác Màn Hình / File Cần Mở | Mục Tiêu & Thông Điệp Cốt Lõi |
| :---: | :--- | :--- | :--- |
| **0:00 – 0:30**<br>(30s) | **Mở đầu: Vấn đề rò rỉ dữ liệu** | Mở trang chủ Dashboard Streamlit (`http://localhost:8501`) hoặc Slide tiêu đề. | Đặt vấn đề: Spyware/malware lén đọc tài liệu nội bộ rồi đẩy ra ngoài mạng; nhu cầu giám sát bảo vệ dữ liệu cục bộ. |
| **0:30 – 1:30**<br>(60s) | **Kiến trúc: Sysmon ETW & Hard Gates** | Mở Tab 3 (*Sơ đồ đường đi dữ liệu*) hoặc sơ đồ kiến trúc ETW. | Trình bày luồng dữ liệu: Microsoft `SysmonDrv` $\to$ user-mode pipeline $\to$ chuỗi 5 Hard Gates $\to$ Cảnh báo RuleBased. |
| **1:30 – 2:30**<br>(60s) | **Benign Workload & Tỷ lệ FPR** | Mở `results/FPR_REPORT.md` (hoặc `results/fpr_summary.json`). | Phân tích bài đo 121.94 phút: 0/1.000 windows, giải thích bản chất phễu lọc chặn ở Gate 0.5 và Gate 2. |
| **2:30 – 4:00**<br>(90s) | **Trực quan hóa Cảnh báo (#175–#177)** | Mở Tab 2 (*Nhật ký & Xử lý nguy cơ*) trên Dashboard Streamlit. | Trình diễn 3 cảnh báo MITRE thật: #175 (T1560.001 ZIP in-memory), #176 (T1041 Bulk C2), #177 (T1567 Web Service); nút chặn Firewall 1-click. |
| **4:00 – 4:30**<br>(30s) | **Bằng chứng Đối soát (Ground Truth)** | Mở `results/demo_export/manifest.json` và `results/MITRE_REPORT.md`. | Chứng minh tính xác thực: `receiver_logs` khớp từng byte (`byte diff = 0`), 100% `source='sysmon'`, 0 synthetic event. |
| **4:30 – 5:00**<br>(30s) | **Hạn chế kỹ thuật & Teaser Q&A** | Mở `docs/LIMITATIONS.md` Mục 11 hoặc Slide Q&A. | Minh bạch giới hạn: Localhost only, T1048 DNS gap (Event 22), phân tích flow-level không can thiệp sâu TLS/ZIP; sẵn sàng trả lời Q&A. |

---

## 2. KỊCH BẢN CHI TIẾT TỪNG PHÂN ĐOẠN

### Phân đoạn 1: Mở đầu & Vấn đề Rò rỉ Dữ liệu (0:00 – 0:30)
- **Màn hình hiển thị**: Mở trình duyệt tại địa chỉ Dashboard `http://localhost:8501` (Tab 1: *🛡️ Tổng quan bảo vệ*).
- **Thao tác**: Giữ chuột trên giao diện tổng quan, chỉ vào số lượng ứng dụng đang được giám sát và tổng số cảnh báo an ninh đã được kích hoạt.
- **Lời thoại gợi ý**:
  > *"Kính chào quý thầy cô và hội đồng đánh giá. Rò rỉ dữ liệu nhạy cảm (Data Exfiltration) hiện nay là một trong những hiểm họa mạng hàng đầu: các mã độc gián điệp, phần mềm độc hại hoặc script lạ thường âm thầm truy cập vào tài liệu mật trong máy rồi bí mật đẩy dữ liệu ra máy chủ ngoại mạng. Hôm nay, chúng tôi xin giới thiệu **PrivacyGuard** — giải pháp phát hiện rò rỉ dữ liệu theo chuỗi nhân quả cục bộ, hoạt động trực tiếp trên nền tảng telemetry chuẩn từ hệ điều hành Windows."*

---

### Phân đoạn 2: Kiến trúc Kỹ thuật & Chuỗi Hard Gates (0:30 – 1:30)
- **Màn hình hiển thị**: Chuyển sang Tab 3 (*🗺️ Sơ đồ đường đi của dữ liệu*) trên Dashboard, hoặc mở tài liệu kiến trúc.
- **Thao tác**: Cuộn qua sơ đồ đồ thị provenance phân luồng (Tệp nhạy cảm $\to$ Tiến trình nghi vấn $\to$ Cổng mạng máy chủ).
- **Lời thoại gợi ý**:
  > *"Để đảm bảo độ tin cậy tuyệt đối mà không cần can thiệp viết driver nhân (kernel driver) thiếu an toàn, PrivacyGuard khai thác trực tiếp driver minifilter chính thức của Microsoft là **SysmonDrv** thông qua cơ chế Event Tracing for Windows (ETW).  
  > Luồng dữ liệu hoạt động như sau:  
  > 1. Sysmon ghi nhận sự kiện mở/tạo tệp (Event ID 11) và kết nối mạng ngoại vi (Event ID 3).  
  > 2. Pipeline chế độ người dùng (user-mode) thu nạp sự kiện vào cơ sở dữ liệu `EventStore` với mã định danh tiến trình bất biến `ProcessGuid`.  
  > 3. Các cửa sổ quan sát được đưa qua chuỗi 5 cổng cứng (Hard Gates):  
  >    - **Cổng 0.5 (Direct Actor)**: Xác thực tiến trình trực tiếp truy cập tệp.  
  >    - **Cổng 2 (Causal Flow)**: Chứng minh quan hệ nhân quả về mặt thời gian (truy cập tệp nhạy cảm trước, sau đó phát sinh kết nối mạng trong vòng 30 giây).  
  >    - **Cổng 3 (Min Bytes)**: Lưu lượng truyền gửi tối thiểu từ 1024 bytes trở lên.  
  >    - **Cổng 4 (Sensitive File)**: Tệp bị tác động nằm trong danh mục tài liệu nhạy cảm.  
  >    - **Cổng 5 (Cooldown)**: Chống nhân bản cảnh báo trùng lặp.  
  > Nhờ cơ chế này, hệ thống đạt khả năng phát hiện chuẩn xác mà không cần giải mã nội dung gói tin."*

---

### Phân đoạn 3: Kiểm chứng Benign Workload & Tỷ lệ Cảnh báo Sai FPR (1:30 – 2:30)
- **Màn hình hiển thị**: Mở tệp [`results/FPR_REPORT.md`](../results/FPR_REPORT.md) hoặc xem tệp [`results/demo_export/phase2_fpr_summary.json`](../results/demo_export/phase2_fpr_summary.json) trên trình soạn thảo.
- **Thao tác**: Cuộn đến bảng phễu lọc (*Scan Stats Funnel*) và thông số bài đo 121.94 phút.
- **Lời thoại gợi ý (BẮT BUỘC NÓI CHUẨN XÁC)**:
  > *"Để chứng minh hệ thống không gây phiền hà cho người dùng trong môi trường văn phòng thực tế, PrivacyGuard đã trải qua bài đo kiểm chứng độ ổn định dài **121.94 phút** với **34.632 sự kiện Sysmon** được thu thập liên tục và **73.531 cửa sổ quan sát** được đánh giá.  
  > Kết quả thu được là: **0 cảnh báo sai trên 1.000 cửa sổ** (FPR = 0/1.000 windows).  
  > Tuy nhiên, về mặt khoa học thực nghiệm, chúng tôi xin nhấn mạnh rõ: **toàn bộ 73.531 cửa sổ lành tính này đều đã được lọc sạch từ sớm ở Cổng 0.5 (Not Direct Actor: 66.361) và Cổng 2 (No Causal Flow: 7.170), do đó tầng quyết định điểm số cuối cùng (Final Decision Layer) chưa phải xử lý các tình huống benign traffic đi sâu qua chuỗi nhân quả**. Đây là minh chứng cho thấy các cổng lọc nhân quả hoạt động rất hiệu quả để loại bỏ nhiễu nền của hệ thống."*

---

### Phân đoạn 4: Trực quan hóa Cảnh báo Thực tế (#175 – #177) (2:30 – 4:00)
- **Màn hình hiển thị**: Mở Tab 2 (*🚨 Nhật ký & Xử lý nguy cơ*) trên Dashboard Streamlit.
- **Thao tác**:
  1. Chọn và bấm mở chi tiết **Cảnh báo #175**:
     - Kỹ thuật: **MITRE ATT&CK T1560.001 (Archive via Utility)**.
     - Cho thấy: Ứng dụng nén 2 tệp nhạy cảm trong bộ nhớ (in-memory ZIP), gửi 8.6 KB ra cổng `127.0.0.1:8765`.
     - Chỉ vào chuỗi nhân quả trực quan (*Causal Chain*) và Narrative giải thích thân thiện cho người dùng.
  2. Bấm mở **Cảnh báo #176**:
     - Kỹ thuật: **MITRE ATT&CK T1041 (Exfiltration Over C2 Channel)**.
     - Cho thấy: Tiến trình đọc 3 tệp nhạy cảm, gửi rò rỉ dữ liệu thô hàng loạt (bulk binary send) 12.4 KB ra cổng `127.0.0.1:8765`.
  3. Bấm mở **Cảnh báo #177**:
     - Kỹ thuật: **MITRE ATT&CK T1567 (Exfiltration Over Web Service - flow level)**.
     - Cho thấy: Gửi dữ liệu nhạy cảm 8.4 KB tới cổng dịch vụ web thay thế `127.0.0.1:8443`.
  4. Cuộn xuống cuối thẻ cảnh báo: Trình diễn nút hành động an toàn **"Tạo lệnh chặn tường lửa (1-Click Firewall Rule)"**: hiển thị lệnh mẫu `netsh advfirewall firewall add rule...`.
- **Lời thoại gợi ý**:
  > *"Trên màn hình là 3 cảnh báo tấn công thực tế mang mã số #175, #176 và #177 vừa được kiểm chứng ở Phase 3.  
  > - Ở Cảnh báo #175, ứng dụng cố tình nén tài liệu nhạy cảm vào bộ nhớ RAM dưới dạng file ZIP rồi gửi ra mạng, PrivacyGuard phát hiện tức thì với điểm rủi ro 100/100 nhờ bắt trọn chuỗi nhân quả giữa tạo tệp và socket.  
  > - Ở Cảnh báo #176, mô phỏng kênh C2 truyền nhị phân dung lượng lớn 12.4 KB, hệ thống lập tức phát cảnh báo và chỉ rõ 3 tệp tin tài chính đã bị đánh cắp.  
  > - Ở Cảnh báo #177, kỹ thuật ngụy trang gửi qua cổng web 8443 cũng bị bắt giữ ở tầng luồng mạng.  
  > Đặc biệt, PrivacyGuard giải thích nguy cơ bằng ngôn ngữ tự nhiên rõ ràng và cung cấp sẵn nút tạo quy tắc tường lửa Windows Firewall 1-click để người quản trị hoặc người dùng có thể cô lập tiến trình độc hại ngay lập tức."*

---

### Phân đoạn 5: Bằng chứng Đối soát Kỹ thuật (Ground Truth Evidence) (4:00 – 4:30)
- **Màn hình hiển thị**: Mở tệp [`results/demo_export/manifest.json`](../results/demo_export/manifest.json) hoặc bảng kết quả [`results/MITRE_REPORT.md`](../results/MITRE_REPORT.md).
- **Thao tác**: Highlight các dòng đối soát byte và nguồn dữ liệu trong báo cáo:
  - T1560: Gửi 8636 bytes $\leftrightarrow$ Receiver nhận 8636 bytes $\to$ **Diff = 0**.
  - T1041: Gửi 12426 bytes $\leftrightarrow$ Receiver nhận 12426 bytes $\to$ **Diff = 0**.
  - T1567: Gửi 8412 bytes $\leftrightarrow$ Receiver nhận 8412 bytes $\to$ **Diff = 0**.
  - Dòng `source == 'sysmon'`: 100% telemetry Sysmon thật, `synthetic_events = 0`.
- **Lời thoại gợi ý**:
  > *"Về độ trung thực khoa học, gói bằng chứng `demo_export` được đối soát chéo với nhật ký của Receiver Server trên máy: toàn bộ số byte tiến trình gửi đi khớp chính xác 100% với số byte máy chủ nhận được, sai số byte diff hoàn toàn bằng 0. Mỗi tiến trình đều có mã GUID độc lập do nhân hệ điều hành cấp phát, 100% sự kiện bắt nguồn từ Sysmon, tuyệt đối không sử dụng sự kiện giả tạo hay chèn ID ảo."*

---

### Phân đoạn 6: Hạn chế Hệ thống & Teaser Q&A (4:30 – 5:00)
- **Màn hình hiển thị**: Mở tài liệu [`docs/LIMITATIONS.md`](LIMITATIONS.md) Mục 11, hoặc màn hình Slide cảm ơn.
- **Thao tác**: Cuộn qua 3 gạch đầu dòng về giới hạn kỹ thuật.
- **Lời thoại gợi ý**:
  > *"Cuối cùng, chúng tôi xin nêu rõ các giới hạn kiến trúc hiện tại:  
  > 1. Toàn bộ thực nghiệm được thực hiện trên loopback socket nội bộ `127.0.0.1` và thư mục `FakeDocuments` để đảm bảo đạo đức an toàn thông tin, không can thiệp vào máy chủ C2 ngoài đời thực hay tệp thật của người dùng.  
  > 2. Kỹ thuật T1048 (rò rỉ qua DNS) hiện chưa được bao phủ do pipeline chưa thu thập Event 22; đây là mục tiêu mở rộng trong tương lai.  
  > 3. Hệ thống phát hiện ở tầng luồng hành vi (flow-level) và chuỗi nhân quả, tôn trọng quyền riêng tư nên không giải mã nội dung HTTPS hay uncompress ZIP stream.  
  > Trên đây là phần trình bày giải pháp PrivacyGuard. Nhóm chúng tôi rất mong nhận được các câu hỏi và đóng góp từ quý hội đồng. Xin trân trọng cảm ơn!"*

---

## 3. PHƯƠNG ÁN DỰ PHÒNG (FALLBACK PROCEDURE)

Nếu trong quá trình quay, giao diện Streamlit Dashboard gặp trục trặc (ví dụ cổng 8501 bị treo hoặc trình duyệt không tải kịp):
1. **Chuyển ngay sang chế độ Static Evidence Review**:
   - Mở tệp [`results/MITRE_REPORT.md`](../results/MITRE_REPORT.md) trên trình soạn thảo VS Code / Markdown Viewer.
   - Thuyết minh trực tiếp trên Bảng kết quả Phân đoạn 4 và Bảng phễu lọc Phân đoạn 5.
   - Mở tệp [`results/demo_export/manifest.json`](../results/demo_export/manifest.json) để chứng minh tính toàn vẹn chữ ký số SHA-256 và tỷ lệ TPR 3/3 (100%).
2. Không cố gắng khởi động lại dịch vụ giữa chừng làm gián đoạn thời lượng 5 phút của video.
