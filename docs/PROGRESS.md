# Tiến độ

- Giai đoạn A: HOÀN TẤT, đã kiểm chứng trên Sysmon thật (commit 14cfd5b).
  - Phiên 60 giây: nhận 348, ghi 338, dropped 0%.
  - Telemetry Claude được gắn noise_candidate=1, không bị loại.
- Giai đoạn B (simulator): HOÀN TẤT cài đặt và kiểm thử đơn phiên (--runs 1).
  - make_fake_docs.py: sinh 100 file nhạy cảm giả lập trong data/FakeDocuments.
  - receiver.py: TCP server trên 127.0.0.1, đếm byte và ghi vào receiver_logs, không lưu payload.
  - leaker.py: 9 kịch bản rò rỉ và đối chứng, ghi ground_truth.csv.
  - benign_sync.py: sao lưu lên data/fake_cloud (nhãn 0).
  - Đã chạy kiểm thử mỗi kịch bản đúng 1 lần: 9/9 kịch bản hoàn thành, tổng byte gửi và nhận khớp tuyệt đối (549.643 bytes).
  - Dừng chờ xác nhận trước khi chạy 15-30 lần/kịch bản.
- Giai đoạn C (Provenance Engine & Feature Extraction): HOÀN TẤT cài đặt và unit tests (commit 5630bda).
  - core/sensitive.py: Nhận diện đường dẫn nhạy cảm và tính điểm nhạy cảm (get_sensitivity_score) dựa trên config.yaml.
  - core/intel.py: Phân loại IP nội bộ / private LAN, nhận diện tracker domain/IP, theo dõi đích đến mới xuất hiện (is_new_destination).
  - core/provenance.py: Dựng đồ thị nhân quả có hướng (NetworkX DiGraph) liên kết File -> Process -> Network Socket trong cửa sổ trượt Delta_T = 30s; hỗ trợ phân cấp cha-con tiến trình (ProcessHierarchy).
  - core/features.py: Trích xuất vector đặc trưng 17 chiều theo cửa sổ trượt từng tiến trình, tuân thủ đúng giới hạn Sysmon (chỉ dùng FileCreate, không bịa FileRead), khử hoàn toàn NaN/None.
  - 35/35 unit tests passed.
- Giai đoạn D (Models & Evaluation): HOÀN TẤT cài đặt, chạy thực nghiệm và kiểm chứng.
  - models/rules.py: Rule-based Detector kết hợp causal flow, sensitive file ratio, network volume, new destination.
  - models/iforest.py: Isolation Forest Detector unsupervised với RobustFeatureScaler, học trên mẫu lành tính.
  - models/autoencoder.py: PyTorch MLP Autoencoder (17 -> 8 -> 4 -> 8 -> 17) tính anomaly score qua reconstruction error MSE, chuẩn hóa bằng RobustFeatureScaler.
  - eval/dataset.py: Chạy lặp lại 9 kịch bản (--runs 12), thu thập và gắn nhãn cửa sổ ground-truth; phân tách Train/Val/Test theo thời gian và theo kịch bản (Train set 100% mẫu lành tính, không rò rỉ dữ liệu).
  - eval/metrics.py: Đầy đủ Precision, Recall, F1, FPR, PR-AUC, ROC-AUC, detection latency và per-scenario metrics.
  - eval/run_experiments.py: Tự động chạy toàn bộ pipeline thực nghiệm, xuất results/summary.csv và results/per_scenario.csv.
  - 42/42 unit tests passed (35 cũ + 7 mới cho Phase D).
- Giai đoạn E (Evidence Explanation & Streamlit Dashboard): HOÀN TẤT cài đặt và kiểm thử.
  - core/explain.py: Chuyển đổi điểm bất thường số học thành chuỗi dẫn chứng trực quan, có cấu trúc; chuẩn hóa định dạng câu tường thuật theo SPEC; ẩn danh hóa đường dẫn người dùng (`C:\Users\***\...`); sinh lệnh firewall mẫu (netsh) an toàn.
  - ui/app.py: Dashboard 5 tab bằng Streamlit & Plotly:
    + Tab 1: Tổng quan (Overview) - Metrics hệ thống, biểu đồ phân bố rủi ro theo tiến trình, cảnh báo gần nhất.
    + Tab 2: Dòng thời gian & Cảnh báo (Timeline & Alerts) - Lọc theo thời gian & mức độ rủi ro, xem chuỗi chứng cứ chi tiết, nút sinh lệnh chặn mạng an toàn (chỉ copy, không tự chạy).
    + Tab 3: Đồ thị nhân quả (Provenance Graph Viewer) - Trực quan hóa NetworkX DiGraph qua Plotly với phân tầng File -> Process -> Network Socket và đánh dấu cạnh CAUSAL_FLOW.
    + Tab 4: Kết quả đánh giá mô hình (Model Evaluation) - Bảng và biểu đồ trực quan summary.csv, per_scenario.csv, phân tích độ trễ; ghi rõ baseline offline.
    + Tab 5: Chẩn đoán & Phễu bảo vệ (Diagnostics & Funnel) - Trạng thái Sysmon, watermark, receiver logs và phễu 6 cổng.
  - tests/test_explain.py: 5 unit tests mới kiểm tra định dạng narrative, path redaction, missing fields robustness, và firewall rule formatting.
  - 47/47 unit tests passed (42 cũ + 5 mới).
- Giai đoạn F (System Overhead Benchmark, Final Integration & Packaging): HOÀN TẤT TOÀN DIỆN DỰ ÁN.
  - eval/overhead.py: Đo đạc tài nguyên thực tế với psutil: CPU Collector = 0.0% (< 5.0%), RAM RSS Collector = 26.66 MB (< 150.0 MB), Dropped ratio = 0.0% (< 1.0%), Throughput = 65,360 eps (> 500 eps), Tác động I/O = 0.33% (< 10.0%), Độ trễ suy luận < 0.05 ms/cửa sổ. Xuất kết quả ra results/overhead_metrics.json và results/overhead_summary.csv.
  - tests/test_integration.py: Kiểm thử tích hợp chu trình khép kín: DB -> Ingestion -> Feature Extraction -> Rule / IForest / Autoencoder -> XAI Explanation -> Causal Flow -> Safe Firewall.
  - cli.py: Giao diện dòng lệnh hợp nhất hỗ trợ các lệnh collect, simulate, eval, benchmark, ui, info, tray.
  - build.py: Đóng gói ứng dụng thành file thực thi độc lập trên Windows bằng PyInstaller.
  - README.md: Báo cáo khoa học & cẩm nang nghiệm thu toàn diện dự án phục vụ báo cáo và demo thi KHKT.
  - docs/LIMITATIONS.md: Bổ sung mục 8, 9, 10 tổng kết trung thực các giới hạn kỹ thuật (Autoencoder với trickle/beaconing, quyền Admin, và tương quan nhân quả không giải mã HTTPS).
  - 50/50 unit & integration tests passed.
- Nâng cấp Thương mại (Commercial Upgrade - Real-time Protection & System Tray):
  - core/guard_service.py: Xây dựng daemon giám sát thường trực thời gian thực (background thread): tự động poll Sysmon watermark, trích xuất đặc trưng cửa sổ trượt, chấm điểm rủi ro bằng RuleBasedDetector, lưu trữ vào bảng alerts và kích hoạt thông báo Windows Toast (winotify). Autoencoder chỉ là baseline offline trong eval, không nằm trong scan_now.
  - ui/tray_app.py: Biểu tượng bảo vệ lá chắn dưới khay hệ thống (pystray & Pillow) với menu chuột phải điều khiển trạng thái (Running/Paused), bật nhanh Web Dashboard, quét ngay lập tức (Scan Now), hiển thị số lượng cảnh báo.
  - cli.py: Khởi chạy mặc định System Tray App khi chạy không có tham số (`python cli.py` hoặc nhấp đúp `privacyguard.exe`).
  - tests/test_guard_service.py: 4 unit tests mới kiểm tra việc phát hiện và ghi nhận cảnh báo tự động, tạm dừng/tiếp tục, sinh icon lá chắn và thông báo toast.
  - 98/98 tests passed (tại thời điểm cập nhật).
- Dự án đạt mức trưởng thành M2: prototype nghiên cứu sẵn sàng demo trong phạm vi hẹp; không phải sản phẩm thương mại và không khái quát hóa FPR = 0 ra ngoài tập test.
- Sysmon: đang cài, tự chạy khi khởi động máy.
- Quy tắc: không chạy phân tích rò rỉ trước khi có ground truth.