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
- Sysmon: đang cài, tự chạy khi khởi động máy.
- Quy tắc: không chạy phân tích rò rỉ trước khi có ground truth.