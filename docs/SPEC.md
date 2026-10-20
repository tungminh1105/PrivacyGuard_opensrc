PrivacyGuard-Win: Đặc tả triển khai chi tiết (dành cho AI lập trình)
Tài liệu này được viết để dán cho một AI lập trình (Claude Code, Cursor, v.v.) và làm theo từng giai đoạn. Mỗi giai đoạn có đầu vào, đầu ra và tiêu chí nghiệm thu rõ ràng.
0. Cách dùng tài liệu
1. Dán toàn bộ tài liệu làm ngữ cảnh nền, sau đó yêu cầu AI làm từng giai đoạn một (mục 11), không làm tất cả cùng lúc.
2. Sau mỗi giai đoạn: chạy kiểm thử, đối chiếu tiêu chí nghiệm thu, rồi mới sang giai đoạn tiếp theo.
3. Khi AI không chắc về tên trường sự kiện ETW hay event ID, bắt buộc dump sự kiện thô để xem thực tế, không đoán.
1. Mục tiêu và ràng buộc
Sản phẩm: công cụ chạy trên Windows 10/11, theo dõi các tiến trình bằng ETW (Event Tracing for Windows), dựng đồ thị truy vết dữ liệu (đọc file nhạy cảm, rồi gửi ra mạng), phát hiện hành vi rò rỉ bằng luật và học máy/học sâu, hiển thị cảnh báo kèm chuỗi bằng chứng.
Câu hỏi nghiên cứu: chỉ dùng siêu dữ liệu từ kernel (không đọc nội dung gói tin), hệ thống phát hiện ứng dụng đọc file nhạy cảm rồi gửi ra ngoài chính xác đến đâu, báo động giả bao nhiêu, và học sâu cải thiện được gì so với luật cứng.
Ràng buộc bắt buộc (AI phải tuân thủ):
• Chỉ giám sát máy của chính người dùng. Không có mã độc thật, không tạo công cụ tấn công, không gửi dữ liệu ra ngoài máy.
• Không lưu nội dung file. Chỉ lưu metadata (đường dẫn, kích thước, thời gian). Đường dẫn chứa tên người dùng được thay bằng <USER> khi hiển thị/xuất báo cáo.
• Mọi xử lý cục bộ. Không gọi API ngoài, trừ tải trước danh sách tracker và GeoLite2 một lần.
• Python 3.11+, chạy bằng quyền Administrator (cần cho ETW kernel).
• Mọi module phải có kiểm thử chạy được không cần quyền Admin (dùng dữ liệu mẫu) để AI tự kiểm tra.
• Simulator chỉ đọc thư mục dữ liệu giả FakeDocuments và chỉ gửi về 127.0.0.1 hoặc máy thử nghiệm của người làm.
2. Công nghệ
Việc
Thư viện
Thu sự kiện ETW
pywintrace (import tên etw)
Dự phòng
Sysmon + pywin32 đọc Event Log
Thông tin tiến trình
psutil, pywin32 (chữ ký số qua WinVerifyTrust hoặc PowerShell Get-AuthenticodeSignature)
Lưu trữ
sqlite3 (WAL mode)
Đồ thị
networkx
ML
scikit-learn, numpy, pandas
DL
torch
Giao diện
streamlit, plotly, pyvis hoặc plotly cho đồ thị
GeoIP
geoip2 + GeoLite2-Country.mmdb (tải thủ công)
Kiểm thử
pytest
Đóng gói demo
pyinstaller
3. Cấu trúc thư mục
privacyguard/
  README.md
  requirements.txt
  config.yaml
  collector/
    etw_collector.py     # thu sự kiện, đẩy vào queue
    proc_info.py         # cache PID -> (tên, đường dẫn exe, chữ ký, thời điểm bắt đầu)
    replay.py            # đọc sự kiện mẫu từ file jsonl để kiểm thử không cần ETW
  core/
    store.py             # SQLite: schema, ghi theo lô, truy vấn
    sensitive.py         # phân loại đường dẫn nhạy cảm
    provenance.py        # cửa sổ trượt, dựng đồ thị nhân quả
    features.py          # vector đặc trưng mỗi (pid, cửa sổ)
    intel.py             # tracker list, GeoIP, đích mới/cũ
    explain.py           # sinh chuỗi bằng chứng
  models/
    rules.py             # baseline luật
    iforest.py
    autoencoder.py
    lstm.py
    train.py             # huấn luyện và lưu mô hình
  simulator/
    make_fake_docs.py    # tạo FakeDocuments
    leaker.py            # các kịch bản rò rỉ giả lập
    receiver.py          # server nhận
    benign_sync.py       # giả lập sao lưu cloud (lành tính)
  eval/
    label_windows.py     # gán nhãn cửa sổ từ ground_truth.csv
    run_experiments.py
    metrics.py
    overhead.py
  ui/
    app.py               # Streamlit
  tests/
  data/                  # db, csv, trọng số mô hình (gitignore)
4. Lược đồ dữ liệu (SQLite)
CREATE TABLE events (
  id INTEGER PRIMARY KEY,
  ts REAL NOT NULL,            -- epoch giây (float)
  pid INTEGER NOT NULL,
  ppid INTEGER,
  proc_key TEXT NOT NULL,      -- pid + ':' + thời điểm tạo tiến trình, tránh nhầm khi PID tái sử dụng
  type TEXT NOT NULL,          -- proc_start | proc_end | file_read | file_write | file_create | net_connect | net_send | net_recv
  path TEXT,                   -- cho sự kiện file
  dest_ip TEXT, dest_port INTEGER, proto TEXT,
  nbytes INTEGER DEFAULT 0
);
CREATE INDEX idx_events_ts ON events(ts);
CREATE INDEX idx_events_pk ON events(proc_key, ts);

CREATE TABLE processes (
  proc_key TEXT PRIMARY KEY,
  pid INTEGER, ppid INTEGER, name TEXT, exe_path TEXT,
  signed INTEGER, publisher TEXT, start_ts REAL, end_ts REAL
);

CREATE TABLE windows (        -- đặc trưng đã tính
  id INTEGER PRIMARY KEY,
  proc_key TEXT, t_start REAL, t_end REAL,
  features_json TEXT,
  label INTEGER,               -- 0 lành tính, 1 rò rỉ giả lập, NULL chưa gán
  scenario TEXT
);

CREATE TABLE alerts (
  id INTEGER PRIMARY KEY, ts REAL, proc_key TEXT, window_id INTEGER,
  detector TEXT, score REAL, severity TEXT, evidence TEXT, status TEXT DEFAULT 'new'
);
5. Collector ETW
Provider cần bật (GUID chuẩn Microsoft, vẫn phải dump xác minh):
• Microsoft-Windows-Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
• Microsoft-Windows-Kernel-File {EDD08927-9CC4-4E65-B970-C2560FB5C289}
• Microsoft-Windows-Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88}
Việc 1 (làm trước nhất): viết collector/dump_raw.py chạy 60 giây và in ra mọi event ID kèm các trường, để người dùng và AI xác định: event ID nào là process start/end, file create/read/write, network send/recv/connect, và tên trường chứa PID, đường dẫn, địa chỉ đích, số byte. Lưu kết quả thành docs/etw_fields.md và mọi code sau dùng bảng ánh xạ này, không hard-code theo trí nhớ.
Yêu cầu thiết kế:
• Callback chỉ làm việc tối thiểu: chuẩn hóa sự kiện thành dict, đưa vào queue.Queue(maxsize=100000). Nếu đầy thì tăng bộ đếm dropped_events (báo cáo ra UI và log).
• Một thread ghi riêng, ghi SQLite theo lô 500 sự kiện hoặc mỗi 1 giây.
• Lọc sớm: bỏ sự kiện do chính tiến trình collector gây ra; bỏ đường dẫn ồn (WinSxS, $Mft, pagefile, \\Device\\... không phải ổ đĩa người dùng) theo danh sách trong config.yaml.
• Đổi đường dẫn dạng thiết bị (\\Device\\HarddiskVolume3\\...) sang C:\\....
• proc_info.py cache thông tin tiến trình ngay khi thấy proc_start; với tiến trình đã chạy trước khi collector bật, quét psutil.process_iter lúc khởi động.
• Chữ ký số tra một lần cho mỗi exe_path và cache (kết quả: signed/unsigned, publisher).
• collector/replay.py: đọc file tests/sample_events.jsonl và phát lại như sự kiện thật, để mọi tầng sau kiểm thử được mà không cần Admin/ETW.
Nghiệm thu: chạy 5 phút khi mở trình duyệt và tải một file, thấy được sự kiện của chrome.exe/msedge.exe với các loại net_send/net_recv và file_read; dropped_events dưới 1%.
Dự phòng: nếu ETW không ổn, viết collector/sysmon_collector.py đọc Event Log của Sysmon (event 1 process create, 3 network connect, 11 file create) và ghi cùng schema. Chấp nhận mất sự kiện đọc file và ghi rõ trong báo cáo.
6. Simulator (toàn bộ vô hại)
make_fake_docs.py: tạo thư mục FakeDocuments (đặt trong Documents) gồm 50-200 file giả (txt, docx rỗng, pdf rỗng, ảnh nhỏ) với tên nghe nhạy cảm (hop_dong_thue_nha.docx, bang_luong.xlsx...) và nội dung là chuỗi ngẫu nhiên vô nghĩa. Không bao giờ dùng file thật của người dùng.
receiver.py: server TCP/HTTP đơn giản trên cổng cấu hình, ghi lại số byte nhận, thời điểm, không lưu nội dung.
leaker.py: nhận tham số --scenario N --gt data/ground_truth.csv. Trước khi chạy ghi dòng start, sau khi xong ghi dòng end: scenario,label,proc_name,pid,t_start,t_end. Các kịch bản:
#
Mô tả
Nhãn

1
Đọc nhiều file rồi gửi một lần
1

2
Gửi chậm, chia mẩu nhỏ theo thời gian
1

3
Nén zip rồi gửi
1

4
Gửi qua tiến trình con (curl hoặc python con)
1

5
Gửi qua cổng 443
1

6
Đọc ít file, gửi định kỳ (beacon)
1

7
Sao lưu thư mục lên cloud giả (benign_sync.py)
0 (khó, dùng thử báo động giả)

8
Chỉ gửi nhiều, không đọc file
0

9
Đọc nhiều file, không gửi gì
0

Mỗi kịch bản chạy lặp 15-30 lần với tham số ngẫu nhiên (số file, kích thước, trễ) để có đủ mẫu.
7. Provenance, đặc trưng, thông tin đích
sensitive.py: hàm sensitivity(path) -> float trong [0,1] theo luật: thư mục Documents/Desktop/Pictures/Downloads, đuôi file (docx, xlsx, pdf, jpg, key, pem, kdbx), vị trí trình duyệt (Login Data, Cookies, Local State) cho điểm cao; thư mục hệ thống và thư mục cài đặt của chính app cho điểm 0.
provenance.py:
• Cửa sổ trượt 60 giây, bước 15 giây, theo proc_key cộng gộp cả cây tiến trình con (dùng ppid để gom).
• Đồ thị networkx.DiGraph: nút là process, file, đích (ip:port). Cạnh process -read-> file, process -write-> file, process -send-> dest (thuộc tính bytes, ts), parent -spawn-> child.
• Cạnh nhân quả file -> dest được suy ra khi trong cùng cây tiến trình có đọc file rồi gửi trong Δt (mặc định 30 giây). Gắn trọng số theo độ gần thời gian.
• Hàm explain_path(graph, alert) trả về các đường dẫn file -> process -> dest.
features.py: với mỗi (cây tiến trình, cửa sổ) tính: n_file_read, bytes_read, n_distinct_dirs, ratio_sensitive (tỉ lệ byte đọc từ file nhạy cảm), n_file_write, bytes_sent, bytes_recv, n_dest, n_new_dest, dest_is_tracker, dest_country_rare, hour_of_day (sin/cos), n_child_proc, is_signed, send_read_ratio, burstiness (hệ số biến thiên khoảng cách giữa các lần gửi), upload_download_ratio. Chuẩn hóa: log1p cho đếm/byte; scaler fit chỉ trên tập train.
intel.py: is_tracker(domain/ip), country(ip), first_seen(dest) (lưu lịch sử đích đã thấy theo từng app). Tên miền lấy từ bộ đệm DNS nếu có (DNS-Client provider hoặc ipconfig /displaydns), nếu không thì chỉ dùng IP.
8. Mô hình
Tất cả có chung giao diện: fit(X_benign), score(X) -> np.ndarray (điểm bất thường, càng cao càng đáng ngờ), predict(X, threshold).
1. Luật (rules.py): ratio_sensitive > 0.3 AND bytes_sent > 100KB AND (n_new_dest > 0 OR dest_country_rare) AND NOT whitelisted. Whitelist: app ký số bởi publisher tin cậy nằm trong config.yaml (Microsoft, Google, Zalo...). Ngưỡng đặt trong config để chỉnh trên tập validation.
2. Isolation Forest: n_estimators=200, train chỉ trên cửa sổ lành tính.
3. Autoencoder (PyTorch): MLP d -> 16 -> 8 -> 4 -> 8 -> 16 -> d, hàm kích hoạt ReLU, loss MSE, Adam lr 1e-3, 100 epoch, early stopping theo validation lành tính. Điểm = lỗi tái tạo. Ngưỡng = phân vị 99 của lỗi trên validation lành tính (cấu hình được).
4. LSTM/GRU (tùy chọn, làm sau cùng): chuỗi 10 cửa sổ liên tiếp của cùng cây tiến trình, mô hình tái tạo chuỗi hoặc dự đoán cửa sổ kế, điểm = sai số. Chỉ làm khi 1-3 đã xong và đã đo.
Quy tắc dữ liệu (quan trọng):
• Tách train/val/test theo thời gian và theo ngày, không trộn ngẫu nhiên.
• Dữ liệu lành tính thu từ sử dụng máy thật nhiều ngày (trình duyệt, Zalo, Office, OneDrive/Google Drive, game, Windows Update). Mô hình chỉ train trên lành tính; dữ liệu rò rỉ giả lập chỉ dùng để chỉnh ngưỡng (val) và đánh giá (test).
• Mỗi kịch bản rò rỉ chia các lần chạy: một phần cho val, phần còn lại cho test, không để cùng một lần chạy xuất hiện ở cả hai.
• Đặt seed cố định, lưu cấu hình thí nghiệm kèm kết quả.
9. Đánh giá (eval/)
• label_windows.py: gán nhãn cửa sổ = 1 nếu giao nhau với khoảng [t_start, t_end] của một lần chạy nhãn 1 trong ground_truth.csv và cùng cây tiến trình; ngược lại 0.
• metrics.py: precision, recall, F1, PR-AUC, ROC-AUC, confusion matrix, báo động giả trên giờ (tính trên dữ liệu lành tính thật), thời gian phát hiện (từ lúc bắt đầu rò rỉ đến cảnh báo đầu tiên), chỉ số theo từng kịch bản.
• run_experiments.py: chạy 4 phương pháp, xuất results/summary.csv, results/per_scenario.csv, các hình PR/ROC, ma trận nhầm lẫn.
• overhead.py: đo CPU% và RAM của collector (psutil) khi idle và khi tải (tải file hàng loạt), và so thời gian một tác vụ chuẩn (sao chép 2 GB file nhỏ) khi bật/tắt collector.
• Phân tích ca sai: xuất ra danh sách false positive / false negative kèm chuỗi sự kiện để viết vào báo cáo.
10. Giải thích và giao diện
explain.py: sinh câu bằng chứng từ cửa sổ và đồ thị, ví dụ: app.exe (không ký số) đọc 12 file trong Documents (3,1 MB) rồi gửi 4,2 MB tới 203.x.x.x:443 (Singapore, chưa từng thấy) lúc 03:12. Điểm bất thường 0,93. Kèm danh sách đặc trưng đóng góp nhiều nhất (với autoencoder: các chiều có lỗi tái tạo lớn nhất).
ui/app.py (Streamlit), 4 trang:
1. Tổng quan: bảng app xếp theo rủi ro, số cảnh báo, thanh trạng thái collector (số sự kiện/giây, dropped_events).
2. Dòng thời gian: biểu đồ byte đọc/gửi theo thời gian của app đã chọn, đánh dấu cảnh báo.
3. Đồ thị provenance: hiển thị file -> process -> đích của một cảnh báo.
4. Chi tiết cảnh báo: chuỗi bằng chứng, nút Bỏ qua (thêm vào whitelist) và Chặn (chạy netsh advfirewall firewall add rule name=PG_block_<app> dir=out action=block program=<exe_path>, cần xác nhận hai bước và ghi log).
Dữ liệu hiển thị che tên người dùng trong đường dẫn.
11. Thứ tự xây dựng và tiêu chí nghiệm thu
GĐ
Yêu cầu AI làm
Nghiệm thu
1
dump_raw.py, ghi docs/etw_fields.md; etw_collector.py, proc_info.py, store.py
5 phút sự kiện trình duyệt vào được SQLite, dropped_events < 1%
2
replay.py, tests/sample_events.jsonl, bộ test pytest cho store và chuẩn hóa đường dẫn
pytest xanh không cần Admin
3
Simulator đầy đủ 9 kịch bản + ground_truth.csv
Chạy mỗi kịch bản, file ground truth đúng, receiver nhận đúng số byte
4
sensitive.py, provenance.py, features.py, intel.py
Với kịch bản 1, đồ thị có đường file -> process -> dest; vector đặc trưng không NaN
5
label_windows.py, rules.py, metrics.py; chạy baseline
Có bảng precision/recall của luật
6
iforest.py, autoencoder.py, train.py, run_experiments.py
Có summary.csv và per_scenario.csv cho 3 phương pháp
7
explain.py, ui/app.py
Chạy kịch bản 1 thì UI hiện cảnh báo kèm chuỗi bằng chứng trong dưới 60 giây
8
overhead.py, lstm.py (nếu còn thời gian), PyInstaller
Bảng overhead; file exe demo chạy được với quyền Admin
12. Quy tắc cho AI khi viết code
• Mỗi hàm có type hint và docstring ngắn; mỗi module có test trong tests/.
• Không hard-code event ID/tên trường: đọc từ docs/etw_fields.md hoặc config.yaml.
• Ghi log bằng logging, không print, trừ script dump.
• Xử lý lỗi ETW (mất session, hết buffer) bằng cách ghi log và tự khởi động lại, không làm sập tiến trình.
• Không thêm tính năng ngoài đặc tả. Nếu phát hiện đặc tả mâu thuẫn hoặc thiếu, hỏi lại trước khi tự quyết.
• Khi có số liệu (kết quả mô hình, overhead), in ra đúng như đo được. Không làm đẹp số liệu, không tự thêm dữ liệu để kết quả tốt lên.
• Không bao giờ tạo, tải hoặc chạy mã độc thật; không đọc file ngoài FakeDocuments trong các kịch bản giả lập.
13. Prompt mẫu cho từng giai đoạn
Giai đoạn 1:
Bạn là kỹ sư Python trên Windows. Dựa vào đặc tả (mục 3, 4, 5), hãy tạo collector/dump_raw.py để bật 3 provider ETW kernel trong 60 giây và in mọi event ID cùng các trường. Sau đó tạo etw_collector.py ghi vào SQLite theo schema đã cho. Giải thích cách tôi chạy với quyền Admin và cách kiểm tra kết quả. Không đoán event ID: nếu cần, hãy chờ tôi dán kết quả dump.
Giai đoạn 3:
Viết toàn bộ thư mục simulator/ theo mục 6. Mọi dữ liệu là giả, chỉ gửi về 127.0.0.1. Thêm cờ --runs N --seed S, ghi ground_truth.csv đúng định dạng. Viết test kiểm tra file ground truth.
Giai đoạn 6:
Viết train.py và run_experiments.py theo mục 8 và 9. Tách dữ liệu theo thời gian, train chỉ trên lành tính, chọn ngưỡng trên val, báo cáo trên test. Xuất bảng tổng hợp và bảng theo kịch bản. In ra cảnh báo nếu số mẫu lành tính ít hơn 5000 cửa sổ hoặc nếu có rò rỉ dữ liệu giữa các tập.
14. Hạn chế cần ghi vào báo cáo
• ETW không cho nội dung gói tin, nên truy vết là tương quan nhân quả, không phải chứng minh nội dung.
• Kết quả trên dữ liệu rò rỉ giả lập, chưa kiểm chứng với mã độc thật.
• Dữ liệu lành tính từ một số máy hạn chế, có thể không đại diện.
• Kẻ tấn công có đặc quyền kernel có thể làm giả sự kiện ETW.
• Tiến trình trung gian hợp pháp (tiêm mã vào trình duyệt) có thể che đích thật.