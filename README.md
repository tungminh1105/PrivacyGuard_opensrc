# PrivacyGuard: Hệ Thống Giám Sát & Phát Hiện Rò Rỉ Dữ Liệu Cá Nhân Trên Windows

> **Dự án Nghiên cứu Khoa học Kỹ thuật (KHKT)**  
> **Lĩnh vực**: Hệ thống phần mềm & An toàn thông tin (Software Systems & Cybersecurity)  
> **Phương pháp tiếp cận**: Phân tích nhân quả luồng dữ liệu (Data Provenance), Trích xuất đặc trưng thời gian (Temporal Sliding Windows), Học máy/Học sâu (Isolation Forest, MLP Autoencoder, Rule-based Engine) và Giám sát thường trực thời gian thực với Biểu tượng khay hệ thống (Real-time System Tray Guard).

---

## 1. Giới thiệu Đề tài & Ý nghĩa Khoa học

### 1.1. Bối cảnh & Tính cấp thiết
Trong kỷ nguyên số, các vụ rò rỉ dữ liệu cá nhân (Personal Identifiable Information - PII, tài liệu tài chính, session cookies, mật khẩu) trên máy trạm Windows ngày càng diễn biến phức tạp. Mã độc và ứng dụng gián điệp tinh vi thường qua mặt phần mềm diệt virus truyền thống bằng cách:
- Sử dụng kênh truyền mã hóa HTTPS/TLS (cổng 443) tới các dịch vụ đám mây công cộng hoặc CDN trung gian.
- Chia nhỏ dữ liệu và truyền chậm rãi (slow trickle / periodic beaconing) để tránh các ngưỡng lưu lượng mạng thông thường.
- Khởi tạo tiến trình con (`subprocess`) nhằm che giấu nguồn gốc đọc file nhạy cảm.

### 1.2. Giải pháp của PrivacyGuard
PrivacyGuard xây dựng một kiến trúc bảo vệ toàn diện với các đóng góp cốt lõi:
1. **Bảo vệ quyền riêng tư tuyệt đối (Privacy-Preserving)**: Không can thiệp giải mã gói tin (SSL/TLS Inspection), thay vào đó phát hiện bất thường dựa trên **quan hệ nhân quả luồng sự kiện (Event Causality Correlation)**.
2. **Đồ thị nhân quả dữ liệu (Data Provenance Graph)**: Dựng đồ thị có hướng (`NetworkX DiGraph`) phân cấp 3 tầng (*Sensitive File* $\rightarrow$ *Process Tree* $\rightarrow$ *Network Socket*) trong cửa sổ thời gian $\Delta t = 30s$ để chứng minh nguồn gốc dữ liệu.
3. **Phát hiện đa tầng (3-Tier Detection Architecture)**:
   - **Tầng 1 (Rule-based Baseline)**: Đánh giá tức thì dựa trên luật cứng, ngưỡng nhạy cảm và tính mới của IP đích.
   - **Tầng 2 (Isolation Forest)**: Học không giám sát (*Unsupervised One-class*) trên không gian đặc trưng 17 chiều từ hành vi lành tính.
   - **Tầng 3 (MLP Autoencoder)**: Mạng nơ-ron học sâu tính toán sai số tái tạo (*MSE Reconstruction Error*) để nhận diện các bất thường phi tuyến tính.
4. **Giải thích chuỗi bằng chứng (Explainable AI - XAI)**: Chuyển đổi điểm số toán học thành chuỗi lập luận tự nhiên, trực quan hóa đồ thị nhân quả trên giao diện Streamlit và đề xuất lệnh chặn tường lửa an toàn.
5. **Cấp độ thương mại (Commercial Real-time Protection & System Tray)**: Daemon giám sát nền thời gian thực thu nhỏ xuống khay hệ thống Windows cạnh đồng hồ, tự động bắn thông báo Windows Toast khi phát hiện rò rỉ.

---

## 2. Kiến trúc Hệ thống

```
+-----------------------------------------------------------------------------------+
|                            WINDOWS OS (KERNEL & USERLAND)                         |
|                                                                                   |
|  [Sysmon Driver]  --> Event ID 1 (Process Start), ID 3 (Network), ID 11 (File)    |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| 1. AGENT COLLECTOR & REAL-TIME GUARD (core/guard_service.py)                     |
|    - Polling dựa trên EventRecordID Watermark (10s/lần, không callback)           |
|    - Bộ lọc nhiễu 2 lớp: Drop Patterns & Noise Tagging (noise_candidate=1)        |
|    - SQLite WAL EventStore (events, processes, file_zones, alerts)                |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| 2. PROVENANCE & FEATURE ENGINE (core/)                                            |
|    - sensitive.py: Nhận diện đường dẫn & tính điểm nhạy cảm [0.0, 1.0]            |
|    - intel.py: Phân loại IP nội bộ / LAN, phát hiện đích đến mới xuất hiện         |
|    - provenance.py: Dựng đồ thị NetworkX, Process Hierarchy, CAUSAL_FLOW edges     |
|    - features.py: Trích xuất vector đặc trưng 17 chiều không có giá trị khuyết    |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| 3. MULTI-MODEL DETECTION ENGINE (models/)                                         |
|    - Rule-based Detector: Ngưỡng dung lượng, file nhạy cảm, IP mới                |
|    - Isolation Forest (n_estimators=200): Học trên tập mẫu lành tính thuần túy   |
|    - PyTorch MLP Autoencoder (17 -> 8 -> 4 -> 8 -> 17): MSE Reconstruction Error   |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| 4. GIAO DIỆN & TƯƠNG TÁC NGƯỜI DÙNG (ui/)                                         |
|    - ui/tray_app.py: Biểu tượng lá chắn bảo vệ dưới khay hệ thống (System Tray)   |
|    - Windows Toast Notification (winotify): Báo động rò rỉ dữ liệu tức thì         |
|    - ui/app.py: Dashboard 4 tab (Overview, Timeline, Provenance Graph, Evaluation) |
+-----------------------------------------------------------------------------------+
```

---

## 3. Không gian Vector Đặc trưng 17 Chiều (`features.py`)

| STT | Tên đặc trưng | Ý nghĩa khoa học |
|:---:|:---|:---|
| 1 | `n_file_create` | Số sự kiện tạo file trong cửa sổ trượt |
| 2 | `n_sensitive_files` | Số lượng file thuộc thư mục nhạy cảm (Documents, Desktop, Credentials...) |
| 3 | `ratio_sensitive_events`| Tỷ lệ sự kiện file nhạy cảm trên tổng số sự kiện file |
| 4 | `n_distinct_dirs` | Số thư mục khác nhau được truy xuất |
| 5 | `n_net_connect` | Số kết nối mạng hướng ngoại được thiết lập |
| 6 | `total_bytes_sent` | Tổng số byte gửi đi (log1p scale) |
| 7 | `n_distinct_dest_ips` | Số lượng địa chỉ IP đích riêng biệt |
| 8 | `n_new_dest` | Số lượng IP đích chưa từng xuất hiện trong lịch sử tiến trình |
| 9 | `dest_is_tracker` | Cờ nhận diện IP/Domain thuộc danh sách theo dõi/quảng cáo |
| 10| `is_local_dest_only` | Cờ chỉ kết nối tới mạng nội bộ / Private LAN |
| 11| `n_child_proc` | Số tiến trình con được khởi tạo bởi tiến trình này |
| 12| `is_signed_process` | Tiến trình có chữ ký số hợp lệ của nhà phát triển |
| 13| `process_lifetime` | Thời gian sống của tiến trình tính từ lúc khởi động |
| 14| `burstiness` | Hệ số biến thiên khoảng cách thời gian giữa các lần truyền mạng |
| 15| `hour_of_day_sin` | Thành phần sin của thời điểm trong ngày (chu kỳ 24h) |
| 16| `hour_of_day_cos` | Thành phần cos của thời điểm trong ngày (chu kỳ 24h) |
| 17| `has_causal_flow` | Tồn tại cạnh CAUSAL_FLOW nối từ File nhạy cảm tới Network Socket |

---

## 4. Kết quả Thực nghiệm & Đo đạc Độc lập

### 4.1. Hiệu năng Phát hiện Bất thường (Evaluation on 9 Scenarios)
Đánh giá trên 117 lượt chạy độc lập của 9 kịch bản rò rỉ và đối chứng:

| Mô hình | Precision | Recall | F1-Score | PR-AUC | ROC-AUC | Số ca sai (FP / FN) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Rule-based Detector** | **1.0000** | **0.9796** | **0.9897** | **0.9951** | **0.9898** | **0 / 3** |
| **Isolation Forest** | 0.9267 | 0.9456 | 0.9360 | 0.9724 | 0.9704 | 11 / 8 |
| **Autoencoder (PyTorch)**| 0.6400 | 0.6531 | 0.6465 | 0.8405 | 0.7935 | 54 / 51 |

### 4.2. Đánh giá Tải Tài nguyên Hệ thống (Overhead Benchmark)
Đo lường độc lập bằng công cụ `eval/overhead.py` trên Windows:

| Tiêu chí | Kết quả đo thực tế | Ngưỡng yêu cầu SPEC | Trạng thái Nghiệm thu |
|:---|:---:|:---:|:---:|
| **CPU Usage (Collector Live)** | **0.0%** | $< 5.0\%$ | **ĐẠT (PASS)** |
| **CPU Usage (Collector Live Peak)** | **0.0%** | $< 10.0\%$ | **ĐẠT (PASS)** |
| **RAM Footprint (Collector Standalone)** | **26.66 MB** | $< 150.0\text{ MB}$ | **ĐẠT (PASS)** |
| **Tỷ lệ rơi rớt sự kiện (Drop Ratio)** | **0.0%** (0 / 3,000) | $< 1.0\%$ | **ĐẠT (PASS)** |
| **Thông lượng nạp (Throughput)** | **65,360.6 sự kiện/giây** | $> 500\text{ eps}$ | **ĐẠT (PASS)** |
| **Tác động trễ File I/O hệ thống** | **+0.33%** | $< 10.0\%$ | **ĐẠT (PASS)** |
| **Độ trễ suy luận Rule Detector** | **0.0070 ms/cửa sổ** | $< 5.0\text{ ms}$ | **ĐẠT (PASS)** |
| **Độ trễ suy luận Isolation Forest** | **0.0429 ms/cửa sổ** | $< 5.0\text{ ms}$ | **ĐẠT (PASS)** |
| **Độ trễ suy luận Autoencoder** | **0.0026 ms/cửa sổ** | $< 10.0\text{ ms}$ | **ĐẠT (PASS)** |

---

## 5. Hướng dẫn Cài đặt & Vận hành

### 5.1. Khởi chạy Ứng dụng Khay Hệ thống (System Tray Mode - Khuyến nghị)
Khi chạy không có tham số, PrivacyGuard mặc định thu nhỏ thành **biểu tượng chiếc khiên xanh** ở khay hệ thống (góc dưới bên phải màn hình):

```powershell
# Bằng Python
python cli.py

# Hoặc bằng file thực thi độc lập (Standalone Exe)
.\dist\privacyguard\privacyguard.exe
```

**Thao tác với Menu Chuột Phải:**
- **"Trạng thái: Đang bảo vệ (Running)"**: Nhấp để Tạm dừng (Pause) hoặc Tiếp tục (Resume).
- **"Mở Web Dashboard"**: Tự động kích hoạt Streamlit Dashboard và mở trình duyệt web.
- **"Quét ngay (Scan Now)"**: Ép phân tích ngay lập tức các sự kiện vừa phát sinh.
- **"Xem số cảnh báo"**: Xem số lượng cảnh báo vi phạm hiện có.
- **"Thoát (Exit)"**: Dừng toàn bộ worker an toàn và thoát ứng dụng.

### 5.2. Các Lệnh Giao Diện Dòng Lệnh (CLI Commands)
```powershell
# Xem trạng thái hệ thống và cơ sở dữ liệu
python cli.py info

# Chạy bộ thu thập Sysmon 60 giây
python cli.py collect --duration 60

# Chạy giả lập 9 kịch bản rò rỉ dữ liệu an toàn
python cli.py simulate --runs 1

# Đánh giá toàn diện các mô hình (Rules, IForest, Autoencoder)
python cli.py eval --runs 12

# Đo đạc tải tài nguyên hệ thống
python cli.py benchmark --duration 10 --stress-events 5000

# Khởi chạy giao diện Web Dashboard độc lập
python cli.py ui
```

---

## 6. Kịch bản Demo Dành cho Ban Giám Khảo Cuộc thi KHKT

Quy trình demo 4 bước thuyết phục trước Ban Giám khảo:

1. **Bước 1: Trình diễn Khay Hệ thống & Chế độ Bảo vệ Nền**
   - Nhấp đúp vào `dist/privacyguard/privacyguard.exe` hoặc chạy `python cli.py`.
   - Chỉ cho Ban Giám khảo thấy **Biểu tượng lá chắn bảo vệ** xuất hiện cạnh đồng hồ Windows Taskbar.
   - Mở menu chuột phải để thấy trạng thái *"Đang bảo vệ (Running)"*.

2. **Bước 2: Kích hoạt Kịch bản Giả lập Rò rỉ Dữ liệu**
   - Mở terminal chạy: `python cli.py simulate --runs 1`.
   - Tiến trình vi phạm đọc file nhạy cảm trong `data/FakeDocuments` và gửi dữ liệu ra ngoài qua kết nối mạng.

3. **Bước 3: Báo động Tức thì qua Windows Toast & Web Dashboard**
   - Thông báo Windows Toast của hệ thống bật lên góc phải màn hình:
     `"[PrivacyGuard] Phát hiện Rò rỉ Dữ liệu! Tiến trình python.exe đã gửi ... ra ngoài sau khi truy cập file nhạy cảm. Click để mở Dashboard."`
   - Nhấp vào thông báo hoặc chọn *"Mở Web Dashboard"* trên khay hệ thống.
   - Ban Giám khảo sẽ thấy:
     + **Tab 1 (Overview)**: KPI cảnh báo tăng lên.
     + **Tab 2 (Timeline)**: Chuỗi chứng cứ được giải thích bằng ngôn ngữ tự nhiên rõ ràng.
     + **Tab 3 (Provenance Graph)**: Đồ thị nhân quả phân cấp trực quan với cạnh `CAUSAL_FLOW` màu đỏ.
     + **Tab 4 (Model Evaluation)**: Biểu đồ Radar so sánh chi tiết các mô hình.

4. **Bước 4: Chứng minh Tải Hệ thống Nhẹ**
   - Mở Task Manager hoặc xem bảng [results/overhead_summary.csv](file:///d:/KERNAL%20PROTECT/privacyguard/results/overhead_summary.csv):
     Collector Agent chỉ dùng **~27 MB RAM** và **0.0% CPU**, đảm bảo không ảnh hưởng đến bất kỳ tác vụ nào của người dùng.

---

## 7. Cấu trúc Thư mục Dự án

```
privacyguard/
├── config.yaml               # Cấu hình ngưỡng nhạy cảm, cổng mạng, bộ lọc nhiễu
├── requirements.txt          # Danh sách thư viện Python
├── cli.py                    # Entry point giao diện dòng lệnh hợp nhất & Tray launcher
├── build.py                  # Script đóng gói Standalone Executable (PyInstaller)
├── assets/                   # Biểu tượng lá chắn bảo vệ (icon.png, icon.ico)
├── collector/
│   └── sysmon_collector.py   # Bộ thu thập Sysmon watermark polling & EventStore
├── core/
│   ├── store.py              # SQLite EventStore (events, processes, alerts)
│   ├── sensitive.py          # Quy tắc nhận diện đường dẫn nhạy cảm
│   ├── intel.py              # Kiểm tra IP/Domain tracker và new destination
│   ├── provenance.py         # Động cơ đồ thị nhân quả NetworkX & Process Hierarchy
│   ├── features.py           # Trích xuất vector đặc trưng 17 chiều
│   ├── explain.py            # Giải thích chuỗi chứng cứ XAI & sinh lệnh Firewall
│   └── guard_service.py      # Real-time Protection daemon & Windows Toast notifier
├── simulator/
│   ├── make_fake_docs.py     # Sinh 100 file nhạy cảm giả lập
│   ├── receiver.py           # Server TCP kiểm thử nội bộ (chỉ đếm byte)
│   ├── leaker.py             # 9 kịch bản rò rỉ dữ liệu giả lập
│   └── benign_sync.py        # Giả lập đồng bộ file lành tính
├── models/
│   ├── rules.py              # Rule-based Detector
│   ├── iforest.py            # Isolation Forest Detector (unsupervised)
│   └── autoencoder.py        # PyTorch MLP Autoencoder Detector
├── eval/
│   ├── dataset.py            # Tạo tập train/val/test theo thời gian
│   ├── metrics.py            # Tính Precision, Recall, F1, PR/ROC AUC, Latency
│   ├── run_experiments.py    # Pipeline thực nghiệm và xuất bảng so sánh
│   └── overhead.py           # Đo lường tài nguyên CPU, RAM, Drop Ratio, I/O
├── ui/
│   ├── app.py                # Dashboard trực quan tương tác 4 tab Streamlit
│   └── tray_app.py           # Ứng dụng khay hệ thống Windows (pystray & Pillow)
├── tests/                    # 54 unit & integration tests (100% PASS)
├── docs/
│   ├── SPEC.md               # Đặc tả kỹ thuật đề tài
│   ├── PROGRESS.md           # Nhật ký tiến độ chi tiết từng giai đoạn
│   └── LIMITATIONS.md        # Báo cáo trung thực các giới hạn kỹ thuật
└── results/                  # Bảng kết quả thực nghiệm và số liệu đo đạc
```

---

## 8. Cam kết Đạo đức Nghiên cứu
- 100% dữ liệu sử dụng trong nghiên cứu là dữ liệu giả lập trong môi trường cách ly an toàn (`data/FakeDocuments`).
- Hệ thống không thu thập, sửa đổi hay truyền tải bất kỳ tệp tin hoặc thông tin cá nhân thực tế nào của người dùng.
