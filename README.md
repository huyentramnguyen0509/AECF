# Adaptive Exploit Chaining Framework (AECF) — Prototype

Khung code này implement đúng những gì đã chốt trong đề cương:
- `core/state.py` — State Representation Model (Chương 3.3)
- `core/memory.py` — Memory Mechanism: Session + Failure Memory (Chương 3.6)
- `core/planner.py` — Adaptive Planning Engine (Chương 3.4)
- `agents/agents.py` — 4 agent: Recon-Analyzer, Planner, Execution-Evaluator, Memory (Chương 3.5)
- `agents/llm_client.py` — gọi Anthropic API để sinh reasoning trace
- `tools/wrappers.py` — wrapper SQLMap / Nuclei / Requests (Chương 4.4)
- `orchestrator.py` — Algorithm 1 & 2, chạy 1 phiên pentest end-to-end
- `experiments/run_experiments.py` — sinh dữ liệu thô cho Chương 5 (3 condition x N lần lặp)
- `experiments/summarize_results.py` — tổng hợp mean ± std, xuất bảng cho Phụ lục C

## 1. Cài đặt

```bash
pip install -r requirements.txt

# Tool ngoài, không cài qua pip:
pip install sqlmap            # hoặc: git clone https://github.com/sqlmapproject/sqlmap
# nuclei:
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Copy `.env.example` thành `.env` (hoặc export trực tiếp):
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

## 2. Dựng target (DVWA / Juice Shop) — bắt buộc chạy local, có kiểm soát

```bash
# DVWA
docker run --rm -it -p 8080:80 vulnerables/web-dvwa

# Juice Shop
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Sau khi DVWA lên, vào `http://localhost:8080/setup.php` để init database trước khi chạy agent.

⚠️ **Chỉ chạy framework nhắm vào target bạn tự dựng / được cấp phép rõ ràng
(DVWA, Juice Shop, CTF lab). Không nhắm vào domain thật không được phép.**

## 3. Chạy một phiên pentest

```bash
python orchestrator.py --target http://localhost:8080 --name dvwa --max-steps 15
```

In ra reasoning trace từng bước (dùng trực tiếp cho Phụ lục A), lưu state đầy
đủ (bao gồm attack graph) vào `storage/runs/<session_id>.json`.

Chạy nhánh ablation không Memory:
```bash
python orchestrator.py --target http://localhost:8080 --name dvwa --no-memory
```

## 4. Sinh dữ liệu thực nghiệm Chương 5 (đây là phần bạn hỏi "kiếm data")

```bash
python -m experiments.run_experiments --target http://localhost:8080 --repeats 8
python -m experiments.summarize_results --plot
```

- `run_experiments.py` tự động chạy **3 kịch bản ablation** (`full`,
  `no_memory`, `static`) × N lần lặp (mặc định 8, khuyến nghị 5–10 theo
  5.3.1), ghi raw data vào `storage/experiments_raw.csv`.
- `summarize_results.py` gộp CSV đó thành bảng **mean ± std** cho từng
  metric (Success Rate, Planning Time, Re-planning Count, Exploit Chain
  Length, Coverage, Exploit Efficiency) — đúng 6 tiêu chí 5.4, xuất ra
  `storage/experiments_summary.csv` + in bảng Markdown để dán thẳng vào
  Chương 5.6 / Phụ lục C.

## 5. Việc còn cần bạn tự làm thêm (chưa code ở prototype này)

- Mở rộng `ReconAnalyzerAgent.seed_known_vuln_candidates()` nếu muốn recon
  động thay vì seed cứng theo cấu trúc DVWA/Juice Shop đã biết.
- Đẩy `AttackGraph` sang Neo4j thật (hiện đang dùng networkx in-memory, đủ
  cho JSON export nhưng Dashboard 4.5.1 cần Neo4j driver riêng nếu muốn
  trực quan hoá tương tác).
- Viết layer FastAPI + Dashboard (Chương 4.1, 4.5) — hiện orchestrator chạy
  CLI, chưa có REST API/UI.
- Target thứ 3 (CTF-style) để generalization test — chưa có wrapper riêng,
  chỉ cần thêm case trong `ReconAnalyzerAgent`.

## Cấu trúc thư mục

```
aecf/
├── core/            # state.py, memory.py, planner.py — "data" nền tảng
├── agents/          # 4 agent + llm_client.py
├── tools/           # wrapper sqlmap/nuclei/requests
├── experiments/      # sinh + tổng hợp dữ liệu Chương 5
├── storage/         # json_store.py + output (runs/, *.csv chạy ra)
├── orchestrator.py  # entry point 1 phiên
└── requirements.txt
```
