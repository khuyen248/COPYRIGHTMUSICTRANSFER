<h1 align="center">ATBMTT - Gửi Tập Tin Nhạc Có Bản Quyền </h1>

## 📝 MÔ TẢ
Hệ thống web cho phép người dùng gửi tập tin nhạc `.mp3` có bản quyền một cách **an toàn, bảo mật và toàn vẹn**.  
Ứng dụng sử dụng các thuật toán mật mã để mã hóa nội dung, ký số metadata, kiểm tra toàn vẹn dữ liệu và xác thực nguồn gửi.

## 🎯 Mục tiêu
- Đảm bảo bản quyền và nội dung nhạc không bị giả mạo.
- Truyền tải dữ liệu giữa bên gửi và bên nhận qua giao thức an toàn.
- Mã hóa file, metadata và kiểm tra toàn vẹn dữ liệu.


## 🌟 TÍNH NĂNG NỔI BẬT
🔐 Mã hóa file nhạc bằng Triple DES

🧾 Metadata được mã hóa bằng DES

🖊️ Ký số bằng RSA/SHA-512 để xác thực

✅ Kiểm tra toàn vẹn gói tin bằng SHA-512

🔄 Giao thức bắt tay xác minh danh tính

🌐 Giao diện web dễ dùng, gửi/nhận file nhanh chóng

## 🔐 Công nghệ sử dụng
- Flask (Python web framework)
- SQLite (cơ sở dữ liệu nhẹ)
- Thuật toán:
  - Triple DES (mã hóa file nhạc)
  - DES (mã hóa metadata)
  - RSA 2048-bit (ký số và trao khóa)
  - SHA-512 (kiểm tra toàn vẹn IV và ciphertext)

## 🔁 Quy trình xử lý
1. **Handshake:**  
   Bên gửi gửi “Hello!”, bên nhận trả lời “Ready!” và gửi public key.

2. **Gửi file:**  
   - Người dùng chọn file `.mp3` và nhập metadata (tiêu đề, tác giả, album, năm).
   - File và metadata được mã hóa, ký số, đóng gói thành gói tin.
3. **Gói tin gửi đi gồm:**
```powershell
{
  "iv": "<Base64_IV>",
  "cipher": "<Base64_file_mã_hóa>",
  "meta": "<Base64_metadata_mã_hóa>",
  "hash": "<SHA-512 của IV || cipher>",
  "sig": "<Chữ ký RSA của metadata>",
  "key": "<SessionKey + DES key được mã hóa RSA>"
}
   ```
4. **Bên nhận:**

- Giải mã session key bằng RSA

- Kiểm tra hash và chữ ký

- Giải mã metadata và file

- Cho phép tải về file gốc nếu hợp lệ

## 🧾 HƯỚNG DẪN SỬ DỤNG 
⚙️ 1. **Cài đặt môi trường**
Bước 1: Cài Python (nếu chưa có)
Yêu cầu: Python 3.8 trở lên

Kiểm tra: 
``` powershellpython --version ```

Bước 2: Cài thư viện
Tạo và kích hoạt môi trường ảo (tuỳ chọn):
``` 
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
 ```

 Cài đặt các thư viện:
 ```pip install Flask Flask_SQLAlchemy cryptography pyDes``` 

 🧠 **2. Khởi tạo cơ sở dữ liệu**
 Chạy main.py để tạo database music_transfer.db:
  ```python main.py ```
  Hệ thống sẽ:

- Xoá và tạo mới toàn bộ bảng

- Khởi chạy ứng dụng tại địa chỉ: http://localhost:5000

## 📂 CẤU TRÚC THƯ MỤC
COPYRIGHTMUSICTRANSFER/
├── __pycache__/              # File tạm biên dịch Python
├── instance/
│   └── music_transfer.db     # CSDL SQLite lưu thông tin gửi/nhận
├── static/                   # File tĩnh cho giao diện web
│   ├── app.js                # JavaScript xử lý front-end
│   └── style.css             # Giao diện CSS
├── templates/                # Giao diện HTML Flask
├── uploads/                  # Lưu file nhạc đã mã hóa/giải mã
├── app.py                    # Flask app chính, định nghĩa route & xử lý logic
├── crypto_utils.py           # Mã hóa: RSA, 3DES, DES, SHA-512
├── secure_protocol.py        # Giao thức bảo mật, đóng gói/gỡ gói tin
├── main.py                   # Chạy app + tạo DB
└── README.MD                 # Tài liệu mô tả hệ thống

