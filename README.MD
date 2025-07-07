<h1 align="center">ATBMTT - Gửi Tập Tin Nhạc Có Bản Quyền </h1>
 Một nhà phát triển ứng dụng âm nhạc gửi file song.mp3 đến nền tảng phát trực tuyến, kèm metadata bản quyền được  mã hóa riêng để bảo vệ quyền sở hữu. File được mã hóa bằng Triple DES và ký số để đảm bảo an toàn, với tính toàn  vẹn được kiểm tra để ngăn chặn giả mạo.

### 1. GIỚI THIỆU

Trong thời đại chuyển đổi số, việc truyền tải nội dung số như âm nhạc cần đảm bảo các yếu tố về bản quyền, bảo mật và xác thực. Nếu không có các biện pháp bảo vệ, file nhạc có thể bị đánh cắp, chỉnh sửa hoặc phát tán trái phép.

Đề tài này xây dựng một hệ thống truyền tập tin nhạc có bản quyền với các mục tiêu chính:

- Bảo mật nội dung tập tin nhạc bằng thuật toán Triple DES.

- Bảo vệ metadata (tên bài, bản quyền) bằng mã hóa DES.

- Xác thực người gửi bằng chữ ký số RSA 1024-bit (OAEP + SHA-512).

- Đảm bảo toàn vẹn dữ liệu bằng hàm băm SHA-512.

- Hệ thống mô phỏng mô hình truyền dữ liệu giữa nhà phát triển và nền tảng phát nhạc.

### 2. TRÌNH BÀY KỸ THUẬT
   
a. Kiến trúc hệ thống
- Mô hình: Client – Server đơn giản mô phỏng vai trò:

  + Người gửi (Developer): chọn file, mã hóa, ký số và gửi.
   
  + Người nhận (Receiver): kiểm tra hash, xác thực chữ ký và giải mã.

- Luồng xử lý:

![image](https://github.com/user-attachments/assets/a4979048-02c2-428c-a6a3-a46b02f7369c)

b. Thành phần kỹ thuật
- Triple DES (3DES):

  + Mã hóa đối xứng 3 vòng
  
  + Tạo IV ngẫu nhiên cho mỗi lần mã hóa file.

- Mã hóa metadata bằng DES:

  + Metadata gồm: tên file, tên nghệ sĩ, năm phát hành.
  
  + Dùng khóa DES 64-bit riêng để mã hóa riêng biệt phần thông tin bản quyền.

- RSA 1024-bit + OAEP:

 RSA được dùng để:

  + Mã hóa session key (Triple DES key).
  
  + Ký số metadata sau khi băm bằng SHA-512.
 
 Sử dụng OAEP + SHA-512 tăng cường chống phân tích.

- SHA-512:

  + Băm dữ liệu (IV || ciphertext) để tạo hash kiểm tra toàn vẹn khi nhận.

c. Các module chính
- crypto_utils.py: Xử lý mã hóa DES, Triple DES, ký số RSA, sinh khóa, tính hash SHA-512.

- secure_protocol.py: Định nghĩa quy trình đóng gói/gỡ gói bảo mật, handshake, ACK/NACK.

- app.py: Xây dựng giao diện người gửi/người nhận bằng Flask, định tuyến URL.

- main.py: Khởi tạo ứng dụng, tạo CSDL và chạy server Flask.

⚙️ Công nghệ: Flask, cryptography, base64, hashlib, SQLAlchemy, uuid.

d. Kết quả
- Giao diện trang chủ
![image](https://github.com/user-attachments/assets/1bf0fd03-90e3-4c02-a016-27edd619793e)
- Giao diện trang người gửi
![image](https://github.com/user-attachments/assets/c1e067ef-7baa-4e50-b1fa-bb2cf703ffce)
- Giao diện hiển thị lịch sử file gửi
![image](https://github.com/user-attachments/assets/d6a39899-491e-4dde-86e5-af9ccc532650)
- Giao diện trang người nhận
![image](https://github.com/user-attachments/assets/5f5b4b51-5ca6-4806-b76e-9f7ca33712a5)
- Giao diện trang quản lý tập tin
![image](https://github.com/user-attachments/assets/0ab1e7d7-9ee3-47a0-9bf0-be49d4955989)
- Giao diện trang xử lý kết nối
![image](https://github.com/user-attachments/assets/c1c3e5fb-8e5a-4d02-89b8-28ca808ae8e7)

### 3. CẤU TRÚC THƯ MỤC
```
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
```

### 4. CÁCH CÀI ĐẶT VÀ CHẠY
a. Yêu cầu
Python ≥ 3.8

- Các thư viện:

  + cryptography
  
  + flask
  
  + flask_sqlalchemy
  
  + uuid, hashlib, base64

b. Cài đặt và chạy
- Cài thư viện
  
   ```powershell
  pip install cryptography flask flask_sqlalchemy
   ```
- Chạy server Flask

   ```powershell
   python main.py
   ```

- Truy cập giao diện
Mở trình duyệt và truy cập:
   ```powershell
   http://127.0.0.1:5000
   ```

→ Chọn vai trò người gửi/người nhận để bắt đầu truyền file bảo mật.
