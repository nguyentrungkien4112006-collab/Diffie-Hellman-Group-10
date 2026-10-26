# Thực thi & Demo Trao đổi Khoá Diffie–Hellman (Chương 3 – Mã hoá Khoá Công khai)

**Học phần:** An toàn và Bảo mật Thông tin  
**Đơn vị:** Khoa Công nghệ Thông tin – Trường Đại học Kinh tế Quốc dân 
**Đề tài (Nhóm B – Chương 3):** Trao đổi khoá Diffie–Hellman — Bài toán Logarit rời rạc, kèm minh hoạ Man-in-the-Middle và cách phòng chống.

---

## 1. Giới thiệu & Điểm nổi bật của Dự án

1. **Tự cài đặt thuật toán từ đầu 100% :**
   - Toàn bộ phần lõi toán học và mật mã đều được nhóm tự lập trình từ đầu bằng Python thuần như `hashlib`, `Crypto`, `openssl` hay hàm `pow(a, b, m)` cho phần lõi. Thư viện chuẩn của Python chỉ được sử dụng trong bộ kiểm thử (`tests/test_diffie_hellman.py`) để đối chiếu kết quả.
   - Đầy đủ các thuật toán nền của Chương 3:
     - Thuật toán Euclid tìm ƯSCLN 
     - Thuật toán tìm phần tử nghịch đảo 
     - Thuật toán **"Bình phương và nhân"** 
     - Hàm Euler, phân tích thừa số nguyên tố, kiểm tra căn nguyên tố và kiểm tra tính nguyên tố xác suất **Miller–Rabin**.

2. **Đầy đủ cả hai phiên bản (Phiên bản thu nhỏ & Phiên bản đầy đủ chuẩn RFC 3526):**
   - **Phiên bản thu nhỏ (Tiny Diffie–Hellman)
   - **Phiên bản đầy đủ (Standard Diffie–Hellman):** Cài đặt các nhóm MODP chuẩn quốc tế **RFC 3526** gồm **Group 5 (1536-bit prime)** và **Group 14 (2048-bit prime)** cùng khả năng sinh số nguyên tố an toàn động.

3. **Có đủ cả hai chiều Mã hoá & Giải mã trên Văn bản và Tệp dữ liệu thật:**
   - Do bản thân Diffie–Hellman là giao thức thiết lập khoá phiên chung, nhóm đã tự cài đặt từ đầu hàm băm **SHA-256 (chuẩn FIPS 180-4)** để dẫn xuất dòng khoá và mã xác thực thông điệp.
   - Hỗ trợ nhập trực tiếp bản rõ tiếng Việt, tệp văn bản (`.txt`) và tệp ảnh nhỏ (`.png`), hiện bản mã rồi giải mã ngược lại **khôi phục đúng 100% từng byte và mã băm SHA-256 của bản rõ ban đầu**.

4. **Phân tích & Thực nghiệm Bài toán Logarit rời rạc và Tấn công Người đứng giữa:**
   - Cài đặt thuật toán phá khoá **Vét cạn** và **Bước nhỏ – Bước lớn**, đo số bước và thời gian chạy thực tế.
   - Mô phỏng trực quan kịch bản **Tấn công Người đứng giữa** khi kênh truyền không xác thực và **Cách phòng chống triệt để** bằng **Chữ ký số RSA** kết hợp hạ tầng PKI.

5. **Hai giao diện Demo (CLI Menu + Web App trực quan) & Bộ kiểm thử đối chiếu chuẩn:**
   - Giao diện dòng lệnh (`main.py`) có menu chọn 8 chế độ demo trực tiếp trên lớp.
   - Giao diện Web App (`web_demo/index.html`) chạy ngay trên mọi trình duyệt không cần cài đặt thêm.
   - Bộ kiểm thử tự động (`tests/test_diffie_hellman.py`) gồm 5 nhóm test case đối chiếu với kết quả tính tay trên Slide, NIST FIPS 180-4 vectors, RFC 3526 và thư viện chuẩn Python.

---

## 2. Cấu trúc Thư mục Dự án

```text
diffie-hellman-key-exchange/
├── core/                           # Package lõi thuật toán 
│   ├── __init__.py                 # Export các hàm và lớp của hệ thống
│   ├── math_utils.py               # Euclid, Euclid mở rộng, Nghịch đảo bảng 6 cột, Bình phương & Nhân, Miller-Rabin
│   ├── diffie_hellman.py           # Tiny DH, Full DH (RFC 3526 1536/2048-bit), Thám mã DLP 
│   ├── cipher_stream.py            # SHA-256 từ đầu + Mã hoá/Giải mã 2 chiều văn bản & tệp (.txt, .png) từ khoá K_AB
│   └── mitm_attack.py              # Mô phỏng tấn công MITM (Eve) & Phòng chống bằng Chữ ký số RSA 
├── tests/                          # Bộ kiểm thử tự động và đối chiếu chuẩn
│   ├── __init__.py
│   └── test_diffie_hellman.py      # 5 ca kiểm thử tự viết + đối chiếu Slide, NIST SHA-256, RFC 3526 & Python stdlib
├── sample_data/                    # Dữ liệu thật phục vụ chạy Demo mã hoá/giải mã tệp
│   ├── sample_text.txt             # Tệp hồ sơ giao dịch văn bản tiếng Việt (.txt)
│   └── sample_image.png            # Tệp hình ảnh mẫu (.png)
├── web_demo/                       # Giao diện Web App tương tác trực quan (chạy độc lập trên trình duyệt)
│   └── index.html                  # Ứng dụng Web 5 tab: Tiny DH, Full DH & File Cipher, DLP, MITM & RSA, Unit Tests
├── main.py                         # Chương trình chính có Menu CLI tương tác & Benchmark hiệu năng
├── requirements.txt                # Thông tin môi trường: Chỉ dùng Python 3.8 + Standard Library, không phụ thuộc ngoài
├── .gitignore                      # Cấu hình bỏ qua file rác khi đẩy lên GitHub
└── README.md                       # Tài liệu hướng dẫn cài đặt, chạy demo
```

---

## 3. Hướng dẫn Cài đặt & Cách chạy Chương trình

### Yêu cầu hệ thống
- **Python 3.8 trở lên** (Không cần cài đặt thêm bất kỳ thư viện ngoài nào vì toàn bộ thuật toán lõi được viết từ đầu bằng Python thuần).

### Cách 1: Chạy Menu Demo tương tác trên Terminal 
```bash
python3 main.py
```
Menu chương trình sẽ hiển thị 8 chức năng để bạn chọn trực tiếp:
- `[1]` **Phiên bản thu nhỏ:** Tái hiện ví dụ Slide 51 ($q=353, \alpha=3, x_A=97, x_B=233$) & in bảng trung gian Bình phương và Nhân.
- `[2]` **Phiên bản đầy đủ:** Nhập bản rõ bất kỳ từ bàn phím, mã hoá và giải mã khôi phục bản rõ.
- `[3]` **Demo trên dữ liệu thật:** Mã hoá và giải mã tệp văn bản (`sample_data/sample_text.txt`) và tệp ảnh (`sample_data/sample_image.png`), đối chiếu mã băm SHA-256.
- `[4]` **Bài toán Logarit rời rạc:** So sánh tốc độ phá khoá giữa Vét cạn và Baby-step Giant-step.
- `[5]` **Minh hoạ Tấn công Người đứng giữa & Phòng chống bằng Chữ ký số RSA.**
- `[6]` **Đo hiệu năng:** Đo thời gian chạy theo kích thước khoá (9-bit to 2048-bit) và kích thước dữ liệu (1 KB to 100 KB).
- `[7]` **Chạy bộ Kiểm thử tự động & in kết quả đối chiếu.**
- `[8]` **Chạy liên hoàn tất cả các phần.**

### Cách 2: Chạy tự động toàn bộ kịch bản Demo 
```bash
python3 main.py --all
```

### Cách 3: Chạy độc lập Bộ kiểm thử 
```bash
python3 tests/test_diffie_hellman.py
```

### Cách 4: Chạy Giao diện Đồ hoạ Web App 
Mở trực tiếp tệp `(https://nguyentrungkien4112006-collab.github.io/Diffie-Hellman-Group-10/)` bằng trình duyệt bất kỳ để thao tác trực quan trên 5 tab chức năng.

- **Tài liệu tham khảo:**
  1. ThS. Nguyễn Quốc Thái, *Bài giảng An toàn và Bảo mật Thông tin – Chương 3: Mã hoá khoá công khai*, Khoa CNTT, Trường Đại học Kinh tế Quốc dân (NEU).
  2. Whitfield Diffie & Martin E. Hellman (1976), *"New Directions in Cryptography"*, IEEE Transactions on Information Theory, Vol. IT-22, No. 6, pp. 644–654.
  3. IETF RFC 3526 (2003), *"More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)"*.
  4. NIST FIPS PUB 180-4 (2015), *"Secure Hash Standard (SHS)"*.
