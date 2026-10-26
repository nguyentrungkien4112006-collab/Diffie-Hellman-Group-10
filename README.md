# Thực thi & Demo Trao đổi Khoá Diffie–Hellman (Chương 3 – Mã hoá Khoá Công khai)

**Học phần:** An toàn và Bảo mật Thông tin  
**Đơn vị:** Khoa Công nghệ Thông tin – Trường Đại học Kinh tế Quốc dân (NEU)  
**Đề tài (Nhóm B – Chương 3):** Trao đổi khoá Diffie–Hellman — Bài toán Logarit rời rạc, kèm minh hoạ Tấn công Người đứng giữa (Man-in-the-Middle) và cách phòng chống.

---

## 1. Giới thiệu & Điểm nổi bật của Dự án

Dự án được xây dựng bám sát 100% các yêu cầu trong **Hướng dẫn làm bài tập nhóm** và **Bài giảng Chương 3 (ThS. Nguyễn Quốc Thái)**:

1. **Tự cài đặt thuật toán từ đầu 100% (From Scratch):**
   - Toàn bộ phần lõi toán học và mật mã đều được nhóm tự lập trình từ đầu bằng Python thuần, **tuyệt đối không gọi thư viện mật mã có sẵn** (như `hashlib`, `Crypto`, `openssl`) hay hàm `pow(a, b, m)` cho phần lõi. Thư viện chuẩn của Python chỉ được sử dụng trong bộ kiểm thử (`tests/test_diffie_hellman.py`) để đối chiếu kết quả.
   - Đầy đủ các thuật toán nền của Chương 3:
     - Thuật toán Euclid tìm ƯSCLN $\text{GCD}(a, b)$ *(Slide 14)* và Euclid mở rộng tìm $(d, x, y)$ thoả mãn $ax + by = d$ *(Slide 15–16)*.
     - Thuật toán tìm phần tử nghịch đảo $a^{-1} \bmod n$ bằng bảng 6 cột $(r_0, r_1, r_2, q, t_0, t_1)$ *(Slide 18–22)*.
     - Thuật toán **"Bình phương và nhân" (Square-and-Multiply)** tính $a^k \bmod n$ kèm lưu bảng từng bước $(i, b_i, c, f)$ *(Slide 23–24)*.
     - Hàm Euler $\Phi(n)$, phân tích thừa số nguyên tố, kiểm tra căn nguyên tố $\alpha$ *(Slide 25–28, 50)* và kiểm tra tính nguyên tố xác suất **Miller–Rabin** *(Slide 29)*.

2. **Đầy đủ cả hai phiên bản (Phiên bản thu nhỏ & Phiên bản đầy đủ chuẩn RFC 3526):**
   - **Phiên bản thu nhỏ (Tiny Diffie–Hellman):** Tái hiện chính xác tuyệt đối Bài tập ví dụ tại **Slide 51** ($q = 353, \alpha = 3, x_A = 97, x_B = 233 \Rightarrow y_A = 40, y_B = 248, K_{AB} = 160$) và in đầy đủ bảng trung gian của thuật toán Bình phương & Nhân để minh hoạ khi thuyết trình.
   - **Phiên bản đầy đủ (Standard Diffie–Hellman):** Cài đặt các nhóm MODP chuẩn quốc tế **RFC 3526** gồm **Group 5 (1536-bit prime)** và **Group 14 (2048-bit prime)** cùng khả năng sinh số nguyên tố an toàn (Safe Prime) động.

3. **Có đủ cả hai chiều Mã hoá & Giải mã trên Văn bản và Tệp dữ liệu thật:**
   - Do bản thân Diffie–Hellman là giao thức thiết lập khoá phiên chung $K_{AB}$ *(Slide 49–50)*, nhóm đã tự cài đặt từ đầu hàm băm **SHA-256 (chuẩn FIPS 180-4)** để dẫn xuất dòng khoá (Keystream CTR Mode) và mã xác thực thông điệp (MAC 16 byte) từ $K_{AB}$.
   - Hỗ trợ nhập trực tiếp bản rõ tiếng Việt (UTF-8), tệp văn bản (`.txt`) và tệp ảnh nhỏ (`.png`), hiện bản mã rồi giải mã ngược lại **khôi phục đúng 100% từng byte và mã băm SHA-256 của bản rõ ban đầu**.

4. **Phân tích & Thực nghiệm Bài toán Logarit rời rạc (DLP) và Tấn công Người đứng giữa (MITM):**
   - Cài đặt thuật toán phá khoá **Vét cạn (Brute-force)** $\mathcal{O}(q)$ và **Bước nhỏ – Bước lớn (Baby-step Giant-step của Shanks)** $\mathcal{O}(\sqrt{q})$, đo số bước và thời gian chạy thực tế.
   - Mô phỏng trực quan kịch bản **Tấn công Người đứng giữa (MITM)** khi kênh truyền không xác thực (Eve chặn $y_A, y_B$, lập 2 khoá $K_{AE}, K_{EB}$, giải mã trộm và sửa nội dung giao dịch) và **Cách phòng chống triệt để** bằng **Chữ ký số RSA** (tự cài đặt theo *Slide 41–44*) kết hợp hạ tầng PKI *(Slide 47–48)*.

5. **Hai giao diện Demo (CLI Menu + Web App trực quan) & Bộ kiểm thử đối chiếu chuẩn:**
   - Giao diện dòng lệnh (`main.py`) có menu chọn 8 chế độ demo trực tiếp trên lớp.
   - Giao diện Web App (`web_demo/index.html`) chạy ngay trên mọi trình duyệt không cần cài đặt thêm.
   - Bộ kiểm thử tự động (`tests/test_diffie_hellman.py`) gồm 5 nhóm test case đối chiếu với kết quả tính tay trên Slide, NIST FIPS 180-4 vectors, RFC 3526 và thư viện chuẩn Python.

---

## 2. Cấu trúc Thư mục Dự án

```text
diffie-hellman-key-exchange/
├── core/                           # Package lõi thuật toán (100% tự cài đặt từ đầu)
│   ├── __init__.py                 # Export các hàm và lớp của hệ thống
│   ├── math_utils.py               # Euclid, Euclid mở rộng, Nghịch đảo bảng 6 cột, Bình phương & Nhân, Miller-Rabin
│   ├── diffie_hellman.py           # Tiny DH (Slide 51), Full DH (RFC 3526 1536/2048-bit), Thám mã DLP (Brute-force & BSGS)
│   ├── cipher_stream.py            # SHA-256 từ đầu + Mã hoá/Giải mã 2 chiều văn bản & tệp (.txt, .png) từ khoá K_AB
│   └── mitm_attack.py              # Mô phỏng tấn công MITM (Eve) & Phòng chống bằng Chữ ký số RSA (Slide 41-44)
├── tests/                          # Bộ kiểm thử tự động và đối chiếu chuẩn
│   ├── __init__.py
│   └── test_diffie_hellman.py      # 5 ca kiểm thử tự viết + đối chiếu Slide, NIST SHA-256, RFC 3526 & Python stdlib
├── sample_data/                    # Dữ liệu thật phục vụ chạy Demo mã hoá/giải mã tệp
│   ├── sample_text.txt             # Tệp hồ sơ giao dịch văn bản tiếng Việt (.txt)
│   └── sample_image.png            # Tệp hình ảnh mẫu (.png)
├── web_demo/                       # Giao diện Web App tương tác trực quan (chạy độc lập trên trình duyệt)
│   └── index.html                  # Ứng dụng Web 5 tab: Tiny DH, Full DH & File Cipher, DLP, MITM & RSA, Unit Tests
├── main.py                         # Chương trình chính có Menu CLI tương tác & Benchmark hiệu năng
├── requirements.txt                # Thông tin môi trường (Chỉ dùng Python 3.8+ Standard Library, không phụ thuộc ngoài)
├── .gitignore                      # Cấu hình bỏ qua file rác khi đẩy lên GitHub
└── README.md                       # Tài liệu hướng dẫn cài đặt, chạy demo và nộp bài GitHub
```

---

## 3. Hướng dẫn Cài đặt & Cách chạy Chương trình

### Yêu cầu hệ thống
- **Python 3.8 trở lên** (Không cần cài đặt thêm bất kỳ thư viện ngoài nào vì toàn bộ thuật toán lõi được viết từ đầu bằng Python thuần).

### Cách 1: Chạy Menu Demo tương tác trên Terminal (Khuyến nghị khi thuyết trình)
```bash
python3 main.py
```
Menu chương trình sẽ hiển thị 8 chức năng để bạn chọn trực tiếp:
- `[1]` **Phiên bản thu nhỏ (Tiny DH):** Tái hiện ví dụ Slide 51 ($q=353, \alpha=3, x_A=97, x_B=233$) & in bảng trung gian Bình phương và Nhân.
- `[2]` **Phiên bản đầy đủ (RFC 3526 2048-bit):** Nhập bản rõ bất kỳ từ bàn phím, mã hoá và giải mã khôi phục bản rõ.
- `[3]` **Demo trên dữ liệu thật:** Mã hoá và giải mã tệp văn bản (`sample_data/sample_text.txt`) và tệp ảnh (`sample_data/sample_image.png`), đối chiếu mã băm SHA-256.
- `[4]` **Bài toán Logarit rời rạc (DLP):** So sánh tốc độ phá khoá giữa Vét cạn $\mathcal{O}(q)$ và Baby-step Giant-step $\mathcal{O}(\sqrt{q})$.
- `[5]` **Minh hoạ Tấn công Người đứng giữa (MITM) & Phòng chống bằng Chữ ký số RSA.**
- `[6]` **Đo hiệu năng (Benchmark):** Đo thời gian chạy theo kích thước khoá (9-bit $\to$ 2048-bit) và kích thước dữ liệu (1 KB $\to$ 100 KB).
- `[7]` **Chạy bộ Kiểm thử tự động (Unit Tests) & in kết quả đối chiếu.**
- `[8]` **Chạy liên hoàn tất cả các phần (Full Demo 1 $\to$ 7).**

### Cách 2: Chạy tự động toàn bộ kịch bản Demo (Không dừng chờ nhập phím)
```bash
python3 main.py --all
```

### Cách 3: Chạy độc lập Bộ kiểm thử (Unit Tests)
```bash
python3 tests/test_diffie_hellman.py
```

### Cách 4: Chạy Giao diện Đồ hoạ Web App (Trực quan trên trình duyệt)
Mở trực tiếp tệp `web_demo/index.html` bằng trình duyệt bất kỳ (Chrome, Edge, Firefox, Safari) để thao tác trực quan trên 5 tab chức năng.

---

## 4. Hướng dẫn Đẩy dự án lên GitHub & Thể hiện Đóng góp của từng Thành viên

Theo yêu cầu trong hướng dẫn bài tập nhóm (*"khuyến khích dùng GitHub và thể hiện được đóng góp của từng thành viên qua lịch sử commit"*), nhóm có thể thực hiện theo quy trình chuẩn sau:

### Bước 1: Khởi tạo Git Repository và đẩy khung dự án lên GitHub
```bash
cd diffie-hellman-key-exchange
git init
git branch -M main
git remote add origin https://github.com/<ten-tai-khoan>/<ten-repo-nhom>.git
```

### Bước 2: Phân chia nhánh/commit theo từng module để thể hiện rõ lịch sử đóng góp
Nếu nhóm có từ 3–5 thành viên, mỗi thành viên phụ trách commit phần việc của mình (hoặc dùng `git commit --author="Ten Thanh Vien <email@domain.com>"` khi tổng hợp):

1. **Thành viên 1 (Cơ sở toán học & Thuật toán nền):**
   ```bash
   git add core/__init__.py core/math_utils.py
   git commit -m "feat(math): implement Euclid, 6-column mod inverse, Square-and-Multiply and Miller-Rabin from scratch"
   ```
2. **Thành viên 2 (Lõi Diffie-Hellman thu nhỏ, RFC 3526 & Thám mã DLP):**
   ```bash
   git add core/diffie_hellman.py
   git commit -m "feat(dh): implement Tiny DH (Slide 51), RFC 3526 2048-bit MODP and BSGS discrete log solver"
   ```
3. **Thành viên 3 (SHA-256, Mã hoá/Giải mã 2 chiều Text & File + Tấn công MITM & RSA):**
   ```bash
   git add core/cipher_stream.py core/mitm_attack.py sample_data/
   git commit -m "feat(security): add from-scratch SHA-256 stream cipher, MITM attack simulation and RSA signature defense"
   ```
4. **Thành viên 4 (Kiểm thử đối chiếu chuẩn, CLI Demo & Web App GUI):**
   ```bash
   git add tests/ main.py web_demo/ README.md requirements.txt .gitignore
   git commit -m "test & ui: add NIST/RFC3526 verification test suite, interactive CLI menu and web demo"
   ```
5. **Đẩy toàn bộ lịch sử lên GitHub:**
   ```bash
   git push -u origin main
   ```

---

## 5. Minh bạch Sử dụng Công cụ Hỗ trợ & Tài liệu Tham khảo

- **Ghi chú sử dụng AI (theo Mục 5 – Lưu ý khác của Hướng dẫn BTN):** Nhóm có sử dụng công cụ AI để hỗ trợ rà soát cấu trúc module chuẩn GitHub, kiểm tra định dạng bảng in kết quả trung gian và thiết kế giao diện CSS (Tailwind) cho bản Web Demo; toàn bộ thuật toán lõi trong thư mục `core/` đều bám sát công thức và giả mã trong Bài giảng Chương 3 để mọi thành viên nắm vững và giải thích chi tiết từng dòng lệnh khi bảo vệ.
- **Tài liệu tham khảo:**
  1. ThS. Nguyễn Quốc Thái, *Bài giảng An toàn và Bảo mật Thông tin – Chương 3: Mã hoá khoá công khai*, Khoa CNTT, Trường Đại học Kinh tế Quốc dân (NEU).
  2. Whitfield Diffie & Martin E. Hellman (1976), *"New Directions in Cryptography"*, IEEE Transactions on Information Theory, Vol. IT-22, No. 6, pp. 644–654.
  3. IETF RFC 3526 (2003), *"More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)"*.
  4. NIST FIPS PUB 180-4 (2015), *"Secure Hash Standard (SHS)"*.
