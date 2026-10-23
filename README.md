# Hệ Trao đổi Khoá Diffie–Hellman (Nhóm 10 – TMDT CLC C)

Bộ mã nguồn thực thi hệ mã và chương trình demo cho bài tập nhóm môn **An toàn và bảo mật thông tin**. Dự án này mô phỏng quy trình trao đổi khoá Diffie–Hellman theo các ví dụ trong chương trình học, đồng thời cung cấp giao diện CLI và giao diện web để trực quan hóa quá trình tính toán.

Giảng viên: **ThS. Nguyễn Quốc Thái**  
Khoa: **Công nghệ Thông tin**  
Trường: **Đại học Quốc gia TP.HCM - ĐHQG TP.HCM**

---

## 1. Tái hiện chính xác ví dụ trên lớp (Slide 50–51, Chương 3)

Chương trình lấy **bài toán ví dụ trên Slide 51 Chương 3** làm cấu hình mặc định cho phiên bản nhỏ, đồng thời hiển thị bảng **Bình phương và nhân** 4 cột (`i`, `b_i`, `c`, `f`) tương ứng với quá trình tính toán.

- **Tham số chung:** số nguyên tố $q = 353$, căn nguyên tố $\alpha = 3$
- **Khóa riêng ngẫu nhiên:**
  - $A$ chọn $x_A = 97$
  - $B$ chọn $x_B = 233$
- **Tính khóa công khai:**
  - $y_A = 3^{97} \bmod 353 = 40$
  - $y_B = 3^{233} \bmod 353 = 248$
- **Tính khóa phiên chung:**
  - Phía $A$: $K_{AB} = y_B^{x_A} \bmod 353 = 248^{97} \bmod 353 = 160$
  - Phía $B$: $K_{AB} = y_A^{x_B} \bmod 353 = 40^{233} \bmod 353 = 160$

Các giá trị này khớp với ví dụ trên lớp và được dùng làm kiểm chứng ban đầu cho chương trình.

### Ví dụ chi tiết

- $y_A = 3^{97} \bmod 353 = 40$  
  với $97 = 1100001_2$, dãy $f$: $3 \to 27 \to 23 \to 176 \to 265 \to 331 \to \mathbf{40}$

- $y_B = 3^{233} \bmod 353 = 248$  
  với $233 = 11101001_2$, dãy $f$: $3 \to 27 \to 69 \to 172 \to 149 \to 315 \to 32 \to \mathbf{248}$

- $K_{AB}$ phía $A$:  
  $248^{97} \bmod 353 = 160$  
  dãy $f$: $248 \to 215 \to 335 \to 324 \to 135 \to 222 \to \mathbf{160}$

- $K_{AB}$ phía $B$:  
  $40^{233} \bmod 353 = 160$  
  dãy $f$: $40 \to 107 \to 119 \to 41 \to 170 \to 307 \to 351 \to \mathbf{160}$

---

## 2. Thành viên nhóm 10

| STT | MSSV | Họ và tên |
| --- | --- | --- |
| 1 | 11244089 | Nguyễn Trung Kiên |
| 2 | 11245586 | Bùi Trần Linh Hương |
| 3 | 11241333 | Phạm Minh Dung |
| 4 | 11240133 | Tạ Huyền Trang |
| 5 | 11242778 | Phùng Trà My |

---

## 3. Cấu trúc thư mục

Dự án được tổ chức theo mô-đun rõ ràng, tách riêng thuật toán nền, giao thức, mã hóa và giao diện người dùng:

- `core/dh_math.py`: triển khai các thuật toán nền tảng trong Chương 3:
  - Thuật toán Euclid (`gcd`)
  - Euclid mở rộng (`extended_gcd`)
  - Bảng tìm phần tử nghịch đảo modulo (`mod_inverse_table`)
  - Thuật toán **Bình phương và nhân** (`square_and_multiply`)
  - Thuật toán kiểm tra số nguyên tố xác suất **Miller–Rabin**
  - Phát hiện căn nguyên tố $\alpha \bmod q$
  - Giải bài toán logarit rời rạc bằng **Baby-step Giant-step**

- `core/dh_protocol.py`: triển khai đầy đủ 2 phiên bản:
  - **TinyDH**: chạy ví dụ Slide 51 mặc định với $q=353$, $\alpha=3$, $x_A=97$, $x_B=233$
  - **Full DH**: hỗ trợ hầu hết các tham số chuẩn quốc tế, bao gồm **RFC 3526 MODP Group 14 (2048-bit)** và chế độ tự sinh Safe Prime (64–2048 bit)

- `core/dh_cipher.py`: tự cài đặt hàm băm **SHA-256** và bộ mã hóa dòng theo mô hình KDF-CTR + MAC để mã hóa/giải mã văn bản UTF-8 và file dữ liệu thực tế

- `core/dh_mitm.py`: mô phỏng tấn công **Man-in-the-Middle** của Eve trên hệ thống Slide 51 và cơ chế chống tấn công bằng chữ ký số RSA

- `tests/test_and_benchmark.py`: kiểm thử toàn bộ bài tập ví dụ trong slide và các test vector chuẩn, bao gồm **RFC 3526 2048-bit** và **NIST FIPS 180-4**

- `main_cli.py`, `web_server.py`, `web_ui/index.html`: giao diện dòng lệnh (CLI) và giao diện web trực quan

---

## 4. Hướng dẫn chạy chương trình

### 4.1 Chạy giao diện web

```bash
python3 web_server.py
```

Sau đó truy cập:

```text
http://localhost:8080
```

Hoặc mở trực tiếp file `web_ui/index.html` trong trình duyệt.

### 4.2 Chạy giao diện CLI

```bash
python3 main_cli.py
```

Nếu muốn chạy tự động hiển thị toàn bộ bảng tính tay của Slide 51 và kết quả kiểm thử:

```bash
python3 main_cli.py --auto
```

### 4.3 Chạy kiểm thử và benchmark

```bash
python3 tests/test_and_benchmark.py
```

---

## 5. Mục tiêu của dự án

Dự án này không chỉ giúp tái hiện thuật toán Diffie–Hellman mà còn giúp người xem hiểu rõ:

- cách sinh khóa công khai và khóa riêng,
- cách tính khóa chung theo nguyên lý trao đổi khóa,
- vai trò của căn nguyên thủy và modulo nguyên tố,
- cách biểu diễn quá trình tính toán bằng bảng bình phương và nhân,
- cách xây dựng giao diện trực quan để minh họa cho bài toán mật mã cơ bản.
