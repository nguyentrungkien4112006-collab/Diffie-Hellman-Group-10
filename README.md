# Hệ Trao đổi Khoá Diffie – Hellman (Nhóm 10 – TMDT CLC C)

Bộ mã nguồn thực thi hệ mã và chương trình chạy demo cho bài tập nhóm môn **An toàn và bảo mật thông tin** (Giảng viên: **ThS. Nguyễn Quốc Thái** – Khoa CNTT, ĐH CNTT & TT, ĐHQG TP.HCM).

## 1. Tái hiện chính xác Ví dụ trên lớp (Slide 50–51 Chương 3)

Chương trình lấy **BTVD trên Slide 51 Chương 3** làm cấu hình mặc định cho phiên bản nhỏ, đồng thời lập bảng **Bình phương và nhân** 4 dòng (`i`, `b_i`, `c`, `f`) điền vào dấu `=....=` trên Slide 51.

* **Tham số chung:** Số nguyên tố $q = 353$, căn nguyên tố $\alpha = 3$.
* **Khoá mật ngẫu nhiên:** $A$ chọn $x_A = 97$, $B$ chọn $x_B = 233$.
* **Tính các khoá công khai (kèm bảng `i, b_i, c, f` điền vào dấu `=....=` trên Slide 51):**
  * $y_A = 3^{97} \bmod 353 = 40$ (với $97 = 1100001_2$, dãy $f$: $3 \to 27 \to 23 \to 176 \to 265 \to 331 \to \mathbf{40}$).
  * $y_B = 3^{233} \bmod 353 = 248$ (với $233 = 11101001_2$, dãy $f$: $3 \to 27 \to 69 \to 172 \to 149 \to 315 \to 32 \to \mathbf{248}$).
* **Tính khoá phiên chung $K_{AB}$:**
  * Phía $A$: $K_{AB} = y_B^{x_A} \bmod 353 = 248^{97} \bmod 353 = 160$ (dãy $f$: $248 \to 215 \to 335 \to 324 \to 135 \to 222 \to \mathbf{160}$).
  * Phía $B$: $K_{AB} = y_A^{x_B} \bmod 353 = 40^{233} \bmod 353 = 160$ (dãy $f$: $40 \to 107 \to 119 \to 41 \to 170 \to 307 \to 351 \to \mathbf{160}$).

## 2. Thành viên Nhóm 10

| STT | MSSV | Họ và tên |
| --- | --- | --- |
| 1 | 11244089 | Nguyễn Trung Kiên |
| 2 | 11245586 | Bùi Trần Linh Hương |
| 3 | 11241333 | Phạm Minh Dung |
| 4 | 11240133 | Tạ Huyền Trang |
| 5 | 11242778 | Phùng Trà My |

## 3. Cấu trúc thư mục (Chia module rõ ràng, tách thuật toán khỏi giao diện)

* `core/dh_math.py`: Tự cài đặt từ đầu toàn bộ thuật toán nền tảng trong Slide Chương 3:
  * Thuật toán Euclide (`gcd` – Slide 14), Euclide mở rộng (`extended_gcd` – Slide 15–16) và Bảng 6 cột tìm phần tử nghịch đảo (`mod_inverse_table` – Slide 18–22).
  * Thuật toán **Bình phương và nhân** (`square_and_multiply` – Slide 23–24) xuất bảng 4 dòng (`i`, `b_i`, `c`, `f`).
  * Thuật toán kiểm tra số nguyên tố xác suất **Miller–Rabin** (`is_prime_miller_rabin` – Slide 29: phân tích $n - 1 = 2^k \cdot q$).
  * Thuật toán kiểm tra/tìm căn nguyên tố $\alpha \bmod q$ và giải bài toán Logarit rời rạc bằng **Baby-step Giant-step** $O(\sqrt{q})$.
* `core/dh_protocol.py`: Cài đặt đầy đủ 2 phiên bản:
  * **Phiên bản thu nhỏ (TinyDH)**: Mặc định chạy BTVD Slide 51 ($q=353, \alpha=3, x_A=97, x_B=233 \Rightarrow y_A=40, y_B=248, K_{AB}=160$) và hỗ trợ bộ số nhỏ bất kỳ ($q=2[...]$.
  * **Phiên bản đầy đủ (Full DH)**: Hỗ trợ tham số chuẩn quốc tế **RFC 3526 MODP Group 14 (2048-bit)** và chế độ tự sinh Safe Prime (64–2048 bit).
* `core/dh_cipher.py`: Tự cài đặt hàm băm **SHA-256** (FIPS 180-4) và bộ mã hoá dòng KDF-CTR + MAC để mã hoá/giải mã văn bản tiếng Việt UTF-8 và tệp dữ liệu thật.
* `core/dh_mitm.py`: Mô phỏng tấn công **Man-in-the-Middle** của Eve trên bộ tham số Slide 51 ($q=353, \alpha=3$) và cơ chế phòng chống bằng chữ ký số RSA.
* `tests/test_and_benchmark.py`: Kiểm thử toàn bộ các BTVD trong Slide Chương 3 (Slide 16, 21, 22, 24, 51) c��ng Test Vector chuẩn **RFC 3526 2048-bit** và **NIST FIPS 180-4**.
* `main_cli.py`, `web_server.py` & `web_ui/index.html`: Giao diện dòng lệnh (CLI) và giao diện Web trực quan.

## 4. Hướng dẫn chạy chương trình

* **Chạy Giao diện Web:** `python3 web_server.py` rồi mở `http://localhost:8080` (hoặc mở trực tiếp `web_ui/index.html`).
* **Chạy Giao diện CLI có menu:** `python3 main_cli.py` (hoặc `python3 main_cli.py --auto` để in toàn bộ bảng tính tay Slide 51 và kết quả kiểm thử).
* **Chạy Kiểm thử & Benchmark:** `python3 tests/test_and_benchmark.py`.
