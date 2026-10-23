#!/usr/bin/env python3
"""
Giao diện dòng lệnh (CLI) có Menu tiếng Việt cho đề tài:
Trao đổi khoá Diffie–Hellman (Nhóm 10 - An toàn và bảo mật thông tin).
Tái hiện chính xác BTVD trên lớp (Slide 50–51 Chương 3 - ThS. Nguyễn Quốc Thái):
  q = 353, α = 3, x_A = 97, x_B = 233 => y_A = 40, y_B = 248, K_AB = 160
kèm bảng "Bình phương và nhân" 4 hàng (i, b_i, c, f) theo đúng Slide 23–24.
"""

import os
import sys

from core import (
    encrypt_decrypt_file_demo,
    encrypt_decrypt_text_demo,
    run_full_dh_exchange,
    run_tiny_dh_exchange,
    simulate_mitm_attack,
    simulate_mitm_defense_authenticated_dh,
)
from tests.test_and_benchmark import ensure_sample_files, run_all_tests, run_benchmarks


def print_banner() -> None:
    print("\n" + "=" * 84)
    print("   CHƯƠNG TRÌNH DEMO: HỆ TRAO ĐỔI KHOÁ DIFFIE–HELLMAN (NHÓM 10 - TMDT CLC C)")
    print("   Giảng viên hướng dẫn: ThS. Nguyễn Quốc Thái (Khoa CNTT - ĐH Kinh tế Quốc dân)")
    print("   Thành viên: Nguyễn Trung Kiên, Bùi Trần Linh Hương, Phạm Minh Dung,")
    print("               Tạ Huyền Trang, Phùng Trà My")
    print("=" * 84)


def print_slide24_table(steps: list) -> None:
    """In bảng ngang 4 dòng (i, b_i, c, f) giống hệt Slide 24 Chương 3."""
    col_w = 5
    row_i = "     | i   |" + "|".join(f"{st['i']:^{col_w}d}" for st in steps) + "|"
    row_b = "     | b_i |" + "|".join(f"{st['b_i']:^{col_w}d}" for st in steps) + "|"
    row_c = "     | c   |" + "|".join(f"{st['c']:^{col_w}d}" for st in steps) + "|"
    row_f = "     | f   |" + "|".join(f"{st['f']:^{col_w}d}" for st in steps) + "|"
    sep = "     +" + "-" * 5 + "+" + "+".join("-" * col_w for _ in steps) + "+"
    print(sep)
    print(row_i)
    print(sep)
    print(row_b)
    print(sep)
    print(row_c)
    print(sep)
    print(row_f)
    print(sep)


def demo_1_tiny_dh(
    q: int = 353, alpha: int = 3, x_A: int = 97, x_B: int = 233, msg: str = "NHOM 10 DH NEU"
) -> None:
    print("\n" + "-" * 84)
    print(
        f"[PHẦN 1] TÁI HIỆN VÍ DỤ TRÊN LỚP (SLIDE 51 CHƯƠNG 3): "
        f"q = {q}, α = {alpha}, x_A = {x_A}, x_B = {x_B}"
    )
    print("-" * 84)
    res = run_tiny_dh_exchange(p=q, g=alpha, a=x_A, b=x_B)
    root_info = res["primitive_root_analysis"]
    print("1. Kiểm tra tham số chung (q, α):")
    print(f"   - q = {q} là số nguyên tố (Miller–Rabin Slide 29): {res['parameters']['is_prime_q']}")
    print(f"   - Φ(q) = q - 1 = {root_info['phi']}, các ước nguyên tố của Φ(q): {root_info['prime_factors_of_phi']}")
    for chk in root_info["factor_checks"]:
        print(
            f"     + Kiểm tra α^((q-1)/{chk['prime_factor']}) mod q = "
            f"{alpha}^{chk['exponent']} mod {q} = {chk['alpha_pow_exp_mod_q']} != 1 -> {chk['passed']}"
        )
    print(f"   => Kết luận α = {alpha} là căn nguyên tố của mod {q}: {res['parameters']['is_primitive_root_alpha']}")

    print("\n2. Bảng tính từng bước thuật toán 'Bình phương và nhân' (Slide 23–24 & Slide 51):")
    for label, base_v, exp_v, pub_v, trace_list in [
        ("Tính khoá công khai của A: y_A = α^(x_A) mod q", alpha, x_A, res["alice"]["y_A"], res["alice"]["trace_A"]),
        ("Tính khoá công khai của B: y_B = α^(x_B) mod q", alpha, x_B, res["bob"]["y_B"], res["bob"]["trace_B"]),
        ("A tính khoá phiên chung: K_AB = y_B^(x_A) mod q", res["bob"]["y_B"], x_A, res["alice"]["K_AB"], res["alice"]["trace_KA"]),
        ("B tính khoá phiên chung: K_AB = y_A^(x_B) mod q", res["alice"]["y_A"], x_B, res["bob"]["K_AB"], res["bob"]["trace_KB"]),
    ]:
        print(f"\n   * {label}: {base_v}^{exp_v} mod {q} = {pub_v} (nhị phân k = {exp_v} = {bin(exp_v)[2:]}_2):")
        print_slide24_table(trace_list)
        for st in trace_list:
            print(f"     - i={st['i']} (b_{st['i']}={st['b_i']}): {st['formula']}")

    print(f"\n3. Đối chiếu kết quả Slide 51 và Mã hoá / Giải mã bản rõ '{msg}':")
    print(
        f"   - y_A = {res['alice']['y_A']} | y_B = {res['bob']['y_B']} | "
        f"K_AB(của A) = {res['alice']['K_AB']} | K_AB(của B) = {res['bob']['K_AB']} | "
        f"Khớp pow() chuẩn: {res['verification']['stdlib_pow_match']}"
    )
    cipher_demo = encrypt_decrypt_text_demo(msg, res["alice"]["K_AB"], res["bob"]["K_AB"])
    print(f"   - Khoá phiên dẫn xuất SHA-256(K_AB): {cipher_demo['session_key_alice_hex']}")
    print(f"   - Bản rõ ban đầu   : {cipher_demo['original_text']}")
    print(f"   - Bản mã (Hex)     : {cipher_demo['ciphertext_hex']}")
    print(f"   - Giải mã ngược lại: {cipher_demo['recovered_text']} (Khớp 100%: {cipher_demo['exact_match']})")


def demo_2_full_dh_and_real_files() -> None:
    print("\n" + "-" * 84)
    print("[PHẦN 2] DEMO PHIÊN BẢN ĐẦY ĐỦ (RFC 3526 - 2048 BIT) & MÃ HOÁ TỆP DỮ LIỆU THẬT")
    print("-" * 84)
    res = run_full_dh_exchange(mode="rfc3526_2048")
    print(f"1. Nguồn tham số: {res['param_source']}")
    print(f"   - Độ dài q: {res['p_bits']} bit | α = {res['g']}")
    print(f"   - Khoá công khai y_A (rút gọn): {res['alice']['A_hex'][:48]}...")
    print(f"   - Khoá công khai y_B (rút gọn): {res['bob']['B_hex'][:48]}...")
    print(f"   - Khoá phiên chung K_AB       : {res['shared_secret_hex'][:48]}...")
    print(f"   - Khớp K_AB(A) == K_AB(B) và khớp pow() chuẩn: {res['verification']['stdlib_pow_match']} ({res['exchange_ms']} ms)")

    files = ensure_sample_files()
    sample_dir = files["sample_dir"]
    k = res["shared_secret_int"]
    txt_res = encrypt_decrypt_file_demo(
        files["txt_path"],
        os.path.join(sample_dir, "thong_diep_nhom10.enc"),
        os.path.join(sample_dir, "thong_diep_nhom10_recovered.txt"),
        k,
        k,
    )
    png_res = encrypt_decrypt_file_demo(
        files["png_path"],
        os.path.join(sample_dir, "logo_nhom10.enc"),
        os.path.join(sample_dir, "logo_nhom10_recovered.png"),
        k,
        k,
    )
    print("\n2. Kết quả mã hoá & giải mã trên dữ liệu thật:")
    for item in (txt_res, png_res):
        print(f"   * Tệp gốc: {item['input_file']} ({item['original_size_bytes']} bytes)")
        print(f"     - Tệp bản mã : {item['encrypted_file']} ({item['encrypted_size_bytes']} bytes)")
        print(f"     - Tệp giải mã: {item['decrypted_file']} ({item['decrypted_size_bytes']} bytes)")
        print(f"     - SHA-256 gốc == SHA-256 giải mã: {item['byte_for_byte_match']} ({item['original_sha256'][:32]}...)")


def demo_3_mitm_attack_and_defense() -> None:
    print("\n" + "-" * 84)
    print("[PHẦN 3] MÔ PHỎNG TẤN CÔNG NGƯỜI ĐỨNG GIỮA (MAN-IN-THE-MIDDLE) & CÁCH PHÒNG CHỐNG")
    print("-" * 84)
    mitm = simulate_mitm_attack(p=353, g=3, a=97, b=233, e1=45, e2=112)
    print(f"1. Khi KHÔNG xác thực khoá công khai trên bộ số bài giảng (q=353, α=3, x_A=97, x_B=233):")
    print(f"   - A gửi y_A = {mitm['keys']['alice_public_A']}, bị Eve chặn và tráo thành y_E1 = {mitm['keys']['eve_public_E1_to_bob']} gửi cho B.")
    print(f"   - B gửi y_B = {mitm['keys']['bob_public_B']}, bị Eve chặn và tráo thành y_E2 = {mitm['keys']['eve_public_E2_to_alice']} gửi cho A.")
    print(f"   - Khoá chung A–Eve: K_AE = {mitm['shared_secrets']['K_Alice_Eve']} | Khoá chung B–Eve: K_BE = {mitm['shared_secrets']['K_Bob_Eve']} (thay vì K_AB = 160)")
    print(f"   - Tin nhắn A gửi đi   : \"{mitm['message_flow']['alice_sent_plaintext']}\"")
    print(f"   - Eve giải mã đọc trộm: \"{mitm['message_flow']['eve_decrypted_plaintext']}\"")
    print(f"   - Tin nhắn B nhận được: \"{mitm['message_flow']['bob_decrypted_plaintext']}\"")

    defense = simulate_mitm_defense_authenticated_dh(p=353, g=3, a=97, b=233, e1=45)
    print(f"\n2. Cơ chế phòng chống bằng Chữ ký số RSA (Authenticated Diffie–Hellman):")
    print(f"   - A ký lên y_A = {defense['alice_signed_message']['dh_public_A']} bằng khoá bí mật RSA -> Chữ ký sig_A = {defense['alice_signed_message']['rsa_signature_sigA']}")
    print(f"   - Kết quả khi Eve tráo y_A thành y_E1 = {defense['eve_attack_attempt']['eve_fake_public_E1']}:")
    print(f"     + {defense['eve_attack_attempt']['reason']}")


def demo_4_tests_and_benchmark() -> None:
    print("\n" + "-" * 84)
    print("[PHẦN 4] BỘ KIỂM THỬ ĐỐI CHIẾU & ĐO THỜI GIAN CHẠY (BENCHMARK)")
    print("-" * 84)
    suite = run_all_tests()
    for tc in suite["test_cases"]:
        mark = "PASS" if tc["passed"] else "FAIL"
        print(f"   [{mark}] {tc['id']} - {tc['name']}: {tc['actual']}")
    print(f"   => Tổng kết: {suite['passed_tests']}/{suite['total_tests']} ca kiểm thử đạt 100%.")

    bench = run_benchmarks()
    print("\n   Bảng đo thời gian trao đổi khoá theo độ dài bit của q:")
    for row in bench["key_size_benchmarks"]:
        print(
            f"   - {row['p_bits']:4d}-bit: Tự cài đặt = {row['custom_square_multiply_ms']:8.4f} ms | "
            f"Python pow() = {row['python_stdlib_pow_ms']:8.4f} ms"
        )


def interactive_menu() -> None:
    while True:
        print_banner()
        print("  1. Chạy BTVD chuẩn trên lớp (Slide 51: q=353, α=3, x_A=97, x_B=233 => y_A=40, y_B=248, K_AB=160)")
        print("  2. Chạy bộ số siêu nhỏ (q=23, α=5, x_A=6, x_B=15 => y_A=8, y_B=19, K_AB=2)")
        print("  3. Nhập tham số (q, α, x_A, x_B, bản rõ) tuỳ chỉnh từ bàn phím")
        print("  4. Chạy phiên bản đầy đủ (RFC 3526 2048-bit) & Mã hoá tệp .txt / .png thật")
        print("  5. Mô phỏng tấn công Người đứng giữa (Man-in-the-Middle) & Phòng chống RSA")
        print("  6. Chạy bộ kiểm thử đối chiếu (Test Suite) & Đo thời gian chạy (Benchmark)")
        print("  7. Chạy liền mạch toàn bộ kịch bản bảo vệ")
        print("  8. Bật màn hình Giao diện Đồ hoạ (Web GUI) trên trình duyệt")
        print("  0. Thoát chương trình")
        choice = input("\nNhập lựa chọn của bạn (0-8): ").strip()

        if choice == "1":
            demo_1_tiny_dh(353, 3, 97, 233, "NHOM 10 DH NEU")
        elif choice == "2":
            demo_1_tiny_dh(23, 5, 6, 15, "NHOM 10 DH")
        elif choice == "3":
            try:
                q = int(input("  Nhập số nguyên tố q (mặc định 353): ") or "353")
                alpha = int(input("  Nhập căn nguyên tố α (mặc định 3): ") or "3")
                x_A = int(input("  Nhập khoá mật x_A (mặc định 97): ") or "97")
                x_B = int(input("  Nhập khoá mật x_B (mặc định 233): ") or "233")
                msg = input("  Nhập bản rõ cần mã hoá (mặc định 'An toan bao mat Nhom 10'): ") or "An toan bao mat Nhom 10"
                demo_1_tiny_dh(q=q, alpha=alpha, x_A=x_A, x_B=x_B, msg=msg)
            except Exception as exc:
                print(f"  [Lỗi dữ liệu đầu vào]: {exc}")
        elif choice == "4":
            demo_2_full_dh_and_real_files()
        elif choice == "5":
            demo_3_mitm_attack_and_defense()
        elif choice == "6":
            demo_4_tests_and_benchmark()
        elif choice == "7":
            demo_1_tiny_dh(353, 3, 97, 233, "NHOM 10 DH NEU")
            demo_2_full_dh_and_real_files()
            demo_3_mitm_attack_and_defense()
            demo_4_tests_and_benchmark()
        elif choice == "8":
            from run_gui import main as launch_gui
            launch_gui()
        elif choice == "0":
            print("Đã thoát chương trình. Chúc Nhóm 10 bảo vệ đạt điểm tối đa!")
            break
        else:
            print("Lựa chọn không hợp lệ, vui lòng chọn từ 0 đến 7.")


if __name__ == "__main__":
    if "--auto" in sys.argv:
        print_banner()
        demo_1_tiny_dh(353, 3, 97, 233, "NHOM 10 DH NEU")
        demo_2_full_dh_and_real_files()
        demo_3_mitm_attack_and_defense()
        demo_4_tests_and_benchmark()
    else:
        interactive_menu()
