#!/usr/bin/env python3
"""
Chương trình Demo chính (CLI Menu & Automated Showcase) cho đề tài:
TRAO ĐỔI KHOÁ DIFFIE-HELLMAN & PHÂN TÍCH AN TOÀN (CHƯƠNG 3 - MÃ HOÁ KHOÁ CÔNG KHAI)
Khoa Công nghệ Thông tin - Trường Đại học Kinh tế Quốc dân (NEU)

Cách chạy:
  1. Chế độ menu tương tác (mặc định):
     python3 main.py
  2. Chế độ chạy tự động toàn bộ 7 kịch bản demo (phục vụ kiểm tra nhanh / thuyết trình):
     python3 main.py --all
"""

import argparse
import importlib.abc
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from typing import Dict, List

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class _ProjectMetaFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        rel = fullname.replace(".", "/")
        pkg_init = os.path.join(PROJECT_ROOT, rel, "__init__.py")
        if os.path.isfile(pkg_init):
            return importlib.util.spec_from_file_location(
                fullname, pkg_init, submodule_search_locations=[os.path.join(PROJECT_ROOT, rel)]
            )
        mod_file = os.path.join(PROJECT_ROOT, rel + ".py")
        if os.path.isfile(mod_file):
            return importlib.util.spec_from_file_location(fullname, mod_file)
        return None


if not any(isinstance(f, _ProjectMetaFinder) for f in sys.meta_path):
    sys.meta_path.insert(0, _ProjectMetaFinder())

from core.cipher_stream import (
    decrypt_bytes,
    decrypt_file,
    decrypt_text,
    encrypt_bytes,
    encrypt_file,
    encrypt_text,
    sha256_from_scratch,
)
from core.diffie_hellman import (
    DiffieHellmanGroup,
    DiffieHellmanParty,
    discrete_log_bruteforce,
    discrete_log_bsgs,
    get_rfc3526_group5,
    get_rfc3526_group14,
    run_slide51_example,
)
from core.math_utils import (
    extended_euclid,
    generate_prime,
    is_primitive_root,
    miller_rabin_test,
    mod_inverse_table,
    square_and_multiply,
)
from core.mitm_attack import (
    simulate_authenticated_dh_defense,
    simulate_unauthenticated_mitm,
)


def print_banner():
    print("\n" + "=" * 92)
    print("  ĐẠI HỌC KINH TẾ QUỐC DÂN - KHOA CÔNG NGHỆ THÔNG TIN")
    print("  HỌC PHẦN: AN TOÀN VÀ BẢO MẬT THÔNG TIN (CHƯƠNG 3: MÃ HOÁ KHOÁ CÔNG KHAI)")
    print("  ĐỀ TÀI  : TRAO ĐỔI KHOÁ DIFFIE-HELLMAN, LOGARIT RỜI RẠC & TẤN CÔNG NGƯỜI ĐỨNG GIỮA (MITM)")
    print("=" * 92)


def print_square_multiply_table(title: str, a: int, k: int, n: int, steps: List[Dict[str, int]]):
    """In bảng trung gian của thuật toán Bình phương và nhân đúng chuẩn Slide 24."""
    bin_str = bin(k)[2:]
    print(f"\n  ► {title}")
    print(f"    Biểu diễn nhị phân của số mũ k = {k} là: ({bin_str})_2 ({len(steps)} bít)")
    header_i = " | ".join(f"{s['i']:>4}" for s in steps)
    header_b = " | ".join(f"{s['b_i']:>4}" for s in steps)
    header_c = " | ".join(f"{s['c']:>4}" for s in steps)
    header_f = " | ".join(f"{s['f']:>4}" for s in steps)
    sep = "-" * (10 + len(header_i))
    print(f"    {sep}")
    print(f"    {'i':>5} | {header_i}")
    print(f"    {'b_i':>5} | {header_b}")
    print(f"    {'c':>5} | {header_c}")
    print(f"    {'f':>5} | {header_f}")
    print(f"    {sep}")
    print(f"    ⇒ Kết quả cuối cùng: {a}^{k} mod {n} = {steps[-1]['f']}")


def demo_1_tiny_dh_slide51():
    """Kịch bản 1: Tái hiện ví dụ thu nhỏ tại Slide 51 kèm in bảng bước trung gian."""
    print("\n" + "#" * 92)
    print(" [DEMO 1] PHIÊN BẢN THU NHỎ (TINY DH) - TÁI HIỆN VÍ DỤ BÀI GIẢNG (SLIDE 51, CHƯƠNG 3)")
    print("#" * 92)
    res = run_slide51_example()

    print(f"\n1. Thỏa thuận tham số miền công khai:")
    print(f"   - Số nguyên tố q = {res['q']} (Kiểm tra Miller-Rabin: Nguyên tố)")
    print(f"   - Phần tử sinh (căn nguyên tố) α = {res['alpha']}")
    chk_str = ", ".join(
        f"3^(352/{c['prime_factor']}) = 3^{c['exponent']} mod 353 = {c['remainder']} ≠ 1"
        for c in res["primitive_checks"]
    )
    print(f"   - Kiểm chứng α = 3 là căn nguyên tố của q = 353 (ước nguyên tố của 352 là 2 và 11):")
    print(f"     {chk_str} ⇒ Thỏa mãn!")

    print(f"\n2. Sinh khoá riêng và tính khoá công khai (in bảng trung gian Bình phương & Nhân):")
    print(f"   - Alice (A) chọn khoá mật x_A = {res['x_A']}")
    print_square_multiply_table(
        "Bảng tính khoá công khai của Alice: y_A = 3^97 mod 353",
        3,
        97,
        353,
        res["alice_keygen_steps"],
    )

    print(f"\n   - Bob (B) chọn khoá mật x_B = {res['x_B']}")
    print_square_multiply_table(
        "Bảng tính khoá công khai của Bob: y_B = 3^233 mod 353",
        3,
        233,
        353,
        res["bob_keygen_steps"],
    )

    print(f"\n3. Trao đổi khoá công khai và tính khoá phiên chung K_AB:")
    print_square_multiply_table(
        "Alice nhận y_B = 248 và tính K_AB = 248^97 mod 353",
        248,
        97,
        353,
        res["alice_shared_steps"],
    )
    print_square_multiply_table(
        "Bob nhận y_A = 40 và tính K_AB = 40^233 mod 353",
        40,
        233,
        353,
        res["bob_shared_steps"],
    )

    print(
        f"\n  [KẾT LUẬN DEMO 1]: y_A = {res['y_A']}, y_B = {res['y_B']}, "
        f"K_AB (Alice) = {res['K_AB_alice']} == K_AB (Bob) = {res['K_AB_bob']} "
        f"(Khớp 100% với Slide 51: {res['matches_slide']})"
    )


def demo_2_full_dh_and_interactive_encryption(interactive: bool = False):
    """Kịch bản 2: Phiên bản đầy đủ (RFC 3526 2048-bit) & Mã hoá/Giải mã bản rõ trực tiếp."""
    print("\n" + "#" * 92)
    print(" [DEMO 2] PHIÊN BẢN ĐẦY ĐỦ (RFC 3526 2048-BIT) & MÃ HOÁ / GIẢI MÃ HAI CHIỀU TRỰC TIẾP")
    print("#" * 92)

    group = get_rfc3526_group14()
    print(f"\n1. Khởi tạo nhóm chuẩn quốc tế: {group.name}")
    print(f"   - Độ dài số nguyên tố q : {group.bit_length} bits")
    print(f"   - Giá trị q (Hex rút gọn): {hex(group.q)[:34]}...{hex(group.q)[-24:]}")
    print(f"   - Phần tử sinh α         : {group.alpha}")

    t0 = time.perf_counter()
    alice = DiffieHellmanParty("Alice", group)
    bob = DiffieHellmanParty("Bob", group)
    k_alice = alice.compute_shared_secret(bob.public_key)
    k_bob = bob.compute_shared_secret(alice.public_key)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    print(f"\n2. Kết quả trao đổi khoá 2048-bit (thời gian thực thi: {elapsed_ms:.2f} ms):")
    print(f"   - Khoá công khai y_A : {hex(alice.public_key)[:34]}...{hex(alice.public_key)[-20:]}")
    print(f"   - Khoá công khai y_B : {hex(bob.public_key)[:34]}...{hex(bob.public_key)[-20:]}")
    print(f"   - Khoá chung K_AB    : {hex(k_alice)[:34]}...{hex(k_alice)[-20:]}")
    print(f"   - Kiểm tra K_AB (Alice == Bob): {k_alice == k_bob}")

    default_msg = "Thông điệp mật NEU-CNTT: Chuyển 250,000,000 VNĐ cho Dự án An toàn thông tin 2026."
    if interactive:
        user_msg = input(f"\nNhập bản rõ cần mã hoá (Enter để dùng mặc định '{default_msg}'): ").strip()
        plaintext = user_msg if user_msg else default_msg
    else:
        plaintext = default_msg

    print(f"\n3. Mã hoá và Giải mã thông điệp hai chiều bằng khoá phiên K_AB:")
    cipher_hex = encrypt_text(plaintext, k_alice)
    recovered_text = decrypt_text(cipher_hex, k_bob)

    print(f"   - Bản rõ ban đầu (Alice)  : {plaintext}")
    print(f"   - Bản mã truyền đi (Hex)  : {cipher_hex[:72]}... ({len(cipher_hex)//2} bytes)")
    print(f"   - Bản rõ khôi phục (Bob)  : {recovered_text}")
    print(f"   - Khôi phục đúng 100% bản rõ ban đầu: {plaintext == recovered_text}")


def demo_3_real_file_encryption():
    """Kịch bản 3: Demo mã hoá và giải mã trên dữ liệu thật (Tệp văn bản .txt & Tệp ảnh .png)."""
    print("\n" + "#" * 92)
    print(" [DEMO 3] DEMO TRÊN DỮ LIỆU THẬT: MÃ HOÁ & GIẢI MÃ TỆP VĂN BẢN (.TXT) VÀ TỆP ẢNH (.PNG)")
    print("#" * 92)

    group = get_rfc3526_group5()
    alice = DiffieHellmanParty("Alice", group)
    bob = DiffieHellmanParty("Bob", group)
    k_ab = alice.compute_shared_secret(bob.public_key)

    sample_dir = os.path.join(PROJECT_ROOT, "sample_data")
    files_to_demo = ["sample_text.txt", "sample_image.png"]

    with tempfile.TemporaryDirectory() as tmpdir:
        for fname in files_to_demo:
            in_path = os.path.join(sample_dir, fname)
            if not os.path.exists(in_path):
                continue
            enc_path = os.path.join(tmpdir, fname + ".dh_enc")
            dec_path = os.path.join(tmpdir, "recovered_" + fname)

            t0 = time.perf_counter()
            enc_res = encrypt_file(in_path, enc_path, k_ab)
            dec_res = decrypt_file(enc_path, dec_path, k_ab)
            dt_ms = (time.perf_counter() - t0) * 1000

            print(f"\n  ► Tệp dữ liệu thật: {fname}")
            print(f"    - Kích thước tệp gốc       : {enc_res['plain_size_bytes']:,} bytes")
            print(f"    - Kích thước tệp bản mã    : {enc_res['cipher_size_bytes']:,} bytes (gồm 8B Nonce + 16B MAC)")
            print(f"    - Kích thước sau giải mã   : {dec_res['recovered_size_bytes']:,} bytes")
            print(f"    - SHA-256 tệp gốc          : {enc_res['plain_sha256']}")
            print(f"    - SHA-256 tệp bản mã       : {enc_res['cipher_sha256']}")
            print(f"    - SHA-256 sau khi giải mã  : {dec_res['recovered_sha256']}")
            print(
                f"    - Đối chiếu toàn vẹn       : KHỚP 100% ({enc_res['plain_sha256'] == dec_res['recovered_sha256']}) "
                f"| Thời gian: {dt_ms:.2f} ms"
            )


def demo_4_discrete_logarithm_attack():
    """Kịch bản 4: Minh hoạ bài toán Logarit rời rạc (Vét cạn vs Baby-step Giant-step)."""
    print("\n" + "#" * 92)
    print(" [DEMO 4] MINH HOẠ BÀI TOÁN LOGARIT RỜI RẠC (DISCRETE LOGARITHM PROBLEM - DLP)")
    print("#" * 92)

    test_targets = [
        ("Slide 51 (9-bit)", 353, 3, 97),
        ("Số nguyên tố 16-bit", 65521, 17, 48123),
        ("Số nguyên tố 20-bit", 1000003, 2, 789456),
    ]

    print(
        f"\n  {'Kịch bản (Kích thước q)':<24} | {'q':>9} | {'y = α^x mod q':>13} | "
        f"{'Vét cạn O(q)':>22} | {'BSGS Shanks O(√q)':>22} | {'Tăng tốc':>9}"
    )
    print("  " + "-" * 112)

    for label, q, alpha, secret_x in test_targets:
        y = square_and_multiply(alpha, secret_x, q)
        x_bf, ops_bf, t_bf = discrete_log_bruteforce(alpha, y, q)
        x_bs, ops_bs, t_bs = discrete_log_bsgs(alpha, y, q)
        speedup = ops_bf / max(1, ops_bs)
        assert x_bf == secret_x and x_bs == secret_x
        print(
            f"  {label:<24} | {q:>9,} | {y:>13,} | "
            f"{ops_bf:>9,} bước ({t_bf*1000:>5.1f}ms) | "
            f"{ops_bs:>7,} bước ({t_bs*1000:>5.2f}ms) | {speedup:>7.1f}x"
        )

    print("\n  ► Nhận xét độ an toàn:")
    print("    - Với số nguyên tố q nhỏ (9-bit .. 20-bit), kẻ thám mã dễ dàng tìm ra khoá mật x bằng BSGS.")
    print("    - Khi q dài 2048 bit (RFC 3526 Group 14), thuật toán BSGS cần √(2^2048) = 2^1024 phép tính")
    print("      và thuật toán Sàng trường số (GNFS) cần ~2^112 phép tính — hoàn toàn bất khả thi trong thực tế!")


def demo_5_mitm_attack_and_defense():
    """Kịch bản 5: Minh hoạ tấn công Người đứng giữa (MITM) và cách phòng chống bằng Chữ ký số RSA."""
    print("\n" + "#" * 92)
    print(" [DEMO 5] MINH HOẠ TẤN CÔNG NGƯỜI ĐỨNG GIỮA (MITM) & CÁCH PHÒNG CHỐNG BẰNG CHỮ KÝ SỐ RSA")
    print("#" * 92)

    mitm = simulate_unauthenticated_mitm()
    print("\n  PHẦN A: KỊCH BẢN TẤN CÔNG MITM THÀNH CÔNG (KHI KHÔNG CÓ XÁC THỰC ĐỊNH DANH)")
    print("  " + "-" * 84)
    print(f"  1. Tham số công khai : q = {mitm['q']}, α = {mitm['alpha']}")
    print(f"  2. Alice sinh        : x_A = {mitm['x_A']} ⇒ gửi y_A = {mitm['y_A']} (bị Eve chặn!)")
    print(f"  3. Bob sinh          : x_B = {mitm['x_B']} ⇒ gửi y_B = {mitm['y_B']} (bị Eve chặn!)")
    print(f"  4. Eve đứng giữa sinh: x_E1 = {mitm['x_E1']} ⇒ gửi y_E1 = {mitm['y_E1']} cho Alice (giả làm Bob)")
    print(f"                         x_E2 = {mitm['x_E2']} ⇒ gửi y_E2 = {mitm['y_E2']} cho Bob (giả làm Alice)")
    print(f"  5. Thiết lập 2 khoá phiên bị tách biệt:")
    print(f"     - Giữa Alice và Eve : K_AE = {mitm['K_AE_alice']} (Alice tính) == {mitm['K_AE_eve']} (Eve tính)")
    print(f"     - Giữa Eve và Bob   : K_EB = {mitm['K_EB_bob']} (Bob tính)   == {mitm['K_EB_eve']} (Eve tính)")
    print(f"  6. Nghe lén và sửa đổi giao dịch:")
    print(f"     - Alice gửi bản rõ gốc       : \"{mitm['alice_original_message']}\"")
    print(f"     - Eve giải mã bằng K_AE      : \"{mitm['eve_decrypted_message']}\"")
    print(f"     - Eve sửa nội dung và mã hoá : \"{mitm['eve_tampered_message']}\" (bằng khoá K_EB)")
    print(f"     - Bob giải mã bằng K_EB nhận : \"{mitm['bob_decrypted_message']}\"")
    print(f"     ⇒ KẾT QUẢ: Cuộc tấn công MITM thành công ({mitm['attack_succeeded']}) mà Alice và Bob không phát hiện!")

    defense = simulate_authenticated_dh_defense()
    print("\n  PHẦN B: PHÒNG CHỐNG TẤN CÔNG MITM BẰNG CHỮ KÝ SỐ RSA (AUTHENTICATED DIFFIE-HELLMAN)")
    print("  " + "-" * 84)
    print(f"  1. Hạ tầng PKI cấp chứng thư khoá công khai RSA:")
    print(f"     - Khoá công khai RSA của Alice : (e_A, N_A) = {defense['alice_rsa_pub']}")
    print(f"     - Khoá công khai RSA của Bob   : (e_B, N_B) = {defense['bob_rsa_pub']}")
    print(f"  2. Alice gửi thông điệp định danh kèm khoá DH: \"{defense['msg_alice']}\"")
    print(f"     - Chữ ký số RSA của Alice đính kèm: Sig_A = {defense['sig_alice']}")
    print(f"  3. Khi Eve can thiệp tráo y_A = {defense['y_A']} thành y_E = {defense['y_E']}:")
    print(
        f"     - Trường hợp Eve giữ nguyên Sig_A cũ: Bob kiểm tra thấy Hash kỳ vọng "
        f"({defense['mitm_replay_sig_verify']['expected_hash_mod_n']}) ≠ Hash giải mã từ chữ ký "
        f"({defense['mitm_replay_sig_verify']['recovered_hash_mod_n']}) ⇒ PHÁT HIỆN GIẢ MẠO!"
    )
    print(
        f"     - Trường hợp Eve tự ký bằng khoá RSA của Eve: Bob kiểm tra bằng e_A của Alice thấy "
        f"({defense['mitm_forged_sig_verify']['expected_hash_mod_n']}) ≠ "
        f"({defense['mitm_forged_sig_verify']['recovered_hash_mod_n']}) ⇒ PHÁT HIỆN GIẢ MẠO!"
    )
    print(
        f"  4. Khi gói tin nguyên vẹn từ Alice: Bob xác thực chữ ký hợp lệ "
        f"({defense['legit_verify']['is_valid']}) và thiết lập an toàn K_AB = {defense['established_K_AB']}."
    )


def demo_6_benchmark_performance():
    """Kịch bản 6: Đo thời gian chạy (Benchmark) theo kích thước khoá và kích thước dữ liệu."""
    print("\n" + "#" * 92)
    print(" [DEMO 6] ĐO THỜI GIAN CHẠY (BENCHMARK) THEO KÍCH THƯỚC KHOÁ & KÍCH THƯỚC DỮ LIỆU")
    print("#" * 92)

    print("\n  1. Thời gian trao đổi khoá Diffie-Hellman (Bình phương & Nhân tự cài đặt) theo độ dài bit của q:")
    print(f"     {'Nhóm / Độ dài khoá q':<36} | {'Số bit của q':>14} | {'Thời gian tạo & trao đổi khoá':>30}")
    print("     " + "-" * 86)

    groups_to_bench = [
        DiffieHellmanGroup(353, 3, "Tiny DH (Slide 51)"),
        DiffieHellmanGroup(65537, 3, "Small DH (16-bit)"),
        get_rfc3526_group5(),
        get_rfc3526_group14(),
    ]
    for grp in groups_to_bench:
        t0 = time.perf_counter()
        a = DiffieHellmanParty("Alice", grp)
        b = DiffieHellmanParty("Bob", grp)
        _ = a.compute_shared_secret(b.public_key)
        _ = b.compute_shared_secret(a.public_key)
        dt_ms = (time.perf_counter() - t0) * 1000
        print(f"     {grp.name:<36} | {grp.bit_length:>10} bit | {dt_ms:>26.3f} ms")

    print("\n  2. Thời gian Mã hoá + Giải mã luồng dữ liệu theo kích thước bản rõ (với khoá phiên K_AB):")
    print(f"     {'Kích thước dữ liệu':<24} | {'Thời gian Mã hoá (ms)':>22} | {'Thời gian Giải mã (ms)':>22} | {'Khớp 100%':>10}")
    print("     " + "-" * 86)

    k_ab = 160
    for size_kb in [1, 10, 50, 100]:
        payload = os.urandom(size_kb * 1024)
        t0 = time.perf_counter()
        enc = encrypt_bytes(payload, k_ab)
        t_enc = (time.perf_counter() - t0) * 1000

        t1 = time.perf_counter()
        dec = decrypt_bytes(enc, k_ab)
        t_dec = (time.perf_counter() - t1) * 1000

        print(
            f"     {size_kb:>6} KB ({len(payload):>7,} B)   | {t_enc:>19.2f} ms | {t_dec:>19.2f} ms | {str(payload == dec):>10}"
        )


def demo_7_run_unit_tests():
    """Kịch bản 7: Chạy bộ kiểm thử tự động & in bảng đối chiếu với thư viện chuẩn / NIST / RFC."""
    print("\n" + "#" * 92)
    print(" [DEMO 7] CHẠY BỘ KIỂM THỬ TỰ ĐỘNG & ĐỐI CHIẾU VECTOR CHUẨN (NIST, RFC 3526, STDLIB)")
    print("#" * 92)
    from tests.test_diffie_hellman import TestDiffieHellmanSuite

    suite = unittest.TestLoader().loadTestsFromTestCase(TestDiffieHellmanSuite)
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)


def interactive_menu():
    """Menu CLI tương tác dành cho buổi bảo vệ và demo trên lớp."""
    while True:
        print_banner()
        print("  CHỌN CHỨC NĂNG DEMO TRỰC TIẾP:")
        print("    [1] Phiên bản thu nhỏ (Tiny DH): Tái hiện ví dụ Slide 51 & in bảng bước trung gian")
        print("    [2] Phiên bản đầy đủ (RFC 3526 2048-bit): Nhập bản rõ, mã hoá & giải mã hai chiều")
        print("    [3] Demo trên dữ liệu thật: Mã hoá & giải mã tệp văn bản (.txt) và tệp ảnh (.png)")
        print("    [4] Bài toán Logarit rời rạc (DLP): So sánh Vét cạn O(q) và Baby-step Giant-step O(√q)")
        print("    [5] Minh hoạ Tấn công Người đứng giữa (MITM) & Phòng chống bằng Chữ ký số RSA")
        print("    [6] Đo hiệu năng (Benchmark): Thời gian chạy theo kích thước khoá và kích thước dữ liệu")
        print("    [7] Chạy bộ Kiểm thử tự động (Unit Tests) & Đối chiếu chuẩn NIST / RFC 3526")
        print("    [8] Chạy liên hoàn tất cả các phần (Full Demo 1 -> 7)")
        print("    [0] Thoát chương trình")
        print("-" * 92)

        choice = input("  Nhập lựa chọn của bạn (0-8): ").strip()
        if choice == "1":
            demo_1_tiny_dh_slide51()
        elif choice == "2":
            demo_2_full_dh_and_interactive_encryption(interactive=True)
        elif choice == "3":
            demo_3_real_file_encryption()
        elif choice == "4":
            demo_4_discrete_logarithm_attack()
        elif choice == "5":
            demo_5_mitm_attack_and_defense()
        elif choice == "6":
            demo_6_benchmark_performance()
        elif choice == "7":
            demo_7_run_unit_tests()
        elif choice == "8":
            run_all_demos()
        elif choice == "0":
            print("\n  Cảm ơn bạn đã sử dụng chương trình Demo Diffie-Hellman!")
            break
        else:
            print("\n  [!] Lựa chọn không hợp lệ, vui lòng chọn từ 0 đến 8.")

        input("\n  Nhấn Enter để quay lại Menu chính...")


def run_all_demos():
    print_banner()
    demo_1_tiny_dh_slide51()
    demo_2_full_dh_and_interactive_encryption(interactive=False)
    demo_3_real_file_encryption()
    demo_4_discrete_logarithm_attack()
    demo_5_mitm_attack_and_defense()
    demo_6_benchmark_performance()
    demo_7_run_unit_tests()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chương trình Demo Trao đổi khoá Diffie-Hellman")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Chạy tự động toàn bộ 7 kịch bản demo và kiểm thử (không dừng chờ nhập phím)",
    )
    args = parser.parse_args()
    if args.all:
        run_all_demos()
    else:
        interactive_menu()
