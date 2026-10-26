"""
Bộ kiểm thử tự động (Unit Tests) & Đối chiếu chuẩn (Standard Reference Verification)
cho đề tài Trao đổi khoá Diffie-Hellman (Chương 3 - Mã hoá khoá công khai).

Đáp ứng đúng yêu cầu trong file Hướng dẫn làm bài tập nhóm:
- "Có bộ kiểm thử: ít nhất ba ca kiểm thử do nhóm tự viết, cộng với đối chiếu bằng bộ
  test vector chuẩn (NIST, RFC) hoặc với thư viện chuẩn, và in ra được kết quả đối chiếu."
- "Phiên bản thu nhỏ phải tái hiện đúng ví dụ đã học trên lớp — đây là căn cứ đầu tiên
  để chấm tính đúng đắn của chương trình."
"""

import hashlib
import importlib.abc
import importlib.util
import math
import os
import sys
import tempfile
import unittest

# Thiết lập đường dẫn gốc của dự án (hỗ trợ cả hệ thống tệp chuẩn và môi trường ảo hoá)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
    euler_totient,
    extended_euclid,
    gcd_euclid,
    is_primitive_root,
    miller_rabin_test,
    mod_inverse_table,
    square_and_multiply,
)
from core.mitm_attack import (
    simulate_authenticated_dh_defense,
    simulate_unauthenticated_mitm,
)


class TestDiffieHellmanSuite(unittest.TestCase):
    """Bộ kiểm thử toàn diện có in bảng đối chiếu chi tiết ra màn hình."""

    def test_01_slide_math_primitives_and_python_stdlib_comparison(self):
        """
        Ca kiểm thử 1: Kiểm tra các thuật toán cơ sở toán học trong Slide Chương 3
        và đối chiếu trực tiếp với thư viện chuẩn của Python (`math.gcd`, `pow`).
        """
        print("\n" + "=" * 88)
        print("[TEST CASE 1] KIỂM THỬ TOÁN HỌC NỀN TẢNG (SLIDE CHƯƠNG 3) & ĐỐI CHIẾU THƯ VIỆN CHUẨN")
        print("=" * 88)

        # 1. Euclid & Euclid mở rộng (Slide 14 & 16): GCD(4864, 3458) = 38, x = 32, y = -45
        (d, x, y), table = extended_euclid(4864, 3458, return_steps=True)
        std_gcd = math.gcd(4864, 3458)
        print(
            f"1. Euclid mở rộng (Slide 16): GCD(4864, 3458) -> Tự cài đặt: d={d}, x={x}, y={y} | "
            f"math.gcd chuẩn: {std_gcd} | Khớp: {d == std_gcd == 38 and x == 32 and y == -45}"
        )
        self.assertEqual(d, 38)
        self.assertEqual(x, 32)
        self.assertEqual(y, -45)
        self.assertEqual(4864 * x + 3458 * y, d)

        # 2. Nghịch đảo modulo bảng 6 cột (Slide 21 & 22): 25^-1 mod 101 = 97; 173^-1 mod 1024 = 805
        inv1, _ = mod_inverse_table(25, 101, return_steps=True)
        std_inv1 = pow(25, -1, 101)
        inv2, _ = mod_inverse_table(173, 1024, return_steps=True)
        std_inv2 = pow(173, -1, 1024)
        print(
            f"2. Nghịch đảo modulo (Slide 21): 25^-1 mod 101   -> Tự cài đặt: {inv1} | "
            f"pow(25, -1, 101) chuẩn: {std_inv1} | Khớp: {inv1 == std_inv1 == 97}"
        )
        print(
            f"3. Nghịch đảo modulo (Slide 22): 173^-1 mod 1024 -> Tự cài đặt: {inv2} | "
            f"pow(173, -1, 1024) chuẩn: {std_inv2} | Khớp: {inv2 == std_inv2 == 805}"
        )
        self.assertEqual(inv1, 97)
        self.assertEqual(inv2, 805)

        # 3. Bình phương và nhân (Slide 24): 7^560 mod 561 = 1
        f_val, steps = square_and_multiply(7, 560, 561, return_steps=True)
        std_pow = pow(7, 560, 561)
        print(
            f"4. Bình phương & nhân (Slide 24): 7^560 mod 561  -> Tự cài đặt: {f_val} (qua {len(steps)} bước) | "
            f"pow(7, 560, 561) chuẩn: {std_pow} | Khớp: {f_val == std_pow == 1}"
        )
        self.assertEqual(f_val, 1)
        self.assertEqual(len(steps), 10)

        # 4. Hàm Euler Phi(n) (Slide 27-28): Phi(10)=4, Phi(37)=36, Phi(21)=12, Phi(72)=24
        self.assertEqual(euler_totient(10), 4)
        self.assertEqual(euler_totient(37), 36)
        self.assertEqual(euler_totient(21), 12)
        self.assertEqual(euler_totient(72), 24)

        # 5. Kiểm tra nguyên tố Miller-Rabin (Slide 29): 353 là nguyên tố, 561 (số Carmichael) là hợp số
        self.assertTrue(miller_rabin_test(353))
        self.assertFalse(miller_rabin_test(561))

    def test_02_tiny_diffie_hellman_slide51_exact_reproduction(self):
        """
        Ca kiểm thử 2: Tái hiện chính xác BTVD Trao đổi khoá Diffie-Hellman tại Slide 51
        (q = 353, alpha = 3, x_A = 97, x_B = 233 -> y_A = 40, y_B = 248, K_AB = 160).
        """
        print("\n" + "=" * 88)
        print("[TEST CASE 2] TÁI HIỆN VÍ DỤ DIFFIE-HELLMAN THU NHỎ TRÊN LỚP (SLIDE 51)")
        print("=" * 88)

        res = run_slide51_example()
        std_ya = pow(3, 97, 353)
        std_yb = pow(3, 233, 353)
        std_kab_a = pow(std_yb, 97, 353)

        print(f"Tham số miền công khai : q = {res['q']}, alpha = {res['alpha']}")
        print(f"Khoá mật đã chọn       : x_A = {res['x_A']}, x_B = {res['x_B']}")
        print(
            f"Khoá công khai y_A     : Tự cài đặt = {res['y_A']} | Slide 51 = 40  | "
            f"Python pow(3, 97, 353) = {std_ya}"
        )
        print(
            f"Khoá công khai y_B     : Tự cài đặt = {res['y_B']} | Slide 51 = 248 | "
            f"Python pow(3, 233, 353) = {std_yb}"
        )
        print(
            f"Khoá phiên chung K_AB  : Alice tính = {res['K_AB_alice']} | Bob tính = {res['K_AB_bob']} | "
            f"Slide 51 = 160 | Python pow = {std_kab_a}"
        )

        self.assertEqual(res["y_A"], 40)
        self.assertEqual(res["y_B"], 248)
        self.assertEqual(res["K_AB_alice"], 160)
        self.assertEqual(res["K_AB_bob"], 160)
        self.assertTrue(res["matches_slide"])

    def test_03_rfc3526_standard_vectors_1536_and_2048_bit(self):
        """
        Ca kiểm thử 3: Kiểm thử phiên bản đầy đủ trên nhóm MODP chuẩn quốc tế RFC 3526
        (Group 5 - 1536 bit và Group 14 - 2048 bit) và đối chiếu với `pow()` chuẩn của Python.
        """
        print("\n" + "=" * 88)
        print("[TEST CASE 3] ĐỐI CHIẾU CHUẨN QUỐC TẾ RFC 3526 (1536-BIT & 2048-BIT MODP GROUPS)")
        print("=" * 88)

        for group in [get_rfc3526_group5(), get_rfc3526_group14()]:
            priv_a = int(hashlib.sha256(b"RFC3526_ALICE_PRIV_SEED").hexdigest(), 16)
            priv_b = int(hashlib.sha256(b"RFC3526_BOB_PRIV_SEED").hexdigest(), 16)

            alice = DiffieHellmanParty("Alice", group, private_key=priv_a)
            bob = DiffieHellmanParty("Bob", group, private_key=priv_b)

            k_alice = alice.compute_shared_secret(bob.public_key)
            k_bob = bob.compute_shared_secret(alice.public_key)

            std_pub_a = pow(group.alpha, priv_a, group.q)
            std_pub_b = pow(group.alpha, priv_b, group.q)
            std_shared = pow(std_pub_b, priv_a, group.q)

            match_all = (
                alice.public_key == std_pub_a
                and bob.public_key == std_pub_b
                and k_alice == k_bob == std_shared
            )
            print(
                f"- Nhóm {group.name} ({group.bit_length} bits):\n"
                f"  + y_A (hex đầu/cuối) : {hex(alice.public_key)[:18]}...{hex(alice.public_key)[-12:]}\n"
                f"  + K_AB (hex đầu/cuối): {hex(k_alice)[:18]}...{hex(k_alice)[-12:]}\n"
                f"  + Khớp giữa Alice & Bob và khớp 100% với Python pow(): {match_all}"
            )
            self.assertEqual(alice.public_key, std_pub_a)
            self.assertEqual(bob.public_key, std_pub_b)
            self.assertEqual(k_alice, k_bob)
            self.assertEqual(k_alice, std_shared)

    def test_04_sha256_nist_vectors_and_two_way_encryption_files(self):
        """
        Ca kiểm thử 4: Đối chiếu hàm băm SHA-256 tự viết với bộ Test Vector chuẩn NIST FIPS 180-4
        và thư viện chuẩn `hashlib.sha256`, đồng thời kiểm thử mã hoá & giải mã hai chiều
        trên văn bản tiếng Việt, tệp văn bản (.txt) và tệp ảnh (.png).
        """
        print("\n" + "=" * 88)
        print("[TEST CASE 4] ĐỐI CHIẾU NIST SHA-256 VECTORS & MÃ HOÁ/GIẢI MÃ 2 CHIỀU (TEXT + FILE)")
        print("=" * 88)

        nist_vectors = [
            (
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ]
        for msg, expected_hex in nist_vectors:
            our_hex = sha256_from_scratch(msg).hex()
            stdlib_hex = hashlib.sha256(msg).hexdigest()
            print(
                f"- NIST Vector ({len(msg)} bytes): Tự cài đặt = {our_hex[:20]}... | "
                f"NIST & hashlib = {stdlib_hex[:20]}... | Khớp: {our_hex == expected_hex == stdlib_hex}"
            )
            self.assertEqual(our_hex, expected_hex)
            self.assertEqual(our_hex, stdlib_hex)

        shared_secret = 160
        original_text = "Đại học Kinh tế Quốc dân - Khoa CNTT: Mật khẩu khoá phiên Diffie-Hellman K_AB = 160!"
        cipher_hex = encrypt_text(original_text, shared_secret)
        recovered_text = decrypt_text(cipher_hex, shared_secret)
        print(
            f"- Mã hoá/Giải mã chuỗi UTF-8: Bản rõ gốc ({len(original_text)} ký tự) -> "
            f"Bản mã Hex ({len(cipher_hex)} ký tự) -> Khôi phục chính xác 100%: {original_text == recovered_text}"
        )
        self.assertEqual(original_text, recovered_text)

        with self.assertRaises(ValueError):
            decrypt_text(cipher_hex, shared_secret=161)

        sample_dir = os.path.join(PROJECT_ROOT, "sample_data")
        for filename in ["sample_text.txt", "sample_image.png"]:
            src_path = os.path.join(sample_dir, filename)
            if os.path.exists(src_path):
                with tempfile.TemporaryDirectory() as tmpdir:
                    enc_path = os.path.join(tmpdir, filename + ".enc")
                    dec_path = os.path.join(tmpdir, "recovered_" + filename)
                    enc_info = encrypt_file(src_path, enc_path, shared_secret)
                    dec_info = decrypt_file(enc_path, dec_path, shared_secret)

                    with open(src_path, "rb") as f1, open(dec_path, "rb") as f2:
                        b_orig = f1.read()
                        b_rec = f2.read()

                    print(
                        f"- Mã hoá/Giải mã tệp '{filename}' ({enc_info['plain_size_bytes']} bytes): "
                        f"SHA-256 gốc = {enc_info['plain_sha256'][:16]}... | "
                        f"SHA-256 sau giải mã = {dec_info['recovered_sha256'][:16]}... | "
                        f"Khớp 100% từng byte: {b_orig == b_rec}"
                    )
                    self.assertEqual(b_orig, b_rec)
                    self.assertEqual(enc_info["plain_sha256"], dec_info["recovered_sha256"])

    def test_05_discrete_logarithm_and_mitm_attack_and_defense(self):
        """
        Ca kiểm thử 5: Kiểm thử giải bài toán Logarit rời rạc (Vét cạn vs Baby-step Giant-step)
        và kiểm thử mô phỏng Tấn công Người đứng giữa (MITM) kèm cơ chế phòng chống bằng Chữ ký số RSA.
        """
        print("\n" + "=" * 88)
        print("[TEST CASE 5] BÀI TOÁN LOGARIT RỜI RẠC (DLP) & TẤN CÔNG NGƯỜI ĐỨNG GIỮA (MITM)")
        print("=" * 88)

        x_bf, steps_bf, _ = discrete_log_bruteforce(3, 40, 353)
        x_bsgs, steps_bsgs, _ = discrete_log_bsgs(3, 40, 353)
        print(
            f"1. Giải DLP trên Slide 51 (3^x ≡ 40 mod 353):\n"
            f"   - Vét cạn (Brute-force)          : tìm được x = {x_bf} sau {steps_bf} bước\n"
            f"   - Bước nhỏ - Bước lớn (BSGS)     : tìm được x = {x_bsgs} sau {steps_bsgs} bước"
        )
        self.assertEqual(x_bf, 97)
        self.assertEqual(x_bsgs, 97)

        q_med, alpha_med, x_secret = 1000003, 2, 789456
        y_med = square_and_multiply(alpha_med, x_secret, q_med)
        x_bf_m, ops_bf_m, t_bf = discrete_log_bruteforce(alpha_med, y_med, q_med)
        x_bs_m, ops_bs_m, t_bs = discrete_log_bsgs(alpha_med, y_med, q_med)
        print(
            f"2. Giải DLP trên q = {q_med} (y = {y_med}):\n"
            f"   - Vét cạn O(q)       : x = {x_bf_m} ({ops_bf_m:,} phép tính, {t_bf*1000:.2f} ms)\n"
            f"   - BSGS O(sqrt(q))    : x = {x_bs_m} ({ops_bs_m:,} phép tính, {t_bs*1000:.2f} ms -> nhanh gấp ~{ops_bf_m // max(1, ops_bs_m)} lần)"
        )
        self.assertEqual(x_bf_m, x_secret)
        self.assertEqual(x_bs_m, x_secret)

        mitm_res = simulate_unauthenticated_mitm()
        defense_res = simulate_authenticated_dh_defense()
        print(
            f"3. Mô phỏng Tấn công Người đứng giữa (MITM) khi KHÔNG xác thực:\n"
            f"   - Khoá chung Alice-Eve K_AE = {mitm_res['K_AE_alice']} | Khoá chung Eve-Bob K_EB = {mitm_res['K_EB_bob']}\n"
            f"   - Eve giải mã trộm và sửa đổi bản tin thành công: {mitm_res['attack_succeeded']}"
        )
        print(
            f"4. Phòng chống MITM bằng Chữ ký số RSA (Authenticated DH):\n"
            f"   - Chữ ký thật của Alice hợp lệ: {defense_res['legit_verify']['is_valid']}\n"
            f"   - Phát hiện khi Eve tráo khoá y_E (giữ chữ ký cũ): {not defense_res['mitm_replay_sig_verify']['is_valid']}\n"
            f"   - Phát hiện khi Eve tự ký khoá y_E bằng RSA của Eve: {not defense_res['mitm_forged_sig_verify']['is_valid']}\n"
            f"   - Chặn đứng thành công cuộc tấn công MITM: {defense_res['mitm_blocked']}"
        )
        self.assertTrue(mitm_res["attack_succeeded"])
        self.assertTrue(defense_res["mitm_blocked"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
