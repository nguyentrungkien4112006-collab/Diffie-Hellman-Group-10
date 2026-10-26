"""
Module cài đặt lõi thuật toán Trao đổi khoá Diffie-Hellman (Slide 49-51)
và giải bài toán Logarit rời rạc (Discrete Logarithm Problem - DLP).

Bao gồm:
1. Phiên bản thu nhỏ (Tiny Diffie-Hellman): tái hiện chính xác BTVD Slide 51
   (q = 353, alpha = 3, x_A = 97, x_B = 233 -> y_A = 40, y_B = 248, K_AB = 160)
   và in bảng trung gian của thuật toán "Bình phương và nhân" (Slide 23-24).
2. Phiên bản đầy đủ (Standard / Full Diffie-Hellman): hỗ trợ các nhóm MODP chuẩn
   RFC 3526 (Group 5 - 1536 bit, Group 14 - 2048 bit) và sinh số nguyên tố an toàn động.
3. Giải bài toán Logarit rời rạc (tìm x biết y = alpha^x mod q):
   - Thuật toán vét cạn (Brute-force search) O(q)
   - Thuật toán Bước nhỏ - Bước lớn (Baby-step Giant-step của Shanks) O(sqrt(q))
"""

import math
import random
import time
from typing import Dict, List, Optional, Tuple

from .math_utils import (
    is_primitive_root,
    miller_rabin_test,
    mod_inverse_table,
    square_and_multiply,
)

# Tham số chuẩn RFC 3526 - Group 5 (1536-bit MODP Group)
RFC3526_GROUP5_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
)

# Tham số chuẩn RFC 3526 - Group 14 (2048-bit MODP Group)
RFC3526_GROUP14_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)


class DiffieHellmanGroup:
    """
    Đại diện cho bộ tham số miền công khai (q, alpha) trong trao đổi khoá Diffie-Hellman (Slide 50):
    - q: Số nguyên tố (hoặc số nguyên tố rất lớn)
    - alpha: Căn nguyên tố (primitive root / generator) của mod q (alpha < q)
    """

    def __init__(self, q: int, alpha: int, name: str = "Custom DH Group", verify_primitive: bool = False):
        if q < 3:
            raise ValueError("Tham số q phải là số nguyên tố >= 3.")
        if not (1 < alpha < q):
            raise ValueError("Tham số alpha phải thoả mãn 1 < alpha < q.")
        self.q = q
        self.alpha = alpha
        self.name = name
        self.bit_length = q.bit_length()
        self.primitive_checks: List[Dict[str, int]] = []

        if verify_primitive:
            if not miller_rabin_test(q):
                raise ValueError(f"q = {q} không phải là số nguyên tố!")
            ok, checks = is_primitive_root(alpha, q)
            self.primitive_checks = checks
            if not ok:
                raise ValueError(f"alpha = {alpha} không phải là căn nguyên tố của q = {q}!")


class DiffieHellmanParty:
    """
    Đại diện cho một bên tham gia trao đổi khoá Diffie-Hellman (ví dụ: Alice hoặc Bob).
    Thực hiện đúng quy trình tại Slide 50:
    1. Chọn khoá mật (riêng) x < q
    2. Tính khoá công khai y = alpha^x mod q
    3. Nhận khoá công khai của đối tác y_partner và tính khoá phiên chung:
       K_AB = (y_partner)^x mod q
    """

    def __init__(
        self,
        name: str,
        group: DiffieHellmanGroup,
        private_key: Optional[int] = None,
        record_steps: bool = False,
    ):
        self.name = name
        self.group = group
        self.record_steps = record_steps

        if private_key is None:
            # Chọn ngẫu nhiên khoá mật x trong khoảng [2, q - 2]
            self.private_key = random.randint(2, group.q - 2)
        else:
            if not (1 <= private_key < group.q):
                raise ValueError(f"Khoá mật x của {name} phải thoả mãn 1 <= x < q ({group.q}).")
            self.private_key = private_key

        # Tính khoá công khai y = alpha^x mod q bằng thuật toán Bình phương và nhân tự viết
        if self.record_steps:
            self.public_key, self.keygen_steps = square_and_multiply(
                group.alpha, self.private_key, group.q, return_steps=True
            )
        else:
            self.public_key = square_and_multiply(
                group.alpha, self.private_key, group.q, return_steps=False
            )
            self.keygen_steps = []

        self.shared_secret: Optional[int] = None
        self.shared_steps: List[Dict[str, int]] = []

    def compute_shared_secret(self, partner_public_key: int) -> int:
        """
        Tính khoá phiên dùng chung K_AB = (y_partner)^(self.private_key) mod q.
        """
        if not (1 <= partner_public_key < self.group.q):
            raise ValueError("Khoá công khai của đối tác không hợp lệ.")

        if self.record_steps:
            secret, steps = square_and_multiply(
                partner_public_key, self.private_key, self.group.q, return_steps=True
            )
            self.shared_secret = secret
            self.shared_steps = steps
        else:
            self.shared_secret = square_and_multiply(
                partner_public_key, self.private_key, self.group.q, return_steps=False
            )
            self.shared_steps = []
        return self.shared_secret


def run_slide51_example() -> Dict[str, object]:
    """
    Tái hiện chính xác Bài tập ví dụ tại Slide 51 (Chương 3 - Mã hoá khoá công khai):
    - Tham số chung: q = 353, alpha = 3
    - Khoá mật: A chọn x_A = 97, B chọn x_B = 233
    - Khoá công khai:
        y_A = 3^97 mod 353 = 40
        y_B = 3^233 mod 353 = 248
    - Khoá phiên chung:
        K_AB (của A) = 248^97 mod 353 = 160
        K_AB (của B) = 40^233 mod 353 = 160
    Trả về đầy đủ kết quả và các bảng bước trung gian để in ra khi thuyết trình.
    """
    group = DiffieHellmanGroup(q=353, alpha=3, name="Slide 51 Tiny DH (q=353, alpha=3)", verify_primitive=True)
    alice = DiffieHellmanParty("Alice (A)", group, private_key=97, record_steps=True)
    bob = DiffieHellmanParty("Bob (B)", group, private_key=233, record_steps=True)

    k_ab_alice = alice.compute_shared_secret(bob.public_key)
    k_ab_bob = bob.compute_shared_secret(alice.public_key)

    return {
        "q": group.q,
        "alpha": group.alpha,
        "primitive_checks": group.primitive_checks,
        "x_A": alice.private_key,
        "x_B": bob.private_key,
        "y_A": alice.public_key,
        "y_B": bob.public_key,
        "K_AB_alice": k_ab_alice,
        "K_AB_bob": k_ab_bob,
        "alice_keygen_steps": alice.keygen_steps,
        "bob_keygen_steps": bob.keygen_steps,
        "alice_shared_steps": alice.shared_steps,
        "bob_shared_steps": bob.shared_steps,
        "matches_slide": (
            alice.public_key == 40
            and bob.public_key == 248
            and k_ab_alice == 160
            and k_ab_bob == 160
        ),
    }


def get_rfc3526_group5() -> DiffieHellmanGroup:
    """Trả về nhóm MODP 1536-bit chuẩn RFC 3526 Group 5 (q 1536 bit, alpha = 2)."""
    q = int(RFC3526_GROUP5_PRIME_HEX, 16)
    return DiffieHellmanGroup(q=q, alpha=2, name="RFC 3526 Group 5 (1536-bit MODP)", verify_primitive=False)


def get_rfc3526_group14() -> DiffieHellmanGroup:
    """Trả về nhóm MODP 2048-bit chuẩn RFC 3526 Group 14 (q 2048 bit, alpha = 2)."""
    q = int(RFC3526_GROUP14_PRIME_HEX, 16)
    return DiffieHellmanGroup(q=q, alpha=2, name="RFC 3526 Group 14 (2048-bit MODP)", verify_primitive=False)


def discrete_log_bruteforce(
    alpha: int, y: int, q: int, max_steps: int = 2_000_000
) -> Tuple[Optional[int], int, float]:
    """
    Giải bài toán Logarit rời rạc (Discrete Logarithm Problem - DLP):
    Tìm khoá bí mật x (1 <= x < q) sao cho alpha^x mod q = y bằng phương pháp vét cạn (Brute-force).
    Độ phức tạp thời gian: O(q), không gian: O(1).
    Trả về: (x tìm được hoặc None, số phép nhân modulo đã thực hiện, thời gian chạy giây).
    """
    t0 = time.perf_counter()
    curr = 1
    limit = min(q, max_steps)
    for x in range(1, limit):
        curr = (curr * alpha) % q
        if curr == y:
            elapsed = time.perf_counter() - t0
            return x, x, elapsed
    elapsed = time.perf_counter() - t0
    return None, limit - 1, elapsed


def discrete_log_bsgs(
    alpha: int, y: int, q: int, max_m: int = 500_000
) -> Tuple[Optional[int], int, float]:
    """
    Giải bài toán Logarit rời rạc (tìm x sao cho alpha^x mod q = y) bằng thuật toán
    Bước nhỏ - Bước lớn (Baby-step Giant-step của Daniel Shanks).
    - Đặt m = ceil(sqrt(q - 1)), viết x = i * m + j với 0 <= i, j < m.
    - Ta có: alpha^(i*m + j) = y (mod q) <=> y * (alpha^(-m))^i = alpha^j (mod q).
    - Bước nhỏ (Baby steps): Tính bảng băm lưu (alpha^j mod q -> j) với j = 0..m-1.
    - Bước lớn (Giant steps): Tính c = alpha^(-m) mod q, duyệt i = 0..m-1 kiểm tra
      xem (y * c^i mod q) có nằm trong bảng băm không.
    Độ phức tạp thời gian và bộ nhớ: O(sqrt(q)) — nhanh hơn hẳn vét cạn O(q) nhưng vẫn
    bất khả thi khi q >= 2048 bit (sqrt(2^2048) = 2^1024 phép tính).
    """
    t0 = time.perf_counter()
    m = math.isqrt(q - 1) + 1
    if m > max_m:
        return None, 0, time.perf_counter() - t0

    # Baby steps: lưu bảng {alpha^j mod q: j}
    baby_table: Dict[int, int] = {}
    curr = 1
    ops = 0
    for j in range(m):
        baby_table[curr] = j
        curr = (curr * alpha) % q
        ops += 1

    # Tính alpha^(-m) mod q sử dụng thuật toán nghịch đảo modulo và bình phương & nhân tự cài đặt
    alpha_m = square_and_multiply(alpha, m, q)
    alpha_neg_m = mod_inverse_table(alpha_m, q)
    if alpha_neg_m is None:
        return None, ops, time.perf_counter() - t0

    # Giant steps: duyệt i = 0..m-1
    gamma = y % q
    for i in range(m):
        ops += 1
        if gamma in baby_table:
            j = baby_table[gamma]
            x = i * m + j
            elapsed = time.perf_counter() - t0
            return x, ops, elapsed
        gamma = (gamma * alpha_neg_m) % q

    elapsed = time.perf_counter() - t0
    return None, ops, elapsed
