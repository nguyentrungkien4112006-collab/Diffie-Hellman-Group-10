"""
Module minh hoạ Tấn công Người đứng giữa (Man-in-the-Middle - MITM) trên giao thức
Diffie-Hellman cơ bản và cơ chế Phòng chống bằng Chữ ký số RSA (Authenticated DH).

1. Nguyên nhân lỗ hổng MITM trên Diffie-Hellman cơ bản:
   - Các khoá công khai y_A và y_B được trao đổi trên kênh truyền không xác thực danh tính.
   - Kẻ tấn công chủ động Eve (hoặc Mallory) đứng giữa đường truyền:
     + Khi Alice gửi y_A cho Bob -> Eve chặn lại và gửi y_E1 = alpha^(x_E1) mod q cho Bob.
     + Khi Bob gửi y_B cho Alice -> Eve chặn lại và gửi y_E2 = alpha^(x_E2) mod q cho Alice.
     + Kết quả:
       * Alice tính khoá chung với Eve: K_AE = (y_E2)^(x_A) mod q = (y_A)^(x_E2) mod q.
       * Bob tính khoá chung với Eve:   K_EB = (y_E1)^(x_B) mod q = (y_B)^(x_E1) mod q.
     + Mọi bản tin Alice mã hoá bằng K_AE gửi đi đều bị Eve giải mã, đọc/sửa nội dung rồi
       mã hoá lại bằng K_EB gửi cho Bob mà cả hai không hề hay biết!

2. Cách phòng chống (Authenticated Diffie-Hellman / STS Protocol):
   - Mỗi bên sở hữu cặp khoá Chữ ký số (ví dụ RSA theo Slide 41-44) đã được chứng thực (PKI - Slide 47-48).
   - Khi gửi khoá công khai DH y_A, Alice ký số lên thông điệp (ID_A || y_A || q || alpha):
     Sig_A = (Hash(ID_A || y_A))^d_A mod N_A.
   - Nếu Eve thay đổi y_A thành y_E, Eve không có khoá bí mật RSA d_A của Alice nên chữ ký
     sẽ không khớp khi Bob kiểm tra bằng khoá công khai RSA (e_A, N_A) -> Phát hiện và chặn đứng MITM!
"""

from typing import Dict, Tuple

from .cipher_stream import decrypt_text, encrypt_text, sha256_from_scratch
from .diffie_hellman import DiffieHellmanGroup, DiffieHellmanParty
from .math_utils import gcd_euclid, mod_inverse_table, square_and_multiply


class SimpleRSA:
    """
    Hệ mã RSA và Chữ ký điện tử RSA tự cài đặt từ đầu theo đúng Slide 41-44 (Chương 3):
    - Chọn 2 số nguyên tố p, q -> N = p * q, Phi(N) = (p - 1)*(q - 1)
    - Chọn e sao cho 1 < e < Phi(N) và GCD(e, Phi(N)) = 1
    - Tính d = e^-1 mod Phi(N) bằng thuật toán bảng nghịch đảo modulo (Slide 18-22)
    - Ký số lên thông điệp M: S = H(M)^d mod N
    - Kiểm tra chữ ký: H_check = S^e mod N == H(M) mod N
    """

    def __init__(self, owner: str, p: int, q: int, e: int = 65537):
        self.owner = owner
        self.p = p
        self.q = q
        self.n = p * q
        self.phi = (p - 1) * (q - 1)

        if e >= self.phi or gcd_euclid(e, self.phi) != 1:
            for cand in [7, 11, 17, 257, 65537]:
                if cand < self.phi and gcd_euclid(cand, self.phi) == 1:
                    e = cand
                    break
        self.e = e
        d = mod_inverse_table(self.e, self.phi)
        if d is None:
            raise ValueError("Không tìm được khoá giải mã RSA d.")
        self.d = d

    def _hash_to_int(self, message: str) -> int:
        """Băm thông điệp bằng SHA-256 tự cài đặt và rút gọn theo modulo N."""
        digest = sha256_from_scratch(message.encode("utf-8"))
        val = int.from_bytes(digest, byteorder="big")
        return val % self.n

    def sign(self, message: str) -> Tuple[int, int]:
        """Tạo chữ ký số RSA: sig = H(message)^d mod N."""
        h = self._hash_to_int(message)
        sig = square_and_multiply(h, self.d, self.n)
        return h, sig

    @staticmethod
    def verify(message: str, signature: int, pub_e: int, pub_n: int) -> Dict[str, object]:
        """Kiểm tra chữ ký số RSA bằng khoá công khai (pub_e, pub_n)."""
        digest = sha256_from_scratch(message.encode("utf-8"))
        expected_h = int.from_bytes(digest, byteorder="big") % pub_n
        recovered_h = square_and_multiply(signature, pub_e, pub_n)
        return {
            "expected_hash_mod_n": expected_h,
            "recovered_hash_mod_n": recovered_h,
            "is_valid": expected_h == recovered_h,
        }


def simulate_unauthenticated_mitm(
    q: int = 353,
    alpha: int = 3,
    x_A: int = 97,
    x_B: int = 233,
    x_E1: int = 123,
    x_E2: int = 55,
    alice_message: str = "Chuyen khoan 50,000,000 VND vao tai khoan Bob: 1903888999",
    tampered_message: str = "Chuyen khoan 50,000,000 VND vao tai khoan Eve: 6666777888",
) -> Dict[str, object]:
    """
    Mô phỏng chi tiết kịch bản tấn công Người đứng giữa (MITM) thành công khi không có xác thực:
    - Alice (x_A) và Bob (x_B) muốn trao đổi khoá trên nhóm (q, alpha).
    - Kẻ tấn công Eve đứng giữa sinh khoá mật x_E1 (để giao tiếp với Alice) và x_E2 (để giao tiếp với Bob).
    - Alice gửi y_A -> Eve chặn lại và gửi y_E1 cho Alice (giả danh Bob).
    - Bob gửi y_B -> Eve chặn lại và gửi y_E2 cho Bob (giả danh Alice).
    - Alice và Eve có chung khoá phiên K_AE = (y_E1)^x_A mod q = (y_A)^x_E1 mod q.
    - Bob và Eve có chung khoá phiên K_EB = (y_E2)^x_B mod q = (y_B)^x_E2 mod q.
    - Alice mã hoá `alice_message` bằng K_AE gửi đi -> Eve giải mã đọc toàn bộ, sửa thành `tampered_message`,
      rồi mã hoá lại bằng K_EB gửi cho Bob -> Bob giải mã thành công và tin rằng đó là tin nhắn của Alice!
    """
    group = DiffieHellmanGroup(q=q, alpha=alpha, name=f"MITM Group (q={q}, alpha={alpha})")
    alice = DiffieHellmanParty("Alice", group, private_key=x_A)
    bob = DiffieHellmanParty("Bob", group, private_key=x_B)
    eve_for_alice = DiffieHellmanParty("Eve (giả danh Bob với Alice)", group, private_key=x_E1)
    eve_for_bob = DiffieHellmanParty("Eve (giả danh Alice với Bob)", group, private_key=x_E2)

    # Bước 1: Eve chặn y_A và y_B, tráo bằng y_E1 (gửi cho Alice) và y_E2 (gửi cho Bob)
    k_alice = alice.compute_shared_secret(eve_for_alice.public_key)
    k_eve_with_alice = eve_for_alice.compute_shared_secret(alice.public_key)

    k_bob = bob.compute_shared_secret(eve_for_bob.public_key)
    k_eve_with_bob = eve_for_bob.compute_shared_secret(bob.public_key)

    # Bước 2: Alice mã hoá bản tin gửi cho Bob bằng khoá k_alice
    cipher_from_alice = encrypt_text(alice_message, k_alice)

    # Bước 3: Eve chặn gói tin, dùng k_eve_with_alice để giải mã, đọc và sửa nội dung
    intercepted_plaintext = decrypt_text(cipher_from_alice, k_eve_with_alice)
    cipher_forged_by_eve = encrypt_text(tampered_message, k_eve_with_bob)

    # Bước 4: Bob nhận gói tin từ Eve và giải mã bằng k_bob
    bob_received_plaintext = decrypt_text(cipher_forged_by_eve, k_bob)

    return {
        "q": q,
        "alpha": alpha,
        "x_A": alice.private_key,
        "y_A": alice.public_key,
        "x_B": bob.private_key,
        "y_B": bob.public_key,
        "x_E1": eve_for_alice.private_key,
        "y_E1": eve_for_alice.public_key,
        "x_E2": eve_for_bob.private_key,
        "y_E2": eve_for_bob.public_key,
        "K_AE_alice": k_alice,
        "K_AE_eve": k_eve_with_alice,
        "K_EB_bob": k_bob,
        "K_EB_eve": k_eve_with_bob,
        "alice_original_message": alice_message,
        "cipher_from_alice_hex": cipher_from_alice,
        "eve_decrypted_message": intercepted_plaintext,
        "eve_tampered_message": tampered_message,
        "cipher_forged_by_eve_hex": cipher_forged_by_eve,
        "bob_decrypted_message": bob_received_plaintext,
        "attack_succeeded": (
            k_alice == k_eve_with_alice
            and k_bob == k_eve_with_bob
            and intercepted_plaintext == alice_message
            and bob_received_plaintext == tampered_message
        ),
    }


def simulate_authenticated_dh_defense(
    q: int = 353,
    alpha: int = 3,
    x_A: int = 97,
    x_B: int = 233,
    x_E: int = 123,
) -> Dict[str, object]:
    """
    Mô phỏng cơ chế Phòng chống tấn công Người đứng giữa (MITM) bằng Chữ ký số RSA & PKI.
    """
    group = DiffieHellmanGroup(q=q, alpha=alpha, name=f"Authenticated DH Group (q={q}, alpha={alpha})")
    alice_dh = DiffieHellmanParty("Alice", group, private_key=x_A)
    bob_dh = DiffieHellmanParty("Bob", group, private_key=x_B)
    eve_dh = DiffieHellmanParty("Eve", group, private_key=x_E)

    # Khởi tạo cặp khoá chữ ký số RSA cho Alice, Bob và Eve
    alice_rsa = SimpleRSA("Alice", p=61, q=53, e=17)
    bob_rsa = SimpleRSA("Bob", p=47, q=71, e=79)
    eve_rsa = SimpleRSA("Eve", p=43, q=59, e=13)

    # Alice ký số lên khoá công khai DH y_A của mình
    msg_alice = f"ALICE_DH_KEY|q={q}|alpha={alpha}|y={alice_dh.public_key}"
    h_alice, sig_alice = alice_rsa.sign(msg_alice)

    # 1. Kiểm tra trường hợp hợp lệ (không bị tráo)
    legit_verify = SimpleRSA.verify(msg_alice, sig_alice, alice_rsa.e, alice_rsa.n)

    # 2. Eve chặn đường truyền và thay y_A bằng y_E
    msg_tampered_by_eve = f"ALICE_DH_KEY|q={q}|alpha={alpha}|y={eve_dh.public_key}"

    # Trường hợp 2a: Eve giữ nguyên chữ ký của Alice nhưng đổi nội dung y_A -> y_E
    mitm_replay_sig_verify = SimpleRSA.verify(
        msg_tampered_by_eve, sig_alice, alice_rsa.e, alice_rsa.n
    )

    # Trường hợp 2b: Eve tự ký lên msg_tampered_by_eve bằng khoá RSA của Eve
    _, sig_forged_by_eve = eve_rsa.sign(msg_tampered_by_eve)
    mitm_forged_sig_verify = SimpleRSA.verify(
        msg_tampered_by_eve, sig_forged_by_eve, alice_rsa.e, alice_rsa.n
    )

    # Sau khi loại bỏ gói tin giả mạo của Eve, Alice và Bob xác thực thành công và thiết lập K_AB
    msg_bob = f"BOB_DH_KEY|q={q}|alpha={alpha}|y={bob_dh.public_key}"
    _, sig_bob = bob_rsa.sign(msg_bob)
    legit_bob_verify = SimpleRSA.verify(msg_bob, sig_bob, bob_rsa.e, bob_rsa.n)

    k_ab = alice_dh.compute_shared_secret(bob_dh.public_key)

    return {
        "alice_rsa_pub": (alice_rsa.e, alice_rsa.n),
        "alice_rsa_priv_d": alice_rsa.d,
        "bob_rsa_pub": (bob_rsa.e, bob_rsa.n),
        "y_A": alice_dh.public_key,
        "y_B": bob_dh.public_key,
        "y_E": eve_dh.public_key,
        "msg_alice": msg_alice,
        "sig_alice": sig_alice,
        "legit_verify": legit_verify,
        "legit_bob_verify": legit_bob_verify,
        "mitm_replay_sig_verify": mitm_replay_sig_verify,
        "mitm_forged_sig_verify": mitm_forged_sig_verify,
        "mitm_blocked": (
            legit_verify["is_valid"]
            and legit_bob_verify["is_valid"]
            and not mitm_replay_sig_verify["is_valid"]
            and not mitm_forged_sig_verify["is_valid"]
        ),
        "established_K_AB": k_ab,
    }
