"""
Package core chứa toàn bộ các thuật toán nền tảng và hệ mã Diffie-Hellman
được nhóm tự cài đặt từ đầu (from scratch), không sử dụng thư viện mật mã có sẵn.
"""

from .math_utils import (
    gcd_euclid,
    extended_euclid,
    mod_inverse_table,
    square_and_multiply,
    miller_rabin_test,
    generate_prime,
    prime_factors,
    is_primitive_root,
    find_primitive_root,
    euler_totient,
)
from .diffie_hellman import (
    DiffieHellmanGroup,
    DiffieHellmanParty,
    run_slide51_example,
    get_rfc3526_group14,
    get_rfc3526_group5,
    discrete_log_bruteforce,
    discrete_log_bsgs,
)
from .cipher_stream import (
    sha256_from_scratch,
    derive_keystream,
    encrypt_bytes,
    decrypt_bytes,
    encrypt_text,
    decrypt_text,
    encrypt_file,
    decrypt_file,
)
from .mitm_attack import (
    SimpleRSA,
    simulate_unauthenticated_mitm,
    simulate_authenticated_dh_defense,
)

__all__ = [
    "gcd_euclid",
    "extended_euclid",
    "mod_inverse_table",
    "square_and_multiply",
    "miller_rabin_test",
    "generate_prime",
    "prime_factors",
    "is_primitive_root",
    "find_primitive_root",
    "euler_totient",
    "DiffieHellmanGroup",
    "DiffieHellmanParty",
    "run_slide51_example",
    "get_rfc3526_group14",
    "get_rfc3526_group5",
    "discrete_log_bruteforce",
    "discrete_log_bsgs",
    "sha256_from_scratch",
    "derive_keystream",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_text",
    "decrypt_text",
    "encrypt_file",
    "decrypt_file",
    "SimpleRSA",
    "simulate_unauthenticated_mitm",
    "simulate_authenticated_dh_defense",
]
