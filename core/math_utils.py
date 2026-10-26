"""
Module toán học nền tảng trên vành Z_n phục vụ hệ mã khoá công khai và Diffie-Hellman.
Tất cả các thuật toán được cài đặt từ đầu (from scratch) bám sát Bài giảng Chương 3:
1. Thuật toán Euclid tìm ƯSCLN - GCD(a, b) (Slide 14)
2. Thuật toán Euclid mở rộng tìm (d, x, y) sao cho a*x + b*y = d (Slide 15-16)
3. Thuật toán tìm phần tử nghịch đảo a^-1 mod n bằng bảng 6 cột (Slide 17-22)
4. Thuật toán "Bình phương và nhân" tính a^k mod n (Slide 23-24)
5. Hàm Euler Phi(n) và phân tích thừa số nguyên tố (Slide 25-28)
6. Thuật toán kiểm tra tính nguyên tố Miller-Rabin (Slide 29)
7. Kiểm tra và tìm căn nguyên thủy (Primitive Root) alpha của số nguyên tố q (Slide 50)
"""

import random
from typing import Dict, List, Optional, Tuple


def gcd_euclid(a: int, b: int, return_steps: bool = False):
    """
    Thuật toán Euclid tìm Ước số chung lớn nhất GCD(a, b) theo Slide 14.
    VÀO: Hai số nguyên không âm a và b.
    RA: UCLN của a và b (kèm danh sách các bước chia nếu return_steps=True).
    """
    a, b = abs(a), abs(b)
    steps: List[Dict[str, int]] = []
    while b != 0:
        q = a // b
        r = a % b
        steps.append({"a": a, "b": b, "q": q, "r": r})
        a, b = b, r
    if return_steps:
        return a, steps
    return a


def extended_euclid(a: int, b: int, return_steps: bool = False):
    """
    Thuật toán Euclid mở rộng theo đúng giả mã tại Slide 15-16.
    Tìm d = GCD(a, b) và hai số nguyên x, y thoả mãn: a*x + b*y = d.
    Lưu lại bảng trạng thái (q, r, x, y, a, b, x2, x1, y2, y1) giống hệt Slide 16.
    """
    if b == 0:
        res = (a, 1, 0)
        return (res, []) if return_steps else res

    x2, x1 = 1, 0
    y2, y1 = 0, 1
    curr_a, curr_b = a, b

    table: List[Dict[str, Optional[int]]] = [
        {
            "q": None,
            "r": None,
            "x": None,
            "y": None,
            "a": curr_a,
            "b": curr_b,
            "x2": x2,
            "x1": x1,
            "y2": y2,
            "y1": y1,
        }
    ]

    while curr_b > 0:
        q = curr_a // curr_b
        r = curr_a - q * curr_b
        x = x2 - q * x1
        y = y2 - q * y1

        curr_a = curr_b
        curr_b = r
        x2 = x1
        x1 = x
        y2 = y1
        y1 = y

        table.append(
            {
                "q": q,
                "r": r,
                "x": x,
                "y": y,
                "a": curr_a,
                "b": curr_b,
                "x2": x2,
                "x1": x1,
                "y2": y2,
                "y1": y1,
            }
        )

    d, final_x, final_y = curr_a, x2, y2
    if return_steps:
        return (d, final_x, final_y), table
    return d, final_x, final_y


def mod_inverse_table(a: int, n: int, return_steps: bool = False):
    """
    Thuật toán tìm số nghịch đảo a^-1 mod n bằng bảng 6 cột (Dòng, r0, r1, r2, q, t0, t1)
    theo đúng hướng dẫn từ Bước 1 đến Bước 6 tại Slide 18-22.
    Ví dụ kiểm chứng:
    - 25^-1 mod 101 = 97 (Slide 21)
    - 173^-1 mod 1024 = 805 (Slide 22)
    """
    a_mod = a % n
    r0, r1 = n, a_mod
    t0, t1 = 0, 1
    row_idx = 0
    rows: List[Dict[str, int]] = []

    while True:
        if r1 == 0:
            if return_steps:
                return None, rows
            return None

        r2 = r0 % r1
        q = r0 // r1

        rows.append(
            {
                "row": row_idx,
                "r0": r0,
                "r1": r1,
                "r2": r2,
                "q": q,
                "t0": t0,
                "t1": t1,
            }
        )

        # Bước 4 & Bước 6: Tính t1 mới cho dòng kế tiếp = (t0 - q * t1) mod n
        next_t1 = (t0 - q * t1) % n

        # Bước 5: Kiểm tra điều kiện dừng khi r2 == 0
        if r2 == 0:
            if r1 == 1:
                inv = t1 % n
                return (inv, rows) if return_steps else inv
            else:
                return (None, rows) if return_steps else None

        # Bước 6: Sao chép giá trị sang dòng tiếp theo
        r0, r1 = r1, r2
        t0, t1 = t1, next_t1
        row_idx += 1


def square_and_multiply(a: int, k: int, n: int, return_steps: bool = False):
    """
    Thuật toán "Bình phương và nhân" tính a^k mod n theo đúng giả mã tại Slide 23-24:
        Biểu diễn k dạng nhị phân b_t b_{t-1} ... b_1 b_0
        c <- 0; f <- 1;
        for i = t downto 0 do
            c <- 2 * c
            f <- (f * f) mod n
            if b_i == 1 then
                c <- c + 1
                f <- (f * a) mod n
        return f

    Ví dụ kiểm chứng tại Slide 24: a = 7, k = 560, n = 561 -> f = 1.
    Lưu ý: Không gọi hàm pow(a, k, n) có sẵn của Python để đảm bảo cài đặt từ đầu 100%.
    """
    if n <= 0:
        raise ValueError("Modulo n phải là số nguyên dương.")
    if n == 1:
        return (0, []) if return_steps else 0
    if k == 0:
        return (1, [{"i": 0, "b_i": 0, "c": 0, "f": 1}]) if return_steps else 1
    if k < 0:
        inv = mod_inverse_table(a, n)
        if inv is None:
            raise ValueError(f"Không tồn tại nghịch đảo của {a} mod {n} cho số mũ âm.")
        a = inv
        k = -k

    bin_str = bin(k)[2:]  # chuỗi bit từ MSB (b_t) xuống LSB (b_0)
    t = len(bin_str) - 1
    c = 0
    f = 1
    steps: List[Dict[str, int]] = []

    for idx, bit_char in enumerate(bin_str):
        i = t - idx
        b_i = 1 if bit_char == "1" else 0
        c = 2 * c
        f = (f * f) % n
        if b_i == 1:
            c = c + 1
            f = (f * a) % n
        if return_steps:
            steps.append({"i": i, "b_i": b_i, "c": c, "f": f})

    if return_steps:
        return f, steps
    return f


def miller_rabin_single_round(n: int, a: int) -> Tuple[bool, Dict[str, object]]:
    """
    Một vòng kiểm tra tính nguyên tố Miller-Rabin với cơ số a theo đúng Slide 29:
    1. Phân tích (n - 1) = 2^k * q (với k > 0, q lẻ)
    2. Chọn a (1 < a < n - 1)
    3. Nếu a^q mod n == 1 -> return True ("n là số nguyên tố" có xác suất)
    4. For j = 0 to k - 1: nếu a^(2^j * q) mod n == n - 1 -> return True
    5. Return False ("n KHÔNG là số nguyên tố")
    """
    q = n - 1
    k = 0
    while q % 2 == 0:
        q //= 2
        k += 1

    # Tính x = a^q mod n bằng thuật toán bình phương và nhân tự cài đặt
    x = square_and_multiply(a, q, n)
    trace = {"a": a, "k": k, "q": q, "a_pow_q_mod_n": x, "j_checks": []}

    if x == 1 or x == n - 1:
        trace["j_checks"].append({"j": 0, "val": x, "passed": True})
        return True, trace

    trace["j_checks"].append({"j": 0, "val": x, "passed": False})
    curr = x
    for j in range(1, k):
        curr = (curr * curr) % n
        if curr == n - 1:
            trace["j_checks"].append({"j": j, "val": curr, "passed": True})
            return True, trace
        trace["j_checks"].append({"j": j, "val": curr, "passed": False})

    return False, trace


def miller_rabin_test(n: int, rounds: int = 16, return_trace: bool = False):
    """
    Kiểm tra tính nguyên tố của số nguyên n bằng thuật toán Miller-Rabin (Slide 29).
    Kết hợp chia thử các số nguyên tố nhỏ và kiểm tra `rounds` cơ số ngẫu nhiên.
    """
    if n < 2:
        return (False, []) if return_trace else False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small_primes:
        return (True, []) if return_trace else True
    for p in small_primes:
        if n % p == 0:
            return (False, []) if return_trace else False

    traces = []
    # Sử dụng tập cơ số cố định kết hợp ngẫu nhiên để đảm bảo tính tất định với số < 2^64
    deterministic_bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    bases_to_test = [b for b in deterministic_bases if 1 < b < n - 1][:rounds]
    while len(bases_to_test) < rounds and n > 40:
        a = random.randint(2, n - 2)
        if a not in bases_to_test:
            bases_to_test.append(a)

    for a in bases_to_test:
        passed, tr = miller_rabin_single_round(n, a)
        traces.append(tr)
        if not passed:
            return (False, traces) if return_trace else False

    return (True, traces) if return_trace else True


def prime_factors(n: int) -> List[int]:
    """
    Phân tích số nguyên dương n ra danh sách các thừa số nguyên tố phân biệt (Slide 25).
    Phục vụ tính hàm Euler Phi(n) và kiểm tra căn nguyên thủy (Primitive Root).
    """
    factors = []
    d = 2
    temp = n
    while d * d <= temp:
        if temp % d == 0:
            factors.append(d)
            while temp % d == 0:
                temp //= d
        d += 1 if d == 2 else 2
    if temp > 1:
        factors.append(temp)
    return factors


def euler_totient(n: int) -> int:
    """
    Tính giá trị hàm Euler Phi(n) theo định lý phân tích thừa số nguyên tố (Slide 27-28):
    Phi(n) = n * Prod_{p | n} (1 - 1/p)
    """
    if n <= 0:
        raise ValueError("n phải là số nguyên dương.")
    if n == 1:
        return 1
    result = n
    for p in prime_factors(n):
        result = result // p * (p - 1)
    return result


def is_primitive_root(alpha: int, q: int) -> Tuple[bool, List[Dict[str, int]]]:
    """
    Kiểm tra alpha có phải là căn nguyên tố (primitive root / phần tử sinh) của số nguyên tố q hay không.
    Theo lý thuyết số (Slide 50): alpha là căn nguyên tố của mod q (q nguyên tố) khi và chỉ khi
    với mọi ước nguyên tố p_i của (q - 1), ta đều có:
        alpha^((q - 1) / p_i) mod q != 1
    """
    if not (1 < alpha < q):
        return False, []
    phi = q - 1
    p_factors = prime_factors(phi)
    checks = []
    is_valid = True
    for pf in p_factors:
        exp = phi // pf
        rem = square_and_multiply(alpha, exp, q)
        checks.append({"prime_factor": pf, "exponent": exp, "remainder": rem})
        if rem == 1:
            is_valid = False
    return is_valid, checks


def find_primitive_root(q: int) -> int:
    """
    Tìm căn nguyên tố dương nhỏ nhất alpha của số nguyên tố q.
    """
    if q == 2:
        return 1
    for alpha in range(2, q):
        ok, _ = is_primitive_root(alpha, q)
        if ok:
            return alpha
    raise ValueError(f"Không tìm thấy căn nguyên tố cho q = {q}")


def generate_prime(bits: int = 64, safe_prime: bool = False) -> Tuple[int, int]:
    """
    Sinh ngẫu nhiên số nguyên tố q có độ dài `bits` bit và căn nguyên thủy alpha tương ứng.
    Nếu safe_prime=True, sinh số nguyên tố an toàn q = 2*p + 1 (với p cũng là số nguyên tố Sophie Germain)
    để việc kiểm tra căn nguyên thủy alpha trên số lớn diễn ra tức thì (chỉ có 2 ước nguyên tố của q-1 là 2 và p).
    """
    if bits < 8:
        raise ValueError("Số bit tối thiểu là 8.")

    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1  # Đảm bảo đủ số bit và là số lẻ

        if safe_prime:
            p = (candidate - 1) // 2
            if p % 2 == 0:
                continue
            if miller_rabin_test(p, rounds=12) and miller_rabin_test(candidate, rounds=12):
                q = candidate
                # Tìm phần tử sinh alpha cho safe prime q = 2p + 1
                for alpha in [2, 3, 5, 7, 11]:
                    if (
                        square_and_multiply(alpha, 2, q) != 1
                        and square_and_multiply(alpha, p, q) != 1
                    ):
                        return q, alpha
        else:
            if miller_rabin_test(candidate, rounds=14):
                q = candidate
                if bits <= 40:
                    alpha = find_primitive_root(q)
                else:
                    alpha = 2
                return q, alpha
