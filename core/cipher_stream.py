"""
Module truyền thông bảo mật sử dụng khoá phiên chung K_AB từ trao đổi khoá Diffie-Hellman.
Theo Slide 49-50:
- Diffie-Hellman không dùng trực tiếp để mã hoá mẩu tin, mà để thiết lập khoá phiên chung K_AB.
- Sau đó K_AB được sử dụng như khoá phiên trong sơ đồ mã hoá khoá riêng (đối xứng) giữa A và B.

Để đáp ứng đầy đủ yêu cầu trong hướng dẫn bài tập nhóm:
- "Nhóm tự cài đặt thuật toán từ đầu. Không dùng thư viện mật mã có sẵn cho phần lõi."
- "Có đủ cả hai chiều: mã hoá và giải mã. Giải mã phải khôi phục đúng bản rõ ban đầu."
- "Demo trên dữ liệu thật, không chỉ vài ký tự: mã hoá một tệp văn bản hoặc một tệp ảnh nhỏ rồi giải mã lại."

Module này tự cài đặt hoàn toàn từ đầu (from scratch):
1. Hàm băm mật mã SHA-256 (theo chuẩn FIPS 180-4, không gọi hashlib ở phần lõi).
2. Bộ sinh dòng khoá (Keystream Generator) ở chế độ Counter Mode dựa trên SHA-256(K_AB || counter)
   kết hợp mã xác thực thông điệp (MAC) từ khoá phiên K_AB để vừa mã hoá/giải mã tốc độ cao
   mọi loại dữ liệu (chuỗi UTF-8, file văn bản, file ảnh PNG/BMP) vừa kiểm tra toàn vẹn.
"""

import struct
from typing import Dict, Tuple

# Hằng số khởi tạo 8 thanh ghi 32-bit của SHA-256 (căn bậc hai của 8 số nguyên tố đầu tiên)
_SHA256_H0 = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]

# Bảng 64 hằng số vòng K của SHA-256 (căn bậc ba của 64 số nguyên tố đầu tiên)
_SHA256_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def _rotr32(x: int, n: int) -> int:
    """Phép dịch vòng phải (Rotate Right) trên từ 32-bit."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def sha256_from_scratch(data: bytes) -> bytes:
    """
    Hàm băm SHA-256 được cài đặt hoàn toàn từ đầu theo chuẩn FIPS 180-4 (không dùng hashlib).
    Đầu vào: chuỗi byte bất kỳ.
    Đầu ra: giá trị băm 32 byte (256 bit).
    """
    # 1. Tiền xử lý (Padding): thêm bit 1 (0x80), các bit 0 và độ dài thông điệp 64-bit big-endian
    bit_len = len(data) * 8
    padded = bytearray(data)
    padded.append(0x80)
    while (len(padded) + 8) % 64 != 0:
        padded.append(0x00)
    padded.extend(struct.pack(">Q", bit_len))

    # 2. Khởi tạo 8 thanh ghi trạng thái H0..H7
    h0, h1, h2, h3, h4, h5, h6, h7 = _SHA256_H0

    # 3. Xử lý từng khối 512-bit (64 byte)
    for offset in range(0, len(padded), 64):
        chunk = padded[offset : offset + 64]
        w = list(struct.unpack(">16I", chunk)) + [0] * 48

        for i in range(16, 64):
            s0 = _rotr32(w[i - 15], 7) ^ _rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr32(w[i - 2], 17) ^ _rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for i in range(64):
            S1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + _SHA256_K[i] + w[i]) & 0xFFFFFFFF
            S0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF

    return struct.pack(">8I", h0, h1, h2, h3, h4, h5, h6, h7)


def shared_secret_to_key_bytes(shared_secret: int) -> bytes:
    """
    Chuyển số nguyên khoá phiên chung K_AB thành khoá đối xứng 256-bit (32 byte)
    bằng hàm băm SHA-256 tự cài đặt.
    """
    byte_len = max(1, (shared_secret.bit_length() + 7) // 8)
    raw_bytes = shared_secret.to_bytes(byte_len, byteorder="big")
    return sha256_from_scratch(b"DH_SESSION_KEY_V1:" + raw_bytes)


def derive_keystream(shared_secret: int, length: int, nonce: bytes = b"DH_NONCE_0001") -> bytes:
    """
    Sinh dòng khoá (Keystream) có độ dài `length` byte từ khoá phiên chung K_AB
    theo cơ chế Counter Mode (CTR) dựa trên hàm băm SHA-256 tự cài đặt.
    """
    master_key = shared_secret_to_key_bytes(shared_secret)
    blocks = []
    num_blocks = (length + 31) // 32
    for counter in range(num_blocks):
        block_input = master_key + nonce + struct.pack(">Q", counter)
        blocks.append(sha256_from_scratch(block_input))
    return b"".join(blocks)[:length]


def compute_mac(shared_secret: int, data: bytes) -> bytes:
    """
    Tính mã xác thực thông điệp (MAC 16 byte) từ khoá chung K_AB và bản mã
    để phát hiện nếu giải mã sai khoá hoặc bản mã bị sửa đổi trên đường truyền.
    """
    master_key = shared_secret_to_key_bytes(shared_secret)
    tag_full = sha256_from_scratch(master_key + b":MAC_TAG:" + data)
    return tag_full[:16]


def encrypt_bytes(plaintext: bytes, shared_secret: int) -> bytes:
    """
    Mã hoá mảng byte bất kỳ (văn bản hoặc tệp nhị phân/hình ảnh) bằng khoá phiên chung K_AB.
    Cấu trúc gói tin đầu ra: [Nonce 8 byte] + [MAC Tag 16 byte] + [Ciphertext].
    """
    nonce = sha256_from_scratch(
        shared_secret_to_key_bytes(shared_secret) + struct.pack(">Q", len(plaintext))
    )[:8]
    keystream = derive_keystream(shared_secret, len(plaintext), nonce=nonce)
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
    mac_tag = compute_mac(shared_secret, nonce + ciphertext)
    return nonce + mac_tag + ciphertext


def decrypt_bytes(packet: bytes, shared_secret: int) -> bytes:
    """
    Giải mã gói tin được mã hoá bởi `encrypt_bytes` với khoá phiên chung K_AB.
    Kiểm tra tính toàn vẹn qua MAC Tag trước khi khôi phục bản rõ.
    Nếu dùng sai khoá K_AB hoặc bản mã bị thay đổi, hàm sẽ ném lỗi ValueError.
    """
    if len(packet) < 24:
        raise ValueError("Gói bản mã không hợp lệ (độ dài nhỏ hơn 24 byte header).")
    nonce = packet[:8]
    mac_tag = packet[8:24]
    ciphertext = packet[24:]

    expected_mac = compute_mac(shared_secret, nonce + ciphertext)
    if mac_tag != expected_mac:
        raise ValueError("Xác thực MAC thất bại! Khoá phiên K_AB không khớp hoặc bản mã đã bị can thiệp.")

    keystream = derive_keystream(shared_secret, len(ciphertext), nonce=nonce)
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, keystream))
    return plaintext


def encrypt_text(plaintext_str: str, shared_secret: int) -> str:
    """
    Mã hoá chuỗi văn bản UTF-8 bằng khoá phiên K_AB và trả về chuỗi Hex.
    """
    raw = plaintext_str.encode("utf-8")
    encrypted = encrypt_bytes(raw, shared_secret)
    return encrypted.hex()


def decrypt_text(cipher_hex: str, shared_secret: int) -> str:
    """
    Giải mã chuỗi Hex bằng khoá phiên K_AB và trả về chuỗi văn bản UTF-8 gốc.
    """
    packet = bytes.fromhex(cipher_hex.strip())
    decrypted = decrypt_bytes(packet, shared_secret)
    return decrypted.decode("utf-8")


def encrypt_file(input_path: str, output_path: str, shared_secret: int) -> Dict[str, object]:
    """
    Mã hoá một tệp thực tế (văn bản .txt, ảnh .png/.bmp, tài liệu...) sử dụng khoá phiên K_AB.
    Trả về thông tin kích thước và mã băm SHA-256 trước/sau khi mã hoá.
    """
    with open(input_path, "rb") as f:
        plain_data = f.read()

    cipher_data = encrypt_bytes(plain_data, shared_secret)
    with open(output_path, "wb") as f:
        f.write(cipher_data)

    return {
        "input_path": input_path,
        "output_path": output_path,
        "plain_size_bytes": len(plain_data),
        "cipher_size_bytes": len(cipher_data),
        "plain_sha256": sha256_from_scratch(plain_data).hex(),
        "cipher_sha256": sha256_from_scratch(cipher_data).hex(),
    }


def decrypt_file(input_path: str, output_path: str, shared_secret: int) -> Dict[str, object]:
    """
    Giải mã tệp đã mã hoá bằng khoá phiên K_AB và lưu ra `output_path`.
    """
    with open(input_path, "rb") as f:
        cipher_data = f.read()

    plain_data = decrypt_bytes(cipher_data, shared_secret)
    with open(output_path, "wb") as f:
        f.write(plain_data)

    return {
        "input_path": input_path,
        "output_path": output_path,
        "cipher_size_bytes": len(cipher_data),
        "recovered_size_bytes": len(plain_data),
        "recovered_sha256": sha256_from_scratch(plain_data).hex(),
    }
