"""
FileGuard - 旧版格式兼容 (仅解密)

V1.0 ~ V1.4 的两种格式都使用 PBKDF2-SHA256(100000 次, salt = 文件前 16 字节):
    经典版 CFB: [salt 16][iv 16][AES-256-CFB 密文][sha256(明文) 32]
    高级版 GCM: [salt 16][nonce 12][AES-256-GCM 密文][tag 16][verifier 32]
注意: 旧高级版的 verifier 与加密密钥完全相同, 等于把密钥明文写进了文件;
旧经典版在文件尾存放明文哈希且没有认证。两者都不安全, 只为解密旧文件而保留。
"""

import os
import hmac
import hashlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:  # cryptography >= 47 把 CFB 移到了 decrepit
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:
    CFB = modes.CFB

from crypto_v2 import FileGuardError, check_paths, atomic_output, finish_atomic

LEGACY_CFB = "V1 经典版 (AES-256-CFB)"
LEGACY_GCM = "V1 高级版 (AES-256-GCM)"

_READ_SIZE = 1024 * 1024


def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000, dklen=32)


def _stream(f_in, start: int, end: int, transform, progress, total: int) -> None:
    f_in.seek(start)
    remaining = end - start
    done = start
    while remaining > 0:
        data = f_in.read(min(_READ_SIZE, remaining))
        if not data:
            raise FileGuardError("文件已损坏（数据被截断）")
        remaining -= len(data)
        transform(data)
        done += len(data)
        if progress:
            progress(done, total)


def _try_gcm(f_in, key: bytes, size: int, f_out, progress) -> bool:
    if size < 16 + 12 + 48:
        return False
    f_in.seek(size - 32)
    if not hmac.compare_digest(f_in.read(32), key):
        return False
    f_in.seek(16)
    nonce = f_in.read(12)
    f_in.seek(size - 48)
    tag = f_in.read(16)
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    _stream(f_in, 28, size - 48, lambda d: f_out.write(decryptor.update(d)), progress, size)
    try:
        f_out.write(decryptor.finalize())
    except InvalidTag:
        raise FileGuardError("文件已损坏或被篡改")
    return True


def _try_cfb(f_in, key: bytes, size: int, f_out, progress) -> bool:
    if size < 16 + 16 + 32:
        return False
    f_in.seek(16)
    iv = f_in.read(16)
    f_in.seek(size - 32)
    stored_hash = f_in.read(32)
    decryptor = Cipher(algorithms.AES(key), CFB(iv)).decryptor()
    digest = hashlib.sha256()

    def transform(data):
        plain = decryptor.update(data)
        digest.update(plain)
        f_out.write(plain)

    _stream(f_in, 32, size - 32, transform, progress, size)
    tail = decryptor.finalize()
    digest.update(tail)
    f_out.write(tail)
    return hmac.compare_digest(digest.digest(), stored_hash)


def decrypt_legacy(input_path: str, output_path: str, password: str, progress=None) -> str:
    """解密 V1.x 文件, 返回识别出的格式名称"""
    check_paths(input_path, output_path)
    size = os.path.getsize(input_path)
    if size < 64:
        raise FileGuardError("无效的加密文件格式")

    f_out, tmp_path = atomic_output(output_path)
    ok = False
    try:
        with open(input_path, "rb") as f_in:
            key = _derive_key(password, f_in.read(16))
            if _try_gcm(f_in, key, size, f_out, progress):
                ok = True
                return LEGACY_GCM
            f_out.seek(0)
            f_out.truncate()
            if _try_cfb(f_in, key, size, f_out, progress):
                ok = True
                return LEGACY_CFB
        raise FileGuardError("密码错误，或不是 FileGuard 加密文件")
    finally:
        finish_atomic(f_out, tmp_path, output_path, ok)
