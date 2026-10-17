"""
FileGuard - V2 加密核心
Argon2id 密钥派生 + 分块流式 AES-256-GCM 认证加密

文件格式 (FGRD v2):
    头部 (固定 44 字节, 同时作为每个分块的 AAD):
        magic       4   b"FGRD"
        version     1   0x02
        kdf_id      1   1 = Argon2id, 2 = scrypt
        kdf_p1      4   Argon2id: memory_cost(KiB) / scrypt: log2(n)
        kdf_p2      4   Argon2id: iterations       / scrypt: r
        kdf_p3      1   Argon2id: lanes            / scrypt: p
        salt        16
        nonce_pref  8
        chunk_size  4
        reserved    1
    分块: [密文 + 16 字节 GCM 标签] * N
        nonce = nonce_pref || 块序号(uint32 BE)
        AAD   = 头部 || 块序号(uint64 BE) || 是否末块(1 字节)
    末块标志防止截断, 块序号防止重排, 头部进入 AAD 防止篡改参数。
    文件中不保存任何密码校验值, 密码错误时首块 GCM 校验即失败。
"""

import os
import struct
import secrets
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"FGRD"
VERSION = 2
KDF_ARGON2ID = 1
KDF_SCRYPT = 2

TAG_SIZE = 16
DEFAULT_CHUNK_SIZE = 1024 * 1024

# Argon2id: 64 MiB 内存, 3 轮, 4 线程 (OWASP 推荐强度以上)
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
# scrypt 备用参数 (仅在 Argon2id 不可用时使用)
SCRYPT_LOG2_N = 17
SCRYPT_R = 8
SCRYPT_P = 1

# 解密时允许的 KDF 参数范围。头部要在密钥派生之后才能被 GCM 认证,
# 所以必须先做范围检查, 否则恶意文件可写入超大参数耗尽内存或让程序长时间卡死。
MAX_KDF_MEMORY_BYTES = 1024 * 1024 * 1024  # 1 GiB
ARGON2_MAX_ITERATIONS = 10
ARGON2_MAX_LANES = 16
SCRYPT_MIN_LOG2_N = 10
SCRYPT_MAX_LOG2_N = 20
SCRYPT_MAX_R = 32
SCRYPT_MAX_P = 16

_HEADER_STRUCT = struct.Struct(">4sBBIIB16s8sIB")
HEADER_SIZE = _HEADER_STRUCT.size


class FileGuardError(Exception):
    """加解密失败, 消息可直接展示给用户"""


def _argon2_available() -> bool:
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        Argon2id(salt=b"\0" * 16, length=32, iterations=1, lanes=1, memory_cost=8).derive(b"x")
        return True
    except Exception:
        return False


def check_kdf_params(kdf_id: int, p1: int, p2: int, p3: int) -> None:
    """检查 KDF 参数是否在安全范围内, 超出范围抛出 FileGuardError"""
    if kdf_id == KDF_ARGON2ID:
        memory_kib, iterations, lanes = p1, p2, p3
        ok = (1 <= lanes <= ARGON2_MAX_LANES
              and 8 * lanes <= memory_kib <= MAX_KDF_MEMORY_BYTES // 1024
              and 1 <= iterations <= ARGON2_MAX_ITERATIONS)
    elif kdf_id == KDF_SCRYPT:
        log2_n, r, p = p1, p2, p3
        ok = (SCRYPT_MIN_LOG2_N <= log2_n <= SCRYPT_MAX_LOG2_N
              and 1 <= r <= SCRYPT_MAX_R
              and 1 <= p <= SCRYPT_MAX_P
              and 128 * r * (1 << log2_n) <= MAX_KDF_MEMORY_BYTES)
    else:
        raise FileGuardError(f"不支持的密钥派生算法: {kdf_id}")
    if not ok:
        raise FileGuardError("文件头中的密钥派生参数超出安全范围，文件可能已损坏或被恶意构造")


def _derive_key(password: str, kdf_id: int, p1: int, p2: int, p3: int, salt: bytes) -> bytes:
    secret = password.encode("utf-8")
    if kdf_id == KDF_ARGON2ID:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        return Argon2id(salt=salt, length=32, iterations=p2, lanes=p3, memory_cost=p1).derive(secret)
    if kdf_id == KDF_SCRYPT:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        return Scrypt(salt=salt, length=32, n=1 << p1, r=p2, p=p3).derive(secret)
    raise FileGuardError(f"不支持的密钥派生算法: {kdf_id}")


def _nonce(prefix: bytes, index: int) -> bytes:
    if index >= 1 << 32:
        raise FileGuardError("文件过大")
    return prefix + struct.pack(">I", index)


def _aad(header: bytes, index: int, final: bool) -> bytes:
    return header + struct.pack(">QB", index, 1 if final else 0)


def _same_file(a: str, b: str) -> bool:
    if os.path.exists(a) and os.path.exists(b):
        return os.path.samefile(a, b)
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def check_paths(input_path: str, output_path: str) -> None:
    if not os.path.isfile(input_path):
        raise FileGuardError(f"文件不存在: {input_path}")
    if _same_file(input_path, output_path):
        raise FileGuardError("输出文件不能与源文件相同")


def atomic_output(output_path: str):
    """在目标目录创建临时文件, 返回 (文件对象, 临时路径)"""
    directory = os.path.dirname(os.path.abspath(output_path))
    fd, tmp_path = tempfile.mkstemp(prefix=".fileguard-", suffix=".tmp", dir=directory)
    return os.fdopen(fd, "wb"), tmp_path


def finish_atomic(f_out, tmp_path: str, output_path: str, ok: bool) -> None:
    f_out.close()
    if ok:
        os.replace(tmp_path, output_path)
    else:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def read_header(path: str) -> dict | None:
    """读取 V2 文件头, 不是 V2 文件时返回 None"""
    try:
        with open(path, "rb") as f:
            raw = f.read(HEADER_SIZE)
    except OSError:
        return None
    if len(raw) != HEADER_SIZE or not raw.startswith(MAGIC):
        return None
    magic, version, kdf_id, p1, p2, p3, salt, prefix, chunk_size, _ = _HEADER_STRUCT.unpack(raw)
    return {
        "raw": raw, "version": version, "kdf_id": kdf_id,
        "p1": p1, "p2": p2, "p3": p3,
        "salt": salt, "nonce_prefix": prefix, "chunk_size": chunk_size,
    }


def describe_header(info: dict) -> str:
    if info["kdf_id"] == KDF_ARGON2ID:
        kdf = f"Argon2id (内存 {info['p1'] // 1024} MiB, {info['p2']} 轮, {info['p3']} 线程)"
    elif info["kdf_id"] == KDF_SCRYPT:
        kdf = f"scrypt (N=2^{info['p1']}, r={info['p2']}, p={info['p3']})"
    else:
        kdf = f"未知 ({info['kdf_id']})"
    return (f"格式: FileGuard V{info['version']}\n"
            f"加密: AES-256-GCM 分块认证加密 (块大小 {info['chunk_size'] // 1024} KiB)\n"
            f"密钥派生: {kdf}")


def encrypt_file(input_path: str, output_path: str, password: str,
                 progress=None, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
    check_paths(input_path, output_path)
    if not password:
        raise FileGuardError("密码不能为空")

    salt = secrets.token_bytes(16)
    prefix = secrets.token_bytes(8)
    if _argon2_available():
        kdf_id, p1, p2, p3 = KDF_ARGON2ID, ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_LANES
    else:
        kdf_id, p1, p2, p3 = KDF_SCRYPT, SCRYPT_LOG2_N, SCRYPT_R, SCRYPT_P
    header = _HEADER_STRUCT.pack(MAGIC, VERSION, kdf_id, p1, p2, p3, salt, prefix, chunk_size, 0)
    aes = AESGCM(_derive_key(password, kdf_id, p1, p2, p3, salt))

    total = os.path.getsize(input_path)
    done = 0
    f_out, tmp_path = atomic_output(output_path)
    ok = False
    try:
        with open(input_path, "rb") as f_in:
            f_out.write(header)
            index = 0
            current = f_in.read(chunk_size)
            while True:
                following = f_in.read(chunk_size)
                final = not following
                f_out.write(aes.encrypt(_nonce(prefix, index), current, _aad(header, index, final)))
                done += len(current)
                if progress:
                    progress(done, total)
                if final:
                    break
                current = following
                index += 1
        ok = True
    finally:
        finish_atomic(f_out, tmp_path, output_path, ok)


def decrypt_file(input_path: str, output_path: str, password: str, progress=None) -> None:
    check_paths(input_path, output_path)
    info = read_header(input_path)
    if info is None:
        raise FileGuardError("不是 FileGuard V2 加密文件")
    if info["version"] != VERSION:
        raise FileGuardError(f"不支持的文件版本: {info['version']}，请升级 FileGuard")
    chunk_size = info["chunk_size"]
    if not 1024 <= chunk_size <= 64 * 1024 * 1024:
        raise FileGuardError("文件头已损坏")
    check_kdf_params(info["kdf_id"], info["p1"], info["p2"], info["p3"])

    header = info["raw"]
    aes = AESGCM(_derive_key(password, info["kdf_id"], info["p1"], info["p2"], info["p3"], info["salt"]))
    block = chunk_size + TAG_SIZE

    total = os.path.getsize(input_path)
    done = HEADER_SIZE
    f_out, tmp_path = atomic_output(output_path)
    ok = False
    try:
        with open(input_path, "rb") as f_in:
            f_in.seek(HEADER_SIZE)
            index = 0
            current = f_in.read(block)
            while True:
                following = f_in.read(block)
                final = not following
                if len(current) < TAG_SIZE:
                    raise FileGuardError("文件已损坏（数据被截断）")
                try:
                    plain = aes.decrypt(_nonce(info["nonce_prefix"], index), current,
                                        _aad(header, index, final))
                except InvalidTag:
                    if index == 0:
                        raise FileGuardError("密码错误，或文件已被篡改")
                    raise FileGuardError("文件已损坏或被篡改，解密已中止")
                f_out.write(plain)
                done += len(current)
                if progress:
                    progress(done, total)
                if final:
                    break
                current = following
                index += 1
        ok = True
    finally:
        finish_atomic(f_out, tmp_path, output_path, ok)
