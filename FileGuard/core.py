"""
FileGuard - 加解密统一入口
加密一律使用 V2 格式; 解密自动识别 V2 / V1.x 旧格式
"""

import crypto_v2
import legacy
from crypto_v2 import FileGuardError

FORMAT_V2 = "FileGuard V2 (Argon2id + AES-256-GCM)"


def encrypt(input_path: str, output_path: str, password: str, progress=None) -> None:
    crypto_v2.encrypt_file(input_path, output_path, password, progress)


def decrypt(input_path: str, output_path: str, password: str, progress=None) -> tuple[str, bool]:
    """解密文件, 返回 (格式名称, 是否为旧版不安全格式)"""
    if crypto_v2.read_header(input_path) is not None:
        crypto_v2.decrypt_file(input_path, output_path, password, progress)
        return FORMAT_V2, False
    return legacy.decrypt_legacy(input_path, output_path, password, progress), True


def detect_format(path: str) -> str:
    info = crypto_v2.read_header(path)
    if info is not None:
        return crypto_v2.describe_header(info)
    return "格式: FileGuard V1.x 旧版格式（或非 FileGuard 文件）\n建议解密后用 V2.0 重新加密"


__all__ = ["encrypt", "decrypt", "detect_format", "FileGuardError", "FORMAT_V2"]
