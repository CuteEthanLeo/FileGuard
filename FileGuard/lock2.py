"""
FileGuard - 高级文件加密核心模块
使用 AES-256-GCM 认证加密
"""

import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class FileLockerV2:
    """AES-256-GCM 文件加密/解密核心类"""

    def __init__(self):
        self.block_size = 64 * 1024

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """密钥派生 - 用于 AES 加密"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def _derive_verifier(self, password: str, salt: bytes) -> bytes:
        """验证哈希派生 - 用于密码验证，同样使用 PBKDF2 防止暴力破解"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # 和密钥派生相同强度
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def encrypt_file(self, input_path: str, output_path: str, password: str) -> tuple[bool, str]:
        """
        AES-256-GCM 加密文件
        格式: [salt(16)][nonce(12)][ciphertext][tag(16)][verifier(32)]
        """
        try:
            if not os.path.exists(input_path):
                return False, f"文件不存在: {input_path}"

            salt = secrets.token_bytes(16)
            nonce = secrets.token_bytes(12)
            key = self._derive_key(password, salt)
            verifier = self._derive_verifier(password, salt)

            with open(input_path, 'rb') as f_in:
                plaintext = f_in.read()

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            tag = encryptor.tag

            with open(output_path, 'wb') as f_out:
                f_out.write(salt)
                f_out.write(nonce)
                f_out.write(ciphertext)
                f_out.write(tag)
                f_out.write(verifier)

            return True, f"加密成功！\n输出文件: {output_path}"

        except Exception as e:
            return False, f"加密失败: {str(e)}"

    def decrypt_file(self, input_path: str, output_path: str, password: str) -> tuple[bool, str]:
        """
        AES-256-GCM 解密文件
        """
        try:
            if not os.path.exists(input_path):
                return False, f"文件不存在: {input_path}"

            with open(input_path, 'rb') as f_in:
                salt = f_in.read(16)
                if len(salt) != 16:
                    return False, "无效的加密文件格式"

                nonce = f_in.read(12)
                if len(nonce) != 12:
                    return False, "无效的加密文件格式"

                remaining = f_in.read()
                if len(remaining) < 48:
                    return False, "无效的加密文件格式"

                tag = remaining[-48:-32]
                stored_verifier = remaining[-32:]
                ciphertext = remaining[:-48]

                # 验证密码 - 使用 PBKDF2 派生对比
                expected_verifier = self._derive_verifier(password, salt)
                if stored_verifier != expected_verifier:
                    return False, "密码错误"

                key = self._derive_key(password, salt)

                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
                decryptor = cipher.decryptor()

                plaintext = decryptor.update(ciphertext) + decryptor.finalize()

                with open(output_path, 'wb') as f_out:
                    f_out.write(plaintext)

            return True, f"解密成功！\n输出文件: {output_path}"

        except Exception as e:
            return False, f"解密失败: {str(e)}"

    def verify_password(self, encrypted_file: str, password: str) -> tuple[bool, str]:
        """验证密码是否正确 - 使用 PBKDF2 派生验证"""
        try:
            with open(encrypted_file, 'rb') as f:
                salt = f.read(16)
                if len(salt) != 16:
                    return False, "无效的加密文件格式"

                f.seek(-32, os.SEEK_END)
                stored_verifier = f.read(32)

                expected_verifier = self._derive_verifier(password, salt)

                if stored_verifier == expected_verifier:
                    return True, "密码验证通过"
                else:
                    return False, "密码错误"

        except Exception:
            return False, "密码错误或文件已损坏"