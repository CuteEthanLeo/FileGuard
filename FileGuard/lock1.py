"""
FileGuard - 文件加密核心模块
使用 SHA256 派生密钥，AES 加密
AICODE+自己修BUG 适用于WINDOWS
"""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class FileLocker:
    """文件加密/解密核心类"""

    def __init__(self):
        self.block_size = 4096  # 分块读取大小

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """使用 SHA256 派生密钥"""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,  # 迭代次数
            dklen=32  # AES-256 需要32字节密钥
        )

    def encrypt_file(self, input_path: str, output_path: str, password: str) -> tuple[bool, str]:
        """
        加密文件
        返回: (成功标志, 消息)
        """
        try:
            # 检查输入文件是否存在
            if not os.path.exists(input_path):
                return False, f"文件不存在: {input_path}"

            # 生成随机盐值（16字节）
            salt = os.urandom(16)
            # 生成随机IV（16字节）
            iv = os.urandom(16)

            # 派生密钥
            key = self._derive_key(password, salt)

            # 创建加密器
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            # 读取原始文件内容
            with open(input_path, 'rb') as f_in:
                original_data = f_in.read()

            # 计算原始数据的哈希（用于密码验证）
            data_hash = hashlib.sha256(original_data).digest()

            # 加密数据
            encrypted_data = encryptor.update(original_data) + encryptor.finalize()

            # 写入文件：salt + iv + 加密数据 + 哈希
            with open(output_path, 'wb') as f_out:
                f_out.write(salt)
                f_out.write(iv)
                f_out.write(encrypted_data)
                f_out.write(data_hash)  # 存储哈希用于验证

            return True, f"加密成功！\n输出文件: {output_path}"

        except Exception as e:
            return False, f"加密失败: {str(e)}"

    def decrypt_file(self, input_path: str, output_path: str, password: str) -> tuple[bool, str]:
        """
        解密文件
        返回: (成功标志, 消息)
        """
        try:
            # 检查输入文件是否存在
            if not os.path.exists(input_path):
                return False, f"文件不存在: {input_path}"

            # 读取文件头：盐值(16) + IV(16)
            with open(input_path, 'rb') as f_in:
                salt = f_in.read(16)
                if len(salt) != 16:
                    return False, "无效的加密文件格式"

                iv = f_in.read(16)
                if len(iv) != 16:
                    return False, "无效的加密文件格式"

                # 读取文件末尾的哈希（最后32字节）
                f_in.seek(-32, os.SEEK_END)
                stored_hash = f_in.read(32)

                # 回到文件内容开始位置
                f_in.seek(32, os.SEEK_SET)  # 跳过 salt(16) + iv(16)

                # 读取加密数据（不包括最后的哈希）
                encrypted_data = f_in.read()
                encrypted_data = encrypted_data[:-32]  # 移除哈希部分

                # 派生密钥
                key = self._derive_key(password, salt)

                # 创建解密器
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()

                # 解密数据
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

                # 验证哈希
                computed_hash = hashlib.sha256(decrypted_data).digest()
                if computed_hash != stored_hash:
                    return False, "密码错误或文件已损坏"

                # 写入输出文件
                with open(output_path, 'wb') as f_out:
                    f_out.write(decrypted_data)

            return True, f"解密成功！\n输出文件: {output_path}"

        except Exception as e:
            return False, f"解密失败: {str(e)}"

    def verify_password(self, encrypted_file: str, password: str) -> tuple[bool, str]:
        """
        验证密码是否正确
        返回: (是否成功, 消息)
        """
        try:
            # 读取文件头
            with open(encrypted_file, 'rb') as f:
                salt = f.read(16)
                iv = f.read(16)

                # 读取文件末尾的哈希（最后32字节）
                f.seek(-32, os.SEEK_END)
                stored_hash = f.read(32)

                # 回到文件内容开始位置
                f.seek(32, os.SEEK_SET)  # 跳过 salt(16) + iv(16)

                # 读取加密数据（不包括最后的哈希）
                encrypted_data = f.read()
                encrypted_data = encrypted_data[:-32]  # 移除哈希部分

                # 派生密钥
                key = self._derive_key(password, salt)

                # 创建解密器
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()

                # 解密数据
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

                # 验证哈希
                computed_hash = hashlib.sha256(decrypted_data).digest()

                if computed_hash == stored_hash:
                    return True, "密码验证通过"
                else:
                    return False, "密码错误"

        except Exception:
            return False, "密码错误或文件已损坏"