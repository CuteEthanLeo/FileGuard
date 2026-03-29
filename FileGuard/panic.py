"""
FileGuard - 文件锁定模块
强制锁定文件，防止被其他程序（包括安全软件）解锁
"""

import os
import ctypes
import ctypes.wintypes


class FileBlocker:
    """强制文件锁定管理器"""

    def __init__(self):
        self.locked_files = {}

    def lock_file(self, file_path: str) -> tuple[bool, str]:
        """
        强制锁定文件（只用一个句柄，不自己锁自己）
        """
        try:
            if not os.path.exists(file_path):
                return False, f"文件不存在: {file_path}"

            if os.path.isdir(file_path):
                return False, "不支持锁定目录"

            if file_path in self.locked_files:
                return False, "文件已被 FileGuard 锁定"

            # 只用 CreateFile 独占访问，不再用 Python open
            GENERIC_READ = 0x80000000
            GENERIC_WRITE = 0x40000000
            OPEN_EXISTING = 3

            handle = ctypes.windll.kernel32.CreateFileW(
                file_path,
                GENERIC_READ | GENERIC_WRITE,
                0,  # 禁止任何共享 - 独占锁
                None,
                OPEN_EXISTING,
                0,
                None
            )

            if handle == -1 or handle == 0:
                error_code = ctypes.GetLastError()
                if error_code == 5:
                    return False, "权限不足，请以管理员身份运行"
                elif error_code == 32:
                    return False, "文件被其他程序占用"
                else:
                    return False, f"锁定失败，错误码: {error_code}"

            # 只存储句柄，不再额外 open 或 mmap
            self.locked_files[file_path] = handle

            return True, f"文件已强制锁定: {os.path.basename(file_path)}"

        except Exception as e:
            return False, f"锁定失败: {str(e)}"

    def unlock_file(self, file_path: str) -> tuple[bool, str]:
        """解锁文件"""
        try:
            if file_path not in self.locked_files:
                return False, "文件未被 FileGuard 锁定"

            handle = self.locked_files[file_path]
            ctypes.windll.kernel32.CloseHandle(handle)

            del self.locked_files[file_path]
            return True, f"文件已解锁: {os.path.basename(file_path)}"

        except Exception as e:
            return False, f"解锁失败: {str(e)}"

    def unlock_all(self) -> tuple[bool, str]:
        """解锁所有文件"""
        count = 0
        for file_path in list(self.locked_files.keys()):
            success, _ = self.unlock_file(file_path)
            if success:
                count += 1
        return count > 0, f"已解锁 {count} 个文件"

    def is_locked(self, file_path: str) -> bool:
        return file_path in self.locked_files

    def get_locked_files(self) -> list:
        return list(self.locked_files.keys())