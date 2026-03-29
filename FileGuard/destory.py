"""
FileGuard - 文件永久损坏工具
警告：此工具会永久损坏指定文件，无法恢复！请谨慎使用！
"""

import os


def destory_file(file_path: str, method: str = 'random') -> tuple[bool, str]:
    """
    永久损坏文件（只覆盖不删除，支持任何文件类型）

    Args:
        file_path: 要损坏的文件路径
        method: 损坏方法
            - 'random': 随机覆盖3次（默认，推荐）
            - 'quick': 快速损坏（只覆盖一次）

    Returns:
        (是否成功, 消息)
    """
    if not os.path.exists(file_path):
        return False, f"文件不存在: {file_path}"

    if os.path.isdir(file_path):
        return False, "不支持目录，请指定文件"

    try:
        original_size = os.path.getsize(file_path)
        original_name = os.path.basename(file_path)

        passes = 3 if method == 'random' else 1

        with open(file_path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(original_size))
                f.flush()
                os.fsync(f.fileno())

        return True, f"文件已永久损坏\n文件: {original_name}\n大小: {original_size} 字节\n内容已被随机数据覆盖，无法恢复"

    except PermissionError:
        return False, "权限不足，无法操作文件"
    except Exception as e:
        return False, f"损坏失败: {str(e)}"


def main():
    """命令行入口 - 仅供独立运行时使用"""
    import sys
    if len(sys.argv) < 2:
        print("用法: python destory.py <文件路径>")
        sys.exit(1)

    file_path = sys.argv[1]
    method = sys.argv[2] if len(sys.argv) > 2 else 'random'

    print(f"正在损坏文件: {file_path}")
    success, msg = destory_file(file_path, method)

    if success:
        print(f"成功: {msg}")
    else:
        print(f"失败: {msg}")
        sys.exit(1)


if __name__ == "__main__":
    main()