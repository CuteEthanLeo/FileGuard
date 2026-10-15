"""
FileGuard - 右键菜单集成模块
在文件右键菜单中添加"FileGuard 加密/解密"选项
写入当前用户注册表 (HKCU)，无需管理员权限
    加密: 所有文件
    解密: 仅 .enc 文件
Windows 11: 在"显示更多选项"中显示
Windows 10: 直接显示在右键菜单
"""

import os
import sys
import winreg

ENCRYPT_KEY = r"Software\Classes\*\shell\FileGuardEncrypt"
DECRYPT_KEY = r"Software\Classes\SystemFileAssociations\.enc\shell\FileGuardDecrypt"
# V1.x 写在 HKEY_CLASSES_ROOT 下的旧菜单
LEGACY_KEYS = [r"*\shell\FileGuardEncrypt", r"*\shell\FileGuardDecrypt"]


def _launch_command() -> tuple[str, str]:
    """返回 (启动命令前缀, 图标路径)"""
    if getattr(sys, 'frozen', False):
        return f'"{sys.executable}"', sys.executable
    script = os.path.abspath(os.path.join(os.path.dirname(__file__), "main.py"))
    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    interpreter = pythonw if os.path.exists(pythonw) else sys.executable
    icon = os.path.join(os.path.dirname(script), "app.ico")
    return f'"{interpreter}" "{script}"', icon


def _delete_tree(root, path: str) -> None:
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_ALL_ACCESS) as key:
            while True:
                try:
                    child = winreg.EnumKey(key, 0)
                except OSError:
                    break
                _delete_tree(root, f"{path}\\{child}")
        winreg.DeleteKey(root, path)
    except FileNotFoundError:
        pass


def _key_exists(root, path: str) -> bool:
    try:
        winreg.OpenKey(root, path).Close()
        return True
    except OSError:
        return False


class ContextMenuManager:
    """右键菜单管理器"""

    def _write_entry(self, path: str, title: str, arg: str) -> None:
        command, icon = _launch_command()
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
            winreg.SetValue(key, "", winreg.REG_SZ, title)
            winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, icon)
            winreg.SetValue(key, "command", winreg.REG_SZ, f'{command} {arg} "%1"')

    def install(self) -> tuple[bool, str]:
        try:
            self._write_entry(ENCRYPT_KEY, "FileGuard 加密", "--encrypt")
            self._write_entry(DECRYPT_KEY, "FileGuard 解密", "--decrypt")
            return True, ("右键菜单安装成功\n\n加密: 右键任意文件\n解密: 右键 .enc 文件\n\n"
                          "Windows 11: 右键文件 → 显示更多选项 → 可看到 FileGuard 菜单")
        except Exception as e:
            return False, f"安装失败: {str(e)}"

    def uninstall(self) -> tuple[bool, str]:
        try:
            _delete_tree(winreg.HKEY_CURRENT_USER, ENCRYPT_KEY)
            _delete_tree(winreg.HKEY_CURRENT_USER, DECRYPT_KEY)
        except Exception as e:
            return False, f"卸载失败: {str(e)}"

        legacy_left = False
        for path in LEGACY_KEYS:
            try:
                _delete_tree(winreg.HKEY_CLASSES_ROOT, path)
            except PermissionError:
                legacy_left = True
            except Exception:
                legacy_left = legacy_left or _key_exists(winreg.HKEY_CLASSES_ROOT, path)

        if legacy_left:
            return True, "右键菜单已卸载\n\n旧版 (V1.x) 安装的菜单需要以管理员身份运行一次 FileGuard 才能删除"
        return True, "右键菜单已卸载"

    def is_installed(self) -> bool:
        return (_key_exists(winreg.HKEY_CURRENT_USER, ENCRYPT_KEY)
                or any(_key_exists(winreg.HKEY_CLASSES_ROOT, p) for p in LEGACY_KEYS))


def main():
    """命令行入口"""
    if len(sys.argv) < 2:
        print("用法:")
        print("  python contextmenu.py install   - 安装右键菜单")
        print("  python contextmenu.py uninstall - 卸载右键菜单")
        sys.exit(1)

    cmd = sys.argv[1]
    manager = ContextMenuManager()

    if cmd == 'install':
        success, msg = manager.install()
    elif cmd == 'uninstall':
        success, msg = manager.uninstall()
    else:
        print(f"未知命令: {cmd}")
        sys.exit(1)

    print(msg)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
