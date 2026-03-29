"""
FileGuard - 右键菜单集成模块
在文件右键菜单中添加"FileGuard 加密/解密"选项
Windows 11: 在"显示更多选项"中显示
Windows 10: 直接显示在右键菜单
"""

import os
import sys
import winreg


class ContextMenuManager:
    """右键菜单管理器"""

    def __init__(self):
        self.app_path = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
        if self.app_path.endswith('.exe'):
            self.app_path = f'"{self.app_path}"'
        else:
            self.app_path = f'python "{self.app_path}"'

    def install(self) -> tuple[bool, str]:
        """
        安装右键菜单
        Windows 10: 直接显示
        Windows 11: 在"显示更多选项"中显示
        """
        try:
            # 加密菜单
            enc_key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, r"*\shell\FileGuardEncrypt")
            winreg.SetValue(enc_key, "", winreg.REG_SZ, "FileGuard 加密")
            winreg.SetValueEx(enc_key, "Icon", 0, winreg.REG_SZ, "app.ico")

            enc_cmd = winreg.CreateKey(enc_key, r"command")
            winreg.SetValue(enc_cmd, "", winreg.REG_SZ, f'{self.app_path} --encrypt "%1"')

            # 解密菜单
            dec_key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, r"*\shell\FileGuardDecrypt")
            winreg.SetValue(dec_key, "", winreg.REG_SZ, "FileGuard 解密")
            winreg.SetValueEx(dec_key, "Icon", 0, winreg.REG_SZ, "app.ico")

            dec_cmd = winreg.CreateKey(dec_key, r"command")
            winreg.SetValue(dec_cmd, "", winreg.REG_SZ, f'{self.app_path} --decrypt "%1"')

            return True, "右键菜单安装成功\n\nWindows 10: 直接显示\nWindows 11: 右键文件 → 显示更多选项 → 可看到 FileGuard 菜单"

        except PermissionError:
            return False, "权限不足，请以管理员身份运行"
        except Exception as e:
            return False, f"安装失败: {str(e)}"

    def uninstall(self) -> tuple[bool, str]:
        """卸载右键菜单"""
        try:
            # 删除加密菜单
            try:
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, r"*\shell\FileGuardEncrypt\command")
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, r"*\shell\FileGuardEncrypt")
            except:
                pass

            # 删除解密菜单
            try:
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, r"*\shell\FileGuardDecrypt\command")
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, r"*\shell\FileGuardDecrypt")
            except:
                pass

            return True, "右键菜单已卸载"

        except PermissionError:
            return False, "权限不足，请以管理员身份运行"
        except Exception as e:
            return False, f"卸载失败: {str(e)}"

    def is_installed(self) -> bool:
        """检查是否已安装"""
        try:
            winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r"*\shell\FileGuardEncrypt")
            return True
        except:
            return False


def main():
    """命令行入口"""
    import sys
    if len(sys.argv) < 2:
        print("用法:")
        print("  python contextmenu.py install   - 安装右键菜单")
        print("  python contextmenu.py uninstall - 卸载右键菜单")
        print("\n安装后:")
        print("  Windows 10: 右键文件直接看到菜单")
        print("  Windows 11: 右键文件 → 显示更多选项 → 看到菜单")
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