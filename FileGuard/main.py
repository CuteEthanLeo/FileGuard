"""
FileGuard - 文件加密工具
黑白风格，简洁现代化界面
加密: Argon2id 密钥派生 + 分块 AES-256-GCM 认证加密 (V2 格式)
解密: 自动识别 V2 格式与 V1.x 旧格式
"""

import sys
import os
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QLineEdit,
                             QFileDialog, QMessageBox, QFrame, QTabWidget,
                             QDialog, QTextEdit, QProgressBar, QInputDialog)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QFileSystemWatcher
from PyQt6.QtGui import QFont, QIcon, QAction

import core
from destory import destory_file
from panic import FileBlocker
from contextmenu import ContextMenuManager
from preview import preview

APP_VERSION = "2.0"
MIN_PASSWORD_LENGTH = 8


def resource_path(name: str) -> str:
    """资源文件路径，兼容 PyInstaller 打包后的临时目录"""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def decrypted_filename(input_path: str) -> str:
    base_name = os.path.basename(input_path)
    if base_name.lower().endswith('.enc'):
        base_name = base_name[:-4]
    name_without_ext, ext = os.path.splitext(base_name)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{name_without_ext}_{timestamp}{ext}"


class WorkerThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str, bool)  # 成功, 消息, 是否旧格式

    def __init__(self, mode, input_file, output_file, password):
        super().__init__()
        self.mode = mode
        self.input_file = input_file
        self.output_file = output_file
        self.password = password

    def on_progress(self, done, total):
        self.progress.emit(int(done * 100 / total) if total else 100)

    def run(self):
        try:
            if self.mode == 'encrypt':
                core.encrypt(self.input_file, self.output_file, self.password, self.on_progress)
                self.finished.emit(True, f"加密成功！\n输出文件: {self.output_file}", False)
            else:
                fmt, is_legacy = core.decrypt(self.input_file, self.output_file, self.password,
                                              self.on_progress)
                self.finished.emit(True, f"解密成功！\n格式: {fmt}\n输出文件: {self.output_file}",
                                   is_legacy)
        except core.FileGuardError as e:
            self.finished.emit(False, str(e), False)
        except PermissionError:
            self.finished.emit(False, "权限不足，无法读写文件", False)
        except Exception as e:
            self.finished.emit(False, f"操作失败: {e}", False)


def make_progress_bar() -> QProgressBar:
    bar = QProgressBar()
    bar.setRange(0, 100)
    bar.setTextVisible(True)
    bar.setVisible(False)
    return bar


def confirm_weak_password(parent, password: str) -> bool:
    if len(password) >= MIN_PASSWORD_LENGTH:
        return True
    reply = QMessageBox.warning(
        parent, "密码较弱",
        f"密码少于 {MIN_PASSWORD_LENGTH} 位，容易被暴力猜解。\n确定继续使用这个密码吗？",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No)
    return reply == QMessageBox.StandardButton.Yes


class EncryptTab(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        algo_desc = QLabel("Argon2id 密钥派生 | AES-256-GCM 分块认证加密 | 防篡改 + 防暴力破解")
        algo_desc.setStyleSheet("color: #40a743; font-size: 10px;")
        layout.addWidget(algo_desc)

        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("源文件:"))
        self.input_file = QLineEdit()
        self.input_file.setPlaceholderText("选择或拖入要加密的文件...")
        input_layout.addWidget(self.input_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(self.select_input)
        input_layout.addWidget(browse_btn)
        layout.addLayout(input_layout)

        output_layout = QHBoxLayout()
        output_layout.addWidget(QLabel("输出文件:"))
        self.output_file = QLineEdit()
        self.output_file.setPlaceholderText("加密后的文件路径...")
        output_layout.addWidget(self.output_file)
        save_btn = QPushButton("保存为")
        save_btn.clicked.connect(self.select_output)
        output_layout.addWidget(save_btn)
        layout.addLayout(output_layout)

        pwd_layout = QHBoxLayout()
        pwd_layout.addWidget(QLabel("密码:"))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText(f"输入加密密码（建议不少于 {MIN_PASSWORD_LENGTH} 位）...")
        pwd_layout.addWidget(self.password)
        layout.addLayout(pwd_layout)

        confirm_layout = QHBoxLayout()
        confirm_layout.addWidget(QLabel("确认密码:"))
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password.setPlaceholderText("再次输入密码...")
        confirm_layout.addWidget(self.confirm_password)
        layout.addLayout(confirm_layout)

        layout.addStretch()

        self.progress_bar = make_progress_bar()
        layout.addWidget(self.progress_bar)

        self.encrypt_btn = QPushButton("开始加密")
        self.encrypt_btn.setMinimumHeight(45)
        self.encrypt_btn.clicked.connect(self.encrypt)
        layout.addWidget(self.encrypt_btn)

        self.setLayout(layout)

    def set_input(self, path):
        self.input_file.setText(path)
        self.output_file.setText(path + ".enc")

    def select_input(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择要加密的文件")
        if path:
            self.set_input(path)

    def select_output(self):
        path, _ = QFileDialog.getSaveFileName(self, "保存加密文件", "", "加密文件 (*.enc)")
        if path:
            self.output_file.setText(path)

    def encrypt(self):
        input_path = self.input_file.text().strip()
        output_path = self.output_file.text().strip()
        password = self.password.text()
        confirm = self.confirm_password.text()

        if not input_path or not os.path.isfile(input_path):
            QMessageBox.critical(self, "错误", "请选择有效的源文件")
            return

        if not output_path:
            QMessageBox.critical(self, "错误", "请指定输出文件路径")
            return

        if not password:
            QMessageBox.critical(self, "错误", "请输入密码")
            return

        if password != confirm:
            QMessageBox.critical(self, "错误", "两次输入的密码不一致")
            return

        if not confirm_weak_password(self, password):
            return

        if os.path.exists(output_path):
            reply = QMessageBox.question(self, "确认", f"文件已存在:\n{output_path}\n是否覆盖？",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply != QMessageBox.StandardButton.Yes:
                return

        self.encrypt_btn.setEnabled(False)
        self.encrypt_btn.setText("加密中...")
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)

        self.worker = WorkerThread('encrypt', input_path, output_path, password)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.on_finished)
        self.worker.start()

    def on_finished(self, success, message, _is_legacy):
        self.encrypt_btn.setEnabled(True)
        self.encrypt_btn.setText("开始加密")
        self.progress_bar.setVisible(False)

        if success:
            QMessageBox.information(self, "成功", message)
            self.input_file.clear()
            self.output_file.clear()
            self.password.clear()
            self.confirm_password.clear()
        else:
            QMessageBox.critical(self, "失败", message)


class DecryptTab(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        self.format_label = QLabel("自动识别加密格式（支持 V2.0 与 V1.x 旧版文件）")
        self.format_label.setStyleSheet("color: #888888; font-size: 10px;")
        layout.addWidget(self.format_label)

        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("加密文件:"))
        self.input_file = QLineEdit()
        self.input_file.setPlaceholderText("选择或拖入要解密的文件...")
        self.input_file.editingFinished.connect(self.on_input_changed)
        input_layout.addWidget(self.input_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(self.select_input)
        input_layout.addWidget(browse_btn)
        layout.addLayout(input_layout)

        output_layout = QHBoxLayout()
        output_layout.addWidget(QLabel("输出目录:"))
        self.output_dir = QLineEdit()
        self.output_dir.setPlaceholderText("选择输出目录...")
        output_layout.addWidget(self.output_dir)
        dir_btn = QPushButton("浏览")
        dir_btn.clicked.connect(self.select_output_dir)
        output_layout.addWidget(dir_btn)
        layout.addLayout(output_layout)

        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("文件名:"))
        self.filename_preview = QLineEdit()
        self.filename_preview.setReadOnly(True)
        self.filename_preview.setPlaceholderText("将自动生成：原文件名_时间戳.扩展名")
        name_layout.addWidget(self.filename_preview)
        layout.addLayout(name_layout)

        pwd_layout = QHBoxLayout()
        pwd_layout.addWidget(QLabel("密码:"))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("输入解密密码...")
        pwd_layout.addWidget(self.password)
        layout.addLayout(pwd_layout)

        layout.addStretch()

        self.progress_bar = make_progress_bar()
        layout.addWidget(self.progress_bar)

        self.decrypt_btn = QPushButton("开始解密")
        self.decrypt_btn.setMinimumHeight(45)
        self.decrypt_btn.clicked.connect(self.decrypt)
        layout.addWidget(self.decrypt_btn)

        self.setLayout(layout)

    def set_input(self, path):
        self.input_file.setText(path)
        if not self.output_dir.text().strip():
            self.output_dir.setText(os.path.dirname(os.path.abspath(path)))
        self.on_input_changed()

    def select_input(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择要解密的文件", "", "加密文件 (*.enc);;所有文件 (*.*)")
        if path:
            self.set_input(path)

    def select_output_dir(self):
        path = QFileDialog.getExistingDirectory(self, "选择输出目录")
        if path:
            self.output_dir.setText(path)
            self.update_filename_preview()

    def on_input_changed(self):
        input_path = self.input_file.text().strip()
        if os.path.isfile(input_path):
            fmt = core.detect_format(input_path).splitlines()[0]
            self.format_label.setText(f"已识别 → {fmt}")
            self.format_label.setStyleSheet("color: #40a743; font-size: 10px;")
        self.update_filename_preview()

    def update_filename_preview(self):
        input_path = self.input_file.text().strip()
        if input_path:
            self.filename_preview.setText(decrypted_filename(input_path))

    def decrypt(self):
        input_path = self.input_file.text().strip()
        output_dir = self.output_dir.text().strip()
        password = self.password.text()

        if not input_path or not os.path.isfile(input_path):
            QMessageBox.critical(self, "错误", "请选择有效的加密文件")
            return

        if not output_dir or not os.path.isdir(output_dir):
            QMessageBox.critical(self, "错误", "请选择有效的输出目录")
            return

        if not password:
            QMessageBox.critical(self, "错误", "请输入密码")
            return

        output_path = os.path.join(output_dir, decrypted_filename(input_path))

        self.decrypt_btn.setEnabled(False)
        self.decrypt_btn.setText("解密中...")
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)

        self.worker = WorkerThread('decrypt', input_path, output_path, password)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.on_decrypt_finished)
        self.worker.start()

    def on_decrypt_finished(self, success, message, is_legacy):
        self.decrypt_btn.setEnabled(True)
        self.decrypt_btn.setText("开始解密")
        self.progress_bar.setVisible(False)

        if success:
            if is_legacy:
                message += ("\n\n⚠️ 该文件使用 V1.x 旧版格式，存在安全缺陷。\n"
                            "建议用 FileGuard 2.0 重新加密解密后的文件，并删除旧的加密文件。")
                QMessageBox.warning(self, "解密成功（旧版格式）", message)
            else:
                QMessageBox.information(self, "成功", message)
            self.input_file.clear()
            self.output_dir.clear()
            self.filename_preview.clear()
            self.password.clear()
            self.format_label.setText("自动识别加密格式（支持 V2.0 与 V1.x 旧版文件）")
            self.format_label.setStyleSheet("color: #888888; font-size: 10px;")
        else:
            QMessageBox.critical(self, "失败", message)


class FileGuardUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.file_blocker = FileBlocker()
        self.context_menu = ContextMenuManager()
        self.init_ui()
        self.apply_style()
        self.setWindowIcon(QIcon(resource_path("app.ico")))
        self.setAcceptDrops(True)

    def init_ui(self):
        self.setWindowTitle(f"FileGuard V{APP_VERSION}")
        self.setGeometry(100, 100, 750, 600)

        menubar = self.menuBar()
        menubar.setStyleSheet("""
            QMenuBar {
                background-color: #2d2d2d;
                color: #ffffff;
                border-bottom: 1px solid #3c3c3c;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 5px 10px;
            }
            QMenuBar::item:selected {
                background-color: #3c3c3c;
            }
            QMenu {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #3c3c3c;
            }
            QMenu::item:selected {
                background-color: #3c3c3c;
            }
        """)

        tools_menu = menubar.addMenu("工具")

        destroy_action = tools_menu.addAction("永久损坏文件")
        destroy_action.triggered.connect(self.destroy_file)

        tools_menu.addSeparator()

        lock_menu = tools_menu.addMenu("文件锁定")
        lock_action = lock_menu.addAction("锁定文件")
        lock_action.triggered.connect(self.lock_file)
        unlock_action = lock_menu.addAction("解锁文件")
        unlock_action.triggered.connect(self.unlock_file)
        unlock_all_action = lock_menu.addAction("解锁所有文件")
        unlock_all_action.triggered.connect(self.unlock_all_files)

        tools_menu.addSeparator()
        preview_action = tools_menu.addAction("文件预览")
        preview_action.triggered.connect(self.open_preview_window)

        settings_menu = menubar.addMenu("设置")
        self.context_menu_action = QAction("右键菜单 (FileGuard 加密/解密)", self)
        self.context_menu_action.setCheckable(True)
        self.context_menu_action.setChecked(self.context_menu.is_installed())
        self.context_menu_action.triggered.connect(self.toggle_context_menu)
        settings_menu.addAction(self.context_menu_action)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("FileGuard")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        layout.addWidget(title)

        subtitle = QLabel(f"V{APP_VERSION} | Argon2id + AES-256-GCM 认证加密 | 拖入文件即可开始")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setFont(QFont("Arial", 10))
        layout.addWidget(subtitle)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)

        self.encrypt_tab = EncryptTab()
        self.decrypt_tab = DecryptTab()
        self.tabs = QTabWidget()
        self.tabs.addTab(self.encrypt_tab, "加密")
        self.tabs.addTab(self.decrypt_tab, "解密")
        layout.addWidget(self.tabs)

        central.setLayout(layout)

    def open_file(self, path, mode=None):
        """把文件填入加密/解密页; mode 为空时按扩展名判断"""
        if mode is None:
            mode = 'decrypt' if path.lower().endswith('.enc') else 'encrypt'
        if mode == 'encrypt':
            self.tabs.setCurrentWidget(self.encrypt_tab)
            self.encrypt_tab.set_input(path)
        else:
            self.tabs.setCurrentWidget(self.decrypt_tab)
            self.decrypt_tab.set_input(path)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.isfile(path):
                self.open_file(path)
                break

    def open_preview_window(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择要预览的文件", "", "所有文件 (*.*)")
        if not file_path:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"预览 - {os.path.basename(file_path)}")
        dialog.setMinimumSize(600, 400)
        dialog.setStyleSheet("background-color: #1e1e1e; color: #ffffff;")

        layout = QVBoxLayout(dialog)

        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Consolas", 10))

        def load_preview():
            try:
                text_edit.setPlainText(preview(file_path))
            except Exception as e:
                text_edit.setPlainText(f"读取失败: {str(e)}")

        load_preview()
        layout.addWidget(text_edit)

        # 文件监听器（自动刷新）
        watcher = QFileSystemWatcher([file_path], dialog)
        watcher.fileChanged.connect(load_preview)

        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("手动刷新")
        refresh_btn.clicked.connect(load_preview)
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(dialog.close)
        btn_layout.addWidget(refresh_btn)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

        status_label = QLabel("✓ 自动监听文件变化，修改后自动刷新")
        status_label.setStyleSheet("color: #888888; font-size: 10px;")
        layout.addWidget(status_label)

        dialog.exec()

    def destroy_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择要永久损坏的文件", "", "所有文件 (*.*)")
        if not file_path:
            return

        reply = QMessageBox.warning(self, "⚠️ 危险操作", f"确定永久损坏 {file_path}？\n\n此操作不可逆！",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return

        success, msg = destory_file(file_path, method='random')
        if success:
            QMessageBox.information(self, "成功", msg)
        else:
            QMessageBox.critical(self, "失败", msg)

    def lock_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择要锁定的文件", "", "所有文件 (*.*)")
        if not file_path:
            return
        if self.file_blocker.is_locked(file_path):
            QMessageBox.warning(self, "提示", "文件已被锁定")
            return
        success, msg = self.file_blocker.lock_file(file_path)
        if success:
            QMessageBox.information(self, "成功", msg + "\n\nFileGuard 运行期间其他程序无法打开该文件，退出时自动解锁")
        else:
            QMessageBox.critical(self, "失败", msg)

    def unlock_file(self):
        locked_files = self.file_blocker.get_locked_files()
        if not locked_files:
            QMessageBox.information(self, "提示", "没有已锁定的文件")
            return
        file_path, ok = QInputDialog.getItem(self, "解锁文件", "选择要解锁的文件:", locked_files, 0, False)
        if ok and file_path:
            success, msg = self.file_blocker.unlock_file(file_path)
            if success:
                QMessageBox.information(self, "成功", msg)
            else:
                QMessageBox.critical(self, "失败", msg)

    def unlock_all_files(self):
        locked_files = self.file_blocker.get_locked_files()
        if not locked_files:
            QMessageBox.information(self, "提示", "没有已锁定的文件")
            return
        reply = QMessageBox.question(self, "确认解锁", f"解锁 {len(locked_files)} 个文件？",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            success, msg = self.file_blocker.unlock_all()
            QMessageBox.information(self, "完成", msg)

    def toggle_context_menu(self):
        if self.context_menu_action.isChecked():
            success, msg = self.context_menu.install()
        else:
            success, msg = self.context_menu.uninstall()
        if success:
            QMessageBox.information(self, "成功", msg)
        else:
            QMessageBox.critical(self, "失败", msg)
        self.context_menu_action.setChecked(self.context_menu.is_installed())

    def closeEvent(self, event):
        self.file_blocker.unlock_all()
        super().closeEvent(event)

    def apply_style(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
            }
            QLabel {
                color: #ffffff;
            }
            QLineEdit {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                padding: 8px;
            }
            QLineEdit:focus {
                border: 1px solid #ffffff;
            }
            QLineEdit:read-only {
                background-color: #252525;
                color: #888888;
            }
            QPushButton {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3c3c3c;
                border: 1px solid #ffffff;
            }
            QPushButton:disabled {
                color: #777777;
            }
            QProgressBar {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                text-align: center;
                height: 18px;
            }
            QProgressBar::chunk {
                background-color: #40a743;
                border-radius: 3px;
            }
            QTabWidget::pane {
                background-color: #1e1e1e;
                border: 1px solid #3c3c3c;
            }
            QTabBar::tab {
                background-color: #2d2d2d;
                color: #ffffff;
                padding: 8px 20px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #3c3c3c;
            }
            QTabBar::tab:hover {
                background-color: #3c3c3c;
            }
        """)


def main():
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(resource_path("app.ico")))
    window = FileGuardUI()
    window.show()

    if len(sys.argv) > 2 and sys.argv[1] in ('--encrypt', '--decrypt'):
        window.open_file(sys.argv[2], 'encrypt' if sys.argv[1] == '--encrypt' else 'decrypt')

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
