"""
FileGuard - 文件加密工具
黑白风格，简洁现代化界面
支持两种加密算法：经典版 (AES-256-CFB) 和 高级版 (AES-256-GCM)
"""

import sys
import os
import math
import random
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QLineEdit,
                             QFileDialog, QMessageBox, QFrame, QTabWidget,
                             QComboBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QRect
from PyQt6.QtGui import QFont, QPainter, QColor, QPen, QBrush,QIcon

from lock1 import FileLocker as FileLockerV1
from lock2 import FileLockerV2


class HumanVerification(QWidget):
    """拼图滑块验证组件 - 参考GitHub开源方案"""
    verified = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        self.dragging = False
        self.drag_pos = 10
        self.verified_flag = False
        self.slider_width = 50
        self.drag_start = 0
        self.start_time = 0
        self.gap_position = random.randint(150, 250)
        self.init_ui()

    def init_ui(self):
        self.setFixedHeight(100)
        self.setMinimumWidth(400)
        self.setMouseTracking(True)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        width = self.width()
        height = self.height()

        # 背景轨道
        track_rect = QRect(10, 40, width - 20, 40)
        painter.fillRect(track_rect, QBrush(QColor(45, 45, 45)))
        painter.setPen(QPen(QColor(60, 60, 60), 1))
        painter.drawRect(track_rect)

        # 绘制缺口
        if not self.verified_flag:
            gap_rect = QRect(self.gap_position, 40, 50, 40)
            painter.fillRect(gap_rect, QBrush(QColor(80, 80, 80, 100)))
            painter.setPen(QPen(QColor(100, 100, 100), 1))
            painter.drawRect(gap_rect)
            painter.drawText(gap_rect, Qt.AlignmentFlag.AlignCenter, "缺口")

        # 绘制滑块
        if not self.verified_flag:
            slider_x = int(self.drag_pos)
            if slider_x < 10:
                slider_x = 10
            if slider_x > width - self.slider_width - 10:
                slider_x = width - self.slider_width - 10

            slider_rect = QRect(slider_x, 40, self.slider_width, 40)
            painter.fillRect(slider_rect, QBrush(QColor(80, 80, 80)))
            painter.setPen(QPen(QColor(200, 200, 200)))
            painter.drawText(slider_rect, Qt.AlignmentFlag.AlignCenter, "▶")

        # 验证成功
        if self.verified_flag:
            success_rect = QRect(10, 40, width - 20, 40)
            painter.fillRect(success_rect, QBrush(QColor(40, 167, 69)))
            painter.setPen(QPen(QColor(255, 255, 255)))
            painter.drawText(success_rect, Qt.AlignmentFlag.AlignCenter, "✓ 验证通过")

        # 提示文字
        painter.setPen(QPen(QColor(150, 150, 150)))
        painter.setFont(QFont("Arial", 9))
        painter.drawText(10, 30, "→ 按住滑块拖动到右侧缺口位置")

    def mousePressEvent(self, event):
        if self.verified_flag:
            return
        x = int(event.position().x())
        y = int(event.position().y())
        slider_x = int(self.drag_pos)
        if slider_x < 10:
            slider_x = 10
        if 10 <= x <= slider_x + self.slider_width and 40 <= y <= 80:
            self.dragging = True
            self.drag_start = x
            self.start_time = event.timestamp()

    def mouseMoveEvent(self, event):
        if not self.dragging or self.verified_flag:
            return
        x = int(event.position().x())
        delta = x - self.drag_start
        self.drag_pos = max(10, min(self.width() - self.slider_width - 10, 10 + delta))

        # 检查是否到达缺口位置
        if abs(self.drag_pos - self.gap_position) <= 8:
            self.verified_flag = True
            self.dragging = False
            self.verified.emit(True)
        self.update()

    def mouseReleaseEvent(self, event):
        if not self.verified_flag:
            self.dragging = False
            self.drag_pos = 10
            self.update()

    def reset(self):
        self.dragging = False
        self.drag_pos = 10
        self.verified_flag = False
        self.gap_position = random.randint(150, self.width() - 80)
        self.update()


class WorkerThread(QThread):
    finished = pyqtSignal(bool, str)
    verify_result = pyqtSignal(bool, str)

    def __init__(self, locker, mode, input_file, output_file, password, verify_only=False):
        super().__init__()
        self.locker = locker
        self.mode = mode
        self.input_file = input_file
        self.output_file = output_file
        self.password = password
        self.verify_only = verify_only

    def run(self):
        if self.verify_only:
            success, msg = self.locker.verify_password(self.input_file, self.password)
            self.verify_result.emit(success, msg)
        elif self.mode == 'encrypt':
            success, msg = self.locker.encrypt_file(self.input_file, self.output_file, self.password)
            self.finished.emit(success, msg)
        else:
            success, msg = self.locker.decrypt_file(self.input_file, self.output_file, self.password)
            self.finished.emit(success, msg)


class CaptchaDialog(QWidget):
    """验证码弹窗 - 拼图滑块验证"""
    verified = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("安全验证")
        self.setFixedSize(400, 320)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        self.setStyleSheet("background-color: #1e1e1e; border: 1px solid #3c3c3c; border-radius: 12px;")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(25, 25, 25, 25)

        # 标题
        title = QLabel("🔐 安全验证")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #ffffff;")
        layout.addWidget(title)

        # 说明
        desc = QLabel("请完成拼图验证，证明您是真实用户")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setStyleSheet("color: #888888; font-size: 12px;")
        layout.addWidget(desc)

        layout.addSpacing(10)

        # 滑块验证区域
        slider_group = QWidget()
        slider_group.setStyleSheet("background-color: #2a2a2a; border-radius: 8px;")
        slider_layout = QVBoxLayout()
        slider_layout.setSpacing(10)

        slider_title = QLabel("拼图验证")
        slider_title.setStyleSheet("color: #ffffff; font-weight: bold;")
        slider_layout.addWidget(slider_title)

        self.slider = HumanVerification()
        slider_layout.addWidget(self.slider)

        slider_group.setLayout(slider_layout)
        layout.addWidget(slider_group)

        layout.addSpacing(10)

        # 按钮区域
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)

        self.confirm_btn = QPushButton("✓ 验证")
        self.confirm_btn.setMinimumHeight(42)
        self.confirm_btn.clicked.connect(self.verify)
        self.confirm_btn.setStyleSheet("""
            QPushButton {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #3c3c3c;
                border-radius: 8px;
                padding: 10px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #3c3c3c;
                border: 1px solid #ffffff;
            }
        """)
        btn_layout.addWidget(self.confirm_btn)

        self.cancel_btn = QPushButton("✗ 取消")
        self.cancel_btn.setMinimumHeight(42)
        self.cancel_btn.clicked.connect(self.reject)
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #3c3c3c;
                border-radius: 8px;
                padding: 10px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #3c3c3c;
                border: 1px solid #ffffff;
            }
        """)
        btn_layout.addWidget(self.cancel_btn)

        layout.addLayout(btn_layout)

        # 错误提示
        self.error_label = QLabel("")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.error_label.setStyleSheet("color: #ff6b6b; font-size: 11px;")
        self.error_label.setVisible(False)
        layout.addWidget(self.error_label)

        self.setLayout(layout)

        self.slider.verified.connect(self.on_slider_verified)
        self.slider_ok = False

    def on_slider_verified(self, ok):
        self.slider_ok = ok
        if ok:
            self.verify()

    def verify(self):
        if self.slider_ok:
            self.verified.emit(True)
            self.close()
        else:
            self.error_label.setText("❌ 请完成拼图验证")
            self.error_label.setVisible(True)
            QTimer.singleShot(2000, lambda: self.error_label.setVisible(False))

    def reject(self):
        self.verified.emit(False)
        self.close()

    def reset(self):
        self.slider.reset()
        self.slider_ok = False
        self.error_label.setVisible(False)
    def reject(self):
        self.verified.emit(False)
        self.close()

    def reset(self):
        self.num1 = random.randint(10, 99)
        self.num2 = random.randint(10, 99)
        self.question.setText(f"{self.num1} + {self.num2} = ?")
        self.answer_input.clear()
        self.slider.reset()
        self.slider_ok = False
        self.error_label.setVisible(False)


class EncryptTab(QWidget):
    def __init__(self, locker_v1, locker_v2):
        super().__init__()
        self.locker_v1 = locker_v1
        self.locker_v2 = locker_v2
        self.current_locker = self.locker_v2  # 默认用高级版
        self.worker = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # 加密算法选择
        algo_layout = QHBoxLayout()
        algo_layout.addWidget(QLabel("加密算法:"))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["AES-256-GCM 认证加密 (高级版 - 防篡改抗暴力破解)", "AES-256-CFB 流加密 (经典版 - 兼容旧文件)"])
        self.algo_combo.setStyleSheet("""
            QComboBox {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                padding: 5px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background-color: #2d2d2d;
                color: #ffffff;
                selection-background-color: #3c3c3c;
            }
        """)
        self.algo_combo.currentIndexChanged.connect(self.on_algo_changed)
        algo_layout.addWidget(self.algo_combo)
        algo_layout.addStretch()
        layout.addLayout(algo_layout)

        # 算法说明
        self.algo_desc = QLabel("GCM模式自带认证，防篡改，推荐使用")
        self.algo_desc.setStyleSheet("color: #888888; font-size: 10px;")
        layout.addWidget(self.algo_desc)

        # 输入文件
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("源文件:"))
        self.input_file = QLineEdit()
        self.input_file.setPlaceholderText("选择要加密的文件...")
        input_layout.addWidget(self.input_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(self.select_input)
        input_layout.addWidget(browse_btn)
        layout.addLayout(input_layout)

        # 输出文件
        output_layout = QHBoxLayout()
        output_layout.addWidget(QLabel("输出文件:"))
        self.output_file = QLineEdit()
        self.output_file.setPlaceholderText("加密后的文件路径...")
        output_layout.addWidget(self.output_file)
        save_btn = QPushButton("保存为")
        save_btn.clicked.connect(self.select_output)
        output_layout.addWidget(save_btn)
        layout.addLayout(output_layout)

        # 密码
        pwd_layout = QHBoxLayout()
        pwd_layout.addWidget(QLabel("密码:"))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("输入加密密码...")
        pwd_layout.addWidget(self.password)
        layout.addLayout(pwd_layout)

        # 确认密码
        confirm_layout = QHBoxLayout()
        confirm_layout.addWidget(QLabel("确认密码:"))
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password.setPlaceholderText("再次输入密码...")
        confirm_layout.addWidget(self.confirm_password)
        layout.addLayout(confirm_layout)

        layout.addStretch()

        # 加密按钮
        self.encrypt_btn = QPushButton("开始加密")
        self.encrypt_btn.setMinimumHeight(45)
        self.encrypt_btn.clicked.connect(self.show_captcha_and_encrypt)
        layout.addWidget(self.encrypt_btn)

        self.setLayout(layout)

    def on_algo_changed(self, index):
        if index == 0:
            self.current_locker = self.locker_v2
            self.algo_desc.setText(
                "AES-256-GCM | 认证加密模式 | 防篡改 + 防暴力破解 (PBKDF2 100000次迭代) | 企业级安全")
            self.algo_desc.setStyleSheet("color: #40a743; font-size: 10px;")
        else:
            self.current_locker = self.locker_v1
            self.algo_desc.setText("AES-256-CFB | 流加密模式 | 基础安全 ")
            self.algo_desc.setStyleSheet("color: #888888; font-size: 10px;")
    def select_input(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择要加密的文件")
        if path:
            self.input_file.setText(path)
            if not self.output_file.text():
                self.output_file.setText(path + ".enc")

    def select_output(self):
        path, _ = QFileDialog.getSaveFileName(self, "保存加密文件", "", "加密文件 (*.enc)")
        if path:
            self.output_file.setText(path)

    def show_captcha_and_encrypt(self):
        captcha = CaptchaDialog(self.window())
        captcha.verified.connect(lambda ok: self.encrypt() if ok else None)
        captcha.show()

    def encrypt(self):
        input_path = self.input_file.text().strip()
        output_path = self.output_file.text().strip()
        password = self.password.text()
        confirm = self.confirm_password.text()

        if not input_path or not os.path.exists(input_path):
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

        if os.path.exists(output_path):
            reply = QMessageBox.question(self, "确认", f"文件已存在:\n{output_path}\n是否覆盖？",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply != QMessageBox.StandardButton.Yes:
                return

        self.encrypt_btn.setEnabled(False)
        self.encrypt_btn.setText("加密中...")

        self.worker = WorkerThread(self.current_locker, 'encrypt', input_path, output_path, password)
        self.worker.finished.connect(self.on_finished)
        self.worker.start()

    def on_finished(self, success, message):
        self.encrypt_btn.setEnabled(True)
        self.encrypt_btn.setText("开始加密")

        if success:
            QMessageBox.information(self, "成功", message)
            self.input_file.clear()
            self.output_file.clear()
            self.password.clear()
            self.confirm_password.clear()
        else:
            QMessageBox.critical(self, "失败", message)


class DecryptTab(QWidget):
    def __init__(self, locker_v1, locker_v2):
        super().__init__()
        self.locker_v1 = locker_v1
        self.locker_v2 = locker_v2
        self.current_locker = self.locker_v2  # 默认用高级版
        self.worker = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # 解密算法选择
        algo_layout = QHBoxLayout()
        algo_layout.addWidget(QLabel("解密算法:"))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems( ["AES-256-GCM 认证加密 (高级版 - 防篡改抗暴力破解)", "AES-256-CFB 流加密 (经典版 - 兼容旧文件)"])
        self.algo_combo.setStyleSheet("""
            QComboBox {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                padding: 5px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background-color: #2d2d2d;
                color: #ffffff;
                selection-background-color: #3c3c3c;
            }
        """)
        self.algo_combo.currentIndexChanged.connect(self.on_algo_changed)
        algo_layout.addWidget(self.algo_combo)
        algo_layout.addStretch()
        layout.addLayout(algo_layout)

        # 算法说明
        self.algo_desc = QLabel("GCM模式自带认证，防篡改，推荐用于新文件")
        self.algo_desc.setStyleSheet("color: #888888; font-size: 10px;")
        layout.addWidget(self.algo_desc)

        # 加密文件
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("加密文件:"))
        self.input_file = QLineEdit()
        self.input_file.setPlaceholderText("选择要解密的文件...")
        input_layout.addWidget(self.input_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(self.select_input)
        input_layout.addWidget(browse_btn)
        layout.addLayout(input_layout)

        # 输出目录
        output_layout = QHBoxLayout()
        output_layout.addWidget(QLabel("输出目录:"))
        self.output_dir = QLineEdit()
        self.output_dir.setPlaceholderText("选择输出目录...")
        output_layout.addWidget(self.output_dir)
        dir_btn = QPushButton("浏览")
        dir_btn.clicked.connect(self.select_output_dir)
        output_layout.addWidget(dir_btn)
        layout.addLayout(output_layout)

        # 显示生成的文件名
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("文件名:"))
        self.filename_preview = QLineEdit()
        self.filename_preview.setReadOnly(True)
        self.filename_preview.setPlaceholderText("将自动生成：原文件名_时间戳.扩展名")
        name_layout.addWidget(self.filename_preview)
        layout.addLayout(name_layout)

        # 密码
        pwd_layout = QHBoxLayout()
        pwd_layout.addWidget(QLabel("密码:"))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("输入解密密码...")
        pwd_layout.addWidget(self.password)
        layout.addLayout(pwd_layout)

        layout.addStretch()

        # 解密按钮
        self.decrypt_btn = QPushButton("开始解密")
        self.decrypt_btn.setMinimumHeight(45)
        self.decrypt_btn.clicked.connect(self.show_captcha_and_decrypt)
        layout.addWidget(self.decrypt_btn)

        self.setLayout(layout)

    def on_algo_changed(self, index):
        if index == 0:
            self.current_locker = self.locker_v2
            self.algo_desc.setText("GCM模式自带认证，防篡改，推荐用于新加密的文件")
            self.algo_desc.setStyleSheet("color: #40a743; font-size: 10px;")
        else:
            self.current_locker = self.locker_v1
            self.algo_desc.setText("CFB模式，经典稳定，用于旧版加密的文件")
            self.algo_desc.setStyleSheet("color: #888888; font-size: 10px;")

    def select_input(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择要解密的文件", "", "加密文件 (*.enc);;所有文件 (*.*)")
        if path:
            self.input_file.setText(path)
            self.update_filename_preview()

    def select_output_dir(self):
        path = QFileDialog.getExistingDirectory(self, "选择输出目录")
        if path:
            self.output_dir.setText(path)
            self.update_filename_preview()

    def update_filename_preview(self):
        input_path = self.input_file.text().strip()
        if input_path:
            base_name = os.path.basename(input_path)
            if base_name.endswith('.enc'):
                base_name = base_name[:-4]

            name_without_ext, ext = os.path.splitext(base_name)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            preview_name = f"{name_without_ext}_{timestamp}{ext}"
            self.filename_preview.setText(preview_name)

    def show_captcha_and_decrypt(self):
        captcha = CaptchaDialog(self.window())
        captcha.verified.connect(lambda ok: self.decrypt() if ok else None)
        captcha.show()

    def decrypt(self):
        input_path = self.input_file.text().strip()
        output_dir = self.output_dir.text().strip()
        password = self.password.text()

        if not input_path or not os.path.exists(input_path):
            QMessageBox.critical(self, "错误", "请选择有效的加密文件")
            return

        if not output_dir or not os.path.exists(output_dir):
            QMessageBox.critical(self, "错误", "请选择有效的输出目录")
            return

        if not password:
            QMessageBox.critical(self, "错误", "请输入密码")
            return

        base_name = os.path.basename(input_path)
        if base_name.endswith('.enc'):
            base_name = base_name[:-4]

        name_without_ext, ext = os.path.splitext(base_name)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"{name_without_ext}_{timestamp}{ext}"
        output_path = os.path.join(output_dir, output_filename)

        self.decrypt_btn.setEnabled(False)
        self.decrypt_btn.setText("验证密码中...")

        # 使用用户选择的算法验证密码
        self.worker = WorkerThread(self.current_locker, '', input_path, '', password, verify_only=True)
        self.worker.verify_result.connect(lambda success, msg: self.on_verify_finished(success, msg, output_path))
        self.worker.start()

    def on_verify_finished(self, success, msg, output_path):
        if not success:
            self.decrypt_btn.setEnabled(True)
            self.decrypt_btn.setText("开始解密")
            QMessageBox.critical(self, "密码错误", f"密码不正确，无法解密\n\n提示：请确认选择了正确的解密算法")
            return

        self.decrypt_btn.setText("解密中...")
        self.worker = WorkerThread(self.current_locker, 'decrypt', self.input_file.text().strip(), output_path, self.password.text())
        self.worker.finished.connect(self.on_decrypt_finished)
        self.worker.start()

    def on_decrypt_finished(self, success, message):
        self.decrypt_btn.setEnabled(True)
        self.decrypt_btn.setText("开始解密")

        if success:
            QMessageBox.information(self, "成功", f"解密成功！\n{message}")
            self.input_file.clear()
            self.output_dir.clear()
            self.filename_preview.clear()
            self.password.clear()
        else:
            QMessageBox.critical(self, "失败", message)
class FileGuardUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.locker_v1 = FileLockerV1()
        self.locker_v2 = FileLockerV2()
        self.init_ui()
        self.apply_style()
        self.setWindowIcon(QIcon("app.ico"))  # 添加这一行

    def init_ui(self):
        self.setWindowTitle("FileGuard")
        self.setGeometry(100, 100, 750, 600)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("FileGuard")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        layout.addWidget(title)

        subtitle = QLabel("基于 Argon2id + AES-256-GCM 的高级文件加密工具 | 企业级安全验证")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setFont(QFont("Arial", 10))
        layout.addWidget(subtitle)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)

        tabs = QTabWidget()
        tabs.addTab(EncryptTab(self.locker_v1, self.locker_v2), "加密")
        tabs.addTab(DecryptTab(self.locker_v1, self.locker_v2), "解密")
        layout.addWidget(tabs)

        central.setLayout(layout)

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
    window = FileGuardUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()