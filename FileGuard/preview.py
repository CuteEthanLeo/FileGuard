"""
FileGuard - 文件预览模块
支持文本、图片、Office 文件、FileGuard 加密文件预览
"""

import os
import zipfile
import xml.etree.ElementTree as ET

from core import detect_format

TEXT_EXTS = ['.txt', '.py', '.json', '.xml', '.html', '.css', '.js', '.md', '.csv', '.ini', '.log']
IMAGE_EXTS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']
MAX_TEXT_CHARS = 5000
MAX_OFFICE_CHARS = 1000


def preview(file_path):
    """返回预览文本"""
    try:
        size = os.path.getsize(file_path)
        ext = os.path.splitext(file_path)[1].lower()
        head = f"文件: {os.path.basename(file_path)}\n大小: {size} 字节\n"

        # 文本文件（只读取需要显示的部分）
        if ext in TEXT_EXTS:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(MAX_TEXT_CHARS + 1)
            if len(content) > MAX_TEXT_CHARS:
                content = content[:MAX_TEXT_CHARS] + f"\n\n... (仅显示前{MAX_TEXT_CHARS}字符)"
            return f"{head}\n{content}"

        # Office 文件 (.docx, .pptx, .xlsx)
        if ext in ['.docx', '.pptx', '.xlsx']:
            return preview_office(file_path, head, ext)

        # 图片
        if ext in IMAGE_EXTS:
            return f"{head}类型: 图片文件\n\n无法显示缩略图，请用图片查看器打开"

        # 加密文件
        if ext == '.enc':
            return f"{head}类型: FileGuard 加密文件\n{detect_format(file_path)}"

        # 二进制
        return f"{head}类型: 二进制文件\n\n不支持预览此格式"

    except Exception as e:
        return f"预览失败: {str(e)}"


def _xml_text(zf, name):
    root = ET.fromstring(zf.read(name))
    return ' '.join(t.strip() for t in root.itertext() if t.strip())


def preview_office(file_path, head, ext):
    """预览 Office 文件"""
    type_name = {
        '.docx': 'Word 文档',
        '.pptx': 'PowerPoint 演示文稿',
        '.xlsx': 'Excel 表格'
    }.get(ext, 'Office 文件')

    sources = {
        '.docx': ('word/document.xml', '正文预览'),
        '.pptx': ('ppt/slides/slide1.xml', '第一页预览'),
        '.xlsx': ('xl/sharedStrings.xml', '单元格文本预览'),
    }

    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            files = zf.namelist()
            info = f"{head}类型: {type_name}\n内部文件数: {len(files)}\n\n"

            name, label = sources[ext]
            text = _xml_text(zf, name)[:MAX_OFFICE_CHARS] if name in files else ''
            if text:
                info += f"{label}:\n{text}"
            else:
                info += "无法提取文本内容，请用 Office 打开"

        return info
    except Exception:
        return f"{head}类型: {type_name}\n\n预览失败，文件可能损坏或加密"
