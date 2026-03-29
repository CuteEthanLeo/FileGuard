"""
FileGuard - 文件预览模块
支持文本、图片、Office 文件预览
"""

import os
import zipfile
import xml.etree.ElementTree as ET


def preview(file_path):
    """返回预览文本"""
    try:
        size = os.path.getsize(file_path)
        ext = os.path.splitext(file_path)[1].lower()

        # 文本文件
        if ext in ['.txt', '.py', '.json', '.xml', '.html', '.css', '.js', '.md', '.csv', '.ini', '.log']:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            if len(content) > 5000:
                content = content[:5000] + "\n\n... (仅显示前5000字符)"
            return f"文件: {os.path.basename(file_path)}\n大小: {size} 字节\n\n{content}"

        # Office 文件 (.docx, .pptx, .xlsx)
        if ext in ['.docx', '.pptx', '.xlsx']:
            return preview_office(file_path, size, ext)

        # 图片
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
            return f"文件: {os.path.basename(file_path)}\n大小: {size} 字节\n类型: 图片文件\n\n无法显示缩略图，请用图片查看器打开"

        # 加密文件
        if ext == '.enc':
            return preview_encrypted(file_path, size)

        # 二进制
        return f"文件: {os.path.basename(file_path)}\n大小: {size} 字节\n类型: 二进制文件\n\n不支持预览此格式"

    except Exception as e:
        return f"预览失败: {str(e)}"


def preview_office(file_path, size, ext):
    """预览 Office 文件"""
    name = os.path.basename(file_path)
    type_name = {
        '.docx': 'Word 文档',
        '.pptx': 'PowerPoint 演示文稿',
        '.xlsx': 'Excel 表格'
    }.get(ext, 'Office 文件')

    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            files = zf.namelist()
            info = f"文件: {name}\n大小: {size} 字节\n类型: {type_name}\n"
            info += f"内部文件数: {len(files)}\n\n"

            if ext == '.pptx' and 'ppt/slides/slide1.xml' in files:
                xml_data = zf.read('ppt/slides/slide1.xml')
                root = ET.fromstring(xml_data)
                text = ''.join(root.itertext())[:500]
                if text:
                    info += f"第一页预览:\n{text}"
                else:
                    info += "无法提取文本内容"
            else:
                info += "无法提取内部文本，请用 Office 打开"

        return info
    except:
        return f"文件: {name}\n大小: {size} 字节\n类型: {type_name}\n\n预览失败，文件可能损坏或加密"


def preview_encrypted(file_path, size):
    """预览加密文件信息"""
    try:
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            nonce = f.read(12)
            f.seek(-16, os.SEEK_END)
            tag = f.read(16)

        return f"文件: {os.path.basename(file_path)}\n大小: {size} 字节\n类型: FileGuard 加密文件\n算法: AES-256-GCM\nSalt: {salt.hex()[:16]}...\nNonce: {nonce.hex()[:16]}...\n认证标签: 存在"
    except:
        return f"文件: {os.path.basename(file_path)}\n大小: {size} 字节\n类型: 加密文件\n\n预览失败"