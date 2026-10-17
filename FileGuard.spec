# PyInstaller 打包配置: pyinstaller FileGuard.spec  (或运行 build.bat)
import os
import re

SRC = os.path.join(SPECPATH, 'FileGuard')
# 版本号统一取自 main.py 的 APP_VERSION, 输出 dist/FileGuardV<版本>.exe
with open(os.path.join(SRC, 'main.py'), encoding='utf-8') as _f:
    APP_VERSION = re.search(r'^APP_VERSION = "([^"]+)"', _f.read(), re.M).group(1)
APP_NAME = f'FileGuardV{APP_VERSION}'

# 纯 Widgets 程序用不到的大体积 Qt 组件
EXCLUDED_BINARIES = ('opengl32sw.dll', 'qpdf.dll', 'Qt6Pdf.dll', 'Qt6Network.dll')

a = Analysis(
    [os.path.join(SRC, 'main.py')],
    pathex=[SRC],
    datas=[(os.path.join(SRC, 'app.ico'), '.')],
    excludes=['tkinter', 'unittest', 'pydoc', 'numpy', 'PIL'],
)
a.binaries = [b for b in a.binaries if os.path.basename(b[0]) not in EXCLUDED_BINARIES]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=APP_NAME,
    icon=os.path.join(SRC, 'app.ico'),
    console=False,
    upx=False,
)
