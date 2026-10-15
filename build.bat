@echo off
REM Build dist\FileGuardV2.0.exe (requires: pip install -r requirements.txt pyinstaller)
cd /d "%~dp0"
python -m PyInstaller --noconfirm --clean FileGuard.spec
