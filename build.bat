@echo off
REM Build dist\FileGuardV<APP_VERSION>.exe (requires: pip install -r requirements.txt pyinstaller)
cd /d "%~dp0"
python -m PyInstaller --noconfirm --clean FileGuard.spec
