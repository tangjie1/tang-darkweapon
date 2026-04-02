@echo off
chcp 65001 >nul
title 唐门-暗之器
color 0a
echo.
echo  ╔═══════════════════════════════════════╗
echo  ║                                       ║
echo  ║        唐 门 - 暗 之 器               ║
echo  ║                                       ║
echo  ║      网络安全工具集                   ║
echo  ║                                       ║
echo  ╚═══════════════════════════════════════╝
echo.
echo  [*] 正在启动程序...
echo.

python main.py

if errorlevel 1 (
    echo.
    echo [!] 启动失败，请检查:
    echo     1. Python 是否已安装
    echo     2. 依赖是否已安装: pip install -r requirements.txt
    echo.
    pause
)
