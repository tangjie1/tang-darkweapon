@echo off
chcp 65001 >nul
title 安装依赖
color 0a
echo.
echo  [*] 正在安装依赖...
echo.

python -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

if errorlevel 1 (
    echo.
    echo [!] 安装失败，尝试使用默认源...
    python -m pip install -r requirements.txt
)

echo.
echo  [*] 安装完成
echo.
pause
