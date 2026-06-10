@echo off
REM 开发环境一键启动说明
echo ========================================
echo  自动化漏洞管理与修复平台 - 开发启动
echo ========================================
echo.
echo 需要两个终端分别运行:
echo.
echo  [终端1] 后端 API (端口 6666):
echo    cd /d %~dp0
echo    python app.py
echo.
echo  [终端2] 前端 Vue (端口 3002):
echo    cd /d %~dp0frontend
echo    npm install
echo    npm run dev
echo.
echo  浏览器访问: http://127.0.0.1:3002
echo  默认账号: admin / admin123 (首次需初始化)
echo ========================================
