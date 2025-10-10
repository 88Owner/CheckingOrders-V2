@echo off
REM Script kiểm tra kết nối MongoDB từ máy khác tới server
REM Sử dụng: test-remote-connection.bat [SERVER_IP]

set SERVER_IP=%1
if "%SERVER_IP%"=="" (
    echo ❌ Vui lòng cung cấp IP của server
    echo Sử dụng: test-remote-connection.bat [SERVER_IP]
    echo Ví dụ: test-remote-connection.bat 192.168.1.100
    pause
    exit /b 1
)

echo 🔍 Kiểm tra kết nối MongoDB tới server %SERVER_IP%...
echo.

REM Kiểm tra Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js chưa được cài đặt
    pause
    exit /b 1
)

echo ✅ Node.js version:
node --version
echo.

REM Kiểm tra network connectivity
echo 🌐 Kiểm tra network connectivity...
ping -n 1 %SERVER_IP% >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Không thể ping tới server %SERVER_IP%
    echo Kiểm tra:
    echo   - Server có đang chạy không
    echo   - IP address có đúng không
    echo   - Network connectivity
    pause
    exit /b 1
)
echo ✅ Server %SERVER_IP% có thể ping được
echo.

REM Kiểm tra port 27017
echo 🔌 Kiểm tra port 27017...
telnet %SERVER_IP% 27017 >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Không thể kết nối tới port 27017 trên server %SERVER_IP%
    echo Kiểm tra:
    echo   - MongoDB có đang chạy trên server không
    echo   - Firewall có cho phép port 27017 không
    echo   - Port forwarding (nếu qua Internet)
    pause
    exit /b 1
)
echo ✅ Port 27017 có thể kết nối được
echo.

REM Test MongoDB connection
echo 📊 Kiểm tra kết nối MongoDB...
set MONGODB_URI=mongodb://%SERVER_IP%:27017/OrderDetailing

node scripts/test-mongodb-connection.js "%MONGODB_URI%"

if %errorlevel% equ 0 (
    echo.
    echo 🎉 Kết nối MongoDB từ xa thành công!
    echo.
    echo 📋 Thông tin kết nối:
    echo    Server IP: %SERVER_IP%
    echo    Port: 27017
    echo    Database: OrderDetailing
    echo    Authentication: None
    echo.
    echo 💡 Bạn có thể sử dụng connection string này trong ứng dụng:
    echo    %MONGODB_URI%
) else (
    echo.
    echo ❌ Kết nối MongoDB từ xa thất bại
    echo Xem thêm hướng dẫn: REMOTE-ACCESS-GUIDE.md
)

echo.
pause
