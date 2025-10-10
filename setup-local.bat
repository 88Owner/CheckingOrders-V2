@echo off
REM Script tự động setup OrderCheck trên Windows
REM Sử dụng: setup-local.bat

echo 🚀 Bắt đầu setup OrderCheck trên máy local...

REM Kiểm tra Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js chưa được cài đặt. Vui lòng cài đặt Node.js ^>= 16.0.0
    pause
    exit /b 1
)

echo ✅ Node.js version:
node --version

REM Kiểm tra MongoDB
mongod --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ MongoDB chưa được cài đặt. Vui lòng cài đặt MongoDB Community Edition
    pause
    exit /b 1
)

echo ✅ MongoDB version:
mongod --version

REM Kiểm tra MongoDB đang chạy
sc query MongoDB >nul 2>&1
if %errorlevel% neq 0 (
    echo ⚠️  MongoDB chưa chạy. Đang khởi động...
    net start MongoDB
)

echo ✅ MongoDB đang chạy

REM Cài đặt dependencies
echo 📦 Đang cài đặt dependencies...
npm install

REM Tạo thư mục logs
if not exist logs mkdir logs

REM Tạo file .env nếu chưa có
if not exist .env (
    echo ⚙️  Tạo file .env...
    (
        echo # MongoDB Local Configuration ^(không có authentication^)
        echo MONGODB_URI=mongodb://localhost:27017/OrderDetailing
        echo.
        echo # Session Secret
        echo SESSION_SECRET=ordercheck-super-secret-key-2025
        echo.
        echo # Server Port
        echo PORT=3001
        echo.
        echo # Environment
        echo NODE_ENV=development
    ) > .env
    echo ✅ File .env đã được tạo
) else (
    echo ✅ File .env đã tồn tại
)

REM Tạo SSL certificate
echo 🔐 Tạo SSL certificate...
node create-ssl-cert.js

REM Import dữ liệu mẫu
echo 📊 Import dữ liệu mẫu...
mongosh OrderDetailing < init-data.js

REM Kiểm tra cài đặt
echo 🔍 Kiểm tra cài đặt...
if exist server.js if exist package.json if exist .env (
    echo ✅ Tất cả files cần thiết đã có
) else (
    echo ❌ Thiếu files cần thiết
    pause
    exit /b 1
)

echo.
echo 🎉 Setup hoàn tất!
echo.
echo 📋 Thông tin truy cập:
echo    - HTTPS: https://localhost:3001
echo    - HTTP:  http://localhost:3001
echo.
echo 👤 Tài khoản đăng nhập:
echo    - admin/admin ^(admin^)
echo    - nv01/123 ^(checker^)
echo    - nv02/123 ^(packer^)
echo    - user/123 ^(user^)
echo.
echo 🚀 Để chạy server:
echo    npm start
echo    hoặc
echo    node server.js
echo.
echo 📖 Xem hướng dẫn chi tiết: DEPLOYMENT-GUIDE.md
pause
