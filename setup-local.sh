#!/bin/bash

# Script tự động setup OrderCheck trên máy local
# Sử dụng: chmod +x setup-local.sh && ./setup-local.sh

echo "🚀 Bắt đầu setup OrderCheck trên máy local..."

# Kiểm tra Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js chưa được cài đặt. Vui lòng cài đặt Node.js >= 16.0.0"
    exit 1
fi

echo "✅ Node.js version: $(node --version)"

# Kiểm tra MongoDB
if ! command -v mongod &> /dev/null; then
    echo "❌ MongoDB chưa được cài đặt. Vui lòng cài đặt MongoDB Community Edition"
    exit 1
fi

echo "✅ MongoDB version: $(mongod --version | head -n 1)"

# Kiểm tra MongoDB đang chạy
if ! pgrep -x "mongod" > /dev/null; then
    echo "⚠️  MongoDB chưa chạy. Đang khởi động..."
    sudo systemctl start mongod || brew services start mongodb/brew/mongodb-community
fi

echo "✅ MongoDB đang chạy"

# Cài đặt dependencies
echo "📦 Đang cài đặt dependencies..."
npm install

# Tạo thư mục logs
mkdir -p logs

# Tạo file .env nếu chưa có
if [ ! -f .env ]; then
    echo "⚙️  Tạo file .env..."
    cat > .env << 'EOF'
# MongoDB Local Configuration
MONGODB_URI=mongodb://ordercheck_user:ordercheck_pass@localhost:27017/ordercheck

# Session Secret
SESSION_SECRET=ordercheck-super-secret-key-2025

# Server Port
PORT=3000

# Environment
NODE_ENV=development
EOF
    echo "✅ File .env đã được tạo"
else
    echo "✅ File .env đã tồn tại"
fi

# Tạo SSL certificate
echo "🔐 Tạo SSL certificate..."
node create-ssl-cert.js

# Tạo database và user MongoDB
echo "🗄️  Tạo database và user MongoDB..."
mongosh --eval "
use ordercheck;
db.createUser({
  user: 'ordercheck_user',
  pwd: 'ordercheck_pass',
  roles: [
    { role: 'readWrite', db: 'ordercheck' }
  ]
});
print('✅ User MongoDB đã được tạo');
"

# Import dữ liệu mẫu
echo "📊 Import dữ liệu mẫu..."
mongosh < init-data.js

# Kiểm tra cài đặt
echo "🔍 Kiểm tra cài đặt..."
if [ -f server.js ] && [ -f package.json ] && [ -f .env ]; then
    echo "✅ Tất cả files cần thiết đã có"
else
    echo "❌ Thiếu files cần thiết"
    exit 1
fi

echo ""
echo "🎉 Setup hoàn tất!"
echo ""
echo "📋 Thông tin truy cập:"
echo "   - HTTPS: https://localhost:3000"
echo "   - HTTP:  http://localhost:3000"
echo ""
echo "👤 Tài khoản đăng nhập:"
echo "   - admin/admin (admin)"
echo "   - nv01/123 (checker)"
echo "   - nv02/123 (packer)"
echo "   - user/123 (user)"
echo ""
echo "🚀 Để chạy server:"
echo "   npm start"
echo "   hoặc"
echo "   node server.js"
echo ""
echo "📖 Xem hướng dẫn chi tiết: DEPLOYMENT-GUIDE.md"
