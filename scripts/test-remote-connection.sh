#!/bin/bash

# Script kiểm tra kết nối MongoDB từ máy khác tới server
# Sử dụng: ./test-remote-connection.sh [SERVER_IP]

SERVER_IP="$1"

if [ -z "$SERVER_IP" ]; then
    echo "❌ Vui lòng cung cấp IP của server"
    echo "Sử dụng: ./test-remote-connection.sh [SERVER_IP]"
    echo "Ví dụ: ./test-remote-connection.sh 192.168.1.100"
    exit 1
fi

echo "🔍 Kiểm tra kết nối MongoDB tới server $SERVER_IP..."
echo

# Kiểm tra Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js chưa được cài đặt"
    exit 1
fi

echo "✅ Node.js version:"
node --version
echo

# Kiểm tra network connectivity
echo "🌐 Kiểm tra network connectivity..."
if ! ping -c 1 "$SERVER_IP" &> /dev/null; then
    echo "❌ Không thể ping tới server $SERVER_IP"
    echo "Kiểm tra:"
    echo "  - Server có đang chạy không"
    echo "  - IP address có đúng không"
    echo "  - Network connectivity"
    exit 1
fi
echo "✅ Server $SERVER_IP có thể ping được"
echo

# Kiểm tra port 27017
echo "🔌 Kiểm tra port 27017..."
if ! timeout 5 bash -c "</dev/tcp/$SERVER_IP/27017" 2>/dev/null; then
    echo "❌ Không thể kết nối tới port 27017 trên server $SERVER_IP"
    echo "Kiểm tra:"
    echo "  - MongoDB có đang chạy trên server không"
    echo "  - Firewall có cho phép port 27017 không"
    echo "  - Port forwarding (nếu qua Internet)"
    exit 1
fi
echo "✅ Port 27017 có thể kết nối được"
echo

# Test MongoDB connection
echo "📊 Kiểm tra kết nối MongoDB..."
MONGODB_URI="mongodb://$SERVER_IP:27017/OrderDetailing"

node scripts/test-mongodb-connection.js "$MONGODB_URI"

if [ $? -eq 0 ]; then
    echo
    echo "🎉 Kết nối MongoDB từ xa thành công!"
    echo
    echo "📋 Thông tin kết nối:"
    echo "   Server IP: $SERVER_IP"
    echo "   Port: 27017"
    echo "   Database: OrderDetailing"
    echo "   Authentication: None"
    echo
    echo "💡 Bạn có thể sử dụng connection string này trong ứng dụng:"
    echo "   $MONGODB_URI"
else
    echo
    echo "❌ Kết nối MongoDB từ xa thất bại"
    echo "Xem thêm hướng dẫn: REMOTE-ACCESS-GUIDE.md"
fi

echo
