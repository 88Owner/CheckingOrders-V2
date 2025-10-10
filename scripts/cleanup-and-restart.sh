#!/bin/bash

# Script dọn dẹp container cũ và khởi động lại với tên mới
# Sử dụng: ./cleanup-and-restart.sh

echo "🧹 Dọn dẹp containers cũ..."

# Dừng và xóa containers cũ
echo "⏹️ Dừng containers cũ..."
docker stop ordercheck-app ordercheck-mongodb 2>/dev/null

echo "🗑️ Xóa containers cũ..."
docker rm ordercheck-app ordercheck-mongodb 2>/dev/null

# Dừng và xóa containers hiện tại (nếu có)
echo "⏹️ Dừng containers hiện tại..."
docker stop ordercheck-app-v2 ordercheck-mongodb-v2 2>/dev/null

echo "🗑️ Xóa containers hiện tại..."
docker rm ordercheck-app-v2 ordercheck-mongodb-v2 2>/dev/null

echo "🧹 Dọn dẹp images không sử dụng..."
docker image prune -f

echo "🔄 Khởi động containers mới..."
docker-compose up -d

echo
echo "✅ Hoàn tất! Containers mới:"
echo "   - ordercheck-app-v2 (Ứng dụng)"
echo "   - ordercheck-mongodb-v2 (MongoDB)"
echo
echo "🌐 Truy cập ứng dụng:"
echo "   http://localhost:3001"
echo
echo "📊 Xem logs:"
echo "   docker logs ordercheck-app-v2"
echo "   docker logs ordercheck-mongodb-v2"
echo
