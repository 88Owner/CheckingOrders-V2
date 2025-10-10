# Hướng dẫn chuyển từ MongoDB Cloud sang MongoDB Local

## 📋 Tổng quan

Tài liệu này hướng dẫn bạn chuyển từ MongoDB Atlas (Cloud) sang MongoDB Local để chạy dự án OrderCheck.

## 🔄 Những thay đổi đã thực hiện

### 1. Docker Compose
- ✅ Thêm MongoDB service vào `docker-compose.yml`
- ✅ Cập nhật MONGODB_URI để kết nối với MongoDB local
- ✅ Thêm volume để lưu trữ dữ liệu MongoDB
- ✅ Cấu hình khởi tạo dữ liệu tự động

### 2. Cấu hình môi trường
- ✅ Cập nhật `env.example` với cấu hình MongoDB local
- ✅ Thêm hướng dẫn cho cả Docker và chạy trực tiếp

### 3. Script khởi tạo
- ✅ Cập nhật `init-data.js` để sử dụng database `OrderDetailing`
- ✅ Thêm tài khoản mặc định và dữ liệu mẫu

### 4. Hướng dẫn
- ✅ Cập nhật `README.md` với hướng dẫn chi tiết
- ✅ Cập nhật `setup-local.bat` cho Windows

## 🚀 Cách sử dụng

### Phương pháp 1: Docker (Khuyến nghị)

```bash
# 1. Sao chép file cấu hình
cp env.example .env

# 2. Chạy tất cả services
docker-compose up -d

# 3. Xem logs
docker-compose logs -f

# 4. Truy cập ứng dụng
# http://localhost:3001
```

### Phương pháp 2: Chạy trực tiếp

```bash
# 1. Cài đặt MongoDB local
# Windows: Tải từ https://www.mongodb.com/try/download/community
# macOS: brew install mongodb-community
# Ubuntu: sudo apt install mongodb

# 2. Khởi động MongoDB
# Windows: net start MongoDB
# macOS/Linux: sudo systemctl start mongod

# 3. Chạy script setup
# Windows: setup-local.bat
# macOS/Linux: ./setup-local.sh

# 4. Hoặc setup thủ công
cp env.example .env
npm install
node create-ssl-cert.js
mongosh OrderDetailing < init-data.js
npm start
```

## 🔑 Tài khoản đăng nhập

Sau khi khởi tạo dữ liệu, sử dụng các tài khoản sau:

| Username | Password | Role    | Mô tả                |
|----------|----------|---------|----------------------|
| admin    | admin    | admin   | Quản trị viên        |
| nv01     | 123      | checker | Nhân viên kiểm hàng  |
| nv02     | 123      | packer  | Nhân viên đóng gói   |
| user     | 123      | user    | Người dùng thường    |

## 🔧 Cấu hình MongoDB

### Docker Compose
```yaml
mongodb:
  image: mongo:7.0
  environment:
    MONGO_INITDB_ROOT_USERNAME: admin
    MONGO_INITDB_ROOT_PASSWORD: password123
    MONGO_INITDB_DATABASE: OrderDetailing
  ports:
    - "27017:27017"
  volumes:
    - mongodb_data:/data/db
    - ./init-data.js:/docker-entrypoint-initdb.d/init-data.js:ro
```

### Kết nối
```javascript
// Cho Docker
MONGODB_URI=mongodb://admin:password123@mongodb:27017/OrderDetailing?authSource=admin
PORT=3001

// Cho chạy trực tiếp
MONGODB_URI=mongodb://localhost:27017/OrderDetailing
PORT=3001
```

## 📊 Dữ liệu mẫu

Script `init-data.js` sẽ tạo:

- **Accounts**: 4 tài khoản với các role khác nhau
- **MasterData**: 3 sản phẩm mẫu
- **ComboData**: 2 combo mẫu
- **Orders**: 2 đơn hàng mẫu
- **Indexes**: Các index cần thiết cho performance

## 🛠️ Troubleshooting

### Lỗi kết nối MongoDB
```bash
# Kiểm tra MongoDB có chạy không
# Windows
sc query MongoDB

# macOS/Linux
sudo systemctl status mongod

# Kiểm tra port
netstat -an | grep 27017
```

### Lỗi Docker
```bash
# Xóa containers và volumes cũ
docker-compose down -v
docker system prune -f

# Khởi động lại
docker-compose up -d
```

### Lỗi permissions
```bash
# Windows: Chạy PowerShell/CMD as Administrator
# macOS/Linux: Thêm sudo nếu cần
```

## 📝 Lưu ý quan trọng

1. **Backup dữ liệu**: Nếu có dữ liệu quan trọng trên MongoDB Cloud, hãy export trước khi chuyển đổi
2. **Port conflicts**: Đảm bảo port 27017 không bị sử dụng bởi service khác
3. **Firewall**: Mở port 27017 nếu cần truy cập từ máy khác
4. **Performance**: MongoDB local có thể chậm hơn MongoDB Atlas tùy thuộc vào cấu hình máy

## 🔄 Rollback (Quay lại MongoDB Cloud)

Nếu cần quay lại MongoDB Cloud:

1. Khôi phục `docker-compose.yml` cũ
2. Cập nhật `MONGODB_URI` trong `.env`
3. Restart services

```bash
# Backup cấu hình hiện tại
cp docker-compose.yml docker-compose.local.yml

# Khôi phục cấu hình cloud
git checkout HEAD~1 docker-compose.yml

# Cập nhật .env
echo "MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/database" > .env

# Restart
docker-compose down
docker-compose up -d
```
