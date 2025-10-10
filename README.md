# OrderCheck - Hệ thống quản lý đơn hàng và kiểm tra hàng 

## 🚀 Hướng dẫn cài đặt

### Cách 1: Sử dụng Docker (Khuyến nghị)

#### 1. Clone dự án
```bash
git clone <repository-url>
cd OrderCheck
```

#### 2. Cấu hình môi trường
Sao chép file cấu hình mẫu:
```bash
cp env.example .env
```

Chỉnh sửa file `.env` nếu cần:
```env
# MongoDB Local Configuration (cho Docker)
MONGODB_URI=mongodb://admin:password123@localhost:27017/OrderDetailing?authSource=admin

# Session Secret (thay đổi thành chuỗi ngẫu nhiên)
SESSION_SECRET=your-session-secret-here

# Server Port
PORT=3001

# Environment
NODE_ENV=development
```

#### 3. Chạy với Docker Compose
```bash
# Khởi động tất cả services (bao gồm MongoDB)
docker-compose up -d

# Xem logs
docker-compose logs -f

# Dừng services
docker-compose down
```

#### 4. Truy cập ứng dụng
- **HTTP**: http://localhost:3001
- **MongoDB**: mongodb://localhost:27017

### Cách 2: Chạy trực tiếp trên máy

#### 1. Clone dự án
```bash
git clone <repository-url>
cd OrderCheck
```

#### 2. Cài đặt MongoDB local
- **Windows**: Tải và cài đặt từ [MongoDB Community Server](https://www.mongodb.com/try/download/community)
- **macOS**: `brew install mongodb-community`
- **Ubuntu**: `sudo apt install mongodb`

#### 3. Khởi động MongoDB
```bash
# Windows (nếu cài đặt service)
net start MongoDB

# macOS/Linux
sudo systemctl start mongod
# hoặc
mongod
```

#### 4. Cài đặt dependencies
```bash
npm install
```

#### 5. Cấu hình môi trường
Tạo file `.env`:
```env
# MongoDB Local Configuration (cho chạy trực tiếp)
MONGODB_URI=mongodb://localhost:27017/OrderDetailing

# Session Secret
SESSION_SECRET=your-session-secret-here

# Server Port
PORT=3001

# Environment
NODE_ENV=development
```

#### 6. Khởi tạo dữ liệu mẫu
```bash
# Kết nối MongoDB và chạy script khởi tạo
mongo OrderDetailing < init-data.js
```

#### 7. Tạo SSL certificate (cho HTTPS)
```bash
node create-ssl-cert.js
```

#### 8. Chạy dự án
```bash
# Development mode
npm run dev

# Production mode
npm start
```

## 🔑 Tài khoản đăng nhập mặc định

Sau khi khởi tạo dữ liệu, bạn có thể đăng nhập với các tài khoản sau:

- **admin/admin** - Quản trị viên
- **nv01/123** - Nhân viên kiểm hàng (checker)
- **nv02/123** - Nhân viên đóng gói (packer)
- **user/123** - Người dùng thường

## 🌐 Truy cập ứng dụng

- **HTTP**: http://localhost:3001
- **HTTPS**: https://localhost:3001 (sau khi tạo SSL certificate)
- **MongoDB Local**: mongodb://localhost:27017
- **MongoDB Remote**: mongodb://YOUR_SERVER_IP:27017/OrderDetailing

> ⚠️ **Lưu ý**: Nếu sử dụng HTTPS, browser sẽ hiện cảnh báo SSL, click "Advanced" → "Proceed"

## 🌍 Remote Access (Truy cập từ xa)

Để máy khác có thể kết nối tới MongoDB trên server này:

### 1. Test kết nối từ máy khác
```bash
# Windows
scripts\test-remote-connection.bat YOUR_SERVER_IP

# Linux/macOS
./scripts/test-remote-connection.sh YOUR_SERVER_IP
```

### 2. Cấu hình ứng dụng từ xa
```bash
# Tạo file .env trên máy client
MONGODB_URI=mongodb://YOUR_SERVER_IP:27017/OrderDetailing
```

### 3. Các bước cấu hình server
- ✅ MongoDB đã được cấu hình bind trên tất cả interfaces
- ✅ Không cần authentication (đơn giản hóa kết nối)
- ⚠️ **Cần cấu hình**: Firewall cho phép port 27017
- ⚠️ **Cần cấu hình**: Port forwarding (nếu qua Internet)

> 📖 **Chi tiết**: Xem [REMOTE-ACCESS-GUIDE.md](REMOTE-ACCESS-GUIDE.md) để biết cách cấu hình chi tiết

