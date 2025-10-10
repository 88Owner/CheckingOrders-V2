# OrderCheck - Hệ thống quản lý đơn hàng và kiểm tra hàng 

##Hướng dẫn cài đặt

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

# Session Secret
SESSION_SECRET=your-session-secret-here

# Server Port
PORT=3000

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
- **HTTP**: http://localhost:30000
- **MongoDB**: mongodb://localhost:27017

### Cách 2: Chạy trực tiếp trên máy

#### 1. Clone dự án
```bash
git clone <repository-url>
cd OrderCheck
```

#### 2. Cài đặt MongoDB local
- **Windows**: Tải và cài đặt từ [MongoDB Community Server]
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
PORT=3000

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

## Tài khoản đăng nhập mặc định

Sau khi khởi tạo dữ liệu, bạn có thể đăng nhập với các tài khoản sau:

- **admin/admin123** - Quản trị viên


## Truy cập ứng dụng

- **HTTP**: http://localhost:3000
- **HTTPS**: https://localhost:3000
- **MongoDB Local**: mongodb://localhost:27017
- **MongoDB Remote**: mongodb://YOUR_SERVER_IP:27017/OrderDetailing
