# Hướng dẫn triển khai OrderCheck trên máy khác với MongoDB Local

## 📋 Yêu cầu hệ thống

### Phần mềm cần thiết:
- **Node.js** >= 16.0.0
- **MongoDB** Community Edition (local)
- **Git** (để clone dự án)
- **Chrome/Edge** (hỗ trợ Web Serial API)

### Hệ điều hành hỗ trợ:
- Windows 10/11
- macOS 10.15+
- Ubuntu 18.04+
- CentOS 7+

## 🚀 Bước 1: Cài đặt MongoDB Local

### Windows:
```bash
# Download MongoDB Community Server
# https://www.mongodb.com/try/download/community

# Cài đặt và khởi động service
net start MongoDB
```

### macOS:
```bash
# Sử dụng Homebrew
brew tap mongodb/brew
brew install mongodb-community
brew services start mongodb/brew/mongodb-community
```

### Ubuntu/Debian:
```bash
# Import public key
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -

# Add repository
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list

# Install MongoDB
sudo apt-get update
sudo apt-get install -y mongodb-org

# Start MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod
```

## 📥 Bước 2: Clone dự án

```bash
# Clone từ GitHub
git clone https://github.com/YOUR_USERNAME/OrderCheck.git
cd OrderCheck

# Hoặc download ZIP và giải nén
```

## 📦 Bước 3: Cài đặt Dependencies

```bash
# Cài đặt Node.js dependencies
npm install

# Kiểm tra cài đặt
node --version
npm --version
mongod --version
```

## ⚙️ Bước 4: Cấu hình MongoDB Local

### Tạo database và user:
```bash
# Kết nối MongoDB shell
mongosh

# Tạo database
use ordercheck

# Tạo user admin
db.createUser({
  user: "admin",
  pwd: "admin123",
  roles: [
    { role: "readWrite", db: "ordercheck" },
    { role: "dbAdmin", db: "ordercheck" }
  ]
})

# Tạo user cho ứng dụng
db.createUser({
  user: "ordercheck_user",
  pwd: "ordercheck_pass",
  roles: [
    { role: "readWrite", db: "ordercheck" }
  ]
})

# Thoát
exit
```

### Import dữ liệu mẫu (tùy chọn):
```bash
# Tạo file init-data.js
cat > init-data.js << 'EOF'
use ordercheck;

// Tạo tài khoản mặc định
db.accounts.insertMany([
  {
    username: "admin",
    password: "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password: admin
    role: "admin",
    createdAt: new Date()
  },
  {
    username: "nv01",
    password: "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password: 123
    role: "checker",
    createdAt: new Date()
  },
  {
    username: "nv02",
    password: "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password: 123
    role: "packer",
    createdAt: new Date()
  },
  {
    username: "user",
    password: "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password: 123
    role: "user",
    createdAt: new Date()
  }
]);

print("✅ Tài khoản mặc định đã được tạo!");
EOF

# Chạy script
mongosh < init-data.js
```

## 🔧 Bước 5: Cấu hình Environment

### Tạo file .env:
```bash
# Tạo file .env
cat > .env << 'EOF'
# MongoDB Local Configuration
MONGODB_URI=mongodb://ordercheck_user:ordercheck_pass@localhost:27017/ordercheck

# Session Secret (thay đổi thành chuỗi ngẫu nhiên)
SESSION_SECRET=your-super-secret-key-here-change-this-in-production

# Server Port
PORT=3000

# Environment
NODE_ENV=production
EOF
```

### Tạo file .env.example:
```bash
cat > .env.example << 'EOF'
# MongoDB Local Configuration
MONGODB_URI=mongodb://username:password@localhost:27017/database_name

# Session Secret
SESSION_SECRET=your-session-secret-here

# Server Port
PORT=3000

# Environment
NODE_ENV=development
EOF
```

## 🔐 Bước 6: Tạo SSL Certificate

```bash
# Tạo SSL certificate cho HTTPS
node create-ssl-cert.js

# Kiểm tra file đã tạo
ls -la server.key server.crt
```

## 🚀 Bước 7: Chạy dự án

### Development mode:
```bash
# Chạy với nodemon (auto-restart)
npm run dev

# Hoặc chạy trực tiếp
node server.js
```

### Production mode:
```bash
# Chạy production
NODE_ENV=production node server.js

# Hoặc sử dụng PM2 (recommended)
npm install -g pm2
pm2 start server.js --name "ordercheck"
pm2 startup
pm2 save
```

## 🌐 Bước 8: Truy cập ứng dụng

### Local access:
- **HTTPS**: https://localhost:3000
- **HTTP**: http://localhost:3000

### Network access:
- **HTTPS**: https://YOUR_IP:3000
- **HTTP**: http://YOUR_IP:3000

### Tìm IP address:
```bash
# Windows
ipconfig

# macOS/Linux
ifconfig
# hoặc
ip addr show
```

## 🔧 Bước 9: Cấu hình Firewall

### Windows:
```bash
# Mở port 3000
netsh advfirewall firewall add rule name="OrderCheck" dir=in action=allow protocol=TCP localport=3000
```

### Linux (ufw):
```bash
# Mở port 3000
sudo ufw allow 3000
sudo ufw reload
```

### Linux (iptables):
```bash
# Mở port 3000
sudo iptables -A INPUT -p tcp --dport 3000 -j ACCEPT
sudo iptables-save
```

## 📱 Bước 10: Test ứng dụng

### 1. Test đăng nhập:
- Mở browser → https://localhost:3000
- Đăng nhập với tài khoản mặc định
- Kiểm tra animation đăng nhập

### 2. Test COM Port:
- Kết nối scanner qua USB
- Vào trang chính → Click "🔌 Kết nối COM"
- Chọn COM port → Test quét mã vạch

### 3. Test upload file:
- Vào trang Upload
- Upload file Excel đơn hàng
- Kiểm tra dữ liệu đã import

## 🛠️ Bước 11: Cấu hình nâng cao

### MongoDB Security:
```bash
# Tạo file mongod.conf
cat > /etc/mongod.conf << 'EOF'
storage:
  dbPath: /var/lib/mongodb
  journal:
    enabled: true

systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log

net:
  port: 27017
  bindIp: 127.0.0.1

security:
  authorization: enabled

processManagement:
  timeZoneInfo: /usr/share/zoneinfo
EOF

# Restart MongoDB
sudo systemctl restart mongod
```

### PM2 Configuration:
```bash
# Tạo file ecosystem.config.js
cat > ecosystem.config.js << 'EOF'
module.exports = {
  apps: [{
    name: 'ordercheck',
    script: 'server.js',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    }
  }]
};
EOF

# Chạy với PM2
pm2 start ecosystem.config.js
```

### Nginx Reverse Proxy (tùy chọn):
```bash
# Cài đặt Nginx
sudo apt install nginx

# Tạo config
sudo cat > /etc/nginx/sites-available/ordercheck << 'EOF'
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass https://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/ordercheck /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## 🔍 Troubleshooting

### Lỗi thường gặp:

**1. MongoDB connection failed:**
```bash
# Kiểm tra MongoDB đang chạy
sudo systemctl status mongod

# Kiểm tra port 27017
netstat -tlnp | grep 27017

# Restart MongoDB
sudo systemctl restart mongod
```

**2. Port 3000 đã được sử dụng:**
```bash
# Tìm process sử dụng port 3000
netstat -tlnp | grep 3000

# Kill process
sudo kill -9 PID
```

**3. SSL certificate error:**
```bash
# Tạo lại certificate
rm server.key server.crt
node create-ssl-cert.js
```

**4. Permission denied:**
```bash
# Cấp quyền cho file
chmod +x server.js
chmod 600 .env
```

## 📊 Monitoring

### Log files:
```bash
# Application logs
tail -f logs/app.log

# MongoDB logs
tail -f /var/log/mongodb/mongod.log

# PM2 logs
pm2 logs ordercheck
```

### Health check:
```bash
# Test API
curl -k https://localhost:3000/api/me

# Test database
mongosh --eval "db.runCommand({ping: 1})"
```

## 🔄 Backup & Restore

### Backup MongoDB:
```bash
# Backup database
mongodump --uri="mongodb://ordercheck_user:ordercheck_pass@localhost:27017/ordercheck" --out=./backup

# Restore database
mongorestore --uri="mongodb://ordercheck_user:ordercheck_pass@localhost:27017/ordercheck" ./backup/ordercheck
```

### Backup files:
```bash
# Backup uploads
tar -czf uploads-backup.tar.gz uploads/

# Backup SSL certificates
tar -czf ssl-backup.tar.gz server.key server.crt
```

## ✅ Checklist triển khai

- [ ] MongoDB đã cài đặt và chạy
- [ ] Node.js >= 16.0.0 đã cài đặt
- [ ] Dự án đã clone về máy
- [ ] Dependencies đã cài đặt (npm install)
- [ ] File .env đã cấu hình
- [ ] SSL certificate đã tạo
- [ ] Database và user đã tạo
- [ ] Tài khoản mặc định đã import
- [ ] Server đã chạy thành công
- [ ] Firewall đã mở port 3000
- [ ] Ứng dụng truy cập được từ browser
- [ ] COM port hoạt động (nếu có scanner)
- [ ] Upload file hoạt động
- [ ] PM2 đã cấu hình (production)

## 📞 Hỗ trợ

Nếu gặp vấn đề, kiểm tra:
1. Log files trong thư mục `logs/`
2. MongoDB logs
3. Browser console
4. Network connectivity

**Tài khoản mặc định:**
- admin/admin (admin)
- nv01/123 (checker)
- nv02/123 (packer)
- user/123 (user)
