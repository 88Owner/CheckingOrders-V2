# 🚀 Hướng dẫn Deploy trên Server Backup

## 📋 Yêu cầu hệ thống

### **Server Requirements:**
- **OS**: Linux (Ubuntu 20.04+), Windows Server, hoặc macOS
- **RAM**: Tối thiểu 4GB (khuyến nghị 8GB+)
- **Storage**: Tối thiểu 10GB trống
- **Network**: Port 3001 và 27017 mở

### **Software cần cài đặt:**
- **Docker**: `docker.io` hoặc `docker-ce`
- **Docker Compose**: `docker-compose` hoặc `docker compose`
- **Git**: `git`

## 🔧 Cài đặt trên Server

### **1. Cài đặt Docker (Ubuntu/Debian)**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
sudo apt install -y docker.io docker-compose

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group (optional)
sudo usermod -aG docker $USER
```

### **2. Cài đặt Docker (CentOS/RHEL)**
```bash
# Install Docker
sudo yum install -y docker docker-compose

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
```

### **3. Cài đặt Docker (Windows Server)**
```powershell
# Download và cài đặt Docker Desktop for Windows
# Hoặc sử dụng Chocolatey
choco install docker-desktop
```

## 📥 Clone và Setup Project

### **1. Clone code từ GitHub**
```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY

# Hoặc nếu dùng SSH
git clone git@github.com:YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY
```

### **2. Tạo file .env**
```bash
# Copy file env.example
cp env.example .env

# Edit file .env với thông tin server
nano .env
```

**Nội dung file .env cho server:**
```env
# MongoDB Local Configuration (cho Docker)
MONGODB_URI=mongodb://mongodb:27017/OrderDetailing

# Session Secret (THAY ĐỔI THÀNH CHUỖI NGẪU NHIÊN)
SESSION_SECRET=your-super-secret-session-key-change-this-in-production

# Server Port
PORT=3001

# Environment
NODE_ENV=production
```

### **3. Khởi động ứng dụng**
```bash
# Build và start containers
docker-compose up -d

# Kiểm tra logs
docker-compose logs -f
```

## 🔍 Kiểm tra và Troubleshooting

### **1. Kiểm tra containers đang chạy**
```bash
docker-compose ps
```

**Kết quả mong đợi:**
```
NAME                      IMAGE                     COMMAND                  SERVICE   CREATED        STATUS                    PORTS
ordercheck-app-v2         ordercheck-copy-ordercheck   "node server.js"        ordercheck   2 minutes ago   Up 2 minutes (healthy)   0.0.0.0:3001->3001/tcp
ordercheck-mongodb-v2     mongo:7.0                  "docker-entrypoint.s…"   mongodb     2 minutes ago   Up 2 minutes             0.0.0.0:27017->27017/tcp
```

### **2. Kiểm tra logs**
```bash
# Logs của ứng dụng
docker logs ordercheck-app-v2

# Logs của MongoDB
docker logs ordercheck-mongodb-v2

# Logs real-time
docker-compose logs -f
```

### **3. Kiểm tra kết nối**
```bash
# Test kết nối ứng dụng
curl -k https://localhost:3001

# Test kết nối MongoDB
docker exec ordercheck-mongodb-v2 mongosh OrderDetailing --eval "db.accounts.countDocuments()"
```

## 🌐 Truy cập ứng dụng

### **Local Access:**
- **HTTPS**: https://localhost:3001
- **HTTP**: http://localhost:3001 (nếu không có SSL)

### **Remote Access:**
- **HTTPS**: https://YOUR_SERVER_IP:3001
- **HTTP**: http://YOUR_SERVER_IP:3001

### **MongoDB Remote:**
- **Connection String**: `mongodb://YOUR_SERVER_IP:27017/OrderDetailing`

## 🔐 Bảo mật Production

### **1. Thay đổi Session Secret**
```bash
# Tạo session secret mạnh
openssl rand -base64 32

# Hoặc sử dụng online generator
# https://generate-secret.vercel.app/32
```

### **2. Cấu hình Firewall (Ubuntu/Debian)**
```bash
# Mở port cần thiết
sudo ufw allow 3001/tcp
sudo ufw allow 27017/tcp
sudo ufw enable
```

### **3. Cấu hình Firewall (CentOS/RHEL)**
```bash
# Mở port cần thiết
sudo firewall-cmd --permanent --add-port=3001/tcp
sudo firewall-cmd --permanent --add-port=27017/tcp
sudo firewall-cmd --reload
```

## 📊 Monitoring và Maintenance

### **1. Kiểm tra tài nguyên**
```bash
# CPU và Memory usage
docker stats

# Disk usage
docker system df
```

### **2. Backup Database**
```bash
# Backup MongoDB
docker exec ordercheck-mongodb-v2 mongodump --db OrderDetailing --out /backup
docker cp ordercheck-mongodb-v2:/backup ./backup-$(date +%Y%m%d)
```

### **3. Restart Services**
```bash
# Restart ứng dụng
docker-compose restart ordercheck

# Restart tất cả
docker-compose restart

# Rebuild và restart
docker-compose down
docker-compose up -d --build
```

## 🚨 Troubleshooting

### **Lỗi thường gặp:**

#### **1. Port đã được sử dụng**
```bash
# Kiểm tra port đang được sử dụng
sudo netstat -tulpn | grep :3001
sudo netstat -tulpn | grep :27017

# Kill process đang sử dụng port
sudo kill -9 PID_NUMBER
```

#### **2. Docker permission denied**
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Logout và login lại
exit
```

#### **3. MongoDB connection failed**
```bash
# Kiểm tra MongoDB container
docker logs ordercheck-mongodb-v2

# Restart MongoDB
docker-compose restart mongodb
```

#### **4. SSL Certificate issues**
```bash
# Regenerate SSL certificate (QUAN TRỌNG cho server backup)
docker exec ordercheck-app-v2 node create-ssl-cert.js

# Hoặc tạo trước khi chạy docker-compose
node create-ssl-cert.js

# Hoặc restart container
docker-compose restart ordercheck
```

#### **5. SSL Certificate cho Server Backup**
```bash
# QUAN TRỌNG: Chứng chỉ hiện tại chỉ cho IP 192.168.1.31
# Trên server backup, bạn PHẢI tạo chứng chỉ mới

# Tạo chứng chỉ mới (thay YOUR_SERVER_IP bằng IP thực)
docker exec ordercheck-app-v2 node create-ssl-cert.js YOUR_SERVER_IP

# Hoặc edit file create-ssl-cert.js để thay đổi IP
```

## 📝 Scripts hữu ích

### **1. Quick Deploy Script**
```bash
#!/bin/bash
# deploy.sh

echo "🚀 Deploying OrderCheck..."

# Pull latest code
git pull origin main

# Rebuild containers
docker-compose down
docker-compose up -d --build

# Wait for services
sleep 30

# Check status
docker-compose ps

echo "✅ Deployment completed!"
echo "🌐 Access: https://$(hostname -I | awk '{print $1}'):3001"
```

### **2. Health Check Script**
```bash
#!/bin/bash
# health-check.sh

echo "🔍 Checking OrderCheck health..."

# Check containers
docker-compose ps

# Check application
curl -k -s -o /dev/null -w "%{http_code}" https://localhost:3001

# Check database
docker exec ordercheck-mongodb-v2 mongosh OrderDetailing --eval "db.accounts.countDocuments()" --quiet

echo "✅ Health check completed!"
```

## 📞 Support

Nếu gặp vấn đề, hãy:

1. **Kiểm tra logs**: `docker-compose logs -f`
2. **Kiểm tra status**: `docker-compose ps`
3. **Kiểm tra resources**: `docker stats`
4. **Restart services**: `docker-compose restart`

---

**🎉 Chúc bạn deploy thành công!**
