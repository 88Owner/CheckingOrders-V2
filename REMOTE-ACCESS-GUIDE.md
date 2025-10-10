# Hướng dẫn cấu hình MongoDB Local cho Remote Access

## 🌐 Tổng quan

Tài liệu này hướng dẫn cách cấu hình MongoDB Local để máy khác có thể kết nối từ xa tới server.

## 🔧 Cấu hình Server (Máy chạy MongoDB)

### 1. Docker Compose (Khuyến nghị)

File `docker-compose.yml` đã được cấu hình sẵn:
```yaml
mongodb:
  ports:
    - "0.0.0.0:27017:27017"  # Bind trên tất cả interfaces
  command: mongod --bind_ip_all --auth  # Cho phép remote access và bật auth
```

### 2. Chạy trực tiếp trên máy

Nếu chạy MongoDB trực tiếp trên máy (không dùng Docker):

#### Windows:
```bash
# Tạo file config mongod.cfg
mongod --config "C:\Program Files\MongoDB\Server\7.0\bin\mongod.cfg" --bind_ip_all --auth
```

#### Linux/macOS:
```bash
# Tạo file config /etc/mongod.conf
net:
  port: 27017
  bindIp: 0.0.0.0  # Cho phép kết nối từ tất cả IP

security:
  authorization: enabled
```

## 🔥 Cấu hình Firewall

### Windows:
```powershell
# Mở port 27017 cho inbound connections
New-NetFirewallRule -DisplayName "MongoDB" -Direction Inbound -Protocol TCP -LocalPort 27017 -Action Allow

# Hoặc sử dụng Windows Firewall GUI
# Control Panel > System and Security > Windows Defender Firewall > Advanced Settings
# Inbound Rules > New Rule > Port > TCP > 27017 > Allow
```

### Linux (Ubuntu/Debian):
```bash
# UFW
sudo ufw allow 27017/tcp

# Firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=27017/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p tcp --dport 27017 -j ACCEPT
```

### macOS:
```bash
# Kiểm tra firewall status
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Mở port (nếu cần)
sudo pfctl -f /etc/pf.conf
```

## 🔐 Authentication

**⚠️ Lưu ý**: Cấu hình hiện tại đã tắt authentication để đơn giản hóa kết nối.

### Nếu muốn bật authentication (tùy chọn):
```javascript
// Kết nối MongoDB
mongosh

// Chuyển sang admin database
use admin

// Tạo user với quyền readWrite cho database OrderDetailing
db.createUser({
  user: "remote_user",
  pwd: "remote_password",
  roles: [
    { role: "readWrite", db: "OrderDetailing" },
    { role: "readWrite", db: "admin" }
  ]
})

// Tạo user với quyền full access (nếu cần)
db.createUser({
  user: "admin_remote",
  pwd: "admin_remote_password",
  roles: ["root"]
})
```

## 💻 Cấu hình Client (Máy kết nối từ xa)

### 1. Connection String

```bash
# Thay YOUR_SERVER_IP bằng IP thực của server (không cần authentication)
MONGODB_URI=mongodb://YOUR_SERVER_IP:27017/OrderDetailing

# Nếu có authentication (tùy chọn)
MONGODB_URI=mongodb://admin:password123@YOUR_SERVER_IP:27017/OrderDetailing?authSource=admin
MONGODB_URI=mongodb://remote_user:remote_password@YOUR_SERVER_IP:27017/OrderDetailing?authSource=admin
```

### 2. Test kết nối

```bash
# Sử dụng mongosh (không cần authentication)
mongosh "mongodb://YOUR_SERVER_IP:27017/OrderDetailing"

# Sử dụng mongo (legacy)
mongo "mongodb://YOUR_SERVER_IP:27017/OrderDetailing"

# Nếu có authentication
mongosh "mongodb://admin:password123@YOUR_SERVER_IP:27017/OrderDetailing?authSource=admin"
```

### 3. Test từ Node.js

```javascript
const mongoose = require('mongoose');

// Không cần authentication
const MONGODB_URI = 'mongodb://YOUR_SERVER_IP:27017/OrderDetailing';

// Nếu có authentication
// const MONGODB_URI = 'mongodb://admin:password123@YOUR_SERVER_IP:27017/OrderDetailing?authSource=admin';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Kết nối MongoDB thành công'))
  .catch(err => console.error('❌ Lỗi kết nối MongoDB:', err));
```

## 🌍 Các trường hợp sử dụng

### 1. Trong cùng mạng LAN
```
Server IP: 192.168.1.100
Client có thể kết nối: mongodb://192.168.1.100:27017/OrderDetailing
```

### 2. Qua Internet (cần Port Forwarding)
```
Router: Port Forward 27017 -> Server IP:27017
Client: mongodb://YOUR_PUBLIC_IP:27017/OrderDetailing
```

### 3. VPN Connection
```
Sau khi kết nối VPN, sử dụng IP nội bộ của server
mongodb://10.0.0.100:27017/OrderDetailing
```

## 🔍 Troubleshooting

### 1. Kiểm tra kết nối
```bash
# Test telnet
telnet YOUR_SERVER_IP 27017

# Test với curl
curl -v telnet://YOUR_SERVER_IP:27017

# Test với nmap
nmap -p 27017 YOUR_SERVER_IP
```

### 2. Kiểm tra logs MongoDB
```bash
# Docker
docker logs ordercheck-mongodb-v2

# Trực tiếp
tail -f /var/log/mongodb/mongod.log
```

### 3. Lỗi thường gặp

#### Connection refused:
- Kiểm tra MongoDB có chạy không
- Kiểm tra firewall
- Kiểm tra bind_ip configuration

#### Authentication failed:
- Kiểm tra username/password
- Kiểm tra authSource database
- Kiểm tra user roles

#### Timeout:
- Kiểm tra network connectivity
- Kiểm tra firewall rules
- Kiểm tra MongoDB max connections

## 🛡️ Bảo mật

### 1. Sử dụng SSL/TLS
```yaml
# docker-compose.yml
mongodb:
  volumes:
    - ./ssl:/etc/ssl/mongodb
  command: mongod --bind_ip_all --auth --sslMode requireSSL --sslPEMKeyFile /etc/ssl/mongodb/mongodb.pem
```

### 2. Whitelist IP addresses
```javascript
// Trong MongoDB config
net:
  bindIp: 192.168.1.0/24,10.0.0.0/8  # Chỉ cho phép IP trong range này
```

### 3. Sử dụng VPN
- Không expose MongoDB port ra Internet
- Sử dụng VPN để kết nối an toàn

## 📋 Checklist

### Server:
- [ ] MongoDB bind trên 0.0.0.0 hoặc IP cụ thể
- [ ] Authentication được bật
- [ ] Firewall cho phép port 27017
- [ ] User được tạo với quyền phù hợp

### Client:
- [ ] Connection string đúng format
- [ ] Username/password chính xác
- [ ] Network connectivity tới server
- [ ] Application có thể resolve server IP

### Network:
- [ ] Port forwarding (nếu qua Internet)
- [ ] VPN connection (nếu cần)
- [ ] DNS resolution (nếu dùng domain)
