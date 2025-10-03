# OrderCheck - Hệ thống quản lý đơn hàng và kiểm tra hàng 
### 1. Clone dự án
```bash
git clone <repository-url>
cd OrderCheck
```

### 2. Cài đặt dependencies
```bash
npm install
```

### 3. Cấu hình môi trường
Tạo file `.env`:
```env
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/database
SESSION_SECRET=your-secret-key-here
PORT=3000
```

### 4. Tạo SSL certificate (cho HTTPS)
```bash
node create-ssl-cert.js
```

### 5. Chạy dự án
```bash
node server.js
```

### 6. Truy cập ứng dụng
- **HTTPS**: https://localhost:3000
- **HTTP**: http://localhost:3000
- **Network**: https://192.168.1.31:3000

> ⚠️ **Lưu ý**: Browser sẽ hiện cảnh báo SSL, click "Advanced" → "Proceed"

## 👥 Tài khoản mặc định

| Username | Password | Role   | Mô tả                    |
|----------|----------|--------|--------------------------|
| admin    | admin    | admin  | Quản trị hệ thống        |
| nv01     | 123      | checker| Kiểm tra đơn hàng        |
| nv02     | 123      | packer | Đóng gói hàng hóa        |
| user     | 123      | user   | Người dùng thường        |

## 🔧 Cấu hình COM Port

### 1. Kết nối scanner
- Kết nối scanner qua USB
- Scanner sẽ hiện dưới dạng COM port (COM3, COM4, COM5...)

### 2. Phân quyền COM port
- Admin đăng nhập → Quản lý tài khoản
- Gán COM port cho từng user
- User chỉ có thể sử dụng COM port được phân quyền

### 3. Sử dụng scanner
- User đăng nhập → Trang chính
- Click "🔌 Kết nối COM" → Chọn COM port
- Quét mã vạch → Tự động nhập vào hệ thống

## 📊 Quản lý dữ liệu

### Upload đơn hàng
1. Vào trang **Upload**
2. Chọn file Excel đơn hàng
3. Hệ thống tự động import vào database

### Upload MasterData
1. Vào trang **Upload** → **MasterData**
2. Chọn file Excel với cột: SKU, Màu Vải, Tên Phiên Bản
3. Hệ thống tự động mapping và lưu

### Upload ComboData
1. Vào trang **Upload** → **ComboData**
2. Chọn file Excel với cột: Combo Code, Mã Hàng, Số Lượng
3. Hệ thống tự động tạo combo sản phẩm

## 🔄 Quy trình kiểm tra đơn hàng

### 1. Load đơn hàng
```
Input mã vận đơn → Hệ thống load đơn → Hiển thị danh sách hàng
```

### 2. Quét mã hàng
```
Quét mã hàng → Hệ thống kiểm tra → Cập nhật trạng thái
```

### 3. Xác nhận hoàn thành
```
Quét đủ hàng → Xác nhận đơn → Đánh dấu hoàn thành
```

## 🚨 Xử lý lỗi thường gặp

### Port 3000 đã được sử dụng
```bash
# Tìm process sử dụng port 3000
netstat -ano | findstr :3000

# Kill process
taskkill /PID <process_id> /F
```

### Lỗi kết nối MongoDB
- Kiểm tra `MONGODB_URI` trong file `.env`
- Đảm bảo MongoDB Atlas cho phép kết nối từ IP hiện tại

### Web Serial API không hoạt động
- Sử dụng Chrome/Edge (không hỗ trợ Firefox)
- Truy cập qua HTTPS (không phải HTTP)
- Đảm bảo scanner được kết nối đúng

### Lỗi SSL certificate
```bash
# Tạo lại certificate
node create-ssl-cert.js

# Hoặc chạy HTTP thay vì HTTPS
# Sửa server.js: comment HTTPS, uncomment HTTP
```

## 📱 API Endpoints

### Authentication
- `POST /api/login` - Đăng nhập
- `POST /api/logout` - Đăng xuất
- `GET /api/me` - Thông tin user hiện tại

### Orders
- `GET /api/orders` - Lấy danh sách đơn hàng
- `GET /api/orders/by-van-don/:maVanDon` - Lấy đơn theo mã vận đơn
- `POST /api/scan` - Quét mã hàng
- `POST /api/orders/unblock-van-don` - Unblock đơn hàng

### COM Port
- `GET /api/checker/com-ports` - Lấy danh sách COM port
- `POST /api/claim-port` - Claim COM port
- `POST /api/release-port` - Release COM port
- `POST /api/com-input` - Gửi dữ liệu từ COM port

### Upload
- `POST /api/checker/upload` - Upload file đơn hàng
- `POST /api/checker/upload-masterdata` - Upload MasterData
- `POST /api/checker/upload-combo` - Upload ComboData

## 🔒 Bảo mật

- **JWT Authentication**: Token-based authentication
- **Role-based Access**: Phân quyền theo vai trò
- **HTTPS**: Mã hóa dữ liệu truyền tải
- **Input Validation**: Kiểm tra dữ liệu đầu vào
- **SQL Injection Protection**: Mongoose ODM protection

## 📈 Performance

- **Real-time Updates**: Polling mỗi 5 giây
- **Efficient Queries**: MongoDB indexes
- **Connection Pooling**: Mongoose connection pooling
- **File Upload**: Multer với giới hạn kích thước

## 🧪 Testing

### Test API
```bash
# Test login
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Test upload
curl -X POST http://localhost:3000/api/checker/upload \
  -F "file=@orders.xlsx" \
  -H "Authorization: Bearer <token>"
```

### Test COM Port
1. Kết nối scanner
2. Mở trang https://localhost:3000/debug-client.html
3. Test kết nối COM port

## 📝 Changelog

### v1.0.0 (2025-10-03)
- ✅ Hoàn thiện hệ thống quản lý đơn hàng
- ✅ Tích hợp Web Serial API cho scanner
- ✅ Quản lý COM port với exclusive access
- ✅ Upload và xử lý Excel files
- ✅ Real-time updates và polling
- ✅ Animation đăng nhập
- ✅ Block/unblock đơn hàng
- ✅ MasterData và ComboData management

## 🤝 Đóng góp

1. Fork dự án
2. Tạo feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Mở Pull Request

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

## 👨‍💻 Tác giả

**NNTruong** - [@kantruong11](https://github.com/kantruong11)

## 📞 Liên hệ

- **Email**: [email@example.com]
- **GitHub**: [https://github.com/kantruong11]
- **Project Link**: [https://github.com/kantruong11/OrderCheck]

## 🙏 Lời cảm ơn

- [Express.js](https://expressjs.com/) - Web framework
- [MongoDB](https://www.mongodb.com/) - Database
- [Mongoose](https://mongoosejs.com/) - ODM
- [Web Serial API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Serial_API) - Serial communication

---

**⭐ Nếu dự án hữu ích, hãy cho một star!**
