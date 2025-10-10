# Hướng dẫn Push Code lên GitHub

## Bước 1: Tạo Repository trên GitHub

1. Đăng nhập vào GitHub.com
2. Click **"New repository"** (nút + ở góc trên bên phải)
3. Điền thông tin:
   - **Repository name**: `OrderCheck`
   - **Description**: `Hệ thống quản lý đơn hàng và kiểm tra hàng hóa bằng mã vạch`
   - **Visibility**: Public hoặc Private
   - **Không** tick "Add a README file"
   - **Không** tick "Add .gitignore"
   - **Không** tick "Choose a license"
4. Click **"Create repository"**

## Bước 2: Cập nhật Remote URL

Sau khi tạo repository, GitHub sẽ hiển thị URL. Thay thế `YOUR_USERNAME` bằng username GitHub của bạn:

```bash
git remote set-url origin https://github.com/YOUR_USERNAME/OrderCheck.git
```

Ví dụ: Nếu username là `kantruong11`:
```bash
git remote set-url origin https://github.com/kantruong11/OrderCheck.git
```

## Bước 3: Push Code

```bash
git push -u origin main
```

## Bước 4: Xác thực (nếu cần)

- Nếu được yêu cầu đăng nhập, sử dụng GitHub Personal Access Token
- Hoặc sử dụng GitHub CLI: `gh auth login`

## Files đã được commit:

✅ **42 files** đã được commit
✅ **18,727 lines** code
✅ **README.md** với hướng dẫn đầy đủ
✅ **.gitignore** đã cấu hình
✅ **Dependencies** đã được cài đặt

## Repository Structure:

```
OrderCheck/
├── README.md              # Documentation
├── package.json           # Dependencies
├── server.js              # Main server
├── config.js              # Configuration
├── models/                # Database models
├── routes/                # API routes
├── public/                # Frontend files
├── uploads/               # Upload directory
├── ssl/                   # SSL certificates
└── utils/                 # Utilities
```

## Tính năng chính:

- 🔐 Đăng nhập đa vai trò (Admin, Checker, Packer, User)
- 📦 Quản lý đơn hàng bằng mã vạch
- 🔌 Quản lý COM Port với Web Serial API
- 📊 Upload và xử lý Excel files
- ⚡ Real-time updates
- 🎨 Professional UI với animations
- 🔒 Exclusive COM port access
- 📱 Responsive design

## Cách chạy dự án:

```bash
# Cài đặt dependencies
npm install

# Tạo SSL certificate
node create-ssl-cert.js

# Chạy server
node server.js

# Truy cập: https://localhost:3000
```

## Tài khoản mặc định:

- **admin/admin** (admin)
- **nv01/123** (checker)  
- **nv02/123** (packer)
- **user/123** (user)
