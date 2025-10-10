// Script khởi tạo dữ liệu mặc định cho MongoDB Local (không có authentication)
db = db.getSiblingDB('OrderDetailing');

// Xóa dữ liệu cũ (nếu có)
db.accounts.deleteMany({});
db.orders.deleteMany({});
db.masterdatas.deleteMany({});
db.combodatas.deleteMany({});
db.portusages.deleteMany({});

print("🗑️ Đã xóa dữ liệu cũ...");

// Tạo tài khoản mặc định
db.accounts.insertMany([
  {
    username: "admin",
    password: "$2a$10$s3B8juzysM/w2LTg7EzlNecaOLVNvNg95CD1i8t7HsQ6cZI7TIUuW", // password: admin123
    role: "admin",
    machineInfo: {
      hostname: "localhost",
      ipAddress: "127.0.0.1",
      platform: "local",
      lastSeen: new Date()
    },
    scannerPermissions: {
      allowedScanners: [],
      assignedScanner: null,
      port: null,
      allowedPorts: []
    },
    comPorts: [],
    createdAt: new Date()
  },
  {
    username: "nv01",
    password: "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password: 123
    role: "checker",
    machineInfo: {
      hostname: "localhost",
      ipAddress: "127.0.0.1",
      platform: "local",
      lastSeen: new Date()
    },
    scannerPermissions: {
      allowedScanners: [],
      assignedScanner: null,
      port: null,
      allowedPorts: []
    },
    comPorts: [],
    createdAt: new Date()
  },
  {
    username: "nv02",
    password: "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password: 123
    role: "packer",
    machineInfo: {
      hostname: "localhost",
      ipAddress: "127.0.0.1",
      platform: "local",
      lastSeen: new Date()
    },
    scannerPermissions: {
      allowedScanners: [],
      assignedScanner: null,
      port: null,
      allowedPorts: []
    },
    comPorts: [],
    createdAt: new Date()
  },
  {
    username: "user",
    password: "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password: 123
    role: "user",
    machineInfo: {
      hostname: "localhost",
      ipAddress: "127.0.0.1",
      platform: "local",
      lastSeen: new Date()
    },
    scannerPermissions: {
      allowedScanners: [],
      assignedScanner: null,
      port: null,
      allowedPorts: []
    },
    comPorts: [],
    createdAt: new Date()
  }
]);

print("✅ Tài khoản mặc định đã được tạo!");

// Tạo dữ liệu MasterData mẫu
db.masterdatas.insertMany([
  {
    sku: "41-6-200-110",
    mauVai: "Xương Rồng",
    tenPhienBan: "Rèm Giường - Xương Rồng",
    createdAt: new Date(),
    updatedAt: new Date()
  },
  {
    sku: "42-7-300-120",
    mauVai: "Hoa Hồng",
    tenPhienBan: "Rèm Cửa - Hoa Hồng",
    createdAt: new Date(),
    updatedAt: new Date()
  },
  {
    sku: "43-8-400-130",
    mauVai: "Xanh Dương",
    tenPhienBan: "Rèm Phòng - Xanh Dương",
    createdAt: new Date(),
    updatedAt: new Date()
  }
]);

print("✅ MasterData mẫu đã được tạo!");

// Tạo dữ liệu ComboData mẫu
db.combodatas.insertMany([
  {
    comboCode: "COMBO001",
    maHang: "41-6-200-110",
    soLuong: 2,
    createdAt: new Date(),
    updatedAt: new Date()
  },
  {
    comboCode: "COMBO002",
    maHang: "42-7-300-120",
    soLuong: 1,
    createdAt: new Date(),
    updatedAt: new Date()
  }
]);

print("✅ ComboData mẫu đã được tạo!");

// Tạo đơn hàng mẫu
db.orders.insertMany([
  {
    stt: 1,
    maDongGoi: "DG001",
    maVanDon: "SPXVN05180561963A",
    maDonHang: "DH001",
    maHang: "41-6-200-110",
    soLuong: 5,
    importDate: new Date(),
    verified: false,
    verifiedAt: null,
    scannedQuantity: 0,
    checkingBy: null,
    block: false,
    blockedAt: null,
    createdAt: new Date(),
    updatedAt: new Date()
  },
  {
    stt: 2,
    maDongGoi: "DG002",
    maVanDon: "SPXVN05180561963A",
    maDonHang: "DH001",
    maHang: "42-7-300-120",
    soLuong: 3,
    importDate: new Date(),
    verified: false,
    verifiedAt: null,
    scannedQuantity: 0,
    checkingBy: null,
    block: false,
    blockedAt: null,
    createdAt: new Date(),
    updatedAt: new Date()
  }
]);

print("✅ Đơn hàng mẫu đã được tạo!");

// Tạo indexes
db.accounts.createIndex({ username: 1 }, { unique: true });
db.orders.createIndex({ maDonHang: 1 });
db.orders.createIndex({ maVanDon: 1 });
db.orders.createIndex({ maDongGoi: 1 });
db.masterdatas.createIndex({ sku: 1 }, { unique: true });
db.combodatas.createIndex({ comboCode: 1 });
db.portusages.createIndex({ comPort: 1, isActive: 1 });
db.portusages.createIndex({ userId: 1, isActive: 1 });

print("✅ Indexes đã được tạo!");

// Hiển thị thống kê
print("\n📊 Thống kê dữ liệu:");
print("Tài khoản: " + db.accounts.countDocuments());
print("Đơn hàng: " + db.orders.countDocuments());
print("MasterData: " + db.masterdatas.countDocuments());
print("ComboData: " + db.combodatas.countDocuments());

print("\n🎉 Khởi tạo dữ liệu hoàn tất!");
print("Tài khoản đăng nhập:");
print("- admin/admin123 (admin)");
print("- nv01/123 (checker)");
print("- nv02/123 (packer)");
print("- user/123 (user)");
