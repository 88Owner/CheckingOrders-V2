/**
 * Tạo hoặc reset user admin (mật khẩu: admin123).
 * Chạy: node scripts/seedAdmin.js
 * Dùng MONGODB_URI trong .env (hoặc biến môi trường đã set sẵn).
 */
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const config = require('../config');
const Account = require('../models/Account');

(async () => {
    try {
        await mongoose.connect(config.MONGODB_URI, {
            serverSelectionTimeoutMS: 15000
        });
        const password = await bcrypt.hash('admin123', 10);
        const doc = await Account.findOneAndUpdate(
            { username: 'admin' },
            {
                $set: {
                    username: 'admin',
                    password,
                    role: 'admin',
                    erpnextEmployeeId: null,
                    erpnextEmployeeName: null
                }
            },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );
        console.log('Đã khởi tạo/cập nhật admin:', doc.username, 'role:', doc.role);
        console.log('Đăng nhập: admin / admin123');
        process.exit(0);
    } catch (e) {
        console.error('Lỗi seed admin:', e.message);
        process.exit(1);
    }
})();
