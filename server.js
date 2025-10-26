// ...existing code...
// Route public lấy danh sách orders không cần xác thực
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const multer = require('multer');
const XLSX = require('xlsx');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const https = require('https');
const fs = require('fs');
const config = require('./config');

// Import models
const Order = require('./models/Order');
const Account = require('./models/Account');
const Machine = require('./models/Machine'); // Thêm model Machine
const DataOrder = require('./models/DataOrder');
const ComboData = require('./models/ComboData');
const ScannerAssignment = require('./models/ScannerAssignment');
const PortUsage = require('./models/PortUsage');
const UserBehaviour = require('./models/UserBehaviour');
const MauVai = require('./models/MauVai');
const KichThuoc = require('./models/KichThuoc');
const comboCache = require('./utils/comboCache');
const SimpleLocking = require('./utils/simpleLocking');
const masterDataUploadRouter = require('./routes/masterDataUpload');
const checkerUploadRouter = require('./routes/checkerUpload');

const app = express();
// Đăng ký router upload sau khi khởi tạo app
app.use(masterDataUploadRouter);
app.use(checkerUploadRouter);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
    secret: config.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: config.MONGODB_URI,
        ttl: 14 * 24 * 60 * 60 // 14 days
    }),
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        maxAge: 14 * 24 * 60 * 60 * 1000, // 14 days
        sameSite: 'lax' // Thêm sameSite để tránh vấn đề với cookie
    },
    name: 'sessionId' // Đặt tên session cookie cụ thể
}));

// JWT middleware for token-based authentication
function authFromToken(req, res, next) {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.substring(7) : null;
    
    if (!token) {
        return res.status(401).json({ success: false, message: 'Thiếu token' });
    }
    
    try {
        const decoded = jwt.verify(token, config.SESSION_SECRET);
        req.authUser = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Token không hợp lệ' });
    }
}

// Login middleware
function requireLogin(req, res, next) {
    console.log('🔍 requireLogin middleware - Session user:', req.session.user);
    console.log('🔍 requireLogin middleware - Session ID:', req.sessionID);
    console.log('🔍 requireLogin middleware - Cookies:', req.headers.cookie);
    
    if (req.session.user) {
        console.log('✅ User authenticated, proceeding...');
        return next();
    }
    console.log('❌ No session user, redirecting to login');
    // Redirect to login page instead of returning JSON
    return res.redirect('/login');
}

// Admin middleware
function requireAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ success: false, message: 'Bạn không có quyền truy cập' });
}

// API login
app.post('/api/login', async (req, res) => {
    try {
    const { username, password } = req.body;
        if (!username || !password) {
            return res.json({ success: false, message: 'Vui lòng nhập đầy đủ thông tin' });
        }

        const account = await Account.findOne({ username });
        if (!account) {
            return res.json({ success: false, message: 'Tài khoản không tồn tại' });
        }

        let isValidPassword = false;
        // Nếu password trong DB là hash bcrypt (bắt đầu bằng $2), dùng bcrypt.compare
        if (typeof account.password === 'string' && account.password.startsWith('$2')) {
            isValidPassword = await bcrypt.compare(password, account.password);
        } else {
            // Nếu password là plain text, so sánh trực tiếp
            isValidPassword = password === account.password;
        }
        if (!isValidPassword) {
            return res.json({ success: false, message: 'Mật khẩu không đúng' });
        }

        // Create JWT token for API access
        const token = jwt.sign(
            { username: account.username, role: account.role },
            config.SESSION_SECRET,
            { expiresIn: '24h' }
        );

        // Create session
        req.session.user = {
            username: account.username,
            role: account.role,
            token: token
        };
        
        console.log('🔐 Login successful - Session created:', req.session.user);

        // Lấy thông tin COM port đã được phân quyền cho user từ collection scannerassignments
        const scannerAssignment = await ScannerAssignment.findOne({ userId: account.username });
        const assignedComPort = scannerAssignment?.comPort || null;
        const allowedPorts = assignedComPort ? [assignedComPort] : [];
        
        res.json({
            success: true,
            message: 'Đăng nhập thành công',
            username: account.username,
            role: account.role,
            token: token,
            assignedComPort: assignedComPort,
            allowedPorts: allowedPorts,
            redirect: account.role === 'admin' ? '/admin' : 
                     (account.role === 'checker' || account.role === 'packer') ? '/checker-home' :
                     account.role === 'warehouse_manager' ? '/warehouse-manager' :
                     account.role === 'warehouse_staff' ? '/warehouse-staff' : '/'
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Lỗi đăng nhập: ' + error.message });
    }
});

// API register (admin only)
app.post('/api/register', requireLogin, requireAdmin, async (req, res) => {
    try {
        const { username, password, role } = req.body;
        
        if (!username || !password || !role) {
            return res.json({ success: false, message: 'Vui lòng nhập đầy đủ thông tin' });
        }

        if (!['user', 'admin', 'packer', 'checker', 'warehouse_manager', 'warehouse_staff'].includes(role)) {
            return res.json({ success: false, message: 'Quyền không hợp lệ' });
        }

        const existingAccount = await Account.findOne({ username });
        if (existingAccount) {
            return res.json({ success: false, message: 'Tài khoản đã tồn tại' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const account = new Account({
            username,
            password: hashedPassword,
            role
        });

        await account.save();

        res.json({ success: true, message: 'Tạo tài khoản thành công' });

    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ success: false, message: 'Lỗi tạo tài khoản: ' + error.message });
    }
});

// API get token for admin
app.get('/api/admin/token', requireLogin, requireAdmin, (req, res) => {
    const token = req.session.user?.token;
    if (!token) {
        return res.status(401).json({ success: false, message: 'Không có token trong session' });
    }
    res.json({ success: true, token: token });
});

// API get accounts (admin only)
app.get('/api/accounts', requireLogin, requireAdmin, async (req, res) => {
    try {
        const accounts = await Account.find({}, { password: 0 });
        
        // Lấy thông tin máy quét để hiển thị
        const scanners = await ScannerAssignment.find({});
        const scannerMap = new Map();
        scanners.forEach(scanner => {
            scannerMap.set(scanner.scannerId, scanner);
        });

        // Enrich account data với thông tin máy quét
        const enrichedAccounts = accounts.map(account => {
            const assignedScannerInfo = account.scannerPermissions?.assignedScanner ? 
                scannerMap.get(account.scannerPermissions.assignedScanner) : null;
            
            const allowedScannersInfo = (account.scannerPermissions?.allowedScanners || []).map(scannerId => 
                scannerMap.get(scannerId)
            ).filter(Boolean);

            return {
                ...account.toObject(),
                assignedScannerInfo,
                allowedScannersInfo
            };
        });

        res.json({ success: true, data: enrichedAccounts });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi lấy danh sách tài khoản: ' + error.message });
    }
});

// Route login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Route admin page
app.get('/admin', requireLogin, requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Route scanner management page (admin only)
app.get('/scanner-management', requireLogin, requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'scanner-management.html'));
});

// Route dashboard page
app.get('/dashboard', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Route checker home page
app.get('/checker-home', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'checker-home.html'));
});

// Route packer home page
app.get('/packer-home', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'packerhome.html'));
});

// API test lấy thông tin cho 1 đơn hàng theo mã vận đơn
app.get('/api/orders/test-van-don/:maVanDon', async (req, res) => {
// Route login page
// ...existing code...
// Đặt các route test sau khi khai báo const app = express();
// API test lấy thông tin cho 1 đơn hàng theo mã hàng (SKU)
    try {
        const maVanDon = req.params.maVanDon;
        const orders = await Order.find({ maVanDon });
        if (!orders.length) return res.json({ success: false, message: 'Không tìm thấy đơn hàng với mã vận đơn này' });
    // Removed duplicate declaration of MasterData
        const skuList = orders.map(o => o.maHang);
        const masterDatas = await MasterData.find({ sku: { $in: skuList } });
        const masterMap = new Map();
        for (const md of masterDatas) masterMap.set(md.sku, md);
        const mappedOrders = orders.map(o => {
            const md = masterMap.get(o.maHang);
            return {
                ...o.toObject(),
                mauVai: md && typeof md.mauVai === 'string' ? md.mauVai : '',
                tenPhienBan: md && typeof md.tenPhienBan === 'string' ? md.tenPhienBan : ''
            };
        });
        res.json({ success: true, maVanDon, orders: mappedOrders });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi test đơn hàng theo mã vận đơn: ' + error.message });
    }
});

// API cập nhật role cho user
app.put('/api/accounts/:id/role', requireLogin, requireAdmin, async (req, res) => {
    try {
        const { role } = req.body;
        const accountId = req.params.id;
        
        console.log(`[UPDATE ROLE] Admin ${req.session.user.username} yêu cầu đổi role cho account ID: ${accountId} -> ${role}`);
        
        if (!role || !['user','admin','packer','checker','warehouse_manager','warehouse_staff'].includes(role)) {
            console.log(`[UPDATE ROLE] Quyền không hợp lệ: ${role}`);
            return res.json({ success: false, message: 'Quyền không hợp lệ' });
        }
        
        const account = await Account.findById(accountId);
        if (!account) {
            console.log(`[UPDATE ROLE] Không tìm thấy account ID: ${accountId}`);
            return res.json({ success: false, message: 'Không tìm thấy tài khoản' });
        }
        
        if (account.username === 'admin') {
            console.log(`[UPDATE ROLE] Không thể đổi quyền tài khoản admin gốc`);
            return res.json({ success: false, message: 'Không thể đổi quyền tài khoản admin gốc' });
        }
        
        const oldRole = account.role;
        account.role = role;
        await account.save();
        
        console.log(`[UPDATE ROLE] Đã save vào database. User: ${account.username}, ${oldRole} -> ${role}`);
        
        // Verify lại từ database để chắc chắn đã update
        const verifyAccount = await Account.findById(accountId);
        console.log(`[UPDATE ROLE] Verify từ DB: role = ${verifyAccount.role}`);
        
        if (verifyAccount.role !== role) {
            console.error(`[UPDATE ROLE] CẢNH BÁO! Role trong DB (${verifyAccount.role}) khác với role mong đợi (${role})`);
            return res.json({
                success: false,
                message: 'Lỗi: Role không được lưu vào database'
            });
        }
        
        console.log(`[UPDATE ROLE] Thành công! Role đã được lưu vào MongoDB`);
        
        // Nếu admin đổi role của chính mình, cập nhật session
        if (req.session.user.username === account.username) {
            req.session.user.role = role;
            console.log(`[UPDATE ROLE] Đã cập nhật session role cho admin hiện tại: ${role}`);
        }
        
        res.json({ 
            success: true, 
            message: `Đã cập nhật quyền của ${account.username} từ ${oldRole.toUpperCase()} thành ${role.toUpperCase()}`,
            data: {
                username: account.username,
                oldRole: oldRole,
                newRole: role,
                verified: true
            }
        });
    } catch (error) {
        console.error(`[UPDATE ROLE] Lỗi:`, error);
        res.status(500).json({ success: false, message: 'Lỗi cập nhật quyền: ' + error.message });
    }
});

// API kiểm tra role của một account (admin only) - for debugging
app.get('/api/accounts/:id/verify-role', requireLogin, requireAdmin, async (req, res) => {
    try {
        const accountId = req.params.id;
        // console.log(`[VERIFY ROLE] Checking account ID: ${accountId}`);
        
        const account = await Account.findById(accountId);
        if (!account) {
            return res.json({ 
                success: false, 
                message: 'Không tìm thấy tài khoản' 
            });
        }
        
        // console.log(`[VERIFY ROLE] Account: ${account.username}, Role: ${account.role}`);
        
        res.json({
            success: true,
            data: {
                _id: account._id,
                username: account.username,
                role: account.role,
                createdAt: account.createdAt,
                scannerPermissions: account.scannerPermissions
            },
            message: `Role hiện tại của ${account.username} là ${account.role.toUpperCase()}`
        });
    } catch (error) {
        console.error(`[VERIFY ROLE] Lỗi:`, error);
        res.status(500).json({ success: false, message: 'Lỗi kiểm tra role: ' + error.message });
    }
});

// API đổi mật khẩu cho user (admin only)
app.post('/api/admin/change-password', requireLogin, requireAdmin, async (req, res) => {
    try {
        console.log('🔑 Change password request received');
        // Avoid logging sensitive fields like passwords
        console.log('Session user:', req.session.user?.username || 'unknown');

        const { accountId, newPassword } = req.body;

        if (!accountId || !newPassword) {
            console.log('❌ Missing required fields');
            return res.json({ success: false, message: 'Vui lòng nhập đầy đủ thông tin' });
        }

        const trimmed = String(newPassword || '').trim();
        if (!trimmed) {
            console.log('❌ Password is empty');
            return res.json({ success: false, message: 'Mật khẩu không được để trống' });
        }

        const account = await Account.findById(accountId);
        if (!account) {
            console.log('❌ Account not found:', accountId);
            return res.json({ success: false, message: 'Không tìm thấy tài khoản' });
        }

        console.log('Found account:', account.username);

        // Hash mật khẩu mới
        const hashedPassword = await bcrypt.hash(trimmed, 10);

        // Cập nhật mật khẩu
        account.password = hashedPassword;
        await account.save();

        console.log('Password updated successfully for user:', account.username);

        // Log hoạt động (do not include password in logs or metadata)
        try {
            await UserBehaviour.create({
                user: req.session.user.username,
                method: 'CHANGE_PASSWORD',
                description: `Admin ${req.session.user.username} đã đổi mật khẩu cho user ${account.username}`,
                metadata: {
                    targetUser: account.username,
                    targetUserId: accountId
                }
            });
            console.log('✅ UserBehaviour logged');
        } catch (logErr) {
            console.warn('⚠️ Failed to log UserBehaviour for CHANGE_PASSWORD:', logErr.message || logErr);
        }

        res.json({ success: true, message: 'Đổi mật khẩu thành công' });
    } catch (error) {
        console.error('❌ Error changing password:', error);
        res.status(500).json({ success: false, message: 'Lỗi đổi mật khẩu: ' + error.message });
    }
});

// API xóa tài khoản (admin only)
app.delete('/api/accounts/:id', requireLogin, requireAdmin, async (req, res) => {
    try {
        const accountId = req.params.id;
        
        const account = await Account.findById(accountId);
        if (!account) {
            return res.json({ success: false, message: 'Không tìm thấy tài khoản' });
        }
        
        // Không cho phép xóa tài khoản admin gốc
        if (account.username === 'admin') {
            return res.json({ success: false, message: 'Không thể xóa tài khoản admin gốc' });
        }
        
        // Xóa tài khoản
        await Account.findByIdAndDelete(accountId);
        
        // Log hoạt động
        try {
            await UserBehaviour.create({
                user: req.session.user.username,
                method: 'DELETE_ACCOUNT',
                description: `Admin ${req.session.user.username} đã xóa tài khoản ${account.username}`,
                metadata: {
                    deletedUser: account.username,
                    deletedUserId: accountId,
                    deletedUserRole: account.role
                }
            });
        } catch (logErr) {
            console.warn('⚠️ Failed to log UserBehaviour for DELETE_ACCOUNT:', logErr.message || logErr);
        }
        
        res.json({ success: true, message: 'Xóa tài khoản thành công' });
    } catch (error) {
        console.error('Error deleting account:', error);
        res.status(500).json({ success: false, message: 'Lỗi xóa tài khoản: ' + error.message });
    }
});

// API cập nhật phân quyền máy quét cho user (admin only)
app.put('/api/accounts/:id/scanner-permissions', requireLogin, requireAdmin, async (req, res) => {
    try {
        const { allowedScanners, assignedScanner, port, allowedPorts } = req.body;
        const account = await Account.findById(req.params.id);
        
        if (!account) {
            return res.json({ success: false, message: 'Không tìm thấy tài khoản' });
        }

        // Validate COM port format nếu có
        if (port && !/^COM\d+$/i.test(port)) {
            return res.json({ 
                success: false, 
                message: 'COM port phải có định dạng COM + số (VD: COM3, COM4)' 
            });
        }

        // Kiểm tra COM port có đang được user khác sử dụng không
        if (port) {
            const otherAssignment = await ScannerAssignment.findOne({ 
                comPort: port.toUpperCase(),
                userId: { $ne: account.username }
            });
            if (otherAssignment) {
                return res.json({ 
                    success: false, 
                    message: `COM port ${port} đang được user ${otherAssignment.userId} sử dụng` 
                });
            }
        }

        // Cập nhật hoặc tạo scanner assignment
        if (port) {
            // Tạo hoặc cập nhật assignment
            await ScannerAssignment.findOneAndUpdate(
                { userId: account.username },
                { 
                    userId: account.username,
                    comPort: port.toUpperCase(),
                    updatedAt: new Date()
                },
                { upsert: true, new: true }
            );
        } else {
            // Xóa assignment nếu không có port
            await ScannerAssignment.findOneAndDelete({ userId: account.username });
        }

        // Cập nhật quyền máy quét trong account (giữ nguyên để tương thích)
        account.scannerPermissions = {
            allowedScanners: allowedScanners || [],
            assignedScanner: assignedScanner || null,
            port: port || null,
            allowedPorts: allowedPorts || []
        };

        await account.save();

        res.json({ 
            success: true, 
            message: 'Đã cập nhật phân quyền máy quét thành công',
            data: {
                username: account.username,
                scannerPermissions: account.scannerPermissions,
                comPort: port
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi cập nhật phân quyền: ' + error.message });
    }
});

// API lấy danh sách cổng port có sẵn cho user (user only)
app.get('/api/ports/available', requireLogin, async (req, res) => {
    try {
        const username = req.session.user.username;
        const account = await Account.findOne({ username });
        
        if (!account) {
            return res.json({ success: false, message: 'Không tìm thấy tài khoản' });
        }

        // Lấy danh sách cổng port được phép sử dụng
        const allowedPorts = account.scannerPermissions?.allowedPorts || [];
        
        if (allowedPorts.length === 0) {
            return res.json({
                success: true,
                data: [],
                message: 'Bạn chưa được phân quyền sử dụng cổng port nào'
            });
        }

        // Kiểm tra trạng thái thực tế của các cổng port
        const availablePorts = [];
        
        for (const portPath of allowedPorts) {
            try {
                // Kiểm tra xem cổng có đang được sử dụng không
                const isInUse = await ScannerAssignment.findOne({ 
                    port: portPath,
                    isActive: true 
                });
                
                availablePorts.push({
                    path: portPath,
                    isAvailable: !isInUse,
                    status: isInUse ? 'in-use' : 'available'
                });
            } catch (error) {
                console.error(`Lỗi kiểm tra cổng ${portPath}:`, error);
                // Vẫn thêm cổng port vào danh sách ngay cả khi có lỗi
                availablePorts.push({
                    path: portPath,
                    isAvailable: true, // Giả định là khả dụng nếu không kiểm tra được
                    status: 'unknown'
                });
            }
        }

        res.json({
            success: true,
            data: availablePorts,
            message: `Có ${availablePorts.length} cổng port khả dụng`
        });
        
    } catch (error) {
        console.error('❌ Lỗi lấy danh sách cổng port:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy danh sách cổng port: ' + error.message
        });
    }
});

// API trả về thông tin user hiện tại
// Hỗn hợp: nếu có JWT thì ưu tiên JWT, nếu không có thì dùng session
app.get('/api/me', async (req, res) => {
    try {
        console.log('🔍 /api/me called - Session user:', req.session.user);
        console.log('🔍 /api/me called - Authorization header:', req.headers.authorization);
        
        let username = null;
        let role = null;

        const auth = req.headers.authorization || '';
        if (auth.startsWith('Bearer ')) {
            try {
                const decoded = jwt.verify(auth.substring(7), config.SESSION_SECRET);
                username = decoded.username;
                role = decoded.role;
                console.log('✅ JWT token valid - Username:', username, 'Role:', role);
            } catch (error) {
                console.log('❌ JWT token invalid:', error.message);
            }
        }
        
        if (!username && req.session.user) {
            username = req.session.user.username;
            role = req.session.user.role;
            console.log('✅ Session user found - Username:', username, 'Role:', role);
        }

        if (!username) {
            console.log('❌ No username found, returning success: false');
            return res.json({ success: false });
        }

        // Lấy thông tin chi tiết từ database bao gồm scanner permissions
        const account = await Account.findOne({ username }, { password: 0 });
        
        if (account) {
            // Kiểm tra xem user có đang sử dụng máy quét ở session khác không
            const currentSessionId = req.sessionID;
            let scannerConflict = null;
            
            if (account.scannerPermissions?.assignedScanner) {
                // Tìm session khác đang sử dụng máy quét này
                const otherAccount = await Account.findOne({
                    'scannerPermissions.assignedScanner': account.scannerPermissions.assignedScanner,
                    username: { $ne: username }
                });
                
                if (otherAccount) {
                    scannerConflict = {
                        message: `Máy quét ${account.scannerPermissions.assignedScanner} đang được ${otherAccount.username} sử dụng`,
                        conflictUser: otherAccount.username,
                        assignedScanner: account.scannerPermissions.assignedScanner
                    };
                    
                    // Reset scanner assignment cho user hiện tại
                    account.scannerPermissions.assignedScanner = null;
                    await account.save();
                }
            }

            return res.json({ 
                success: true, 
                username: account.username, 
                role: account.role,
                scannerPermissions: account.scannerPermissions,
                scannerConflict: scannerConflict
            });
        } else {
            return res.json({ success: true, username, role });
        }
    } catch (error) {
        console.error('Error in /api/me:', error);
        return res.json({ success: false, message: 'Lỗi lấy thông tin user' });
    }
});

// API logout - support session or token-based logout (unblock orders)
app.post('/api/logout', async (req, res) => {
    try {
        // Determine user from session OR token (support per-tab JWT logouts)
        let username = null;
        if (req.session && req.session.user && req.session.user.username) {
            username = req.session.user.username;
        } else {
            const auth = req.headers.authorization || '';
            if (auth.startsWith('Bearer ')) {
                try {
                    const decoded = jwt.verify(auth.substring(7), config.SESSION_SECRET);
                    username = decoded.username;
                } catch (e) {
                    // ignore invalid token
                }
            }
        }

        if (username) {
            // Unblock tất cả đơn hàng mà user này đang check
            const blockedOrders = await Order.find({ checkingBy: username, block: true });
            if (blockedOrders.length > 0) {
                await Order.updateMany(
                    { checkingBy: username, block: true },
                    { 
                        $set: { 
                            checkingBy: null, 
                            block: false, 
                            blockedAt: null,
                            // Reset trạng thái quét khi logout
                            scannedQuantity: 0,
                            verified: false,
                            verifiedAt: null
                        } 
                    }
                );
                // console.log(`User ${username} logout - đã unblock ${blockedOrders.length} đơn hàng và reset trạng thái quét`);
            }
        }

        // If session exists, destroy it. If not (token-only), just return success.
        if (req.session) {
            req.session.destroy((err) => {
                if (err) {
                    console.error('Lỗi xóa session:', err);
                    return res.status(500).json({ success: false, message: 'Lỗi đăng xuất' });
                }
                res.json({ success: true, message: 'Đăng xuất thành công' });
            });
        } else {
            res.json({ success: true, message: 'Đăng xuất thành công' });
        }

    } catch (error) {
        console.error('❌ Lỗi logout:', error);
        res.status(500).json({ success: false, message: 'Lỗi đăng xuất: ' + error.message });
    }
});
// Route trang check đơn hàng
app.get('/check', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'check.html'));
});

// Route trang warehouse manager
app.get('/warehouse-manager', requireWarehouseLogin, (req, res) => {
    console.log('🔍 Warehouse Manager Access - Session user:', req.session.user);
    if (req.session.user.role !== 'warehouse_manager') {
        console.log('❌ Role mismatch - Expected: warehouse_manager, Got:', req.session.user.role);
        return res.redirect('/login');
    }
    console.log('✅ Warehouse Manager access granted');
    res.sendFile(path.join(__dirname, 'public', 'warehouse-manager.html'));
});

// Route trang warehouse staff
app.get('/warehouse-staff', requireWarehouseLogin, (req, res) => {
    console.log('🔍 Warehouse Staff Access - Session user:', req.session.user);
    if (req.session.user.role !== 'warehouse_staff') {
        console.log('❌ Role mismatch - Expected: warehouse_staff, Got:', req.session.user.role);
        return res.redirect('/login');
    }
    console.log('✅ Warehouse Staff access granted');
    res.sendFile(path.join(__dirname, 'public', 'warehouse-staff.html'));
});

// Route debug session
app.get('/debug-session', (req, res) => {
    res.json({
        sessionUser: req.session.user,
        sessionID: req.sessionID,
        cookies: req.headers.cookie,
        sessionStore: req.sessionStore ? 'Available' : 'Not available'
    });
});
// Route chính: điều hướng theo role để đảm bảo checker chỉ làm việc trên 1 màn hình
app.get('/', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/guest');
    }
    const role = req.session.user.role;
    if (role === 'checker' || role === 'packer') {
        return res.redirect('/checker-home');
    }
    if (role === 'admin') {
        return res.redirect('/admin');
    }
    if (role === 'warehouse_manager') {
        return res.redirect('/warehouse-manager');
    }
    if (role === 'warehouse_staff') {
        return res.redirect('/warehouse-staff');
    }
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Route guest: chỉ hiển thị thông báo không có quyền
app.get('/guest', (req, res) => {
    res.send(`
        <div style="text-align:center;padding:80px 0;font-family:Segoe UI,Arial,sans-serif;">
            <h1 style="color:#667eea;font-size:2.5rem;">Chào mừng bạn đến với Shisonson</h1>
            <p style="font-size:1.2rem;color:#333;">Bạn đang truy cập với quyền khách. Vui lòng đăng nhập để sử dụng các chức năng.</p>
            <a href="/login" style="display:inline-block;margin-top:30px;padding:12px 32px;background:#667eea;color:#fff;border-radius:8px;font-weight:bold;text-decoration:none;font-size:1.1rem;">Đăng nhập</a>
        </div>
    `);
});

// Static files
app.use(express.static('public'));

// Cấu hình multer cho upload file
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter: function (req, file, cb) {
        const allowedTypes = ['.xlsx', '.xls'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Chỉ cho phép file Excel (.xlsx, .xls)'));
        }
    },
    limits: {
        fileSize: 10 * 1024 * 1024 // Giới hạn 10MB
    }
});

// Kết nối MongoDB với retry logic
async function connectToMongoDB() {
    try {
        console.log('Đang kết nối MongoDB...');
        await mongoose.connect(config.MONGODB_URI, {
            serverSelectionTimeoutMS: 30000, // 30 giây
            socketTimeoutMS: 45000, // 45 giây
            connectTimeoutMS: 30000, // 30 giây
            maxPoolSize: 10 // Maintain up to 10 socket connections
        });
        console.log('Kết nối MongoDB thành công');
        
        // Khởi tạo cache sau khi kết nối MongoDB thành công
        try {
            await comboCache.refreshCache();
            console.log('✅ ComboData cache initialized');
        } catch (cacheError) {
            console.error('⚠️ ComboData cache initialization failed:', cacheError.message);
        }
        
        return true;
    } catch (error) {
        console.error('Lỗi kết nối MongoDB:', error.message);

        setTimeout(() => {
            console.log('Thử kết nối lại MongoDB...');
            connectToMongoDB();
        }, 5000);
        
        return false;
    }
}

// Khởi tạo kết nối MongoDB
connectToMongoDB();

// Route kiểm tra trạng thái kết nối MongoDB
app.post('/api/logout', async (req, res) => {
    try {
        // Determine user from session OR token (support per-tab JWT logouts)
        let username = null;
        if (req.session && req.session.user && req.session.user.username) {
            username = req.session.user.username;
        } else {
            const auth = req.headers.authorization || '';
            if (auth.startsWith('Bearer ')) {
                try {
                    const decoded = jwt.verify(auth.substring(7), config.SESSION_SECRET);
                    username = decoded.username;
                } catch (e) {
                    // ignore invalid token
                }
            }
        }

        if (username) {
            // Unblock tất cả đơn hàng mà user này đang check
            const blockedOrders = await Order.find({ checkingBy: username, block: true });
            if (blockedOrders.length > 0) {
                await Order.updateMany(
                    { checkingBy: username, block: true },
                    { 
                        $set: { 
                            checkingBy: null, 
                            block: false, 
                            blockedAt: null,
                            // Reset trạng thái quét khi logout
                            scannedQuantity: 0,
                            verified: false,
                            verifiedAt: null
                        } 
                    }
                );
            }
        }

        // If session exists, destroy it. If not (token-only), just return success.
        if (req.session) {
            req.session.destroy((err) => {
                if (err) {
                    console.error('Lỗi xóa session:', err);
                    return res.status(500).json({ success: false, message: 'Lỗi đăng xuất' });
                }
                res.json({ success: true, message: 'Đăng xuất thành công' });
            });
        } else {
            res.json({ success: true, message: 'Đăng xuất thành công' });
        }

    } catch (error) {
        console.error('❌ Lỗi logout:', error);
        res.status(500).json({ success: false, message: 'Lỗi đăng xuất: ' + error.message });
    }
});
app.post('/upload', upload.single('xlsxFile'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'Không có file được upload'
            });
        }

        // Read workbook and parse to JSON rows (header as first row)
        const workbook = XLSX.readFile(req.file.path);
        const sheetName = workbook.SheetNames[0];
        const worksheet = workbook.Sheets[sheetName];
        const jsonData = XLSX.utils.sheet_to_json(worksheet, { header: 1 });

        // Bỏ qua dòng header (dòng đầu tiên) và tìm dòng bắt đầu dữ liệu thực tế
        if (!jsonData || jsonData.length <= 1) {
            // cleanup file
            try { require('fs').unlinkSync(req.file.path); } catch(e) {}
            return res.status(400).json({ success: false, message: 'File Excel trống hoặc chỉ có header' });
        }
        let dataRows = jsonData.slice(1);

        // Lấy tên cột từ header
        const headers = jsonData[0];
        console.log('Headers từ file Excel:', headers);
        console.log('Số dòng dữ liệu ban đầu:', dataRows.length);

        // Tìm dòng đầu tiên có dữ liệu hợp lệ (không phải header, không phải tổng)
        let startIndex = 0;
        for (let i = 0; i < dataRows.length; i++) {
            const row = dataRows[i];
            // Kiểm tra nếu dòng có đủ 6 cột và cột đầu tiên là số
            if (row && row.length >= 6 && typeof row[0] === 'number' && row[0] > 0) {
                startIndex = i;
                break;
            }
        }

        // Lấy dữ liệu từ dòng hợp lệ đầu tiên
        dataRows = dataRows.slice(startIndex);

        console.log('Dòng bắt đầu dữ liệu thực tế:', startIndex);
        console.log('Số dòng dữ liệu thực tế:', dataRows.length);
        console.log('Dòng dữ liệu đầu tiên:', dataRows[0]);
        console.log('Dòng dữ liệu thứ hai:', dataRows[1]);

        // Kiểm tra kết nối MongoDB trước khi thực hiện operations
        if (mongoose.connection.readyState !== 1) {
            throw new Error('MongoDB chưa kết nối. Vui lòng thử lại sau.');
        }

        // Xác định ngày import mới nhất trong orders
        const DataOrder = require('./models/DataOrder');
        const today = new Date();
        today.setHours(0,0,0,0);
        const currentOrders = await Order.find({});
        let backupCount = 0;
        let updateCount = 0;
        let insertCount = 0;
        let skipCount = 0;
        let processLog = [];

        // Nếu có dữ liệu cũ, kiểm tra ngày import
        if (currentOrders.length > 0) {
            // Nếu dữ liệu cũ không phải của hôm nay, backup toàn bộ sang DataOrder và clear orders
            const latestOrder = currentOrders.reduce((max, o) => o.importDate > max.importDate ? o : max, currentOrders[0]);
            const latestDate = new Date(latestOrder.importDate);
            latestDate.setHours(0,0,0,0);
            if (latestDate.getTime() < today.getTime()) {
                // Backup toàn bộ
                const backupOrders = currentOrders.map(order => {
                    const obj = order.toObject();
                    obj.archivedAt = new Date();
                    delete obj._id;
                    return obj;
                });
                await DataOrder.insertMany(backupOrders);
                backupCount = backupOrders.length;
                processLog.push(`Đã backup ${backupCount} đơn hàng sang DataOrder.`);
                await Order.deleteMany({});
                processLog.push('Đã xóa toàn bộ đơn hàng cũ trong orders.');
            }
        }

        // Chuẩn hóa dữ liệu từ file
        const orders = dataRows.map((row, index) => {
            const stt = parseInt(row[0]) || index + 1;
            const maDongGoi = row[1] || '';
            const maVanDon = row[2] || '';
            const maDonHang = row[3] || '';
            const maHang = row[4] || '';
            const soLuong = parseInt(row[5]) || 1;
            return {
                stt,
                maDongGoi,
                maVanDon,
                maDonHang,
                maHang,
                soLuong,
                importDate: today
            };
        }).filter(order => {
            return order.maDongGoi && 
                   order.maVanDon && 
                   order.maDonHang && 
                   order.maHang && 
                   order.maDongGoi.trim() !== '' && 
                   order.maVanDon.trim() !== '' && 
                   order.maDonHang.trim() !== '' && 
                   order.maHang.trim() !== '' &&
                   order.stt > 0;
        });

        // Tối ưu: Đọc toàn bộ orders hiện tại vào Map để tra cứu nhanh
        const existedOrdersArr = await Order.find({});
        const existedOrdersMap = new Map();
        existedOrdersArr.forEach(o => {
            existedOrdersMap.set(`${o.maDonHang}-${o.maHang}`, o);
        });

        // Gom các thao tác bulk
        const bulkOps = [];
        for (const order of orders) {
            const key = `${order.maDonHang}-${order.maHang}`;
            const existed = existedOrdersMap.get(key);
            if (!existed) {
                // Chưa có đơn hàng -> Insert mới
                bulkOps.push({ insertOne: { document: order } });
                insertCount++;
                processLog.push(`Thêm mới đơn hàng: ${order.maDonHang} - ${order.maHang}`);
            } else {
                // Đã có đơn hàng -> Kiểm tra logic cập nhật
                if (existed.verified === true) {
                    // Đơn đã verified = true -> Không được cập nhật
                    skipCount++;
                    processLog.push(`Bỏ qua đơn đã hoàn thành: ${order.maDonHang} - ${order.maHang} (verified = true)`);
                } else {
                    // Đơn chưa verified = false -> Kiểm tra có thay đổi không
                    if (existed.soLuong !== order.soLuong || existed.maDongGoi !== order.maDongGoi || existed.maVanDon !== order.maVanDon) {
                        bulkOps.push({
                            updateOne: {
                                filter: { _id: existed._id },
                                update: {
                                    $set: {
                                        stt: order.stt,
                                        maDongGoi: order.maDongGoi,
                                        maVanDon: order.maVanDon,
                                        soLuong: order.soLuong,
                                        importDate: today
                                    }
                                }
                            }
                        });
                        updateCount++;
                        processLog.push(`Cập nhật đơn hàng chưa hoàn thành: ${order.maDonHang} - ${order.maHang}`);
                    } else {
                        skipCount++;
                        processLog.push(`Giữ nguyên đơn hàng: ${order.maDonHang} - ${order.maHang}`);
                    }
                }
            }
        }

        // Thực hiện bulkWrite nếu có thao tác
        if (bulkOps.length > 0) {
            await Order.bulkWrite(bulkOps);
        }

        // Xóa file tạm
        fs.unlinkSync(req.file.path);

        res.json({
            success: true,
            message: `Import thành công! Backup: ${backupCount}, Thêm mới: ${insertCount}, Cập nhật: ${updateCount}, Giữ nguyên: ${skipCount}`,
            data: {
                backupCount,
                insertCount,
                updateCount,
                skipCount,
                processLog,
                importTime: new Date().toLocaleString('vi-VN'),
                fileName: req.file.originalname
            }
        });

    } catch (error) {
        console.error('❌ Lỗi xử lý file:', error);

        // Xóa file tạm nếu có lỗi
        if (req.file) {
            try {
                fs.unlinkSync(req.file.path);
            } catch (deleteError) {
                console.log('Không thể xóa file tạm:', deleteError.message);
            }
        }

        let errorMessage = 'Lỗi xử lý file: ' + error.message;

        // Xử lý các lỗi cụ thể
        if (error.message.includes('buffering timed out')) {
            errorMessage = '❌ Lỗi kết nối MongoDB: Timeout. Vui lòng kiểm tra kết nối internet và thử lại.';
        } else if (error.message.includes('Could not connect to any servers')) {
            errorMessage = '❌ Lỗi kết nối MongoDB: Không thể kết nối đến server. Vui lòng kiểm tra IP whitelist trong MongoDB Atlas.';
        }

        res.status(500).json({
            success: false,
            message: errorMessage
        });
    }
});

// Middleware đặc biệt cho warehouse routes
function requireWarehouseLogin(req, res, next) {
    console.log('🏭 Warehouse Login Check - Session user:', req.session.user);
    console.log('🏭 Warehouse Login Check - Session ID:', req.sessionID);
    console.log('🏭 Warehouse Login Check - Cookies:', req.headers.cookie);
    
    if (!req.session.user) {
        console.log('❌ No session user in warehouse middleware');
        return res.redirect('/login');
    }
    
    console.log('✅ Session user found in warehouse middleware:', req.session.user);
    return next();
}

// Middleware kiểm tra quyền warehouse manager
function requireWarehouseManager(req, res, next) {
    if (req.session.user && req.session.user.role === 'warehouse_manager') {
        return next();
    }
    return res.status(403).json({ success: false, message: 'Bạn không có quyền truy cập' });
}

// Middleware kiểm tra quyền warehouse staff hoặc manager
function requireWarehouseAccess(req, res, next) {
    if (req.session.user && (req.session.user.role === 'warehouse_manager' || req.session.user.role === 'warehouse_staff')) {
        return next();
    }
    return res.status(403).json({ success: false, message: 'Bạn không có quyền truy cập' });
}

// Route upload file Mẫu vải
app.post('/api/upload-mau-vai', requireLogin, requireWarehouseManager, upload.single('xlsxFile'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'Không có file được upload'
            });
        }

        // Read workbook and parse to JSON rows
        const workbook = XLSX.readFile(req.file.path);
        const sheetName = workbook.SheetNames[0];
        const worksheet = workbook.Sheets[sheetName];
        const jsonData = XLSX.utils.sheet_to_json(worksheet, { header: 1 });

        if (!jsonData || jsonData.length <= 1) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ success: false, message: 'File Excel trống hoặc chỉ có header' });
        }

        // Bỏ qua dòng header và lấy dữ liệu
        const dataRows = jsonData.slice(1).filter(row => row[0] && row[1]); // MaMau và TenMau không được rỗng

        if (dataRows.length === 0) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ success: false, message: 'Không có dữ liệu hợp lệ trong file' });
        }

        // Kiểm tra kết nối MongoDB
        if (mongoose.connection.readyState !== 1) {
            throw new Error('MongoDB chưa kết nối. Vui lòng thử lại sau.');
        }

        // Chuẩn hóa dữ liệu
        const mauVaiData = dataRows.map((row, index) => ({
            maMau: String(row[0] || '').trim(),
            tenMau: String(row[1] || '').trim(),
            createdBy: req.session.user.username
        })).filter(item => item.maMau && item.tenMau);

        if (mauVaiData.length === 0) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ success: false, message: 'Không có dữ liệu hợp lệ sau khi chuẩn hóa' });
        }

        // Xử lý upsert: update nếu có, thêm mới nếu chưa có
        let insertedCount = 0;
        let updatedCount = 0;
        const processedData = [];

        for (const item of mauVaiData) {
            try {
                const result = await MauVai.findOneAndUpdate(
                    { maMau: item.maMau }, // Tìm theo maMau
                    {
                        $set: {
                            tenMau: item.tenMau,
                            createdBy: item.createdBy,
                            importDate: new Date()
                        }
                    },
                    { 
                        upsert: true, // Tạo mới nếu không tìm thấy
                        new: true, // Trả về document sau khi update
                        runValidators: true
                    }
                );
                
                if (result.isNew) {
                    insertedCount++;
                } else {
                    updatedCount++;
                }
                
                processedData.push(result);
            } catch (error) {
                console.error('Error processing item:', item, error);
                // Tiếp tục với item tiếp theo
            }
        }

        // Xóa file tạm
        fs.unlinkSync(req.file.path);

        res.json({
            success: true,
            message: `Import thành công! Thêm mới: ${insertedCount}, Cập nhật: ${updatedCount}`,
            data: processedData.slice(0, 10) // Trả về 10 bản ghi đầu để preview
        });

    } catch (error) {
        console.error('❌ Lỗi xử lý file Mẫu vải:', error);

        // Xóa file tạm nếu có lỗi
        if (req.file) {
            try {
                fs.unlinkSync(req.file.path);
            } catch (deleteError) {
                console.log('Không thể xóa file tạm:', deleteError.message);
            }
        }

        res.status(500).json({
            success: false,
            message: 'Lỗi xử lý file Mẫu vải: ' + error.message
        });
    }
});

// Route upload file Kích thước
app.post('/api/upload-kich-thuoc', requireLogin, requireWarehouseManager, upload.single('xlsxFile'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'Không có file được upload'
            });
        }

        // Read workbook and parse to JSON rows
        const workbook = XLSX.readFile(req.file.path);
        const sheetName = workbook.SheetNames[0];
        const worksheet = workbook.Sheets[sheetName];
        const jsonData = XLSX.utils.sheet_to_json(worksheet, { header: 1 });

        if (!jsonData || jsonData.length <= 1) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ success: false, message: 'File Excel trống hoặc chỉ có header' });
        }

        // Bỏ qua dòng header và lấy dữ liệu
        const dataRows = jsonData.slice(1).filter(row => row[0] && row[1] && row[2]); // Sz_SKU, KichThuoc, DienTich không được rỗng

        if (dataRows.length === 0) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ success: false, message: 'Không có dữ liệu hợp lệ trong file' });
        }

        // Kiểm tra kết nối MongoDB
        if (mongoose.connection.readyState !== 1) {
            throw new Error('MongoDB chưa kết nối. Vui lòng thử lại sau.');
        }

        // Chuẩn hóa dữ liệu
        const kichThuocData = dataRows.map((row, index) => ({
            szSku: String(row[0] || '').trim(),
            kichThuoc: String(row[1] || '').trim(),
            dienTich: parseFloat(row[2]) || 0,
            createdBy: req.session.user.username
        })).filter(item => item.szSku && item.kichThuoc && item.dienTich > 0);

        if (kichThuocData.length === 0) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ success: false, message: 'Không có dữ liệu hợp lệ sau khi chuẩn hóa' });
        }

        // Xử lý upsert: update nếu có, thêm mới nếu chưa có
        let insertedCount = 0;
        let updatedCount = 0;
        const processedData = [];

        for (const item of kichThuocData) {
            try {
                const result = await KichThuoc.findOneAndUpdate(
                    { szSku: item.szSku }, // Tìm theo szSku
                    {
                        $set: {
                            kichThuoc: item.kichThuoc,
                            dienTich: item.dienTich,
                            createdBy: item.createdBy,
                            importDate: new Date()
                        }
                    },
                    { 
                        upsert: true, // Tạo mới nếu không tìm thấy
                        new: true, // Trả về document sau khi update
                        runValidators: true
                    }
                );
                
                if (result.isNew) {
                    insertedCount++;
                } else {
                    updatedCount++;
                }
                
                processedData.push(result);
            } catch (error) {
                console.error('Error processing item:', item, error);
                // Tiếp tục với item tiếp theo
            }
        }

        // Xóa file tạm
        fs.unlinkSync(req.file.path);

        res.json({
            success: true,
            message: `Import thành công! Thêm mới: ${insertedCount}, Cập nhật: ${updatedCount}`,
            data: processedData.slice(0, 10) // Trả về 10 bản ghi đầu để preview
        });

    } catch (error) {
        console.error('❌ Lỗi xử lý file Kích thước:', error);

        // Xóa file tạm nếu có lỗi
        if (req.file) {
            try {
                fs.unlinkSync(req.file.path);
            } catch (deleteError) {
                console.log('Không thể xóa file tạm:', deleteError.message);
            }
        }

        res.status(500).json({
            success: false,
            message: 'Lỗi xử lý file Kích thước: ' + error.message
        });
    }
});

// Route xuất file nhập phôi
app.get('/api/export-nhap-phoi', requireLogin, requireWarehouseAccess, async (req, res) => {
    try {
        // Kiểm tra kết nối MongoDB
        if (mongoose.connection.readyState !== 1) {
            throw new Error('MongoDB chưa kết nối. Vui lòng thử lại sau.');
        }

        // Lấy dữ liệu từ các collection
        const [mauVaiData, kichThuocData, ordersData] = await Promise.all([
            MauVai.find({}).sort({ maMau: 1 }),
            KichThuoc.find({}).sort({ szSku: 1 }),
            Order.find({}).sort({ stt: 1 })
        ]);

        // Tạo workbook mới
        const workbook = XLSX.utils.book_new();

        // Sheet 1: Mẫu vải
        if (mauVaiData.length > 0) {
            const mauVaiSheet = XLSX.utils.json_to_sheet(mauVaiData.map(item => ({
                'Mã mẫu': item.maMau,
                'Tên mẫu': item.tenMau,
                'Ngày import': new Date(item.importDate).toLocaleDateString('vi-VN'),
                'Người tạo': item.createdBy || ''
            })));
            XLSX.utils.book_append_sheet(workbook, mauVaiSheet, 'Mẫu vải');
        }

        // Sheet 2: Kích thước
        if (kichThuocData.length > 0) {
            const kichThuocSheet = XLSX.utils.json_to_sheet(kichThuocData.map(item => ({
                'Sz_SKU': item.szSku,
                'Kích thước': item.kichThuoc,
                'Diện tích': item.dienTich,
                'Ngày import': new Date(item.importDate).toLocaleDateString('vi-VN'),
                'Người tạo': item.createdBy || ''
            })));
            XLSX.utils.book_append_sheet(workbook, kichThuocSheet, 'Kích thước');
        }

        // Sheet 3: Đơn hàng
        if (ordersData.length > 0) {
            const ordersSheet = XLSX.utils.json_to_sheet(ordersData.map(item => ({
                'STT': item.stt,
                'Mã đóng gói': item.maDongGoi,
                'Mã vận đơn': item.maVanDon,
                'Mã đơn hàng': item.maDonHang,
                'Mã hàng': item.maHang,
                'Số lượng': item.soLuong,
                'Trạng thái': item.verified ? 'Đã xác nhận' : 'Chưa xác nhận',
                'Số lượng đã quét': item.scannedQuantity || 0,
                'Người kiểm tra': item.checkingBy || '',
                'Ngày xác nhận': item.verifiedAt ? new Date(item.verifiedAt).toLocaleDateString('vi-VN') : '',
                'Ngày import': new Date(item.importDate).toLocaleDateString('vi-VN')
            })));
            XLSX.utils.book_append_sheet(workbook, ordersSheet, 'Đơn hàng');
        }

        // Sheet 4: Tổng hợp
        const summaryData = [
            {
                'Loại dữ liệu': 'Mẫu vải',
                'Số lượng': mauVaiData.length,
                'Ghi chú': 'Dữ liệu mẫu vải đã import'
            },
            {
                'Loại dữ liệu': 'Kích thước',
                'Số lượng': kichThuocData.length,
                'Ghi chú': 'Dữ liệu kích thước đã import'
            },
            {
                'Loại dữ liệu': 'Đơn hàng',
                'Số lượng': ordersData.length,
                'Ghi chú': 'Tổng số đơn hàng trong hệ thống'
            },
            {
                'Loại dữ liệu': 'Đơn hàng đã xác nhận',
                'Số lượng': ordersData.filter(o => o.verified).length,
                'Ghi chú': 'Số đơn hàng đã được kiểm tra'
            },
            {
                'Loại dữ liệu': 'Đơn hàng chưa xác nhận',
                'Số lượng': ordersData.filter(o => !o.verified).length,
                'Ghi chú': 'Số đơn hàng chưa được kiểm tra'
            }
        ];

        const summarySheet = XLSX.utils.json_to_sheet(summaryData);
        XLSX.utils.book_append_sheet(workbook, summarySheet, 'Tổng hợp');

        // Tạo buffer từ workbook
        const buffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });

        // Set headers để download file
        const fileName = `NhapPhoi_${new Date().toISOString().split('T')[0]}.xlsx`;
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        res.setHeader('Content-Length', buffer.length);

        // Gửi file
        res.send(buffer);

    } catch (error) {
        console.error('❌ Lỗi xuất file nhập phôi:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi xuất file nhập phôi: ' + error.message
        });
    }
});

// Route lấy danh sách orders
const MasterData = require('./models/MasterData');
app.get('/api/orders', authFromToken, async (req, res) => {
    try {
        const limit = Number(req.query.limit) || 1000;
        const orders = await Order.find({}).limit(limit);
        // Map MasterData theo cả SKU và Mã Hàng
        const skuList = orders.map(o => o.maHang).filter(Boolean);
        const masterDatas = await MasterData.find({ sku: { $in: skuList } });
        const masterMap = new Map();
        for (const md of masterDatas) {
            if (md.sku) masterMap.set(md.sku, md);
        }
        const mappedOrders = orders.map(o => {
            // Mapping MasterData theo SKU = maHang
            let md = masterMap.get(o.maHang);
            return {
                ...o.toObject(),
                mauVai: md && typeof md.mauVai === 'string' ? md.mauVai : '',
                tenPhienBan: md && typeof md.tenPhienBan === 'string' ? md.tenPhienBan : '',
                masterData: md || null
            };
        });
        res.json({ success: true, data: { orders: mappedOrders } });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi lấy đơn hàng: ' + error.message });
    }
});

// Route xóa tất cả orders
app.delete('/api/orders', authFromToken, async (req, res) => {
    // Check if user is admin
    if (req.authUser.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Chỉ admin mới có quyền xóa tất cả đơn hàng' });
    }
    try {
        // Kiểm tra kết nối MongoDB
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({
                success: false,
                message: 'MongoDB chưa kết nối. Vui lòng thử lại sau.'
            });
        }

        const result = await Order.deleteMany({});
        res.json({
            success: true,
            message: `Đã xóa ${result.deletedCount} đơn hàng`,
            deletedCount: result.deletedCount
        });
    } catch (error) {
        console.error('❌ Lỗi xóa orders:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi xóa đơn hàng: ' + error.message
        });
    }
});

// Route tìm đơn hàng theo mã vận đơn
app.get('/api/orders/by-van-don/:maVanDon', authFromToken, async (req, res) => {
    try {
        
        // Kiểm tra kết nối MongoDB
        if (mongoose.connection.readyState !== 1) {
            console.log('❌ MongoDB not connected');
            return res.status(503).json({
                success: false,
                message: 'MongoDB chưa kết nối. Vui lòng thử lại sau.'
            });
        }

        const { maVanDon } = req.params;
        
        // Lấy user từ session
        const userId = req.authUser.username;

        // Tìm tất cả đơn hàng trong mã vận đơn
        const orders = await Order.find({ maVanDon });
        
        // Map ComboData để convert mã combo thành mã base nếu cần
        const ComboData = require('./models/ComboData');
        let comboDatas = [];
        try {
            comboDatas = await comboCache.getAllCombos();
        } catch (error) {
            console.log('ComboData collection không tồn tại hoặc rỗng:', error.message);
        }
        const comboMap = new Map();
        // comboDatas là Map từ cache, cần flatten thành array
        const comboArray = [];
        for (const combos of comboDatas.values()) {
            comboArray.push(...combos);
        }
        // Tạo map theo comboCode để lấy tất cả sản phẩm trong combo
        for (const cd of comboArray) {
            if (cd && cd.comboCode) {
                if (!comboMap.has(cd.comboCode)) {
                    comboMap.set(cd.comboCode, []);
                }
                comboMap.get(cd.comboCode).push(cd);
            }
        }
        
        // Tách combo thành các SKU riêng biệt và cộng số lượng nếu trùng
        const skuMap = new Map(); // Map để cộng số lượng SKU trùng
        
        orders.forEach(o => {
            const combos = comboMap.get(o.maHang);
            
            if (combos && combos.length > 0) {
                // Nếu là combo: tách thành các SKU riêng biệt
                combos.forEach(combo => {
                    const skuKey = combo.maHang;
                    const quantity = o.soLuong * combo.soLuong;
                    
                    if (skuMap.has(skuKey)) {
                        // SKU đã tồn tại, cộng số lượng
                        skuMap.get(skuKey).quantity += quantity;
                        skuMap.get(skuKey).sources.push({
                            type: 'combo',
                            comboCode: o.maHang,
                            orderQuantity: o.soLuong,
                            comboItemQuantity: combo.soLuong
                        });
                    } else {
                        // SKU mới
                        skuMap.set(skuKey, {
                            maHang: skuKey,
                            quantity: quantity,
                            sources: [{
                                type: 'combo',
                                comboCode: o.maHang,
                                orderQuantity: o.soLuong,
                                comboItemQuantity: combo.soLuong
                            }]
                        });
                    }
                });
                
            } else {
                // Nếu không phải combo: thêm SKU trực tiếp
                const skuKey = o.maHang;
                const quantity = o.soLuong;
                
                if (skuMap.has(skuKey)) {
                    // SKU đã tồn tại, cộng số lượng
                    skuMap.get(skuKey).quantity += quantity;
                    skuMap.get(skuKey).sources.push({
                        type: 'direct',
                        orderQuantity: quantity
                    });
                } else {
                    // SKU mới
                    skuMap.set(skuKey, {
                        maHang: skuKey,
                        quantity: quantity,
                        sources: [{
                            type: 'direct',
                            orderQuantity: quantity
                        }]
                    });
                }
            }
        });
        
        // Chuyển Map thành array và sắp xếp theo STT
        const processedOrders = Array.from(skuMap.values()).map((sku, index) => {
            const directSources = sku.sources.filter(s => s.type === 'direct');
            const comboSources = sku.sources.filter(s => s.type === 'combo');
            
            return {
                stt: index + 1,
                maDongGoi: orders[0]?.maDongGoi || '', // Lấy từ order đầu tiên
                maVanDon: orders[0]?.maVanDon || '', // Lấy từ order đầu tiên
                maDonHang: orders[0]?.maDonHang || '', // Lấy từ order đầu tiên
                maHang: sku.maHang,
                soLuong: sku.quantity,
                displayMaHang: sku.maHang,
                displaySoLuong: sku.quantity,
                isCombo: false, // Đã tách thành SKU riêng biệt
                isCombined: directSources.length > 0 && comboSources.length > 0, // Có cả đơn riêng và combo
                sources: sku.sources,
                importDate: orders[0]?.importDate || new Date(),
                verified: false,
                verifiedAt: null,
                scannedQuantity: 0,
                checkingBy: null,
                block: false,
                blockedAt: null
            };
        });
        
        // Lấy thông tin MasterData cho tất cả mã hàng
        const allSkuList = [...new Set(processedOrders.map(o => o.maHang))];
        
        // Kiểm tra tổng số MasterData trong collection
        const totalMasterData = await MasterData.countDocuments();
        
        let masterDatas = [];
        try {
            masterDatas = await MasterData.find({ sku: { $in: allSkuList } });
        } catch (error) {
            console.error('❌ [MASTERDATA] Error loading MasterData:', error);
            masterDatas = [];
        }
        
        const masterMap = new Map();
        for (const md of masterDatas) {
            if (md.sku) {
                masterMap.set(md.sku, md);
            }
        }
        
        const mappedOrders = processedOrders.map(o => {
            // Tìm MasterData theo maHang (mã SKU riêng biệt)
            const md = masterMap.get(o.maHang);
            
            return {
                ...o, // o đã là plain object từ processedOrders
                mauVai: md && typeof md.mauVai === 'string' ? md.mauVai : '',
                tenPhienBan: md && typeof md.tenPhienBan === 'string' ? md.tenPhienBan : '',
                // Thông tin nguồn gốc của SKU
                sourceInfo: {
                    isCombined: o.isCombined,
                    sources: o.sources,
                    totalQuantity: o.quantity
                }
            };
        });

        if (orders.length === 0) {
            console.log(`❌ No orders found for maVanDon: ${maVanDon}`);
            return res.json({
                success: false,
                message: 'Không tìm thấy đơn hàng với mã vận đơn này',
                data: { items: [], totalItems: 0 }
            });
        }

        // Kiểm tra xem tất cả đơn hàng đã hoàn thành chưa
        const allCompleted = orders.every(order => order.verified === true);
        if (allCompleted) {
            return res.json({
                success: false,
                message: 'Đơn hàng đã được quét hoàn tất',
                data: { items: [], totalItems: 0, allCompleted: true }
            });
        }

        // Kiểm tra xem có đơn hàng nào đang bị block bởi người khác không
        const now = new Date();
        const blockTimeout = 10 * 60 * 1000; // 10 phút
        let hasBlockedOrders = false;
        let blockedBy = '';

        for (const order of orders) {
            // Kiểm tra timeout - nếu block quá 10 phút thì tự động unblock
            if (order.block && order.blockedAt && (now - order.blockedAt) > blockTimeout) {
                order.block = false;
                order.checkingBy = null;
                order.blockedAt = null;
                // Reset trạng thái quét khi timeout auto-unblock
                order.scannedQuantity = 0;
                order.verified = false;
                order.verifiedAt = null;
                await order.save();
                console.log(`Tự động unblock đơn hàng ${order.maHang} do timeout và reset trạng thái quét`);
            }

            // Nếu có đơn hàng đang bị block bởi người khác
            if (order.block && order.checkingBy && order.checkingBy !== userId) {
                hasBlockedOrders = true;
                blockedBy = order.checkingBy;
                break;
            }
        }

        // Nếu có đơn hàng bị block bởi người khác, trả về lỗi
        if (hasBlockedOrders) {
            return res.json({
                success: false,
                blocked: true,
                message: `Đơn vận đơn ${maVanDon} đang được ${blockedBy} kiểm tra. Vui lòng chờ ${blockedBy} hoàn thành hoặc thử lại sau.`
            });
        }

        // Block tất cả đơn hàng trong mã vận đơn cho user hiện tại với optimistic locking
        const orderIds = orders.map(order => order._id);
        const lockResult = await SimpleLocking.blockOrders(orderIds, userId);
        
        if (!lockResult.success || lockResult.errors.length > 0) {
            console.error('❌ [LOCK-ERROR] Failed to lock orders:', lockResult.errors);
            return res.status(500).json({
                success: false,
                message: 'Lỗi khóa đơn hàng: ' + lockResult.errors.join(', ')
            });
        }
        
        console.log(`✅ Successfully blocked ${lockResult.blockedCount} orders for user ${userId}`);


        // Lưu user behaviour cho việc load order
        try {
            const UserBehaviour = require('./models/UserBehaviour');
            const behaviour = new UserBehaviour({
                user: userId,
                method: 'scanner',
                description: `Load đơn hàng: ${maVanDon} - ${orders.length} mặt hàng`,
                metadata: {
                    maVanDon,
                    orderCount: orders.length,
                    action: 'load_order'
                },
                ipAddress: req.ip || req.connection.remoteAddress,
                userAgent: req.get('User-Agent') || '',
                sessionId: req.sessionID || ''
            });
            await behaviour.save();
        } catch (behaviourError) {
            console.log('Lỗi lưu user behaviour:', behaviourError.message);
        }

        // Kiểm tra trạng thái hoàn thành của toàn bộ maVanDon
        // Đơn hoàn thành khi: tất cả maHang đã verified = true (đã confirm đơn)
        const verifiedOrders = await Order.find({ maVanDon, verified: true });
        const allItemsCompleted = orders.length > 0 && orders.length === verifiedOrders.length;
        const isVanDonCompleted = allItemsCompleted;

        // Trả về đúng cấu trúc cho checker: orders (full info)
        res.json({
            success: true,
            message: `Tìm thấy ${mappedOrders.length} đơn hàng trong đơn vận đơn ${maVanDon}`,
            data: {
                orders: mappedOrders,
                totalItems: mappedOrders.length,
                maVanDon,
                verified: isVanDonCompleted,
                completedItems: verifiedOrders.length,
                allItemsCompleted: allItemsCompleted
            }
        });

    } catch (error) {
        console.error('❌ Lỗi tìm đơn hàng:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi tìm đơn hàng: ' + error.message
        });
    }
});

// Route lưu user behaviour
app.post('/api/user-behaviour', authFromToken, async (req, res) => {
    try {
        const UserBehaviour = require('./models/UserBehaviour');
        const { method, description, metadata = {} } = req.body;
        
        if (!method || !description) {
            return res.status(400).json({
                success: false,
                message: 'Method và description là bắt buộc'
            });
        }
        
        const behaviour = new UserBehaviour({
            user: req.authUser.username,
            method,
            description,
            metadata,
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent') || '',
            sessionId: req.sessionID || ''
        });
        
        await behaviour.save();
        
        res.json({
            success: true,
            message: 'Đã lưu user behaviour',
            data: { id: behaviour._id }
        });
        
    } catch (error) {
        console.error('❌ Lỗi lưu user behaviour:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lưu user behaviour: ' + error.message
        });
    }
});

// Route lấy user behaviour (cho admin)
app.get('/api/user-behaviour', authFromToken, async (req, res) => {
    try {
        const UserBehaviour = require('./models/UserBehaviour');
        const { user, method, limit = 100, page = 1 } = req.query;
        
        // Admin có thể xem tất cả, checker chỉ có thể xem của mình
        const query = {};
        if (req.authUser.role !== 'admin') {
            // Checker chỉ có thể xem behaviour của chính mình
            query.user = req.authUser.username;
        } else {
            // Admin có thể filter theo user khác
            if (user) query.user = user;
        }
        if (method) query.method = method;
        
        const skip = (page - 1) * limit;
        const behaviours = await UserBehaviour.find(query)
            .sort({ time: -1 })
            .limit(parseInt(limit))
            .skip(skip);
        
        const total = await UserBehaviour.countDocuments(query);
        
        res.json({
            success: true,
            data: {
                behaviours,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / limit)
                }
            }
        });
        
    } catch (error) {
        console.error('❌ Lỗi lấy user behaviour:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy user behaviour: ' + error.message
        });
    }
});

// Route xác nhận mã hàng (quét mã)
app.post('/api/orders/scan', authFromToken, async (req, res) => {
    try {
        // Kiểm tra kết nối MongoDB
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({
                success: false,
                message: 'MongoDB chưa kết nối. Vui lòng thử lại sau.'
            });
        }

        const { maVanDon, maHang } = req.body;
        // Lấy user từ session, nếu không có thì trả về lỗi
        const userId = req.authUser.username;

        // Nếu mã quét là mã combo, hướng dẫn quét mã base
        if (maHang && typeof maHang === 'string') {
            const combos = await comboCache.getCombosByCode(maHang);
            if (combos && combos.length > 0) {
                // Lấy danh sách tất cả mã base trong combo
                const baseItems = combos.map(combo => `${combo.maHang} (x${combo.soLuong})`).join(', ');
                return res.json({
                    success: false,
                    message: `Đây là mã combo (${maHang}). Vui lòng quét mã hàng base: ${baseItems}`
                });
            }
        }

        // Tìm đơn hàng cụ thể - Logic cải thiện cho ComboData:
        // 1. Tìm trực tiếp với maHang (cho trường hợp non-combo)
        // 2. Tìm tất cả combo có mã base = maHang đang quét
        // 3. Tính tổng số lượng từ cả đơn riêng và combo
        let directOrder = await Order.findOne({ maVanDon, maHang });
        let comboOrders = [];
        let totalRequiredQuantity = 0;
        let totalScannedQuantity = 0;
        let isComboOrder = false;
        
        // Tìm tất cả combo có mã base = maHang đang quét
        const combos = await comboCache.getCombosByMaHang(maHang);
        console.log(`🔍 Found ${combos.length} combos for base maHang: ${maHang}`);
        
        // Tìm order với combo code phù hợp trong maVanDon
        for (const combo of combos) {
            const comboOrder = await Order.findOne({ maVanDon, maHang: combo.comboCode });
            if (comboOrder) {
                comboOrders.push({
                    order: comboOrder,
                    combo: combo
                });
                console.log(`🔍 Found matching combo: ${combo.comboCode} -> ${combo.maHang}, found order: ${!!comboOrder}`);
            }
        }
        
        // Tính tổng số lượng cần quét
        if (directOrder) {
            // Sản phẩm có đơn riêng
            totalRequiredQuantity += directOrder.soLuong;
            totalScannedQuantity += directOrder.scannedQuantity || 0;
            console.log(`📦 Direct order: ${directOrder.soLuong} required, ${directOrder.scannedQuantity || 0} scanned`);
        }
        
        // Cộng thêm từ combo - GIỮ NGUYÊN LOGIC NGHIỆP VỤ CŨ
        for (const { order: comboOrder, combo } of comboOrders) {
            // Logic cũ: 1 combo = 1 lần quét (không nhân với số lượng base products)
            const comboRequiredQuantity = comboOrder.soLuong; // Chỉ tính số combo, không nhân base products
            totalRequiredQuantity += comboRequiredQuantity;
            // scannedQuantity của combo order chính là số combo đã quét
            const comboScannedQuantity = comboOrder.scannedQuantity || 0;
            totalScannedQuantity += comboScannedQuantity;
            console.log(`📦 Combo ${combo.comboCode}: ${comboOrder.soLuong} combo required, ${comboScannedQuantity} combo scanned`);
        }
        
        // Xác định order chính để cập nhật (ưu tiên đơn riêng, nếu không có thì lấy combo đầu tiên)
        let mainOrder = directOrder;
        if (!mainOrder && comboOrders.length > 0) {
            mainOrder = comboOrders[0].order;
            isComboOrder = true;
        }
        
        if (directOrder && comboOrders.length > 0) {
            console.log(`🔍 Product ${maHang} has both direct order and combo orders - total required: ${totalRequiredQuantity}, total scanned: ${totalScannedQuantity}`);
        }

        if (!mainOrder) {
            return res.json({
                success: false,
                message: 'Không tìm thấy mã hàng trong đơn vận đơn này'
            });
        }

        // Kiểm tra timeout - nếu block quá 10 phút thì tự động unblock
        const now = new Date();
        const blockTimeout = 10 * 60 * 1000; // 10 phút
        if (mainOrder.block && mainOrder.blockedAt && (now - mainOrder.blockedAt) > blockTimeout) {
            mainOrder.block = false;
            mainOrder.checkingBy = null;
            mainOrder.blockedAt = null;
            // Reset trạng thái quét khi timeout auto-unblock
            mainOrder.scannedQuantity = 0;
            mainOrder.verified = false;
            mainOrder.verifiedAt = null;
            await mainOrder.save();
            console.log(`🕐 Tự động unblock đơn hàng ${mainOrder.maHang} do timeout và reset trạng thái quét`);
        }

        // Nếu đang bị block bởi người khác
        if (mainOrder.block && mainOrder.checkingBy !== userId) {
            return res.json({
                success: false,
                blocked: true,
                message: `Mã hàng ${maHang} đang được ${mainOrder.checkingBy} kiểm tra. Vui lòng chờ ${mainOrder.checkingBy} hoàn thành hoặc thử lại sau.`
            });
        }

        // Block đơn hàng với optimistic locking
        const lockResult = await SimpleLocking.blockSingleOrder(mainOrder._id, userId);
        
        if (!lockResult.success) {
            console.error('❌ [LOCK-ERROR] Failed to lock order:', lockResult.error);
            return res.status(500).json({
                success: false,
                message: 'Lỗi khóa đơn hàng: ' + lockResult.error
            });
        }
        
        console.log(`✅ Successfully blocked single order ${mainOrder.maDongGoi} for user ${userId}`);

        // Kiểm tra đã xác nhận chưa - cho phép quét lại
        if (totalScannedQuantity >= totalRequiredQuantity) {
            // Tính lại progress cho đơn vận đơn
            const allOrders = await Order.find({ maVanDon });
            const verifiedOrders = await Order.find({ maVanDon, verified: true });
            const isCompleted = allOrders.length === verifiedOrders.length;
            
            return res.json({
                success: true,
                message: `Mã hàng ${maHang} đã đủ số lượng (${totalScannedQuantity}/${totalRequiredQuantity}). Tiếp tục quét đơn hàng khác.`,
                data: {
                    maHang: maHang,
                    soLuong: totalRequiredQuantity,
                    verified: true,
                    verifiedAt: mainOrder.verifiedAt,
                    scannedQuantity: totalScannedQuantity,
                    progress: {
                        completed: verifiedOrders.length,
                        total: allOrders.length,
                        isCompleted
                    }
                }
            });
        }

        // Cập nhật số lượng quét - GIỮ NGUYÊN LOGIC NGHIỆP VỤ CŨ
        // Chỉ cập nhật mainOrder (direct order hoặc combo order chính)
        if (!mainOrder.scannedQuantity) {
            mainOrder.scannedQuantity = 0;
        }
        mainOrder.scannedQuantity += 1;

        // Tính số lượng quét mới
        const newTotalScanned = totalScannedQuantity + 1;
        
        // Cập nhật trạng thái verified cho mainOrder
        if (newTotalScanned >= totalRequiredQuantity) {
            mainOrder.verified = true;
            mainOrder.verifiedAt = new Date();
            // Lưu thông tin nhân viên quét khi hoàn tất
            if (!mainOrder.checkingBy) {
                mainOrder.checkingBy = userId;
            }
        } else {
            mainOrder.verified = false;
        }
        
        // Lưu mainOrder
        await mainOrder.save();
        
        // Xử lý duplicate orders (orders có cùng maHang nhưng khác maDongGoi)
        // Chỉ áp dụng cho non-combo orders (không áp dụng cho combo orders)
        if (!isComboOrder) {
            const duplicateOrders = await Order.find({ 
                maVanDon, 
                maHang,
                _id: { $ne: mainOrder._id } // Loại trừ mainOrder
            });
            
            // Cập nhật duplicate orders để đồng bộ với mainOrder
            for (const duplicateOrder of duplicateOrders) {
                duplicateOrder.scannedQuantity = mainOrder.scannedQuantity;
                duplicateOrder.verified = mainOrder.verified;
                duplicateOrder.verifiedAt = mainOrder.verifiedAt;
                // Đồng bộ thông tin nhân viên quét
                if (mainOrder.verified && !duplicateOrder.checkingBy) {
                    duplicateOrder.checkingBy = mainOrder.checkingBy;
                }
                await duplicateOrder.save();
            }
        }
        
        // Lấy mainOrder sau khi cập nhật
        const updatedMainOrder = await Order.findById(mainOrder._id);

        
        // Lưu user behaviour cho việc quét mã hàng
        try {
            const UserBehaviour = require('./models/UserBehaviour');
            const behaviour = new UserBehaviour({
                user: userId,
                method: 'scanner',
                description: `Quét mã hàng: ${maHang} - Tiến độ: ${newTotalScanned}/${totalRequiredQuantity} - ${updatedMainOrder.verified ? 'Hoàn thành' : 'Đang quét'}`,
                metadata: {
                    maVanDon,
                    maHang: maHang,
                    originalMaHang: updatedMainOrder.maHang,
                    scannedQuantity: newTotalScanned,
                    requiredQuantity: totalRequiredQuantity,
                    verified: updatedMainOrder.verified,
                    isCombo: isComboOrder,
                    hasDirectOrder: !!directOrder,
                    comboOrdersCount: comboOrders.length,
                    totalOrders: (directOrder ? 1 : 0) + comboOrders.length
                },
                ipAddress: req.ip || req.connection.remoteAddress,
                userAgent: req.get('User-Agent') || '',
                sessionId: req.sessionID || ''
            });
            await behaviour.save();
        } catch (behaviourError) {
            console.log('Lỗi lưu user behaviour:', behaviourError.message);
        }

        // Kiểm tra xem đã xác nhận hết chưa
        const allOrders = await Order.find({ maVanDon });
        const verifiedOrders = await Order.find({ maVanDon, verified: true });

        const isCompleted = allOrders.length === verifiedOrders.length;

        res.json({
            success: true,
            message: updatedMainOrder.verified ? 
                `Hoàn thành mã hàng ${maHang}! (${newTotalScanned}/${totalRequiredQuantity})` :
                `Đã quét mã hàng ${maHang}! (${newTotalScanned}/${totalRequiredQuantity})`,
            data: {
                maHang: maHang,
                soLuongYeuCau: totalRequiredQuantity,
                soLuongDaQuet: newTotalScanned,
                originalMaHang: updatedMainOrder.maHang,
                isCombo: isComboOrder,
                hasDirectOrder: !!directOrder,
                comboOrdersCount: comboOrders.length,
                verified: updatedMainOrder.verified,
                verifiedAt: updatedMainOrder.verifiedAt,
                progress: {
                    completed: verifiedOrders.length,
                    total: allOrders.length,
                    isCompleted
                }
            }
        });

    } catch (error) {
        console.error('❌ Lỗi quét mã hàng:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi quét mã hàng: ' + error.message
        });
    }
});

// Route đánh dấu đơn vận đơn hoàn thành (ở cấp độ maVanDon)
app.post('/api/orders/complete-van-don', authFromToken, async (req, res) => {
    try {
        // Kiểm tra kết nối MongoDB
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({
                success: false,
                message: 'MongoDB chưa kết nối. Vui lòng thử lại sau.'
            });
        }

        const { maVanDon } = req.body;
        const userId = req.authUser.username;

        if (!maVanDon) {
            return res.status(400).json({
                success: false,
                message: 'Thiếu mã vận đơn'
            });
        }

        // Tìm tất cả đơn hàng trong mã vận đơn
        const orders = await Order.find({ maVanDon });
        
        if (orders.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Không tìm thấy đơn vận đơn này'
            });
        }

        // Kiểm tra tất cả mã hàng đã được quét đủ số lượng chưa
        // Logic tối ưu: Phân biệt combo orders và direct orders
        
        // Phân loại orders: combo orders vs direct orders
        const comboCache = require('./utils/comboCache');
        const comboOrders = [];
        const directOrders = [];
        
        for (const order of orders) {
            const combos = await comboCache.getCombosByCode(order.maHang);
            if (combos && combos.length > 0) {
                // Đây là combo order
                comboOrders.push(order);
            } else {
                // Đây là direct order
                directOrders.push(order);
            }
        }
        
        console.log(`🔍 Found ${comboOrders.length} combo orders and ${directOrders.length} direct orders`);
        
        // Kiểm tra combo orders (logic cũ: scannedQuantity >= soLuong)
        const comboCompleted = await Promise.all(comboOrders.map(async (order) => {
            const isCompleted = order.verified && (order.scannedQuantity || 0) >= order.soLuong;
            console.log(`📦 Combo ${order.maHang}: required=${order.soLuong}, scanned=${order.scannedQuantity || 0}, verified=${order.verified}, completed=${isCompleted}`);
            return isCompleted;
        }));
        
        // Kiểm tra direct orders (xử lý duplicate orders)
        const directOrderGroups = {};
        directOrders.forEach(order => {
            if (!directOrderGroups[order.maHang]) {
                directOrderGroups[order.maHang] = {
                    totalRequired: 0,
                    totalScanned: 0,
                    verified: true
                };
            }
            directOrderGroups[order.maHang].totalRequired += order.soLuong;
            directOrderGroups[order.maHang].totalScanned += order.scannedQuantity || 0;
            if (!order.verified) {
                directOrderGroups[order.maHang].verified = false;
            }
        });
        
        const directCompleted = Object.entries(directOrderGroups).every(([maHang, group]) => {
            const isCompleted = group.verified && group.totalScanned >= group.totalRequired;
            console.log(`📦 Direct ${maHang}: required=${group.totalRequired}, scanned=${group.totalScanned}, verified=${group.verified}, completed=${isCompleted}`);
            return isCompleted;
        });
        
        // Tất cả orders phải hoàn thành (combo + direct)
        const allItemsCompleted = comboCompleted.every(completed => completed) && directCompleted;

        if (!allItemsCompleted) {
            return res.status(400).json({
                success: false,
                message: 'Đơn vận đơn chưa đủ điều kiện hoàn thành. Vui lòng quét đủ tất cả mã hàng.'
            });
        }

        // Đánh dấu tất cả đơn hàng trong maVanDon là hoàn thành ở cấp độ maVanDon
        // Sử dụng trường verified để đánh dấu đơn đã hoàn thành (không dùng vanDonVerified)
        // Đồng thời unblock tất cả các maHang trong đơn vì đơn đã hoàn thành
        await Order.updateMany(
            { maVanDon },
            { 
                verified: true,         // Đánh dấu đơn đã hoàn thành bằng trường verified
                verifiedAt: new Date(),
                block: false,           // Unblock tất cả maHang trong đơn
                // Giữ lại checkingBy để theo dõi nhân viên quét
                blockedAt: null         // Xóa blockedAt
            }
        );

        
        // Lưu user behaviour cho việc hoàn thành đơn
        try {
            const UserBehaviour = require('./models/UserBehaviour');
            const behaviour = new UserBehaviour({
                user: userId,
                method: 'scanner',
                description: `Hoàn thành đơn vận đơn: ${maVanDon} - ${orders.length} mặt hàng`,
                metadata: {
                    maVanDon,
                    orderCount: orders.length,
                    action: 'complete_order',
                    verifiedAt: new Date()
                },
                ipAddress: req.ip || req.connection.remoteAddress,
                userAgent: req.get('User-Agent') || '',
                sessionId: req.sessionID || ''
            });
            await behaviour.save();
        } catch (behaviourError) {
            console.log('Lỗi lưu user behaviour:', behaviourError.message);
        }

        res.json({
            success: true,
            message: `Đã đánh dấu đơn vận đơn ${maVanDon} hoàn thành`,
            data: {
                maVanDon,
                totalItems: orders.length,
                verifiedBy: userId,
                verifiedAt: new Date()
            }
        });

    } catch (error) {
        console.error('❌ Lỗi hoàn thành đơn vận đơn:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi hoàn thành đơn vận đơn: ' + error.message
        });
    }
});

// Route cleanup dữ liệu: unblock các maHang đã hoàn thành nhưng vẫn bị block
app.post('/api/orders/cleanup-blocked-items', authFromToken, async (req, res) => {
    try {
        // Kiểm tra kết nối MongoDB
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({
                success: false,
                message: 'MongoDB chưa kết nối. Vui lòng thử lại sau.'
            });
        }

        // Tìm tất cả các maHang đã verified nhưng vẫn bị block
        const blockedButVerified = await Order.find({ 
            verified: true, 
            block: true 
        });

        if (blockedButVerified.length === 0) {
            return res.json({
                success: true,
                message: 'Không có dữ liệu cần cleanup',
                cleanedCount: 0
            });
        }

        // Unblock các maHang đã verified
        await Order.updateMany(
            { verified: true, block: true },
            { 
                block: false,
                checkingBy: null,
                blockedAt: null
            }
        );

        console.log(`Cleaned up ${blockedButVerified.length} blocked but verified items`);

        res.json({
            success: true,
            message: `Đã cleanup ${blockedButVerified.length} mã hàng đã hoàn thành nhưng vẫn bị block`,
            data: {
                cleanedCount: blockedButVerified.length,
                cleanedItems: blockedButVerified.map(item => ({
                    maHang: item.maHang,
                    maVanDon: item.maVanDon,
                    verified: item.verified,
                    scannedQuantity: item.scannedQuantity,
                    soLuong: item.soLuong
                }))
            }
        });

    } catch (error) {
        console.error('❌ Lỗi cleanup blocked items:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi cleanup: ' + error.message
        });
    }
});

// Route unblock đơn hàng khi user rời khỏi trang
app.post('/api/orders/unblock', async (req, res) => {
    try {
        // Kiểm tra kết nối MongoDB
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({
                success: false,
                message: 'MongoDB chưa kết nối. Vui lòng thử lại sau.'
            });
        }

        const { maVanDon, maHang } = req.body;
        // Lấy user từ session hoặc từ token (support per-tab JWT)
        let userId = null;
        if (req.session && req.session.user && req.session.user.username) {
            userId = req.session.user.username;
        } else {
            const auth = req.headers.authorization || '';
            if (auth.startsWith('Bearer ')) {
                try {
                    const decoded = jwt.verify(auth.substring(7), config.SESSION_SECRET);
                    userId = decoded.username;
                } catch (e) {
                    // invalid token
                }
            }
        }
        if (!userId) {
            return res.status(401).json({ success: false, message: 'Không xác định được user. Vui lòng đăng nhập lại.' });
        }

        // Tìm đơn hàng cụ thể
        const order = await Order.findOne({ maVanDon, maHang });

        if (!order) {
            return res.json({
                success: false,
                message: 'Không tìm thấy đơn hàng'
            });
        }

        // Chỉ cho phép unblock nếu user hiện tại đang check đơn này
        if (order.checkingBy === userId && order.block) {
            order.checkingBy = null;
            order.block = false;
            order.blockedAt = null;
            // Reset trạng thái quét khi hủy đơn
            order.scannedQuantity = 0;
            order.verified = false;
            order.verifiedAt = null;
            await order.save();
            
            return res.json({
                success: true,
                message: 'Đã unblock đơn hàng thành công và reset trạng thái quét'
            });
        }

        return res.json({
            success: false,
            message: 'Bạn không có quyền unblock đơn hàng này'
        });

    } catch (error) {
        console.error('❌ Lỗi unblock đơn hàng:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi unblock đơn hàng: ' + error.message
        });
    }
});

// Route unblock toàn bộ đơn vận đơn khi user rời khỏi trang
app.post('/api/orders/unblock-van-don', authFromToken, async (req, res) => {
    try {
        // Kiểm tra kết nối MongoDB
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({
                success: false,
                message: 'MongoDB chưa kết nối. Vui lòng thử lại sau.'
            });
        }

        const { maVanDon } = req.body;
        // Lấy user từ session
        const userId = req.authUser.username;

        // Tìm tất cả đơn hàng trong mã vận đơn
        const orders = await Order.find({ maVanDon });

        if (orders.length === 0) {
            return res.json({
                success: false,
                message: 'Không tìm thấy đơn hàng'
            });
        }

        // Unblock tất cả đơn hàng với optimistic locking
        const unlockResult = await SimpleLocking.unblockOrders(maVanDon, userId);
        
        if (!unlockResult.success) {
            console.error('❌ [UNLOCK-ERROR] Failed to unlock orders:', unlockResult.errors);
            return res.status(500).json({
                success: false,
                message: 'Lỗi unlock đơn hàng: ' + unlockResult.errors.join(', ')
            });
        }
        
        console.log(`✅ Successfully unblocked ${unlockResult.unblockedCount} orders for user ${userId}`);

        
        return res.json({
            success: true,
            message: `Đã unblock ${unlockResult.unblockedCount} đơn hàng thành công`
        });

    } catch (error) {
        console.error('❌ Lỗi unblock đơn vận đơn:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi unblock đơn vận đơn: ' + error.message
        });
    }
});

// Route reset trạng thái quét cho một đơn vận đơn
app.post('/api/orders/reset-scan/:maVanDon', async (req, res) => {
    try {
        // Kiểm tra kết nối MongoDB
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({
                success: false,
                message: 'MongoDB chưa kết nối. Vui lòng thử lại sau.'
            });
        }

        const { maVanDon } = req.params;

        // Reset tất cả trạng thái quét cho đơn vận đơn này
        const result = await Order.updateMany(
            { maVanDon },
            { 
                $set: { 
                    scannedQuantity: 0,
                    verified: false,
                    verifiedAt: null
                }
            }
        );

        console.log(`Đã reset trạng thái quét cho đơn vận đơn ${maVanDon}: ${result.modifiedCount} đơn hàng`);

        res.json({
            success: true,
            message: `Đã reset trạng thái quét cho ${result.modifiedCount} đơn hàng trong đơn vận đơn ${maVanDon}`,
            data: {
                maVanDon,
                resetCount: result.modifiedCount
            }
        });

    } catch (error) {
        console.error('❌ Lỗi reset trạng thái quét:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi reset trạng thái quét: ' + error.message
        });
    }
});

// API cho checker/packer - lấy danh sách COM ports đã phân quyền
app.get('/api/checker/com-ports', requireLogin, async (req, res) => {
    try {
        const username = req.session?.user?.username;
        console.log(`[API /api/checker/com-ports] User: ${username}`);
        
        // Kiểm tra MongoDB connection
        if (mongoose.connection.readyState !== 1) {
            return res.status(500).json({
                success: false,
                message: 'MongoDB chưa kết nối'
            });
        }
        
        // Lấy danh sách COM ports đã phân quyền cho user này
        const scannerAssignments = await ScannerAssignment.find({ userId: username });
        
        console.log(`[API /api/checker/com-ports] Found ${scannerAssignments.length} assignments for ${username}`);
        
        const ports = scannerAssignments.map(assignment => ({
            path: assignment.comPort,
            assignedToUser: assignment.userId,
            createdAt: assignment.createdAt
        }));
        
        res.json({
            success: true,
            data: {
                ports: ports,
                total: ports.length
            }
        });
        
    } catch (error) {
        console.error('[API /api/checker/com-ports] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy danh sách COM ports: ' + error.message
        });
    }
});

// API kiểm tra port usage
app.post('/api/check-port-usage', requireLogin, async (req, res) => {
    try {
        const { comPort } = req.body;
        const username = req.session?.user?.username;
        
        console.log(`[API /api/check-port-usage] User: ${username}, COM Port: ${comPort}`);
        
        // Kiểm tra xem có user nào đang sử dụng COM port này không
        const currentUser = await PortUsage.getCurrentUser(comPort);
        const isInUse = !!currentUser; // Port đang được sử dụng nếu có currentUser
        
        console.log(`[API /api/check-port-usage] Port ${comPort} is in use: ${isInUse}, by user: ${currentUser}`);
        
        res.json({
            success: true,
            isInUse: isInUse,
            currentUser: currentUser,
            message: isInUse ? `COM port ${comPort} đang được sử dụng bởi ${currentUser}` : `COM port ${comPort} có thể sử dụng`
        });
        
    } catch (error) {
        console.error('[API /api/check-port-usage] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi kiểm tra port usage: ' + error.message
        });
    }
});

// API claim port khi kết nối (atomic operation)
app.post('/api/claim-port', requireLogin, async (req, res) => {
    try {
        const { comPort, machineId, sessionId, screenId } = req.body;
        const username = req.session?.user?.username;
        
        console.log(`[API /api/claim-port] User: ${username} attempting to claim COM Port: ${comPort}, Machine: ${machineId}, Session: ${sessionId}, Screen: ${screenId}`);
        
        // Claim port với atomic transaction (đã bao gồm kiểm tra conflict)
        const usage = await PortUsage.claimPort(comPort, username, machineId, sessionId, screenId);
        console.log(`[API /api/claim-port] User ${username} successfully claimed port ${comPort}`);
        
        res.json({
            success: true,
            message: `Đã kết nối thành công với COM port ${comPort}`,
            usage: usage
        });
        
    } catch (error) {
        console.error('[API /api/claim-port] Error:', error);
        
        // Kiểm tra loại lỗi để trả về response phù hợp
        if (error.message.includes('đang được sử dụng bởi user')) {
            return res.status(409).json({
                success: false,
                message: error.message
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Lỗi claim port: ' + error.message
        });
    }
});

// API release port khi ngắt kết nối
app.post('/api/release-port', requireLogin, async (req, res) => {
    try {
        const { comPort } = req.body;
        const username = req.session?.user?.username;
        
        console.log(`[API /api/release-port] User: ${username} releasing COM Port: ${comPort}`);
        
        // Release port
        const released = await PortUsage.releasePort(comPort, username);
        
        if (released) {
            console.log(`[API /api/release-port] User ${username} successfully released port ${comPort}`);
            res.json({
                success: true,
                message: `Đã ngắt kết nối thành công với COM port ${comPort}`
            });
        } else {
            console.log(`[API /api/release-port] User ${username} was not using port ${comPort}`);
            res.json({
                success: true,
                message: `COM port ${comPort} không được sử dụng bởi user này`
            });
        }
        
    } catch (error) {
        console.error('[API /api/release-port] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi release port: ' + error.message
        });
    }
});

// API để release port cho bất kỳ user nào (dùng khi logout hoặc ngắt kết nối)
app.post('/api/release-port-any', requireLogin, async (req, res) => {
    try {
        const { comPort } = req.body;
        const username = req.session?.user?.username;
        
        console.log(`[API /api/release-port-any] User: ${username} releasing COM Port: ${comPort} for any user`);
        
        // Release port cho bất kỳ user nào
        const released = await PortUsage.releasePortForAnyUser(comPort);
        
        if (released) {
            console.log(`[API /api/release-port-any] Successfully released port ${comPort} for any user`);
            res.json({
                success: true,
                message: `Đã ngắt kết nối thành công với COM port ${comPort}`
            });
        } else {
            console.log(`[API /api/release-port-any] No active users found for port ${comPort}`);
            res.json({
                success: true,
                message: `COM port ${comPort} không có user nào đang sử dụng`
            });
        }
        
    } catch (error) {
        console.error('[API /api/release-port-any] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi release port: ' + error.message
        });
    }
});

// API release tất cả port của user hiện tại (dùng khi logout)
app.post('/api/release-all-user-ports', requireLogin, async (req, res) => {
    try {
        const { userId } = req.body;
        const username = req.session?.user?.username;
        
        console.log(`[API /api/release-all-user-ports] User: ${username} releasing all ports for user: ${userId}`);
        
        // Release tất cả port của user hiện tại
        const released = await PortUsage.releaseAllUserPorts(userId);
        
        // Cleanup timeout ports (heartbeat > 30 seconds)
        const cleaned = await PortUsage.cleanupTimeoutPorts(30);
        
        console.log(`[API /api/release-all-user-ports] Released ${released} ports for user ${userId}, cleaned ${cleaned} timeout ports`);
        res.json({
            success: true,
            message: `Đã release ${released} port của user ${userId}`,
            releasedCount: released
        });
        
    } catch (error) {
        console.error('[API /api/release-all-user-ports] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi release all user ports: ' + error.message
        });
    }
});

// API để xóa hoàn toàn tất cả bản ghi port của user (khi logout)
app.post('/api/delete-all-user-ports', requireLogin, async (req, res) => {
    try {
        const { userId } = req.body;
        const username = req.session?.user?.username;
        
        
        // Kiểm tra xem có bản ghi nào của user này không
        const existingPorts = await PortUsage.find({ userId: userId });
        
        // Xóa hoàn toàn tất cả bản ghi port của user
        const deleted = await PortUsage.deleteAllUserPorts(userId);
        
        // Cleanup timeout ports (heartbeat > 30 seconds)
        const cleaned = await PortUsage.cleanupTimeoutPorts(30);
        
        res.json({
            success: true,
            message: `Đã xóa ${deleted} bản ghi port của user ${userId}`,
            deletedCount: deleted,
            existingCount: existingPorts.length
        });
        
    } catch (error) {
        console.error('[API /api/delete-all-user-ports] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi delete all user ports: ' + error.message
        });
    }
});

// API để xóa bản ghi port cụ thể
app.post('/api/delete-port', requireLogin, async (req, res) => {
    try {
        const { comPort } = req.body;
        const username = req.session?.user?.username;
        
        console.log(`[API /api/delete-port] User: ${username} deleting port: ${comPort}`);
        
        // Xóa bản ghi port cụ thể
        const deleted = await PortUsage.deletePort(comPort);
        
        console.log(`[API /api/delete-port] Deleted ${deleted} port record: ${comPort}`);
        res.json({
            success: true,
            message: `Đã xóa bản ghi port ${comPort}`,
            deletedCount: deleted
        });
        
    } catch (error) {
        console.error('[API /api/delete-port] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi delete port: ' + error.message
        });
    }
});

// ==================== SCANNER MANAGEMENT APIs ====================

// API phát hiện cổng port thực tế của CPU
// API cho admin - yêu cầu quyền admin
app.get('/api/ports/detect', requireLogin, requireAdmin, async (req, res) => {
    try {
        console.log('\n========================================');
        console.log('[API /api/ports/detect] Request received');
        console.log(`[API /api/ports/detect] User: ${req.session?.username}`);
        console.log(`[API /api/ports/detect] Query params:`, req.query);
        console.log('========================================\n');
        
        // Kiểm tra MongoDB connection
        if (mongoose.connection.readyState !== 1) {
            console.warn('[API /api/ports/detect] MongoDB chưa kết nối');
            return res.status(503).json({
                success: false,
                message: 'MongoDB chưa kết nối. Vui lòng đợi server khởi động hoàn tất.'
            });
        }
        console.log('[API /api/ports/detect] MongoDB: Connected ✓');
        
        const scannerDetector = require('./utils/scannerDetector');
        console.log('[API /api/ports/detect] scannerDetector module loaded ✓');
        
        // Force refresh nếu có query parameter
        if (req.query.refresh === 'true') {
            scannerDetector.clearCache();
            console.log('[API /api/ports/detect] Cache cleared (force refresh)');
        }
        
        // Phát hiện tất cả cổng serial hiện đang kết nối
        console.log('[API /api/ports/detect] Calling scannerDetector.detectAllSerialPorts()...');
        const allPorts = await scannerDetector.detectAllSerialPorts();
        console.log(`[API /api/ports/detect] detectAllSerialPorts() returned ${allPorts.length} ports`);
        
        if (allPorts.length === 0) {
            console.warn('[API /api/ports/detect] KHÔNG TÌM THẤY CỔNG SERIAL NÀO!');
            return res.json({
                success: true,
                data: {
                    machineInfo: {
                        hostname: require('os').hostname(),
                        platform: require('os').platform(),
                        arch: require('os').arch(),
                        totalMemory: require('os').totalmem(),
                        freeMemory: require('os').freemem(),
                        uptime: require('os').uptime()
                    },
                    ports: [],
                    scannerAssignments: [],
                    summary: {
                        totalPorts: 0,
                        availablePorts: 0,
                        assignedPorts: 0,
                        scannerDevices: 0
                    }
                },
                message: 'Không tìm thấy cổng serial nào. Hãy kiểm tra kết nối máy quét.',
                timestamp: new Date().toISOString()
            });
        }
        
        console.log(`[API /api/ports/detect] Processing ${allPorts.length} ports...`);
        
        // Lấy thông tin máy tính hiện tại
        const os = require('os');
        const machineInfo = {
            hostname: os.hostname(),
            platform: os.platform(),
            arch: os.arch(),
            totalMemory: os.totalmem(),
            freeMemory: os.freemem(),
            uptime: os.uptime(),
            cpuCount: os.cpus().length,
            networkInterfaces: Object.keys(os.networkInterfaces())
        };
        
        // Lấy tất cả ScannerAssignment từ database
        console.log('[API /api/ports/detect] Fetching ScannerAssignment data...');
        const scannerAssignments = await ScannerAssignment.find({}).lean();
        console.log(`[API /api/ports/detect] Found ${scannerAssignments.length} scanner assignments`);
        
        // Tạo map để tra cứu nhanh scanner assignment theo port
        const assignmentMap = new Map();
        scannerAssignments.forEach(assignment => {
            if (assignment.scannerId) {
                assignmentMap.set(assignment.scannerId, assignment);
            }
        });
        
        // Kiểm tra trạng thái sử dụng cho từng cổng
        const portsWithStatus = await Promise.all(allPorts.map(async (port) => {
            try {
                // Kiểm tra trong Account collection (phân quyền cũ)
                let assignedToUser = null;
                let assignmentInfo = null;
                let isInUse = false;
                
                // Tìm user đang sử dụng cổng này trong Account
                const account = await Account.findOne({
                    $or: [
                        { 'scannerPermissions.port': port.path },
                        { 'scannerPermissions.allowedPorts': port.path }
                    ]
                }, { username: 1, scannerPermissions: 1 }).maxTimeMS(5000);
                
                if (account) {
                    assignedToUser = account.username;
                    isInUse = true;
                }
                
                // Kiểm tra trong ScannerAssignment collection
                const scannerAssignment = assignmentMap.get(port.path);
                if (scannerAssignment) {
                    assignmentInfo = {
                        scannerId: scannerAssignment.scannerId,
                        scannerName: scannerAssignment.scannerName,
                        assignedTo: scannerAssignment.assignedTo,
                        sessionId: scannerAssignment.sessionId,
                        status: scannerAssignment.status,
                        assignedAt: scannerAssignment.assignedAt,
                        expiresAt: scannerAssignment.expiresAt,
                        metadata: scannerAssignment.metadata
                    };
                    
                    if (scannerAssignment.assignedTo) {
                        assignedToUser = scannerAssignment.assignedTo;
                        isInUse = true;
                    }
                }
                
                // Xác định độ tin cậy của thiết bị
                const isLikelyScanner = scannerDetector.isScannerPort(port);
                let confidence = 'low';
                if (isLikelyScanner) {
                    confidence = 'high';
                } else if (port.vendorId && port.productId) {
                    confidence = 'medium';
                }
                
                // Xác định loại thiết bị
                let deviceType = 'Serial Device';
                if (isLikelyScanner) {
                    deviceType = 'Scanner (detected)';
                } else if (port.manufacturer && port.manufacturer.toLowerCase().includes('usb')) {
                    deviceType = 'USB Device';
                }
                
                return {
                    // Thông tin cổng cơ bản
                    path: port.path,
                    manufacturer: port.manufacturer || 'Unknown',
                    vendorId: port.vendorId || null,
                    productId: port.productId || null,
                    serialNumber: port.serialNumber || null,
                    pnpId: port.pnpId || null,
                    locationId: port.locationId || null,
                    
                    // Thông tin trạng thái
                    isInUse,
                    assignedToUser,
                    isAvailable: !isInUse,
                    status: isInUse ? 'assigned' : 'available',
                    
                    // Thông tin phân tích
                    isLikelyScanner,
                    confidence,
                    deviceType,
                    
                    // Thông tin assignment chi tiết
                    assignmentInfo,
                    
                    // Thông tin bổ sung
                    note: isLikelyScanner 
                        ? 'Thiết bị có khả năng cao là máy quét' 
                        : confidence === 'medium'
                        ? 'Thiết bị nối tiếp, có thể là máy quét'
                        : 'Thiết bị nối tiếp thông thường',
                    
                    // Timestamp
                    detectedAt: new Date().toISOString()
                };
            } catch (portError) {
                console.warn(`Lỗi kiểm tra cổng ${port.path}:`, portError.message);
                // Fallback: trả về port mà không kiểm tra trạng thái
                return {
                    path: port.path,
                    manufacturer: port.manufacturer || 'Unknown',
                    vendorId: port.vendorId || null,
                    productId: port.productId || null,
                    serialNumber: port.serialNumber || null,
                    pnpId: port.pnpId || null,
                    locationId: port.locationId || null,
                    isInUse: false,
                    assignedToUser: null,
                    isAvailable: true,
                    status: 'available',
                    isLikelyScanner: scannerDetector.isScannerPort(port),
                    confidence: 'low',
                    deviceType: 'Serial Device',
                    assignmentInfo: null,
                    note: 'Lỗi kiểm tra trạng thái',
                    detectedAt: new Date().toISOString()
                };
            }
        }));
        
        // Tính toán thống kê
        const summary = {
            totalPorts: portsWithStatus.length,
            availablePorts: portsWithStatus.filter(p => p.isAvailable).length,
            assignedPorts: portsWithStatus.filter(p => p.isInUse).length,
            scannerDevices: portsWithStatus.filter(p => p.isLikelyScanner).length,
            highConfidenceDevices: portsWithStatus.filter(p => p.confidence === 'high').length,
            mediumConfidenceDevices: portsWithStatus.filter(p => p.confidence === 'medium').length,
            lowConfidenceDevices: portsWithStatus.filter(p => p.confidence === 'low').length
        };
        
        console.log(`[API /api/ports/detect] Processed ${portsWithStatus.length} ports successfully`);
        console.log(`[API /api/ports/detect] Summary:`, summary);
        console.log('[API /api/ports/detect] ✅ Returning response...\n');
        
        res.json({
            success: true,
            data: {
                machineInfo,
                ports: portsWithStatus,
                scannerAssignments: scannerAssignments,
                summary
            },
            message: `Phát hiện ${portsWithStatus.length} cổng serial trên máy ${machineInfo.hostname}`,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('[API /api/ports/detect] ❌ LỖI:', error);
        console.error('[API /api/ports/detect] Stack:', error.stack);
        res.status(500).json({
            success: false,
            message: 'Lỗi phát hiện cổng port: ' + error.message
        });
    }
});

// Route lấy thống kê quét
app.get('/api/orders/scan-stats/:maVanDon', async (req, res) => {
    try {
        // Kiểm tra kết nối MongoDB
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({
                success: false,
                message: 'MongoDB chưa kết nối. Vui lòng thử lại sau.'
            });
        }

        const { maVanDon } = req.params;

        const orders = await Order.find({ maVanDon });
        
        const stats = {
            total: orders.length,
            completed: orders.filter(o => o.verified).length,
            inProgress: orders.filter(o => !o.verified && (o.scannedQuantity || 0) > 0 && (o.scannedQuantity || 0) <= o.soLuong).length,
            pending: orders.filter(o => !o.verified && (o.scannedQuantity || 0) === 0).length,
            error: orders.filter(o => !o.verified && (o.scannedQuantity || 0) > o.soLuong).length,
            totalScanned: orders.reduce((sum, o) => sum + (o.scannedQuantity || 0), 0),
            totalRequired: orders.reduce((sum, o) => sum + o.soLuong, 0)
        };

        res.json({
            success: true,
            message: `Thống kê quét cho đơn vận đơn ${maVanDon}`,
            data: {
                maVanDon,
                stats
            }
        });

    } catch (error) {
        console.error('❌ Lỗi lấy thống kê quét:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy thống kê quét: ' + error.message
        });
    }
});

// Tạo thư mục uploads nếu chưa có
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Khởi động server
const PORT = config.PORT;

// Load SSL certificates
const sslOptions = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt')
};

// Start HTTPS server
https.createServer(sslOptions, app).listen(PORT, '0.0.0.0', () => {
    console.log(`HTTPS Server đang chạy tại https://0.0.0.0:${PORT}`);
    console.log(`Truy cập từ máy khác: https://192.168.1.31:${PORT}`);
    console.log('Mở trình duyệt và truy cập https://localhost:' + PORT);
    console.log('⚠️  Browser sẽ hiện cảnh báo SSL, click "Advanced" → "Proceed"');
});

// API client gửi COM port của máy họ lên server
app.post('/api/machine/com-ports', requireLogin, async (req, res) => {
    try {
        const { comPorts } = req.body;
        const username = req.session.user.username;
        
        // Lấy IP address của client
        const clientIP = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
        
        // Cập nhật thông tin máy tính và COM ports
        const account = await Account.findOneAndUpdate(
            { username },
            {
                'machineInfo.hostname': require('os').hostname(),
                'machineInfo.ipAddress': clientIP,
                'machineInfo.platform': require('os').platform(),
                'machineInfo.lastSeen': new Date(),
                comPorts: comPorts || []
            },
            { new: true }
        );
        
        if (!account) {
            return res.status(404).json({
                success: false,
                message: 'Không tìm thấy tài khoản'
            });
        }
        
        res.json({
            success: true,
            message: 'Đã cập nhật COM ports của máy',
            data: {
                username: account.username,
                machineInfo: account.machineInfo,
                comPortsCount: account.comPorts.length
            }
        });
        
    } catch (error) {
        console.error('Error updating machine COM ports:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi cập nhật COM ports: ' + error.message
        });
    }
});

// API admin lấy COM ports của tất cả máy
app.get('/api/admin/all-machines-com-ports', requireLogin, requireAdmin, async (req, res) => {
    try {
        // Lấy tất cả account có COM ports
        const accounts = await Account.find({
            comPorts: { $exists: true, $not: { $size: 0 } }
        }, {
            username: 1,
            role: 1,
            machineInfo: 1,
            comPorts: 1,
            scannerPermissions: 1
        }).sort({ 'machineInfo.lastSeen': -1 });
        
        // Tổng hợp dữ liệu
        const machinesData = accounts.map(account => ({
            username: account.username,
            role: account.role,
            machineInfo: account.machineInfo,
            comPorts: account.comPorts.map(port => ({
                ...port,
                isAssigned: account.scannerPermissions?.port === port.path,
                assignedTo: account.scannerPermissions?.port === port.path ? account.username : null
            })),
            totalPorts: account.comPorts.length,
            availablePorts: account.comPorts.filter(port => port.isAvailable).length,
            assignedPorts: account.comPorts.filter(port => account.scannerPermissions?.port === port.path).length
        }));
        
        // Thống kê tổng
        const totalStats = {
            totalMachines: machinesData.length,
            totalPorts: machinesData.reduce((sum, machine) => sum + machine.totalPorts, 0),
            totalAvailablePorts: machinesData.reduce((sum, machine) => sum + machine.availablePorts, 0),
            totalAssignedPorts: machinesData.reduce((sum, machine) => sum + machine.assignedPorts, 0),
            onlineMachines: machinesData.filter(machine => 
                new Date() - new Date(machine.machineInfo.lastSeen) < 5 * 60 * 1000 // 5 phút
            ).length
        };
        
        res.json({
            success: true,
            data: {
                machines: machinesData,
                stats: totalStats
            },
            message: `Tìm thấy ${machinesData.length} máy với COM ports`
        });
        
    } catch (error) {
        console.error('Error getting all machines COM ports:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy COM ports của tất cả máy: ' + error.message
        });
    }
});

// API lấy tất cả COM ports đã đăng ký (admin only)
app.get('/api/admin/all-com-ports', requireLogin, requireAdmin, async (req, res) => {
    try {
        // Lấy tất cả scanner assignments
        const assignments = await ScannerAssignment.find({}).sort({ updatedAt: -1 });
        
        // Lấy tất cả accounts để lấy thông tin user
        const accounts = await Account.find({}).select({
            username: 1,
            role: 1
        });

        // Tạo map username -> account info
        const accountMap = new Map();
        accounts.forEach(account => {
            accountMap.set(account.username, account);
        });

        // Tạo danh sách COM ports từ assignments
        const ports = assignments.map(assignment => {
            const account = accountMap.get(assignment.userId);
            return {
                path: assignment.comPort,
                manufacturer: 'Manual Entry',
                isAvailable: false, // Tất cả ports trong assignments đều đã được phân quyền
                isLikelyScanner: true,
                confidence: 'high',
                deviceType: 'Scanner Device',
                assignedToUser: assignment.userId,
                note: `${assignment.comPort} - ${account?.role || 'Unknown'} User`,
                lastUpdated: assignment.updatedAt,
                createdAt: assignment.createdAt,
                userId: assignment.userId,
                userRole: account?.role || 'Unknown'
            };
        });

        // Thống kê
        const stats = {
            totalPorts: ports.length,
            availablePorts: 0, // Tất cả ports đều đã được phân quyền
            assignedPorts: ports.length,
            scannerDevices: ports.length
        };

        res.json({
            success: true,
            data: {
                ports: ports,
                summary: stats
            },
            message: `Tìm thấy ${ports.length} COM ports đã phân quyền`
        });
    } catch (error) {
        console.error('Error getting all COM ports:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy danh sách COM ports: ' + error.message
        });
    }
});

// API thêm COM port mới (admin only) - Tạo assignment trực tiếp
app.post('/api/admin/add-com-port', requireLogin, requireAdmin, async (req, res) => {
    try {
        const { portName, userId, description } = req.body;
        
        if (!portName) {
            return res.json({ success: false, message: 'Vui lòng nhập tên COM port' });
        }

        if (!userId) {
            return res.json({ success: false, message: 'Vui lòng chọn user để phân quyền' });
        }

        // Validate COM port format
        if (!/^COM\d+$/i.test(portName)) {
            return res.json({ success: false, message: 'COM port phải có định dạng COM + số (VD: COM3)' });
        }

        const normalizedPortName = portName.toUpperCase();

        // Kiểm tra user có tồn tại không
        const account = await Account.findOne({ username: userId });
        if (!account) {
            return res.json({ success: false, message: 'Không tìm thấy user' });
        }

        // Kiểm tra COM port đã được phân quyền cho user khác chưa
        const existingAssignment = await ScannerAssignment.findOne({ 
            comPort: normalizedPortName 
        });
        if (existingAssignment) {
            return res.json({ 
                success: false, 
                message: `COM port ${normalizedPortName} đã được phân quyền cho user ${existingAssignment.userId}` 
            });
        }

        // Kiểm tra user đã có COM port khác chưa
        const userAssignment = await ScannerAssignment.findOne({ userId: userId });
        if (userAssignment) {
            return res.json({ 
                success: false, 
                message: `User ${userId} đã có COM port ${userAssignment.comPort}. Chỉ được sử dụng 1 COM port tại 1 thời điểm.` 
            });
        }

        // Tạo assignment mới
        const newAssignment = new ScannerAssignment({
            userId: userId,
            comPort: normalizedPortName
        });

        await newAssignment.save();

        res.json({
            success: true,
            message: `Đã phân quyền COM port ${normalizedPortName} cho user ${userId} thành công`,
            data: {
                assignment: newAssignment
            }
        });
    } catch (error) {
        console.error('Error adding COM port:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi thêm COM port: ' + error.message
        });
    }
});

// API client gửi COM port của máy họ lên server (KHÔNG CẦN LOGIN)
app.post('/api/machine/register-com-ports', async (req, res) => {
    try {
        const { comPorts, hostname, platform } = req.body;
        
        // Lấy IP address của client
        const clientIP = req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 
                        req.headers['x-forwarded-for'] || req.connection.socket.remoteAddress;
        
        // Lấy User-Agent
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        console.log(`[MACHINE-REGISTER] IP: ${clientIP}, Hostname: ${hostname}, COM Ports: ${comPorts?.length || 0}`);
        
        // Tìm hoặc tạo machine record
        const machine = await Machine.findOneAndUpdate(
            { ipAddress: clientIP },
            {
                hostname: hostname || 'Unknown',
                platform: platform || 'Unknown',
                userAgent: userAgent,
                comPorts: comPorts || [],
                lastSeen: new Date(),
                lastComScan: new Date(),
                isOnline: true,
                $inc: { accessCount: 1 }
            },
            { 
                upsert: true, 
                new: true,
                setDefaultsOnInsert: true
            }
        );
        
        res.json({
            success: true,
            message: 'Đã đăng ký COM ports của máy',
            data: {
                ipAddress: machine.ipAddress,
                hostname: machine.hostname,
                comPortsCount: machine.comPorts.length,
                machineId: machine._id
            }
        });
        
    } catch (error) {
        console.error('Error registering machine COM ports:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi đăng ký COM ports: ' + error.message
        });
    }
});

// API nhận input từ COM port và in ra console (KHÔNG CẦN LOGIN)
app.post('/api/com-input', async (req, res) => {
    try {
        const { userId, comPort, inputData, timestamp, sessionId } = req.body;
        
        // Kiểm tra quyền sử dụng COM port
        if (comPort && userId) {
            const currentUser = await PortUsage.getCurrentUser(comPort);
            console.log(`🔍 [COM-INPUT] Checking permission for user ${userId} (session: ${sessionId}) on port ${comPort}, current user: ${currentUser}`);
            
            if (currentUser && currentUser !== userId) {
                console.log(`🚫 [COM-INPUT] User ${userId} (session: ${sessionId}) không có quyền sử dụng COM port ${comPort} (đang được sử dụng bởi ${currentUser})`);
                return res.status(403).json({
                    success: false,
                    message: `COM port ${comPort} đang được sử dụng bởi user khác`,
                    currentUser: currentUser
                });
            }
            
            // Nếu không có user nào đang sử dụng port, từ chối input
            if (!currentUser) {
                console.log(`🚫 [COM-INPUT] User ${userId} (session: ${sessionId}) không có quyền sử dụng COM port ${comPort} (port chưa được claim)`);
                return res.status(403).json({
                    success: false,
                    message: `COM port ${comPort} chưa được claim bởi user nào`,
                    currentUser: null
                });
            }
        }
        
        // Lấy IP address của client
        const clientIP = req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 
                        req.headers['x-forwarded-for'] || req.connection.socket.remoteAddress;
        
        // In ra console server với format rõ ràng
        console.log('\n' + '='.repeat(80));
        console.log('📱 COM PORT INPUT RECEIVED');
        console.log('='.repeat(80));
        console.log(`👤 User ID: ${userId || 'Unknown'}`);
        console.log(`🔑 Session ID: ${sessionId || 'Unknown'}`);
        console.log(`🔌 COM Port: ${comPort || 'Unknown'}`);
        console.log(`📊 Input Data: ${inputData || 'No data'}`);
        console.log(`⏰ Timestamp: ${timestamp || new Date().toISOString()}`);
        console.log(`🌐 Client IP: ${clientIP}`);
        console.log(`🕐 Server Time: ${new Date().toLocaleString('vi-VN')}`);
        console.log('='.repeat(80) + '\n');
        
        // Cập nhật lastActivity cho port usage
        if (comPort && userId) {
            await PortUsage.updateOne(
                { comPort: comPort, userId: userId, isActive: true },
                { lastActivity: new Date() }
            );
        }
        
        // Trả về response đơn giản
        res.json({
            success: true,
            message: 'Input received and logged',
            logged: true
        });
        
    } catch (error) {
        console.error('❌ Error logging COM input:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi ghi log input: ' + error.message
        });
    }
});

// API lấy COM ports của tất cả máy (admin only)
app.get('/api/admin/all-machines', requireLogin, requireAdmin, async (req, res) => {
    try {
        // Lấy tất cả máy
        const machines = await Machine.find({})
            .sort({ lastSeen: -1 })
            .lean();
        
        // Cập nhật trạng thái online/offline
        const now = new Date();
        const onlineThreshold = 5 * 60 * 1000; // 5 phút
        
        const machinesWithStatus = machines.map(machine => {
            const isOnline = (now - new Date(machine.lastSeen)) < onlineThreshold;
            return {
                ...machine,
                isOnline,
                timeSinceLastSeen: Math.floor((now - new Date(machine.lastSeen)) / 1000 / 60) // phút
            };
        });
        
        // Thống kê
        const stats = {
            totalMachines: machines.length,
            onlineMachines: machinesWithStatus.filter(m => m.isOnline).length,
            offlineMachines: machinesWithStatus.filter(m => !m.isOnline).length,
            totalComPorts: machines.reduce((sum, m) => sum + (m.comPorts?.length || 0), 0),
            totalAvailablePorts: machines.reduce((sum, m) => 
                sum + (m.comPorts?.filter(p => p.isAvailable).length || 0), 0
            )
        };
        
        res.json({
            success: true,
            data: {
                machines: machinesWithStatus,
                stats
            },
            message: `Tìm thấy ${machines.length} máy`
        });
        
    } catch (error) {
        console.error('Error getting all machines:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy danh sách máy: ' + error.message
        });
    }
});

// API để release tất cả port của machine
app.post('/api/release-all-machine-ports', requireLogin, async (req, res) => {
    try {
        const { machineId } = req.body;
        const username = req.session?.user?.username;
        
        console.log(`[API /api/release-all-machine-ports] User: ${username} releasing all ports for machine: ${machineId}`);
        
        const released = await PortUsage.releaseAllMachinePorts(machineId);
        
        console.log(`[API /api/release-all-machine-ports] Released ${released} ports for machine ${machineId}`);
        res.json({
            success: true,
            message: `Đã release ${released} port của machine ${machineId}`,
            releasedCount: released
        });
        
    } catch (error) {
        console.error('[API /api/release-all-machine-ports] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi release all machine ports: ' + error.message
        });
    }
});

// API để release tất cả port của session
app.post('/api/release-all-session-ports', requireLogin, async (req, res) => {
    try {
        const { sessionId } = req.body;
        const username = req.session?.user?.username;
        
        console.log(`[API /api/release-all-session-ports] User: ${username} releasing all ports for session: ${sessionId}`);
        
        const released = await PortUsage.releaseAllSessionPorts(sessionId);
        
        console.log(`[API /api/release-all-session-ports] Released ${released} ports for session ${sessionId}`);
        res.json({
            success: true,
            message: `Đã release ${released} port của session ${sessionId}`,
            releasedCount: released
        });
        
    } catch (error) {
        console.error('[API /api/release-all-session-ports] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi release all session ports: ' + error.message
        });
    }
});

// API để update heartbeat
app.post('/api/update-heartbeat', requireLogin, async (req, res) => {
    try {
        const { comPort } = req.body;
        const username = req.session?.user?.username;
        
        const updated = await PortUsage.updateHeartbeat(comPort, username);
        
        res.json({
            success: true,
            updated: updated,
            message: updated ? 'Heartbeat updated' : 'Port not found or not active'
        });
        
    } catch (error) {
        console.error('[API /api/update-heartbeat] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi update heartbeat: ' + error.message
        });
    }
});

// API để lấy thông tin port usage
app.get('/api/port-usage-info/:comPort', requireLogin, async (req, res) => {
    try {
        const { comPort } = req.params;
        const username = req.session?.user?.username;
        
        const info = await PortUsage.getPortUsageInfo(comPort);
        
        res.json({
            success: true,
            info: info,
            message: info ? 'Port usage info retrieved' : 'Port not in use'
        });
        
    } catch (error) {
        console.error('[API /api/port-usage-info] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi get port usage info: ' + error.message
        });
    }
});

// API để cleanup timeout ports (admin only)
app.post('/api/cleanup-timeout-ports', requireAdmin, async (req, res) => {
    try {
        const { timeoutSeconds = 30 } = req.body;
        const username = req.session?.user?.username;
        
        console.log(`[API /api/cleanup-timeout-ports] Admin: ${username} cleaning up ports with timeout ${timeoutSeconds}s`);
        
        const cleaned = await PortUsage.cleanupTimeoutPorts(timeoutSeconds);
        
        console.log(`[API /api/cleanup-timeout-ports] Cleaned up ${cleaned} timeout ports`);
        res.json({
            success: true,
            message: `Đã cleanup ${cleaned} timeout ports`,
            cleanedCount: cleaned
        });
        
    } catch (error) {
        console.error('[API /api/cleanup-timeout-ports] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi cleanup timeout ports: ' + error.message
        });
    }
});

// API kiểm tra trạng thái ComboData cache
app.get('/api/combo-cache/stats', requireLogin, requireAdmin, async (req, res) => {
    try {
        const stats = comboCache.getCacheStats();
        res.json({
            success: true,
            data: stats
        });
    } catch (error) {
        console.error('[API /api/combo-cache/stats] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy thống kê cache: ' + error.message
        });
    }
});

// API refresh ComboData cache
app.post('/api/combo-cache/refresh', requireLogin, requireAdmin, async (req, res) => {
    try {
        await comboCache.refreshCache();
        const stats = comboCache.getCacheStats();
        res.json({
            success: true,
            message: 'Cache đã được refresh thành công',
            data: stats
        });
    } catch (error) {
        console.error('[API /api/combo-cache/refresh] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi refresh cache: ' + error.message
        });
    }
});

// API thống kê số lượng đơn hàng theo nhân viên theo ngày
app.get('/api/stats/orders-by-employee', requireLogin, async (req, res) => {
    try {
        const { date } = req.query;
        const selectedDate = date ? new Date(date) : new Date();
        
        // Lấy ngày bắt đầu và kết thúc của ngày được chọn
        const startOfDay = new Date(selectedDate);
        startOfDay.setHours(0, 0, 0, 0);
        
        const endOfDay = new Date(selectedDate);
        endOfDay.setHours(23, 59, 59, 999);
        
        console.log(`[API /api/stats/orders-by-employee] Thống kê từ ${startOfDay.toISOString()} đến ${endOfDay.toISOString()}`);
        
        // Tìm tất cả đơn hàng đã được verify trong ngày
        const orders = await Order.find({
            verified: true,
            verifiedAt: {
                $gte: startOfDay,
                $lte: endOfDay
            }
        }).select('checkingBy verifiedAt maVanDon maHang soLuong scannedQuantity');
        
        console.log(`[API /api/stats/orders-by-employee] Tìm thấy ${orders.length} đơn hàng đã verify`);
        
        // Nhóm theo nhân viên
        const employeeStats = {};
        let totalOrders = 0;
        let totalItems = 0;
        
        orders.forEach(order => {
            const employee = order.checkingBy || 'Không xác định';
            
            if (!employeeStats[employee]) {
                employeeStats[employee] = {
                    employeeName: employee,
                    totalOrders: 0,
                    totalItems: 0,
                    orders: []
                };
            }
            
            employeeStats[employee].totalOrders++;
            employeeStats[employee].totalItems += (order.scannedQuantity || order.soLuong || 1);
            employeeStats[employee].orders.push({
                maVanDon: order.maVanDon,
                maHang: order.maHang,
                soLuong: order.soLuong,
                scannedQuantity: order.scannedQuantity,
                verifiedAt: order.verifiedAt
            });
            
            totalOrders++;
            totalItems += (order.scannedQuantity || order.soLuong || 1);
        });
        
        // Chuyển đổi object thành array và sắp xếp theo số lượng đơn hàng giảm dần
        const statsArray = Object.values(employeeStats).sort((a, b) => b.totalOrders - a.totalOrders);
        
        console.log(`[API /api/stats/orders-by-employee] Thống kê: ${statsArray.length} nhân viên, ${totalOrders} đơn hàng, ${totalItems} sản phẩm`);
        
        res.json({
            success: true,
            data: {
                date: selectedDate.toISOString().split('T')[0],
                totalEmployees: statsArray.length,
                totalOrders: totalOrders,
                totalItems: totalItems,
                employeeStats: statsArray
            }
        });
        
    } catch (error) {
        console.error('[API /api/stats/orders-by-employee] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy thống kê: ' + error.message
        });
    }
});
