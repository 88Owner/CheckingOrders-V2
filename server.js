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
        maxAge: 14 * 24 * 60 * 60 * 1000 // 14 days
    }
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
    if (req.session.user) {
        return next();
    }
    return res.status(401).json({ success: false, message: 'Vui lòng đăng nhập' });
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

        // Create session
        req.session.user = {
            username: account.username,
            role: account.role
        };

        // Create JWT token for API access
        const token = jwt.sign(
            { username: account.username, role: account.role },
            config.SESSION_SECRET,
            { expiresIn: '24h' }
        );

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
                     (account.role === 'checker' || account.role === 'packer') ? '/checker-home' : '/'
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

        if (!['user', 'admin', 'packer', 'checker'].includes(role)) {
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
        
        // console.log(`[UPDATE ROLE] Admin ${req.session.username} yêu cầu đổi role cho account ID: ${accountId} -> ${role}`);
        
        if (!role || !['user','admin','packer','checker'].includes(role)) {
            // console.log(`[UPDATE ROLE] Quyền không hợp lệ: ${role}`);
            return res.json({ success: false, message: 'Quyền không hợp lệ' });
        }
        
        const account = await Account.findById(accountId);
        if (!account) {
            // console.log(`[UPDATE ROLE] Không tìm thấy account ID: ${accountId}`);
            return res.json({ success: false, message: 'Không tìm thấy tài khoản' });
        }
        
        if (account.username === 'admin') {
            // console.log(`[UPDATE ROLE] Không thể đổi quyền tài khoản admin gốc`);
            return res.json({ success: false, message: 'Không thể đổi quyền tài khoản admin gốc' });
        }
        
        const oldRole = account.role;
        account.role = role;
        await account.save();
        
        // console.log(`[UPDATE ROLE] Đã save vào database. User: ${account.username}, ${oldRole} -> ${role}`);
        
        // Verify lại từ database để chắc chắn đã update
        const verifyAccount = await Account.findById(accountId);
        // console.log(`[UPDATE ROLE] Verify từ DB: role = ${verifyAccount.role}`);
        
        if (verifyAccount.role !== role) {
            // console.error(`[UPDATE ROLE] CẢNH BÁO! Role trong DB (${verifyAccount.role}) khác với role mong đợi (${role})`);
            return res.json({
                success: false,
                message: 'Lỗi: Role không được lưu vào database'
            });
        }
        
        // console.log(`[UPDATE ROLE] Thành công! Role đã được lưu vào MongoDB`);
        
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
        let username = null;
        let role = null;

        const auth = req.headers.authorization || '';
        if (auth.startsWith('Bearer ')) {
            try {
                const decoded = jwt.verify(auth.substring(7), config.SESSION_SECRET);
                username = decoded.username;
                role = decoded.role;
            } catch {}
        }
        
        if (!username && req.session.user) {
            username = req.session.user.username;
            role = req.session.user.role;
        }

        if (!username) {
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

// Route trang check đơn hàng
app.get('/check', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'check.html'));
});

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
                console.log(`� User ${username} logout - đã unblock ${blockedOrders.length} đơn hàng`);
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
app.delete('/api/orders', async (req, res) => {
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
        console.log(`🔍 API /api/orders/by-van-don/${req.params.maVanDon} called by user: ${req.authUser?.username}`);
        
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
        console.log(`📦 Found ${orders.length} orders for maVanDon: ${maVanDon}`);
        
        // Map ComboData để convert mã combo thành mã base nếu cần
        const ComboData = require('./models/ComboData');
        let comboDatas = [];
        try {
            comboDatas = await ComboData.find({});
        } catch (error) {
            console.log('ComboData collection không tồn tại hoặc rỗng:', error.message);
        }
        const comboMap = new Map();
        for (const cd of comboDatas) {
            if (cd && cd.comboCode) {
                comboMap.set(cd.comboCode, cd);
            }
        }
        
        // Tính toán displayMaHang và displaySoLuong trước
        const processedOrders = orders.map(o => {
            const combo = comboMap.get(o.maHang);
            let displayMaHang = o.maHang;
            let displaySoLuong = o.soLuong;
            let isCombo = false;
            
            if (combo) {
                // Nếu là combo: hiển thị mã base, số lượng đã nhân combo
                displayMaHang = combo.maHang || o.maHang;
                // Hiển thị số lượng đã nhân combo: soLuong_trong_DB * combo_multiplier
                displaySoLuong = o.soLuong * (combo.soLuong || 1);
                isCombo = true;
                console.log(`🔍 Order combo: ${o.maHang} -> ${displayMaHang} x${displaySoLuong} (DB: ${o.soLuong}, combo x${combo.soLuong})`);
            } else {
                // Nếu không phải combo: hiển thị mã gốc, số lượng gốc
                displayMaHang = o.maHang;
                displaySoLuong = o.soLuong; // Số lượng gốc từ database
                isCombo = false;
            }
            
            return {
                ...o.toObject(), // Convert Mongoose document to plain object
                displayMaHang,
                displaySoLuong,
                isCombo,
                combo
            };
        });
        
        // Lấy thông tin MasterData cho tất cả mã hàng (cả gốc và display)
        const allSkuList = [...new Set([
            ...orders.map(o => o.maHang),
            ...processedOrders.map(o => o.displayMaHang)
        ])];
        console.log(`[MASTERDATA] Looking for SKUs:`, allSkuList);
        
        // Kiểm tra tổng số MasterData trong collection
        const totalMasterData = await MasterData.countDocuments();
        console.log(`[MASTERDATA] Total MasterData in collection: ${totalMasterData}`);
        
        let masterDatas = [];
        try {
            masterDatas = await MasterData.find({ sku: { $in: allSkuList } });
            console.log(`[MASTERDATA] Found ${masterDatas.length} MasterData records for requested SKUs`);
        } catch (error) {
            console.error('❌ [MASTERDATA] Error loading MasterData:', error);
            masterDatas = [];
        }
        
        const masterMap = new Map();
        for (const md of masterDatas) {
            if (md.sku) {
                masterMap.set(md.sku, md);
                console.log(`✅ [MASTERDATA] Mapped SKU: ${md.sku} -> MàuVải: ${md.mauVai || 'N/A'}, TênPhiênBản: ${md.tenPhienBan || 'N/A'}`);
                console.log(`🔍 [MASTERDATA] Full MasterData fields:`, Object.keys(md.toObject()));
            }
        }
        
        const mappedOrders = processedOrders.map(o => {
            // Tìm MasterData theo displayMaHang (mã base để hiển thị)
            const md = masterMap.get(o.displayMaHang);
            
            return {
                ...o, // o đã là plain object từ processedOrders
                maHang: o.displayMaHang, // Hiển thị mã base
                soLuong: o.displaySoLuong, // Hiển thị số lượng đúng
                originalMaHang: o.maHang, // Giữ mã combo gốc
                isCombo: o.isCombo,
                comboInfo: o.combo ? {
                    comboCode: o.combo.comboCode,
                    comboSoLuong: o.combo.soLuong,
                    originalSoLuong: o.soLuong / (o.combo.soLuong || 1), // Số lượng gốc từ file (chưa nhân combo)
                    calculatedSoLuong: o.soLuong // Số lượng đã nhân combo trong database
                } : null,
                mauVai: md && typeof md.mauVai === 'string' ? md.mauVai : '',
                tenPhienBan: md && typeof md.tenPhienBan === 'string' ? md.tenPhienBan : ''
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
            console.log(`All orders completed for maVanDon: ${maVanDon}`);
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

        // Block tất cả đơn hàng trong mã vận đơn cho user hiện tại
        for (const order of orders) {
            if (!order.block || order.checkingBy === userId) {
                order.block = true;
                order.checkingBy = userId;
                order.blockedAt = new Date();
                await order.save();
            }
        }

        console.log(`User ${userId} đã block đơn vận đơn ${maVanDon} với ${orders.length} đơn hàng`);

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
        console.log(`✅ Returning ${mappedOrders.length} orders for maVanDon: ${maVanDon}`);
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
        
        // Chỉ admin mới có thể xem tất cả behaviour
        if (req.authUser.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Chỉ admin mới có thể xem user behaviour'
            });
        }
        
        const query = {};
        if (user) query.user = user;
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
            const combo = await ComboData.findOne({ comboCode: maHang });
            if (combo) {
                const base = combo.maHang || 'mã base của combo';
                return res.json({
                    success: false,
                    message: `Đây là mã combo (${maHang}). Vui lòng quét mã hàng base: ${base}`
                });
            }
        }

        // Tìm đơn hàng cụ thể - Logic cải thiện cho ComboData:
        // 1. Tìm trực tiếp với maHang (cho trường hợp non-combo)
        // 2. Nếu không tìm thấy, tìm tất cả combo có mã base = maHang đang quét, 
        //    rồi tìm order với mã combo phù hợp trong maVanDon
        let order = await Order.findOne({ maVanDon, maHang });
        let isComboOrder = false;
        
        if (!order) {
            // Có thể là combo: tìm tất cả combo có mã base = maHang đang quét
            const ComboData = require('./models/ComboData');
            const combos = await ComboData.find({ maHang: maHang });
            console.log(`🔍 Found ${combos.length} combos for base maHang: ${maHang}`);
            
            // Tìm order với combo code phù hợp trong maVanDon
            for (const combo of combos) {
                const comboOrder = await Order.findOne({ maVanDon, maHang: combo.comboCode });
                if (comboOrder) {
                    order = comboOrder;
                    isComboOrder = true;
                    console.log(`🔍 Found matching combo: ${combo.comboCode} -> ${combo.maHang}, found order: ${!!order}`);
                    break; // Tìm thấy order phù hợp thì dừng
                }
            }
        } else {
            // Kiểm tra xem maHang này có phải là combo code không
            const ComboData = require('./models/ComboData');
            const combo = await ComboData.findOne({ comboCode: maHang });
            if (combo) {
                isComboOrder = true;
                console.log(`🔍 Input is combo code: ${maHang} -> ${combo.maHang}`);
            }
        }

        if (!order) {
            return res.json({
                success: false,
                message: 'Không tìm thấy mã hàng trong đơn vận đơn này'
            });
        }

        // Kiểm tra timeout - nếu block quá 10 phút thì tự động unblock
        const now = new Date();
        const blockTimeout = 10 * 60 * 1000; // 10 phút
        if (order.block && order.blockedAt && (now - order.blockedAt) > blockTimeout) {
            order.block = false;
            order.checkingBy = null;
            order.blockedAt = null;
            // Reset trạng thái quét khi timeout auto-unblock
            order.scannedQuantity = 0;
            order.verified = false;
            order.verifiedAt = null;
            await order.save();
            console.log(`🕐 Tự động unblock đơn hàng ${order.maHang} do timeout và reset trạng thái quét`);
        }

        // Nếu đang bị block bởi người khác
        if (order.block && order.checkingBy !== userId) {
            return res.json({
                success: false,
                blocked: true,
                message: `Mã hàng ${displayMaHang} đang được ${order.checkingBy} kiểm tra. Vui lòng chờ ${order.checkingBy} hoàn thành hoặc thử lại sau.`
            });
        }

        // Nếu chưa ai check hoặc chưa bị block, gán checkingBy và block đơn này ngay khi truy xuất
        if (!order.checkingBy || !order.block) {
            order.checkingBy = userId;
            order.block = true;
            order.blockedAt = new Date();
            await order.save();
            console.log(`User ${userId} đã block đơn hàng ${order.maHang}`);
        }

        // Kiểm tra đã xác nhận chưa
        if (order.verified) {
            return res.json({
                success: false,
                message: `Mã hàng ${maHang} đã được xác nhận trước đó`,
                data: {
                    maHang: order.maHang,
                    soLuong: order.soLuong,
                    verified: true,
                    verifiedAt: order.verifiedAt
                }
            });
        }

        // Xác định mã hiển thị và thông tin combo
        let displayMaHang = maHang; // Mặc định là mã đang quét
        let comboInfo = null;
        
        if (isComboOrder) {
            // Trường hợp combo: hiển thị mã base, lấy thông tin combo
            const ComboData = require('./models/ComboData');
            const combo = await ComboData.findOne({ comboCode: order.maHang });
            if (combo) {
                displayMaHang = combo.maHang || maHang;
                comboInfo = {
                    comboCode: combo.comboCode,
                    comboSoLuong: combo.soLuong,
                    originalSoLuong: order.soLuong / (combo.soLuong || 1),
                    calculatedSoLuong: order.soLuong
                };
                console.log(`📦 Combo info: ${combo.comboCode} -> ${combo.maHang} x${combo.soLuong}`);
            }
        } else {
            // Trường hợp non-combo: hiển thị mã gốc
            displayMaHang = order.maHang;
        }

        // Database lưu mã combo và số lượng gốc (chưa nhân combo)
        // So sánh scannedQuantity với soLuong đã nhân combo
        if (!order.scannedQuantity) {
            order.scannedQuantity = 0;
        }
        
        // Tính số lượng cần quét (đã nhân combo)
        let requiredQuantity = order.soLuong;
        if (isComboOrder) {
            const ComboData = require('./models/ComboData');
            const combo = await ComboData.findOne({ comboCode: order.maHang });
            if (combo) {
                requiredQuantity = order.soLuong * (combo.soLuong || 1);
                console.log(`📦 Scan logic: ${order.soLuong} * ${combo.soLuong} = ${requiredQuantity} scans needed`);
            }
        }
        
        if (order.scannedQuantity >= requiredQuantity) {
            return res.json({
                success: false,
                message: `Mã hàng ${displayMaHang} đã đủ số lượng (${order.scannedQuantity}/${requiredQuantity}). Không thể quét thêm.`
            });
        }
        order.scannedQuantity += 1;

        // Chỉ hoàn thành khi quét đủ đúng số lượng (đã nhân combo)
        if (order.scannedQuantity === requiredQuantity) {
            order.verified = true;
            order.verifiedAt = new Date();
            console.log(`User ${userId} đã hoàn thành đơn hàng ${displayMaHang} (${order.scannedQuantity}/${requiredQuantity})`);
        } else {
            order.verified = false;
        }
        
        // KHÔNG cập nhật block/unblock khi quét maHang
        // Chỉ cập nhật block/unblock khi confirm đơn (quét lại maVanDon)

        // Lưu trực tiếp vào database
        await order.save();

        console.log(`Đã quét mã hàng ${displayMaHang}: ${order.scannedQuantity}/${requiredQuantity} - Status: ${order.verified ? 'COMPLETED' : 'IN_PROGRESS'}`);
        
        // Lưu user behaviour cho việc quét mã hàng
        try {
            const UserBehaviour = require('./models/UserBehaviour');
            const behaviour = new UserBehaviour({
                user: userId,
                method: 'scanner',
                description: `Quét mã hàng: ${displayMaHang} - Tiến độ: ${order.scannedQuantity}/${requiredQuantity} - ${order.verified ? 'Hoàn thành' : 'Đang quét'}`,
                metadata: {
                    maVanDon,
                    maHang: displayMaHang,
                    originalMaHang: order.maHang,
                    scannedQuantity: order.scannedQuantity,
                    requiredQuantity,
                    verified: order.verified,
                    isCombo: isComboOrder,
                    comboInfo: comboInfo
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
            message: order.verified ? 
                `Hoàn thành mã hàng ${displayMaHang}! (${order.scannedQuantity}/${requiredQuantity})` :
                `Đã quét mã hàng ${displayMaHang}! (${order.scannedQuantity}/${requiredQuantity})`,
            data: {
                maHang: displayMaHang,
                soLuongYeuCau: requiredQuantity,
                soLuongDaQuet: order.scannedQuantity,
                originalMaHang: order.maHang,
                isCombo: isComboOrder,
                comboInfo: comboInfo,
                verified: order.verified,
                verifiedAt: order.verifiedAt,
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
        // Với combo items, cần kiểm tra scannedQuantity với requiredQuantity (đã nhân combo)
        const allCompleted = await Promise.all(orders.map(async (order) => {
            if (!order.verified) return false;
            
            // Tính requiredQuantity cho combo items
            let requiredQuantity = order.soLuong;
            const ComboData = require('./models/ComboData');
            const combo = await ComboData.findOne({ comboCode: order.maHang });
            if (combo) {
                requiredQuantity = order.soLuong * (combo.soLuong || 1);
            }
            
            return order.scannedQuantity === requiredQuantity;
        }));
        
        const allItemsCompleted = allCompleted.every(completed => completed);

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
                checkingBy: null,       // Xóa checkingBy
                blockedAt: null         // Xóa blockedAt
            }
        );

        console.log(`User ${userId} đã hoàn thành đơn vận đơn ${maVanDon}`);
        
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
            console.log(`User ${userId} đã unblock đơn hàng ${order.maHang} và reset trạng thái quét`);
            
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

        let unblockedCount = 0;
        // Unblock tất cả đơn hàng mà user hiện tại đang check
        // Đồng thời reset trạng thái quét để đảm bảo tính nhất quán
        for (const order of orders) {
            if (order.checkingBy === userId && order.block) {
                order.checkingBy = null;
                order.block = false;
                order.blockedAt = null;
                // Reset trạng thái quét khi hủy đơn
                order.scannedQuantity = 0;
                order.verified = false;
                order.verifiedAt = null;
                await order.save();
                unblockedCount++;
            }
        }

        console.log(`User ${userId} đã unblock ${unblockedCount} đơn hàng trong mã vận đơn ${maVanDon}`);
        
        return res.json({
            success: true,
            message: `Đã unblock ${unblockedCount} đơn hàng thành công`
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

// API claim port khi kết nối
app.post('/api/claim-port', requireLogin, async (req, res) => {
    try {
        const { comPort, machineId, sessionId, screenId } = req.body;
        const username = req.session?.user?.username;
        
        console.log(`[API /api/claim-port] User: ${username} claiming COM Port: ${comPort}, Machine: ${machineId}, Session: ${sessionId}, Screen: ${screenId}`);
        
        // Kiểm tra xem port có đang được sử dụng bởi user khác không
        const isInUse = await PortUsage.isPortInUse(comPort, username);
        if (isInUse) {
            const currentUser = await PortUsage.getCurrentUser(comPort);
            return res.status(409).json({
                success: false,
                message: `COM port ${comPort} đang được sử dụng bởi ${currentUser}. Vui lòng đợi user đó ngắt kết nối.`
            });
        }
        
        // Claim port với machine/session tracking
        const usage = await PortUsage.claimPort(comPort, username, machineId, sessionId, screenId);
        console.log(`[API /api/claim-port] User ${username} successfully claimed port ${comPort}`);
        
        res.json({
            success: true,
            message: `Đã kết nối thành công với COM port ${comPort}`,
            usage: usage
        });
        
    } catch (error) {
        console.error('[API /api/claim-port] Error:', error);
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
        
        console.log(`[API /api/delete-all-user-ports] User: ${username} deleting all port records for user: ${userId}`);
        console.log(`[API /api/delete-all-user-ports] Request body:`, req.body);
        
        // Kiểm tra xem có bản ghi nào của user này không
        const existingPorts = await PortUsage.find({ userId: userId });
        console.log(`[API /api/delete-all-user-ports] Found ${existingPorts.length} existing port records for user ${userId}:`, existingPorts.map(p => ({ comPort: p.comPort, isActive: p.isActive })));
        
        // Xóa hoàn toàn tất cả bản ghi port của user
        const deleted = await PortUsage.deleteAllUserPorts(userId);
        
        // Cleanup timeout ports (heartbeat > 30 seconds)
        const cleaned = await PortUsage.cleanupTimeoutPorts(30);
        
        console.log(`[API /api/delete-all-user-ports] Deleted ${deleted} port records for user ${userId}, cleaned ${cleaned} timeout ports`);
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
        const { userId, comPort, inputData, timestamp } = req.body;
        
        // Kiểm tra quyền sử dụng COM port
        if (comPort && userId) {
            const currentUser = await PortUsage.getCurrentUser(comPort);
            console.log(`🔍 [COM-INPUT] Checking permission for user ${userId} on port ${comPort}, current user: ${currentUser}`);
            
            if (currentUser && currentUser !== userId) {
                console.log(`🚫 [COM-INPUT] User ${userId} không có quyền sử dụng COM port ${comPort} (đang được sử dụng bởi ${currentUser})`);
                return res.status(403).json({
                    success: false,
                    message: `COM port ${comPort} đang được sử dụng bởi user khác`,
                    currentUser: currentUser
                });
            }
            
            // Nếu không có user nào đang sử dụng port, từ chối input
            if (!currentUser) {
                console.log(`🚫 [COM-INPUT] User ${userId} không có quyền sử dụng COM port ${comPort} (port chưa được claim)`);
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
