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
const http = require('http');
const fs = require('fs');
const { URL } = require('url');
const bwipjs = require('bwip-js');
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
const MasterDataVai = require('./models/MasterDataVai');
const NhapPhoi = require('./models/NhapPhoi');
const DoiTuongCatVai = require('./models/DoiTuongCatVai');
const DatabaseConfig = require('./models/DatabaseConfig');
const Template = require('./models/Template');
const QAOrder = require('./models/QAOrder');
const QAOrderProgress = require('./models/QAOrderProgress');
const Counter = require('./models/Counter');

const QA_ORDER_CODE_COUNTER_ID = 'qa_order_code';

let qaOrderCodeCounterSeeded = false;

async function getNextQaOrderCode() {
    if (!qaOrderCodeCounterSeeded) {
        qaOrderCodeCounterSeeded = true;
        const agg = await QAOrder.aggregate([
            { $match: { orderCode: { $regex: /^PO\d{5}$/ } } },
            { $project: { n: { $toInt: { $substrCP: ['$orderCode', 2, 5] } } } },
            { $group: { _id: null, max: { $max: '$n' } } }
        ]);
        const maxN = agg[0]?.max || 0;
        if (maxN > 0) {
            await Counter.updateOne({ _id: QA_ORDER_CODE_COUNTER_ID }, { $max: { seq: maxN } }, { upsert: true });
        }
    }
    const doc = await Counter.findOneAndUpdate(
        { _id: QA_ORDER_CODE_COUNTER_ID },
        { $inc: { seq: 1 } },
        { new: true, upsert: true }
    ).lean();
    const n = Number(doc.seq) || 1;
    return `PO${String(n).padStart(5, '0')}`;
}

/** Hàng đợi theo khóa công đoạn (currentStage trên QAOrder) */
const PRODUCTION_STAGE_QUEUE = {
    fabric_cutting: ['Cắt vải', 'Tạo đơn'],
    cotton_press: ['Ép bông'],
    sewing: ['May'],
    eyelet: ['Đóng khoen'],
    assembly: ['Tổ hợp']
};

const ROLE_TO_PRODUCTION_STAGE_KEY = {
    fabric_cutting_team: 'fabric_cutting',
    cotton_press_team: 'cotton_press',
    sewing_team: 'sewing',
    eyelet_team: 'eyelet',
    assembly_team: 'assembly'
};

function resolveProductionQueueStageKey(req) {
    const role = req.session.user?.role;
    const mapped = ROLE_TO_PRODUCTION_STAGE_KEY[role];
    if (mapped) return mapped;
    if (role === 'production_manager' || role === 'production_worker') {
        const k = String(req.query.stageKey || '').trim();
        return PRODUCTION_STAGE_QUEUE[k] ? k : null;
    }
    return null;
}

/**
 * Sau ép bông: tự chọn nhánh Đóng khoen vs May theo tên SP.
 * — Có "Rido" (không phân biệt hoa thường) → Đóng khoen
 * — Có "Rèm giường" (bỏ dấu so khớp tương đương) → Đóng khoen
 * — Còn lại → May
 */
function foldViPlain(s) {
    return String(s || '')
        .normalize('NFD')
        .replace(/[\u0300-\u036f\u0323\u031b]/g, '')
        .replace(/đ/gi, 'd')
        .toLowerCase()
        .replace(/\s+/g, ' ')
        .trim();
}

function resolveRouteAfterPressFromProductName(productName) {
    const raw = String(productName || '').trim();
    if (!raw) return 'May';
    if (/rido/i.test(raw)) return 'Đóng khoen';
    const folded = foldViPlain(raw);
    if (/\brem\s+giuong\b/.test(folded) || folded.includes('rem giuong')) return 'Đóng khoen';
    return 'May';
}

function effectiveProductionStage(order) {
    const cur = String(order.currentStage || 'Tạo đơn').trim();
    return cur === 'Tạo đơn' ? 'Cắt vải' : cur;
}

function isOrderAtProductionStage(order, stageLabel) {
    const cur = String(order.currentStage || 'Tạo đơn').trim();
    const st = String(stageLabel || '').trim();
    if (st === 'Cắt vải') return cur === 'Tạo đơn' || cur === 'Cắt vải';
    return cur === st;
}

function nextProductionStageAfterRecord(order) {
    const eff = effectiveProductionStage(order);
    if (eff === 'Cắt vải') return 'Ép bông';
    if (eff === 'Ép bông') return order.routeAfterPress || 'May';
    if (eff === 'May' || eff === 'Đóng khoen') return 'Tổ hợp';
    if (eff === 'Tổ hợp') return 'Hoàn thành';
    return order.currentStage;
}

/** Khâu ngay trước (đầu vào SL đạt) khi đang ghi nhận tại `stageLabel` */
function getPreviousProductionStageForRecord(order, stageLabel) {
    const st = String(stageLabel || '').trim();
    if (st === 'Cắt vải') return null;
    if (st === 'Ép bông') return 'Cắt vải';
    if (st === 'May' || st === 'Đóng khoen') return 'Ép bông';
    if (st === 'Tổ hợp') {
        return order.routeAfterPress === 'Đóng khoen' ? 'Đóng khoen' : 'May';
    }
    if (st === 'Hoàn thành') return 'Tổ hợp';
    return null;
}

/** Khâu trước để hiển thị trên QA (theo currentStage của đơn) */
function getDisplayPreviousStageForOrder(order) {
    const cur = String(order.currentStage || 'Tạo đơn').trim();
    if (cur === 'Tạo đơn' || cur === 'Cắt vải') return null;
    if (cur === 'Ép bông') return 'Cắt vải';
    if (cur === 'May' || cur === 'Đóng khoen') return 'Ép bông';
    if (cur === 'Tổ hợp') {
        return order.routeAfterPress === 'Đóng khoen' ? 'Đóng khoen' : 'May';
    }
    if (cur === 'Hoàn thành') return 'Tổ hợp';
    return null;
}

async function sumCompletedQtyForStage(orderCode, stage) {
    if (!stage) return 0;
    const agg = await QAOrderProgress.aggregate([
        { $match: { orderCode, stage } },
        { $group: { _id: null, t: { $sum: '$completedQty' } } }
    ]);
    return Number(agg[0]?.t) || 0;
}

function parseProductionNaturalInt(value, fieldLabel, { allowEmpty = false } = {}) {
    if (value === null || value === undefined || value === '') {
        if (allowEmpty) return null;
        throw new Error(`${fieldLabel}: bắt buộc nhập số tự nhiên`);
    }
    const s = String(value).trim();
    if (s === '') {
        if (allowEmpty) return null;
        throw new Error(`${fieldLabel}: bắt buộc nhập số tự nhiên`);
    }
    if (!/^\d+$/.test(s)) {
        throw new Error(`${fieldLabel}: chỉ được nhập số tự nhiên (0–9), không chữ hoặc ký tự đặc biệt`);
    }
    const n = parseInt(s, 10);
    if (n > Number.MAX_SAFE_INTEGER) {
        throw new Error(`${fieldLabel}: số quá lớn`);
    }
    return n;
}

async function buildProductionScanMeta(order) {
    const workStage = effectiveProductionStage(order);
    const prev = getPreviousProductionStageForRecord(order, workStage);
    const qtyPO = Number(order.quantity || 0);
    let inboundCap = qtyPO;
    let prevLabel = '';
    if (prev) {
        inboundCap = await sumCompletedQtyForStage(order.orderCode, prev);
        prevLabel = prev;
    } else {
        prevLabel = 'Số lượng đơn (PO)';
    }
    return {
        stage: workStage,
        prevStageLabel: prevLabel,
        inboundCap,
        inboundCapNote: prev
            ? `Tối đa (SL đạt từ khâu trước «${prev}»): ${inboundCap}`
            : `Tối đa (SL đơn): ${inboundCap}`
    };
}

const comboCache = require('./utils/comboCache');
const SimpleLocking = require('./utils/simpleLocking');
const masterDataUploadRouter = require('./routes/masterDataUpload');
const checkerUploadRouter = require('./routes/checkerUpload');
const exportNhapPhoiRouter = require('./routes/exportNhapPhoi');
const barcodeRouter = require('./routes/barcode');
const app = express();

// Middleware - Phải setup trước các router
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration - Phải setup trước các router cần authentication
// Sử dụng mongoUrl với config.MONGODB_URI
// Lưu reference đến session store để có thể cập nhật khi chuyển đổi database
let sessionStore = MongoStore.create({
    mongoUrl: config.MONGODB_URI,
    ttl: 14 * 24 * 60 * 60 // 14 days
});

app.use(session({
    secret: config.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        maxAge: 14 * 24 * 60 * 60 * 1000, // 14 days
        sameSite: 'lax' // Thêm sameSite để tránh vấn đề với cookie
    },
    name: 'sessionId' // Đặt tên session cookie cụ thể
}));

// Middleware để cập nhật session store động khi chuyển đổi database
// Override sessionStore trong request để dùng store mới
app.use((req, res, next) => {
    // Nếu session store đã được cập nhật, override trong request
    if (sessionStore && req.sessionStore) {
        // Thay thế sessionStore trong request bằng store mới
        // Điều này đảm bảo các operations session sử dụng store mới
        try {
            Object.defineProperty(req, 'sessionStore', {
                value: sessionStore,
                writable: true,
                configurable: true
            });
        } catch (e) {
            // Nếu không thể override, ít nhất log warning
            console.warn('[SESSION STORE] Không thể override sessionStore:', e.message);
        }
    }
    next();
});

// Đăng ký router upload SAU KHI session middleware đã được setup
app.use(masterDataUploadRouter);
app.use(checkerUploadRouter);
app.use('/api/export-nhap-phoi', exportNhapPhoiRouter);
app.use(barcodeRouter);

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

        // Kiểm tra mapping Employee cho production_worker
        // Nếu là production_worker mà chưa có mapping Employee thì không cho login
        if (account.role === 'production_worker' && !account.erpnextEmployeeId) {
            return res.json({ 
                success: false, 
                message: 'Tài khoản chưa được mapping với Employee trong ERPNext. Vui lòng liên hệ quản trị viên để được cấu hình.' 
            });
        }

        // Create JWT token for API access
        const token = jwt.sign(
            { username: account.username, role: account.role },
            config.SESSION_SECRET,
            { expiresIn: '24h' }
        );

        // Lấy thông tin Employee từ ERPNext nếu có mapping
        let erpnextEmployeeInfo = null;
        if (account.erpnextEmployeeId) {
            try {
                const employeeResult = await erpnextAPI('GET', `Employee/${account.erpnextEmployeeId}`, null, null, null);
                if (employeeResult.data) {
                    erpnextEmployeeInfo = {
                        id: employeeResult.data.name,
                        name: employeeResult.data.employee_name || employeeResult.data.name,
                        employeeNumber: employeeResult.data.employee_number || null
                    };
                    // Cập nhật cache tên nhân viên
                    if (employeeResult.data.employee_name && account.erpnextEmployeeName !== employeeResult.data.employee_name) {
                        account.erpnextEmployeeName = employeeResult.data.employee_name;
                        await account.save();
                    }
                } else {
                    // Nếu không tìm thấy Employee trong ERPNext, từ chối login cho production_worker
                    if (account.role === 'production_worker') {
                        return res.json({ 
                            success: false, 
                            message: 'Không tìm thấy Employee trong ERPNext với ID đã mapping. Vui lòng liên hệ quản trị viên.' 
                        });
                    }
                }
            } catch (error) {
                console.log('Không thể lấy thông tin Employee từ ERPNext:', error.message);
                // Nếu có cache, dùng cache
                if (account.erpnextEmployeeName) {
                    erpnextEmployeeInfo = {
                        id: account.erpnextEmployeeId,
                        name: account.erpnextEmployeeName,
                        employeeNumber: null
                    };
                } else {
                    // Nếu không có cache và là production_worker, từ chối login
                    if (account.role === 'production_worker') {
                        return res.json({ 
                            success: false, 
                            message: 'Không thể xác thực Employee trong ERPNext. Vui lòng liên hệ quản trị viên.' 
                        });
                    }
                }
            }
        }

        // Create session
        req.session.user = {
            username: account.username,
            role: account.role,
            token: token,
            erpnextEmployeeId: account.erpnextEmployeeId,
            erpnextEmployeeName: erpnextEmployeeInfo?.name || account.erpnextEmployeeName || account.username
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
            erpnextEmployee: erpnextEmployeeInfo,
            employeeName: erpnextEmployeeInfo?.name || account.erpnextEmployeeName || account.username,
            redirect: account.role === 'admin' ? '/admin' : 
                     (account.role === 'checker' || account.role === 'packer') ? '/checker-home' :
                     account.role === 'warehouse_manager' ? '/warehouse-manager' :
                     account.role === 'warehouse_staff' ? '/warehouse-staff' :
                     account.role === 'production_worker' ? '/production-status' :
                     account.role === 'reconciler' ? '/reconciler-home' :
                     account.role === 'production_manager' ? '/production-manager' :
                     account.role === 'qa' ? '/qa-dashboard' :
                     account.role === 'fabric_cutting_team' ? '/fabric-cutting-team' :
                     account.role === 'cotton_press_team' ? '/cotton-press-team' :
                     account.role === 'eyelet_team' ? '/eyelet-team' :
                     account.role === 'sewing_team' ? '/sewing-team' :
                     account.role === 'assembly_team' ? '/assembly-team' :
                     '/'
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

        if (!['user', 'admin', 'packer', 'checker', 'warehouse_manager', 'warehouse_staff', 'production_worker', 'reconciler', 'production_manager', 'qa', 'fabric_cutting_team', 'cotton_press_team', 'eyelet_team', 'sewing_team', 'assembly_team'].includes(role)) {
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

        let message = 'Tạo tài khoản thành công';
        if (role === 'production_worker') {
            message += '. Lưu ý: Vui lòng mapping Employee trong ERPNext để nhân viên có thể đăng nhập.';
        }

        res.json({ success: true, message: message });

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

// Route reconciler (Đối soát) home page
app.get('/reconciler-home', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'reconciler-home.html'));
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

// API cập nhật ERPNext Employee mapping cho user
app.put('/api/accounts/:id/erpnext-employee', requireLogin, requireAdmin, async (req, res) => {
    try {
        const { erpnextEmployeeId } = req.body;
        const accountId = req.params.id;
        
        console.log(`[UPDATE ERPNext Employee] Admin ${req.session.user.username} mapping employee cho account ID: ${accountId} -> ${erpnextEmployeeId}`);
        
        const account = await Account.findById(accountId);
        if (!account) {
            return res.json({ success: false, message: 'Không tìm thấy tài khoản' });
        }

        // Cảnh báo nếu xóa mapping của production_worker
        if (account.role === 'production_worker' && account.erpnextEmployeeId && !erpnextEmployeeId) {
            return res.json({ 
                success: false, 
                message: 'Không thể xóa mapping Employee cho nhân viên sản xuất. Tài khoản này bắt buộc phải có mapping Employee để có thể đăng nhập.' 
            });
        }

        // Nếu có employeeId, lấy thông tin từ ERPNext
        let employeeName = null;
        if (erpnextEmployeeId) {
            try {
                const employeeResult = await erpnextAPI('GET', `Employee/${erpnextEmployeeId}`, null, null, null);
                if (employeeResult.data) {
                    employeeName = employeeResult.data.employee_name || employeeResult.data.name;
                } else {
                    return res.json({ 
                        success: false, 
                        message: `Không tìm thấy Employee với ID: ${erpnextEmployeeId}. Vui lòng kiểm tra lại.` 
                    });
                }
            } catch (error) {
                console.error('Lỗi khi lấy thông tin Employee từ ERPNext:', error);
                return res.json({ 
                    success: false, 
                    message: `Không tìm thấy Employee với ID: ${erpnextEmployeeId}. Vui lòng kiểm tra lại.` 
                });
            }
        }

        account.erpnextEmployeeId = erpnextEmployeeId || null;
        account.erpnextEmployeeName = employeeName || null;
        await account.save();

        console.log(`[UPDATE ERPNext Employee] Đã cập nhật. User: ${account.username}, Employee: ${employeeName || 'None'}`);

        const message = account.role === 'production_worker' && erpnextEmployeeId 
            ? 'Đã cập nhật mapping Employee thành công. Nhân viên có thể đăng nhập.' 
            : 'Đã cập nhật mapping Employee thành công';

        res.json({
            success: true,
            message: message,
            account: {
                username: account.username,
                erpnextEmployeeId: account.erpnextEmployeeId,
                erpnextEmployeeName: account.erpnextEmployeeName
            }
        });
    } catch (error) {
        console.error('Update ERPNext Employee error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi cập nhật mapping Employee: ' + error.message
        });
    }
});

// API cập nhật role cho user
app.put('/api/accounts/:id/role', requireLogin, requireAdmin, async (req, res) => {
    try {
        const { role } = req.body;
        const accountId = req.params.id;

        console.log(`[UPDATE ROLE] Admin ${req.session.user.username} yêu cầu đổi role cho account ID: ${accountId} -> ${role}`);

        if (!role || !['user','admin','packer','checker','warehouse_manager','warehouse_staff','production_worker','reconciler','production_manager','qa','fabric_cutting_team','cotton_press_team','eyelet_team','sewing_team','assembly_team'].includes(role)) {
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

// API lấy trạng thái database
app.get('/api/admin/database-status', requireLogin, requireAdmin, async (req, res) => {
    try {
        const dbConfig = await DatabaseConfig.getConfig();
        const isConnected = mongoose.connection.readyState === 1;
        
        res.json({
            success: true,
            data: {
                currentDbType: dbConfig.currentDbType,
                lastBackupTime: dbConfig.lastBackupTime,
                isConnected: isConnected,
                connectionState: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
            }
        });
    } catch (error) {
        console.error('[DATABASE STATUS] Lỗi:', error);
        res.status(500).json({ success: false, message: 'Lỗi lấy trạng thái database: ' + error.message });
    }
});

// API backup database từ local lên cloud
app.post('/api/admin/backup-database', requireLogin, requireAdmin, async (req, res) => {
    const startTime = Date.now();
    const backupStartTime = new Date(); // Thời điểm bắt đầu backup
    let collectionsBackedUp = 0;
    let documentsBackedUp = 0;
    let documentsSkipped = 0;
    
    try {
        console.log('[BACKUP DATABASE] Bắt đầu backup database...');
        console.log('[BACKUP DATABASE] Thời điểm backup:', backupStartTime.toISOString());
        
        const dbConfig = await DatabaseConfig.getConfig();
        
        if (dbConfig.currentDbType !== 'local') {
            return res.json({ 
                success: false, 
                message: 'Chỉ có thể backup từ Local database. Database hiện tại: ' + dbConfig.currentDbType 
            });
        }
        
        // Đảm bảo cloud URI có database name
        let cloudUri = dbConfig.cloudDbUri.trim();
        
        // Parse URI để đảm bảo có database name
        // Format mongodb+srv: mongodb+srv://user:pass@cluster0.xxx.mongodb.net/?appName=...
        // Cần có: mongodb+srv://user:pass@cluster0.xxx.mongodb.net/OrderDetailing?appName=...
        
        if (cloudUri.includes('mongodb+srv://') || cloudUri.includes('mongodb://')) {
            // Tách URI thành parts
            const urlParts = cloudUri.match(/^(mongodb\+?srv?:\/\/[^\/]+)(\/[^?]*)?(\?.*)?$/);
            if (urlParts) {
                const base = urlParts[1]; // mongodb+srv://user:pass@host
                const currentDb = urlParts[2]; // /database hoặc null
                const query = urlParts[3] || ''; // ?appName=...
                
                // Nếu chưa có database name hoặc database name rỗng
                if (!currentDb || currentDb === '/') {
                    cloudUri = base + '/OrderDetailing' + query;
                } else {
                    // Đã có database name, giữ nguyên
                    cloudUri = base + currentDb + query;
                }
            }
        }
        
        console.log('[BACKUP DATABASE] Cloud URI (masked):', cloudUri.replace(/:[^:]+@/, ':****@')); // Ẩn password
        
        // Kết nối đến cloud database
        const cloudConnection = mongoose.createConnection(cloudUri, {
            serverSelectionTimeoutMS: 30000,
            socketTimeoutMS: 45000,
            connectTimeoutMS: 30000
        });
        
        // Đợi kết nối sẵn sàng
        try {
            // Thử sử dụng asPromise() nếu có
            if (typeof cloudConnection.asPromise === 'function') {
                await cloudConnection.asPromise();
            } else {
                // Hoặc đợi readyState === 1
                let retryCount = 0;
                while (cloudConnection.readyState !== 1 && retryCount < 30) {
                    await new Promise(resolve => setTimeout(resolve, 1000));
                    retryCount++;
                }
                if (cloudConnection.readyState !== 1) {
                    throw new Error('Cloud connection timeout. ReadyState: ' + cloudConnection.readyState);
                }
            }
        } catch (connectError) {
            await cloudConnection.close().catch(() => {});
            throw new Error('Không thể kết nối đến cloud database: ' + connectError.message);
        }
        
        // Đợi db object được khởi tạo - thử nhiều cách
        let cloudDb = null;
        let retryCount = 0;
        while (!cloudDb && retryCount < 15) {
            // Thử lấy từ connection.db
            if (cloudConnection.db) {
                cloudDb = cloudConnection.db;
                break;
            }
            
            // Thử lấy từ client nếu có
            if (cloudConnection.getClient && cloudConnection.readyState === 1) {
                try {
                    const client = cloudConnection.getClient();
                    if (client && client.db) {
                        // Lấy database name từ URI
                        const dbName = cloudUri.match(/\/([^\/?]+)(\?|$)/);
                        const databaseName = dbName ? dbName[1] : 'OrderDetailing';
                        cloudDb = client.db(databaseName);
                        if (cloudDb) break;
                    }
                } catch (clientError) {
                    console.warn('[BACKUP DATABASE] Không thể lấy db từ client:', clientError.message);
                }
            }
            
            await new Promise(resolve => setTimeout(resolve, 500));
            retryCount++;
        }
        
        if (!cloudDb) {
            await cloudConnection.close().catch(() => {});
            throw new Error(`Cloud connection không có db object sau ${retryCount} lần thử. ReadyState: ${cloudConnection.readyState}`);
        }
        
        console.log('[BACKUP DATABASE] ✅ Đã kết nối đến cloud database');
        console.log('[BACKUP DATABASE] Cloud connection readyState:', cloudConnection.readyState);
        console.log('[BACKUP DATABASE] Cloud database name:', cloudDb.databaseName);
        
        // Lấy danh sách collections từ local database
        if (!mongoose.connection.db) {
            throw new Error('Local connection không có db object');
        }
        
        const localCollections = await mongoose.connection.db.listCollections().toArray();
        
        console.log(`[BACKUP DATABASE] Tìm thấy ${localCollections.length} collections trong local database`);
        console.log(`[BACKUP DATABASE] Chỉ backup documents có createdAt <= ${backupStartTime.toISOString()}`);
        
        // Backup từng collection
        for (const collectionInfo of localCollections) {
            const collectionName = collectionInfo.name;
            
            // Bỏ qua system collections
            if (collectionName.startsWith('system.') || collectionName === 'databaseconfigs') {
                continue;
            }
            
            try {
                if (!mongoose.connection.db) {
                    console.error(`[BACKUP DATABASE] Local connection không có db object cho collection: ${collectionName}`);
                    continue;
                }
                
                const localCollection = mongoose.connection.db.collection(collectionName);
                
                // Đảm bảo cloud db vẫn còn active
                if (!cloudDb) {
                    throw new Error('Cloud db đã bị null. ReadyState: ' + cloudConnection.readyState);
                }
                
                // Thử lấy collection từ cloud db
                let cloudCollection;
                try {
                    cloudCollection = cloudDb.collection(collectionName);
                } catch (collectionError) {
                    console.error(`[BACKUP DATABASE] Không thể lấy collection ${collectionName} từ cloud:`, collectionError.message);
                    throw collectionError;
                }
                
                // Lấy TẤT CẢ documents từ local có createdAt trước thời điểm backup
                // Chỉ backup documents được tạo TRƯỚC khi click backup để tránh backup dữ liệu đang được tạo trong quá trình backup
                let query = {
                    $or: [
                        { createdAt: { $lte: backupStartTime } }, // Documents có createdAt <= thời điểm backup
                        { createdAt: { $exists: false } } // Documents không có createdAt (dữ liệu cũ)
                    ]
                };
                
                // Đếm tổng số documents trong collection
                const totalCount = await localCollection.countDocuments({});
                const documentsToBackup = await localCollection.find(query).toArray();
                const skippedCount = totalCount - documentsToBackup.length;
                
                console.log(`[BACKUP DATABASE] Collection ${collectionName}:`);
                console.log(`  - Tổng số documents: ${totalCount}`);
                console.log(`  - Documents sẽ backup (createdAt <= ${backupStartTime.toISOString()}): ${documentsToBackup.length}`);
                console.log(`  - Documents bỏ qua (createdAt > ${backupStartTime.toISOString()}): ${skippedCount}`);
                
                if (documentsToBackup.length > 0) {
                    // Sử dụng bulkWrite để tăng hiệu suất
                    const bulkOps = documentsToBackup.map(doc => ({
                        replaceOne: {
                            filter: { _id: doc._id },
                            replacement: doc,
                            upsert: true
                        }
                    }));
                    
                    // Chia nhỏ thành các batch 1000 documents để tránh quá tải
                    const batchSize = 1000;
                    let batchNumber = 0;
                    for (let i = 0; i < bulkOps.length; i += batchSize) {
                        batchNumber++;
                        const batch = bulkOps.slice(i, i + batchSize);
                        const result = await cloudCollection.bulkWrite(batch, { ordered: false });
                        const batchBackedUp = result.upsertedCount + result.modifiedCount;
                        documentsBackedUp += batchBackedUp;
                        console.log(`[BACKUP DATABASE] Collection ${collectionName}: Batch ${batchNumber}/${Math.ceil(bulkOps.length/batchSize)} - Upserted: ${result.upsertedCount}, Modified: ${result.modifiedCount}`);
                    }
                    
                    collectionsBackedUp++;
                    documentsSkipped += skippedCount;
                    console.log(`[BACKUP DATABASE] ✅ Đã backup ${documentsToBackup.length} documents từ collection: ${collectionName}`);
                } else {
                    console.log(`[BACKUP DATABASE] ⏭️ Collection ${collectionName}: Không có documents để backup (tất cả đều có createdAt sau thời điểm backup)`);
                }
            } catch (collectionError) {
                console.error(`[BACKUP DATABASE] ❌ Lỗi backup collection ${collectionName}:`, collectionError.message);
                console.error(`[BACKUP DATABASE] Stack:`, collectionError.stack);
                // Tiếp tục với collection tiếp theo
            }
        }
        
        // Đóng kết nối cloud
        await cloudConnection.close();
        
        // Cập nhật thời gian backup gần nhất = thời điểm bắt đầu backup
        dbConfig.lastBackupTime = backupStartTime;
        await dbConfig.save();
        
        const duration = ((Date.now() - startTime) / 1000).toFixed(2) + 's';
        
        console.log(`[BACKUP DATABASE] Backup hoàn tất:`);
        console.log(`  - Collections đã backup: ${collectionsBackedUp}`);
        console.log(`  - Documents đã backup: ${documentsBackedUp}`);
        console.log(`  - Documents đã bỏ qua (createdAt sau thời điểm backup): ${documentsSkipped}`);
        console.log(`  - Thời gian thực hiện: ${duration}`);
        
        res.json({
            success: true,
            message: `Backup thành công: ${collectionsBackedUp} collections, ${documentsBackedUp} documents đã backup, ${documentsSkipped} documents đã bỏ qua`,
            data: {
                collectionsBackedUp,
                documentsBackedUp,
                documentsSkipped,
                backupStartTime: backupStartTime.toISOString(),
                duration
            }
        });
    } catch (error) {
        console.error('[BACKUP DATABASE] Lỗi:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Lỗi backup database: ' + error.message 
        });
    }
});

// API restore database từ cloud về local
app.post('/api/admin/restore-database', requireLogin, requireAdmin, async (req, res) => {
    const startTime = Date.now();
    let collectionsRestored = 0;
    let documentsRestored = 0;

    try {
        console.log('[RESTORE DATABASE] Bắt đầu restore database từ cloud về local...');

        const dbConfig = await DatabaseConfig.getConfig();

        // Chỉ cho phép restore khi database hiện tại là local
        if (dbConfig.currentDbType !== 'local') {
            return res.json({
                success: false,
                message: 'Chỉ có thể restore khi đang dùng Local database. Database hiện tại: ' + dbConfig.currentDbType
            });
        }

        // Chuẩn hóa cloud URI tương tự API backup
        let cloudUri = dbConfig.cloudDbUri.trim();
        if (cloudUri.includes('mongodb+srv://') || cloudUri.includes('mongodb://')) {
            const urlParts = cloudUri.match(/^(mongodb\+?srv?:\/\/[^\/]+)(\/[^?]*)?(\?.*)?$/);
            if (urlParts) {
                const base = urlParts[1];
                const currentDb = urlParts[2];
                const query = urlParts[3] || '';
                if (!currentDb || currentDb === '/') {
                    cloudUri = base + '/OrderDetailing' + query;
                } else {
                    cloudUri = base + currentDb + query;
                }
            }
        }

        console.log('[RESTORE DATABASE] Cloud URI (masked):', cloudUri.replace(/:[^:]+@/, ':****@'));

        // Kết nối đến cloud database
        const cloudConnection = mongoose.createConnection(cloudUri, {
            serverSelectionTimeoutMS: 30000,
            socketTimeoutMS: 45000,
            connectTimeoutMS: 30000
        });

        try {
            if (typeof cloudConnection.asPromise === 'function') {
                await cloudConnection.asPromise();
            } else {
                let retryCount = 0;
                while (cloudConnection.readyState !== 1 && retryCount < 30) {
                    await new Promise(resolve => setTimeout(resolve, 1000));
                    retryCount++;
                }
                if (cloudConnection.readyState !== 1) {
                    throw new Error('Cloud connection timeout. ReadyState: ' + cloudConnection.readyState);
                }
            }
        } catch (connectError) {
            await cloudConnection.close().catch(() => {});
            throw new Error('Không thể kết nối đến cloud database: ' + connectError.message);
        }

        // Lấy db object từ cloud connection
        let cloudDb = null;
        let retryCount = 0;
        while (!cloudDb && retryCount < 15) {
            if (cloudConnection.db) {
                cloudDb = cloudConnection.db;
                break;
            }
            if (cloudConnection.getClient && cloudConnection.readyState === 1) {
                try {
                    const client = cloudConnection.getClient();
                    if (client && client.db) {
                        const dbName = cloudUri.match(/\/([^\/?]+)(\?|$)/);
                        const databaseName = dbName ? dbName[1] : 'OrderDetailing';
                        cloudDb = client.db(databaseName);
                        if (cloudDb) break;
                    }
                } catch (clientError) {
                    console.warn('[RESTORE DATABASE] Không thể lấy db từ client:', clientError.message);
                }
            }
            await new Promise(resolve => setTimeout(resolve, 500));
            retryCount++;
        }

        if (!cloudDb) {
            await cloudConnection.close().catch(() => {});
            throw new Error(`Cloud connection không có db object sau ${retryCount} lần thử. ReadyState: ${cloudConnection.readyState}`);
        }

        console.log('[RESTORE DATABASE] ✅ Đã kết nối đến cloud database');
        console.log('[RESTORE DATABASE] Cloud database name:', cloudDb.databaseName);

        // Đảm bảo local connection có db
        if (!mongoose.connection.db) {
            await cloudConnection.close().catch(() => {});
            throw new Error('Local connection không có db object');
        }

        // Lấy danh sách collections từ cloud database
        const cloudCollections = await cloudDb.listCollections().toArray();
        console.log(`[RESTORE DATABASE] Tìm thấy ${cloudCollections.length} collections trong cloud database`);

        // Restore từng collection từ cloud về local
        for (const collectionInfo of cloudCollections) {
            const collectionName = collectionInfo.name;

            // Bỏ qua system collections và DatabaseConfig để tránh ghi đè cấu hình local
            if (collectionName.startsWith('system.') || collectionName === 'databaseconfigs') {
                continue;
            }

            try {
                const cloudCollection = cloudDb.collection(collectionName);
                const localCollection = mongoose.connection.db.collection(collectionName);

                const documents = await cloudCollection.find({}).toArray();
                console.log(`[RESTORE DATABASE] Collection ${collectionName}: ${documents.length} documents từ cloud`);

                if (documents.length === 0) {
                    continue;
                }

                const bulkOps = documents.map(doc => ({
                    replaceOne: {
                        filter: { _id: doc._id },
                        replacement: doc,
                        upsert: true
                    }
                }));

                const batchSize = 1000;
                let batchNumber = 0;

                for (let i = 0; i < bulkOps.length; i += batchSize) {
                    batchNumber++;
                    const batch = bulkOps.slice(i, i + batchSize);
                    const result = await localCollection.bulkWrite(batch, { ordered: false });
                    const batchRestored = (result.upsertedCount || 0) + (result.modifiedCount || 0);
                    documentsRestored += batchRestored;
                    console.log(`[RESTORE DATABASE] Collection ${collectionName}: Batch ${batchNumber}/${Math.ceil(bulkOps.length / batchSize)} - Upserted: ${result.upsertedCount || 0}, Modified: ${result.modifiedCount || 0}`);
                }

                collectionsRestored++;
                console.log(`[RESTORE DATABASE] ✅ Đã restore ${documents.length} documents vào collection: ${collectionName}`);
            } catch (collectionError) {
                console.error(`[RESTORE DATABASE] ❌ Lỗi restore collection ${collectionName}:`, collectionError.message);
                console.error(`[RESTORE DATABASE] Stack:`, collectionError.stack);
                // Tiếp tục với collection tiếp theo
            }
        }

        await cloudConnection.close().catch(() => {});

        const duration = ((Date.now() - startTime) / 1000).toFixed(2) + 's';
        console.log('[RESTORE DATABASE] Restore hoàn tất:');
        console.log(`  - Collections đã restore: ${collectionsRestored}`);
        console.log(`  - Documents đã restore: ${documentsRestored}`);
        console.log(`  - Thời gian thực hiện: ${duration}`);

        res.json({
            success: true,
            message: `Restore thành công: ${collectionsRestored} collections, ${documentsRestored} documents đã restore từ cloud về local`,
            data: {
                collectionsRestored,
                documentsRestored,
                duration
            }
        });
    } catch (error) {
        console.error('[RESTORE DATABASE] Lỗi:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi restore database: ' + error.message
        });
    }
});

// API chuyển đổi database (local/cloud)
app.post('/api/admin/switch-database', requireLogin, requireAdmin, async (req, res) => {
    try {
        const { dbType } = req.body;
        
        if (!dbType || !['local', 'cloud'].includes(dbType)) {
            return res.json({ 
                success: false, 
                message: 'dbType phải là "local" hoặc "cloud"' 
            });
        }
        
        console.log(`[SWITCH DATABASE] Chuyển đổi sang ${dbType} database...`);
        
        const dbConfig = await DatabaseConfig.getConfig();
        
        if (dbConfig.currentDbType === dbType) {
            return res.json({ 
                success: false, 
                message: `Database hiện tại đã là ${dbType}` 
            });
        }
        
        // Đóng kết nối hiện tại
        await mongoose.connection.close();
        console.log('[SWITCH DATABASE] Đã đóng kết nối database hiện tại');
        
        // Xác định URI mới
        const newUri = dbType === 'local' ? dbConfig.localDbUri : dbConfig.cloudDbUri;
        
        // Kết nối đến database mới
        await mongoose.connect(newUri, {
            serverSelectionTimeoutMS: 30000,
            socketTimeoutMS: 45000,
            connectTimeoutMS: 30000,
            maxPoolSize: 10
        });
        
        console.log(`[SWITCH DATABASE] Đã kết nối đến ${dbType} database`);
        
        // Cập nhật cấu hình
        dbConfig.currentDbType = dbType;
        await dbConfig.save();
        
        // Cập nhật MONGODB_URI trong config
        config.MONGODB_URI = newUri;
        
        // QUAN TRỌNG: Cập nhật session store với URI mới
        // Đóng session store cũ và tạo mới với URI mới
        try {
            // Đóng session store cũ
            if (sessionStore && typeof sessionStore.close === 'function') {
                await new Promise((resolve, reject) => {
                    try {
                        sessionStore.close(() => {
                            console.log('[SWITCH DATABASE] Đã đóng session store cũ');
                            resolve();
                        });
                    } catch (closeError) {
                        console.warn('[SWITCH DATABASE] Lỗi đóng session store cũ:', closeError.message);
                        resolve(); // Vẫn tiếp tục dù có lỗi
                    }
                });
            }
            
            // Tạo session store mới với URI mới
            const newSessionStore = MongoStore.create({
                mongoUrl: newUri,
                ttl: 14 * 24 * 60 * 60 // 14 days
            });
            
            // QUAN TRỌNG: Cập nhật session store
            // Vì session middleware đã được setup, không thể thay đổi store trực tiếp
            // Nhưng có thể cập nhật biến sessionStore để các request mới sử dụng store mới
            // Tuy nhiên, các session hiện tại vẫn dùng store cũ
            // Giải pháp: Cần yêu cầu user logout và login lại
            sessionStore = newSessionStore;
            
            // Cập nhật session middleware store bằng cách thay đổi req.sessionStore trong middleware
            // Tạo middleware để override sessionStore cho mỗi request
            // Lưu ý: Điều này chỉ hoạt động nếu session middleware cho phép override
            console.log('[SWITCH DATABASE] ✅ Đã tạo session store mới với URI:', newUri.replace(/:[^:]+@/, ':****@'));
            console.warn('[SWITCH DATABASE] ⚠️ CẢNH BÁO: Session store đã được cập nhật.');
            console.warn('[SWITCH DATABASE] ⚠️ Các session hiện tại có thể không hoạt động. Vui lòng logout và login lại.');
        } catch (storeError) {
            console.error('[SWITCH DATABASE] ❌ Lỗi cập nhật session store:', storeError.message);
            throw new Error('Không thể cập nhật session store: ' + storeError.message);
        }
        
        // Khởi tạo lại cache
        try {
            await comboCache.refreshCache();
            console.log('[SWITCH DATABASE] ✅ ComboData cache đã được refresh');
        } catch (cacheError) {
            console.error('[SWITCH DATABASE] ⚠️ ComboData cache refresh failed:', cacheError.message);
        }
        
        res.json({
            success: true,
            message: `Đã chuyển sang ${dbType} database thành công. Vui lòng logout và login lại để session hoạt động đúng với database mới.`,
            data: {
                currentDbType: dbType,
                connectionState: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
                requiresReLogin: true // Yêu cầu user logout và login lại
            }
        });
    } catch (error) {
        console.error('[SWITCH DATABASE] Lỗi:', error);
        
        // Thử reconnect lại database cũ nếu chuyển đổi thất bại
        try {
            const dbConfig = await DatabaseConfig.getConfig();
            const fallbackUri = dbConfig.currentDbType === 'local' ? dbConfig.localDbUri : dbConfig.cloudDbUri;
            await mongoose.connect(fallbackUri, {
                serverSelectionTimeoutMS: 30000,
                socketTimeoutMS: 45000,
                connectTimeoutMS: 30000,
                maxPoolSize: 10
            });
            console.log('[SWITCH DATABASE] Đã reconnect lại database cũ');
        } catch (reconnectError) {
            console.error('[SWITCH DATABASE] Lỗi reconnect:', reconnectError);
        }
        
        res.status(500).json({ 
            success: false, 
            message: 'Lỗi chuyển đổi database: ' + error.message 
        });
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

            // Lấy thông tin Employee từ ERPNext nếu có mapping
            let erpnextEmployeeInfo = null;
            if (account.erpnextEmployeeId) {
                try {
                    const employeeResult = await erpnextAPI('GET', `Employee/${account.erpnextEmployeeId}`, null, null, null);
                    if (employeeResult.data) {
                        erpnextEmployeeInfo = {
                            id: employeeResult.data.name,
                            name: employeeResult.data.employee_name || employeeResult.data.name,
                            employeeNumber: employeeResult.data.employee_number || null
                        };
                        // Cập nhật cache nếu cần
                        if (employeeResult.data.employee_name && account.erpnextEmployeeName !== employeeResult.data.employee_name) {
                            account.erpnextEmployeeName = employeeResult.data.employee_name;
                            await account.save();
                        }
                    }
                } catch (error) {
                    console.log('Không thể lấy thông tin Employee từ ERPNext:', error.message);
                    // Dùng cache nếu có
                    if (account.erpnextEmployeeName) {
                        erpnextEmployeeInfo = {
                            id: account.erpnextEmployeeId,
                            name: account.erpnextEmployeeName,
                            employeeNumber: null
                        };
                    }
                }
            }

            return res.json({ 
                success: true, 
                username: account.username, 
                role: account.role,
                scannerPermissions: account.scannerPermissions,
                scannerConflict: scannerConflict,
                erpnextEmployee: erpnextEmployeeInfo,
                employeeName: erpnextEmployeeInfo?.name || account.erpnextEmployeeName || account.username,
                erpnextEmployeeId: account.erpnextEmployeeId
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

// Middleware for production worker
function requireProductionWorker(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    if (req.session.user.role !== 'production_worker') {
        return res.status(403).json({ success: false, message: 'Bạn không có quyền truy cập' });
    }
    next();
}

function requireRole(requiredRole) {
    return (req, res, next) => {
        if (!req.session.user) {
            return res.redirect('/login');
        }
        if (req.session.user.role !== requiredRole) {
            return res.status(403).json({ success: false, message: 'Bạn không có quyền truy cập' });
        }
        next();
    };
}

function requireAnyRole(roles) {
    return (req, res, next) => {
        if (!req.session.user) {
            return res.redirect('/login');
        }
        if (!roles.includes(req.session.user.role)) {
            return res.status(403).json({ success: false, message: 'Bạn không có quyền truy cập' });
        }
        next();
    };
}

// Route trang production worker
app.get('/production-worker', requireProductionWorker, (req, res) => {
    console.log('🔍 Production Worker Access - Session user:', req.session.user);
    res.sendFile(path.join(__dirname, 'public', 'production-worker.html'));
});

app.get('/production-status', requireAnyRole([
    'production_worker',
    'production_manager',
    'fabric_cutting_team',
    'cotton_press_team',
    'eyelet_team',
    'sewing_team',
    'assembly_team'
]), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'production-status.html'));
});

app.get('/production-manager', requireRole('production_manager'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'production-manager.html'));
});

app.get('/qa-dashboard', requireRole('qa'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'qa-dashboard.html'));
});

app.get('/fabric-cutting-team', requireRole('fabric_cutting_team'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'fabric-cutting-team.html'));
});

app.get('/cotton-press-team', requireRole('cotton_press_team'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'cotton-press-team.html'));
});

app.get('/eyelet-team', requireRole('eyelet_team'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'eyelet-team.html'));
});

app.get('/sewing-team', requireRole('sewing_team'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'sewing-team.html'));
});

app.get('/assembly-team', requireRole('assembly_team'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'assembly-team.html'));
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
    if (role === 'production_worker') {
        return res.redirect('/production-status');
    }
    if (role === 'production_manager') {
        return res.redirect('/production-manager');
    }
    if (role === 'qa') {
        return res.redirect('/qa-dashboard');
    }
    if (role === 'fabric_cutting_team') {
        return res.redirect('/fabric-cutting-team');
    }
    if (role === 'cotton_press_team') {
        return res.redirect('/cotton-press-team');
    }
    if (role === 'eyelet_team') {
        return res.redirect('/eyelet-team');
    }
    if (role === 'sewing_team') {
        return res.redirect('/sewing-team');
    }
    if (role === 'assembly_team') {
        return res.redirect('/assembly-team');
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
        const allowedTypes = ['.xlsx', '.xls', '.csv'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Chỉ cho phép template (.xlsx, .xls, .csv)'));
        }
    },
    limits: {
        fileSize: 10 * 1024 * 1024 // Giới hạn 10MB
    }
});

function detectCsvDelimiter(line) {
    if (!line || typeof line !== 'string') return ',';
    const candidates = [',', ';', '\t'];

    let best = ',';
    let bestCount = -1;

    for (const delim of candidates) {
        let inQuotes = false;
        let count = 0;
        for (let i = 0; i < line.length; i++) {
            const ch = line[i];
            if (ch === '"') {
                const next = line[i + 1];
                if (inQuotes && next === '"') {
                    i++;
                    continue;
                }
                inQuotes = !inQuotes;
            } else if (ch === delim && !inQuotes) {
                count++;
            }
        }

        if (count > bestCount) {
            bestCount = count;
            best = delim;
        }
    }

    return best;
}

function parseCsvLine(line, delimiter = ',') {
    const cells = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"') {
            const next = line[i + 1];
            if (inQuotes && next === '"') {
                cur += '"';
                i++;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (ch === delimiter && !inQuotes) {
            cells.push(cur);
            cur = '';
        } else {
            cur += ch;
        }
    }
    cells.push(cur);
    return cells.map(v => String(v || '').replace(/^\uFEFF/, '').trim());
}

function normalizeCsvHeaderTo24(headerCells) {
    if (!Array.isArray(headerCells)) return [];

    const h = headerCells.map(v => String(v || '').replace(/^\uFEFF/, '').trim());

    // Xóa ô trống ở cuối (thường do export dư cột)
    while (h.length > 0 && h[h.length - 1] === '') {
        h.pop();
    }

    if (h.length < 24) return [];

    // Trường hợp hay gặp: export CSV bị nhân header đôi -> 48 cột
    if (h.length === 48) {
        const a = h.slice(0, 24);
        const b = h.slice(24, 48);
        const isDup = a.every((v, i) => String(v || '').trim().toLowerCase() === String(b[i] || '').trim().toLowerCase());
        if (isDup) return a;
    }

    // Nếu >24 cột nhưng không đúng pattern, cứ lấy 24 cột đầu để chạy theo format A–X
    return h.slice(0, 24);
}

function maybeFixMojibakeUtf8FromLatin1(input) {
    const s = String(input ?? '');
    // Heuristic: các chuỗi bị lỗi UTF-8->latin1 thường có "Ã", "Â", "Ä", "Æ"
    if (!/[ÃÂÄÆ]/.test(s)) return s;
    try {
        const fixed = Buffer.from(s, 'latin1').toString('utf8');
        // Nếu sửa xong vẫn còn ký tự mojibake thì giữ nguyên
        if (/[ÃÂÄÆ]/.test(fixed)) return s;
        return fixed;
    } catch {
        return s;
    }
}

function parseQAImportSheet(filePath) {
    const workbook = XLSX.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    if (!sheetName) {
        throw new Error('File import không có sheet dữ liệu');
    }

    const rows = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName], { defval: '' });
    if (!rows.length) {
        return [];
    }

    const normalize = (value) => String(value || '').trim().toLowerCase();
    const resolveKey = (row, keys) => {
        const entries = Object.keys(row);
        return entries.find((key) => keys.includes(normalize(key)));
    };

    const firstRow = rows[0];
    const orderCodeKey = resolveKey(firstRow, ['mã đơn', 'ma don', 'madon', 'order code', 'ordercode']);
    const skuKey = resolveKey(firstRow, ['sku', 'mã sku', 'ma sku']);
    const productNameKey = resolveKey(firstRow, ['tên sp', 'ten sp', 'tên sản phẩm', 'ten san pham', 'product name', 'productname']);
    const quantityKey = resolveKey(firstRow, ['số lượng', 'so luong', 'quantity']);
    const routeAfterPressKey = resolveKey(firstRow, [
        'sau ép bông',
        'sau ep bong',
        'nhánh sau ép',
        'nhanh sau ep',
        'route sau ép',
        'routeafterpress',
        'sau ép',
        'sau ep'
    ]);

    if (!skuKey || !quantityKey) {
        throw new Error('File phải có cột: SKU, Số lượng (cột Mã đơn tùy chọn — để trống sẽ tự cấp mã)');
    }

    const mapped = [];
    for (const row of rows) {
        const orderCode = orderCodeKey ? String(row[orderCodeKey] || '').trim() : '';
        const sku = String(row[skuKey] || '').trim();
        const productName = productNameKey ? String(row[productNameKey] || '').trim() : '';
        const quantity = Number(row[quantityKey]);

        if (!sku || !Number.isFinite(quantity) || quantity <= 0) {
            continue;
        }

        let routeAfterPress = null;
        if (routeAfterPressKey) {
            const rv = String(row[routeAfterPressKey] || '').trim();
            if (rv) {
                const f = foldViPlain(rv);
                if (f.includes('khoen')) {
                    routeAfterPress = 'Đóng khoen';
                } else if (f === 'may') {
                    routeAfterPress = 'May';
                }
            }
        }

        mapped.push({
            orderCode,
            sku,
            productName,
            quantity: Math.floor(quantity),
            routeAfterPress
        });
    }

    return mapped;
}

async function lookupProductNameFromMasterDataBySku(sku) {
    const skuInput = String(sku || '').trim();
    if (!skuInput) return '';

    const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const normalizeSku = (value) => String(value || '').trim().toUpperCase().replace(/\s+/g, '');
    const skuNormalized = normalizeSku(skuInput);
    const exactRegex = new RegExp(`^${escapeRegExp(skuInput)}$`, 'i');

    const [masterData, masterDataVai] = await Promise.all([
        MasterData.findOne({ $or: [{ sku: skuInput }, { sku: exactRegex }] }).lean(),
        MasterDataVai.findOne({ $or: [{ sku: skuInput }, { sku: exactRegex }] }).lean()
    ]);

    let finalMasterData = masterData;
    let finalMasterDataVai = masterDataVai;

    if (!finalMasterData || !finalMasterDataVai) {
        const [masterDataCandidates, masterDataVaiCandidates] = await Promise.all([
            MasterData.find({ sku: { $regex: escapeRegExp(skuInput), $options: 'i' } }).limit(50).lean(),
            MasterDataVai.find({ sku: { $regex: escapeRegExp(skuInput), $options: 'i' } }).limit(50).lean()
        ]);

        if (!finalMasterData) {
            finalMasterData =
                masterDataCandidates.find((item) => normalizeSku(item.sku) === skuNormalized) ||
                masterDataCandidates[0] ||
                null;
        }
        if (!finalMasterDataVai) {
            finalMasterDataVai =
                masterDataVaiCandidates.find((item) => normalizeSku(item.sku) === skuNormalized) ||
                masterDataVaiCandidates[0] ||
                null;
        }
    }

    return (
        (finalMasterDataVai && typeof finalMasterDataVai.ten === 'string' && finalMasterDataVai.ten.trim()) ||
        (finalMasterData && typeof finalMasterData.tenPhienBan === 'string' && finalMasterData.tenPhienBan.trim()) ||
        ''
    );
}

app.get('/api/qa/orders', requireRole('qa'), async (req, res) => {
    try {
        const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1);
        const pageSize = Math.min(100, Math.max(1, parseInt(String(req.query.pageSize || '20'), 10) || 20));
        const skip = (page - 1) * pageSize;

        const [items, total] = await Promise.all([
            QAOrder.find({}, { __v: 0 }).sort({ createdAt: -1 }).skip(skip).limit(pageSize).lean(),
            QAOrder.countDocuments({})
        ]);

        const codes = items.map((o) => o.orderCode).filter(Boolean);
        let logs = [];
        if (codes.length) {
            logs = await QAOrderProgress.find({ orderCode: { $in: codes } }).lean();
        }
        const byCode = {};
        for (const l of logs) {
            if (!byCode[l.orderCode]) byCode[l.orderCode] = [];
            byCode[l.orderCode].push(l);
        }

        const enriched = items.map((order) => {
            const prev = getDisplayPreviousStageForOrder(order);
            let qaPrevStageGood = null;
            let qaPrevStageDefect = null;
            if (prev) {
                const list = byCode[order.orderCode] || [];
                qaPrevStageGood = list.filter((x) => x.stage === prev).reduce((s, x) => s + (Number(x.completedQty) || 0), 0);
                qaPrevStageDefect = list.filter((x) => x.stage === prev).reduce((s, x) => s + (Number(x.defectQty) || 0), 0);
            }
            return {
                ...order,
                qaPrevStageName: prev,
                qaPrevStageGood,
                qaPrevStageDefect
            };
        });

        res.json({
            success: true,
            items: enriched,
            total,
            page,
            pageSize,
            totalPages: Math.max(1, Math.ceil(total / pageSize))
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/qa/orders', requireRole('qa'), async (req, res) => {
    try {
        const { orderCode, sku, productName, quantity, priority, routeAfterPress } = req.body;
        if (!sku || !quantity) {
            return res.status(400).json({ success: false, message: 'Thiếu SKU hoặc số lượng' });
        }

        const parsedQuantity = Number(quantity);
        if (!Number.isFinite(parsedQuantity) || parsedQuantity <= 0) {
            return res.status(400).json({ success: false, message: 'Số lượng không hợp lệ' });
        }

        let finalOrderCode = String(orderCode || '').trim();
        if (!finalOrderCode) {
            finalOrderCode = await getNextQaOrderCode();
        }

        let finalProductName = String(productName || '').trim();
        if (!finalProductName) {
            finalProductName = await lookupProductNameFromMasterDataBySku(sku);
        }
        if (!finalProductName) {
            return res.status(400).json({ success: false, message: 'Không tìm thấy Tên SP từ master data cho SKU đã nhập' });
        }

        const pri = priority === 'high' ? 'high' : 'normal';
        const autoRoute = resolveRouteAfterPressFromProductName(finalProductName);
        const route =
            routeAfterPress === 'May' || routeAfterPress === 'Đóng khoen' ? routeAfterPress : autoRoute;

        const created = await QAOrder.create({
            orderCode: finalOrderCode,
            sku: String(sku).trim(),
            productName: finalProductName,
            quantity: Math.floor(parsedQuantity),
            currentStage: 'Cắt vải',
            currentStatus: 'pending',
            priority: pri,
            routeAfterPress: route,
            createdBy: req.session.user?.username || null
        });

        res.json({ success: true, item: created });
    } catch (error) {
        if (error?.code === 11000) {
            return res.status(409).json({ success: false, message: 'Mã đơn đã tồn tại' });
        }
        res.status(500).json({ success: false, message: error.message });
    }
});

app.patch('/api/qa/orders/:orderCode', requireRole('qa'), async (req, res) => {
    try {
        const orderCode = String(req.params.orderCode || '').trim();
        if (!orderCode) {
            return res.status(400).json({ success: false, message: 'Thiếu mã đơn' });
        }
        const { priority, routeAfterPress } = req.body;
        const update = {};
        if (priority === 'high' || priority === 'normal') {
            update.priority = priority;
        }
        if (routeAfterPress === 'May' || routeAfterPress === 'Đóng khoen') {
            update.routeAfterPress = routeAfterPress;
        }
        if (!Object.keys(update).length) {
            return res.status(400).json({ success: false, message: 'Cần ít nhất: priority hoặc routeAfterPress hợp lệ' });
        }
        const order = await QAOrder.findOneAndUpdate(
            { orderCode },
            { $set: update },
            { new: true }
        ).lean();
        if (!order) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy đơn' });
        }
        res.json({ success: true, item: order });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/qa/orders/import', requireRole('qa'), upload.single('xlsxFile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, message: 'Vui lòng chọn file import' });
    }

    try {
        const rows = parseQAImportSheet(req.file.path);
        if (!rows.length) {
            return res.status(400).json({ success: false, message: 'Không có dòng hợp lệ để import' });
        }

        let inserted = 0;
        let updated = 0;
        let autoFilled = 0;
        let missingProductName = 0;
        let autoOrderCodes = 0;

        for (const row of rows) {
            let finalProductName = String(row.productName || '').trim();
            if (!finalProductName) {
                finalProductName = await lookupProductNameFromMasterDataBySku(row.sku);
                if (finalProductName) {
                    autoFilled += 1;
                }
            }

            if (!finalProductName) {
                missingProductName += 1;
                continue;
            }

            const rowRoute = row.routeAfterPress === 'May' || row.routeAfterPress === 'Đóng khoen'
                ? row.routeAfterPress
                : resolveRouteAfterPressFromProductName(finalProductName);

            let oc = String(row.orderCode || '').trim();
            if (!oc) {
                oc = await getNextQaOrderCode();
                autoOrderCodes += 1;
            }

            const writeResult = await QAOrder.updateOne(
                { orderCode: oc },
                {
                    $set: {
                        sku: row.sku,
                        productName: finalProductName,
                        quantity: row.quantity,
                        routeAfterPress: rowRoute,
                        createdBy: req.session.user?.username || null
                    },
                    $setOnInsert: {
                        currentStage: 'Cắt vải',
                        currentStatus: 'pending',
                        priority: 'normal',
                        totalCompleted: 0,
                        totalDefect: 0
                    }
                },
                { upsert: true }
            );

            if (writeResult?.upsertedCount) inserted += writeResult.upsertedCount;
            else if (writeResult?.modifiedCount || writeResult?.matchedCount) updated += 1;
        }

        res.json({
            success: true,
            message: `Import thành công ${rows.length} dòng`,
            summary: { total: rows.length, inserted, updated, autoFilled, missingProductName, autoOrderCodes }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    } finally {
        fs.unlink(req.file.path, () => {});
    }
});

app.get('/api/qa/orders/:id/barcode', requireRole('qa'), async (req, res) => {
    try {
        const order = await QAOrder.findById(req.params.id).lean();
        if (!order) {
            return res.status(404).send('Order not found');
        }

        const png = await bwipjs.toBuffer({
            bcid: 'code128',
            text: order.orderCode,
            scale: 3,
            height: 12,
            includetext: true,
            textxalign: 'center'
        });

        res.set('Content-Type', 'image/png');
        res.send(png);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/qa/orders/:orderCode/progress', requireRole('qa'), async (req, res) => {
    try {
        const orderCode = String(req.params.orderCode || '').trim();
        if (!orderCode) {
            return res.status(400).json({ success: false, message: 'Mã đơn không hợp lệ' });
        }
        const logs = await QAOrderProgress.find({ orderCode }, { __v: 0 }).sort({ createdAt: -1 }).lean();
        res.json({ success: true, items: logs });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/production/orders/scan', requireAnyRole([
    'production_worker',
    'production_manager',
    'fabric_cutting_team',
    'cotton_press_team',
    'eyelet_team',
    'sewing_team',
    'assembly_team'
]), async (req, res) => {
    try {
        const { orderCode } = req.body;
        const normalized = String(orderCode || '').trim();
        if (!normalized) {
            return res.status(400).json({ success: false, message: 'Vui lòng nhập mã đơn' });
        }

        const order = await QAOrder.findOne({ orderCode: normalized }).lean();
        if (!order) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy đơn QA theo mã đơn' });
        }

        let meta = null;
        try {
            meta = await buildProductionScanMeta(order);
        } catch (_) {
            meta = null;
        }

        res.json({ success: true, item: order, meta });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/production/orders/queue', requireAnyRole([
    'production_worker',
    'production_manager',
    'fabric_cutting_team',
    'cotton_press_team',
    'eyelet_team',
    'sewing_team',
    'assembly_team'
]), async (req, res) => {
    try {
        const stageKey = resolveProductionQueueStageKey(req);
        if (!stageKey) {
            return res.status(400).json({
                success: false,
                message: 'Thiếu stageKey hợp lệ (bắt buộc với quản lý / NV sản xuất chung): fabric_cutting, cotton_press, sewing, eyelet, assembly'
            });
        }
        const stages = PRODUCTION_STAGE_QUEUE[stageKey];
        const items = await QAOrder.find({ currentStage: { $in: stages } })
            .sort({ priority: 1, createdAt: 1 })
            .lean();
        const highCount = items.filter((o) => o.priority === 'high').length;
        res.json({
            success: true,
            stageKey,
            items,
            counts: { total: items.length, highPriority: highCount }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/production/orders/update-status', requireAnyRole([
    'production_worker',
    'production_manager',
    'fabric_cutting_team',
    'cotton_press_team',
    'eyelet_team',
    'sewing_team',
    'assembly_team'
]), async (req, res) => {
    try {
        const { orderCode, stage, completedQty, defectQty, note } = req.body;
        const normalizedOrderCode = String(orderCode || '').trim();
        const normalizedStage = String(stage || '').trim();
        let done;
        let defect;
        try {
            done = parseProductionNaturalInt(completedQty, 'Số lượng hoàn thành', { allowEmpty: false });
            defect = parseProductionNaturalInt(defectQty, 'Số lượng lỗi', { allowEmpty: true });
        } catch (e) {
            return res.status(400).json({ success: false, message: e.message || 'Dữ liệu không hợp lệ' });
        }
        if (defect === null) defect = 0;

        if (!normalizedOrderCode || !normalizedStage) {
            return res.status(400).json({ success: false, message: 'Thiếu mã đơn hoặc công đoạn' });
        }

        const order = await QAOrder.findOne({ orderCode: normalizedOrderCode });
        if (!order) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy đơn QA theo mã đơn' });
        }

        const qtyTotal = Number(order.quantity || 0);
        if (!Number.isFinite(qtyTotal) || qtyTotal <= 0) {
            return res.status(400).json({ success: false, message: 'Số lượng đơn không hợp lệ' });
        }

        if (!isOrderAtProductionStage(order, normalizedStage)) {
            return res.status(400).json({
                success: false,
                message: `Đơn không đang ở công đoạn này (hiện tại: ${order.currentStage || '—'})`
            });
        }

        if (defect > 0 && !String(note || '').trim()) {
            return res.status(400).json({ success: false, message: 'Có số lượng lỗi thì bắt buộc nhập lý do lỗi' });
        }

        if (done + defect <= 0) {
            return res.status(400).json({ success: false, message: 'Tổng SL hoàn thành + lỗi phải lớn hơn 0' });
        }

        const prevStage = getPreviousProductionStageForRecord(order, normalizedStage);
        let inboundCap = qtyTotal;
        if (prevStage) {
            inboundCap = await sumCompletedQtyForStage(order.orderCode, prevStage);
        }
        if (done + defect > inboundCap) {
            return res.status(400).json({
                success: false,
                message: `SL hoàn thành + SL lỗi (${done + defect}) không được vượt SL đầu vào từ khâu trước (${inboundCap})`
            });
        }

        const nextStage = nextProductionStageAfterRecord(order);
        order.currentStage = nextStage;
        order.currentStatus = nextStage === 'Hoàn thành' ? 'completed' : 'in_progress';
        order.totalCompleted = done;
        order.totalDefect = defect;
        order.lastUpdatedBy = req.session.user?.username || null;
        await order.save();

        await QAOrderProgress.create({
            orderCode: order.orderCode,
            sku: order.sku,
            productName: order.productName,
            quantity: order.quantity,
            stage: normalizedStage,
            completedQty: done,
            defectQty: defect,
            note: String(note || '').trim(),
            updatedBy: req.session.user?.username || 'unknown',
            updatedByRole: req.session.user?.role || 'unknown'
        });

        res.json({ success: true, item: order, message: 'Đã cập nhật trạng thái đơn thành công' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
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
        
        // Session store đã được setup với mongoUrl, sẽ tự động dùng URI từ config.MONGODB_URI
        // Không cần cập nhật ở đây vì session store đã được tạo với config.MONGODB_URI ban đầu
        
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

// Route upload file MasterDataVai
app.post('/api/upload-master-data-vai', requireLogin, requireWarehouseManager, upload.single('xlsxFile'), async (req, res) => {
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
        // Cột: Sku, Tên, Mẫu, Ngang, Cao
        const dataRows = jsonData.slice(1).filter(row => row[0] && row[1] && row[2] && row[3] && row[4]); // Tất cả 5 cột không được rỗng

        if (dataRows.length === 0) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ success: false, message: 'Không có dữ liệu hợp lệ trong file' });
        }

        // Kiểm tra kết nối MongoDB
        if (mongoose.connection.readyState !== 1) {
            throw new Error('MongoDB chưa kết nối. Vui lòng thử lại sau.');
        }

        // Chuẩn hóa dữ liệu
        const masterDataVaiList = [];
        const uniqueKeyMap = new Map(); // Để kiểm tra duplicate uniqueKey

        for (const row of dataRows) {
            const sku = String(row[0] || '').trim();
            const ten = String(row[1] || '').trim();
            const mau = String(row[2] || '').trim();
            const ngang = String(row[3] || '').trim();
            const cao = String(row[4] || '').trim();

            if (!sku || !ten || !mau || !ngang || !cao) {
                continue; // Bỏ qua dòng không đủ dữ liệu
            }

            // Tạo uniqueKey từ bộ 3 [Mẫu][Ngang][Cao]
            const uniqueKey = `${mau}|${ngang}|${cao}`;

            // Kiểm tra duplicate uniqueKey với SKU và Tên khác nhau
            if (uniqueKeyMap.has(uniqueKey)) {
                const existing = uniqueKeyMap.get(uniqueKey);
                if (existing.sku !== sku || existing.ten !== ten) {
                    console.warn(`Cảnh báo: uniqueKey "${uniqueKey}" đã tồn tại với SKU="${existing.sku}", Tên="${existing.ten}". Bỏ qua SKU="${sku}", Tên="${ten}"`);
                    continue; // Bỏ qua nếu uniqueKey trùng nhưng SKU hoặc Tên khác
                }
            } else {
                uniqueKeyMap.set(uniqueKey, { sku, ten });
            }

            masterDataVaiList.push({
                sku,
                ten,
                mau,
                ngang,
                cao,
                uniqueKey,
                createdBy: req.session.user.username
            });
        }

        if (masterDataVaiList.length === 0) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ success: false, message: 'Không có dữ liệu hợp lệ sau khi chuẩn hóa' });
        }

        // Xử lý upsert: update nếu có, thêm mới nếu chưa có (dựa trên uniqueKey)
        let insertedCount = 0;
        let updatedCount = 0;
        const processedData = [];

        for (const item of masterDataVaiList) {
            try {
                const result = await MasterDataVai.findOneAndUpdate(
                    { uniqueKey: item.uniqueKey }, // Tìm theo uniqueKey
                    {
                        $set: {
                            sku: item.sku,
                            ten: item.ten,
                            mau: item.mau,
                            ngang: item.ngang,
                            cao: item.cao,
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
        console.error('❌ Lỗi xử lý file MasterDataVai:', error);

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
            message: 'Lỗi xử lý file MasterDataVai: ' + error.message
        });
    }
});

// Route upload template xuất file - Hỗ trợ nhiều template với tên
app.post('/api/upload-template', requireLogin, requireWarehouseManager, upload.single('templateFile'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'Không có file được upload'
            });
        }

        const { name, description } = req.body;
        if (!name || !name.trim()) {
            return res.status(400).json({
                success: false,
                message: 'Vui lòng nhập tên template'
            });
        }

        const ext = path.extname(req.file.originalname).toLowerCase();
        const isCsvTemplate = ext === '.csv';

        const templateDir = path.join(__dirname, 'uploads', 'template');
        
        // Tạo thư mục nếu chưa có
        if (!fs.existsSync(templateDir)) {
            fs.mkdirSync(templateDir, { recursive: true });
        }

        // Tạo tên file unique
        const timestamp = Date.now();
        const sanitizedName = name.trim().replace(/[^a-zA-Z0-9_-]/g, '_');
        const filename = `${sanitizedName}_${timestamp}${ext}`;
        const templatePath = path.join(templateDir, filename);

        // Copy file mới vào thư mục template
        fs.copyFileSync(req.file.path, templatePath);
        
        // Parse header để đưa vào template.csvHeader (dùng cho export CSV)
        let csvHeader = [];
        if (isCsvTemplate) {
            const raw = fs.readFileSync(req.file.path, 'utf8');
            const lines = raw.split(/\r\n|\n|\r/);

            // Một số file template có thể có đoạn mô tả ở đầu file,
            // header thực tế nằm ở dòng sau (ví dụ dòng 2-3 hoặc dòng 8).
            // Vì vậy quét qua N dòng đầu để chọn dòng header phù hợp nhất.
            const maxScanLines = Math.min(lines.length, 200);
            const keywords = [
                /sku/i,
                /kho/i,
                /meter/i,
                /unit/i,
                /mã/i,
                /số\s*lượng/i,
                /so\s*luong/i
            ];

            let best = { idx: -1, line: '', delimiter: ',', cells: [] };
            let bestScore = -1;

            for (let i = 0; i < maxScanLines; i++) {
                const lnRaw = lines[i];
                if (!lnRaw || !String(lnRaw).trim()) continue;

                const ln = String(lnRaw).replace(/\r$/, '');
                const delimiter = detectCsvDelimiter(ln);
                const cells = parseCsvLine(ln, delimiter);

                // Score: ưu tiên dòng có nhiều cột hơn, và có từ khóa trong các ô
                const hasKeyword = Array.isArray(cells) && cells.some(c => keywords.some(kw => kw.test(String(c || ''))));
                const score = (cells.length || 0) + (hasKeyword ? 100 : 0);

                if (score > bestScore) {
                    bestScore = score;
                    best = { idx: i, line: ln, delimiter, cells };
                }
            }

            csvHeader = best.idx >= 0 ? best.cells : [];

            // Chuẩn hóa header về 24 cột (A–X). Một số file export bị đếm 48 cột do nhân header.
            csvHeader = normalizeCsvHeaderTo24(csvHeader);

            // Kỳ vọng tối thiểu A–X (24 cột)
            if (csvHeader.length < 24) {
                return res.status(400).json({
                    success: false,
                    message: `Template CSV cần tối thiểu 24 cột header (A–X). Hiện tại sau chuẩn hóa còn ${csvHeader.length} cột.`
                });
            }
        } else {
            // Với template Excel: header thực tế có thể nằm gần startRow (ví dụ dòng 8),
            // nên ưu tiên lấy quanh startRow, nếu không thì tự dò dòng phù hợp.
            try {
                const startRowReq = req.body.startRow ? parseInt(req.body.startRow) : 1; // UI dùng 1-index
                const workbook = XLSX.readFile(templatePath);
                const sheetName = workbook.SheetNames[0];
                if (sheetName) {
                    const worksheet = workbook.Sheets[sheetName];
                    const rows = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: '' });
                    if (Array.isArray(rows) && rows.length > 0) {
                        const keywords = [
                            /sku/i,
                            /kho/i,
                            /meter/i,
                            /unit/i,
                            /mã/i,
                            /số\s*lượng/i,
                            /so\s*luong/i
                        ];
                        const scoreRow = (r) => {
                            const cells = (r || []).map((c) => String(c || '').trim());
                            const nonEmpty = cells.filter((c) => c !== '').length;
                            const hasKeyword = cells.some((c) => keywords.some((kw) => kw.test(c)));
                            return nonEmpty + (hasKeyword ? 100 : 0);
                        };

                        // 1) Ưu tiên dòng startRow (vì nghiệp vụ hay đặt header ở đây)
                        const idxStart = Math.max(0, (Number.isFinite(startRowReq) ? startRowReq : 1) - 1);
                        const candidatesIdx = [idxStart, idxStart - 1, idxStart - 2, 0, 1, 2].filter(
                            (i) => i >= 0 && i < rows.length
                        );

                        let bestIdx = -1;
                        let bestScore = -1;
                        for (const idx of candidatesIdx) {
                            const sc = scoreRow(rows[idx]);
                            if (sc > bestScore) {
                                bestScore = sc;
                                bestIdx = idx;
                            }
                        }

                        // 2) Nếu vẫn không ổn, quét thêm 200 dòng đầu
                        const maxScan = Math.min(rows.length, 200);
                        for (let i = 0; i < maxScan; i++) {
                            const sc = scoreRow(rows[i]);
                            if (sc > bestScore) {
                                bestScore = sc;
                                bestIdx = i;
                            }
                        }

                        csvHeader = bestIdx >= 0 ? normalizeCsvHeaderTo24(rows[bestIdx] || []) : [];
                    }
                }
            } catch (e) {
                // Không fatal: nếu không parse được header thì export sẽ fallback A..X
                console.warn('Không parse được header từ template Excel:', e?.message || String(e));
                csvHeader = [];
            }
        }

        // Xóa file tạm
        fs.unlinkSync(req.file.path);

        // Lưu thông tin template vào database
        const template = new Template({
            name: name.trim(),
            filename: filename,
            filePath: templatePath,
            skuColumn: req.body.skuColumn || 'C',
            slColumn: req.body.slColumn || 'D',
            startRow: req.body.startRow ? parseInt(req.body.startRow) : 1,
            description: maybeFixMojibakeUtf8FromLatin1(description || ''),
            warehousePhoiName: maybeFixMojibakeUtf8FromLatin1((req.body.warehousePhoiName && String(req.body.warehousePhoiName).trim()) || 'Kho Phôi - Shi'),
            warehouseNVLName: maybeFixMojibakeUtf8FromLatin1((req.body.warehouseNVLName && String(req.body.warehouseNVLName).trim()) || 'Kho NVL - Shi'),
            warehousePhePhamName: maybeFixMojibakeUtf8FromLatin1((req.body.warehousePhePhamName && String(req.body.warehousePhePhamName).trim()) || 'Kho Phế phẩm - Shi'),
            skuHangLoiSuffix: (req.body.skuHangLoiSuffix && String(req.body.skuHangLoiSuffix).trim()) || '00-404-230',
            skuNhapKhoSuffix: (req.body.skuNhapKhoSuffix && String(req.body.skuNhapKhoSuffix).trim()) || '00-000-230',
            csvHeader: (csvHeader || []).map(maybeFixMojibakeUtf8FromLatin1),
            createdBy: req.session.user?.username || null
        });

        await template.save();

        res.json({
            success: true,
            message: 'Upload template thành công!',
            data: {
                id: template._id,
                name: template.name,
                filename: template.filename,
                size: fs.statSync(templatePath).size,
                skuColumn: template.skuColumn,
                slColumn: template.slColumn,
                startRow: template.startRow,
                createdAt: template.createdAt
            }
        });

    } catch (error) {
        console.error('❌ Lỗi upload template:', error);
        
        // Xóa file tạm nếu có lỗi
        if (req.file) {
            try {
                fs.unlinkSync(req.file.path);
            } catch (deleteError) {
                console.log('Không thể xóa file tạm:', deleteError.message);
            }
        }

        // Xóa file đã copy nếu có lỗi
        if (req.body.name && req.file) {
            try {
                const templateDir = path.join(__dirname, 'uploads', 'template');
                const sanitizedName = req.body.name.trim().replace(/[^a-zA-Z0-9_-]/g, '_');
                const filename = `${sanitizedName}_${Date.now()}.xlsx`;
                const templatePath = path.join(templateDir, filename);
                if (fs.existsSync(templatePath)) {
                    fs.unlinkSync(templatePath);
                }
            } catch (deleteError) {
                console.log('Không thể xóa file template:', deleteError.message);
            }
        }

        if (error.code === 11000) {
            return res.status(400).json({
                success: false,
                message: 'Tên template đã tồn tại. Vui lòng chọn tên khác.'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Lỗi upload template: ' + error.message
        });
    }
});

// Route lấy danh sách tất cả templates
app.get('/api/templates', requireLogin, requireWarehouseManager, async (req, res) => {
    try {
        const templates = await Template.find({}).sort({ createdAt: -1 });
        res.json({
            success: true,
            data: templates
        });
    } catch (error) {
        console.error('❌ Lỗi lấy danh sách templates:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy danh sách templates: ' + error.message
        });
    }
});

// Route lấy thông tin template theo ID
app.get('/api/template/:id', requireLogin, requireWarehouseManager, async (req, res) => {
    try {
        const template = await Template.findById(req.params.id);
        if (!template) {
            return res.status(404).json({
                success: false,
                message: 'Template không tồn tại'
            });
        }

        // Kiểm tra file có tồn tại không
        const fileExists = fs.existsSync(template.filePath);
        const fileStats = fileExists ? fs.statSync(template.filePath) : null;

        res.json({
            success: true,
            data: {
                ...template.toObject(),
                fileExists: fileExists,
                fileSize: fileStats ? fileStats.size : null,
                fileModified: fileStats ? fileStats.mtime : null
            }
        });
    } catch (error) {
        console.error('❌ Lỗi lấy thông tin template:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy thông tin template: ' + error.message
        });
    }
});

// Route cập nhật mapping cột cho template
app.put('/api/template/:id', requireLogin, requireWarehouseManager, async (req, res) => {
    try {
        const {
            skuColumn,
            slColumn,
            startRow,
            description,
            name,
            warehousePhoiName,
            warehouseNVLName,
            warehousePhePhamName,
            skuHangLoiSuffix,
            skuNhapKhoSuffix
        } = req.body;
        const template = await Template.findById(req.params.id);
        
        if (!template) {
            return res.status(404).json({
                success: false,
                message: 'Template không tồn tại'
            });
        }

        // Cập nhật các trường
        if (skuColumn) template.skuColumn = skuColumn.toUpperCase();
        if (slColumn) template.slColumn = slColumn.toUpperCase();
        if (startRow !== undefined) template.startRow = parseInt(startRow);
        if (description !== undefined) template.description = description;
        if (warehousePhoiName !== undefined) template.warehousePhoiName = String(warehousePhoiName).trim();
        if (warehouseNVLName !== undefined) template.warehouseNVLName = String(warehouseNVLName).trim();
        if (warehousePhePhamName !== undefined) template.warehousePhePhamName = String(warehousePhePhamName).trim();
        if (skuHangLoiSuffix !== undefined) template.skuHangLoiSuffix = String(skuHangLoiSuffix).trim();
        if (skuNhapKhoSuffix !== undefined) template.skuNhapKhoSuffix = String(skuNhapKhoSuffix).trim();
        if (name && name.trim() && name.trim() !== template.name) {
            // Kiểm tra tên trùng
            const existingTemplate = await Template.findOne({ name: name.trim(), _id: { $ne: template._id } });
            if (existingTemplate) {
                return res.status(400).json({
                    success: false,
                    message: 'Tên template đã tồn tại'
                });
            }
            template.name = name.trim();
        }

        await template.save();

        res.json({
            success: true,
            message: 'Cập nhật template thành công!',
            data: template
        });
    } catch (error) {
        console.error('❌ Lỗi cập nhật template:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi cập nhật template: ' + error.message
        });
    }
});

// Route xóa template
app.delete('/api/template/:id', requireLogin, requireWarehouseManager, async (req, res) => {
    try {
        const template = await Template.findById(req.params.id);
        
        if (!template) {
            return res.status(404).json({
                success: false,
                message: 'Template không tồn tại'
            });
        }

        // Xóa file
        if (fs.existsSync(template.filePath)) {
            try {
                fs.unlinkSync(template.filePath);
            } catch (fileError) {
                console.log('Không thể xóa file template:', fileError.message);
            }
        }

        // Xóa record trong database
        await Template.findByIdAndDelete(req.params.id);

        res.json({
            success: true,
            message: 'Xóa template thành công!'
        });
    } catch (error) {
        console.error('❌ Lỗi xóa template:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi xóa template: ' + error.message
        });
    }
});

// Route set template active (template được sử dụng khi xuất file)
app.post('/api/template/:id/set-active', requireLogin, requireWarehouseManager, async (req, res) => {
    try {
        // Tắt tất cả template active khác
        await Template.updateMany({}, { isActive: false });
        
        // Set template này là active
        const template = await Template.findByIdAndUpdate(
            req.params.id,
            { isActive: true },
            { new: true }
        );

        if (!template) {
            return res.status(404).json({
                success: false,
                message: 'Template không tồn tại'
            });
        }

        res.json({
            success: true,
            message: `Template "${template.name}" đã được đặt làm template mặc định!`,
            data: template
        });
    } catch (error) {
        console.error('❌ Lỗi set active template:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi set active template: ' + error.message
        });
    }
});

// Route lấy template active (để tương thích với code cũ)
app.get('/api/template-info', requireLogin, requireWarehouseManager, async (req, res) => {
    try {
        const activeTemplate = await Template.findOne({ isActive: true });
        
        if (activeTemplate && fs.existsSync(activeTemplate.filePath)) {
            const stats = fs.statSync(activeTemplate.filePath);
            res.json({
                success: true,
                data: {
                    id: activeTemplate._id,
                    name: activeTemplate.name,
                    filename: activeTemplate.filename,
                    size: stats.size,
                    modified: stats.mtime,
                    skuColumn: activeTemplate.skuColumn,
                    slColumn: activeTemplate.slColumn,
                    startRow: activeTemplate.startRow
                }
            });
        } else {
            // Fallback: tìm template đầu tiên
            const firstTemplate = await Template.findOne().sort({ createdAt: -1 });
            if (firstTemplate && fs.existsSync(firstTemplate.filePath)) {
                const stats = fs.statSync(firstTemplate.filePath);
                res.json({
                    success: true,
                    data: {
                        id: firstTemplate._id,
                        name: firstTemplate.name,
                        filename: firstTemplate.filename,
                        size: stats.size,
                        modified: stats.mtime,
                        skuColumn: firstTemplate.skuColumn,
                        slColumn: firstTemplate.slColumn,
                        startRow: firstTemplate.startRow
                    }
                });
            } else {
                res.json({
                    success: true,
                    data: null,
                    message: 'Chưa có template được upload'
                });
            }
        }
    } catch (error) {
        console.error('❌ Lỗi lấy thông tin template:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy thông tin template: ' + error.message
        });
    }
});

// API xóa tất cả dữ liệu Mẫu vải
app.delete('/api/delete-all/mau-vai', requireLogin, requireWarehouseManager, async (req, res) => {
    try {
        const result = await MauVai.deleteMany({});
        res.json({
            success: true,
            message: `Đã xóa ${result.deletedCount} bản ghi mẫu vải`,
            deletedCount: result.deletedCount
        });
    } catch (error) {
        console.error('❌ Lỗi xóa dữ liệu mẫu vải:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi xóa dữ liệu mẫu vải: ' + error.message
        });
    }
});

// API xóa tất cả dữ liệu Kích thước
app.delete('/api/delete-all/kich-thuoc', requireLogin, requireWarehouseManager, async (req, res) => {
    try {
        const result = await KichThuoc.deleteMany({});
        res.json({
            success: true,
            message: `Đã xóa ${result.deletedCount} bản ghi kích thước`,
            deletedCount: result.deletedCount
        });
    } catch (error) {
        console.error('❌ Lỗi xóa dữ liệu kích thước:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi xóa dữ liệu kích thước: ' + error.message
        });
    }
});

// API xóa tất cả dữ liệu MasterDataVai
app.delete('/api/delete-all/master-data-vai', requireLogin, requireWarehouseManager, async (req, res) => {
    try {
        const result = await MasterDataVai.deleteMany({});
        res.json({
            success: true,
            message: `Đã xóa ${result.deletedCount} bản ghi MasterDataVai`,
            deletedCount: result.deletedCount
        });
    } catch (error) {
        console.error('❌ Lỗi xóa dữ liệu MasterDataVai:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi xóa dữ liệu MasterDataVai: ' + error.message
        });
    }
});

// Route báo cáo data cắt vải
app.get('/api/report-cat-vai', requireLogin, requireWarehouseManager, async (req, res) => {
    try {
        const {
            catVaiId,
            createdBy,
            maMau,
            filterType,
            date,
            month,
            quarter,
            year,
            dateFrom,
            dateTo,
            groupByCatVaiId,
            export: isExport,
            timeField,
            page,
            pageSize
        } = req.query;
        
        // timeField:
        // - 'cut'  : lọc theo lịch sử cắt (lichSuCat.ngayCat) (mặc định)
        // - 'import': lọc theo ngày nhập đối tượng (ngayNhap) (giữ hành vi cũ nếu cần)
        const resolvedTimeField = (timeField || 'cut').toLowerCase() === 'import' ? 'import' : 'cut';
        
        // Tính time range từ filterType
        let startDate = null;
        let endDate = null;
        if (filterType && filterType !== 'all') {
            switch (filterType) {
                case 'date':
                    if (date) {
                        startDate = new Date(date);
                        startDate.setHours(0, 0, 0, 0);
                        endDate = new Date(date);
                        endDate.setHours(23, 59, 59, 999);
                    }
                    break;
                case 'month':
                    if (month) {
                        const [yearStr, monthStr] = month.split('-');
                        startDate = new Date(parseInt(yearStr), parseInt(monthStr) - 1, 1);
                        endDate = new Date(parseInt(yearStr), parseInt(monthStr), 0, 23, 59, 59, 999);
                    }
                    break;
                case 'quarter':
                    if (quarter && year) {
                        const yearNum = parseInt(year);
                        let startMonth = 0;
                        if (quarter === 'Q1') startMonth = 0;
                        else if (quarter === 'Q2') startMonth = 3;
                        else if (quarter === 'Q3') startMonth = 6;
                        else if (quarter === 'Q4') startMonth = 9;
                        startDate = new Date(yearNum, startMonth, 1);
                        endDate = new Date(yearNum, startMonth + 3, 0, 23, 59, 59, 999);
                    }
                    break;
                case 'year':
                    if (year) {
                        const yearNum = parseInt(year);
                        startDate = new Date(yearNum, 0, 1);
                        endDate = new Date(yearNum, 11, 31, 23, 59, 59, 999);
                    }
                    break;
                case 'range':
                    if (dateFrom) {
                        startDate = new Date(dateFrom);
                        startDate.setHours(0, 0, 0, 0);
                    }
                    if (dateTo) {
                        endDate = new Date(dateTo);
                        endDate.setHours(23, 59, 59, 999);
                    }
                    break;
            }
        }
        
        // Xây dựng query filter
        const query = {};
        if (maMau) {
            query.maMau = maMau;
        }
        if (catVaiId) {
            query.catVaiId = String(catVaiId).trim();
        }
        
        // Lấy dữ liệu:
        // - Nếu lọc theo ngayNhap: dùng query ngayNhap như trước
        // - Nếu lọc theo lichSuCat.ngayCat: lọc theo phần tử lịch sử (elemMatch) và TRIM lịch sử theo range
        if (startDate || endDate) {
            if (resolvedTimeField === 'import') {
                const ngayNhapCond = {};
                if (startDate) ngayNhapCond.$gte = startDate;
                if (endDate) ngayNhapCond.$lte = endDate;
                query.ngayNhap = ngayNhapCond;
            } else {
                const ngayCatCond = {};
                if (startDate) ngayCatCond.$gte = startDate;
                if (endDate) ngayCatCond.$lte = endDate;
                const elemMatch = { ngayCat: ngayCatCond };
                if (createdBy) elemMatch.createdBy = String(createdBy).trim();
                query.lichSuCat = { $elemMatch: elemMatch };
            }
        } else if (resolvedTimeField === 'cut' && createdBy) {
            // Lọc theo nhân viên cắt dù không chọn thời gian
            query.lichSuCat = { $elemMatch: { createdBy: String(createdBy).trim() } };
        } else if (resolvedTimeField === 'import' && createdBy) {
            // Lọc theo người tạo đối tượng (ngày nhập)
            query.createdBy = String(createdBy).trim();
        }

        let list = await DoiTuongCatVai.find(query).sort({ ngayNhap: -1, catVaiId: 1 }).lean();
        
        // Nếu đang lọc theo lịch sử cắt, trim lichSuCat theo range để UI/Excel phản ánh đúng "lịch sử trong kỳ"
        if (resolvedTimeField === 'cut' && (startDate || endDate || createdBy)) {
            list = list.map(item => {
                const lichSuCat = Array.isArray(item.lichSuCat) ? item.lichSuCat : [];
                const filtered = lichSuCat.filter(cut => {
                    if (!cut || !cut.ngayCat) return false;
                    if (createdBy && String(cut.createdBy || '').trim() !== String(createdBy).trim()) return false;
                    const t = new Date(cut.ngayCat).getTime();
                    if (startDate && t < startDate.getTime()) return false;
                    if (endDate && t > endDate.getTime()) return false;
                    return true;
                });
                return { ...item, lichSuCat: filtered };
            });
        }
        
        // Gom nhóm theo catVaiId nếu được yêu cầu
        if (groupByCatVaiId === 'true') {
            const grouped = {};
            list.forEach(item => {
                const key = item.catVaiId;
                if (!grouped[key]) {
                    grouped[key] = item;
                } else {
                    // Cộng dồn (thường không xảy ra vì catVaiId là unique, nhưng phòng hờ)
                    grouped[key].dienTichDaCat += (item.dienTichDaCat || 0);
                    grouped[key].dienTichConLai = Math.max(0, grouped[key].dienTichBanDau - grouped[key].dienTichDaCat);
                    grouped[key].soMConLai = Math.round((grouped[key].dienTichConLai / 2.3) * 100) / 100;
                    grouped[key].tienDoPercent = grouped[key].chieuDaiCayVai > 0 ? 
                        Math.round(((grouped[key].chieuDaiCayVai - grouped[key].soMConLai) / grouped[key].chieuDaiCayVai) * 100) : 0;
                }
            });
            list = Object.values(grouped);
        }

        // Snapshot trước phân trang để summary phản ánh TOÀN BỘ dữ liệu theo filter
        const fullList = Array.isArray(list) ? list : [];

        // Tính toán thống kê:
        // - Nếu lọc theo lịch sử cắt: tổng hợp theo các entry lichSuCat (đúng "theo lịch sử cắt")
        // - Nếu lọc theo ngày nhập: giữ cách tính cũ theo aggregate của đối tượng
        const summary = (() => {
            if (resolvedTimeField === 'cut') {
                const allCuts = [];
                for (const item of fullList) {
                    const cuts = Array.isArray(item.lichSuCat) ? item.lichSuCat : [];
                    cuts.forEach((cut, idx) => {
                        allCuts.push({ cut, idx, item });
                    });
                }
                return {
                    totalCatVai: fullList.length,
                    totalCuts: allCuts.length,
                    totalItems: allCuts.reduce((sum, x) => sum + (Array.isArray(x.cut.items) ? x.cut.items.length : 0), 0),
                    totalDienTich: allCuts.reduce((sum, x) => sum + (Number(x.cut.dienTichDaCat) || 0), 0),
                    totalSoM: allCuts.reduce((sum, x) => sum + (Number(x.cut.dienTichDaCat) || 0) / 2.3, 0),
                    totalVaiThieu: allCuts.reduce((sum, x) => sum + (Number(x.cut.vaiThieu && x.cut.vaiThieu.soM) || 0), 0),
                    totalVaiLoi: allCuts.reduce((sum, x) => sum + (Number(x.cut.vaiLoi && x.cut.vaiLoi.soM) || 0), 0),
                    totalNhapLaiKho: allCuts.reduce((sum, x) => sum + (Number(x.cut.nhapLaiKho && x.cut.nhapLaiKho.soM) || 0), 0)
                };
            }
            return {
                totalCatVai: fullList.length,
                totalItems: fullList.reduce((sum, item) => sum + (item.items ? item.items.length : 0), 0),
                totalDienTich: fullList.reduce((sum, item) => sum + (item.dienTichDaCat || 0), 0),
                totalSoM: fullList.reduce((sum, item) => sum + (item.chieuDaiCayVai - (item.soMConLai || 0)), 0),
                totalVaiThieu: fullList.reduce((sum, item) => sum + ((item.vaiThieu && item.vaiThieu.soM) ? item.vaiThieu.soM : 0), 0),
                totalVaiLoi: fullList.reduce((sum, item) => sum + ((item.vaiLoi && item.vaiLoi.soM) ? item.vaiLoi.soM : 0), 0),
                totalNhapLaiKho: fullList.reduce((sum, item) => sum + ((item.nhapLaiKho && item.nhapLaiKho.soM) ? item.nhapLaiKho.soM : 0), 0)
            };
        })();

        // Lấy danh sách mẫu vải để filter
        const mauVaiList = await MauVai.find({}).sort({ maMau: 1 }).lean();

        // Phân trang (chỉ áp dụng cho JSON response, không áp dụng cho export)
        const resolvedPageSizeRaw = Number(pageSize);
        const resolvedPageRaw = Number(page);
        const resolvedPageSize = Number.isFinite(resolvedPageSizeRaw) && resolvedPageSizeRaw > 0 ? Math.min(200, Math.max(5, resolvedPageSizeRaw)) : 20;
        const resolvedPage = Number.isFinite(resolvedPageRaw) && resolvedPageRaw > 0 ? Math.floor(resolvedPageRaw) : 1;
        const totalItems = fullList.length;
        const totalPages = Math.max(1, Math.ceil(totalItems / resolvedPageSize));
        const safePage = Math.min(totalPages, Math.max(1, resolvedPage));
        const startIdx = (safePage - 1) * resolvedPageSize;
        const endIdx = startIdx + resolvedPageSize;
        list = fullList.slice(startIdx, endIdx);

        // Nếu là export, tạo file Excel
        if (isExport === 'true') {
            const workbook = XLSX.utils.book_new();
            
            // Sheet 1: Tổng quan
            const summaryData = [
                ['Báo cáo data cắt vải'],
                ['Ngày xuất:', new Date().toLocaleString('vi-VN')],
                [''],
                ['Tổng đối tượng cắt vải:', summary.totalCatVai],
                ['Tổng số kích thước đã cắt:', summary.totalItems],
                ['Tổng diện tích đã cắt (m²):', summary.totalDienTich.toFixed(2)],
                ['Tổng số m đã cắt:', summary.totalSoM.toFixed(2)],
                ['Tổng vải thiếu (m):', summary.totalVaiThieu.toFixed(2)],
                ['Tổng vải lỗi (m):', summary.totalVaiLoi.toFixed(2)],
                ['Tổng nhập lại kho (m):', summary.totalNhapLaiKho.toFixed(2)],
                ['']
            ];
            const summarySheet = XLSX.utils.aoa_to_sheet(summaryData);
            XLSX.utils.book_append_sheet(workbook, summarySheet, 'Tổng quan');
            
            // Sheet 2: Chi tiết
            const detailData = list.map(item => ({
                'ID': item.catVaiId,
                'Mẫu vải': `${item.maMau} - ${item.tenMau}`,
                'Ngày nhập': new Date(item.ngayNhap).toLocaleDateString('vi-VN'),
                'Nhân viên': item.createdBy,
                'Chiều dài (m)': item.chieuDaiCayVai,
                'Diện tích ban đầu (m²)': item.dienTichBanDau,
                'Diện tích đã cắt (m²)': item.dienTichDaCat,
                'Số m còn lại': item.soMConLai,
                'Tiến độ (%)': item.tienDoPercent,
                'Vải thiếu (m)': (item.vaiThieu && item.vaiThieu.soM) ? item.vaiThieu.soM : 0,
                'Vải lỗi (m)': (item.vaiLoi && item.vaiLoi.soM) ? item.vaiLoi.soM : 0,
                'Nhập lại kho (m)': (item.nhapLaiKho && item.nhapLaiKho.soM) ? item.nhapLaiKho.soM : 0,
                'Số lần cắt': item.lichSuCat ? item.lichSuCat.length : 1,
                'Số kích thước': item.items ? item.items.length : 0,
                'Trạng thái': item.trangThai === 'active' ? 'Đang cắt' : item.trangThai === 'completed' ? 'Hoàn thành' : 'Lưu trữ'
            }));
            const detailSheet = XLSX.utils.json_to_sheet(detailData);
            XLSX.utils.book_append_sheet(workbook, detailSheet, 'Chi tiết');
            
            // Sheet 3: Lịch sử cắt (theo từng lần cắt)
            const allCuts = [];
            list.forEach(item => {
                const cuts = Array.isArray(item.lichSuCat) ? item.lichSuCat : [];
                cuts.forEach((cut, idx) => {
                    allCuts.push({
                        'ID': item.catVaiId,
                        'Mẫu vải': `${item.maMau} - ${item.tenMau}`,
                        'Lần cắt': idx + 1,
                        'Ngày cắt': cut.ngayCat ? new Date(cut.ngayCat).toLocaleString('vi-VN') : '',
                        'Nhân viên cắt': cut.createdBy || item.createdBy || '',
                        'Số kích thước': Array.isArray(cut.items) ? cut.items.length : 0,
                        'Diện tích cắt (m²)': Number(cut.dienTichDaCat) || 0,
                        'Số m còn lại': Number(cut.soMConLai) || 0,
                        'Vải thiếu (m)': Number(cut.vaiThieu && cut.vaiThieu.soM) || 0,
                        'Vải lỗi (m)': Number(cut.vaiLoi && cut.vaiLoi.soM) || 0,
                        'Nhập lại kho (m)': Number(cut.nhapLaiKho && cut.nhapLaiKho.soM) || 0
                    });
                });
            });
            if (allCuts.length) {
                const cutsSheet = XLSX.utils.json_to_sheet(allCuts);
                XLSX.utils.book_append_sheet(workbook, cutsSheet, 'Lich su cat');
            }
            
            const outputBuffer = XLSX.write(workbook, { bookType: 'xlsx', type: 'buffer' });
            const filename = `BaoCaoCatVai_${new Date().toISOString().split('T')[0]}.xlsx`;
            
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
            res.send(outputBuffer);
            return;
        }

        res.json({
            success: true,
            data: {
                list,
                summary,
                mauVaiList,
                meta: {
                    timeField: resolvedTimeField,
                    startDate,
                    endDate
                },
                pagination: {
                    page: safePage,
                    pageSize: resolvedPageSize,
                    totalItems,
                    totalPages
                }
            }
        });

    } catch (error) {
        console.error('❌ Lỗi lấy báo cáo:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy báo cáo: ' + error.message
        });
    }
});

// API lấy danh sách mẫu vải
app.get('/api/mau-vai', requireLogin, requireWarehouseAccess, async (req, res) => {
    try {
        const mauVaiList = await MauVai.find({}).sort({ maMau: 1 });
        res.json({
            success: true,
            data: mauVaiList
        });
    } catch (error) {
        console.error('❌ Lỗi lấy danh sách mẫu vải:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy danh sách mẫu vải: ' + error.message
        });
    }
});

// API lấy danh sách kích thước
app.get('/api/kich-thuoc', requireLogin, requireWarehouseAccess, async (req, res) => {
    try {
        const kichThuocList = await KichThuoc.find({}).sort({ kichThuoc: 1 });
        res.json({
            success: true,
            data: kichThuocList
        });
    } catch (error) {
        console.error('❌ Lỗi lấy danh sách kích thước:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy danh sách kích thước: ' + error.message
        });
    }
});

// Hàm utility để parse cao và ngang từ kích thước
// Hỗ trợ các format: 
// - "30cm x 40cm", "30x40", "30cmx40cm", "30 x 40", "30cm x40cm"
// - "Ngang1m5xCao2m", "ngang150xcao200", "Ngang1.5m x Cao2m"
// - "1m5x2m", "1.5m x 2m"
function parseCaoNgangFromKichThuoc(kichThuoc) {
    if (!kichThuoc || typeof kichThuoc !== 'string') {
        return { cao: null, ngang: null };
    }

    // Loại bỏ khoảng trắng thừa và chuyển về lowercase
    const cleaned = kichThuoc.trim().toLowerCase();
    
    // Pattern 1: "Ngang1m5xCao2m" hoặc "ngang1m5xcao2m" (format không có khoảng trắng)
    // Tìm "ngang" + số + "m" + số (tùy chọn) + "x" + "cao" + số + "m" + số (tùy chọn)
    const patternNgangCaoCompact = /ngang\s*(\d+)\s*m\s*(\d+)?\s*x\s*cao\s*(\d+)\s*m\s*(\d+)?/i;
    const matchNgangCaoCompact = cleaned.match(patternNgangCaoCompact);
    
    if (matchNgangCaoCompact) {
        let ngang = parseFloat(matchNgangCaoCompact[1]);
        // Nếu có số thứ 2 (ví dụ: 1m5 = 1.5m)
        if (matchNgangCaoCompact[2]) {
            ngang = ngang + parseFloat('0.' + matchNgangCaoCompact[2]);
        }
        ngang = ngang * 100; // Chuyển về cm
        
        let cao = parseFloat(matchNgangCaoCompact[3]);
        // Nếu có số thứ 4 (ví dụ: 2m0 = 2.0m)
        if (matchNgangCaoCompact[4]) {
            cao = cao + parseFloat('0.' + matchNgangCaoCompact[4]);
        }
        cao = cao * 100; // Chuyển về cm
        
        return { cao: cao.toString(), ngang: ngang.toString() };
    }
    
    // Pattern 2: "Ngang150xcao200" hoặc "ngang1.5m x cao2m" (format có khoảng trắng hoặc số thập phân)
    // Tìm "ngang" + số + đơn vị + "x" + "cao" + số + đơn vị
    const patternNgangCao = /ngang\s*(\d+(?:\.\d+)?)\s*(?:m|cm)?\s*(?:(\d+))?\s*x\s*cao\s*(\d+(?:\.\d+)?)\s*(?:m|cm)?/i;
    const matchNgangCao = cleaned.match(patternNgangCao);
    
    if (matchNgangCao) {
        let ngang = parseFloat(matchNgangCao[1]);
        // Nếu có số thứ 2 (ví dụ: 1m5 = 1.5m)
        if (matchNgangCao[2]) {
            ngang = ngang + parseFloat('0.' + matchNgangCao[2]);
        }
        // Chuyển về cm nếu là m
        if (cleaned.includes('m') && !cleaned.includes('cm')) {
            ngang = ngang * 100;
        }
        
        let cao = parseFloat(matchNgangCao[3]);
        // Chuyển về cm nếu là m
        if (cleaned.includes('m') && !cleaned.includes('cm')) {
            cao = cao * 100;
        }
        
        return { cao: cao.toString(), ngang: ngang.toString() };
    }
    
    // Pattern 3: "1m5x2m" hoặc "1.5m x 2m" (format ngắn gọn)
    // Tìm số + m + số (tùy chọn) + x + số + m
    const patternShort = /(\d+)\s*m\s*(\d+)?\s*x\s*(\d+)\s*m/i;
    const matchShort = cleaned.match(patternShort);
    
    if (matchShort) {
        let ngang = parseFloat(matchShort[1]);
        if (matchShort[2]) {
            ngang = ngang + parseFloat('0.' + matchShort[2]);
        }
        ngang = ngang * 100; // Chuyển về cm
        
        let cao = parseFloat(matchShort[3]) * 100; // Chuyển về cm
        
        return { cao: cao.toString(), ngang: ngang.toString() };
    }
    
    // Pattern 4: "30cm x 40cm" hoặc "30cmx40cm" hoặc "30 x 40"
    const pattern1 = /(\d+(?:\.\d+)?)\s*(?:cm|m)?\s*x\s*(\d+(?:\.\d+)?)\s*(?:cm|m)?/i;
    const match1 = cleaned.match(pattern1);
    
    if (match1) {
        let cao = parseFloat(match1[1]);
        let ngang = parseFloat(match1[2]);
        
        // Chuyển về cm nếu là m
        if (cleaned.includes('m') && !cleaned.includes('cm')) {
            cao = cao * 100;
            ngang = ngang * 100;
        }
        
        return { cao: cao.toString(), ngang: ngang.toString() };
    }

    // Pattern 5: "30x40" (không có đơn vị, giả định là cm)
    const pattern2 = /(\d+(?:\.\d+)?)\s*x\s*(\d+(?:\.\d+)?)/i;
    const match2 = cleaned.match(pattern2);
    
    if (match2) {
        const cao = parseFloat(match2[1]);
        const ngang = parseFloat(match2[2]);
        return { cao: cao.toString(), ngang: ngang.toString() };
    }

    return { cao: null, ngang: null };
}

// Hàm tính toán may áo gối từ items
// Có 2 trường hợp:
// 1. Kích thước có chiều cao 180cm (ví dụ: 100-180) → (ngang + 5) * SL
// 2. Có 2 kích thước có tổng chiều cao = 180cm (ví dụ: 150-110 + 100-70) → (ngang1 + 5 + ngang2 + 5) * SL
// Khi có kích thước này, phần vải còn lại (230-180=50cm) dùng để may áo gối
function calculateMayAoGoi(items, maMau) {
    const mayAoGoi = [];
    
    try {
        if (!items || items.length === 0) return mayAoGoi;
        
        // Trường hợp 1: Tìm kích thước có chiều cao 180cm
        items.forEach(it => {
            // Tìm pattern trong cả kichThuoc và szSku (pattern có thể nằm trong szSku như "100-180")
            const kichThuoc = (it.kichThuoc || '').toString();
            const szSku = (it.szSku || '').toString();
            
            // Tìm pattern: số - 180 (ví dụ: "100-180", "100 - 180", "(100-180)")
            let match = kichThuoc.match(/(\d+)\s*-\s*180/);
            if (!match) {
                match = kichThuoc.match(/\((\d+)\s*-\s*180\)/);
            }
            // Nếu không tìm thấy trong kichThuoc, tìm trong szSku
            if (!match) {
                match = szSku.match(/(\d+)\s*-\s*180/);
            }
            
            if (match) {
                const ngang = parseInt(match[1], 10);
                if (!isNaN(ngang)) {
                    const qty = parseInt(it.soLuong || 0, 10) || 0;
                    if (qty > 0) {
                        const value = (ngang + 5) * qty;
                        mayAoGoi.push({
                            maMau: maMau,
                            label: 'May áo gối',
                            ngang: ngang,
                            qty: qty,
                            calcStr: `(${ngang} + 5) * ${qty}`,
                            value: value
                        });
                    }
                }
            }
        });
        
        // Trường hợp 2: Tìm các cặp kích thước có tổng chiều cao = 180cm (110 + 70 = 180)
        // CHỈ ÁP DỤNG CHO MẪU CÓ MÃ MẪU 4 VÀ 14 (Mùa đông, corgi)
        const maMauNum = parseInt(maMau, 10);
        const isMuaDongOrCorgi = (maMauNum === 4 || maMauNum === 14);
        
        if (isMuaDongOrCorgi) {
            // Tìm kích thước có chiều cao 110cm (1m1) - tìm trong cả kichThuoc và szSku
            const kichThuoc110 = items.filter(it => {
                const kt = (it.kichThuoc || '').toString();
                const szSku = (it.szSku || '').toString();
                const match = kt.match(/(\d+)\s*-\s*110/) || szSku.match(/(\d+)\s*-\s*110/);
                return match !== null;
            });
            
            // Tìm kích thước có chiều cao 70cm (0.7m) - tìm trong cả kichThuoc và szSku
            const kichThuoc70 = items.filter(it => {
                const kt = (it.kichThuoc || '').toString();
                const szSku = (it.szSku || '').toString();
                const match = kt.match(/(\d+)\s*-\s*70/) || szSku.match(/(\d+)\s*-\s*70/);
                return match !== null;
            });
            
            // Nếu có cả 2 loại, tính toán may áo gối - tách riêng từng cặp
            if (kichThuoc110.length > 0 && kichThuoc70.length > 0) {
                // Duyệt từng cặp kích thước và tính riêng
                kichThuoc110.forEach(item110 => {
                    const kt110 = (item110.kichThuoc || '').toString();
                    const szSku110 = (item110.szSku || '').toString();
                    let match110 = kt110.match(/(\d+)\s*-\s*110/);
                    if (!match110) match110 = szSku110.match(/(\d+)\s*-\s*110/);
                    if (!match110) return;
                    
                    const ngang110 = parseInt(match110[1], 10);
                    if (isNaN(ngang110)) return;
                    const qty110 = parseInt(item110.soLuong || 0, 10);
                    
                    kichThuoc70.forEach(item70 => {
                        const kt70 = (item70.kichThuoc || '').toString();
                        const szSku70 = (item70.szSku || '').toString();
                        let match70 = kt70.match(/(\d+)\s*-\s*70/);
                        if (!match70) match70 = szSku70.match(/(\d+)\s*-\s*70/);
                        if (!match70) return;
                        
                        const ngang70 = parseInt(match70[1], 10);
                        if (isNaN(ngang70)) return;
                        const qty70 = parseInt(item70.soLuong || 0, 10);
                        
                        // Số lượng = số lượng nhỏ nhất của cặp này
                        const qty = Math.min(qty110, qty70);
                        
                        if (qty > 0) {
                            const value = (ngang110 + 5 + ngang70 + 5) * qty;
                            mayAoGoi.push({
                                maMau: maMau,
                                label: 'May áo gối',
                                ngang: ngang110 + ngang70, // Lưu tổng của 2 ngang (Number)
                                qty: qty,
                                calcStr: `(${ngang110} + 5 + ${ngang70} + 5) * ${qty}`,
                                value: value
                            });
                        }
                    });
                });
            }
        }
        
    } catch (e) {
        console.warn('Error calculating mayAoGoi:', e);
    }
    
    return mayAoGoi;
}

// Tính tổng số mét đã cắt dựa trên (ngang + 5) * SL / 100
// Bỏ qua phôi phát sinh/lưu trữ và áp dụng hệ số cho cao 110 (1/2) và 70 (1/3) cho mẫu không đặc biệt
// QUAN TRỌNG: Với bộ kích thước đặc biệt (isSpecialSet), chỉ tính 1 lần cho kích thước đầu tiên
function shouldApplyCao110CeilRule(tenMau) {
    // Ngoại lệ: mẫu "sương đêm corgi mùa đông" (match theo keyword)
    const t = String(tenMau || '').toLowerCase();
    if (!t) return true;
    const isException =
        t.includes('sương đêm') ||
        t.includes('suong dem') ||
        t.includes('corgi') ||
        t.includes('mùa đông') ||
        t.includes('mua dong');
    return !isException;
}

function calculateSoMDaCat(items, maMau, tenMau) {
    const maMauStr = String(maMau || '');
    const isMauDacBiet = maMauStr === '2' || maMauStr === '43' || maMauStr === '4' || maMauStr === '14';
    let totalMeters = 0;
    
    // Theo dõi các bộ kích thước đặc biệt đã tính để tránh tính trùng
    const processedSpecialSets = new Set();

    (items || []).forEach(item => {
        if (!item || item.isPhatSinh || item.isLuuTru) return;

        // Xử lý bộ kích thước đặc biệt: chỉ tính 1 lần cho kích thước đầu tiên trong bộ
        if (item.isSpecialSet && item.specialSetName) {
            // Nếu đã tính cho bộ này rồi, bỏ qua các kích thước còn lại trong bộ
            if (processedSpecialSets.has(item.specialSetName)) {
                return;
            }
            // Đánh dấu đã tính cho bộ này
            processedSpecialSets.add(item.specialSetName);
        }

        const szSku = (item.szSku || '').toString();
        const parts = szSku.split('-');
        const ngang = parseFloat(parts[0]) || 0;
        if (!ngang) return;

        let soLuongThucTe = parseFloat(item.soLuong || 0) || 0;

            if (!isMauDacBiet) {
            const hasCao110 = parts.slice(1).some(p => parseInt(p) === 110);
            const hasCao70 = !hasCao110 && parts.slice(1).some(p => parseInt(p) === 70);

            if (hasCao110) {
                    const applyCao110Ceil = shouldApplyCao110CeilRule(tenMau);
                    // Cao 110: chia 2 làm tròn lên (ceil), trừ ngoại lệ
                    soLuongThucTe = applyCao110Ceil ? Math.ceil(soLuongThucTe / 2) : (soLuongThucTe / 2);
            } else if (hasCao70) {
                // Với cao 70: làm tròn lên đến bội của 3 gần nhất, rồi chia 3
                // Ví dụ: 16 → làm tròn lên 18 → 18/3 = 6
                soLuongThucTe = Math.ceil(soLuongThucTe / 3);
            }
        }

        const ngangThucTe = ngang + 5;
        totalMeters += (soLuongThucTe * ngangThucTe) / 100; // đổi cm sang m
    });

    return Math.round(totalMeters * 100) / 100;
}

/** Mỗi dòng items = một bản ghi NhapPhoi riêng (không upsert/gộp theo mẫu+kích thước). */
async function insertNhapPhoiRecordsFromItems(items, username, catVaiId, vaiLoiSnapshot = null) {
    if (!items || !Array.isArray(items)) return;
    const soMLoiVal =
        vaiLoiSnapshot && Number(vaiLoiSnapshot.soM) > 0 ? Number(vaiLoiSnapshot.soM) : null;
    let skuHangLoiVal = null;
    if (soMLoiVal != null && items[0] && items[0].maMau) {
        let tpl = await Template.findOne({ isActive: true });
        if (!tpl) tpl = await Template.findOne().sort({ createdAt: -1 });
        const hangLoiSuffix = tpl?.skuHangLoiSuffix || '00-404-230';
        skuHangLoiVal = `${String(items[0].maMau).trim()}-${hangLoiSuffix}`;
    }
    for (const item of items) {
        const { maMau, tenMau, kichThuoc, szSku, soLuong, slLoi } = item;
        if (!maMau || !tenMau || !kichThuoc || !szSku || soLuong === undefined || soLuong < 0) {
            continue;
        }
        await NhapPhoi.create({
            maMau: String(maMau).trim(),
            tenMau: String(tenMau).trim(),
            kichThuoc: String(kichThuoc).trim(),
            szSku: String(szSku).trim(),
            soLuong: Math.floor(Number(soLuong)),
            slLoi: slLoi !== undefined && slLoi !== null ? Math.max(0, Math.floor(Number(slLoi))) : 0,
            soMLoi: soMLoiVal,
            skuHangLoi: skuHangLoiVal,
            createdBy: username,
            importDate: new Date(),
            catVaiId: catVaiId ? String(catVaiId).trim() : null
        });
    }
}

// API lưu/cập nhật nhập phôi
app.post('/api/nhap-phoi', requireLogin, requireWarehouseAccess, async (req, res) => {
    try {
        const { items, chieuDaiCayVai, vaiLoi, vaiThieu, nhapLaiKho, catVaiId, linkedItems } = req.body;
        const username = req.session.user.username;

        if (!items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Danh sách nhập phôi không được rỗng'
            });
        }

        if (!chieuDaiCayVai || chieuDaiCayVai <= 0) {
            return res.status(400).json({
                success: false,
                message: 'Chiều dài cây vải không hợp lệ'
            });
        }

        // Tính toán diện tích
        const dienTichBanDau = chieuDaiCayVai * 2.3;
        let dienTichDaCat = 0;
        const itemsWithDienTich = [];
        const firstItem = items[0];

        for (const item of items) {
            const { maMau, tenMau, kichThuoc, szSku, soLuong, slLoi } = item;
            
            if (!maMau || !tenMau || !kichThuoc || !szSku || soLuong === undefined || soLuong < 0) {
                continue;
            }

            // Lấy diện tích từ kích thước
            const kichThuocData = await KichThuoc.findOne({ szSku: szSku });
            const dienTich = kichThuocData ? (kichThuocData.dienTich || 0) : 0;
            const dienTichCat = soLuong * dienTich;
            dienTichDaCat += dienTichCat;

            itemsWithDienTich.push({
                kichThuoc,
                szSku,
                soLuong,
                slLoi: slLoi !== undefined && slLoi !== null ? Number(slLoi) : 0,
                dienTich,
                dienTichCat
            });
        }

        // Chuẩn hóa dữ liệu vải lỗi, thiếu, nhập lại kho - luôn có giá trị, mặc định 0
        const vaiLoiData = vaiLoi && vaiLoi.chieuDai > 0 ? vaiLoi : { chieuDai: 0, dienTich: 0, soM: 0 };
        const vaiThieuData = vaiThieu && vaiThieu.soM !== undefined ? vaiThieu : { soM: 0 };
        const nhapLaiKhoData = nhapLaiKho && nhapLaiKho.soM !== undefined ? nhapLaiKho : { soM: 0 };

        const dienTichConLai = Math.max(0, dienTichBanDau - dienTichDaCat);
        const chieuDaiHuuDung = Math.max(0, chieuDaiCayVai - (vaiLoiData.chieuDai || 0));
        const soMDaCat = calculateSoMDaCat(items, firstItem.maMau, firstItem.tenMau);

        if (soMDaCat > chieuDaiHuuDung) {
            return res.status(400).json({
                success: false,
                message: `Tổng (ngang + 5) * SL = ${soMDaCat.toFixed(2)}m vượt Số m hữu dụng ${chieuDaiHuuDung.toFixed(2)}m (đã trừ vải lỗi nếu có). Vui lòng giảm số lượng phôi.`
            });
        }

        const soMConLai = Math.max(0, Math.round((chieuDaiHuuDung - soMDaCat) * 100) / 100);
        const tienDoPercent = chieuDaiCayVai > 0 ? Math.round(((chieuDaiCayVai - soMConLai) / chieuDaiCayVai) * 100) : 0;

        // Tính toán may áo gối từ items có chiều cao 180
        const mayAoGoiData = calculateMayAoGoi(items, firstItem.maMau);

        // Lưu thông tin cây vải
        const CayVai = require('./models/CayVai');
        const cayVai = new CayVai({
            maMau: firstItem.maMau,
            tenMau: firstItem.tenMau,
            chieuDaiCayVai: chieuDaiCayVai,
            dienTichBanDau: dienTichBanDau,
            dienTichDaCat: dienTichDaCat,
            dienTichConLai: dienTichConLai,
            soMConLai: soMConLai,
            tienDoPercent: tienDoPercent,
            vaiLoi: vaiLoiData,
            vaiThieu: vaiThieuData,
            nhapLaiKho: nhapLaiKhoData,
            items: itemsWithDienTich,
            mayAoGoi: mayAoGoiData,
            createdBy: username
        });

        await cayVai.save();

        // Lưu/Update đối tượng cắt vải
        let doiTuongCatVai;
        const lichSuCatEntry = {
            ngayCat: new Date(),
            items: itemsWithDienTich,
            dienTichDaCat: dienTichDaCat,
            dienTichConLai: dienTichConLai,
            soMConLai: soMConLai,
            vaiLoi: vaiLoiData, // Lưu thông tin vải lỗi cho lần cắt này
            vaiThieu: vaiThieuData, // Lưu thông tin vải thiếu cho lần cắt này
            nhapLaiKho: nhapLaiKhoData, // Lưu thông tin nhập lại kho cho lần cắt này
            createdBy: username
        };

        if (catVaiId) {
            // Cập nhật đối tượng cắt vải đã có
            doiTuongCatVai = await DoiTuongCatVai.findOne({ catVaiId: catVaiId });
            
            if (doiTuongCatVai) {
                // Cập nhật thông tin
                doiTuongCatVai.dienTichDaCat += dienTichDaCat;
                doiTuongCatVai.dienTichConLai = Math.max(0, doiTuongCatVai.dienTichBanDau - doiTuongCatVai.dienTichDaCat);
                
                // Thêm items vào danh sách
                doiTuongCatVai.items.push(...itemsWithDienTich);
                
                // Thêm vào lịch sử cắt
                doiTuongCatVai.lichSuCat.push(lichSuCatEntry);
                
                // Cập nhật vải lỗi, thiếu, nhập lại kho - luôn cập nhật
                // Vải lỗi: cộng dồn nếu có giá trị > 0
                if (vaiLoiData && vaiLoiData.chieuDai > 0) {
                    doiTuongCatVai.vaiLoi.chieuDai += vaiLoiData.chieuDai;
                    doiTuongCatVai.vaiLoi.dienTich += vaiLoiData.dienTich;
                    doiTuongCatVai.vaiLoi.soM += vaiLoiData.soM;
                }
                // Vải thiếu: luôn lưu, lấy giá trị lớn nhất giữa giá trị hiện tại và giá trị mới
                // Nếu không tick thì giá trị là 0, nếu tick thì lấy soMConLai
                doiTuongCatVai.vaiThieu.soM = Math.max(doiTuongCatVai.vaiThieu.soM || 0, vaiThieuData.soM || 0);
                // Nhập lại kho: luôn lưu, lấy giá trị lớn nhất giữa giá trị hiện tại và giá trị mới
                // Nếu không tick thì giá trị là 0, nếu tick thì lấy soMConLai
                doiTuongCatVai.nhapLaiKho.soM = Math.max(doiTuongCatVai.nhapLaiKho.soM || 0, nhapLaiKhoData.soM || 0);
                
                // Cập nhật may áo gối: cộng dồn vào danh sách hiện có
                if (mayAoGoiData && mayAoGoiData.length > 0) {
                    if (!doiTuongCatVai.mayAoGoi) {
                        doiTuongCatVai.mayAoGoi = [];
                    }
                    doiTuongCatVai.mayAoGoi.push(...mayAoGoiData);
                }

                // Tính lại số m còn lại theo chiều dài hữu dụng sau khi cộng dồn
                const totalSoMDaCat = calculateSoMDaCat(doiTuongCatVai.items, doiTuongCatVai.maMau, doiTuongCatVai.tenMau);
                const chieuDaiHuuDungUpdate = Math.max(0, doiTuongCatVai.chieuDaiCayVai - (doiTuongCatVai.vaiLoi?.chieuDai || 0));
                if (totalSoMDaCat > chieuDaiHuuDungUpdate) {
                    return res.status(400).json({
                        success: false,
                        message: `Tổng (ngang + 5) * SL tích lũy = ${totalSoMDaCat.toFixed(2)}m vượt Số m hữu dụng ${chieuDaiHuuDungUpdate.toFixed(2)}m. Vui lòng giảm số lượng phôi.`
                    });
                }
                doiTuongCatVai.soMConLai = Math.max(0, Math.round((chieuDaiHuuDungUpdate - totalSoMDaCat) * 100) / 100);
                doiTuongCatVai.tienDoPercent = doiTuongCatVai.chieuDaiCayVai > 0 ? 
                    Math.round(((doiTuongCatVai.chieuDaiCayVai - doiTuongCatVai.soMConLai) / doiTuongCatVai.chieuDaiCayVai) * 100) : 0;
                
                await doiTuongCatVai.save();
            } else {
                return res.status(404).json({
                    success: false,
                    message: 'Không tìm thấy đối tượng cắt vải với ID: ' + catVaiId
                });
            }
        } else {
            // Tạo mới đối tượng cắt vải
            // Tạo ID tự động: CV-{maMau}-{timestamp}
            const timestamp = Date.now();
            const newCatVaiId = `CV-${firstItem.maMau}-${timestamp}`;
            
            doiTuongCatVai = new DoiTuongCatVai({
                catVaiId: newCatVaiId,
                maMau: firstItem.maMau,
                tenMau: firstItem.tenMau,
                ngayNhap: new Date(),
                createdBy: username,
                chieuDaiCayVai: chieuDaiCayVai,
                dienTichBanDau: dienTichBanDau,
                dienTichDaCat: dienTichDaCat,
                dienTichConLai: dienTichConLai,
                soMConLai: soMConLai,
                tienDoPercent: tienDoPercent,
                vaiLoi: vaiLoiData,
                vaiThieu: vaiThieuData,
                nhapLaiKho: nhapLaiKhoData,
                items: itemsWithDienTich,
                mayAoGoi: mayAoGoiData,
                lichSuCat: [lichSuCatEntry],
                trangThai: 'active'
            });
            
            await doiTuongCatVai.save();
        }

        await insertNhapPhoiRecordsFromItems(items, username, doiTuongCatVai.catVaiId, vaiLoiData);

        // Xử lý linkedItems (Trời xanh 43) nếu có
        const linkedCayVaiList = [];
        if (linkedItems && Array.isArray(linkedItems) && linkedItems.length > 0) {
            // Tính toán diện tích cho linkedItems
            let linkedDienTichDaCat = 0;
            const linkedItemsWithDienTich = [];
            const firstLinkedItem = linkedItems[0];
            
            for (const item of linkedItems) {
                const { maMau, tenMau, kichThuoc, szSku, soLuong } = item;
                
                if (!maMau || !tenMau || !kichThuoc || !szSku || soLuong === undefined || soLuong < 0) {
                    continue;
                }

                // Lấy diện tích từ kích thước (nếu có trong database)
                let kichThuocData = await KichThuoc.findOne({ szSku: szSku });
                let dienTich = kichThuocData ? (kichThuocData.dienTich || 0) : 0;
                
                // Nếu không tìm thấy diện tích, tính từ szSku (format: 43-25-ngang-cao)
                // Ví dụ: 43-25-100-120 => ngang=100cm, cao=120cm => dienTich = 1.2 m²
                if (dienTich === 0 && szSku.includes('-')) {
                    const parts = szSku.split('-');
                    if (parts.length >= 4) {
                        const ngang = parseFloat(parts[2]) || 0; // cm
                        const cao = parseFloat(parts[3]) || 0; // cm
                        if (ngang > 0 && cao > 0) {
                            dienTich = (ngang * cao) / 10000; // Chuyển từ cm² sang m²
                        }
                    }
                }
                
                const dienTichCat = soLuong * dienTich;
                linkedDienTichDaCat += dienTichCat;

                linkedItemsWithDienTich.push({
                    kichThuoc,
                    szSku,
                    soLuong,
                    dienTich,
                    dienTichCat
                });
            }
            
            // Tính toán các thông tin cho linkedCayVai
            // Với linkedItems, không có chieuDaiCayVai riêng, tính từ diện tích
            const linkedChieuDaiCayVai = linkedDienTichDaCat > 0 ? Math.round((linkedDienTichDaCat / 2.3) * 100) / 100 : 0;
            const linkedDienTichBanDau = linkedDienTichDaCat; // Diện tích ban đầu = diện tích đã cắt (vì là phát sinh)
            const linkedDienTichConLai = 0; // Không còn lại vì là phát sinh
            const linkedSoMConLai = 0;
            const linkedTienDoPercent = 100; // 100% vì đã cắt hết
            
            // Tính may áo gối cho linkedItems (nếu có)
            const linkedMayAoGoi = calculateMayAoGoi(linkedItems, firstLinkedItem.maMau);
            
            // Tạo CayVai cho Trời xanh (43)
            const linkedCayVai = new CayVai({
                maMau: firstLinkedItem.maMau,
                tenMau: firstLinkedItem.tenMau,
                chieuDaiCayVai: linkedChieuDaiCayVai,
                dienTichBanDau: linkedDienTichBanDau,
                dienTichDaCat: linkedDienTichDaCat,
                dienTichConLai: linkedDienTichConLai,
                soMConLai: linkedSoMConLai,
                tienDoPercent: linkedTienDoPercent,
                vaiLoi: { chieuDai: 0, dienTich: 0, soM: 0 },
                vaiThieu: { soM: 0 },
                nhapLaiKho: { soM: 0 },
                items: linkedItemsWithDienTich,
                mayAoGoi: linkedMayAoGoi,
                createdBy: username
            });
            
            await linkedCayVai.save();
            
            // Tạo DoiTuongCatVai cho Trời xanh (43)
            const linkedTimestamp = Date.now();
            const linkedCatVaiId = `CV-${firstLinkedItem.maMau}-${linkedTimestamp}`;
            
            const linkedDoiTuongCatVai = new DoiTuongCatVai({
                catVaiId: linkedCatVaiId,
                maMau: firstLinkedItem.maMau,
                tenMau: firstLinkedItem.tenMau,
                ngayNhap: new Date(),
                createdBy: username,
                chieuDaiCayVai: linkedChieuDaiCayVai,
                dienTichBanDau: linkedDienTichBanDau,
                dienTichDaCat: linkedDienTichDaCat,
                dienTichConLai: linkedDienTichConLai,
                soMConLai: linkedSoMConLai,
                tienDoPercent: linkedTienDoPercent,
                vaiLoi: { chieuDai: 0, dienTich: 0, soM: 0 },
                vaiThieu: { soM: 0 },
                nhapLaiKho: { soM: 0 },
                items: linkedItemsWithDienTich,
                mayAoGoi: linkedMayAoGoi,
                lichSuCat: [{
                    ngayCat: new Date(),
                    items: linkedItemsWithDienTich,
                    dienTichDaCat: linkedDienTichDaCat,
                    dienTichConLai: linkedDienTichConLai,
                    soMConLai: linkedSoMConLai,
                    vaiLoi: { chieuDai: 0, dienTich: 0, soM: 0 },
                    vaiThieu: { soM: 0 },
                    nhapLaiKho: { soM: 0 },
                    createdBy: username
                }],
                trangThai: 'active'
            });
            
            await linkedDoiTuongCatVai.save();

            await insertNhapPhoiRecordsFromItems(linkedItems, username, linkedDoiTuongCatVai.catVaiId, null);
            
            // Thêm vào danh sách để trả về
            linkedCayVaiList.push({
                nhapPhoi: linkedItems,
                cayVai: linkedCayVai,
                doiTuongCatVai: {
                    catVaiId: linkedDoiTuongCatVai.catVaiId,
                    maMau: linkedDoiTuongCatVai.maMau,
                    tenMau: linkedDoiTuongCatVai.tenMau,
                    ngayNhap: linkedDoiTuongCatVai.ngayNhap,
                    createdBy: linkedDoiTuongCatVai.createdBy,
                    chieuDaiCayVai: linkedDoiTuongCatVai.chieuDaiCayVai,
                    dienTichBanDau: linkedDoiTuongCatVai.dienTichBanDau,
                    dienTichDaCat: linkedDoiTuongCatVai.dienTichDaCat,
                    dienTichConLai: linkedDoiTuongCatVai.dienTichConLai,
                    soMConLai: linkedDoiTuongCatVai.soMConLai,
                    tienDoPercent: linkedDoiTuongCatVai.tienDoPercent,
                    vaiLoi: linkedDoiTuongCatVai.vaiLoi,
                    vaiThieu: linkedDoiTuongCatVai.vaiThieu,
                    nhapLaiKho: linkedDoiTuongCatVai.nhapLaiKho,
                    items: linkedDoiTuongCatVai.items,
                    mayAoGoi: linkedDoiTuongCatVai.mayAoGoi,
                    trangThai: linkedDoiTuongCatVai.trangThai
                }
            });
        }

        const responseData = {
            success: true,
            message: `Đã lưu ${items.length} mục nhập phôi và thông tin cây vải`,
            data: {
                nhapPhoi: items,
                cayVai: cayVai,
                doiTuongCatVai: {
                    catVaiId: doiTuongCatVai.catVaiId,
                    maMau: doiTuongCatVai.maMau,
                    tenMau: doiTuongCatVai.tenMau,
                    ngayNhap: doiTuongCatVai.ngayNhap,
                    createdBy: doiTuongCatVai.createdBy,
                    chieuDaiCayVai: doiTuongCatVai.chieuDaiCayVai,
                    dienTichBanDau: doiTuongCatVai.dienTichBanDau,
                    dienTichDaCat: doiTuongCatVai.dienTichDaCat,
                    dienTichConLai: doiTuongCatVai.dienTichConLai,
                    soMConLai: doiTuongCatVai.soMConLai,
                    tienDoPercent: doiTuongCatVai.tienDoPercent,
                    vaiLoi: doiTuongCatVai.vaiLoi,
                    vaiThieu: doiTuongCatVai.vaiThieu,
                    nhapLaiKho: doiTuongCatVai.nhapLaiKho,
                    items: doiTuongCatVai.items,
                    mayAoGoi: doiTuongCatVai.mayAoGoi,
                    trangThai: doiTuongCatVai.trangThai
                }
            }
        };
        
        // Thêm linkedCayVai vào response nếu có
        if (linkedCayVaiList.length > 0) {
            responseData.data.linkedCayVai = linkedCayVaiList;
        }
        
        res.json(responseData);

    } catch (error) {
        console.error('❌ Lỗi lưu nhập phôi:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lưu nhập phôi: ' + error.message
        });
    }
});

// API lấy thông tin đối tượng cắt vải theo ID
app.get('/api/doi-tuong-cat-vai/:catVaiId', requireLogin, requireWarehouseAccess, async (req, res) => {
    try {
        const { catVaiId } = req.params;
        const username = req.session.user.username;

        const doiTuong = await DoiTuongCatVai.findOne({ catVaiId: catVaiId });

        if (!doiTuong) {
            return res.status(404).json({
                success: false,
                message: 'Không tìm thấy đối tượng cắt vải với ID: ' + catVaiId
            });
        }

        // Chỉ cho phép xem đối tượng của chính mình hoặc admin
        if (doiTuong.createdBy !== username && req.session.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Bạn không có quyền xem đối tượng cắt vải này'
            });
        }

        res.json({
            success: true,
            data: {
                catVaiId: doiTuong.catVaiId,
                maMau: doiTuong.maMau,
                tenMau: doiTuong.tenMau,
                ngayNhap: doiTuong.ngayNhap,
                createdBy: doiTuong.createdBy,
                chieuDaiCayVai: doiTuong.chieuDaiCayVai,
                dienTichBanDau: doiTuong.dienTichBanDau,
                dienTichDaCat: doiTuong.dienTichDaCat,
                dienTichConLai: doiTuong.dienTichConLai,
                soMConLai: doiTuong.soMConLai,
                tienDoPercent: doiTuong.tienDoPercent,
                vaiLoi: doiTuong.vaiLoi,
                vaiThieu: doiTuong.vaiThieu,
                nhapLaiKho: doiTuong.nhapLaiKho,
                items: doiTuong.items,
                mayAoGoi: doiTuong.mayAoGoi || [],
                trangThai: doiTuong.trangThai,
                lichSuCat: doiTuong.lichSuCat || []
            }
        });

    } catch (error) {
        console.error('❌ Lỗi lấy thông tin đối tượng cắt vải:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy thông tin đối tượng cắt vải: ' + error.message
        });
    }
});

// API tìm kiếm DoiTuongCatVai bằng keyword
app.get('/api/doi-tuong-cat-vai/search/keyword', requireLogin, requireWarehouseAccess, async (req, res) => {
    try {
        const { q } = req.query;
        const username = req.session.user.username;
        
        if (!q || q.trim().length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Vui lòng nhập từ khóa tìm kiếm'
            });
        }

        // Tìm kiếm bằng catVaiId, maMau, tenMau (admin xem được tất cả, user xem của mình)
        const query = {
            $or: [
                { catVaiId: { $regex: q, $options: 'i' } },
                { maMau: { $regex: q, $options: 'i' } },
                { tenMau: { $regex: q, $options: 'i' } }
            ]
        };

        // Nếu không phải admin, chỉ xem của chính mình
        if (req.session.user.role !== 'admin') {
            query.createdBy = username;
        }

        const doiTuongList = await DoiTuongCatVai.find(query)
            .sort({ ngayNhap: -1 })
            .limit(50);

        res.json({
            success: true,
            data: doiTuongList.map(dt => ({
                _id: dt._id,
                catVaiId: dt.catVaiId,
                maMau: dt.maMau,
                tenMau: dt.tenMau,
                ngayNhap: dt.ngayNhap,
                createdBy: dt.createdBy,
                chieuDaiCayVai: dt.chieuDaiCayVai,
                tienDoPercent: dt.tienDoPercent,
                trangThai: dt.trangThai
            }))
        });

    } catch (error) {
        console.error('❌ Lỗi tìm kiếm đối tượng cắt vải:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi tìm kiếm đối tượng cắt vải: ' + error.message
        });
    }
});

// API lấy danh sách nhập phôi đã nhập (của user hiện tại)
app.get('/api/nhap-phoi', requireLogin, requireWarehouseAccess, async (req, res) => {
    try {
        const username = req.session.user.username;
        const CayVai = require('./models/CayVai');
        
        // Lấy cả NhapPhoi, CayVai và DoiTuongCatVai
        // Ưu tiên lấy từ DoiTuongCatVai vì đây là dữ liệu mới nhất
        const [nhapPhoiList, cayVaiList, doiTuongCatVaiList] = await Promise.all([
            NhapPhoi.find({ createdBy: username })
                .sort({ importDate: -1, createdAt: -1, maMau: 1, kichThuoc: 1 }),
            CayVai.find({ createdBy: username })
                .sort({ importDate: -1, maMau: 1 }),
            DoiTuongCatVai.find({ createdBy: username, trangThai: { $ne: 'archived' } })
                .sort({ ngayNhap: -1, maMau: 1 })
        ]);

        // Chuyển đổi DoiTuongCatVai thành format tương tự CayVai để hiển thị
        const cayVaiListFromDoiTuong = doiTuongCatVaiList.map(doiTuong => ({
            _id: doiTuong._id,
            maMau: doiTuong.maMau,
            tenMau: doiTuong.tenMau,
            chieuDaiCayVai: doiTuong.chieuDaiCayVai,
            dienTichBanDau: doiTuong.dienTichBanDau,
            dienTichDaCat: doiTuong.dienTichDaCat,
            dienTichConLai: doiTuong.dienTichConLai,
            soMConLai: doiTuong.soMConLai,
            tienDoPercent: doiTuong.tienDoPercent,
            vaiLoi: doiTuong.vaiLoi,
            vaiThieu: doiTuong.vaiThieu,
            nhapLaiKho: doiTuong.nhapLaiKho,
            items: doiTuong.items,
            mayAoGoi: doiTuong.mayAoGoi || [],
            createdBy: doiTuong.createdBy,
            importDate: doiTuong.ngayNhap,
            catVaiId: doiTuong.catVaiId
        }));

        // Gộp danh sách, ưu tiên DoiTuongCatVai
        const allCayVaiList = [...cayVaiListFromDoiTuong, ...cayVaiList];

        res.json({
            success: true,
            data: nhapPhoiList,
            cayVaiList: allCayVaiList
        });
    } catch (error) {
        console.error('❌ Lỗi lấy danh sách nhập phôi:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy danh sách nhập phôi: ' + error.message
        });
    }
});

// API xóa một mục nhập phôi
app.delete('/api/nhap-phoi/:id', requireLogin, requireWarehouseAccess, async (req, res) => {
    try {
        const { id } = req.params;
        const username = req.session.user.username;

        const result = await NhapPhoi.findOneAndDelete({
            _id: id,
            createdBy: username
        });

        if (!result) {
            return res.status(404).json({
                success: false,
                message: 'Không tìm thấy mục nhập phôi hoặc không có quyền xóa'
            });
        }

        res.json({
            success: true,
            message: 'Đã xóa mục nhập phôi',
            data: result
        });

    } catch (error) {
        console.error('❌ Lỗi xóa nhập phôi:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi xóa nhập phôi: ' + error.message
        });
    }
});

// Route lấy danh sách orders cho checker với date filtering
app.get('/api/orders/checker', authFromToken, async (req, res) => {
    try {
        // Chỉ cho phép checker, đối soát và admin truy cập
        if (!['checker', 'reconciler', 'admin'].includes(req.authUser.role)) {
            return res.status(403).json({
                success: false,
                message: 'Chỉ checker, đối soát hoặc admin mới có quyền truy cập'
            });
        }

        const { dateFrom, dateTo, maVanDon, page = 1, pageSize = 20 } = req.query;
        const pageNum = parseInt(page, 10);
        const pageSizeNum = parseInt(pageSize, 10);

        // Build query với date filtering
        // Hàm helper để build date query
        const buildDateQuery = () => {
            if (!dateFrom && !dateTo) return null;
            
            const dateConditions = [];
            if (dateFrom && dateTo) {
                const fromDate = new Date(dateFrom);
                const toDate = new Date(dateTo);
                toDate.setHours(23, 59, 59, 999);
                dateConditions.push(
                    { importDate: { $gte: fromDate, $lte: toDate } },
                    { verifiedAt: { $gte: fromDate, $lte: toDate } },
                    { blockedAt: { $gte: fromDate, $lte: toDate } }
                );
            } else if (dateFrom) {
                const fromDate = new Date(dateFrom);
                dateConditions.push(
                    { importDate: { $gte: fromDate } },
                    { verifiedAt: { $gte: fromDate } },
                    { blockedAt: { $gte: fromDate } }
                );
            } else if (dateTo) {
                const toDate = new Date(dateTo);
                toDate.setHours(23, 59, 59, 999);
                dateConditions.push(
                    { importDate: { $lte: toDate } },
                    { verifiedAt: { $lte: toDate } },
                    { blockedAt: { $lte: toDate } }
                );
            }
            
            return dateConditions.length > 0 ? { $or: dateConditions } : null;
        };

        // Build query cho Order/DataOrder
        const buildQuery = () => {
            const query = {};
            const conditions = [];
            
            // Thêm điều kiện mã vận đơn
            if (maVanDon) {
                conditions.push({ maVanDon: { $regex: new RegExp(maVanDon, 'i') } });
            }
            
            // Thêm điều kiện ngày (nếu có)
            const dateQuery = buildDateQuery();
            if (dateQuery) {
                conditions.push(dateQuery);
            }
            
            // Kết hợp các điều kiện
            if (conditions.length === 0) {
                return {};
            } else if (conditions.length === 1) {
                return conditions[0];
            } else {
                return { $and: conditions };
            }
        };

        const query = buildQuery();

        // Nếu có filter theo ngày HOẶC chỉ tìm theo maVanDon (không có date), truy vấn từ cả Order và DataOrder
        let orders = [];
        let totalOrders = 0;
        
        if (dateFrom || dateTo || (maVanDon && !dateFrom && !dateTo)) {
            // Truy vấn từ cả Order và DataOrder khi:
            // 1. Có filter ngày
            // 2. Hoặc chỉ tìm theo maVanDon (không có date) - để tìm được đơn hàng cũ đã backup
            const [ordersFromOrder, ordersFromDataOrder, countFromOrder, countFromDataOrder] = await Promise.all([
                Order.find(query).sort({ importDate: -1 }).lean(),
                DataOrder.find(query).sort({ importDate: -1 }).lean(),
                Order.countDocuments(query),
                DataOrder.countDocuments(query)
            ]);
            
            // Merge và sort kết quả
            orders = [...ordersFromOrder, ...ordersFromDataOrder];
            orders.sort((a, b) => {
                const dateA = new Date(a.importDate || 0);
                const dateB = new Date(b.importDate || 0);
                return dateB - dateA; // Sort descending
            });
            
            totalOrders = countFromOrder + countFromDataOrder;
            
            // Áp dụng phân trang sau khi merge
            const startIdx = (pageNum - 1) * pageSizeNum;
            const endIdx = startIdx + pageSizeNum;
            orders = orders.slice(startIdx, endIdx);
        } else {
            // Không có filter ngày và không có maVanDon - chỉ truy vấn từ Order (hiển thị đơn hàng hiện tại)
            totalOrders = await Order.countDocuments(query);
            orders = await Order.find(query)
                .sort({ importDate: -1 })
                .skip((pageNum - 1) * pageSizeNum)
                .limit(pageSizeNum)
                .lean();
        }

        // Map MasterData như API cũ
        const skuList = orders.map(o => o.maHang).filter(Boolean);
        const masterDatas = await MasterData.find({ sku: { $in: skuList } });
        const masterMap = new Map();
        for (const md of masterDatas) {
            if (md.sku) masterMap.set(md.sku, md);
        }

        const mappedOrders = orders.map(o => {
            let md = masterMap.get(o.maHang);
            // orders có thể là plain object (từ .lean()) hoặc Mongoose document
            const orderObj = o.toObject ? o.toObject() : o;
            return {
                ...orderObj,
                mauVai: md && typeof md.mauVai === 'string' ? md.mauVai : '',
                tenPhienBan: md && typeof md.tenPhienBan === 'string' ? md.tenPhienBan : '',
                masterData: md || null
            };
        });

        res.json({
            success: true,
            data: {
                orders: mappedOrders,
                pagination: {
                    page: pageNum,
                    pageSize: pageSizeNum,
                    total: totalOrders,
                    totalPages: Math.ceil(totalOrders / pageSizeNum)
                },
                filters: { dateFrom, dateTo, maVanDon }
            }
        });
    } catch (error) {
        console.error('❌ Lỗi API orders/checker:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy đơn hàng cho checker: ' + error.message
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

// Route tra cứu tên sản phẩm theo SKU từ master data
app.get('/api/master-data/sku/:sku', authFromToken, async (req, res) => {
    try {
        const sku = String(req.params.sku || '').trim();
        if (!sku) {
            return res.status(400).json({ success: false, message: 'SKU không hợp lệ' });
        }
        const productName = await lookupProductNameFromMasterDataBySku(sku);

        if (!productName) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy tên sản phẩm theo SKU' });
        }

        return res.json({
            success: true,
            data: {
                sku,
                productName,
                source: 'MasterData'
            }
        });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Lỗi tra cứu SKU: ' + error.message });
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
        
        // Chuyển Map thành array và sắp xếp theo STT, đồng thời tính toán lại trạng thái
        const processedOrders = Array.from(skuMap.values()).map((sku, index) => {
            const totalRequired = sku.quantity;
            
            // Tìm đơn hàng gốc (direct order) cho SKU này để lấy trạng thái quét
            // Giả định rằng số lượng quét cho một mã hàng được lưu trữ trên một bản ghi order duy nhất của mã hàng đó
            const sourceDirectOrder = orders.find(o => o.maHang === sku.maHang);
            
            const scannedQuantity = sourceDirectOrder ? (sourceDirectOrder.scannedQuantity || 0) : 0;
            
            // Một SKU tổng hợp được coi là 'verified' nếu số lượng quét đủ yêu cầu
            const isVerified = scannedQuantity >= totalRequired;
            
            const verifiedAt = (isVerified && sourceDirectOrder) ? sourceDirectOrder.verifiedAt : null;
            const checkingBy = sourceDirectOrder ? sourceDirectOrder.checkingBy : null;
            const block = sourceDirectOrder ? sourceDirectOrder.block : false;
            const blockedAt = sourceDirectOrder ? sourceDirectOrder.blockedAt : null;

            const directSources = sku.sources.filter(s => s.type === 'direct');
            const comboSources = sku.sources.filter(s => s.type === 'combo');

            return {
                stt: index + 1,
                maDongGoi: orders[0]?.maDongGoi || '',
                maVanDon: orders[0]?.maVanDon || '',
                maDonHang: orders[0]?.maDonHang || '',
                maHang: sku.maHang,
                soLuong: totalRequired,
                displayMaHang: sku.maHang,
                displaySoLuong: totalRequired,
                isCombo: false, // Đã tách thành SKU riêng biệt
                isCombined: directSources.length > 0 && comboSources.length > 0,
                sources: sku.sources,
                importDate: orders[0]?.importDate || new Date(),
                verified: isVerified,
                verifiedAt: verifiedAt,
                scannedQuantity: scannedQuantity,
                checkingBy: checkingBy,
                block: block,
                blockedAt: blockedAt
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

// Route lấy danh sách "đơn hủy" (từ UserBehaviour) cho checker/admin
app.get('/api/cancelled-orders', authFromToken, async (req, res) => {
    try {
        const UserBehaviour = require('./models/UserBehaviour');

        // Chỉ checker/admin mới xem danh sách đơn hủy toàn hệ thống
        if (!['admin', 'checker'].includes(req.authUser.role)) {
            return res.status(403).json({ success: false, message: 'Bạn không có quyền truy cập' });
        }

        const {
            dateFrom,
            dateTo,
            user,
            searchText,
            limit = 2000,
            page = 1
        } = req.query;

        const query = {
            method: 'scanner',
            $or: [
                { 'metadata.action': 'cancel_order' },
                { description: { $regex: /hủy\s*đơn/i } }
            ]
        };

        if (user) {
            query.user = String(user).trim();
        }

        if (dateFrom || dateTo) {
            query.time = {};
            if (dateFrom) {
                const from = new Date(String(dateFrom));
                if (!isNaN(from.getTime())) query.time.$gte = from;
            }
            if (dateTo) {
                const to = new Date(String(dateTo));
                if (!isNaN(to.getTime())) {
                    to.setHours(23, 59, 59, 999);
                    query.time.$lte = to;
                }
            }
            // nếu parse fail -> xóa để tránh query sai
            if (!Object.keys(query.time).length) delete query.time;
        }

        if (searchText) {
            const st = String(searchText).trim();
            if (st) {
                query.$and = query.$and || [];
                query.$and.push({
                    $or: [
                        { 'metadata.maVanDon': { $regex: new RegExp(st.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') } },
                        { description: { $regex: new RegExp(st.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') } }
                    ]
                });
            }
        }

        const pageNum = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(5000, Math.max(1, parseInt(limit) || 2000));
        const skip = (pageNum - 1) * limitNum;

        const behaviours = await UserBehaviour.find(query)
            .sort({ time: -1 })
            .limit(limitNum)
            .skip(skip)
            .lean();

        const total = await UserBehaviour.countDocuments(query);

        return res.json({
            success: true,
            data: {
                behaviours,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    total,
                    pages: Math.ceil(total / limitNum)
                }
            }
        });
    } catch (error) {
        console.error('❌ Lỗi lấy cancelled-orders:', error);
        return res.status(500).json({ success: false, message: 'Lỗi lấy đơn hủy: ' + error.message });
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
        // 1. Tìm TẤT CẢ các đơn trực tiếp với maHang (xử lý duplicate orders)
        // 2. Tìm tất cả combo có mã base = maHang đang quét
        // 3. Tính tổng số lượng từ cả đơn riêng và combo
        let directOrders = await Order.find({ maVanDon, maHang }); // Tìm TẤT CẢ các đơn duplicate
        let directOrder = directOrders.length > 0 ? directOrders[0] : null; // Lấy đơn đầu tiên làm mainOrder
        let comboOrders = [];
        let totalRequiredQuantity = 0;
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
        
        // Tính tổng số lượng cần quét từ TẤT CẢ các direct orders (xử lý duplicate)
        if (directOrders.length > 0) {
            // Cộng tổng số lượng từ tất cả các đơn duplicate
            totalRequiredQuantity += directOrders.reduce((sum, order) => sum + order.soLuong, 0);
            console.log(`🔍 Found ${directOrders.length} duplicate direct orders for ${maHang}, total required: ${totalRequiredQuantity}`);
        }
        
        // Cộng thêm từ combo - SỬA LỖI LOGIC
        for (const { order: comboOrder, combo } of comboOrders) {
            // Logic mới: Nhân số lượng combo với số lượng sản phẩm trong combo
            const comboRequiredQuantity = comboOrder.soLuong * combo.soLuong;
            totalRequiredQuantity += comboRequiredQuantity;
            console.log(`📦 Combo ${combo.comboCode} requires ${combo.soLuong} of ${combo.maHang} each. Order has ${comboOrder.soLuong} combos. Contribution: ${comboRequiredQuantity}`);
        }
        
        // Xác định order chính để cập nhật (ưu tiên đơn riêng, nếu không có thì lấy combo đầu tiên)
        let mainOrder = directOrder;
        if (!mainOrder && comboOrders.length > 0) {
            mainOrder = comboOrders[0].order;
            isComboOrder = true;
        }
        
        // SỬA LỖI: Lấy số lượng đã quét từ mainOrder, là nơi duy nhất lưu trữ số lần quét cho mã hàng này
        const totalScannedQuantity = mainOrder ? (mainOrder.scannedQuantity || 0) : 0;
        
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

        // Cập nhật số lượng quét
        const newTotalScanned = totalScannedQuantity + 1;
        mainOrder.scannedQuantity = newTotalScanned;
        
        // Cập nhật trạng thái verified và lưu các bản ghi liên quan
        if (newTotalScanned >= totalRequiredQuantity) {
            const verifiedAt = new Date();
            mainOrder.verified = true;
            mainOrder.verifiedAt = verifiedAt;
            if (!mainOrder.checkingBy) {
                mainOrder.checkingBy = userId;
            }

            // Khi một mã hàng tổng hợp đã đủ, xác nhận tất cả các order gốc của nó (cả direct và combo)
            const allPromises = [];
            
            // Thêm mainOrder vào danh sách lưu (nó có thể là direct order hoặc combo order đầu tiên)
            allPromises.push(mainOrder.save());

            // Nếu có directOrders (bao gồm duplicate), verify tất cả các duplicate orders
            if (directOrders && directOrders.length > 0) {
                for (const dupOrder of directOrders) {
                    // Tránh lưu lại mainOrder nếu nó là một direct order
                    if (dupOrder._id.toString() !== mainOrder._id.toString()) {
                        dupOrder.verified = true;
                        dupOrder.verifiedAt = verifiedAt;
                        dupOrder.scannedQuantity = newTotalScanned; // Đồng bộ số lượng đã quét
                        if (!dupOrder.checkingBy) {
                            dupOrder.checkingBy = userId;
                        }
                        allPromises.push(dupOrder.save());
                    }
                }
            } else if (directOrder && directOrder._id.toString() !== mainOrder._id.toString()) {
                // Fallback: Nếu không có directOrders array, dùng directOrder cũ
                directOrder.verified = true;
                directOrder.verifiedAt = verifiedAt;
                directOrder.scannedQuantity = newTotalScanned; // Đồng bộ số lượng đã quét
                if (!directOrder.checkingBy) {
                    directOrder.checkingBy = userId;
                }
                allPromises.push(directOrder.save());
            }

            // Xác nhận và thêm các combo order khác (nếu có) vào danh sách lưu
            for (const { order: comboOrderToVerify } of comboOrders) {
                // Tránh lưu lại mainOrder nếu nó là một combo order
                if (mainOrder._id.toString() !== comboOrderToVerify._id.toString()) {
                    comboOrderToVerify.verified = true;
                    comboOrderToVerify.verifiedAt = verifiedAt;
                    if (!comboOrderToVerify.checkingBy) {
                        comboOrderToVerify.checkingBy = userId;
                    }
                    allPromises.push(comboOrderToVerify.save());
                }
            }
            
            await Promise.all(allPromises);

        } else {
            mainOrder.verified = false;
            await mainOrder.save();
            
            // Nếu có directOrders (bao gồm duplicate), cập nhật trạng thái chưa verified cho tất cả
            if (directOrders && directOrders.length > 0) {
                for (const dupOrder of directOrders) {
                    if (dupOrder._id.toString() !== mainOrder._id.toString()) {
                        dupOrder.verified = false;
                        dupOrder.scannedQuantity = newTotalScanned; // Đồng bộ số lượng đã quét
                        await dupOrder.save();
                    }
                }
            } else if (directOrder && directOrder._id.toString() !== mainOrder._id.toString()) {
                // Fallback: Nếu không có directOrders array, dùng directOrder cũ
                directOrder.verified = false;
                directOrder.scannedQuantity = newTotalScanned; // Đồng bộ số lượng đã quét
                await directOrder.save();
            }
        }
        
        // Xử lý duplicate orders (orders có cùng maHang nhưng khác maDongGoi)
        // Chỉ áp dụng cho non-combo orders (không áp dụng cho combo orders)
        // Lưu ý: Logic này đã được xử lý ở trên khi verify, nhưng vẫn giữ lại để đảm bảo đồng bộ
        if (!isComboOrder) {
            // Chỉ tìm các duplicate orders chưa được xử lý ở trên
            const duplicateOrders = await Order.find({ 
                maVanDon, 
                maHang,
                _id: { $ne: mainOrder._id } // Loại trừ mainOrder
            });
            
            // Cập nhật duplicate orders để đồng bộ với mainOrder (nếu chưa được cập nhật ở trên)
            for (const duplicateOrder of duplicateOrders) {
                // Chỉ cập nhật nếu chưa được xử lý ở trên (kiểm tra bằng cách so sánh scannedQuantity)
                if (duplicateOrder.scannedQuantity !== mainOrder.scannedQuantity || 
                    duplicateOrder.verified !== mainOrder.verified) {
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
        }
        
        // Lấy mainOrder sau khi cập nhật - đảm bảo lấy trạng thái mới nhất
        let updatedMainOrder = await Order.findById(mainOrder._id);
        
        // Nếu có directOrder và nó khác mainOrder, cũng refresh nó để đảm bảo có trạng thái mới nhất
        // (Trường hợp này xảy ra khi mainOrder là combo order nhưng có directOrder riêng)
        if (directOrder && directOrder._id.toString() !== mainOrder._id.toString()) {
            const refreshedDirectOrder = await Order.findById(directOrder._id);
            // Nếu directOrder đã được verify trong lần cập nhật này, sử dụng nó làm updatedMainOrder cho response
            if (refreshedDirectOrder && refreshedDirectOrder.verified && !updatedMainOrder.verified) {
                updatedMainOrder = refreshedDirectOrder;
            }
        }

        
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

        // Xác định trạng thái verified cuối cùng
        // Khi có cả directOrder và comboOrders, cần kiểm tra xem đã đủ số lượng chưa
        // Nếu đã đủ số lượng (newTotalScanned >= totalRequiredQuantity), thì verified phải là true
        let finalVerified = updatedMainOrder.verified;
        
        // Kiểm tra lại: nếu đã quét đủ số lượng thì phải verified
        if (newTotalScanned >= totalRequiredQuantity) {
            finalVerified = true;
            // Đảm bảo updatedMainOrder cũng có verified = true (nếu chưa có)
            if (!updatedMainOrder.verified) {
                updatedMainOrder.verified = true;
                updatedMainOrder.verifiedAt = updatedMainOrder.verifiedAt || new Date();
            }
        }
        
        // Nếu có directOrder riêng biệt (không phải mainOrder), cũng kiểm tra nó
        if (directOrder && directOrder._id.toString() !== mainOrder._id.toString()) {
            const refreshedDirectOrder = await Order.findById(directOrder._id);
            if (refreshedDirectOrder) {
                // Nếu đã đủ số lượng, cả hai đều phải verified
                if (newTotalScanned >= totalRequiredQuantity) {
                    finalVerified = true;
                } else {
                    finalVerified = updatedMainOrder.verified && refreshedDirectOrder.verified;
                }
            }
        }

        res.json({
            success: true,
            message: finalVerified ? 
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
                verified: finalVerified,
                verifiedAt: finalVerified ? (updatedMainOrder.verifiedAt || new Date()) : null,
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
        // Logic mới: Nhóm theo mã hàng base (maHang thực tế được quét) và tính tổng từ cả direct và combo
        
        const comboCache = require('./utils/comboCache');
        
        // Map để nhóm các sản phẩm theo mã base (maHang thực tế được quét)
        // Key: maHang base (ví dụ: "2-6-200-110")
        // Value: { totalRequired, totalScanned, directOrder, verified }
        const productGroups = new Map();
        
        // Xử lý tất cả orders
        for (const order of orders) {
            const combos = await comboCache.getCombosByCode(order.maHang);
            
            if (combos && combos.length > 0) {
                // Đây là combo order - tách thành các mã base
                for (const combo of combos) {
                    const baseMaHang = combo.maHang; // Mã base thực tế
                    const comboRequiredQuantity = order.soLuong * combo.soLuong;
                    
                    if (!productGroups.has(baseMaHang)) {
                        productGroups.set(baseMaHang, {
                            totalRequired: 0,
                            totalScanned: 0,
                            directOrder: null,
                            verified: true
                        });
                    }
                    
                    const group = productGroups.get(baseMaHang);
                    group.totalRequired += comboRequiredQuantity;
                    
                    // Nếu có direct order cho mã base này, số lượng đã quét được lưu ở đó
                    // Nếu không có direct order, số lượng đã quét được lưu ở combo order
                    // Nhưng thực tế, số lượng đã quét luôn được lưu ở direct order (nếu có)
                    // hoặc ở combo order đầu tiên (nếu không có direct)
                }
            } else {
                // Đây là direct order
                const baseMaHang = order.maHang;
                
                if (!productGroups.has(baseMaHang)) {
                    productGroups.set(baseMaHang, {
                        totalRequired: 0,
                        totalScanned: 0,
                        directOrders: [], // Lưu tất cả các duplicate orders
                        verified: true
                    });
                }
                
                const group = productGroups.get(baseMaHang);
                group.totalRequired += order.soLuong;
                
                // SỬA LỖI: Nếu group đã tồn tại từ combo processing (có directOrder: null),
                // cần khởi tạo directOrders array nếu chưa có
                if (!group.directOrders) {
                    group.directOrders = [];
                    // Xóa directOrder cũ nếu có (từ combo processing)
                    if (group.directOrder !== undefined) {
                        delete group.directOrder;
                    }
                }
                
                group.directOrders.push(order); // Thêm vào danh sách duplicate orders
                
                // Cộng số lượng đã quét từ tất cả các duplicate orders
                // (scannedQuantity được đồng bộ giữa các duplicate orders, nên chỉ cần lấy từ 1 order)
                // Nhưng để đảm bảo, lấy giá trị lớn nhất từ tất cả các duplicate orders
                const scannedQty = order.scannedQuantity || 0;
                if (scannedQty > group.totalScanned) {
                    group.totalScanned = scannedQty;
                }
                
                if (!order.verified) {
                    group.verified = false;
                }
            }
        }
        
        // Cập nhật totalScanned và verified cho các sản phẩm
        // Ưu tiên lấy từ direct orders (nếu có), vì đó là nơi lưu trữ scannedQuantity khi có cả direct và combo
        for (const [baseMaHang, group] of productGroups.entries()) {
            if (group.directOrders && group.directOrders.length > 0) {
                // Đã có direct orders - số lượng đã quét đã được set ở trên từ tất cả duplicate orders
                // Đảm bảo verified được set đúng: nếu tất cả direct orders đều verified thì verified = true
                const allVerified = group.directOrders.every(order => order.verified);
                if (allVerified && group.directOrders.length > 0) {
                    group.verified = true;
                }
            } else {
                // Chỉ có combo order - tìm combo order đầu tiên có chứa mã base này
                for (const order of orders) {
                    const combos = await comboCache.getCombosByCode(order.maHang);
                    if (combos && combos.some(c => c.maHang === baseMaHang)) {
                        group.totalScanned = order.scannedQuantity || 0;
                        group.verified = order.verified || false;
                        break;
                    }
                }
            }
            
            // Đảm bảo verified được set đúng dựa trên số lượng đã quét
            // Nếu đã quét đủ số lượng thì phải verified = true
            if (group.totalScanned >= group.totalRequired && group.totalRequired > 0) {
                group.verified = true;
            }
        }
        
        console.log(`🔍 Checking ${productGroups.size} unique products`);
        
        // Kiểm tra tất cả các sản phẩm đã hoàn thành chưa
        const allItemsCompleted = Array.from(productGroups.entries()).every(([baseMaHang, group]) => {
            const isCompleted = group.verified && group.totalScanned >= group.totalRequired;
            console.log(`📦 Product ${baseMaHang}: required=${group.totalRequired}, scanned=${group.totalScanned}, verified=${group.verified}, completed=${isCompleted}`);
            return isCompleted;
        });

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

// API lấy danh sách các ngày có đơn hàng (từ Order và DataOrder)
app.get('/api/stats/available-dates', requireLogin, async (req, res) => {
    try {
        // Lấy danh sách các ngày có đơn hàng từ Order (dựa trên importDate)
        const orderDates = await Order.distinct('importDate');
        
        // Lấy danh sách các ngày có đơn hàng từ DataOrder (dựa trên importDate)
        const dataOrderDates = await DataOrder.distinct('importDate');
        
        // Lấy danh sách các ngày có đơn hàng được verify (dựa trên verifiedAt)
        const verifiedDates = await Order.distinct('verifiedAt', { verified: true });
        const dataOrderVerifiedDates = await DataOrder.distinct('verifiedAt', { verified: true });
        
        // Kết hợp tất cả các ngày
        const allDateObjects = [...orderDates, ...dataOrderDates, ...verifiedDates, ...dataOrderVerifiedDates]
            .filter(date => date != null); // Loại bỏ null/undefined
        
        // Chuyển đổi sang format YYYY-MM-DD và loại bỏ trùng lặp
        const dateSet = new Set();
        allDateObjects.forEach(date => {
            const d = new Date(date);
            if (!isNaN(d.getTime())) {
                // Lấy ngày (bỏ qua giờ)
                const dateStr = d.toISOString().split('T')[0];
                dateSet.add(dateStr);
            }
        });
        
        // Chuyển Set thành array và sắp xếp mới nhất trước
        const allDates = Array.from(dateSet).sort().reverse();
        
        console.log(`[API /api/stats/available-dates] Tìm thấy ${allDates.length} ngày có đơn hàng`);
        
        res.json({
            success: true,
            data: {
                dates: allDates
            }
        });
    } catch (error) {
        console.error('[API /api/stats/available-dates] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy danh sách ngày: ' + error.message
        });
    }
});

// API thống kê số lượng đơn hàng theo nhân viên theo ngày
app.get('/api/stats/orders-by-employee', requireLogin, async (req, res) => {
    try {
        const { date } = req.query;
        
        // Xử lý date đúng cách - tránh lỗi timezone
        let selectedDate;
        if (date) {
            // Parse date string (format: YYYY-MM-DD) và tạo date ở timezone local
            const [year, month, day] = date.split('-').map(Number);
            selectedDate = new Date(year, month - 1, day);
        } else {
            selectedDate = new Date();
        }
        
        // Lấy ngày bắt đầu và kết thúc của ngày được chọn (timezone local)
        const startOfDay = new Date(selectedDate);
        startOfDay.setHours(0, 0, 0, 0);
        
        const endOfDay = new Date(selectedDate);
        endOfDay.setHours(23, 59, 59, 999);
        
        console.log(`[API /api/stats/orders-by-employee] Thống kê từ ${startOfDay.toISOString()} đến ${endOfDay.toISOString()}`);
        
        // Tìm TẤT CẢ đơn hàng trong ngày (verified và chưa verified)
        // Truy vấn từ cả Order và DataOrder dựa trên importDate hoặc verifiedAt
        const queryForDate = {
            $or: [
                // Đơn hàng có importDate trong ngày
                {
                    importDate: {
                        $gte: startOfDay,
                        $lte: endOfDay
                    }
                },
                // Hoặc đơn hàng được verify trong ngày
                {
                    verified: true,
                    verifiedAt: {
                        $gte: startOfDay,
                        $lte: endOfDay
                    }
                }
            ]
        };
        
        // Truy vấn từ Order và DataOrder
        const [ordersFromOrder, ordersFromDataOrder] = await Promise.all([
            Order.find(queryForDate).select('checkingBy verifiedAt createdAt importDate maVanDon maHang soLuong scannedQuantity verified').lean(),
            DataOrder.find(queryForDate).select('checkingBy verifiedAt createdAt importDate maVanDon maHang soLuong scannedQuantity verified').lean()
        ]);
        
        // Merge kết quả
        const allOrders = [...ordersFromOrder, ...ordersFromDataOrder];
        
        console.log(`[API /api/stats/orders-by-employee] Tìm thấy ${allOrders.length} đơn hàng trong ngày`);
        
        // Tính số lượng MaVanDon duy nhất (Tổng số đơn hàng)
        const uniqueMaVanDons = new Set(allOrders.map(o => o.maVanDon).filter(Boolean));
        const totalUniqueVanDons = uniqueMaVanDons.size;
        
        // Phân loại đơn hàng
        const verifiedOrders = allOrders.filter(o => o.verified && o.verifiedAt && 
            o.verifiedAt >= startOfDay && o.verifiedAt <= endOfDay);
        const pendingOrders = allOrders.filter(o => !o.verified);
        const inProgressOrders = allOrders.filter(o => !o.verified && (o.scannedQuantity || 0) > 0);
        
        // Tính số MaVanDon đã verify (duy nhất)
        const verifiedMaVanDons = new Set(verifiedOrders.map(o => o.maVanDon).filter(Boolean));
        const totalVerifiedVanDons = verifiedMaVanDons.size;
        
        // Tính số MaVanDon chưa verify (duy nhất)
        const pendingMaVanDons = new Set(pendingOrders.map(o => o.maVanDon).filter(Boolean));
        const totalPendingVanDons = pendingMaVanDons.size;
        
        // Tính số MaVanDon đang quét (duy nhất)
        const inProgressMaVanDons = new Set(inProgressOrders.map(o => o.maVanDon).filter(Boolean));
        const totalInProgressVanDons = inProgressMaVanDons.size;
        
        // Nhóm theo nhân viên (chỉ tính đơn hàng đã verify)
        const employeeStats = {};
        const vanDonStats = {}; // Thống kê theo maVanDon
        let totalVerifiedOrders = 0;
        let totalVerifiedItems = 0;
        let totalScannedItems = 0;
        let totalRequiredItems = 0;
        
        verifiedOrders.forEach(order => {
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
            
            totalVerifiedOrders++;
            totalVerifiedItems += (order.scannedQuantity || order.soLuong || 1);
        });
        
        // Thống kê tổng quan cho tất cả đơn hàng
        allOrders.forEach(order => {
            totalScannedItems += (order.scannedQuantity || 0);
            totalRequiredItems += order.soLuong;
            
            // Thống kê theo maVanDon
            if (!vanDonStats[order.maVanDon]) {
                vanDonStats[order.maVanDon] = {
                    maVanDon: order.maVanDon,
                    totalOrders: 0,
                    verifiedOrders: 0,
                    totalItems: 0,
                    scannedItems: 0
                };
            }
            vanDonStats[order.maVanDon].totalOrders++;
            vanDonStats[order.maVanDon].totalItems += order.soLuong;
            vanDonStats[order.maVanDon].scannedItems += (order.scannedQuantity || 0);
            if (order.verified) {
                vanDonStats[order.maVanDon].verifiedOrders++;
            }
        });
        
        // Chuyển đổi object thành array và sắp xếp
        const statsArray = Object.values(employeeStats).sort((a, b) => b.totalOrders - a.totalOrders);
        const vanDonStatsArray = Object.values(vanDonStats).sort((a, b) => b.totalOrders - a.totalOrders);
        
        console.log(`[API /api/stats/orders-by-employee] Thống kê: ${statsArray.length} nhân viên, ${totalVerifiedVanDons} mã vận đơn đã verify, ${totalUniqueVanDons} tổng mã vận đơn`);
        
        res.json({
            success: true,
            data: {
                date: date || selectedDate.toISOString().split('T')[0],
                totalEmployees: statsArray.length,
                totalOrders: totalUniqueVanDons, // Tổng số đơn hàng (số MaVanDon duy nhất)
                totalVerifiedOrders: totalVerifiedVanDons, // Số mã vận đơn đã verify (duy nhất)
                totalPendingOrders: totalPendingVanDons, // Số mã vận đơn chưa verify (duy nhất)
                totalInProgressOrders: totalInProgressVanDons, // Số mã vận đơn đang quét (duy nhất)
                totalOrderItems: allOrders.length, // Tổng số order items (để tham khảo)
                totalItems: totalRequiredItems, // Tổng số sản phẩm yêu cầu
                totalScannedItems: totalScannedItems, // Tổng số sản phẩm đã quét
                totalVerifiedItems: totalVerifiedItems, // Tổng số sản phẩm đã verify
                completionRate: totalRequiredItems > 0 ? Math.round((totalScannedItems / totalRequiredItems) * 100) : 0,
                employeeStats: statsArray,
                vanDonStats: vanDonStatsArray // Tất cả mã vận đơn
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

// ==================== ERPNext API Endpoints ====================

// Helper function to make ERPNext API calls using Node.js https/http
function erpnextAPI(method, endpoint, data = null, username = null, password = null) {
    return new Promise((resolve, reject) => {
        const erpnextUrl = config.ERPNEXT_URL;
        const apiKey = config.ERPNEXT_API_KEY;
        const apiSecret = config.ERPNEXT_API_SECRET;

        // Use API Key/Secret if available, otherwise use username/password
        let authHeader = '';
        if (apiKey && apiSecret && apiKey.trim() !== '' && apiSecret.trim() !== '') {
            authHeader = `token ${apiKey}:${apiSecret}`;
        } else if (username && password) {
            authHeader = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
        } else {
            return reject(new Error('ERPNext authentication credentials not configured. Please set ERPNEXT_API_KEY and ERPNEXT_API_SECRET in .env file. See env.example for reference.'));
        }

        // Encode endpoint properly (ERPNext doctypes with spaces need encoding)
        const encodedEndpoint = endpoint.split('/').map(part => encodeURIComponent(part)).join('/');
        const baseUrl = new URL(erpnextUrl);
        const isHttps = baseUrl.protocol === 'https:';
        const httpModule = isHttps ? https : http;
        const path = `/api/resource/${encodedEndpoint}`;

        const options = {
            hostname: baseUrl.hostname,
            port: baseUrl.port || (isHttps ? 443 : 80),
            path: path,
            method: method,
            headers: {
                'Authorization': authHeader,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        };

        if (data && (method === 'POST' || method === 'PUT')) {
            const body = JSON.stringify(data);
            options.headers['Content-Length'] = Buffer.byteLength(body);
        }

        const req = httpModule.request(options, (res) => {
            let responseData = '';

            res.on('data', (chunk) => {
                responseData += chunk;
            });

            res.on('end', () => {
                try {
                    const result = JSON.parse(responseData);

                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        resolve(result);
                    } else {
                        // Log chi tiết lỗi từ ERPNext
                        console.error(`[ERPNext API Error ${res.statusCode}]`, {
                            endpoint: endpoint,
                            method: method,
                            response: result,
                            responseData: responseData
                        });
                        
                        // Cải thiện thông báo lỗi cho các mã lỗi phổ biến
                        let errorMessage = result.message || result.exc || result.exc_type || `ERPNext API error: ${res.statusCode}`;
                        
                        if (res.statusCode === 403) {
                            errorMessage = `Lỗi 403 Forbidden: API Key không có quyền truy cập. Vui lòng kiểm tra:\n1. API Key có đúng không?\n2. User được gán cho API Key có quyền Read/Write Job Card không?\n3. API Key có còn active không?`;
                        } else if (res.statusCode === 401) {
                            errorMessage = `Lỗi 401 Unauthorized: API Key/Secret không đúng hoặc đã hết hạn. Vui lòng kiểm tra lại thông tin xác thực.`;
                        } else if (res.statusCode === 404) {
                            errorMessage = `Lỗi 404 Not Found: Không tìm thấy tài nguyên. Có thể Job Card không tồn tại hoặc URL không đúng.`;
                        } else if (res.statusCode === 500) {
                            // Lỗi 500 thường do validation hoặc custom fields không tồn tại
                            const excMessage = result.exc || result.message || '';
                            if (excMessage.includes('custom_')) {
                                errorMessage = `Lỗi 500: Custom field không tồn tại trong ERPNext. Vui lòng tạo các custom fields sau trong Job Card doctype:\n- custom_lý_do_lỗi (Data)\n- custom_notes (Small Text)\n- custom_support_employees (Data)\n\nChi tiết: ${excMessage}`;
                            } else if (excMessage.includes('employee') || excMessage.includes('Employee')) {
                                errorMessage = `Lỗi 500: Employee không hợp lệ. Vui lòng kiểm tra Employee ID: ${data?.employee || 'N/A'}\n\nChi tiết: ${excMessage}`;
                            } else {
                                errorMessage = `Lỗi 500 Internal Server Error từ ERPNext.\n\nChi tiết: ${excMessage || result.message || 'Không có thông tin chi tiết'}\n\nVui lòng kiểm tra:\n1. Custom fields có tồn tại trong Job Card doctype không?\n2. Dữ liệu có đúng format không?\n3. Employee ID có hợp lệ không?`;
                            }
                        }
                        
                        reject(new Error(errorMessage));
                    }
                } catch (error) {
                    console.error('[ERPNext API] Failed to parse response:', {
                        error: error.message,
                        responseData: responseData,
                        statusCode: res.statusCode
                    });
                    reject(new Error(`Failed to parse response: ${error.message}. Response: ${responseData.substring(0, 200)}`));
                }
            });
        });

        req.on('error', (error) => {
            console.error('ERPNext API Request Error:', error);
            // Cải thiện thông báo lỗi cho người dùng
            if (error.code === 'ECONNREFUSED') {
                reject(new Error(`Không thể kết nối đến ERPNext tại ${erpnextUrl}. Vui lòng kiểm tra: 1) ERPNext có đang chạy không? 2) URL và port có đúng không? 3) Firewall có chặn không?`));
            } else if (error.code === 'ENOTFOUND') {
                reject(new Error(`Không tìm thấy server ERPNext tại ${erpnextUrl}. Vui lòng kiểm tra URL.`));
            } else if (error.code === 'ETIMEDOUT') {
                reject(new Error(`Kết nối đến ERPNext bị timeout tại ${erpnextUrl}. Vui lòng kiểm tra kết nối mạng.`));
            } else {
                reject(new Error(`Lỗi kết nối ERPNext: ${error.message}. URL: ${erpnextUrl}`));
            }
        });

        if (data && (method === 'POST' || method === 'PUT')) {
            req.write(JSON.stringify(data));
        }

        req.end();
    });
}

// Get Job Card by ID
app.post('/api/erpnext/job-card', requireLogin, async (req, res) => {
    try {
        const { jobCardId } = req.body;
        if (!jobCardId) {
            return res.json({ success: false, message: 'Vui lòng cung cấp Job Card ID' });
        }

        // Get user's ERPNext credentials from session or use system credentials
        const username = req.session.user?.erpnext_username || null;
        const password = req.session.user?.erpnext_password || null;

        const result = await erpnextAPI('GET', `Job Card/${jobCardId}`, null, username, password);

        if (result.data) {
            res.json({
                success: true,
                jobCard: result.data
            });
        } else {
            res.json({ success: false, message: 'Không tìm thấy Job Card' });
        }
    } catch (error) {
        console.error('Get Job Card error:', error);
        res.status(500).json({
            success: false,
            message: error.message || 'Lỗi khi lấy thông tin Job Card'
        });
    }
});

// Get Job Card by Work Order and Employee
app.post('/api/erpnext/job-card-by-work-order', requireLogin, async (req, res) => {
    try {
        const { workOrder, employeeId } = req.body;
        if (!workOrder) {
            return res.json({ success: false, message: 'Vui lòng cung cấp Work Order' });
        }
        if (!employeeId) {
            return res.json({ success: false, message: 'Tài khoản chưa được mapping với Employee. Vui lòng liên hệ quản trị viên.' });
        }

        const username = req.session.user?.erpnext_username || null;
        const password = req.session.user?.erpnext_password || null;

        // Search for Job Card by Work Order and Employee
        const baseUrl = new URL(config.ERPNEXT_URL);
        const isHttps = baseUrl.protocol === 'https:';
        const httpModule = isHttps ? https : http;
        
        // Encode doctype name and build search params
        // Tìm Job Card có work_order = workOrder
        // Lưu ý: Một số fields không được phép query trong API list (như total_scrap_qty)
        const doctypeName = encodeURIComponent('Job Card');
        const filters = JSON.stringify([["work_order","=",workOrder]]);
        // Chỉ query các fields được phép - không query total_scrap_qty vì không được phép
        const path = `/api/resource/${doctypeName}?filters=${encodeURIComponent(filters)}&limit_page_length=1000`;
        
        let authHeader = '';
        if (config.ERPNEXT_API_KEY && config.ERPNEXT_API_SECRET && 
            config.ERPNEXT_API_KEY.trim() !== '' && config.ERPNEXT_API_SECRET.trim() !== '') {
            authHeader = `token ${config.ERPNEXT_API_KEY}:${config.ERPNEXT_API_SECRET}`;
        } else if (username && password) {
            authHeader = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
        } else {
            throw new Error('ERPNext authentication credentials not configured. Please set ERPNEXT_API_KEY and ERPNEXT_API_SECRET in .env file.');
        }

        const result = await new Promise((resolve, reject) => {
            const options = {
                hostname: baseUrl.hostname,
                port: baseUrl.port || (isHttps ? 443 : 80),
                path: path,
                method: 'GET',
                headers: {
                    'Authorization': authHeader,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            };

            const req = httpModule.request(options, (res) => {
                let responseData = '';
                res.on('data', (chunk) => { responseData += chunk; });
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(responseData));
                    } catch (error) {
                        reject(error);
                    }
                });
            });

            req.on('error', (error) => {
                console.error('ERPNext API Request Error:', error);
                if (error.code === 'ECONNREFUSED') {
                    reject(new Error(`Không thể kết nối đến ERPNext tại ${config.ERPNEXT_URL}. Vui lòng kiểm tra: 1) ERPNext có đang chạy không? 2) URL và port có đúng không? 3) Firewall có chặn không?`));
                } else if (error.code === 'ENOTFOUND') {
                    reject(new Error(`Không tìm thấy server ERPNext tại ${config.ERPNEXT_URL}. Vui lòng kiểm tra URL.`));
                } else if (error.code === 'ETIMEDOUT') {
                    reject(new Error(`Kết nối đến ERPNext bị timeout tại ${config.ERPNEXT_URL}. Vui lòng kiểm tra kết nối mạng.`));
                } else {
                    reject(new Error(`Lỗi kết nối ERPNext: ${error.message}. URL: ${config.ERPNEXT_URL}`));
                }
            });
            
            req.setTimeout(10000, () => {
                req.destroy();
                reject(new Error(`Kết nối đến ERPNext timeout sau 10 giây tại ${config.ERPNEXT_URL}`));
            });
            
            req.end();
        });

        // Log kết quả từ ERPNext để debug
        console.log(`[ERPNext Response] Work Order: ${workOrder}, Employee: ${employeeId}`);
        console.log(`[ERPNext Response] Total Job Cards found: ${result.data?.length || 0}`);
        
        if (!result.data || result.data.length === 0) {
            console.log(`[ERPNext Response] No Job Cards found or result.data is empty`);
            console.log(`[ERPNext Response] Full result:`, JSON.stringify(result, null, 2));
            return res.json({ 
                success: false, 
                message: `Không tìm thấy Job Card nào trong Work Order ${workOrder}. Vui lòng kiểm tra lại Work Order.` 
            });
        }

        // API list chỉ trả về name, cần gọi GET từng Job Card để lấy đầy đủ thông tin
        console.log(`[Fetching Details] Fetching full details for ${result.data.length} Job Cards...`);
        
        // Gọi song song để tối ưu performance
        const jobCardPromises = result.data.map(jc => 
            erpnextAPI('GET', `Job Card/${jc.name}`, null, username, password)
                .then(detail => ({ success: true, data: detail.data }))
                .catch(error => {
                    console.error(`[Error] Failed to fetch Job Card ${jc.name}:`, error.message);
                    return { success: false, error: error.message };
                })
        );
        
        const jobCardResults = await Promise.all(jobCardPromises);
        const jobCardsWithDetails = jobCardResults
            .filter(result => result.success && result.data)
            .map(result => result.data);
        
        console.log(`[Fetching Details] Successfully fetched ${jobCardsWithDetails.length}/${result.data.length} Job Cards with full details`);

        if (jobCardsWithDetails.length === 0) {
            return res.json({ 
                success: false, 
                message: `Không thể lấy thông tin chi tiết của Job Card trong Work Order ${workOrder}. Vui lòng kiểm tra quyền API.` 
            });
        }

        // Log summary sau khi có đầy đủ thông tin
        console.log(`[Job Cards With Details] Summary:`, jobCardsWithDetails.map(jc => ({
            name: jc.name,
            operation: jc.operation,
            status: jc.status,
            docstatus: jc.docstatus,
            sequence_id: jc.sequence_id,
            employee_count: (jc.employee || []).length,
            time_logs_count: (jc.time_logs || []).length,
            total_completed_qty: jc.total_completed_qty,
            for_quantity: jc.for_quantity
        })));

        // Sử dụng jobCardsWithDetails thay vì result.data
        const resultData = jobCardsWithDetails;

        if (resultData && resultData.length > 0) {
            // KHÔNG CẦN kiểm tra Employee - Tìm trực tiếp Job Card kế tiếp chưa hoàn thành
            // Logic: Tìm tất cả Job Card chưa hoàn thành trong Work Order, sắp xếp theo sequence_id
            // Tự động gán employee vào Job Card kế tiếp nếu chưa có
            
            console.log(`[Job Card Search] Work Order: ${workOrder}, Employee: ${employeeId}`);
            console.log(`[Job Card Search] Searching for next incomplete Job Card (no employee check required)...`);
            
            // Log TẤT CẢ Job Card trước khi filter để xem trạng thái thực tế
            console.log(`[All Job Cards Before Filter] Total: ${resultData.length}`);
            resultData.forEach((jc, idx) => {
                console.log(`[Job Card ${idx + 1}] ${jc.name}:`, {
                    operation: jc.operation,
                    status: jc.status || 'NULL',
                    docstatus: jc.docstatus,
                    sequence_id: jc.sequence_id,
                    total_completed_qty: jc.total_completed_qty,
                    for_quantity: jc.for_quantity,
                    employee_count: (jc.employee || []).length
                });
            });
            
            // Tìm tất cả Job Card chưa hoàn thành (KHÔNG cần kiểm tra employee)
            const allIncompleteJobCards = resultData.filter(jc => {
                // Logic: Job Card chưa hoàn thành = docstatus = 0 (Draft) và chưa bị hủy
                // Chấp nhận TẤT CẢ status nếu docstatus = 0, trừ Completed và Cancelled
                const isDraft = jc.docstatus === 0;
                const isNotCompleted = jc.status !== 'Completed';
                const isNotCancelled = jc.status !== 'Cancelled' && jc.docstatus !== 2;
                    
                const isIncomplete = isDraft && isNotCompleted && isNotCancelled;
                    
                console.log(`[Filter Check] Job Card ${jc.name}:`, {
                    docstatus: jc.docstatus,
                    status: jc.status || 'NULL',
                    isDraft: isDraft,
                    isNotCompleted: isNotCompleted,
                    isNotCancelled: isNotCancelled,
                    isIncomplete: isIncomplete,
                    reason: !isIncomplete ? 
                        (!isDraft ? `docstatus=${jc.docstatus} (not Draft, must be 0)` : 
                         !isNotCompleted ? 'status=Completed' :
                         !isNotCancelled ? 'status=Cancelled or docstatus=2' : 'unknown') : 'PASSED - Will include'
                });
                    
                return isIncomplete;
            });

                console.log(`[Filter] Total Job Cards: ${resultData.length}, Incomplete: ${allIncompleteJobCards.length}`);
                if (allIncompleteJobCards.length > 0) {
                    console.log(`[Filter] Incomplete Job Cards:`, allIncompleteJobCards.map(jc => ({
                        name: jc.name,
                        operation: jc.operation,
                        status: jc.status,
                        docstatus: jc.docstatus,
                        sequence_id: jc.sequence_id
                    })));
                }

                if (allIncompleteJobCards.length === 0) {
                    // Log chi tiết tất cả Job Card để debug
                    const statusBreakdown = {
                        completed: resultData.filter(jc => jc.status === 'Completed' || jc.docstatus === 1).length,
                        cancelled: resultData.filter(jc => jc.docstatus === 2 || jc.status === 'Cancelled').length,
                        draft: resultData.filter(jc => jc.docstatus === 0 && jc.status === 'Draft').length,
                        workInProgress: resultData.filter(jc => jc.docstatus === 0 && jc.status === 'Work In Progress').length,
                        other: resultData.filter(jc => {
                            const status = jc.status || 'Unknown';
                            const docstatus = jc.docstatus;
                            return !(status === 'Completed' || docstatus === 1 || 
                                    docstatus === 2 || status === 'Cancelled' ||
                                    status === 'Draft' || status === 'Work In Progress');
                        }).length
                    };
                    
                    console.log(`[Status Breakdown]`, statusBreakdown);
                    console.log(`[All Job Cards Details]`, resultData.map(jc => ({
                        name: jc.name,
                        operation: jc.operation,
                        status: jc.status,
                        docstatus: jc.docstatus,
                        total_completed_qty: jc.total_completed_qty,
                        for_quantity: jc.for_quantity,
                        sequence_id: jc.sequence_id
                    })));
                    
                    return res.json({ 
                        success: false, 
                        message: `Tất cả Job Card trong Work Order ${workOrder} đã hoàn thành hoặc bị hủy. Không còn công đoạn nào cần thực hiện.\n\nChi tiết: ${statusBreakdown.completed} đã hoàn thành, ${statusBreakdown.cancelled} bị hủy, ${statusBreakdown.draft} Draft, ${statusBreakdown.workInProgress} Work In Progress, ${statusBreakdown.other} trạng thái khác.\n\nVui lòng kiểm tra log trên server để xem chi tiết từng Job Card.` 
                    });
                }

                // Sắp xếp theo sequence_id và chọn Job Card kế tiếp
                allIncompleteJobCards.sort((a, b) => {
                    const seqA = a.sequence_id || 999;
                    const seqB = b.sequence_id || 999;
                    return seqA - seqB;
                });

                const nextJobCard = allIncompleteJobCards[0];
                
                // Kiểm tra xem employee đã có trong Job Card chưa
                const employees = nextJobCard.employee || [];
                const employeeExists = employees.some(emp => emp.employee === employeeId);
                
                if (!employeeExists) {
                    // Tự động gán employee vào Job Card
                    console.log(`[Auto Assign] Auto-assigning employee ${employeeId} to Job Card ${nextJobCard.name}`);
                    
                    try {
                        // Cập nhật Job Card để thêm employee vào child table
                        const updatedEmployees = [
                            ...employees,
                            { employee: employeeId }
                        ];
                        
                        const updateData = {
                            employee: updatedEmployees
                        };
                        
                        // Update Job Card với employee mới
                        await erpnextAPI('PUT', `Job Card/${nextJobCard.name}`, updateData, username, password);
                        
                        // Lấy lại Job Card sau khi update
                        const updatedJobCard = await erpnextAPI('GET', `Job Card/${nextJobCard.name}`, null, username, password);
                        nextJobCard.employee = updatedJobCard.data?.employee || updatedEmployees;
                        
                        console.log(`[Auto Assign] Successfully assigned employee ${employeeId} to Job Card ${nextJobCard.name}`);
                    } catch (error) {
                        console.error(`[Auto Assign] Error assigning employee:`, error);
                        // Tiếp tục với Job Card hiện tại dù có lỗi khi gán
                    }
                }
                
                // Trả về Job Card kế tiếp (đã tự động gán employee nếu cần)
                console.log(`[Job Card Search] Returning next incomplete Job Card: ${nextJobCard.name}, Operation: ${nextJobCard.operation}`);
                
                res.json({
                    success: true,
                    jobCard: nextJobCard,
                    message: `Đã tự động tìm thấy công đoạn kế tiếp: ${nextJobCard.operation || 'N/A'} (Job Card: ${nextJobCard.name})${!employeeExists ? ' - Đã tự động gán bạn vào Job Card này' : ''}`,
                    totalIncomplete: allIncompleteJobCards.length,
                    isNextOperation: true,
                    autoAssigned: !employeeExists
                });
                
                return; // Return early - đã tìm thấy và trả về Job Card kế tiếp
        } else {
            res.json({ 
                success: false, 
                message: `Không tìm thấy Job Card nào trong Work Order ${workOrder}. Vui lòng kiểm tra lại Work Order.` 
            });
        }
    } catch (error) {
        console.error('Get Job Card by Work Order error:', error);
        res.status(500).json({
            success: false,
            message: error.message || 'Lỗi khi lấy thông tin Job Card'
        });
    }
});

// Get Job Card by Work Order + Operation
app.post('/api/erpnext/job-card-by-wo', requireLogin, async (req, res) => {
    try {
        const { workOrder, operation } = req.body;
        if (!workOrder || !operation) {
            return res.json({ success: false, message: 'Vui lòng cung cấp Work Order và Operation' });
        }

        const username = req.session.user?.erpnext_username || null;
        const password = req.session.user?.erpnext_password || null;

        // Search for Job Card by Work Order and Operation
        const baseUrl = new URL(config.ERPNEXT_URL);
        const isHttps = baseUrl.protocol === 'https:';
        const httpModule = isHttps ? https : http;
        
        // Encode doctype name and build search params
        const doctypeName = encodeURIComponent('Job Card');
        const filters = JSON.stringify([["work_order","=",workOrder],["operation","=",operation]]);
        const path = `/api/resource/${doctypeName}?filters=${encodeURIComponent(filters)}&limit_page_length=1`;
        
        let authHeader = '';
        if (config.ERPNEXT_API_KEY && config.ERPNEXT_API_SECRET && 
            config.ERPNEXT_API_KEY.trim() !== '' && config.ERPNEXT_API_SECRET.trim() !== '') {
            authHeader = `token ${config.ERPNEXT_API_KEY}:${config.ERPNEXT_API_SECRET}`;
        } else if (username && password) {
            authHeader = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
        } else {
            throw new Error('ERPNext authentication credentials not configured. Please set ERPNEXT_API_KEY and ERPNEXT_API_SECRET in .env file.');
        }

        const result = await new Promise((resolve, reject) => {
            const options = {
                hostname: baseUrl.hostname,
                port: baseUrl.port || (isHttps ? 443 : 80),
                path: path,
                method: 'GET',
                headers: {
                    'Authorization': authHeader,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            };

            const req = httpModule.request(options, (res) => {
                let responseData = '';
                res.on('data', (chunk) => { responseData += chunk; });
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(responseData));
                    } catch (error) {
                        reject(error);
                    }
                });
            });

            req.on('error', (error) => {
                console.error('ERPNext API Request Error:', error);
                if (error.code === 'ECONNREFUSED') {
                    reject(new Error(`Không thể kết nối đến ERPNext tại ${config.ERPNEXT_URL}. Vui lòng kiểm tra: 1) ERPNext có đang chạy không? 2) URL và port có đúng không? 3) Firewall có chặn không?`));
                } else if (error.code === 'ENOTFOUND') {
                    reject(new Error(`Không tìm thấy server ERPNext tại ${config.ERPNEXT_URL}. Vui lòng kiểm tra URL.`));
                } else if (error.code === 'ETIMEDOUT') {
                    reject(new Error(`Kết nối đến ERPNext bị timeout tại ${config.ERPNEXT_URL}. Vui lòng kiểm tra kết nối mạng.`));
                } else {
                    reject(new Error(`Lỗi kết nối ERPNext: ${error.message}. URL: ${config.ERPNEXT_URL}`));
                }
            });
            
            req.setTimeout(10000, () => {
                req.destroy();
                reject(new Error(`Kết nối đến ERPNext timeout sau 10 giây tại ${config.ERPNEXT_URL}`));
            });
            
            req.end();
        });

        if (result.data && result.data.length > 0) {
            res.json({
                success: true,
                jobCard: result.data[0]
            });
        } else {
            res.json({ success: false, message: 'Không tìm thấy Job Card với Work Order và Operation này' });
        }
    } catch (error) {
        console.error('Get Job Card by WO error:', error);
        res.status(500).json({
            success: false,
            message: error.message || 'Lỗi khi lấy thông tin Job Card'
        });
    }
});

// Update Job Card (Draft only - no submit)
app.post('/api/erpnext/update-job-card', requireLogin, async (req, res) => {
    try {
        const { jobCardId, completedQty, scrapQty, scrapReason, notes, employee, supportEmployees } = req.body;

        if (!jobCardId) {
            return res.json({ success: false, message: 'Vui lòng cung cấp Job Card ID' });
        }

        const username = req.session.user?.erpnext_username || null;
        const password = req.session.user?.erpnext_password || null;

        // First, get current Job Card
        const currentJobCard = await erpnextAPI('GET', `Job Card/${jobCardId}`, null, username, password);

        if (!currentJobCard.data) {
            return res.json({ success: false, message: 'Không tìm thấy Job Card' });
        }

        // Check Job Card status - cannot update if cancelled or submitted
        const docstatus = currentJobCard.data.docstatus || 0;
        const status = currentJobCard.data.status || '';
        
        if (docstatus === 2) {
            return res.json({ 
                success: false, 
                message: 'Không thể cập nhật Job Card đã bị hủy (Cancelled). Vui lòng liên hệ quản lý.' 
            });
        }
        
        if (docstatus === 1) {
            return res.json({ 
                success: false, 
                message: 'Không thể cập nhật Job Card đã được submit. Job Card này chỉ có thể được cập nhật khi ở trạng thái Draft hoặc Work In Progress.' 
            });
        }
        
        // Check if status allows updates
        if (status === 'Cancelled' || status === 'Completed') {
            return res.json({ 
                success: false, 
                message: `Không thể cập nhật Job Card ở trạng thái "${status}". Chỉ có thể cập nhật khi Job Card ở trạng thái Draft hoặc Work In Progress.` 
            });
        }

        // IMPORTANT: ERPNext calculates total_completed_qty and total_scrap_qty from time_logs child table
        // DO NOT update total_completed_qty and total_scrap_qty directly
        // Only update time_logs, and ERPNext will automatically calculate the totals

        // Validate employee exists in ERPNext
        if (employee) {
            try {
                const empCheck = await erpnextAPI('GET', `Employee/${employee}`, null, username, password);
                if (!empCheck.data) {
                    console.warn(`[WARNING] Employee ${employee} not found in ERPNext, but continuing...`);
                }
            } catch (error) {
                console.warn(`[WARNING] Could not verify Employee ${employee}:`, error.message);
                // Continue anyway, ERPNext will validate
            }
        }

        // Prepare update data - DO NOT include total_completed_qty or total_scrap_qty
        const updateData = {};

        // Update time_logs child table - ERPNext calculates totals from this
        const currentTimeLogs = currentJobCard.data.time_logs || [];
        const currentTimeLog = currentTimeLogs.find(log => log.employee === employee && log.from_time) || null;
        
        const completedQtyValue = parseFloat(completedQty) || 0;
        const scrapQtyValue = parseFloat(scrapQty) || 0;
        const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
        
        if (currentTimeLog) {
            // Update existing time log - add to existing completed_qty and scrap_qty
            updateData.time_logs = currentTimeLogs.map(log => {
                if (log.employee === employee && log.from_time) {
                    const updatedLog = {
                        ...log,
                        completed_qty: (parseFloat(log.completed_qty) || 0) + completedQtyValue
                    };
                    // Add scrap_qty if the field exists in time_logs
                    if (scrapQtyValue > 0) {
                        updatedLog.scrap_qty = (parseFloat(log.scrap_qty) || 0) + scrapQtyValue;
                    }
                    return updatedLog;
                }
                return log;
            });
        } else if (employee && (completedQtyValue > 0 || scrapQtyValue > 0)) {
            // Create new time log entry
            const newTimeLog = {
                employee: employee,
                from_time: now,
                time_in_mins: 0,
                completed_qty: completedQtyValue
            };
            // Add scrap_qty if > 0
            if (scrapQtyValue > 0) {
                newTimeLog.scrap_qty = scrapQtyValue;
            }
            updateData.time_logs = [
                ...currentTimeLogs,
                newTimeLog
            ];
        }

        // Update employee child table (if needed for tracking)
        if (employee) {
            const currentEmployees = currentJobCard.data.employee || [];
            const employeeExists = currentEmployees.some(emp => emp.employee === employee);
            
            if (!employeeExists) {
                // Add new employee to the list
                updateData.employee = [
                    ...currentEmployees,
                    { 
                        employee: employee,
                        completed_qty: completedQtyValue,
                        time_in_mins: 0
                    }
                ];
            } else {
                // Update existing employee's completed_qty
                updateData.employee = currentEmployees.map(emp => {
                    if (emp.employee === employee) {
                        return {
                            ...emp,
                            completed_qty: (parseFloat(emp.completed_qty) || 0) + completedQtyValue
                        };
                    }
                    return emp;
                });
            }
        }

        // IMPORTANT: Do NOT send custom fields via API if they might be child tables
        // ERPNext will try to process them as child tables and fail with TypeError
        // We'll only update standard fields: total_completed_qty, total_scrap_qty, employee
        // Custom fields (custom_lý_do_lỗi, notes, support_employees) will need to be configured
        // properly in ERPNext as Data/Small Text fields (NOT child tables)
        
        // Save custom fields if they exist
        if (scrapReason && scrapReason.trim()) {
            updateData.custom_lý_do_lỗi = scrapReason.trim();
            console.log('[INFO] Setting custom_lý_do_lỗi:', scrapReason.trim());
        }
        
        // Log other custom data for reference
        console.log('[INFO] Custom data:', {
            custom_lý_do_lỗi: scrapReason,
            notes: notes,
            supportEmployees: supportEmployees
        });
        
        // Note: To save other custom data, ensure custom fields are created in ERPNext as:
        // - custom_lý_do_lỗi: Data type (NOT child table) - Đã được thêm
        // - custom_notes: Small Text type (NOT child table)  
        // - custom_support_employees: Data type (NOT child table)
        // Then uncomment the code below:
        /*
        if (notes && notes.trim()) {
            updateData.custom_notes = notes.trim();
        }
        if (supportEmployees && supportEmployees.length > 0) {
            updateData.custom_support_employees = supportEmployees.join(', ');
        }
        */

        // Log update data for debugging
        console.log(`[Update Job Card] ${jobCardId}:`, {
            updateData: JSON.stringify(updateData, null, 2),
            employee: employee,
            completedQty: completedQty,
            scrapQty: scrapQty,
            completedQtyValue: completedQtyValue,
            scrapQtyValue: scrapQtyValue
        });

        // Update Job Card (will remain in Draft status)
        const updateResult = await erpnextAPI('PUT', `Job Card/${jobCardId}`, updateData, username, password);

        // Log the update
        console.log(`[ERPNext] Job Card ${jobCardId} updated by ${employee}: +${completedQty} completed, +${scrapQty} scrap`);

        res.json({
            success: true,
            message: 'Job Card đã được cập nhật thành công (Draft)',
            jobCard: updateResult.data
        });
    } catch (error) {
        console.error('[Update Job Card Error]', {
            error: error.message,
            stack: error.stack,
            jobCardId: req.body.jobCardId,
            updateData: {
                completedQty: req.body.completedQty,
                scrapQty: req.body.scrapQty,
                employee: req.body.employee
            }
        });
        
        // Provide more helpful error message
        let errorMessage = error.message || 'Lỗi khi cập nhật Job Card';
        
        // Check for cancelled document error
        if (errorMessage.includes('Không thể chỉnh sửa tài liệu hủy') || 
            errorMessage.includes('Cannot edit cancelled document') ||
            errorMessage.includes('cancelled document') ||
            errorMessage.includes('hủy')) {
            errorMessage = 'Không thể cập nhật Job Card đã bị hủy (Cancelled). Vui lòng liên hệ quản lý để kiểm tra trạng thái Job Card.';
        }
        
        // Check for submitted document error
        if (errorMessage.includes('submitted') || errorMessage.includes('đã được submit')) {
            errorMessage = 'Không thể cập nhật Job Card đã được submit. Job Card này chỉ có thể được cập nhật khi ở trạng thái Draft hoặc Work In Progress.';
        }
        
        // If it's a 500 error about custom fields, provide specific guidance
        if (errorMessage.includes('custom_')) {
            errorMessage += '\n\nVui lòng tạo các Custom Fields sau trong ERPNext:\n' +
                '1. Vào Job Card doctype\n' +
                '2. Thêm Custom Fields:\n' +
                '   - custom_lý_do_lỗi (Data type)\n' +
                '   - custom_notes (Small Text type)\n' +
                '   - custom_support_employees (Data type)';
        }
        
        res.status(500).json({
            success: false,
            message: errorMessage
        });
    }
});

// Get Employees list
app.get('/api/erpnext/employees', requireLogin, async (req, res) => {
    try {
        const username = req.session.user?.erpnext_username || null;
        const password = req.session.user?.erpnext_password || null;

        // Search for active employees
        const baseUrl = new URL(config.ERPNEXT_URL);
        const isHttps = baseUrl.protocol === 'https:';
        const httpModule = isHttps ? https : http;
        
        const filters = JSON.stringify([["status","=","Active"]]);
        const fields = JSON.stringify(["name","employee_name","employee_number"]);
        const path = `/api/resource/Employee?filters=${encodeURIComponent(filters)}&fields=${encodeURIComponent(fields)}&limit_page_length=1000`;
        
        let authHeader = '';
        if (config.ERPNEXT_API_KEY && config.ERPNEXT_API_SECRET && 
            config.ERPNEXT_API_KEY.trim() !== '' && config.ERPNEXT_API_SECRET.trim() !== '') {
            authHeader = `token ${config.ERPNEXT_API_KEY}:${config.ERPNEXT_API_SECRET}`;
        } else if (username && password) {
            authHeader = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
        } else {
            throw new Error('ERPNext authentication credentials not configured. Please set ERPNEXT_API_KEY and ERPNEXT_API_SECRET in .env file.');
        }

        const result = await new Promise((resolve, reject) => {
            const options = {
                hostname: baseUrl.hostname,
                port: baseUrl.port || (isHttps ? 443 : 80),
                path: path,
                method: 'GET',
                headers: {
                    'Authorization': authHeader,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            };

            const req = httpModule.request(options, (res) => {
                let responseData = '';
                res.on('data', (chunk) => { responseData += chunk; });
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(responseData));
                    } catch (error) {
                        reject(error);
                    }
                });
            });

            req.on('error', (error) => {
                console.error('ERPNext API Request Error:', error);
                if (error.code === 'ECONNREFUSED') {
                    reject(new Error(`Không thể kết nối đến ERPNext tại ${config.ERPNEXT_URL}. Vui lòng kiểm tra: 1) ERPNext có đang chạy không? 2) URL và port có đúng không? 3) Firewall có chặn không?`));
                } else if (error.code === 'ENOTFOUND') {
                    reject(new Error(`Không tìm thấy server ERPNext tại ${config.ERPNEXT_URL}. Vui lòng kiểm tra URL.`));
                } else if (error.code === 'ETIMEDOUT') {
                    reject(new Error(`Kết nối đến ERPNext bị timeout tại ${config.ERPNEXT_URL}. Vui lòng kiểm tra kết nối mạng.`));
                } else {
                    reject(new Error(`Lỗi kết nối ERPNext: ${error.message}. URL: ${config.ERPNEXT_URL}`));
                }
            });
            
            req.setTimeout(10000, () => {
                req.destroy();
                reject(new Error(`Kết nối đến ERPNext timeout sau 10 giây tại ${config.ERPNEXT_URL}`));
            });
            
            req.end();
        });

        if (result.data) {
            res.json({
                success: true,
                employees: result.data
            });
        } else {
            res.json({ success: false, message: 'Không thể lấy danh sách nhân viên' });
        }
    } catch (error) {
        console.error('Get Employees error:', error);
        res.status(500).json({
            success: false,
            message: error.message || 'Lỗi khi lấy danh sách nhân viên'
        });
    }
});

// Get Work Orders with High Priority
app.get('/api/erpnext/work-orders-high-priority', requireLogin, async (req, res) => {
    try {
        // Chỉ cho phép production_worker truy cập
        if (req.session.user.role !== 'production_worker') {
            return res.status(403).json({
                success: false,
                message: 'Chỉ nhân viên sản xuất mới có quyền truy cập'
            });
        }

        const username = req.session.user?.erpnext_username || null;
        const password = req.session.user?.erpnext_password || null;

        // Search for Work Orders with custom_priority = "High"
        const baseUrl = new URL(config.ERPNEXT_URL);
        const isHttps = baseUrl.protocol === 'https:';
        const httpModule = isHttps ? https : http;
        
        // Lấy Work Orders có custom_priority = "High"
        const filters = JSON.stringify([["custom_priority","=","High"]]);
        const fields = JSON.stringify(["name", "production_item", "item_name", "qty", "status", "custom_priority"]);
        const doctypeName = encodeURIComponent('Work Order');
        const path = `/api/resource/${doctypeName}?filters=${encodeURIComponent(filters)}&fields=${encodeURIComponent(fields)}&limit_page_length=1000`;
        
        console.log(`[High Priority WO] Filtering Work Orders with custom_priority = "High"`);
        console.log(`[High Priority WO] Filter: ${filters}`);
        console.log(`[High Priority WO] Path: ${path}`);
        
        let authHeader = '';
        if (config.ERPNEXT_API_KEY && config.ERPNEXT_API_SECRET && 
            config.ERPNEXT_API_KEY.trim() !== '' && config.ERPNEXT_API_SECRET.trim() !== '') {
            authHeader = `token ${config.ERPNEXT_API_KEY}:${config.ERPNEXT_API_SECRET}`;
        } else if (username && password) {
            authHeader = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
        } else {
            throw new Error('ERPNext authentication credentials not configured. Please set ERPNEXT_API_KEY and ERPNEXT_API_SECRET in .env file.');
        }

        const result = await new Promise((resolve, reject) => {
            const options = {
                hostname: baseUrl.hostname,
                port: baseUrl.port || (isHttps ? 443 : 80),
                path: path,
                method: 'GET',
                headers: {
                    'Authorization': authHeader,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            };

            const req = httpModule.request(options, (res) => {
                let responseData = '';
                res.on('data', (chunk) => { responseData += chunk; });
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(responseData));
                    } catch (error) {
                        reject(error);
                    }
                });
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.setTimeout(10000, () => {
                req.destroy();
                reject(new Error(`Kết nối đến ERPNext timeout sau 10 giây tại ${config.ERPNEXT_URL}`));
            });

            req.end();
        });

        if (result.data && Array.isArray(result.data)) {
            console.log(`[High Priority WO] Found ${result.data.length} Work Orders with custom_priority = "High"`);
            
            // Lấy danh sách tên sản phẩm (item_name) từ các Work Orders
            // Lọc thêm để đảm bảo custom_priority thực sự là "High" (phòng trường hợp filter không hoạt động đúng)
            const products = result.data
                .filter(wo => {
                    // Đảm bảo có item_name và custom_priority = "High"
                    const hasItemName = wo.item_name;
                    const hasHighPriority = wo.custom_priority === "High" || wo.custom_priority === "high";
                    return hasItemName && hasHighPriority;
                })
                .map(wo => ({
                    workOrder: wo.name,
                    itemName: wo.item_name,
                    productionItem: wo.production_item,
                    qty: wo.qty || 0,
                    status: wo.status || 'Unknown',
                    customPriority: wo.custom_priority || 'N/A'
                }));

            console.log(`[High Priority WO] Returning ${products.length} products after filtering`);

            res.json({
                success: true,
                products: products,
                count: products.length
            });
        } else {
            res.json({
                success: true,
                products: [],
                count: 0
            });
        }
    } catch (error) {
        console.error('Get High Priority Work Orders error:', error);
        res.status(500).json({
            success: false,
            message: error.message || 'Lỗi khi lấy danh sách Work Orders có độ ưu tiên cao'
        });
    }
});

// Test ERPNext Connection
app.get('/api/erpnext/test-connection', requireLogin, async (req, res) => {
    try {
        const erpnextUrl = config.ERPNEXT_URL;
        const apiKey = config.ERPNEXT_API_KEY;
        const apiSecret = config.ERPNEXT_API_SECRET;

        // Kiểm tra cấu hình
        if (!erpnextUrl || !apiKey || !apiSecret || 
            apiKey.trim() === '' || apiSecret.trim() === '') {
            return res.json({
                success: false,
                message: 'ERPNext chưa được cấu hình. Vui lòng kiểm tra file .env',
                config: {
                    hasUrl: !!erpnextUrl,
                    hasApiKey: !!(apiKey && apiKey.trim() !== ''),
                    hasApiSecret: !!(apiSecret && apiSecret.trim() !== ''),
                    url: erpnextUrl || 'Chưa cấu hình'
                }
            });
        }

        // Thử kết nối đến ERPNext
        const baseUrl = new URL(erpnextUrl);
        const isHttps = baseUrl.protocol === 'https:';
        const httpModule = isHttps ? https : http;
        
        // Test với endpoint đơn giản
        const testPath = '/api/method/frappe.auth.get_logged_user';
        const authHeader = `token ${apiKey}:${apiSecret}`;

        const result = await new Promise((resolve, reject) => {
            const options = {
                hostname: baseUrl.hostname,
                port: baseUrl.port || (isHttps ? 443 : 80),
                path: testPath,
                method: 'GET',
                headers: {
                    'Authorization': authHeader,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                timeout: 5000
            };

            const req = httpModule.request(options, (res) => {
                let responseData = '';
                res.on('data', (chunk) => { responseData += chunk; });
                res.on('end', () => {
                    resolve({
                        statusCode: res.statusCode,
                        data: responseData
                    });
                });
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.setTimeout(5000, () => {
                req.destroy();
                reject(new Error('Connection timeout'));
            });

            req.end();
        });

        // Kiểm tra response
        let responseData;
        try {
            responseData = JSON.parse(result.data);
        } catch (e) {
            responseData = result.data;
        }

        // Kiểm tra nếu có lỗi 403 hoặc 401
        if (result.statusCode === 403) {
            return res.status(403).json({
                success: false,
                message: 'API Key không có quyền truy cập (403 Forbidden). Vui lòng kiểm tra quyền của API Key trong ERPNext.',
                details: {
                    url: erpnextUrl,
                    statusCode: result.statusCode,
                    troubleshooting: {
                        step1: 'Đăng nhập ERPNext với tài khoản Administrator',
                        step2: 'Vào Settings > Integrations > API Keys',
                        step3: 'Kiểm tra API Key có còn active không',
                        step4: 'Kiểm tra User được gán cho API Key có quyền Read Job Card không',
                        step5: 'Kiểm tra Role của User có quyền truy cập Job Card không',
                        step6: 'Xem file ERPNext_API_KEY_SETUP.md để biết chi tiết'
                    }
                }
            });
        } else if (result.statusCode === 401) {
            return res.status(401).json({
                success: false,
                message: 'API Key/Secret không đúng hoặc đã hết hạn (401 Unauthorized).',
                details: {
                    url: erpnextUrl,
                    statusCode: result.statusCode
                }
            });
        }

        res.json({
            success: true,
            message: 'Kết nối ERPNext thành công!',
            details: {
                url: erpnextUrl,
                statusCode: result.statusCode,
                hostname: baseUrl.hostname,
                port: baseUrl.port || (isHttps ? 443 : 80),
                response: responseData
            }
        });

    } catch (error) {
        console.error('Test ERPNext connection error:', error);
        
        let message = 'Không thể kết nối đến ERPNext.';
        if (error.code === 'ECONNREFUSED') {
            message = `Không thể kết nối đến ERPNext tại ${config.ERPNEXT_URL}. Vui lòng kiểm tra:\n1. ERPNext có đang chạy không?\n2. URL và port có đúng không? (Bạn truy cập ERPNext qua URL nào?)\n3. Firewall có chặn không?`;
        } else if (error.code === 'ENOTFOUND') {
            message = `Không tìm thấy server ERPNext tại ${config.ERPNEXT_URL}. Vui lòng kiểm tra URL.`;
        } else if (error.code === 'ETIMEDOUT' || error.message.includes('timeout')) {
            message = `Kết nối đến ERPNext bị timeout tại ${config.ERPNEXT_URL}. Vui lòng kiểm tra kết nối mạng.`;
        } else {
            message = `Lỗi: ${error.message}`;
        }

        res.status(500).json({
            success: false,
            message: message,
            error: {
                code: error.code,
                message: error.message,
                url: config.ERPNEXT_URL
            },
            troubleshooting: {
                step1: 'Kiểm tra ERPNext có đang chạy: Mở trình duyệt và truy cập URL ERPNext',
                step2: 'Kiểm tra file .env có đúng URL không (chỉ base URL, không có /app/home)',
                step3: 'Kiểm tra port có đúng không (nếu truy cập qua http://localhost:8080/app/home thì port là 8080)',
                step4: 'Restart server sau khi thay đổi .env'
            }
        });
    }
});

// ==================== End ERPNext API Endpoints ====================
