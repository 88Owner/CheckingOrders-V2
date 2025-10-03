// ...existing code...
const express = require('express');
const multer = require('multer');
const XLSX = require('xlsx');
const path = require('path');
const Order = require('../models/Order');
const ComboData = require('../models/ComboData');
const MasterData = require('../models/MasterData');

const router = express.Router();

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

// Middleware kiểm tra role checker
function requireChecker(req, res, next) {
    // Dùng JWT cho checker
    const auth = req.headers.authorization || '';
    // console.log('🔑 [REQUIRE-CHECKER] Authorization header:', auth);
    
    const token = auth.startsWith('Bearer ') ? auth.substring(7) : null;
    // console.log('🔑 [REQUIRE-CHECKER] Token extracted:', token ? 'Có token' : 'Không có token');
    
    if (!token) {
        // console.log('❌ [REQUIRE-CHECKER] Thiếu token');
        return res.status(401).json({ success: false, message: 'Thiếu token' });
    }
    
    try {
        const decoded = require('jsonwebtoken').verify(token, process.env.SESSION_SECRET || 'secret');
        // console.log('🔑 [REQUIRE-CHECKER] Token decoded:', { username: decoded.username, role: decoded.role });
        
        if (decoded.role !== 'checker') {
            // console.log('❌ [REQUIRE-CHECKER] Role không đúng:', decoded.role);
            return res.status(403).send('Bạn không có quyền truy cập');
        }
        
        req.authUser = decoded;
        next();
    } catch (e) {
        // console.log('❌ [REQUIRE-CHECKER] Token không hợp lệ:', e.message);
        return res.status(401).json({ success: false, message: 'Token không hợp lệ' });
    }
}

// API upload file xlsx cho checker
router.post('/api/checker/upload', requireChecker, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Vui lòng chọn file Excel' });
        }

        // Đọc file Excel
        const workbook = XLSX.readFile(req.file.path);
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const data = XLSX.utils.sheet_to_json(sheet, { header: 1 });

        // 1. Kiểm tra orders hiện tại
        const today = new Date();
        today.setHours(0,0,0,0);
        const orders = await Order.find({});
        let needBackup = false;
        if (orders.length > 0) {
            // Nếu có đơn hàng, kiểm tra ngày import
            const firstOrderDate = orders[0].importDate ? new Date(orders[0].importDate) : orders[0].createdAt;
            firstOrderDate.setHours(0,0,0,0);
            if (firstOrderDate.getTime() !== today.getTime()) {
                needBackup = true;
            }
        }
        if (needBackup) {
            // Backup toàn bộ sang DataOrder
            const DataOrder = require('../models/DataOrder');
            const backupDocs = orders.map(o => ({
                ...o.toObject(),
                archivedAt: new Date()
            }));
            if (backupDocs.length > 0) await DataOrder.insertMany(backupDocs);
            // Xóa khỏi orders
            await Order.deleteMany({});
        }

        // 2. Chuẩn hóa dữ liệu mới
        // Tối ưu: load toàn bộ đơn hàng cũ vào RAM
        const oldOrders = await Order.find({});
        const oldMap = new Map();
        for (const o of oldOrders) {
            oldMap.set(o.maDonHang + '|' + o.maHang, o);
        }

        // 2.1. Nạp ComboData để chuẩn hóa mã combo => mã base
        const comboDocs = await ComboData.find({});
        const comboByCode = new Map(); // key: comboCode, value: combo doc
        for (const c of comboDocs) {
            if (c && typeof c.comboCode === 'string' && c.comboCode.trim()) {
                comboByCode.set(c.comboCode.trim(), c);
            }
        }
        let imported = 0, updated = 0, unchanged = 0;
        const ops = [];
        for (let i = 2; i < data.length; i++) {
            const row = data[i];
            if (!row || row.length < 6) continue;
            const [stt, maDongGoi, maVanDon, maDonHang, maHang, soLuong] = row;
            if (!stt || !maDongGoi || !maVanDon || !maDonHang || !maHang || !soLuong) continue;

            // Giữ nguyên mã combo trong database, chỉ nhân số lượng
            let normalizedMaHang = String(maHang).trim();
            let normalizedSoLuong = Number(soLuong);
            const combo = comboByCode.get(normalizedMaHang);
            if (combo) {
                const factor = Number(combo.soLuong) || 1;
                normalizedSoLuong = normalizedSoLuong * factor;
                // Giữ nguyên mã combo, chỉ nhân số lượng
            }

            const key = String(maDonHang) + '|' + String(normalizedMaHang);
            const exist = oldMap.get(key);
            if (!exist) {
                ops.push({
                    insertOne: {
                        document: {
                            stt: Number(stt),
                            maDongGoi: String(maDongGoi),
                            maVanDon: String(maVanDon),
                            maDonHang: String(maDonHang),
                            maHang: String(normalizedMaHang),
                            soLuong: Number(normalizedSoLuong),
                            importDate: today,
                            createdBy: req.authUser.username
                        }
                    }
                });
                imported++;
            } else {
                // Đã có đơn hàng -> Kiểm tra logic cập nhật
                if (exist.verified === true) {
                    // Đơn đã verified = true -> Không được cập nhật
                    unchanged++;
                } else {
                    // Đơn chưa verified = false -> Kiểm tra có thay đổi không
                    let changed = false;
                    if (exist.stt !== Number(stt)) changed = true;
                    if (exist.maDongGoi !== String(maDongGoi)) changed = true;
                    if (exist.maVanDon !== String(maVanDon)) changed = true;
                    if (exist.soLuong !== Number(normalizedSoLuong)) changed = true;
                    if (changed) {
                        ops.push({
                            updateOne: {
                                filter: { _id: exist._id },
                                update: {
                                    $set: {
                                        stt: Number(stt),
                                        maDongGoi: String(maDongGoi),
                                        maVanDon: String(maVanDon),
                                        soLuong: Number(normalizedSoLuong),
                                        importDate: today,
                                        createdBy: req.authUser.username
                                    }
                                }
                            }
                        });
                        updated++;
                    } else {
                        unchanged++;
                    }
                }
            }
        }
        if (ops.length > 0) {
            await Order.bulkWrite(ops);
        }
        res.json({ success: true, message: `Đã import ${imported} đơn mới, cập nhật ${updated}, giữ nguyên ${unchanged}.` });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi import file: ' + error.message });
    }
});

// API fix ComboData collection (xóa index cũ, tạo index mới)
router.post('/api/checker/fix-combodata', requireChecker, async (req, res) => {
    try {
        console.log('🔧 Bắt đầu fix ComboData collection...');
        
        // 1. Xóa tất cả index cũ
        try {
            const indexes = await ComboData.collection.getIndexes();
            console.log('📋 Current indexes:', indexes);
            
            // Convert to array if needed
            const indexArray = Array.isArray(indexes) ? indexes : Object.values(indexes);
            
            for (const index of indexArray) {
                if (index.name && index.name !== '_id_') {
                    try {
                        await ComboData.collection.dropIndex(index.name);
                        console.log(`✅ Đã xóa index: ${index.name}`);
                    } catch (e) {
                        console.log(`⚠️ Không thể xóa index ${index.name}:`, e.message);
                    }
                }
            }
        } catch (e) {
            console.log('⚠️ Lỗi khi xóa index cũ:', e.message);
        }
        
        // 2. Tạo index mới cho comboCode
        try {
            await ComboData.collection.createIndex({ comboCode: 1 }, { unique: true, name: 'comboCode_1' });
            console.log('✅ Đã tạo index comboCode_1');
        } catch (e) {
            console.log('⚠️ Lỗi khi tạo index comboCode:', e.message);
        }
        
        // 3. Tạo index cho maHang (đã có trong schema)
        try {
            await ComboData.collection.createIndex({ maHang: 1 }, { name: 'maHang_1' });
            console.log('✅ Đã tạo index maHang_1');
        } catch (e) {
            console.log('⚠️ Lỗi khi tạo index maHang:', e.message);
        }
        
        // 4. Kiểm tra indexes cuối cùng
        const finalIndexes = await ComboData.collection.getIndexes();
        console.log('📋 Final indexes:', finalIndexes);
        
        // Convert indexes to array if needed
        const indexNames = Array.isArray(finalIndexes) 
            ? finalIndexes.map(idx => idx.name)
            : Object.keys(finalIndexes).map(key => finalIndexes[key].name || key);
        
        res.json({ 
            success: true, 
            message: 'Đã fix ComboData collection thành công. Bây giờ có thể upload file.',
            indexes: indexNames
        });
        
    } catch (error) {
        console.error('❌ Lỗi fix ComboData:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Lỗi fix ComboData: ' + error.message 
        });
    }
});

// API upload ComboData
router.post('/api/checker/upload-combodata', requireChecker, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Vui lòng chọn file Excel ComboData' });
        }

        // Đọc file Excel
        const workbook = XLSX.readFile(req.file.path);
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const data = XLSX.utils.sheet_to_json(sheet, { header: 1 });

        // 1. Load ComboData cũ để so sánh
        const oldComboData = await ComboData.find({});
        const oldComboMap = new Map();
        for (const c of oldComboData) {
            if (c && c.comboCode) {
                oldComboMap.set(c.comboCode, c);
            }
        }

        let imported = 0, updated = 0, unchanged = 0;
        const ops = [];
        
        // 2. Xử lý dữ liệu từ dòng 1 (có thể có header ở dòng 0)
        for (let i = 0; i < data.length; i++) {
            const row = data[i];
            if (!row || row.length < 3) continue;

            // Cấu trúc file: [Mã SKU Combo, SKU, Số lượng]
            const comboCodeRaw = row[0]; // Mã SKU Combo (ví dụ: 24-6-200-110-RG3)
            const maHangRaw = row[1];    // SKU base (ví dụ: 24-6-200-110)
            const soLuongRaw = row[2];   // Số lượng (ví dụ: 3)

            // Skip nếu là header (chứa text như "Mã SKU Combo", "SKU", "Số lượng")
            if (typeof comboCodeRaw === 'string' && 
                (comboCodeRaw.includes('Mã') || comboCodeRaw.includes('SKU') || comboCodeRaw.includes('Combo'))) {
                continue;
            }

            if (!comboCodeRaw || !maHangRaw || !soLuongRaw) continue;

            const comboCode = String(comboCodeRaw).trim();
            const maHang = String(maHangRaw).trim();
            const soLuong = Number(soLuongRaw) || 1;

            const exist = oldComboMap.get(comboCode);
            if (!exist) {
                // Combo mới - insert
                ops.push({
                    insertOne: {
                        document: {
                            comboCode,
                            maHang,
                            soLuong,
                            importDate: new Date(),
                            createdBy: req.authUser.username
                        }
                    }
                });
                imported++;
            } else {
                // Combo đã tồn tại - kiểm tra có thay đổi không
                let changed = false;
                if (exist.maHang !== maHang) changed = true;
                if (exist.soLuong !== soLuong) changed = true;
                
                if (changed) {
                    ops.push({
                        updateOne: {
                            filter: { _id: exist._id },
                            update: {
                                $set: {
                                    maHang,
                                    soLuong,
                                    importDate: new Date(),
                                    createdBy: req.authUser.username
                                }
                            }
                        }
                    });
                    updated++;
                } else {
                    unchanged++;
                }
            }
        }

        if (ops.length > 0) {
            await ComboData.bulkWrite(ops);
        }
        
        res.json({ 
            success: true, 
            message: `Đã import ${imported} combo mới, cập nhật ${updated}, giữ nguyên ${unchanged}.` 
        });
        
    } catch (error) {
        console.error('❌ Lỗi upload ComboData:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Lỗi import ComboData: ' + error.message 
        });
    }
});

// API upload MasterData - CHỈ DÀNH CHO ROLE CHECKER
router.post('/api/checker/upload-masterdata', requireChecker, upload.single('file'), async (req, res) => {
    try {
        // console.log(`[API /api/checker/upload-masterdata] User: ${req.authUser.username} (${req.authUser.role}) uploading MasterData`);
        
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Vui lòng chọn file Excel MasterData' });
        }

        // Kiểm tra role một lần nữa (double check)
        if (req.authUser.role !== 'checker') {
            return res.status(403).json({ 
                success: false, 
                message: 'Chỉ có role Checker mới được upload MasterData' 
            });
        }

        // Đọc file Excel
        const workbook = XLSX.readFile(req.file.path);
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const data = XLSX.utils.sheet_to_json(sheet, { header: 1 });

        console.log(`[API /api/checker/upload-masterdata] File có ${data.length} dòng dữ liệu`);

        // 1. Load MasterData cũ để so sánh và tránh trùng SKU
        const oldMasterData = await MasterData.find({});
        const oldMasterMap = new Map();
        for (const m of oldMasterData) {
            if (m && m.sku) {
                oldMasterMap.set(m.sku.toLowerCase().trim(), m); // Case insensitive
            }
        }

        console.log(`[API /api/checker/upload-masterdata] Database hiện có ${oldMasterData.length} MasterData`);

        let imported = 0, updated = 0, unchanged = 0, skipped = 0;
        const ops = [];
        const duplicateSkus = new Set(); // Track duplicate SKUs trong file
        
        // 2. Xử lý dữ liệu từ dòng 1 (có thể có header ở dòng 0)
        for (let i = 0; i < data.length; i++) {
            const row = data[i];
            if (!row || row.length < 2) {
                skipped++;
                continue;
            }

            // Cấu trúc file: [Mã SKU*, Mẫu Vải, Tên phiên bản sản phẩm, ...]
            const skuRaw = row[0];        // Mã SKU*
            const mauVaiRaw = row[1];     // Mẫu Vải
            const tenPhienBanRaw = row[2]; // Tên phiên bản sản phẩm

            // Skip nếu là header (chứa text như "Mã SKU", "Mẫu Vải", "Tên phiên bản")
            if (typeof skuRaw === 'string' && 
                (skuRaw.includes('Mã SKU') || skuRaw.includes('Mẫu Vải') || skuRaw.includes('Tên phiên bản'))) {
                skipped++;
                continue;
            }

            if (!skuRaw || !mauVaiRaw) {
                skipped++;
                continue;
            }

            const sku = String(skuRaw).trim();
            const mauVai = String(mauVaiRaw).trim();
            const tenPhienBan = tenPhienBanRaw ? String(tenPhienBanRaw).trim() : '';

            // Kiểm tra trùng SKU trong file hiện tại
            const skuKey = sku.toLowerCase();
            if (duplicateSkus.has(skuKey)) {
                console.log(`⚠️ [API /api/checker/upload-masterdata] SKU trùng trong file: ${sku}`);
                skipped++;
                continue;
            }
            duplicateSkus.add(skuKey);

            // Kiểm tra SKU đã tồn tại trong database
            const exist = oldMasterMap.get(skuKey);
            if (!exist) {
                // MasterData mới - insert
                ops.push({
                    insertOne: {
                        document: {
                            sku,
                            mauVai,
                            tenPhienBan,
                            importDate: new Date(),
                            createdBy: req.authUser.username
                        }
                    }
                });
                imported++;
                console.log(`✅ [API /api/checker/upload-masterdata] Thêm mới SKU: ${sku}`);
            } else {
                // MasterData đã tồn tại - kiểm tra có thay đổi không
                let changed = false;
                if (exist.mauVai !== mauVai) changed = true;
                if (exist.tenPhienBan !== tenPhienBan) changed = true;
                
                if (changed) {
                    ops.push({
                        updateOne: {
                            filter: { _id: exist._id },
                            update: {
                                $set: {
                                    mauVai,
                                    tenPhienBan,
                                    importDate: new Date(),
                                    createdBy: req.authUser.username
                                }
                            }
                        }
                    });
                    updated++;
                    console.log(`🔄 [API /api/checker/upload-masterdata] Cập nhật SKU: ${sku}`);
                } else {
                    unchanged++;
                    console.log(`⏭️ [API /api/checker/upload-masterdata] Giữ nguyên SKU: ${sku}`);
                }
            }
        }

        // 3. Thực hiện bulk operations
        if (ops.length > 0) {
            console.log(`[API /api/checker/upload-masterdata] Thực hiện ${ops.length} operations...`);
            await MasterData.bulkWrite(ops);
        }
        
        console.log(`[API /api/checker/upload-masterdata] Hoàn thành: ${imported} mới, ${updated} cập nhật, ${unchanged} giữ nguyên, ${skipped} bỏ qua`);
        
        res.json({ 
            success: true, 
            message: `Đã import ${imported} MasterData mới, cập nhật ${updated}, giữ nguyên ${unchanged}, bỏ qua ${skipped} dòng.`,
            stats: {
                imported,
                updated,
                unchanged,
                skipped,
                total: data.length
            }
        });
        
    } catch (error) {
        console.error('❌ [API /api/checker/upload-masterdata] Lỗi:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Lỗi import MasterData: ' + error.message 
        });
    }
});

module.exports = router;
