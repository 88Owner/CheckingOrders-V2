// ...existing code...
const express = require('express');
const multer = require('multer');
const XLSX = require('xlsx');
const path = require('path');
const Order = require('../models/Order');
const ComboData = require('../models/ComboData');
const MasterData = require('../models/MasterData');
const MauVai = require('../models/MauVai');
const { sapoAPI } = require('../utils/sapoApi');
const config = require('../config');

const router = express.Router();

/**
 * Helper: Tính danh sách đơn hàng thiếu dựa trên tồn kho Sapo.
 * - Lấy toàn bộ orders hiện tại
 * - Gọi Sapo /admin/products.json để lấy inventory theo SKU
 * - Nếu inventory_quantity <= Số lượng SKU trong đơn -> coi là thiếu
 */
async function computeMissingOrdersFromSapo() {
    const todayOrders = await Order.find({}).lean();
    if (!todayOrders.length) {
        return { rows: [], stats: { totalOrders: 0, totalLines: 0, totalDistinctSku: 0, totalMissing: 0 } };
    }

    // Gom theo MaVanDon + SKU để tính tổng số lượng mỗi SKU trong từng đơn
    const aggregated = new Map(); // key: maVanDon|sku
    const skuSet = new Set();

    for (const o of todayOrders) {
        if (!o.maVanDon || !o.maHang || !o.soLuong) continue;
        const key = `${o.maVanDon}|${o.maHang}`;
        const current = aggregated.get(key) || {
            maVanDon: o.maVanDon,
            sku: o.maHang,
            soLuong: 0,
            tenPhienBan: o.tenPhienBan || '',
            mauVai: o.mauVai || ''
        };
        current.soLuong += Number(o.soLuong) || 0;
        aggregated.set(key, current);
        skuSet.add(o.maHang);
    }

    const aggregatedRows = Array.from(aggregated.values());
    if (!aggregatedRows.length) {
        return { rows: [], stats: { totalOrders: todayOrders.length, totalLines: 0, totalDistinctSku: skuSet.size, totalMissing: 0 } };
    }

    // Chuẩn bị map Mẫu vải (MauVai) từ mã mẫu (aa trong SKU aa-bb-ccc-ddd)
    const maMauSet = new Set();
    for (const row of aggregatedRows) {
        const sku = row.sku;
        if (!sku) continue;
        const parts = String(sku).trim().split('-');
        if (parts.length >= 4) {
            const [aa, bb, ccc, ddd] = parts;
            if (
                aa && bb && ccc && ddd &&
                /^\d+$/.test(aa) &&
                /^\d+$/.test(bb) &&
                /^\d+$/.test(ccc) &&
                /^\d+$/.test(ddd)
            ) {
                maMauSet.add(String(aa).trim());
            }
        }
    }

    let mauVaiMap = new Map();
    if (maMauSet.size > 0) {
        const mauVaiDocs = await MauVai.find({ maMau: { $in: Array.from(maMauSet) } }).lean();
        for (const mv of mauVaiDocs) {
            if (mv && mv.maMau) {
                mauVaiMap.set(String(mv.maMau).trim(), mv);
            }
        }
    }

    const normalizeSku = (s) => String(s || '').trim().toLowerCase();

    // Load MasterData để fallback tên SP (key chuẩn hóa)
    const masterDatas = await MasterData.find({ sku: { $in: Array.from(skuSet) } }).lean();
    const masterMap = new Map();
    for (const md of masterDatas) {
        if (md && md.sku) masterMap.set(normalizeSku(md.sku), md);
    }

    // Gọi Sapo /admin/products.json — lấy đủ tất cả trang (phân trang)
    const LIMIT_PER_PAGE = 250;
    let sapoProducts = [];
    let page = 1;
    let hasMore = true;
    while (hasMore) {
        const endpoint = `/admin/products.json?limit=${LIMIT_PER_PAGE}&page=${page}`;
        const sapoRes = await sapoAPI('GET', endpoint);
        const payload = sapoRes ? sapoRes.data : null;

        let chunk = [];
        if (payload && Array.isArray(payload.products)) {
            chunk = payload.products;
        } else if (payload && payload.data && Array.isArray(payload.data.products)) {
            chunk = payload.data.products;
        }
        if (!chunk.length) break;
        sapoProducts = sapoProducts.concat(chunk);
        hasMore = chunk.length >= LIMIT_PER_PAGE;
        page += 1;
    }

    const skuInventoryMap = new Map(); // key: SKU normalized (lowercase trim), value: inventory_quantity
    const skuNameMap = new Map();      // key: SKU normalized, value: tên hiển thị

    // Lấy số trong kho: ưu tiên inventory_quantity của variant (đúng trường Sapo)
    const getVariantInventoryQuantity = (variant) => {
        if (!variant || typeof variant !== 'object') return 0;
        if (typeof variant.inventory_quantity === 'number') return variant.inventory_quantity;
        if (typeof variant.inventory === 'number') return variant.inventory;
        if (Array.isArray(variant.inventories)) {
            return variant.inventories.reduce((sum, inv) => sum + (Number(inv.quantity) || 0), 0);
        }
        return 0;
    };

    for (const p of sapoProducts) {
        const productName = p.name || p.title || '';
        const variants = Array.isArray(p.variants) ? p.variants : [];
        if (!variants.length) continue;

        for (const v of variants) {
            const skuRaw = String(v.sku || v.variant_sku || v.product_sku || '').trim();
            if (!skuRaw) continue;
            const skuKey = normalizeSku(skuRaw);
            const inventory_quantity = getVariantInventoryQuantity(v);
            const prev = skuInventoryMap.get(skuKey) ?? 0;
            skuInventoryMap.set(skuKey, prev + inventory_quantity);

            if (!skuNameMap.has(skuKey)) {
                const variantName = v.name || v.title || '';
                skuNameMap.set(skuKey, variantName || productName);
            }
        }
    }

    // Hàm parse Mẫu / Loại / Ngang / Cao từ tên SP
    function parseFromName(name) {
        const result = { mau: '', loai: '', ngang: '', cao: '' };
        if (!name || typeof name !== 'string') return result;
        const trimmed = name.trim();

        // Pattern: "Ngân hà Rido 120-150"
        const match = trimmed.match(/(.+?)\s+(\S+)\s+(\d+)\s*-\s*(\d+)/u);
        if (match) {
            result.mau = match[1].trim();
            result.loai = match[2].trim();
            result.ngang = match[3];
            result.cao = match[4];
            return result;
        }

        // Fallback: cố gắng tách số cuối cùng
        const numMatch = trimmed.match(/(.+?)(\d+)\s*-\s*(\d+)/u);
        if (numMatch) {
            result.mau = numMatch[1].trim();
            result.ngang = numMatch[2];
            result.cao = numMatch[3];
            return result;
        }

        result.mau = trimmed;
        return result;
    }

    // Hàm parse thông tin từ SKU dạng aa-bb-ccc-ddd
    function parseFromSkuForMissingOrder(sku, mauVaiMapLocal) {
        const result = { mau: '', loai: '', ngang: '', cao: '' };
        if (!sku) return result;

        const parts = String(sku).trim().split('-');
        if (parts.length < 4) return result;

        const [aa, bb, ccc, ddd] = parts;
        if (!aa || !bb || !ccc || !ddd) return result;
        if (
            !/^\d+$/.test(aa) ||
            !/^\d+$/.test(bb) ||
            !/^\d+$/.test(ccc) ||
            !/^\d+$/.test(ddd)
        ) {
            return result;
        }

        const maMau = String(aa).trim();
        const mv = mauVaiMapLocal.get(maMau);
        result.mau = mv ? (mv.tenMau || mv.maMau || maMau) : maMau;

        const loaiCode = parseInt(bb, 10);
        switch (loaiCode) {
            case 1:
                result.loai = 'Rido';
                break;
            case 2:
                result.loai = 'Ore';
                break;
            case 3:
                result.loai = 'Dán 1 lớp';
                break;
            case 4:
                result.loai = 'Dán 2 lớp';
                break;
            case 6:
                result.loai = 'Rèm giường';
                break;
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
                result.loai = 'Áo gối B';
                break;
            default:
                result.loai = '';
        }

        // Chuẩn hóa kích thước: bỏ 0 ở đầu nếu có, nhưng không để trống
        const ngangStr = String(ccc).trim();
        const caoStr = String(ddd).trim();
        result.ngang = ngangStr.replace(/^0+/, '') || ngangStr;
        result.cao = caoStr.replace(/^0+/, '') || caoStr;

        return result;
    }

    const missingRows = [];

    for (const row of aggregatedRows) {
        const skuKey = normalizeSku(row.sku);
        const inventoryQty = skuInventoryMap.get(skuKey);
        const soLuong = row.soLuong || 0;

        // Chỉ coi là thiếu khi: đã tìm thấy SKU trên Sapo VÀ tồn kho <= số lượng đơn
        // SKU không có trong Sapo (undefined) -> không liệt vào hàng thiếu
        if (inventoryQty === undefined || inventoryQty === null) continue;
        if (Number(inventoryQty) > soLuong) continue;

        const master = masterMap.get(skuKey);
        const nameFromMaster = master && typeof master.tenPhienBan === 'string' ? master.tenPhienBan : null;
        const nameFromOrder = row.tenPhienBan && typeof row.tenPhienBan === 'string' ? row.tenPhienBan : null;
        const nameFromSapo = skuNameMap.get(skuKey);
        const tenSp = nameFromOrder || nameFromMaster || nameFromSapo || '';

        const parsedFromSku = parseFromSkuForMissingOrder(row.sku, mauVaiMap);
        const parsedFromName = parseFromName(tenSp);

        // inventoryQuantity = inventory_quantity của variant tương ứng SKU (từ Sapo variants[])
        missingRows.push({
            maVanDon: row.maVanDon,
            sku: row.sku,
            tenSp,
            soLuong,
            inventoryQuantity: Number(inventoryQty) || 0,
            mau: parsedFromSku.mau || parsedFromName.mau,
            loai: parsedFromSku.loai || parsedFromName.loai,
            ngang: parsedFromSku.ngang || parsedFromName.ngang,
            cao: parsedFromSku.cao || parsedFromName.cao
        });
    }

    return {
        rows: missingRows,
        stats: {
            totalOrders: todayOrders.length,
            totalLines: aggregatedRows.length,
            totalDistinctSku: skuSet.size,
            totalMissing: missingRows.length,
            sapoProductsPages: page - 1,
            sapoProductsCount: sapoProducts.length,
            sapoSkuCount: skuInventoryMap.size
        }
    };
}

// State dùng để đặt tên file xuất đơn hàng thiếu trong ngày
let missingOrdersExportState = {
    dateKey: null,
    index: 0
};

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
        
        if (!['checker', 'packer'].includes(decoded.role)) {
            // console.log('❌ [REQUIRE-CHECKER] Role không đúng:', decoded.role);
            return res.status(403).json({ success: false, message: 'Bạn không có quyền truy cập' });
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
            const backupDocs = orders.map(o => {
                const doc = o.toObject();
                delete doc._id;
                return { ...doc, archivedAt: new Date() };
            });
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
        const comboCache = require('../utils/comboCache');
        const comboDocsMap = await comboCache.getAllCombos();
        // Flatten Map thành array
        const comboDocs = [];
        for (const combos of comboDocsMap.values()) {
            comboDocs.push(...combos);
        }
        const comboByCode = new Map(); // key: comboCode, value: combo doc
        for (const c of comboDocs) {
            if (c && typeof c.comboCode === 'string' && c.comboCode.trim()) {
                comboByCode.set(c.comboCode.trim(), c);
            }
        }
        let imported = 0, updated = 0, unchanged = 0;
        const ops = [];
        let lastMaDongGoi = '';
        let lastMaVanDon = '';
        for (let i = 5; i < data.length; i++) {
            const row = data[i];
            if (!row || row.length < 38) continue;
            const maVanDon = row[1]; // Cột B
            const maDongGoi = row[2]; // Cột C
            const maHang = row[34]; // Cột AI
            const soLuong = row[37]; // Cột AL

            // Fill down: nếu trống thì dùng giá trị dòng trước
            const currentMaDongGoi = maDongGoi || lastMaDongGoi;
            const currentMaVanDon = maVanDon || lastMaVanDon;
            if (maDongGoi) lastMaDongGoi = maDongGoi;
            if (maVanDon) lastMaVanDon = maVanDon;

            if (!currentMaDongGoi || !currentMaVanDon || !maHang || !soLuong) continue;

            // Set các trường khác mặc định
            const stt = i - 4; // Số thứ tự từ 1
            const maDonHang = String(currentMaVanDon); // Giả sử mã đơn hàng là mã vận đơn

            // Giữ nguyên mã combo và số lượng từ file Excel
            let normalizedMaHang = String(maHang).trim();
            let normalizedSoLuong = Number(soLuong);
            
            // Kiểm tra combo nhưng KHÔNG nhân số lượng
            // ComboData chỉ dùng để reference, không thay đổi số lượng
            const combo = comboByCode.get(normalizedMaHang);

            const key = String(maDonHang) + '|' + String(normalizedMaHang);
            const exist = oldMap.get(key);
            if (!exist) {
                ops.push({
                    insertOne: {
                        document: {
                            stt: Number(stt),
                            maDongGoi: String(currentMaDongGoi),
                            maVanDon: String(currentMaVanDon),
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
                    if (exist.maDongGoi !== String(currentMaDongGoi)) changed = true;
                    if (exist.maVanDon !== String(currentMaVanDon)) changed = true;
                    if (exist.soLuong !== Number(normalizedSoLuong)) changed = true;
                    if (changed) {
                        ops.push({
                            updateOne: {
                                filter: { _id: exist._id },
                                update: {
                                    $set: {
                                        stt: Number(stt),
                                        maDongGoi: String(currentMaDongGoi),
                                        maVanDon: String(currentMaVanDon),
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

        // Xóa file tạm
        if (req.file) {
            const fs = require('fs');
            try {
                fs.unlinkSync(req.file.path);
                console.log(`🗑️ Đã xóa file tạm: ${req.file.path}`);
            } catch (deleteError) {
                console.error('Không thể xóa file tạm:', deleteError.message);
            }
        }

        res.json({ success: true, message: `Đã import ${imported} đơn mới, cập nhật ${updated}, giữ nguyên ${unchanged}.` });
    } catch (error) {
        console.error('Checker upload error:', error);
        
        // Xóa file tạm nếu có lỗi
        if (req.file) {
            const fs = require('fs');
            try {
                fs.unlinkSync(req.file.path);
                console.log(`🗑️ Đã xóa file tạm sau lỗi: ${req.file.path}`);
            } catch (deleteError) {
                console.error('Không thể xóa file tạm sau lỗi:', deleteError.message);
            }
        }
        
        res.status(500).json({ success: false, message: 'Lỗi import file: ' + error.message });
    }
});

// API cho checker: tự động lấy đơn hàng từ Sapo và nạp vào Order
router.post('/api/checker/upload-from-sapo', requireChecker, async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const orders = await Order.find({});
        let needBackup = false;
        if (orders.length > 0) {
            const firstOrderDate = orders[0].importDate ? new Date(orders[0].importDate) : orders[0].createdAt;
            firstOrderDate.setHours(0, 0, 0, 0);
            if (firstOrderDate.getTime() !== today.getTime()) {
                needBackup = true;
            }
        }

        if (needBackup) {
            const DataOrder = require('../models/DataOrder');
            const backupDocs = orders.map(o => ({
                ...o.toObject(),
                archivedAt: new Date()
            }));
            if (backupDocs.length > 0) await DataOrder.insertMany(backupDocs);
            await Order.deleteMany({});
        }

        // Luôn gọi đúng endpoint danh sách đơn hàng trên Sapo
        const endpoint = '/admin/orders.json';

        const sapoRes = await sapoAPI('GET', endpoint);
        const payload = sapoRes ? sapoRes.data : null;

        // Sapo có thể trả về nhiều shape khác nhau tùy phiên bản/endpoint
        let sapoOrders = [];
        if (payload && Array.isArray(payload.orders)) {
            sapoOrders = payload.orders;
        } else if (payload && payload.data && Array.isArray(payload.data.orders)) {
            sapoOrders = payload.data.orders;
        } else if (payload && Array.isArray(payload.data)) {
            sapoOrders = payload.data;
        } else if (Array.isArray(payload)) {
            sapoOrders = payload;
        }

        if (!sapoOrders.length) {
            return res.json({
                success: true,
                message: 'Không có đơn hàng nào từ Sapo để import.',
                data: {
                    imported: 0,
                    updated: 0,
                    unchanged: 0,
                    totalFromSapo: 0,
                    debug: payload && typeof payload === 'object' ? { keys: Object.keys(payload).slice(0, 30) } : null
                }
            });
        }

        const oldOrders = await Order.find({});
        const oldMap = new Map();
        for (const o of oldOrders) {
            oldMap.set(o.maDonHang + '|' + o.maHang, o);
        }

        let imported = 0, updated = 0, unchanged = 0;
        const ops = [];
        let stt = 1;
        const rowsForUpsert = [];

        let ordersWithItems = 0;
        let itemsImportedConsidered = 0;
        let totalOrdersWithFulfillments = 0;
        let totalMatchedFulfillmentPending = 0;
        const statusSamples = [];

        for (const so of sapoOrders) {
            // Điều kiện: chỉ lấy các đơn có fulfillments khác rỗng
            // và trong fulfillments có ít nhất 1 phần tử có shipment_status = 'pending'
            let hasFulfillments = false;
            let hasPendingFulfillment = false;
            const sampleStatus = {};

            if (so && Array.isArray(so.fulfillments) && so.fulfillments.length > 0) {
                hasFulfillments = true;
                totalOrdersWithFulfillments++;

                const fulfillments = so.fulfillments;

                const checkFulfillmentPending = (f) => {
                    if (!f || typeof f !== 'object') return false;
                    if (f.shipment_status === 'pending') return true;
                    if (Array.isArray(f.shipment_statuses)) {
                        return f.shipment_statuses.some(s => s === 'pending' || (s && s.status === 'pending'));
                    }
                    if (typeof f.shipment_statuses === 'string' && f.shipment_statuses === 'pending') {
                        return true;
                    }
                    return false;
                };

                hasPendingFulfillment = fulfillments.some(f => checkFulfillmentPending(f));

                if (statusSamples.length < 10) {
                    sampleStatus.fulfillments = fulfillments.slice(0, 3); // tránh trả về quá nặng
                }
            }

            if (!hasFulfillments || !hasPendingFulfillment) {
                // Không có fulfillments hoặc không fulfillment nào pending -> bỏ qua
                if (statusSamples.length < 10 && (hasFulfillments || so.fulfillments)) {
                    statusSamples.push({
                        id: so.id ?? null,
                        code: so.code ?? so.name ?? so.number ?? null,
                        statusFields: sampleStatus
                    });
                }
                continue;
            }

            if (hasPendingFulfillment) {
                totalMatchedFulfillmentPending++;
                if (statusSamples.length < 10) {
                    statusSamples.push({
                        id: so.id ?? null,
                        code: so.code ?? so.name ?? so.number ?? null,
                        statusFields: sampleStatus
                    });
                }
            }

            const maDongGoi = String(so.packing_code || so.number || '').trim();
            let maVanDon = String(so.shipping_code || so.fulfillment_code || '').trim();
            // Nếu không có mã vận đơn riêng, dùng trường name/code làm mã vận đơn
            if (!maVanDon) {
                maVanDon = String(so.name || so.code || so.number || so.id || '').trim();
            }
            const maDonHang = maVanDon;

            if (!maDonHang) {
                continue;
            }

            const lineItems =
                (Array.isArray(so.line_items) ? so.line_items : null) ||
                (Array.isArray(so.items) ? so.items : null) ||
                (Array.isArray(so.order_items) ? so.order_items : null) ||
                [];

            if (lineItems.length) ordersWithItems++;

            for (const li of lineItems) {
                const maHang = String(li.sku || li.variant_sku || li.product_sku || '').trim();
                const soLuong = Number(li.quantity || li.qty || 0);
                if (!maHang || !soLuong) continue;
                itemsImportedConsidered++;
                rowsForUpsert.push({
                    stt: stt++,
                    maDongGoi,
                    maVanDon,
                    maDonHang,
                    maHang,
                    soLuong
                });
            }
        }

        // Lookup MasterData theo SKU để gán tên SP giống luồng upload file
        const skuList = [...new Set(rowsForUpsert.map(r => r.maHang).filter(Boolean))];
        const masterDatas = skuList.length ? await MasterData.find({ sku: { $in: skuList } }).lean() : [];
        const masterMap = new Map();
        for (const md of masterDatas) {
            if (md && md.sku) masterMap.set(String(md.sku).trim(), md);
        }

        for (const r of rowsForUpsert) {
            const md = masterMap.get(r.maHang);
            const mauVai = md && typeof md.mauVai === 'string' ? md.mauVai : '';
            const tenPhienBan = md && typeof md.tenPhienBan === 'string' ? md.tenPhienBan : '';

            const key = r.maDonHang + '|' + r.maHang;
            const exist = oldMap.get(key);
            if (!exist) {
                ops.push({
                    insertOne: {
                        document: {
                            stt: r.stt,
                            maDongGoi: r.maDongGoi,
                            maVanDon: r.maVanDon,
                            maDonHang: r.maDonHang,
                            maHang: r.maHang,
                            mauVai,
                            tenPhienBan,
                            soLuong: r.soLuong,
                            importDate: today,
                            createdBy: req.authUser.username
                        }
                    }
                });
                imported++;
            } else {
                if (exist.verified === true) {
                    unchanged++;
                } else {
                    let changed = false;
                    if (exist.stt !== r.stt) changed = true;
                    if (exist.maDongGoi !== r.maDongGoi) changed = true;
                    if (exist.maVanDon !== r.maVanDon) changed = true;
                    if (exist.soLuong !== r.soLuong) changed = true;
                    if ((exist.mauVai || '') !== mauVai) changed = true;
                    if ((exist.tenPhienBan || '') !== tenPhienBan) changed = true;

                    if (changed) {
                        ops.push({
                            updateOne: {
                                filter: { _id: exist._id },
                                update: {
                                    $set: {
                                        stt: r.stt,
                                        maDongGoi: r.maDongGoi,
                                        maVanDon: r.maVanDon,
                                        soLuong: r.soLuong,
                                        mauVai,
                                        tenPhienBan,
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

        return res.json({
            success: true,
            message: `Đã import tự động từ Sapo: ${imported} đơn mới, cập nhật ${updated}, giữ nguyên ${unchanged}.`,
            data: {
                imported,
                updated,
                unchanged,
                totalFromSapo: sapoOrders.length,
                ordersWithItems,
                itemsConsidered: itemsImportedConsidered,
                debug: {
                    endpoint,
                    sampleOrderKeys: sapoOrders[0] && typeof sapoOrders[0] === 'object' ? Object.keys(sapoOrders[0]).slice(0, 40) : null,
                    sampleLineItemKeys: (sapoOrders[0] && (sapoOrders[0].line_items || sapoOrders[0].items || sapoOrders[0].order_items) && (sapoOrders[0].line_items || sapoOrders[0].items || sapoOrders[0].order_items)[0])
                        ? Object.keys((sapoOrders[0].line_items || sapoOrders[0].items || sapoOrders[0].order_items)[0]).slice(0, 40)
                        : null,
                    statusStats: {
                        totalOrdersFromSapo: sapoOrders.length,
                        totalOrdersWithFulfillments,
                        totalMatchedFulfillmentPending
                    },
                    statusSamples
                }
            }
        });
    } catch (error) {
        console.error('Checker upload-from-sapo error:', error);
        return res.status(500).json({
            success: false,
            message: 'Lỗi lấy đơn từ Sapo: ' + error.message
        });
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
        const comboCache = require('../utils/comboCache');
        const oldComboDataMap = await comboCache.getAllCombos();
        // Flatten Map thành array
        const oldComboData = [];
        for (const combos of oldComboDataMap.values()) {
            oldComboData.push(...combos);
        }
        const oldComboMap = new Map();
        for (const c of oldComboData) {
            if (c && c.comboCode && c.maHang) {
                // Tạo key composite: comboCode + maHang
                const key = `${c.comboCode}|${c.maHang}`;
                oldComboMap.set(key, c);
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

            // Tạo key composite để kiểm tra tồn tại
            const key = `${comboCode}|${maHang}`;
            const exist = oldComboMap.get(key);
            
            if (!exist) {
                // Combo + SKU mới - insert
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
                // Combo + SKU đã tồn tại - kiểm tra có thay đổi không
                let changed = false;
                if (exist.soLuong !== soLuong) changed = true;
                
                if (changed) {
                    ops.push({
                        updateOne: {
                            filter: { _id: exist._id },
                            update: {
                                $set: {
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
            // Invalidate cache sau khi có thay đổi dữ liệu
            const comboCache = require('../utils/comboCache');
            comboCache.invalidateCache();
        }
        
        // Xóa file tạm
        if (req.file) {
            const fs = require('fs');
            try {
                fs.unlinkSync(req.file.path);
                console.log(`🗑️ [API /api/checker/upload-combodata] Đã xóa file tạm: ${req.file.path}`);
            } catch (deleteError) {
                console.error('Không thể xóa file tạm:', deleteError.message);
            }
        }

        res.json({ 
            success: true, 
            message: `Đã import ${imported} combo mới, cập nhật ${updated}, giữ nguyên ${unchanged}.` 
        });
        
    } catch (error) {
        console.error('❌ Lỗi upload ComboData:', error);
        
        // Xóa file tạm nếu có lỗi
        if (req.file) {
            const fs = require('fs');
            try {
                fs.unlinkSync(req.file.path);
                console.log(`🗑️ [API /api/checker/upload-combodata] Đã xóa file tạm sau lỗi: ${req.file.path}`);
            } catch (deleteError) {
                console.error('Không thể xóa file tạm sau lỗi:', deleteError.message);
            }
        }
        
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

        // console.log(`[API /api/checker/upload-masterdata] File có ${data.length} dòng dữ liệu`);

        // 1. Load MasterData cũ để so sánh và tránh trùng SKU
        const oldMasterData = await MasterData.find({});
        const oldMasterMap = new Map();
        for (const m of oldMasterData) {
            if (m && m.sku) {
                oldMasterMap.set(m.sku.toLowerCase().trim(), m); // Case insensitive
            }
        }

        // console.log(`[API /api/checker/upload-masterdata] Database hiện có ${oldMasterData.length} MasterData`);

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
                // console.log(`⚠️ [API /api/checker/upload-masterdata] SKU trùng trong file: ${sku}`);
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
                // console.log(`✅ [API /api/checker/upload-masterdata] Thêm mới SKU: ${sku}`);
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
                    // console.log(`🔄 [API /api/checker/upload-masterdata] Cập nhật SKU: ${sku}`);
                } else {
                    unchanged++;
                    // console.log(`⏭️ [API /api/checker/upload-masterdata] Giữ nguyên SKU: ${sku}`);
                }
            }
        }

        // 3. Thực hiện bulk operations
        if (ops.length > 0) {
            // console.log(`[API /api/checker/upload-masterdata] Thực hiện ${ops.length} operations...`);
            await MasterData.bulkWrite(ops);
        }
        
        // console.log(`[API /api/checker/upload-masterdata] Hoàn thành: ${imported} mới, ${updated} cập nhật, ${unchanged} giữ nguyên, ${skipped} bỏ qua`);
        
        // Xóa file tạm
        if (req.file) {
            const fs = require('fs');
            try {
                fs.unlinkSync(req.file.path);
                console.log(`🗑️ [API /api/checker/upload-masterdata] Đã xóa file tạm: ${req.file.path}`);
            } catch (deleteError) {
                console.error('Không thể xóa file tạm:', deleteError.message);
            }
        }

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
        
        // Xóa file tạm nếu có lỗi
        if (req.file) {
            const fs = require('fs');
            try {
                fs.unlinkSync(req.file.path);
                console.log(`🗑️ [API /api/checker/upload-masterdata] Đã xóa file tạm sau lỗi: ${req.file.path}`);
            } catch (deleteError) {
                console.error('Không thể xóa file tạm sau lỗi:', deleteError.message);
            }
        }
        
        res.status(500).json({ 
            success: false, 
            message: 'Lỗi import MasterData: ' + error.message 
        });
    }
});

// API cho checker: Lấy danh sách đơn hàng thiếu dựa trên tồn kho Sapo
router.get('/api/checker/missing-orders', requireChecker, async (req, res) => {
    try {
        const { rows, stats } = await computeMissingOrdersFromSapo();
        return res.json({
            success: true,
            data: {
                rows,
                stats
            }
        });
    } catch (error) {
        console.error('❌ Lỗi /api/checker/missing-orders:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi tính toán đơn hàng thiếu: ' + error.message
        });
    }
});

// API cho checker: Xuất file Excel đơn hàng thiếu
router.get('/api/checker/missing-orders/export', requireChecker, async (req, res) => {
    try {
        const { rows } = await computeMissingOrdersFromSapo();

        // Chuẩn bị dữ liệu cho Excel - SL = trị tuyệt đối của số lượng thiếu
        const sortedRows = Array.isArray(rows)
            ? [...rows].sort((a, b) => String(a?.maVanDon || '').localeCompare(String(b?.maVanDon || ''), 'vi', { numeric: true }))
            : [];
        const aoa = [];
        aoa.push(['MaVanDon', 'SKU', 'SL', 'Loai', 'Mau', 'Ngang', 'Cao']);
        for (const r of sortedRows) {
            const soLuongThieu = Math.abs((r.inventoryQuantity || 0));
            aoa.push([
                r.maVanDon || '',
                r.sku || '',
                soLuongThieu,
                r.loai || '',
                r.mau || '',
                r.ngang || '',
                r.cao || ''
            ]);
        }

        const workbook = XLSX.utils.book_new();
        const worksheet = XLSX.utils.aoa_to_sheet(aoa);
        XLSX.utils.book_append_sheet(workbook, worksheet, 'Don hang thieu');

        const buffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });

        // Tên file dạng: Don-Hang-Thieu-mm-dd-ca-i.xlsx (i tăng dần trong ngày)
        const now = new Date();
        const mm = String(now.getMonth() + 1).padStart(2, '0');
        const dd = String(now.getDate()).padStart(2, '0');
        const dateKey = `${now.getFullYear()}-${mm}-${dd}`;

        if (missingOrdersExportState.dateKey !== dateKey) {
            missingOrdersExportState.dateKey = dateKey;
            missingOrdersExportState.index = 0;
        }
        missingOrdersExportState.index += 1;

        const caIndex = missingOrdersExportState.index;
        const fileName = `Don-hang-thieu-${mm}-${dd}-ca-${caIndex}.xlsx`;

        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        res.send(buffer);
    } catch (error) {
        console.error('❌ Lỗi /api/checker/missing-orders/export:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi xuất file đơn hàng thiếu: ' + error.message
        });
    }
});

module.exports = router;
