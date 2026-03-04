console.log('SAPO_LOCATION_ID from env    =', process.env.SAPO_LOCATION_ID);
const express = require('express');
const multer = require('multer');
const XLSX = require('xlsx');
const path = require('path');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const MasterData = require('../models/MasterData');
const config = require('../config');
console.log('SAPO_LOCATION_ID from config =', config.SAPO_LOCATION_ID);
console.log('SAPO_LOCATION_ID from env    =', process.env.SAPO_LOCATION_ID);

const { sapoAPI } = require('../utils/sapoApi');

const router = express.Router();

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
        fileSize: 10 * 1024 * 1024
    }
});

function requireOrderCreator(req, res, next) {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.substring(7) : null;

    if (!token) {
        return res.status(401).json({ success: false, message: 'Thiếu token' });
    }

    try {
        const decoded = jwt.verify(token, config.SESSION_SECRET || process.env.SESSION_SECRET || 'secret');
        if (decoded.role !== 'order_creator' && decoded.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Bạn không có quyền truy cập' });
        }
        req.authUser = decoded;
        next();
    } catch (e) {
        return res.status(401).json({ success: false, message: 'Token không hợp lệ' });
    }
}

async function createPurchaseOrderOnSapo(baseConfig, purchaseOrder, endpoint) {
    const {
        location_id,
        supplier_id
    } = baseConfig;

    const normalizeLineItem = (it) => ({
        sku: it.sku,
        name: it.name || it.sku,
        quantity: Number(it.quantity) || 0
    });

    const payload = {
        purchase_order: {
            location_id,
            supplier_id,
            line_items: (purchaseOrder.line_items || []).map(normalizeLineItem),
            note: purchaseOrder.note || null,
            reference: purchaseOrder.reference || null
        }
    };

    return sapoAPI('POST', endpoint, payload);
}

async function fetchInventoryItemIdsFromSapoBySkus(skus) {
    const normalizedSkus = Array.from(
        new Set(
            (skus || [])
                .map(s => String(s || '').trim().toLowerCase())
                .filter(Boolean)
        )
    );

    if (!normalizedSkus.length) {
        return {};
    }

    const foundMap = new Map();

    for (const skuNorm of normalizedSkus) {
        const skuOriginal = skus.find(s => String(s || '').trim().toLowerCase() === skuNorm) || skuNorm;

        const endpoint = `/admin/inventory_items.json?limit=1&sku=${encodeURIComponent(skuOriginal)}`;
        const res = await sapoAPI('GET', endpoint);

        const items = res && res.data && Array.isArray(res.data.inventory_items)
            ? res.data.inventory_items
            : [];

        if (!items.length) {
            continue;
        }

        const inventoryItem = items[0];
        const invId = inventoryItem && inventoryItem.id;

        if (!invId) {
            continue;
        }

        foundMap.set(skuNorm, {
            sku: skuOriginal,
            inventory_item_id: invId
        });
    }

    if (!foundMap.size) {
        return {};
    }

    const ops = [];
    for (const [, info] of foundMap.entries()) {
        ops.push(
            MasterData.findOneAndUpdate(
                { sku: info.sku },
                {
                    $set: {
                        sku: info.sku,
                        sapoInventoryItemId: info.inventory_item_id
                    }
                },
                { upsert: true, new: true }
            )
        );
    }

    try {
        await Promise.all(ops);
    } catch (e) {
        console.error('Lỗi cập nhật MasterData với inventory_item_id từ Sapo:', e.message);
    }

    const result = {};
    for (const [normSku, info] of foundMap.entries()) {
        result[normSku] = info.inventory_item_id;
    }

    return result;
}

async function autoFillInventoryItemIds(items) {
    if (!Array.isArray(items) || !items.length) {
        return;
    }

    const skusToLookup = Array.from(
        new Set(
            items
                .filter(it => !Number.isFinite(it.inventory_item_id))
                .map(it => String(it.sku || '').trim())
                .filter(Boolean)
        )
    );

    if (!skusToLookup.length) {
        return;
    }

    const map = await fetchInventoryItemIdsFromSapoBySkus(skusToLookup);

    items.forEach(it => {
        const norm = String(it.sku || '').trim().toLowerCase();
        if (!Number.isFinite(it.inventory_item_id) && Object.prototype.hasOwnProperty.call(map, norm)) {
            it.inventory_item_id = map[norm];
        }
    });
}

router.post('/api/order-creator/upload', requireOrderCreator, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Vui lòng chọn file Excel đơn hàng' });
        }

        const workbook = XLSX.readFile(req.file.path);
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const data = XLSX.utils.sheet_to_json(sheet, { header: 1 });

        const rows = [];
        for (let i = 0; i < data.length; i++) {
            const row = data[i];
            if (!row || row.length < 2) continue;

            const skuRaw = row[0];
            const qtyRaw = row[1];

            if (typeof skuRaw === 'string' && (skuRaw.toLowerCase().includes('sku') || skuRaw.includes('Mã'))) {
                continue;
            }

            if (!skuRaw || !qtyRaw) continue;

            const sku = String(skuRaw).trim();
            const quantity = Number(qtyRaw);

            if (!sku || !Number.isFinite(quantity) || quantity <= 0) continue;

            rows.push({ sku, quantity });
        }

        if (!rows.length) {
            return res.status(400).json({ success: false, message: 'Không tìm thấy dòng dữ liệu hợp lệ (SKU + Số lượng)' });
        }

        const uniqueSkus = Array.from(new Set(rows.map(r => r.sku)));
        const masterDocs = await MasterData.find({ sku: { $in: uniqueSkus } });
        const masterMap = new Map();
        for (const md of masterDocs) {
            if (md && md.sku) {
                masterMap.set(String(md.sku).trim().toLowerCase(), md);
            }
        }

        const items = [];
        const missingSkus = [];

        for (const row of rows) {
            const key = row.sku.trim().toLowerCase();
            const md = masterMap.get(key);
            if (!md) {
                missingSkus.push(row.sku);
            }
            const name = md && typeof md.tenPhienBan === 'string' && md.tenPhienBan.trim()
                ? md.tenPhienBan.trim()
                : row.sku;

            const inventoryItemId = md && typeof md.sapoInventoryItemId === 'number'
                ? md.sapoInventoryItemId
                : null;

            items.push({
                sku: row.sku,
                name,
                quantity: row.quantity,
                inventory_item_id: inventoryItemId
            });
        }

        await autoFillInventoryItemIds(items);

        const missingInventoryIds = items
            .filter(it => !Number.isFinite(it.inventory_item_id))
            .map(it => it.sku);

        if (missingInventoryIds.length) {
            return res.status(400).json({
                success: false,
                message: 'Không tìm được inventory_item_id trên Sapo cho một số SKU. Vui lòng kiểm tra lại SKU hoặc cấu hình sản phẩm trên Sapo.',
                data: {
                    missingInventoryItemSkus: missingInventoryIds,
                    missingMasterDataSkus: missingSkus
                }
            });
        }

        let sapoResult = null;
        try {
            const endpoint =
                config.SAPO_PURCHASE_ORDER_ENDPOINT ||
                process.env.SAPO_PURCHASE_ORDER_ENDPOINT ||
                '/admin/purchase_orders.json';

            const locationIdRaw = config.SAPO_LOCATION_ID || process.env.SAPO_LOCATION_ID;
            const supplierIdRaw = config.SAPO_SUPPLIER_ID || process.env.SAPO_SUPPLIER_ID;
            const assigneeIdRaw = config.SAPO_ASSIGNEE_ID || process.env.SAPO_ASSIGNEE_ID;
            const receiptStatusRaw = config.SAPO_RECEIPT_STATUS || process.env.SAPO_RECEIPT_STATUS || 'pending';

            const location_id = Number(locationIdRaw);
            const supplier_id = Number(supplierIdRaw);
            const assignee_id = Number(assigneeIdRaw);

            if (!Number.isFinite(location_id) || location_id <= 0) {
                return res.status(400).json({ success: false, message: 'Thiếu cấu hình SAPO_LOCATION_ID trong .env' });
            }
            if (!Number.isFinite(supplier_id) || supplier_id <= 0) {
                return res.status(400).json({ success: false, message: 'Thiếu cấu hình SAPO_SUPPLIER_ID trong .env' });
            }
            if (!Number.isFinite(assignee_id) || assignee_id <= 0) {
                return res.status(400).json({ success: false, message: 'Thiếu cấu hình SAPO_ASSIGNEE_ID trong .env' });
            }

            const allowedReceiptStatuses = ['pending', 'received'];
            const normalizedStatus = String(receiptStatusRaw || '').trim().toLowerCase();
            const receipt_status = allowedReceiptStatuses.includes(normalizedStatus) ? normalizedStatus : 'pending';

            const baseConfig = {
                location_id,
                supplier_id,
                assignee_id,
                receipt_status
            };

            const purchaseOrder = {
                line_items: items
            };

            sapoResult = await createPurchaseOrderOnSapo(baseConfig, purchaseOrder, endpoint);
        } catch (e) {
            return res.status(500).json({
                success: false,
                message: 'Lỗi gọi API Sapo: ' + e.message,
                data: {
                    items,
                    missingSkus
                }
            });
        } finally {
            if (req.file) {
                try {
                    fs.unlinkSync(req.file.path);
                } catch (err) {
                    console.error('Không thể xóa file tạm:', err.message);
                }
            }
        }

        return res.json({
            success: true,
            message: 'Đã đọc file và gửi dữ liệu sang Sapo',
            data: {
                items,
                missingSkus,
                sapoResponse: sapoResult
            }
        });
    } catch (error) {
        console.error('Order Creator upload error:', error);

        if (req.file) {
            try {
                fs.unlinkSync(req.file.path);
            } catch (err) {
                console.error('Không thể xóa file tạm sau lỗi:', err.message);
            }
        }

        return res.status(500).json({ success: false, message: 'Lỗi xử lý file: ' + error.message });
    }
});

router.post('/api/order-creator/receive-inventories/bulk', requireOrderCreator, async (req, res) => {
    try {
        const payload = req.body || {};
        const list = Array.isArray(payload.receive_inventories) ? payload.receive_inventories : payload.orders;

        if (!Array.isArray(list) || list.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Thiếu danh sách đơn nhập hàng (receive_inventories hoặc orders phải là mảng).'
            });
        }

        const endpoint =
            config.SAPO_PURCHASE_ORDER_ENDPOINT ||
            process.env.SAPO_PURCHASE_ORDER_ENDPOINT ||
            '/admin/purchase_orders.json';

        const locationIdRaw = config.SAPO_LOCATION_ID || process.env.SAPO_LOCATION_ID;
        const supplierIdRaw = config.SAPO_SUPPLIER_ID || process.env.SAPO_SUPPLIER_ID;
        const assigneeIdRaw = config.SAPO_ASSIGNEE_ID || process.env.SAPO_ASSIGNEE_ID;
        const receiptStatusRaw = config.SAPO_RECEIPT_STATUS || process.env.SAPO_RECEIPT_STATUS || 'pending';

        const location_id = Number(locationIdRaw);
        const supplier_id = Number(supplierIdRaw);
        const assignee_id = Number(assigneeIdRaw);

        if (!Number.isFinite(location_id) || location_id <= 0) {
            return res.status(400).json({ success: false, message: 'Thiếu cấu hình SAPO_LOCATION_ID trong .env' });
        }
        if (!Number.isFinite(supplier_id) || supplier_id <= 0) {
            return res.status(400).json({ success: false, message: 'Thiếu cấu hình SAPO_SUPPLIER_ID trong .env' });
        }
        if (!Number.isFinite(assignee_id) || assignee_id <= 0) {
            return res.status(400).json({ success: false, message: 'Thiếu cấu hình SAPO_ASSIGNEE_ID trong .env' });
        }

        const allowedReceiptStatuses = ['pending', 'received'];
        const normalizedStatus = String(receiptStatusRaw || '').trim().toLowerCase();
        const receipt_status = allowedReceiptStatuses.includes(normalizedStatus) ? normalizedStatus : 'pending';

        const baseConfig = {
            location_id,
            supplier_id,
            assignee_id,
            receipt_status
        };

        const results = [];

        for (let i = 0; i < list.length; i++) {
            const inv = list[i] || {};

            if (!Array.isArray(inv.line_items) || inv.line_items.length === 0) {
                results.push({
                    index: i,
                    success: false,
                    error: 'Đơn thiếu line_items hoặc line_items rỗng.',
                    request: inv
                });
                continue;
            }

            try {
                const sapoRes = await createPurchaseOrderOnSapo(baseConfig, inv, endpoint);
                results.push({
                    index: i,
                    success: true,
                    sapoResponse: sapoRes
                });
            } catch (e) {
                results.push({
                    index: i,
                    success: false,
                    error: e.message,
                    request: inv
                });
            }
        }

        const succeeded = results.filter(r => r.success).length;
        const failed = results.length - succeeded;

        return res.json({
            success: true,
            message: 'Đã xử lý tạo đơn nhập hàng hàng loạt.',
            total: results.length,
            succeeded,
            failed,
            results
        });
    } catch (error) {
        console.error('Bulk receive inventories error:', error);
        return res.status(500).json({
            success: false,
            message: 'Lỗi xử lý bulk receive inventories: ' + error.message
        });
    }
});

module.exports = router;

