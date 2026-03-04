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

async function createReceiveInventoryOnSapo(baseConfig, inventory, endpoint) {
    const {
        location_id,
        supplier_id,
        assignee_id,
        receipt_status
    } = baseConfig;

    const normalizeLineItem = (it) => ({
        sku: it.sku,
        barcode: it.barcode || null,
        note: it.note || null,
        name: it.name || it.sku,
        title: it.title || null,
        variant_title: it.variant_title || null,
        price: typeof it.price === 'number' ? it.price : null,
        quantity: Number(it.quantity) || 0,
        rejected_quantity: Number(it.rejected_quantity) || 0,
        unit: it.unit || null,
        tax_title: it.tax_title || null,
        tax_rate: typeof it.tax_rate === 'number' ? it.tax_rate : null,
        discount_type: it.discount_type || null,
        discount_value: typeof it.discount_value === 'number' ? it.discount_value : null,
        purchase_order_line_item_id: it.purchase_order_line_item_id || null,
        lot_items: Array.isArray(it.lot_items) ? it.lot_items : []
    });

    const payload = {
        receive_inventory: {
            id: 0,
            location_id,
            supplier_id,
            assignee_id,
            receipt_status,
            discount_type: inventory.discount_type || null,
            discount_value: typeof inventory.discount_value === 'number' ? inventory.discount_value : 0,
            line_items: (inventory.line_items || []).map(normalizeLineItem),
            combination_line_items: Array.isArray(inventory.combination_line_items) ? inventory.combination_line_items : [],
            landed_cost_lines: Array.isArray(inventory.landed_cost_lines) ? inventory.landed_cost_lines : [],
            tax_included: typeof inventory.tax_included === 'boolean' ? inventory.tax_included : false,
            tags: Array.isArray(inventory.tags) ? inventory.tags : [],
            due_on: inventory.due_on || null,
            reference: inventory.reference || null,
            note: inventory.note || null,
            purchase_order_id: inventory.purchase_order_id || null
        }
    };

    return sapoAPI('POST', endpoint, payload);
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

            items.push({
                sku: row.sku,
                name,
                quantity: row.quantity
            });
        }

        let sapoResult = null;
        try {
            const endpoint =
                config.SAPO_PURCHASE_ORDER_ENDPOINT ||
                process.env.SAPO_PURCHASE_ORDER_ENDPOINT ||
                '/admin/receive_inventories.json';

            const locationIdRaw = config.SAPO_LOCATION_ID || process.env.SAPO_LOCATION_ID;
            const supplierIdRaw = config.SAPO_SUPPLIER_ID || process.env.SAPO_SUPPLIER_ID;
            const assigneeIdRaw = config.SAPO_ASSIGNEE_ID || process.env.SAPO_ASSIGNEE_ID;
            const receiptStatus = config.SAPO_RECEIPT_STATUS || process.env.SAPO_RECEIPT_STATUS || 'pending';

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

            const baseConfig = {
                location_id,
                supplier_id,
                assignee_id,
                receipt_status: receiptStatus
            };

            const inventory = {
                line_items: items
            };

            sapoResult = await createReceiveInventoryOnSapo(baseConfig, inventory, endpoint);
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
            '/admin/receive_inventories.json';

        const locationIdRaw = config.SAPO_LOCATION_ID || process.env.SAPO_LOCATION_ID;
        const supplierIdRaw = config.SAPO_SUPPLIER_ID || process.env.SAPO_SUPPLIER_ID;
        const assigneeIdRaw = config.SAPO_ASSIGNEE_ID || process.env.SAPO_ASSIGNEE_ID;
        const receiptStatus = config.SAPO_RECEIPT_STATUS || process.env.SAPO_RECEIPT_STATUS || 'pending';

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

        const baseConfig = {
            location_id,
            supplier_id,
            assignee_id,
            receipt_status: receiptStatus
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
                const sapoRes = await createReceiveInventoryOnSapo(baseConfig, inv, endpoint);
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

