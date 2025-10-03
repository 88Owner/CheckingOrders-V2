const express = require('express');
const multer = require('multer');
const XLSX = require('xlsx');
const path = require('path');
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

// API upload MasterData
router.post('/api/master-data/upload', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Vui lòng chọn file Excel' });
        }

        // Đọc file Excel
        const workbook = XLSX.readFile(req.file.path);
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const data = XLSX.utils.sheet_to_json(sheet, { header: 1 });

        // Chuẩn hóa dữ liệu (giả sử cấu trúc: SKU, Màu vải, Tên phiên bản)
        const masterDataList = [];
        let imported = 0, updated = 0;

        for (let i = 1; i < data.length; i++) { // Bỏ qua header
            const row = data[i];
            if (!row || row.length < 3) continue;
            
            const [sku, mauVai, tenPhienBan] = row;
            if (!sku) continue;

            masterDataList.push({
                sku: String(sku).trim(),
                mauVai: String(mauVai || '').trim(),
                tenPhienBan: String(tenPhienBan || '').trim()
            });
        }

        // Bulk upsert
        const bulkOps = [];
        for (const item of masterDataList) {
            bulkOps.push({
                updateOne: {
                    filter: { sku: item.sku },
                    update: { $set: item },
                    upsert: true
                }
            });
        }

        if (bulkOps.length > 0) {
            const result = await MasterData.bulkWrite(bulkOps);
            imported = result.upsertedCount;
            updated = result.modifiedCount;
        }

        // Xóa file tạm
        const fs = require('fs');
        fs.unlinkSync(req.file.path);

        res.json({
            success: true,
            message: `Đã import MasterData: ${imported} mới, ${updated} cập nhật`,
            data: {
                imported,
                updated,
                total: imported + updated
            }
        });

    } catch (error) {
        console.error('MasterData upload error:', error);
        
        // Xóa file tạm nếu có lỗi
        if (req.file) {
            const fs = require('fs');
            try {
                fs.unlinkSync(req.file.path);
            } catch (deleteError) {
                console.log('Không thể xóa file tạm:', deleteError.message);
            }
        }

        res.status(500).json({
            success: false,
            message: 'Lỗi upload MasterData: ' + error.message
        });
    }
});

// API lấy danh sách MasterData
router.get('/api/master-data', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 100;
        const skip = (page - 1) * limit;

        const masterData = await MasterData.find()
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        const total = await MasterData.countDocuments();

        res.json({
            success: true,
            data: {
                masterData,
                pagination: {
                    currentPage: page,
                    totalPages: Math.ceil(total / limit),
                    totalRecords: total,
                    hasNext: page < Math.ceil(total / limit),
                    hasPrev: page > 1
                }
            }
        });
    } catch (error) {
        console.error('Lỗi lấy MasterData:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy MasterData: ' + error.message
        });
    }
});

// API xóa tất cả MasterData
router.delete('/api/master-data', async (req, res) => {
    try {
        const result = await MasterData.deleteMany({});
        res.json({
            success: true,
            message: `Đã xóa ${result.deletedCount} MasterData`,
            deletedCount: result.deletedCount
        });
    } catch (error) {
        console.error('Lỗi xóa MasterData:', error);
        res.status(500).json({
            success: false,
            message: 'Lỗi xóa MasterData: ' + error.message
        });
    }
});

module.exports = router;