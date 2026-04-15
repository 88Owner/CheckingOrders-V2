const mongoose = require('mongoose');

const templateSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    filename: {
        type: String,
        required: true
    },
    filePath: {
        type: String,
        required: true
    },
    skuColumn: {
        type: String,
        required: true,
        default: 'C' // Mặc định cột C
    },
    slColumn: {
        type: String,
        required: true,
        default: 'D' // Mặc định cột D
    },
    startRow: {
        type: Number,
        default: 1 // Hàng bắt đầu ghi dữ liệu (0-indexed, mặc định là 1 = hàng thứ 2)
    },
    isActive: {
        type: Boolean,
        default: false // Template đang được sử dụng
    },
    description: {
        type: String,
        default: ''
    },
    /** Tên kho hiển thị cột D khi xuất CSV nhập phôi */
    warehousePhoiName: {
        type: String,
        default: 'Kho Phôi - Shi',
        trim: true
    },
    warehouseNVLName: {
        type: String,
        default: 'Kho NVL - Shi',
        trim: true
    },
    warehousePhePhamName: {
        type: String,
        default: 'Kho Phế phẩm - Shi',
        trim: true
    },
    /** Hậu tố SKU: {maMau}-{suffix} */
    skuHangLoiSuffix: {
        type: String,
        default: '00-404-230',
        trim: true
    },
    skuNhapKhoSuffix: {
        type: String,
        default: '00-000-230',
        trim: true
    },
    /** Header dòng 1 của template CSV (dạng mảng ô, kỳ vọng A–X ~ 24 cột) */
    csvHeader: {
        type: [String],
        default: []
    },
    createdBy: {
        type: String,
        default: null
    }
}, {
    timestamps: true
});

templateSchema.index({ name: 1 });
templateSchema.index({ isActive: 1 });

module.exports = mongoose.model('Template', templateSchema);
