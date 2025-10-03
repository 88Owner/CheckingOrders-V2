const mongoose = require('mongoose');

const ComboDataSchema = new mongoose.Schema({
    comboCode: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    maHang: {
        type: String,
        required: true,
        index: true
    },
    soLuong: {
        type: Number,
        required: true,
        default: 1
    },
    // Người import
    createdBy: {
        type: String,
        default: ''
    },
    // Ngày import
    importDate: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true // Tự động thêm createdAt và updatedAt
});

// Index cho tìm kiếm nhanh
ComboDataSchema.index({ maHang: 1 });

module.exports = mongoose.model('ComboData', ComboDataSchema);
