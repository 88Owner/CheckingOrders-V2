const mongoose = require('mongoose');

const ComboDataSchema = new mongoose.Schema({
    comboCode: {
        type: String,
        required: true,
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

// Index cho tìm kiếm nhanh - tối ưu cho các truy vấn thường dùng
ComboDataSchema.index({ comboCode: 1 }); // Tìm theo comboCode (truy vấn chính)
ComboDataSchema.index({ maHang: 1 }); // Tìm theo maHang (truy vấn phụ)
// Composite unique index: một comboCode có thể có nhiều maHang khác nhau
ComboDataSchema.index({ comboCode: 1, maHang: 1 }, { unique: true });
// Sparse index cho các trường có thể null
ComboDataSchema.index({ createdBy: 1 }, { sparse: true });
ComboDataSchema.index({ importDate: -1 }); // Sắp xếp theo ngày import mới nhất

module.exports = mongoose.model('ComboData', ComboDataSchema);
