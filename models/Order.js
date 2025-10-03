const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
    stt: {
        type: Number,
        required: true
    },
    maDongGoi: {
        type: String,
        required: true
    },
    maVanDon: {
        type: String,
        required: true
    },
    maDonHang: {
        type: String,
        required: true
    },
    maHang: {
        type: String,
        required: true
    },
    soLuong: {
        type: Number,
        required: true
    },
    importDate: {
        type: Date,
        default: Date.now
    },
    verified: {
        type: Boolean,
        default: false
    },
    verifiedAt: {
        type: Date,
        default: null
    },
    scannedQuantity: {
        type: Number,
        default: 0
    },
    checkingBy: {
        type: String,
        default: null
    },
    block: {
        type: Boolean,
        default: false // true: đang bị block, false: không block
    },
    blockedAt: {
        type: Date,
        default: null // thời gian bắt đầu block
    }
}, {
    timestamps: true // Tự động thêm createdAt và updatedAt
});

orderSchema.index({ maDonHang: 1 });
orderSchema.index({ maVanDon: 1 });
orderSchema.index({ maDongGoi: 1 });

module.exports = mongoose.model('Order', orderSchema);
