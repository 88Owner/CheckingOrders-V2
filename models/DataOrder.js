const mongoose = require('mongoose');

const dataOrderSchema = new mongoose.Schema({
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
        default: false
    },
    blockedAt: {
        type: Date,
        default: null
    },
    archivedAt: {
        type: Date,
        default: Date.now
    },
    createdBy: {
        type: String,
        default: null
    }
}, {
    timestamps: true
});

dataOrderSchema.index({ maDonHang: 1 });
dataOrderSchema.index({ maVanDon: 1 });
dataOrderSchema.index({ maDongGoi: 1 });
dataOrderSchema.index({ archivedAt: 1 });

module.exports = mongoose.model('DataOrder', dataOrderSchema);