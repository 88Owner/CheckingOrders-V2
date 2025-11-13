const mongoose = require('mongoose');

const nhapPhoiSchema = new mongoose.Schema({
    maMau: {
        type: String,
        required: true
    },
    tenMau: {
        type: String,
        required: true
    },
    kichThuoc: {
        type: String,
        required: true
    },
    szSku: {
        type: String,
        required: true
    },
    soLuong: {
        type: Number,
        required: true,
        min: 0
    },
    createdBy: {
        type: String,
        required: true
    },
    importDate: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Index để tìm kiếm nhanh
nhapPhoiSchema.index({ maMau: 1, kichThuoc: 1 });
nhapPhoiSchema.index({ createdBy: 1, importDate: -1 });

module.exports = mongoose.model('NhapPhoi', nhapPhoiSchema);

