const mongoose = require('mongoose');

const cayVaiSchema = new mongoose.Schema({
    maMau: {
        type: String,
        required: true
    },
    tenMau: {
        type: String,
        required: true
    },
    chieuDaiCayVai: {
        type: Number,
        required: true,
        min: 0
    },
    dienTichBanDau: {
        type: Number,
        required: true,
        min: 0
    },
    dienTichDaCat: {
        type: Number,
        default: 0,
        min: 0
    },
    dienTichConLai: {
        type: Number,
        default: 0,
        min: 0
    },
    soMConLai: {
        type: Number,
        default: 0,
        min: 0
    },
    tienDoPercent: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    },
    vaiLoi: {
        chieuDai: { type: Number, default: 0 },
        dienTich: { type: Number, default: 0 },
        soM: { type: Number, default: 0 }
    },
    vaiThieu: {
        soM: { type: Number, default: 0 }
    },
    nhapLaiKho: {
        soM: { type: Number, default: 0 }
    },
    items: [{
        kichThuoc: String,
        szSku: String,
        soLuong: Number,
        dienTich: Number,
        dienTichCat: Number
    }],
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
cayVaiSchema.index({ maMau: 1, importDate: -1 });
cayVaiSchema.index({ createdBy: 1, importDate: -1 });

module.exports = mongoose.model('CayVai', cayVaiSchema);

