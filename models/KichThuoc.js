const mongoose = require('mongoose');

const kichThuocSchema = new mongoose.Schema({
    szSku: {
        type: String,
        required: true,
        unique: true
    },
    kichThuoc: {
        type: String,
        required: true
    },
    dienTich: {
        type: Number,
        required: true
    },
    importDate: {
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

kichThuocSchema.index({ szSku: 1 });
kichThuocSchema.index({ kichThuoc: 1 });

module.exports = mongoose.model('KichThuoc', kichThuocSchema);
