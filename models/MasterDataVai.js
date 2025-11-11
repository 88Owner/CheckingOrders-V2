const mongoose = require('mongoose');

const masterDataVaiSchema = new mongoose.Schema({
    sku: {
        type: String,
        required: true
    },
    ten: {
        type: String,
        required: true
    },
    mau: {
        type: String,
        required: true
    },
    ngang: {
        type: String,
        required: true
    },
    cao: {
        type: String,
        required: true
    },
    uniqueKey: {
        type: String,
        required: true,
        unique: true
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

// Tạo index để tìm kiếm nhanh hơn
masterDataVaiSchema.index({ sku: 1 });
masterDataVaiSchema.index({ uniqueKey: 1 });
masterDataVaiSchema.index({ mau: 1, ngang: 1, cao: 1 });

module.exports = mongoose.model('MasterDataVai', masterDataVaiSchema);

