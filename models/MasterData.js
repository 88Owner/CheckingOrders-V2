const mongoose = require('mongoose');

const masterDataSchema = new mongoose.Schema({
    sku: {
        type: String,
        required: true,
        unique: true
    },
    mauVai: {
        type: String,
        default: ''
    },
    tenPhienBan: {
        type: String,
        default: ''
    },
    // ID sản phẩm tồn kho trên Sapo, dùng cho receive_inventories
    sapoInventoryItemId: {
        type: Number,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Tạo index để tìm kiếm nhanh hơn
masterDataSchema.index({ sku: 1 });

module.exports = mongoose.model('MasterData', masterDataSchema);