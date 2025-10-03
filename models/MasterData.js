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