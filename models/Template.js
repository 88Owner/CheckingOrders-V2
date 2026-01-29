const mongoose = require('mongoose');

const templateSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    filename: {
        type: String,
        required: true
    },
    filePath: {
        type: String,
        required: true
    },
    skuColumn: {
        type: String,
        required: true,
        default: 'C' // Mặc định cột C
    },
    slColumn: {
        type: String,
        required: true,
        default: 'D' // Mặc định cột D
    },
    startRow: {
        type: Number,
        default: 1 // Hàng bắt đầu ghi dữ liệu (0-indexed, mặc định là 1 = hàng thứ 2)
    },
    isActive: {
        type: Boolean,
        default: false // Template đang được sử dụng
    },
    description: {
        type: String,
        default: ''
    },
    createdBy: {
        type: String,
        default: null
    }
}, {
    timestamps: true
});

templateSchema.index({ name: 1 });
templateSchema.index({ isActive: 1 });

module.exports = mongoose.model('Template', templateSchema);
