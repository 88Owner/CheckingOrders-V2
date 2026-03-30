const mongoose = require('mongoose');

const qaOrderSchema = new mongoose.Schema(
    {
        orderCode: {
            type: String,
            required: true,
            trim: true,
            unique: true
        },
        sku: {
            type: String,
            required: true,
            trim: true
        },
        productName: {
            type: String,
            required: true,
            trim: true
        },
        quantity: {
            type: Number,
            required: true,
            min: 1
        },
        currentStage: {
            type: String,
            default: 'Cắt vải'
        },
        currentStatus: {
            type: String,
            default: 'pending'
        },
        /** cao: xếp trước trong hàng đợi công đoạn */
        priority: {
            type: String,
            enum: ['high', 'normal'],
            default: 'normal'
        },
        /** Sau ép bông: chuyển sang May hoặc Đóng khoen (tùy loại hàng) */
        routeAfterPress: {
            type: String,
            enum: ['May', 'Đóng khoen'],
            default: 'May'
        },
        totalCompleted: {
            type: Number,
            default: 0
        },
        totalDefect: {
            type: Number,
            default: 0
        },
        lastUpdatedBy: {
            type: String,
            default: null
        },
        createdBy: {
            type: String,
            default: null
        }
    },
    { timestamps: true }
);

qaOrderSchema.index({ createdAt: -1 });
qaOrderSchema.index({ sku: 1 });

module.exports = mongoose.model('QAOrder', qaOrderSchema);
