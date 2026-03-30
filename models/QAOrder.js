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
            default: 'Tạo đơn'
        },
        currentStatus: {
            type: String,
            default: 'pending'
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
