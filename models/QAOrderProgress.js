const mongoose = require('mongoose');

const qaOrderProgressSchema = new mongoose.Schema(
    {
        orderCode: { type: String, required: true, trim: true },
        sku: { type: String, required: true, trim: true },
        productName: { type: String, required: true, trim: true },
        quantity: { type: Number, required: true, min: 1 },
        stage: { type: String, required: true, trim: true },
        completedQty: { type: Number, required: true, min: 0 },
        defectQty: { type: Number, required: true, min: 0 },
        note: { type: String, default: '' },
        updatedBy: { type: String, required: true, trim: true },
        updatedByRole: { type: String, required: true, trim: true }
    },
    { timestamps: true }
);

qaOrderProgressSchema.index({ orderCode: 1, createdAt: -1 });

module.exports = mongoose.model('QAOrderProgress', qaOrderProgressSchema);
