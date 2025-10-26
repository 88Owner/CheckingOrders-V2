const mongoose = require('mongoose');

const mauVaiSchema = new mongoose.Schema({
    maMau: {
        type: String,
        required: true,
        unique: true
    },
    tenMau: {
        type: String,
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

mauVaiSchema.index({ maMau: 1 });
mauVaiSchema.index({ tenMau: 1 });

module.exports = mongoose.model('MauVai', mauVaiSchema);
