const mongoose = require('mongoose');

/** Bộ đếm dùng chung (vd: mã đơn QA tự tăng) */
const counterSchema = new mongoose.Schema(
    {
        _id: { type: String, required: true },
        seq: { type: Number, default: 0 }
    },
    { collection: 'counters' }
);

module.exports = mongoose.model('Counter', counterSchema);
