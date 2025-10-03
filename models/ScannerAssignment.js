const mongoose = require('mongoose');

const scannerAssignmentSchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    comPort: {
        type: String,
        required: true,
        validate: {
            validator: function(v) {
                return /^COM\d+$/i.test(v);
            },
            message: 'COM port phải có định dạng COM + số (VD: COM3, COM4)'
        }
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true // Tự động cập nhật createdAt và updatedAt
});

// Middleware để cập nhật updatedAt trước khi save
scannerAssignmentSchema.pre('save', function(next) {
    this.updatedAt = new Date();
    next();
});

// Index để tìm kiếm nhanh
scannerAssignmentSchema.index({ userId: 1 });
scannerAssignmentSchema.index({ comPort: 1 });

module.exports = mongoose.model('ScannerAssignment', scannerAssignmentSchema);