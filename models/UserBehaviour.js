const mongoose = require('mongoose');

const UserBehaviourSchema = new mongoose.Schema({
    // Thời gian thực hiện
    time: {
        type: Date,
        default: Date.now,
        required: true
    },
    
    // Người dùng
    user: {
        type: String,
        required: true,
        index: true
    },
    
    // Loại thao tác
    method: {
        type: String,
        required: true,
        enum: ['keyboard', 'mouse', 'scanner', 'api', 'system'],
        index: true
    },
    
    // Mô tả chi tiết
    description: {
        type: String,
        required: true
    },
    
    // Thông tin bổ sung
    metadata: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },
    
    // IP address
    ipAddress: {
        type: String,
        default: ''
    },
    
    // User agent
    userAgent: {
        type: String,
        default: ''
    },
    
    // Session ID
    sessionId: {
        type: String,
        default: ''
    }
}, {
    timestamps: true // Tự động thêm createdAt và updatedAt
});

// Index cho tìm kiếm nhanh
UserBehaviourSchema.index({ user: 1, time: -1 });
UserBehaviourSchema.index({ method: 1, time: -1 });
UserBehaviourSchema.index({ time: -1 });

module.exports = mongoose.model('UserBehaviour', UserBehaviourSchema);
