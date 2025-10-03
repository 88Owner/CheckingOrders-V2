const mongoose = require('mongoose');

const machineSchema = new mongoose.Schema({
    // Thông tin máy tính
    ipAddress: { 
        type: String, 
        required: true, 
        unique: true,
        index: true 
    },
    hostname: { 
        type: String, 
        default: 'Unknown' 
    },
    platform: { 
        type: String, 
        default: 'Unknown' 
    },
    userAgent: { 
        type: String, 
        default: null 
    },
    
    // COM Ports của máy này
    comPorts: [{
        path: { type: String, required: true },
        manufacturer: { type: String, default: 'Unknown' },
        vendorId: { type: String, default: null },
        productId: { type: String, default: null },
        isAvailable: { type: Boolean, default: true },
        isLikelyScanner: { type: Boolean, default: false },
        confidence: { type: String, enum: ['high', 'medium', 'low'], default: 'low' },
        deviceType: { type: String, default: 'Serial Device' },
        lastUpdated: { type: Date, default: Date.now }
    }],
    
    // Thông tin truy cập
    firstSeen: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },
    accessCount: { type: Number, default: 1 },
    
    // Trạng thái
    isOnline: { type: Boolean, default: true },
    lastComScan: { type: Date, default: Date.now }
}, {
    timestamps: true
});

// Index cho tìm kiếm nhanh
machineSchema.index({ ipAddress: 1 });
machineSchema.index({ lastSeen: -1 });
machineSchema.index({ isOnline: 1 });

module.exports = mongoose.model('Machine', machineSchema); 