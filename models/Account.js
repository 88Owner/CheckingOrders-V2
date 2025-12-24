const mongoose = require('mongoose');

const accountSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin', 'packer', 'checker', 'warehouse_manager', 'warehouse_staff', 'production_worker'], default: 'user' },
    
    // Mapping với ERPNext Employee
    erpnextEmployeeId: { type: String, default: null }, // Employee ID/Name trong ERPNext
    erpnextEmployeeName: { type: String, default: null }, // Tên nhân viên trong ERPNext (cache)
    
    // Thông tin máy tính
    machineInfo: {
        hostname: { type: String, default: null },
        ipAddress: { type: String, default: null },
        platform: { type: String, default: null },
        lastSeen: { type: Date, default: Date.now }
    },
    
    // Phân quyền máy quét
    scannerPermissions: {
        allowedScanners: [{ 
            type: String // Scanner IDs được phép sử dụng
        }],
        assignedScanner: { 
            type: String, // Scanner ID hiện tại được assign
            default: null 
        },
        port: {
            type: String, // Cổng USB/COM được phân quyền
            default: null
        },
        allowedPorts: [{
            type: String // Danh sách cổng port được phép sử dụng
        }]
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
    
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Account', accountSchema);
