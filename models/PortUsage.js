const mongoose = require('mongoose');

const portUsageSchema = new mongoose.Schema({
    comPort: {
        type: String,
        required: true
        // Bỏ unique constraint để cho phép multiple users claim cùng 1 port (sẽ được handle bởi logic)
    },
    userId: {
        type: String,
        required: true
    },
    machineId: { 
        type: String, 
        required: true, 
        index: true 
    }, // Thêm machine ID để track multiple machines
    sessionId: { 
        type: String, 
        required: true, 
        index: true 
    }, // Thêm session ID để track multiple sessions
    screenId: { 
        type: String, 
        default: 'main' 
    }, // Thêm screen ID (main, secondary) cho multiple screens
    connectedAt: {
        type: Date,
        default: Date.now
    },
    lastActivity: {
        type: Date,
        default: Date.now
    },
    isActive: {
        type: Boolean,
        default: true
    },
    heartbeat: {
        type: Date,
        default: Date.now
    } // Thêm heartbeat để detect disconnected users
}, {
    timestamps: true
});

// Index để tìm kiếm nhanh
portUsageSchema.index({ comPort: 1, isActive: 1 });
portUsageSchema.index({ userId: 1, isActive: 1 });
portUsageSchema.index({ machineId: 1, isActive: 1 });
portUsageSchema.index({ sessionId: 1, isActive: 1 });
portUsageSchema.index({ heartbeat: 1 }); // Index cho timeout cleanup

// Method để kiểm tra xem port có đang được sử dụng không
portUsageSchema.statics.isPortInUse = async function(comPort, excludeUserId = null) {
    const query = { 
        comPort: comPort, 
        isActive: true 
    };
    
    if (excludeUserId) {
        query.userId = { $ne: excludeUserId };
    }
    
    const usage = await this.findOne(query);
    return !!usage;
};

// Method để lấy user đang sử dụng port
portUsageSchema.statics.getCurrentUser = async function(comPort) {
    const usage = await this.findOne({ 
        comPort: comPort, 
        isActive: true 
    });
    const currentUser = usage ? usage.userId : null;
    // console.log(`🔍 [PORT-USAGE] Current user for port ${comPort}: ${currentUser}`);
    return currentUser;
};

// Method để release port
portUsageSchema.statics.releasePort = async function(comPort, userId) {
    // console.log(`🔓 [PORT-USAGE] Releasing port ${comPort} for user ${userId}`);
    const result = await this.updateOne(
        { comPort: comPort, userId: userId, isActive: true },
        { isActive: false, lastActivity: new Date() }
    );
    // console.log(`🔓 [PORT-USAGE] Release result: ${result.modifiedCount} documents modified`);
    return result.modifiedCount > 0;
};

// Method để release port cho bất kỳ user nào (dùng khi logout hoặc ngắt kết nối)
portUsageSchema.statics.releasePortForAnyUser = async function(comPort) {
    // console.log(`🔓 [PORT-USAGE] Releasing port ${comPort} for any user`);
    const result = await this.updateMany(
        { comPort: comPort, isActive: true },
        { isActive: false, lastActivity: new Date() }
    );
    // console.log(`🔓 [PORT-USAGE] Release result: ${result.modifiedCount} documents modified`);
    return result.modifiedCount > 0;
};

// Method để claim port với machine/session tracking (atomic operation)
portUsageSchema.statics.claimPort = async function(comPort, userId, machineId, sessionId, screenId = 'main') {
    console.log(`🔒 [PORT-USAGE] Attempting to claim port ${comPort} for user ${userId} on machine ${machineId}, session ${sessionId}, screen ${screenId}`);
    
    try {
        // Bước 1: Kiểm tra xem port có đang được sử dụng bởi user khác không
        const existingUsage = await this.findOne(
            { comPort: comPort, isActive: true, userId: { $ne: userId } }
        );
        
        if (existingUsage) {
            console.log(`🔒 [PORT-USAGE] Port ${comPort} is already in use by user ${existingUsage.userId}`);
            throw new Error(`COM port ${comPort} đang được sử dụng bởi user ${existingUsage.userId}`);
        }
        
        // Bước 2: Release port cũ của user hiện tại nếu có
        const releaseResult = await this.updateMany(
            { comPort: comPort, userId: userId, isActive: true },
            { 
                isActive: false, 
                lastActivity: new Date(),
                releasedAt: new Date()
            }
        );
        
        if (releaseResult.modifiedCount > 0) {
            console.log(`🔒 [PORT-USAGE] Released ${releaseResult.modifiedCount} old port usage for user ${userId}`);
        }
        
        // Bước 3: Tạo hoặc cập nhật port usage mới
        const result = await this.findOneAndUpdate(
            { comPort: comPort, userId: userId },
            { 
                machineId: machineId,
                sessionId: sessionId,
                screenId: screenId,
                isActive: true, 
                connectedAt: new Date(),
                lastActivity: new Date(),
                heartbeat: new Date()
            },
            { 
                upsert: true, 
                new: true
            }
        );
        
        console.log(`🔒 [PORT-USAGE] Successfully claimed port ${comPort} for user ${userId}, usage ID: ${result._id}`);
        return result;
        
    } catch (error) {
        console.error(`🔒 [PORT-USAGE] Failed to claim port ${comPort} for user ${userId}:`, error.message);
        throw error;
    }
};

// Method để release tất cả port của user
portUsageSchema.statics.releaseAllUserPorts = async function(userId) {
    // console.log(`🔓 [PORT-USAGE] Releasing all ports for user ${userId}`);
    const result = await this.updateMany(
        { userId: userId, isActive: true },
        { isActive: false, lastActivity: new Date() }
    );
    // console.log(`🔓 [PORT-USAGE] Released ${result.modifiedCount} ports for user ${userId}`);
    return result.modifiedCount;
};

// Method để xóa hoàn toàn tất cả bản ghi port của một user
portUsageSchema.statics.deleteAllUserPorts = async function(userId) {
    // console.log(`🗑️ [PORT-USAGE] Deleting all port records for user ${userId}`);
    const result = await this.deleteMany({ userId: userId });
    // console.log(`🗑️ [PORT-USAGE] Deleted ${result.deletedCount} port records for user ${userId}`);
    return result.deletedCount;
};

// Method để xóa bản ghi port cụ thể
portUsageSchema.statics.deletePort = async function(comPort) {
    // console.log(`🗑️ [PORT-USAGE] Deleting port record: ${comPort}`);
    const result = await this.deleteOne({ comPort: comPort });
    // console.log(`🗑️ [PORT-USAGE] Deleted ${result.deletedCount} port record: ${comPort}`);
    return result.deletedCount;
};

// Method để release tất cả port của machine (khi machine shutdown)
portUsageSchema.statics.releaseAllMachinePorts = async function(machineId) {
    // console.log(`🔓 [PORT-USAGE] Releasing all ports for machine ${machineId}`);
    const result = await this.updateMany(
        { machineId: machineId, isActive: true },
        { isActive: false, lastActivity: new Date() }
    );
    console.log(`🔓 [PORT-USAGE] Released ${result.modifiedCount} ports for machine ${machineId}`);
    return result.modifiedCount;
};

// Method để release tất cả port của session (khi session timeout)
portUsageSchema.statics.releaseAllSessionPorts = async function(sessionId) {
    // console.log(`🔓 [PORT-USAGE] Releasing all ports for session ${sessionId}`);
    const result = await this.updateMany(
        { sessionId: sessionId, isActive: true },
        { isActive: false, lastActivity: new Date() }
    );
    console.log(`🔓 [PORT-USAGE] Released ${result.modifiedCount} ports for session ${sessionId}`);
    return result.modifiedCount;
};

// Method để update heartbeat
portUsageSchema.statics.updateHeartbeat = async function(comPort, userId) {
    const result = await this.updateOne(
        { comPort: comPort, userId: userId, isActive: true },
        { 
            heartbeat: new Date(),
            lastActivity: new Date()
        }
    );
    return result.modifiedCount > 0;
};

// Method để cleanup ports với timeout (heartbeat > 30 seconds)
portUsageSchema.statics.cleanupTimeoutPorts = async function(timeoutSeconds = 30) {
    const timeoutDate = new Date(Date.now() - timeoutSeconds * 1000);
    // console.log(`🧹 [PORT-USAGE] Cleaning up ports with heartbeat older than ${timeoutSeconds}s`);
    
    const result = await this.updateMany(
        { 
            isActive: true,
            heartbeat: { $lt: timeoutDate }
        },
        { 
            isActive: false, 
            lastActivity: new Date() 
        }
    );
    
    // console.log(`🧹 [PORT-USAGE] Cleaned up ${result.modifiedCount} timeout ports`);
    return result.modifiedCount;
};

// Method để lấy thông tin chi tiết về port usage
portUsageSchema.statics.getPortUsageInfo = async function(comPort) {
    const usage = await this.findOne({ 
        comPort: comPort, 
        isActive: true 
    });
    
    if (!usage) return null;
    
    return {
        comPort: usage.comPort,
        userId: usage.userId,
        machineId: usage.machineId,
        sessionId: usage.sessionId,
        screenId: usage.screenId,
        connectedAt: usage.connectedAt,
        lastActivity: usage.lastActivity,
        heartbeat: usage.heartbeat,
        isActive: usage.isActive
    };
};

module.exports = mongoose.model('PortUsage', portUsageSchema);